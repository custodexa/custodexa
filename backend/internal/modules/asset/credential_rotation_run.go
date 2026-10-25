package asset

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/material"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 輪替的執行面：逐成員動遠端、驗證、就位與收斂。
//
// # 逐台流程固定三段
//
// 候選先落庫 → 動遠端 → 以新秘密驗證。三段的順序不是風格問題：候選若在動遠端之後
// 才落庫，行程在那個窗口被砍時新秘密就永久遺失，而遠端可能已經換過去了——那台機器
// 從此沒有任何一組已知的秘密可以登入。
//
// # 為什麼失敗要分「確定沒改成」與「不知道」
//
// 前者可以安全地清掉候選並讓下一輪重來；後者不行——候選是那把可能已在遠端生效的
// 秘密的唯一副本，清掉它等於在猜遠端狀態，猜錯就把還能用的憑證改壞。分流沿用執行器
// 介面的四類錯誤契約，不另立第二套判準。

// RotationRecordOrigin 輪替成員改密記錄的來源歸屬。
//
// 兩者皆為 0＝由憑證庫直接發起（不屬於任何計劃或批次）；有值時記錄掛回該計劃或批次，
// 使批次的四種計數與計劃的執行記錄涵蓋整組改密的逐台結果。
type RotationRecordOrigin struct {
	PlanID  uint
	BatchID uint
}

// memberRun 一次成員推進的記錄用上下文。
//
// 憑證名稱與秘密型別於**推進前**擷取：拆分成功後原憑證可能已轉為專用或被回收，
// 事後再讀到的是收尾之後的樣子，而記錄要的是執行當下的事實。
type memberRun struct {
	origin         RotationRecordOrigin
	credentialName string
	secretType     string
	// recovery 發起者失權後的有限驗證（只 Verify 與本地提交）
	recovery bool
}

// Run 推進本輪：把排隊中與已到期的成員各推一步。
//
// 逐成員隔離錯誤——單一成員失敗不中斷其他成員，也不使整組停止。成員之間沒有相依性，
// 停下來只是讓已經可以改的主機也不改。
func (s *CredentialRotationService) Run(ctx context.Context, rotationID uint) error {
	_, err := s.RunFor(ctx, rotationID, RotationRecordOrigin{})
	return err
}

// RunFor 推進本輪並回傳本次產生的改密記錄（供計劃與批次彙總計數）。
func (s *CredentialRotationService) RunFor(ctx context.Context, rotationID uint,
	origin RotationRecordOrigin) ([]model.ChangeSecretRecord, error) {

	watermark := latestRecordID(s.db)
	err := s.run(ctx, rotationID, origin)
	return recordsAfter(s.db, watermark, s.memberAccountIDs(rotationID)), err
}

// memberAccountIDs 本輪成員的掛載識別（回收本次記錄時用來釘住範圍）。
func (s *CredentialRotationService) memberAccountIDs(rotationID uint) []uint {
	members, err := rotationMembers(s.db, rotationID)
	if err != nil {
		return nil
	}
	out := make([]uint, 0, len(members))
	for i := range members {
		out = append(out, members[i].AccountID)
	}
	return out
}

func (s *CredentialRotationService) run(ctx context.Context, rotationID uint,
	origin RotationRecordOrigin) error {

	rot, err := loadRotation(s.db, rotationID)
	if err != nil {
		return err
	}
	if rot.Status != model.CredentialRotationRunning {
		return ErrCredentialRotationNotRunning
	}
	members, err := rotationMembers(s.db, rot.ID)
	if err != nil {
		return err
	}
	now := time.Now()
	for i := range members {
		member := members[i]
		switch member.State {
		case model.CredentialMemberQueued:
		case model.CredentialMemberRetryWait:
			if member.NextAttemptAt != nil && member.NextAttemptAt.After(now) {
				continue
			}
		default:
			continue
		}
		s.runMember(ctx, rot, member.ID, origin)
	}
	return nil
}

// latestRecordID 記錄表當下的最大識別（推進前的水位）。
func latestRecordID(db *gorm.DB) uint {
	var max *uint
	if err := db.Model(&model.ChangeSecretRecord{}).Select("MAX(id)").Scan(&max).Error; err != nil || max == nil {
		return 0
	}
	return *max
}

// recordsAfter 水位之後、屬於本輪成員的記錄（本次推進產生的那些）。
//
// **同時以水位與掛載範圍釘住**：只看水位會在兩個批次並行時把別人的記錄算進來，
// 而呼叫端拿它去寫批次的四種計數。掛載於推進期間由 per-account 互斥鎖持有，
// 故這個範圍內的新記錄只可能是本次寫的。
func recordsAfter(db *gorm.DB, watermark uint, accountIDs []uint) []model.ChangeSecretRecord {
	if len(accountIDs) == 0 {
		return nil
	}
	var out []model.ChangeSecretRecord
	if err := db.Where("id > ? AND account_id IN ?", watermark, accountIDs).
		Order("id asc").Find(&out).Error; err != nil {
		return nil
	}
	return out
}

// RunMember 逐台補跑：**只操作指定成員**，其餘成員的狀態與就位版本一律不動。
//
// 終局失敗與已收束的成員先被重新排入本輪（**重用同一個待生效版本**，不產生第二個
// 秘密——每次補跑換一組新密碼會讓「遠端到底是哪一版」永遠答不出來）。
//
// **只給有人在場的補跑用**：重新排入會再對遠端下達一次改密。背景排程走
// AdvanceMemberInBackground，不重新排入。
func (s *CredentialRotationService) RunMember(ctx context.Context, rotationID, memberID uint) error {
	return s.RunMemberFor(ctx, rotationID, memberID, RotationRecordOrigin{})
}

// RunMemberFor 逐台補跑並指定記錄歸屬（語義同 RunMember）。
func (s *CredentialRotationService) RunMemberFor(ctx context.Context, rotationID, memberID uint,
	origin RotationRecordOrigin) error {

	rot, err := loadRotation(s.db, rotationID)
	if err != nil {
		return err
	}
	// 已放棄的輪替仍可逐台補跑：那正是未收斂狀態的**唯一出口**——放棄不回滾，
	// 待生效版本還在、部分主機已經吃了新秘密，堵住補跑等於讓憑證永遠停在不同步。
	// 補跑重用同一個待生效版本，全部就位時照樣走收斂（提升現行版本、標記本輪完成）
	if rot.Status == model.CredentialRotationCompleted {
		return ErrCredentialRotationNotRunning
	}
	// 本輪的目標版本已被操作者宣告的密文取代時同樣不得補跑（見同名函式）
	if err := assertRotationTargetStillPending(s.db, rot); err != nil {
		return err
	}
	member, err := loadRotationMember(s.db, rot.ID, memberID)
	if err != nil {
		return err
	}
	switch member.State {
	case model.CredentialMemberTerminalFailed, model.CredentialMemberAbandoned:
		if err := s.requeueMember(ctx, rot, memberID); err != nil {
			return err
		}
	case model.CredentialMemberApplied:
		// 本輪終態：補跑一台已經就位的機器只會多一次遠端往返
		return nil
	}
	s.runMember(ctx, rot, memberID, origin)
	return nil
}

// requeueMember 把最終失敗或已收束的成員重新排入本輪：取得帳號鎖、於寫入交易內重讀成員後
// 才判定能力，通過即在同一筆更新內把狀態改為 queued 並記下重排者、當時通過的權限世代與時刻。
//
// 判定不在等鎖之前做：等鎖期間可能很長，等到鎖時點擊者可能已失權，寫入前的判定必須是
// 取得鎖之後的那一次。重排紀錄與狀態同交易落列，之後每次派送（手動或背景接手）都以本輪
// 發起者與重排者雙方當下的能力重驗（見 revalidateMember），使重排與派送之間的解鎖窗口
// 不會讓已失權的重排者經由背景排程把工作重新打開。等鎖期間成員已被別條路徑推離可重排
// 狀態時為無操作（由之後的 runMember 依當下狀態處理）。
func (s *CredentialRotationService) requeueMember(ctx context.Context, rot *model.CredentialRotation, memberID uint) error {
	member, err := loadRotationMember(s.db, rot.ID, memberID)
	if err != nil {
		return err
	}
	unlock := lockRotationAccount(member.AccountID)
	defer unlock()
	return s.db.Transaction(func(tx *gorm.DB) error {
		m, err := loadRotationMember(tx, rot.ID, memberID)
		if err != nil {
			return err
		}
		switch m.State {
		case model.CredentialMemberTerminalFailed, model.CredentialMemberAbandoned:
		default:
			return nil
		}
		// 重新排入是一次寫入，之後還會再對遠端下達：寫入前（持鎖、同交易）判定能力，缺能力即拒（fail closed）
		actorID, actorName, version, err := s.requireRequeue(ctx, tx, rot)
		if err != nil {
			return err
		}
		if err := transitionMember(tx, m, model.CredentialMemberQueued, memberTransition{}); err != nil {
			return err
		}
		if err := tx.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).Updates(map[string]any{
			"requeued_by": actorID, "requeued_by_name": actorName,
			"requeued_authz_version": version, "requeued_at": time.Now(),
		}).Error; err != nil {
			return fmt.Errorf("寫入重排紀錄失敗: %w", err)
		}
		return nil
	})
}

// requireRequeue 重新排入最終失敗或已收束成員前的能力判定（遠端輪替能力，影響集合為憑證全部掛載），
// 於呼叫端持鎖的寫入交易內執行；通過回重排者（識別與名稱）與當下通過的權限世代版本。
// 有點擊者：判點擊者當下的能力。沒有點擊者（重啟後的補跑）：以本輪持久授權脈絡的發起者當下能力
// 重驗；脈絡缺失、讀不到或發起者已失權一律拒絕，不沿用失權者的脈絡、也不以「無從判定」放行。
func (s *CredentialRotationService) requireRequeue(ctx context.Context, tx *gorm.DB,
	rot *model.CredentialRotation) (actorID uint, actorName string, version int64, err error) {

	if uid, uname := model.UserFromContext(ctx); uid != 0 {
		decision, err := s.requireBoundManagementDecision(ctx, tx, CredOpRotate, rot.CredentialID, CredCapRotate)
		if err != nil {
			return 0, "", 0, err
		}
		return uid, uname, decision.AuthzVersion, nil
	}
	auth, err := loadJobAuthorization(tx, rot.AuthorizationID)
	if err != nil {
		return 0, "", 0, fmt.Errorf("%w: 補跑缺可用的授權脈絡: %v", ErrCredentialAuthzUnavailable, err)
	}
	assetIDs, err := credentialBoundAssetIDs(tx, rot.CredentialID)
	if err != nil {
		return 0, "", 0, err
	}
	reason, version := revalidateAuthorizationVersion(s.mgmt, tx, ctx, auth, CredentialManagementRequest{
		CredentialIDs: []uint{rot.CredentialID}, MountedAssetIDs: assetIDs,
	}, []string{CredCapRotate})
	switch reason {
	case "":
		return auth.ActorID, auth.ActorName, version, nil
	case model.ChangeSecretReasonAuthzRevoked:
		return 0, "", 0, ErrCredentialBindForbidden
	default:
		return 0, "", 0, fmt.Errorf("%w: 補跑重驗未通過: %s", ErrCredentialAuthzUnavailable, reason)
	}
}

// AdvanceMemberInBackground 背景排程推進單一成員（到期成員掃描與候選重試排程共用）。
//
// 與 RunMember 的差別在於**不重新排入**：背景只推進本輪仍待處理的成員——排隊中、等待
// 重試（到期才推）、已送出未驗證（到期才推，且只以新秘密登入驗證、不下達）。最終失敗、
// 已收束、已就位的成員一律不碰：把它們重新排入就會再對遠端下達一次改密，而無人在場時
// 沒有人確認過那台主機此刻的實際狀態，重下一次可能蓋掉別條路徑剛改好的秘密。那要有人
// 按下逐台補跑才做。也只推進進行中的那一輪（放棄後停止自動化，見 DueMembers）。
//
// 回傳 true＝本次確實推進了一步；false＝依上述規則不推進（不是錯誤）。
func (s *CredentialRotationService) AdvanceMemberInBackground(ctx context.Context, rotationID, memberID uint) (bool, error) {
	rot, err := loadRotation(s.db, rotationID)
	if err != nil {
		return false, err
	}
	if rot.Status != model.CredentialRotationRunning {
		return false, nil
	}
	if err := assertRotationTargetStillPending(s.db, rot); err != nil {
		return false, err
	}
	member, err := loadRotationMember(s.db, rot.ID, memberID)
	if err != nil {
		return false, err
	}
	if !memberDueInBackground(member, time.Now()) {
		return false, nil
	}
	// runMember 取鎖後重讀，只處理排隊、等待重試與已送出未驗證三格：等鎖期間轉成
	// 最終失敗或已收束的成員，在那裡同樣是無操作
	s.runMember(ctx, rot, memberID, RotationRecordOrigin{})
	return true, nil
}

// memberDueInBackground 背景是否推進這個成員（見 AdvanceMemberInBackground）。
//
// 下次嘗試時刻為空＝成員沒有自己的退避（遠端結果未知而轉入已送出未驗證時即如此），
// 節奏由該掛載的候選列承擔；有值則以它為準——兩套排程各推各的，就是兩套鎖帳風險。
func memberDueInBackground(member *model.CredentialRotationMember, now time.Time) bool {
	switch member.State {
	case model.CredentialMemberQueued:
		return true
	case model.CredentialMemberRetryWait, model.CredentialMemberChangedUnverified:
		return member.NextAttemptAt == nil || !member.NextAttemptAt.After(now)
	}
	return false
}

// runMember 單一成員推進一步；任何錯誤只落成員狀態與原因碼，不上拋。
//
// per-account 互斥與改密執行器共用同一組鎖：同一個掛載的兩次改密同時跑，會有兩個
// 候選互相覆蓋遠端狀態。
func (s *CredentialRotationService) runMember(ctx context.Context, rot *model.CredentialRotation,
	memberID uint, origin RotationRecordOrigin) {

	member, err := loadRotationMember(s.db, rot.ID, memberID)
	if err != nil {
		return
	}
	release := lockRotationAccount(member.AccountID)
	defer release()

	// 取鎖後重讀：等鎖期間別的路徑可能已經推進過本成員
	member, err = loadRotationMember(s.db, rot.ID, memberID)
	if err != nil {
		return
	}
	run := memberRun{
		origin:         origin,
		credentialName: credentialNameSnapshot(s.db, member.CredentialID),
		secretType:     credentialSecretType(s.db, member.CredentialID),
	}
	switch member.State {
	case model.CredentialMemberQueued, model.CredentialMemberRetryWait:
		// 每次遠端下達之前以發起者當下的能力重驗（背景補跑、重試、手動補跑同一道關卡）
		if reason := s.revalidateMember(ctx, rot, member); reason != "" {
			s.stopMember(rot, member, reason, run)
			return
		}
		s.deliverMember(ctx, rot, member, run)
	case model.CredentialMemberChangedUnverified:
		reason := s.revalidateMember(ctx, rot, member)
		if reason == "" {
			s.verifyMember(ctx, rot, member, run)
			return
		}
		// 失權：已確認下達且目標未被改動時，只開放「只驗證、只提交本地」的有限收斂；
		// 其餘情形停止（成員與候選保留），不發任何新的遠端變更
		if reason == model.ChangeSecretReasonAuthzRevoked {
			applied := false
			groupCandidate := false
			if cand, cerr := s.candidates.FindByAccount(member.AccountID); cerr == nil && cand != nil {
				applied = cand.Applied
				groupCandidate = rot.Mode == model.CredentialRotationModeGroup
			}
			reason = recoveryVerdict(s.db, s.hostKeys, applied, rot.StartedAt, member.TargetFingerprint,
				member.AccountID, hostIdentityJobOfMember(member, groupCandidate))
			if reason == model.ChangeSecretReasonHostIdentityChanged {
				// 失權後的有限驗證在判定階段被身分擋下：沒有撥號，補寫停止審計
				s.recordMemberRecoveryStop(rot, member)
			}
			if reason == "" {
				run.recovery = true
				if s.stopNotify != nil && claimRecoveryAlert(s.db, &model.CredentialRotationMember{}, member.ID) {
					s.stopNotify("改密工作於授權失效後進入有限驗證",
						fmt.Sprintf("rotation=%d asset_id=%d account=%s 發起者已失權，因遠端變更已送出，僅做驗證與本地提交（不再下達新變更），請具權者知悉",
							rot.ID, member.AssetID, member.Username))
				}
				s.verifyMember(ctx, rot, member, run)
				return
			}
		}
		s.stopUnverifiedMember(rot, member, reason, run)
	}
}

// stopUnverifiedMember 已下達未驗證的成員因授權停止：成員與候選保留，退避到期後再看，
// 逾期則終局並沿原放棄告警。同一原因的告警每個成員只發一次，不隨退避週期重複。
func (s *CredentialRotationService) stopUnverifiedMember(rot *model.CredentialRotation,
	member *model.CredentialRotationMember, reason string, run memberRun) {

	logJobStop(fmt.Sprintf("rotation=%d member=%d", rot.ID, member.ID), reason, rot.RequestedBy)
	first := member.LastError != reason
	s.stayUnverified(rot, member, reason, run)
	if s.stopNotify == nil {
		return
	}
	if member.State == model.CredentialMemberTerminalFailed || time.Since(rot.StartedAt) >= recoveryWindow {
		s.stopNotify("改密候選憑證已放棄重試",
			fmt.Sprintf("rotation=%d asset_id=%d account=%s 已逾期限仍無法驗證，需管理員以帶外途徑處置",
				rot.ID, member.AssetID, member.Username))
		return
	}
	// 主機身分停止有自己的停止審計與通知（每個身分狀態一次），不套授權失效的告警
	if first && reason != model.ChangeSecretReasonHostIdentityChanged {
		s.stopNotify("改密工作因授權失效停止",
			fmt.Sprintf("rotation=%d asset_id=%d account=%s reason=%s（遠端未被新增變更，候選保留，需具權者處置）",
				rot.ID, member.AssetID, member.Username, reason))
	}
}

// credentialSecretType 取憑證的秘密型別（讀不到時退為密碼，記錄欄位不因此空白）。
func credentialSecretType(db *gorm.DB, credentialID uint) string {
	var cred model.Credential
	if err := db.Unscoped().Where("id = ?", credentialID).First(&cred).Error; err != nil {
		return model.ChangeSecretTypePassword
	}
	if cred.SecretType == "" {
		return model.ChangeSecretTypePassword
	}
	return cred.SecretType
}

// recordMember 為單一成員的一次結果落一筆改密記錄。
//
// **整組改密與拆分也要留記錄**：輪替證據報告的區間明細讀的是改密記錄，只寫成員列
// 會讓「這一期做過整組改密」在報告上完全看不見。記錄帶執行當下的憑證與版本快照，
// 事後改綁不會汙染它。落庫失敗只留 log——記錄寫不進去不改變已經發生的遠端結果。
func (s *CredentialRotationService) recordMember(member *model.CredentialRotationMember,
	status, reason string, run memberRun) {

	rec := model.ChangeSecretRecord{
		PlanID:          run.origin.PlanID,
		BatchID:         run.origin.BatchID,
		AssetID:         member.AssetID,
		AccountID:       member.AccountID,
		AccountUsername: member.Username,
		SecretType:      run.secretType,
		CredentialID:    member.CredentialID,
		CredentialName:  run.credentialName,
		Status:          status,
		Error:           reason,
		ExecutedAt:      time.Now(),
	}
	if member.TargetVersionID != nil {
		rec.TargetVersionID = *member.TargetVersionID
	}
	if err := s.db.Create(&rec).Error; err != nil {
		log.Printf("[CredentialRotation] 成員改密記錄入庫失敗 member=%d err=%v", member.ID, err)
	}
}

// memberContext 一次成員執行所需的目標描述與兩組秘密。
type memberContext struct {
	target    rotationTarget
	logTarget changeSecretTarget
	exec      rotationExecutor
	old       *ResolvedCredential
	// newPassword／newPrivateKey 本輪要推到遠端的秘密（依型別二擇一）
	newPassword   *material.Secret
	newPrivateKey *material.Secret
	secretType    string
	// deliveryGuard 下達握手的放行計數與停止審計用（只在下達路徑建立）
	deliveryGuard *immediateVerifyGuard
}

// prepareMember 組出目標描述並取回新舊兩組秘密。
//
// 回傳的原因碼非空即代表「還沒碰到遠端就失敗了」，呼叫端據此走乾淨失敗。
func (s *CredentialRotationService) prepareMember(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember) (*memberContext, string) {

	asset, err := s.assets.GetByID(member.AssetID)
	if err != nil {
		return nil, model.ChangeSecretReasonAssetLookupFailed
	}
	channel := asset.EffectiveRotationChannel()
	if channel == model.RotationChannelNone {
		return nil, model.ChangeSecretReasonChannelNotConfigured
	}
	old, err := s.assets.resolver.ResolveForBinding(ctx, member.AssetID, member.AccountID)
	if err != nil {
		return nil, model.ChangeSecretReasonCredentialLoadFailed
	}
	transferred := false
	defer func() {
		if !transferred {
			old.Destroy()
		}
	}()
	// 釘住帳號名：成員快照與現況不符即代表這一列已代表另一個系統身分，
	// 把新秘密推上去等於改錯對象
	if old.Username != member.Username {
		return nil, model.ChangeSecretReasonAccountChanged
	}
	if old.Password.IsEmpty() && old.PrivateKey.IsEmpty() {
		return nil, model.ChangeSecretReasonNoCredential
	}

	next, reason := s.targetSecret(ctx, rot, member)
	if reason != "" {
		return nil, reason
	}
	defer next.Destroy()
	secretType := next.SecretType
	if secretType == "" {
		secretType = model.ChangeSecretTypePassword
	}
	if model.IsWindowsRotationChannel(channel) && secretType == model.ChangeSecretTypeSSHKey {
		return nil, model.ChangeSecretReasonSecretTypeUnsupported
	}
	password, err := material.Move(next.Password)
	if err != nil {
		return nil, model.ChangeSecretReasonCredentialLoadFailed
	}
	key, err := material.Move(next.PrivateKey)
	if err != nil {
		password.Destroy()
		return nil, model.ChangeSecretReasonCredentialLoadFailed
	}
	transferred = true
	// 主機金鑰回呼帶撥號脈絡：輪替屬背景路徑，不符時留痕後拒絕；連線使用者為輪替發起者
	// 基底回呼 fail-closed：正式撥號點都會依路線覆寫成綁定或預期身分回呼，
	// 漏覆寫的新呼叫點在握手就被拒絕，不會落到一般的首次信任判定
	hostKeyCB := ssh.HostKeyCallback(func(string, net.Addr, ssh.PublicKey) error { return ErrHostKeyCheckFailed })
	return &memberContext{
		target: rotationTarget{
			asset:      asset,
			channel:    channel,
			username:   member.Username,
			secretType: secretType,
			addr:       rotationAddr(asset, channel),
			hostKeyCB:  hostKeyCB,
		},
		logTarget: changeSecretTarget{
			assetID: member.AssetID, accountID: member.AccountID,
			username: member.Username, channel: channel,
		},
		exec:          s.executors(channel),
		old:           old,
		newPassword:   password,
		newPrivateKey: key,
		secretType:    secretType,
	}, ""
}

// targetSecret 取本成員要推到遠端的新秘密。
//
// 整組模式取本輪的待生效版本（全體同一組）；拆分模式取該掛載自己的候選（每台不同）。
// 兩者都**不產生新秘密**——重試與補跑重用同一份，否則「遠端到底是哪一版」答不出來。
func (s *CredentialRotationService) targetSecret(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember) (*ResolvedCredential, string) {

	if rot.Mode == model.CredentialRotationModeSplit {
		cand, err := s.candidates.FindByAccount(member.AccountID)
		if err != nil {
			return nil, model.ChangeSecretReasonCandidateQueryFailed
		}
		if cand == nil {
			return nil, model.ChangeSecretReasonNoCredential
		}
		secret, err := s.candidates.Secret(ctx, cand)
		if err != nil {
			return nil, model.ChangeSecretReasonRetrySecretUnavailable
		}
		defer secret.Destroy()
		password, err := material.Move(secret.Password)
		if err != nil {
			return nil, model.ChangeSecretReasonCredentialLoadFailed
		}
		key, err := material.Move(secret.PrivateKey)
		if err != nil {
			password.Destroy()
			return nil, model.ChangeSecretReasonCredentialLoadFailed
		}
		return &ResolvedCredential{
			SecretType: cand.SecretType,
			Password:   password,
			PrivateKey: key,
		}, ""
	}
	if member.TargetVersionID == nil || *member.TargetVersionID == 0 {
		return nil, model.ChangeSecretReasonCredentialLoadFailed
	}
	resolved, err := s.assets.resolver.ResolveVersion(ctx, member.CredentialID, *member.TargetVersionID)
	if err != nil {
		return nil, model.ChangeSecretReasonCredentialLoadFailed
	}
	return resolved, ""
}

// memberHostKeyDialContext 輪替成員撥號的主機金鑰脈絡：輪替屬背景路徑，不符時留痕後拒絕；
// 連線使用者為輪替發起者。
func memberHostKeyDialContext(rot *model.CredentialRotation, member *model.CredentialRotationMember) HostKeyDialContext {
	return HostKeyDialContext{
		AssetID: member.AssetID, Path: HostKeyPathCredentialRotation,
		UserID: rot.RequestedBy, Username: rot.RequestedByName, AccountID: member.AccountID,
		ConnectionRef: fmt.Sprintf("credential_rotation_member:%d", member.ID),
	}
}

// deliveryDecision 下達前的分流結果：路線，以及整組模式下分流當下該帳號的候選列是否存在。
type deliveryDecision struct {
	route                deliveryRoute
	groupCandidateExists bool
}

// decideDelivery 依成員的派送證據分流。必須在 ensureCandidate 之前呼叫：整組模式的候選列
// 只在重建之前的狀態才是「是否曾下達」的證據；拆分模式的候選在起始交易就備妥，不看候選列。
func (s *CredentialRotationService) decideDelivery(rot *model.CredentialRotation,
	member *model.CredentialRotationMember) (deliveryDecision, string) {

	exists := false
	if rot.Mode != model.CredentialRotationModeSplit {
		cand, err := s.candidates.FindByAccount(member.AccountID)
		if err != nil {
			return deliveryDecision{}, model.ChangeSecretReasonCandidateQueryFailed
		}
		exists = cand != nil
	}
	return deliveryDecision{route: classifyMemberDelivery(member, rot.Mode, exists), groupCandidateExists: exists}, ""
}

// guardDeliveryIdentity 已有送出證據（沿原快照）或不可比對（停止）的路線，在撥號前以查庫判定放行與否。
// 回傳非空＝停止細節；Bind 路線不經此判定。
func guardDeliveryIdentity(db *gorm.DB, member *model.CredentialRotationMember,
	asset *model.Asset, dec deliveryDecision) string {

	if dec.route == deliveryRouteBind {
		return ""
	}
	detail := hostIdentityVerdict(db, hostIdentityJobOfMember(member, dec.groupCandidateExists), asset)
	if detail == "" && dec.route == deliveryRouteBlocked {
		return hostIdentityUnboundLegacy // 判定與分流不一致時以較嚴者為準
	}
	return detail
}

// attachDeliveryIdentity 依路線把主機身分綁定接到本次下達：
//   - Bind：SSH 家族用綁定回呼（第一次握手在認證前綁定）；WinRM 在 Rotate 之前條件式寫入綁定。
//   - Pinned：以成員自己的快照為預期身分，不重綁（WinRM 沒有金鑰可比）。
//
// 回傳非空原因碼＝尚未動遠端的乾淨失敗。
func (s *CredentialRotationService) attachDeliveryIdentity(rot *model.CredentialRotation,
	member *model.CredentialRotationMember, mc *memberContext, dec deliveryDecision) string {

	winrm := rotationTransportOf(mc.target.asset) == model.HostKeyTransportWinRM
	mc.deliveryGuard = s.memberVerifyGuard(rot, member)
	if winrm {
		// WinRM 沒有 SSH 握手，也就沒有主機金鑰回呼可言：不留 fail-closed 的基底回呼，與補跑驗證路徑一致
		mc.target.hostKeyCB = nil
	}
	switch dec.route {
	case deliveryRouteBind:
		if winrm {
			if err := s.hostKeys.BindWinRM(HostKeyBindTarget{MemberID: member.ID}); err != nil {
				return model.ChangeSecretReasonHostKeyCheckFailed
			}
			return ""
		}
		cb, _ := s.hostKeys.CallbackForBinding(memberHostKeyDialContext(rot, member),
			HostKeyBindTarget{MemberID: member.ID})
		mc.target.hostKeyCB = mc.deliveryGuard.countPasses(cb)
	case deliveryRoutePinned:
		if !winrm {
			mc.target.hostKeyCB = mc.deliveryGuard.countPasses(s.hostKeys.CallbackForPinned(
				memberHostKeyDialContext(rot, member),
				HostKeyPin{Algorithm: member.HostKeyAlgorithm, Fingerprint: member.HostKeyFingerprint}))
		}
	}
	return ""
}

// stopDelivery 撥號前的主機身分守衛不放行：沒有送出任何新秘密，成員轉已下達未驗證（結果未知的既有處置），
// 原因碼為主機身分變更，之後由人工承接。
func (s *CredentialRotationService) stopDelivery(rot *model.CredentialRotation, member *model.CredentialRotationMember,
	detail string, run memberRun) {

	reason := hostIdentityRecoveryReason(detail)
	log.Printf("[CredentialRotation] 撥號前主機身分守衛停止: member=%d asset=%d detail=%s", member.ID, member.AssetID, detail)
	if err := s.markUnverified(member, reason); err == nil {
		s.recordMember(member, model.ChangeSecretUnverified, reason, run)
	}
	if reason == model.ChangeSecretReasonHostIdentityChanged {
		s.recordMemberPrecheckStop(rot, member, detail)
	}
}

// deliveryIdentityStopped 下達握手被主機身分回呼拒絕（含被包裝的錯誤）。
//   - 已送出（Pinned 路線沿舊憑證快照撥號，或首次派送的綁定回呼已放行過至少一次，其後即送出認證）：
//     不是「遠端確定沒改成」，不可清候選副本也不可走乾淨失敗。保留工作證據、成員轉已下達未驗證
//     （原因碼為主機身分變更），並寫 phase=handshake 的停止審計。
//   - 首次派送（Bind 路線）且回呼從未放行：認證之前就被拒絕，秘密並未送出，維持乾淨失敗
//     （不標記已送出、候選副本依首次派送規則清除、可重試），仍補寫 verification_sent=false 的停止審計。
//
// 放行計數不可得（回呼沒有經過計數）時視為已送出，取較嚴的處置。回傳是否已處理。
func (s *CredentialRotationService) deliveryIdentityStopped(rot *model.CredentialRotation,
	member *model.CredentialRotationMember, mc *memberContext, cand *model.ChangeSecretCandidate,
	dec deliveryDecision, err error, run memberRun) bool {

	if !errors.Is(err, ErrHostIdentityChanged) {
		return false
	}
	guard := mc.deliveryGuard
	if guard == nil {
		guard = s.memberVerifyGuard(rot, member)
	}
	passes, counted := guard.passCount()
	if dec.route == deliveryRouteBind && counted && passes == 0 {
		log.Printf("[CredentialRotation] 首次派送綁定握手主機身分不符（尚未送出秘密）: member=%d asset=%d", member.ID, member.AssetID)
		s.memberIdentityStopped(guard, member, err)
		s.discardUndeliveredCandidate(rot, cand)
		s.failClean(rot, member, model.ChangeSecretReasonHostKeyCheckFailed, run)
		return true
	}
	reason := model.ChangeSecretReasonHostIdentityChanged
	log.Printf("[CredentialRotation] 下達握手主機身分不符: member=%d asset=%d", member.ID, member.AssetID)
	if merr := s.markUnverified(member, reason); merr == nil {
		s.recordMember(member, model.ChangeSecretUnverified, reason, run)
	}
	s.memberIdentityStopped(guard, member, err)
	return true
}

// deliverMember 對遠端下達新秘密並驗證。
func (s *CredentialRotationService) deliverMember(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember, run memberRun) {

	if err := s.transition(member, model.CredentialMemberChanging, memberTransition{}); err != nil {
		return
	}
	// 分流早於建回呼與重建候選副本
	dec, reason := s.decideDelivery(rot, member)
	if reason != "" {
		s.failClean(rot, member, reason, run)
		return
	}
	mc, reason := s.prepareMember(ctx, rot, member)
	if reason != "" {
		s.failClean(rot, member, reason, run)
		return
	}

	defer mc.Destroy()
	if detail := guardDeliveryIdentity(s.db, member, mc.target.asset, dec); detail != "" {
		s.stopDelivery(rot, member, detail, run)
		return
	}
	cand, reason := s.ensureCandidate(ctx, rot, member, mc)
	if reason != "" {
		s.failClean(rot, member, reason, run)
		return
	}
	if reason := s.attachDeliveryIdentity(rot, member, mc, dec); reason != "" {
		s.discardUndeliveredCandidate(rot, cand)
		s.failClean(rot, member, reason, run)
		return
	}

	if mc.secretType == model.ChangeSecretTypeSSHKey {
		s.deliverKey(ctx, rot, member, mc, cand, dec, run)
		return
	}
	s.deliverPassword(ctx, rot, member, mc, cand, dec, run)
}

// deliverPassword 密碼型別：下達 → 標記已下達 → 以新密驗證。
func (s *CredentialRotationService) deliverPassword(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember,
	mc *memberContext, cand *model.ChangeSecretCandidate, dec deliveryDecision, run memberRun) {

	oldSecret := mc.old.Password
	if err := withProtocolPair(oldSecret, mc.newPassword, func(old, next []byte) error { return mc.exec.Rotate(ctx, mc.target, old, next) }); err != nil {
		logRemoteCause(mc.logTarget, "改密失敗", err)
		if s.deliveryIdentityStopped(rot, member, mc, cand, dec, err, run) {
			return
		}
		reason, clean := classifyRotationError(err)
		if clean {
			s.discardUndeliveredCandidate(rot, cand)
			s.failClean(rot, member, reason, run)
			return
		}
		if err := s.markUnverified(member, reason); err == nil {
			s.recordMember(member, model.ChangeSecretUnverified, reason, run)
		}
		return
	}
	if merr := s.candidates.MarkApplied(cand.ID); merr != nil {
		log.Printf("[CredentialRotation] 標記候選已下達失敗 member=%d err=%v", member.ID, merr)
	}
	if err := s.markUnverified(member, ""); err != nil {
		return
	}
	// 立即 Verify 會再送一次新秘密：先重讀成員列做撥號前查庫，撥號只認綁定的金鑰
	guard := s.memberVerifyGuard(rot, member)
	verifyTarget := mc.target
	cb, err := guard.prepare(mc.target.asset)
	if err == nil {
		verifyTarget.hostKeyCB = cb
		err = withProtocolSecret(mc.newPassword, func(next []byte) error { return mc.exec.Verify(ctx, verifyTarget, next) })
	}
	if err != nil {
		logRemoteCause(mc.logTarget, "新密驗證失敗", err)
		s.memberIdentityStopped(guard, member, err)
		reason := verifyFailureReason(err, model.ChangeSecretReasonVerifyFailed)
		_, _ = s.candidates.RecordFailure(cand, reason)
		s.stayUnverified(rot, member, reason, run)
		return
	}
	s.commitApplied(ctx, rot, member, mc, run)
}

// deliverKey 金鑰型別：三段式（加新 → 驗新 → 刪舊）由 keyApplier 承擔。
//
// 三段式留在專用路徑而未收進執行器介面：還原必須在**同一條已認證的 SFTP 連線**上
// 回寫（重新撥號的還原會與舊憑證是否仍有效綁在一起），這條連線的生命週期跨越
// 「動遠端」與「驗證」兩步，無法以兩次獨立呼叫表達。
func (s *CredentialRotationService) deliverKey(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember,
	mc *memberContext, cand *model.ChangeSecretCandidate, dec deliveryDecision, run memberRun) {

	newLine, err := publicLineFromOwnedKey(mc.newPrivateKey)
	if err != nil {
		s.failClean(rot, member, model.ChangeSecretReasonKeypairGenerateFailed, run)
		return
	}
	previousLine := ""
	if !mc.old.PrivateKey.IsEmpty() {
		if line, lerr := publicLineFromOwnedKey(mc.old.PrivateKey); lerr == nil {
			previousLine = line
		}
	}
	// 既有金鑰（含使用者自放的）一律保留：整組輪替換的是本系統推送的那一把，
	// 順手清掉別人放的鑰會讓管理者失去自己的入口，而他的操作裡沒有一步表達過這個意思
	guard := s.memberVerifyGuard(rot, member)
	mc.target.verifyHostKeyCB = func() (ssh.HostKeyCallback, error) { return guard.prepare(mc.target.asset) }
	// 首次寫入與刪舊鑰各是一次遠端寫入：寫入之前以同一道成員判定短交易重驗（與下達入口同一關卡，
	// 通過即更新 dispatch claim），登入、讀檔與驗新期間的撤權或移出範圍在下一次寫入之前生效
	recheck := func(string) string { return s.revalidateMember(ctx, rot, member) }
	err = withProtocolPair(mc.old.Password, mc.old.PrivateKey, func(password, key []byte) error {
		return withProtocolSecret(mc.newPrivateKey, func(next []byte) error {
			return s.keyApplier(ctx, mc.exec, mc.target, mc.logTarget,
				password, key, next, newLine, previousLine,
				model.KeyStrategyAppendReplace,
				func() error { return s.candidates.MarkApplied(cand.ID) }, recheck)
		})
	})
	var stopped *dispatchStoppedError
	if errors.As(err, &stopped) {
		s.stopKeyDelivery(rot, member, cand, stopped, run)
		return
	}
	if err != nil {
		// 身分拒絕若來自驗證階段的回呼（verify 守衛已走到），沿用下面的未知分流與驗證守衛留痕；
		// 否則是下達的舊憑證握手被拒
		if !guard.reached() && s.deliveryIdentityStopped(rot, member, mc, cand, dec, err, run) {
			return
		}
		reason, clean := classifyRotationError(err)
		if clean {
			s.discardUndeliveredCandidate(rot, cand)
			s.failClean(rot, member, reason, run)
			return
		}
		_, _ = s.candidates.RecordFailure(cand, reason)
		if merr := s.markUnverified(member, reason); merr == nil {
			s.recordMember(member, model.ChangeSecretUnverified, reason, run)
		}
		s.memberIdentityStopped(guard, member, err)
		return
	}
	if err := s.markUnverified(member, ""); err != nil {
		return
	}
	s.commitApplied(ctx, rot, member, mc, run)
}

// stopKeyDelivery 金鑰下達途中重驗未通過（處置同單帳號路徑 rotateKey）：
// 首次寫入之前停下＝遠端未改動，候選依模式處置、成員停止；刪舊鑰之前停下＝新鑰已寫入、舊鑰未刪，
// 候選保留、成員停在已下達未驗證，之後只走有限驗證，不再發新的遠端變更。
func (s *CredentialRotationService) stopKeyDelivery(rot *model.CredentialRotation,
	member *model.CredentialRotationMember, cand *model.ChangeSecretCandidate,
	stopped *dispatchStoppedError, run memberRun) {

	if !stopped.delivered {
		s.discardUndeliveredCandidate(rot, cand)
		s.stopMember(rot, member, stopped.reason, run)
		return
	}
	_, _ = s.candidates.RecordFailure(cand, stopped.reason)
	if err := s.markUnverified(member, stopped.reason); err != nil {
		return
	}
	s.recordMember(member, model.ChangeSecretUnverified, stopped.reason, run)
	logJobStop(fmt.Sprintf("rotation=%d member=%d", rot.ID, member.ID), stopped.reason, rot.RequestedBy)
	s.auditMemberStop(rot, member, stopped.reason)
	if s.stopNotify != nil {
		s.stopNotify("改密工作因授權失效停止",
			fmt.Sprintf("rotation=%d asset_id=%d account=%s reason=%s（遠端未被新增變更，候選保留，需具權者處置）",
				rot.ID, member.AssetID, member.Username, stopped.reason))
	}
}

// verifyMember 對停在「已下達、未驗證」的成員再驗一次。
//
// **不以舊秘密回探來分辨「遠端沒改成」**：那會對目標機多打一輪認證，而分辨出來
// 也不改變處置（不採自動回滾）。
func (s *CredentialRotationService) verifyMember(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember, run memberRun) {

	// 撥號前先查庫（早於取回秘密）：新秘密已送出，驗證會再送一次認證，只對綁定的主機送
	asset, aerr := s.assets.GetByID(member.AssetID)
	if aerr != nil {
		s.stayUnverified(rot, member, model.ChangeSecretReasonAssetLookupFailed, run)
		return
	}
	guard := s.memberVerifyGuard(rot, member)
	// refuse 預檢不放行：沒有撥號，補寫停止審計後維持未驗證
	refuse := func(gerr error) {
		log.Printf("[CredentialRotation] 補跑驗證前主機身分不放行 member=%d asset=%d: %v", member.ID, member.AssetID, gerr)
		s.memberIdentityStopped(guard, member, gerr)
		if run.recovery {
			_ = s.recoveryAudit(rot, member, "verify_failed")
		}
		s.stayUnverified(rot, member, verifyFailureReason(gerr, model.ChangeSecretReasonRetryLoginFailed), run)
	}
	if _, gerr := guard.prepare(asset); gerr != nil {
		refuse(gerr)
		return
	}
	if s.verifyPrecheckHook != nil {
		s.verifyPrecheckHook()
	}
	mc, reason := s.prepareMember(ctx, rot, member)
	if reason != "" {
		s.stayUnverified(rot, member, reason, run)
		return
	}
	defer mc.Destroy()
	// 上面的預檢與 prepareMember 各讀一次資產，兩次之間資產可能被改了通道或端點：
	// 實際撥號的目標與執行器以 prepareMember 的資產為準，因此對它再判一次並重產回呼
	guardedCB, gerr := guard.prepare(mc.target.asset)
	if gerr != nil {
		refuse(gerr)
		return
	}
	mc.target.hostKeyCB = guardedCB
	newSecret := mc.newPassword
	if mc.secretType == model.ChangeSecretTypeSSHKey {
		newSecret = mc.newPrivateKey
	}
	if err := withProtocolSecret(newSecret, func(next []byte) error { return mc.exec.Verify(ctx, mc.target, next) }); err != nil {
		logRemoteCause(mc.logTarget, "補跑驗證失敗", err)
		s.memberIdentityStopped(guard, member, err)
		if run.recovery {
			_ = s.recoveryAudit(rot, member, "verify_failed")
		}
		reason := verifyFailureReason(err, model.ChangeSecretReasonRetryLoginFailed)
		if cand, cerr := s.candidates.FindByAccount(member.AccountID); cerr == nil && cand != nil {
			_, _ = s.candidates.RecordFailure(cand, reason)
		}
		s.stayUnverified(rot, member, reason, run)
		return
	}
	if run.recovery {
		// 在發起者已失權的狀態下代為完成本地提交：留痕寫不進去就不提交，成員與候選保留
		if err := s.recoveryAudit(rot, member, "verified"); err != nil {
			s.stayUnverified(rot, member, model.ChangeSecretReasonAuthzUnavailable, run)
			return
		}
	}
	s.commitApplied(ctx, rot, member, mc, run)
}

// recoveryCleanupPending SSH 型別且新版本帶舊公鑰＝失權後不替發起者刪舊鑰，舊鑰待人清理。
func (s *CredentialRotationService) recoveryCleanupPending(member *model.CredentialRotationMember) bool {
	if credentialSecretType(s.db, member.CredentialID) != model.ChangeSecretTypeSSHKey || member.TargetVersionID == nil {
		return false
	}
	var ver model.CredentialSecretVersion
	return s.db.Where("id = ?", *member.TargetVersionID).First(&ver).Error == nil && ver.PreviousPublicKey != ""
}

// recoveryAudit 有限驗證的結果留痕。
func (s *CredentialRotationService) recoveryAudit(rot *model.CredentialRotation,
	member *model.CredentialRotationMember, result string) error {

	return writeRecoveryVerifyAudit(s.auditTx, s.db, recoveryAuditInput{
		resource: model.ResourceCredential, resourceID: member.CredentialID, assetID: member.AssetID,
		accountID: member.AccountID, authorizationID: rot.AuthorizationID,
		initiatorID: rot.RequestedBy, initiatorName: rot.RequestedByName,
		cleanupPending: s.recoveryCleanupPending(member), source: "rotation_member",
		result: result, fingerprint: member.TargetFingerprint,
	})
}

// ensureCandidate 取（或建立）本成員的候選秘密。
//
// **候選先於遠端落庫**：後端在「已下達、尚未驗證」的窗口被砍時，候選若只在記憶體
// 即永久遺失。拆分模式的候選於起始交易已建好，此處只取回。
func (s *CredentialRotationService) ensureCandidate(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember,
	mc *memberContext) (*model.ChangeSecretCandidate, string) {

	existing, err := s.candidates.FindByAccount(member.AccountID)
	if err != nil {
		return nil, model.ChangeSecretReasonCandidateQueryFailed
	}
	if existing != nil {
		return existing, ""
	}
	if rot.Mode == model.CredentialRotationModeSplit {
		// 拆分模式的候選是那組秘密的唯一副本；它不見了就沒有可推的東西
		return nil, model.ChangeSecretReasonNoCredential
	}
	in := CandidateInput{
		AssetID: member.AssetID, AccountID: member.AccountID, AccountUsername: member.Username,
		SecretType: mc.secretType, CredentialID: member.CredentialID,
	}
	if member.TargetVersionID != nil {
		in.TargetVersionID = *member.TargetVersionID
	}
	cand, err := s.candidates.createOwnedInTx(ctx, s.db, in, mc.newPassword, mc.newPrivateKey)
	if err != nil {
		if errors.Is(err, ErrCandidateExists) {
			return nil, model.ChangeSecretReasonCandidatePending
		}
		return nil, model.ChangeSecretReasonCandidatePersistFailed
	}
	return cand, ""
}

// discardUndeliveredCandidate 遠端確定未變更時的候選處置。
//
// 整組模式的候選只是待生效版本的一份副本，清掉它下一輪會依同一個版本重建，故清；
// 拆分模式的候選是那台**唯一**的目標秘密副本——清掉就沒有可以補跑的東西了，故留。
func (s *CredentialRotationService) discardUndeliveredCandidate(rot *model.CredentialRotation,
	cand *model.ChangeSecretCandidate) {

	if rot.Mode == model.CredentialRotationModeSplit {
		return
	}
	_ = s.candidates.Discard(cand.ID)
}

// classifyRotationError 遠端錯誤分流。沿用執行器介面的四類契約，不另立判準。
//
// 回傳的 clean＝「遠端此刻確定不是新秘密」，唯有此時清候選才是安全的。
func classifyRotationError(err error) (string, bool) {
	var localErr *localPreconditionError
	if errors.As(err, &localErr) {
		return localErr.reason, true
	}
	var rejected *remoteRejectedError
	if errors.As(err, &rejected) {
		return rejected.reason, true
	}
	var unknown *remoteStateUnknownError
	if errors.As(err, &unknown) {
		return unknown.reason, false
	}
	return model.ChangeSecretReasonRemoteStateUnknown, false
}

// --- 狀態寫入的四個入口（全部經 transitionMember，不繞過轉移表）---

// transition 於自有交易內套用一次轉移。
func (s *CredentialRotationService) transition(member *model.CredentialRotationMember,
	to string, opt memberTransition) error {

	return s.db.Transaction(func(tx *gorm.DB) error {
		return transitionMember(tx, member, to, opt)
	})
}

// failClean 遠端確定未變更：依是否已逾本輪期限決定重試或終局失敗。
func (s *CredentialRotationService) failClean(rot *model.CredentialRotation,
	member *model.CredentialRotationMember, reason string, run memberRun) {

	next, at := memberBackoffTransition(member, rot.StartedAt)
	if err := s.transition(member, next, memberTransition{
		LastError: reason, BumpAttempt: true, NextAttemptAt: at,
	}); err != nil {
		logMemberTransitionFailure(member, next, err)
		return
	}
	s.recordMember(member, model.ChangeSecretFailed, reason, run)
}

// markUnverified 進入「已下達、未驗證」：候選保留，就位版本不動。
//
// **此台在驗證通過前不可連線**是明示的未驗證窗口，不謊稱舊版仍有效——
// 遠端可能已經是新秘密了，猜錯的代價是一次失敗的登入嘗試與可能的帳號鎖定。
func (s *CredentialRotationService) markUnverified(member *model.CredentialRotationMember, reason string) error {
	err := s.transition(member, model.CredentialMemberChangedUnverified,
		memberTransition{LastError: reason})
	if err != nil {
		logMemberTransitionFailure(member, model.CredentialMemberChangedUnverified, err)
	}
	return err
}

// stayUnverified 驗證仍未通過：維持原狀態、累計次數；逾本輪期限才轉終局失敗。
func (s *CredentialRotationService) stayUnverified(rot *model.CredentialRotation,
	member *model.CredentialRotationMember, reason string, run memberRun) {

	if time.Since(rot.StartedAt) >= candidateRetryDeadline {
		if err := s.transition(member, model.CredentialMemberTerminalFailed,
			memberTransition{LastError: reason, BumpAttempt: true}); err != nil {
			logMemberTransitionFailure(member, model.CredentialMemberTerminalFailed, err)
			return
		}
		s.recordMember(member, model.ChangeSecretUnverified, reason, run)
		return
	}
	next := time.Now().Add(candidateBackoff(member.AttemptCount + 1))
	err := s.db.Model(&model.CredentialRotationMember{}).
		Where("id = ? AND state = ?", member.ID, member.State).
		Updates(map[string]any{
			"last_error":      reason,
			"attempt_count":   member.AttemptCount + 1,
			"next_attempt_at": &next,
		}).Error
	if err != nil {
		logMemberTransitionFailure(member, member.State, err)
		return
	}
	member.LastError = reason
	member.AttemptCount++
	member.NextAttemptAt = &next
	s.recordMember(member, model.ChangeSecretUnverified, reason, run)
}

// commitApplied 驗證通過：於**同一資料庫交易**內更新就位版本、成員狀態、審計與候選。
//
// 拆分模式另有改綁的步驟，故轉交拆分路徑處理。
func (s *CredentialRotationService) commitApplied(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember,
	mc *memberContext, run memberRun) {

	var err error
	if rot.Mode == model.CredentialRotationModeSplit {
		err = s.commitSplitApplied(ctx, rot, member, mc, nil, memberTransition{})
	} else {
		err = s.commitGroupApplied(ctx, rot, member, nil, memberTransition{})
	}
	if err != nil {
		logMemberTransitionFailure(member, model.CredentialMemberApplied, err)
		if errors.Is(err, ErrHostIdentityChanged) {
			s.recordMemberCommitStop(rot, member)
		}
		// 提交失敗＝遠端已是新秘密而庫內沒有記錄它就位；候選必須留著，
		// 否則那把秘密的唯一副本就沒了
		if cand, cerr := s.candidates.FindByAccount(member.AccountID); cerr == nil && cand != nil {
			_, _ = s.candidates.RecordFailure(cand, promoteFailureReason(err))
		}
		s.stayUnverified(rot, member, promoteFailureReason(err), run)
		return
	}
	successReason := ""
	if run.recovery {
		successReason = s.finishRecovery(rot, member)
	}
	s.recordMember(member, model.ChangeSecretSuccess, successReason, run)
}

// finishRecovery 有限驗證成功並提交後：回成功記錄要帶的原因碼（SSH 舊鑰未清則標未完成並告警）。
func (s *CredentialRotationService) finishRecovery(rot *model.CredentialRotation,
	member *model.CredentialRotationMember) string {

	if !s.recoveryCleanupPending(member) {
		return ""
	}
	if s.stopNotify != nil {
		s.stopNotify("改密候選已驗證但舊公鑰待清理",
			fmt.Sprintf("rotation=%d asset_id=%d account=%s 已於失權後完成有限驗證，目標機上的舊公鑰尚未清除，請具權者手動處置",
				rot.ID, member.AssetID, member.Username))
	}
	return model.ChangeSecretReasonRecoveredCleanupPending
}

// commitGroupApplied 整組模式的就位交易。confirm 非 nil（人工承接）時，主機身分以承接紀錄為預期，
// 並在同一交易內條件式消耗該紀錄：受影響列數不為 1 即整筆回滾。
func (s *CredentialRotationService) commitGroupApplied(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember,
	confirm *model.CredentialHostIdentityConfirmation, applied memberTransition) error {

	userID, operator := model.UserFromContext(ctx)
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, member.AssetID); err != nil {
			return err
		}
		// 主機身分比對在資產列鎖之後、任何憑證列之前，以交易內重讀的成員列綁定快照為準
		// （呼叫端手上的成員物件可能是綁定前的複本）
		m, err := loadRotationMember(tx, rot.ID, member.ID)
		if err != nil {
			return err
		}
		if err := assertMemberHostIdentityTx(tx, m, true, confirm); err != nil {
			return err
		}
		cred, err := lockCredentialRow(tx, member.CredentialID)
		if err != nil {
			return err
		}
		// 遠端往返期間待生效版本可能已被操作者宣告的密文取代：此時把就位版本
		// 改寫成本輪的目標，等於在沒有任何提示的情況下蓋掉他剛宣告的那一組。
		// 回錯即走「已下達未驗證」的保留路徑，候選不丟
		if err := assertRotationTargetStillPending(tx, rot); err != nil {
			return err
		}
		consumedByTransition := isExpiredMemberState(m.State)
		if err := transitionMember(tx, m, model.CredentialMemberApplied, applied); err != nil {
			return err
		}
		if err := deleteAccountCandidate(tx, m.AccountID); err != nil {
			return err
		}
		if err := consumeConfirmationHooked(tx, confirm, consumedByTransition, s.confirmedCommitHook); err != nil {
			return err
		}
		if err := writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    credentialOpRotate,
			Scope:        cred.Scope,
			Fields:       []string{"effective_version_id"},
			AssetID:      m.AssetID,
			AccountID:    m.AccountID,
		}, userID, operator); err != nil {
			return err
		}
		member.State = m.State
		member.AppliedAt = m.AppliedAt
		return s.convergeIfComplete(tx, rot, cred)
	})
}

// convergeIfComplete 全部成員就位後於同一交易收斂（服務層入口）。
func (s *CredentialRotationService) convergeIfComplete(tx *gorm.DB,
	rot *model.CredentialRotation, cred *model.Credential) error {

	return convergeRotationIfComplete(tx, rot, cred)
}

// memberBindingIsLive 該成員的掛載此刻是否仍在，且仍引用本憑證。
//
// 收斂判定的分母是**當下存活的掛載**而不是啟動時的成員快照：未同步期間唯一被
// 允許的拓撲變更是卸載（死主機要能移除，否則沒有出口），被卸下的那一台不該
// 繼續擋著其餘各台的收斂——它已經不由本系統以這組秘密登入了。
func memberBindingIsLive(tx *gorm.DB, credentialID uint,
	member *model.CredentialRotationMember) (bool, error) {

	var count int64
	err := tx.Model(&model.AssetAccount{}).
		Where("id = ? AND asset_id = ? AND credential_id = ?",
			member.AccountID, member.AssetID, credentialID).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("查詢成員掛載失敗: %w", err)
	}
	return count > 0, nil
}

// convergeRotationIfComplete 存活掛載全數就位後於同一交易收斂。
//
// 整組模式：待生效版本提升為現行版本、清除待生效與進行中的指標，聚合態回到 idle。
// 拆分模式沒有整組的目標版本（每台不同），只清除進行中的指標。
//
// **零成員就位時不提升現行版本**：那一版沒有任何一台確認收下過，把它宣告成
// 憑證的現行秘密等於憑空斷言遠端狀態。此時只清掉待生效版本讓憑證收束。
func convergeRotationIfComplete(tx *gorm.DB,
	rot *model.CredentialRotation, cred *model.Credential) error {

	members, err := rotationMembers(tx, rot.ID)
	if err != nil {
		return err
	}
	applied := 0
	for i := range members {
		if members[i].State == model.CredentialMemberApplied {
			applied++
			continue
		}
		live, lerr := memberBindingIsLive(tx, cred.ID, &members[i])
		if lerr != nil {
			return lerr
		}
		if live {
			return nil
		}
	}
	now := time.Now()
	if err := tx.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
		Updates(map[string]any{
			"status":      model.CredentialRotationCompleted,
			"finished_at": &now,
		}).Error; err != nil {
		return fmt.Errorf("更新輪替狀態失敗: %w", err)
	}
	updates := map[string]any{"active_rotation_id": nil}
	if rot.Mode == model.CredentialRotationModeGroup && rot.TargetVersionID != nil {
		if applied > 0 {
			updates["current_version_id"] = *rot.TargetVersionID
		}
		updates["pending_version_id"] = nil
	}
	if err := tx.Model(&model.Credential{}).Where("id = ?", cred.ID).
		Updates(updates).Error; err != nil {
		return fmt.Errorf("收斂輪替狀態失敗: %w", err)
	}
	return nil
}

// deleteAccountCandidate 就位後清除該掛載的候選（同一交易）。
//
// **順序是「先就位、後刪列」**：就位後刪列失敗只會讓下一輪重試再提交一次同一個值；
// 反過來先刪列則在就位失敗時失去唯一副本，帳號永久鎖死。
func deleteAccountCandidate(tx *gorm.DB, accountID uint) error {
	if err := tx.Where("account_id = ?", accountID).
		Delete(&model.ChangeSecretCandidate{}).Error; err != nil {
		return fmt.Errorf("清除候選失敗: %w", err)
	}
	return nil
}

// logMemberTransitionFailure 狀態寫入失敗只進後端 log。
//
// 遠端原文與秘密材料一律不進本行：err 可能挾帶目標機回吐的攻擊者可控字串。
func logMemberTransitionFailure(member *model.CredentialRotationMember, to string, err error) {
	log.Printf("[CredentialRotation] 成員狀態寫入失敗 member=%d to=%s err=%s",
		member.ID, to, sanitizeRemoteMessage(err.Error()))
}

func (m *memberContext) Destroy() {
	if m != nil {
		m.old.Destroy()
		m.newPassword.Destroy()
		m.newPrivateKey.Destroy()
	}
}
