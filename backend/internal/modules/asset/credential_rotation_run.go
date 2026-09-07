package asset

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

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
		unlock := lockRotationAccount(member.AccountID)
		err := s.db.Transaction(func(tx *gorm.DB) error {
			m, lerr := loadRotationMember(tx, rot.ID, memberID)
			if lerr != nil {
				return lerr
			}
			return transitionMember(tx, m, model.CredentialMemberQueued, memberTransition{})
		})
		unlock()
		if err != nil {
			return err
		}
	case model.CredentialMemberApplied:
		// 本輪終態：補跑一台已經就位的機器只會多一次遠端往返
		return nil
	}
	s.runMember(ctx, rot, memberID, origin)
	return nil
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
		s.deliverMember(ctx, rot, member, run)
	case model.CredentialMemberChangedUnverified:
		s.verifyMember(ctx, rot, member, run)
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
	newPassword   string
	newPrivateKey string
	secretType    string
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
	// 釘住帳號名：成員快照與現況不符即代表這一列已代表另一個系統身分，
	// 把新秘密推上去等於改錯對象
	if old.Username != member.Username {
		return nil, model.ChangeSecretReasonAccountChanged
	}
	if old.Password == "" && old.PrivateKey == "" {
		return nil, model.ChangeSecretReasonNoCredential
	}

	next, reason := s.targetSecret(ctx, rot, member)
	if reason != "" {
		return nil, reason
	}
	secretType := next.SecretType
	if secretType == "" {
		secretType = model.ChangeSecretTypePassword
	}
	if model.IsWindowsRotationChannel(channel) && secretType == model.ChangeSecretTypeSSHKey {
		return nil, model.ChangeSecretReasonSecretTypeUnsupported
	}
	return &memberContext{
		target: rotationTarget{
			asset:      asset,
			channel:    channel,
			username:   member.Username,
			secretType: secretType,
			addr:       rotationAddr(asset, channel),
			hostKeyCB:  s.hostKeys.Callback(member.AssetID),
		},
		logTarget: changeSecretTarget{
			assetID: member.AssetID, accountID: member.AccountID,
			username: member.Username, channel: channel,
		},
		exec:          s.executors(channel),
		old:           old,
		newPassword:   next.Password,
		newPrivateKey: next.PrivateKey,
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
		return &ResolvedCredential{
			SecretType: cand.SecretType,
			Password:   secret.Password,
			PrivateKey: secret.PrivateKey,
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

// deliverMember 對遠端下達新秘密並驗證。
func (s *CredentialRotationService) deliverMember(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember, run memberRun) {

	if err := s.transition(member, model.CredentialMemberChanging, memberTransition{}); err != nil {
		return
	}
	mc, reason := s.prepareMember(ctx, rot, member)
	if reason != "" {
		s.failClean(rot, member, reason, run)
		return
	}

	cand, reason := s.ensureCandidate(ctx, rot, member, mc)
	if reason != "" {
		s.failClean(rot, member, reason, run)
		return
	}

	if mc.secretType == model.ChangeSecretTypeSSHKey {
		s.deliverKey(ctx, rot, member, mc, cand, run)
		return
	}
	s.deliverPassword(ctx, rot, member, mc, cand, run)
}

// deliverPassword 密碼型別：下達 → 標記已下達 → 以新密驗證。
func (s *CredentialRotationService) deliverPassword(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember,
	mc *memberContext, cand *model.ChangeSecretCandidate, run memberRun) {

	oldSecret := mc.old.Password
	if err := mc.exec.Rotate(ctx, mc.target, oldSecret, mc.newPassword); err != nil {
		logRemoteCause(mc.logTarget, "改密失敗", err)
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
	_ = s.candidates.MarkApplied(cand.ID)
	if err := s.markUnverified(member, ""); err != nil {
		return
	}
	if err := mc.exec.Verify(ctx, mc.target, mc.newPassword); err != nil {
		logRemoteCause(mc.logTarget, "新密驗證失敗", err)
		_, _ = s.candidates.RecordFailure(cand, model.ChangeSecretReasonVerifyFailed)
		s.stayUnverified(rot, member, model.ChangeSecretReasonVerifyFailed, run)
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
	mc *memberContext, cand *model.ChangeSecretCandidate, run memberRun) {

	newLine, err := PublicLineFromPrivateKey(mc.newPrivateKey)
	if err != nil {
		s.failClean(rot, member, model.ChangeSecretReasonKeypairGenerateFailed, run)
		return
	}
	previousLine := ""
	if mc.old.PrivateKey != "" {
		if line, lerr := PublicLineFromPrivateKey(mc.old.PrivateKey); lerr == nil {
			previousLine = line
		}
	}
	// 既有金鑰（含使用者自放的）一律保留：整組輪替換的是本系統推送的那一把，
	// 順手清掉別人放的鑰會讓管理者失去自己的入口，而他的操作裡沒有一步表達過這個意思
	err = s.keyApplier(ctx, mc.exec, mc.target, mc.logTarget,
		mc.old.Password, mc.old.PrivateKey, mc.newPrivateKey, newLine, previousLine,
		model.KeyStrategyAppendReplace,
		func() { _ = s.candidates.MarkApplied(cand.ID) })
	if err != nil {
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
		return
	}
	if err := s.markUnverified(member, ""); err != nil {
		return
	}
	s.commitApplied(ctx, rot, member, mc, run)
}

// verifyMember 對停在「已下達、未驗證」的成員再驗一次。
//
// **不以舊秘密回探來分辨「遠端沒改成」**：那會對目標機多打一輪認證，而分辨出來
// 也不改變處置（不採自動回滾）。
func (s *CredentialRotationService) verifyMember(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember, run memberRun) {

	mc, reason := s.prepareMember(ctx, rot, member)
	if reason != "" {
		s.stayUnverified(rot, member, reason, run)
		return
	}
	newSecret := mc.newPassword
	if mc.secretType == model.ChangeSecretTypeSSHKey {
		newSecret = mc.newPrivateKey
	}
	if err := mc.exec.Verify(ctx, mc.target, newSecret); err != nil {
		logRemoteCause(mc.logTarget, "補跑驗證失敗", err)
		if cand, cerr := s.candidates.FindByAccount(member.AccountID); cerr == nil && cand != nil {
			_, _ = s.candidates.RecordFailure(cand, model.ChangeSecretReasonRetryLoginFailed)
		}
		s.stayUnverified(rot, member, model.ChangeSecretReasonRetryLoginFailed, run)
		return
	}
	s.commitApplied(ctx, rot, member, mc, run)
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
	if mc.secretType == model.ChangeSecretTypeSSHKey {
		in.PrivateKey = mc.newPrivateKey
	} else {
		in.Password = mc.newPassword
	}
	cand, err := s.candidates.Create(ctx, in)
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
		err = s.commitSplitApplied(ctx, rot, member, mc)
	} else {
		err = s.commitGroupApplied(ctx, rot, member)
	}
	if err != nil {
		logMemberTransitionFailure(member, model.CredentialMemberApplied, err)
		// 提交失敗＝遠端已是新秘密而庫內沒有記錄它就位；候選必須留著，
		// 否則那把秘密的唯一副本就沒了
		if cand, cerr := s.candidates.FindByAccount(member.AccountID); cerr == nil && cand != nil {
			_, _ = s.candidates.RecordFailure(cand, model.ChangeSecretReasonPromoteFailed)
		}
		s.stayUnverified(rot, member, model.ChangeSecretReasonPromoteFailed, run)
		return
	}
	s.recordMember(member, model.ChangeSecretSuccess, "", run)
}

// commitGroupApplied 整組模式的就位交易。
func (s *CredentialRotationService) commitGroupApplied(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember) error {

	userID, operator := model.UserFromContext(ctx)
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, member.AssetID); err != nil {
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
		m, err := loadRotationMember(tx, rot.ID, member.ID)
		if err != nil {
			return err
		}
		if err := transitionMember(tx, m, model.CredentialMemberApplied, memberTransition{}); err != nil {
			return err
		}
		if err := deleteAccountCandidate(tx, m.AccountID); err != nil {
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
