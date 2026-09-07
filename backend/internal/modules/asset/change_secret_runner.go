package asset

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/branding"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

const changeSecretDialTimeout = 10 * time.Second

// ChangeSecretRunner 改密執行器。
//
// 執行單位是**帳號**而非資產：計劃的（資產集 × 帳號範圍）展開為帳號清單，
// 逐帳號隔離錯誤。兩種秘密型別共用同一套可靠性語義——
// 候選先落庫 → 動遠端 → 驗證 → 驗證成功才提交本地憑證。
type ChangeSecretRunner struct {
	db           *gorm.DB
	assetService *AssetService
	candidates   *ChangeSecretCandidateService
	hostKeys     *HostKeyService
	notifier     *audit.AlertNotifier

	// executors 依通道取執行器。**可換**是為了讓狀態機的測試不必真的連上任何
	// 目標機——選路與三態處理是本結構的責任，遠端協定不是
	executors func(channel string) rotationExecutor

	// rotations 輪替引擎；nil＝尚未接線。
	//
	// 共用憑證的成員不得走單帳號路徑：那條路徑會在共用憑證上追加一個只有一台
	// 主機吃得到的版本並把它設成現行版本，其餘成員的憑證庫狀態自此說謊。
	// 未接線時一律跳過並記原因碼，不退回單帳號路徑
	rotations *CredentialRotationService
}

// WithRotationService 接上輪替引擎（組裝根注入）。
func (r *ChangeSecretRunner) WithRotationService(rotations *CredentialRotationService) *ChangeSecretRunner {
	r.rotations = rotations
	return r
}

// NewChangeSecretRunner 建立執行器
func NewChangeSecretRunner(db *gorm.DB, assetService *AssetService,
	candidates *ChangeSecretCandidateService, hostKeys *HostKeyService, notifier *audit.AlertNotifier) *ChangeSecretRunner {
	return &ChangeSecretRunner{
		db: db, assetService: assetService,
		candidates: candidates, hostKeys: hostKeys, notifier: notifier,
		executors: rotationExecutorFor,
	}
}

// changeSecretTarget 單一改密目標（資產 × 帳號）
type changeSecretTarget struct {
	assetID   uint
	accountID uint
	username  string
	// channel 推導後的有效改密通道；在 resolveTargets 一次算定，
	// 其後全程沿用同一個值（執行中途重算會讓選路與記錄不同源）
	channel string
	// credentialID／credentialName 執行當下該掛載引用的憑證快照（記錄與候選各存一份）
	credentialID   uint
	credentialName string
	// sharedCredential 該掛載引用的是共用憑證
	sharedCredential bool
}

// rotationJob 一次執行的設定來源。
//
// 計劃與批次改密走同一條狀態機，差別只在「設定從哪裡來」：計劃帶排程與資產集合，
// 批次帶帳號名與一次性的目標選擇。把兩者翻成同一個純值再交給狀態機，
// resolveTargets／runTarget 就不必認識任何一種來源。
type rotationJob struct {
	// planID／batchID 記錄與候選的來源；恰一個非 0
	planID  uint
	batchID uint
	// source 告警內容裡的來源識別（計劃名或批次識別）
	source string
	// scope 帳號範圍：計劃沿其設定，批次為單一帳號名
	scope       model.AccountScope
	secretType  string
	keyStrategy string
	policy      PasswordPolicy
	// fixedPassword 非空＝所有目標使用同一組新密碼（批次的整批同一組模式），
	// 空＝每個目標各自隨機
	fixedPassword string

	// targetKind／targetCredentialID 計劃的目標種類與目標憑證（批次恆為帳號目標）
	targetKind         string
	targetCredentialID uint

	// sharedCredentialID／sharedVersionID 整批同一組模式為本批次建立的具名共用憑證
	// 與其密文版本；成功的目標改綁到它並就位該版本
	sharedCredentialID   uint
	sharedVersionID      uint
	sharedCredentialName string
}

// jobFromPlan 把計劃翻成執行設定；行為與直接讀計劃逐項相同
func jobFromPlan(plan *model.ChangeSecretPlan) rotationJob {
	job := rotationJob{
		planID:      plan.ID,
		source:      "plan=" + plan.Name,
		scope:       model.AccountScope(PlanAccountScope(plan)),
		secretType:  normalizeSecretType(plan.SecretType),
		keyStrategy: plan.KeyStrategy,
		policy:      PolicyFromPlan(plan),
		targetKind:  plan.TargetKind,
	}
	if job.targetKind == "" {
		job.targetKind = model.PlanTargetAccount
	}
	if plan.TargetCredentialID != nil {
		job.targetCredentialID = *plan.TargetCredentialID
	}
	return job
}

// RunPlan 執行計劃：逐帳號隔離錯誤，單一失敗不中斷批次
func (r *ChangeSecretRunner) RunPlan(plan *model.ChangeSecretPlan) []model.ChangeSecretRecord {
	job := jobFromPlan(plan)
	if job.targetKind == model.PlanTargetCredential {
		return r.runCredentialTarget(job)
	}
	return r.run(job, AssetIDList(plan))
}

// runCredentialTarget 以憑證為目標的計劃：整組改密，成員集合＝該憑證當下的全部掛載。
//
// **不另造排程器**：cron、啟用旗標、密碼策略與適用天數全部沿用計劃既有的欄位，
// 目標種類只決定「要改的是哪一組東西」。
func (r *ChangeSecretRunner) runCredentialTarget(job rotationJob) []model.ChangeSecretRecord {
	if job.targetCredentialID == 0 {
		log.Printf("[ChangeSecret] 以憑證為目標的計劃沒有目標憑證 plan=%d", job.planID)
		return nil
	}
	if r.rotations == nil {
		log.Printf("[ChangeSecret] 輪替引擎未接線，略過憑證目標計劃 plan=%d", job.planID)
		return nil
	}
	ctx := context.Background()
	rot, err := r.rotations.Start(ctx, job.targetCredentialID, StartRotationRequest{Policy: job.policy})
	if err != nil {
		log.Printf("[ChangeSecret] 整組改密啟動失敗 plan=%d credential=%d err=%v",
			job.planID, job.targetCredentialID, err)
		return nil
	}
	records, err := r.rotations.RunFor(ctx, rot.ID, RotationRecordOrigin{PlanID: job.planID})
	if err != nil {
		log.Printf("[ChangeSecret] 整組改密推進失敗 plan=%d rotation=%d err=%v", job.planID, rot.ID, err)
	}
	r.alertFailures(job, records)
	return records
}

// alertFailures 對失敗與狀態不可知的記錄逐筆推送告警（與逐帳號路徑同一條通道）。
func (r *ChangeSecretRunner) alertFailures(job rotationJob, records []model.ChangeSecretRecord) {
	for i := range records {
		if records[i].Status == model.ChangeSecretFailed || records[i].Status == model.ChangeSecretUnverified {
			r.alertFailure(job, records[i])
		}
	}
}

// RunBatch 執行批次：對每台目標資產以批次的帳號名解析帳號，逐目標沿計劃的
// 狀態機執行；全部處理完後寫回計數，並判定本批次建立的共用憑證是否轉回專用。
func (r *ChangeSecretRunner) RunBatch(batch *model.ChangeSecretBatch, assetIDs []uint) []model.ChangeSecretRecord {
	job, err := r.jobFromBatch(batch, assetIDs)
	if err != nil {
		// 整批同一組的密碼產生失敗：沒有任何遠端被觸碰，每台各記一筆乾淨失敗
		log.Printf("[ChangeSecret] 批次密碼產生失敗 batch=%d err=%v", batch.ID, err)
		var records []model.ChangeSecretRecord
		for _, assetID := range assetIDs {
			records = append(records, r.save(model.ChangeSecretRecord{
				BatchID: batch.ID, AssetID: assetID, SecretType: model.ChangeSecretTypePassword,
				Status: model.ChangeSecretFailed, Error: model.ChangeSecretReasonPasswordGenerateFailed,
				ExecutedAt: time.Now(),
			}))
		}
		completeBatch(r.db, batch.ID, records)
		return records
	}
	// 上一輪尚未收斂的憑證，本批次一律不碰（兩種密碼模式皆然）
	staleRecords, blocked := r.skipOutOfSyncBindings(job, assetIDs)
	// 每台各自隨機時，掛在共用憑證上的目標改走拆分輪替：在共用憑證上追加一個
	// 只有一台吃得到的版本會讓其餘成員的憑證庫狀態說謊
	splitRecords, routed := r.runSharedMembersSplit(job, remainingAssetIDs(assetIDs, blocked))
	for id := range blocked {
		routed[id] = true
	}
	records := append([]model.ChangeSecretRecord(nil), staleRecords...)
	records = append(records, splitRecords...)
	records = append(records, r.run(job, remainingAssetIDs(assetIDs, routed))...)
	completeBatch(r.db, batch.ID, records)
	settleBatchSharedCredential(r.db, job.sharedCredentialID)
	return records
}

// run 對資產集合逐台、逐帳號執行；任何錯誤只入記錄
func (r *ChangeSecretRunner) run(job rotationJob, assetIDs []uint) []model.ChangeSecretRecord {
	var records []model.ChangeSecretRecord
	for _, assetID := range assetIDs {
		targets, skipRec := r.resolveTargets(job, assetID)
		if skipRec != nil {
			records = append(records, r.save(*skipRec))
			continue
		}
		for _, tgt := range targets {
			rec := r.runTarget(job, tgt)
			records = append(records, rec)
			if rec.Status == model.ChangeSecretFailed || rec.Status == model.ChangeSecretUnverified {
				r.alertFailure(job, rec)
			}
		}
	}
	return records
}

// resolveTargets 把（資產 × 帳號範圍）展開為帳號清單。
// 回傳非 nil 的 record 代表整台資產層級即被跳過（非 SSH、無帳號、讀取失敗）
func (r *ChangeSecretRunner) resolveTargets(job rotationJob, assetID uint) ([]changeSecretTarget, *model.ChangeSecretRecord) {
	base := model.ChangeSecretRecord{
		PlanID: job.planID, BatchID: job.batchID, AssetID: assetID,
		SecretType: job.secretType, ExecutedAt: time.Now(),
	}
	asset, err := r.assetService.GetByID(assetID)
	if err != nil {
		base.Status = model.ChangeSecretFailed
		base.Error = model.ChangeSecretReasonAssetLookupFailed
		return nil, &base
	}
	// 改密通道決定「這台機器改不改得了密、怎麼改」。
	//
	// 兩種跳過刻意分碼：協定本身不在改密射程內（資料庫、VNC、K8s——沒有作業系統
	// 帳號可換）回 PROTOCOL_UNSUPPORTED；協定改得了密但這台沒設定通道
	//（rdp 資產預設如此）回 CHANNEL_NOT_CONFIGURED。前者無事可做，
	// 後者是一個設定動作就能解決的狀態，混為一碼會讓管理員看不出差別。
	channel := asset.EffectiveRotationChannel()
	if channel == model.RotationChannelNone {
		base.Status = model.ChangeSecretSkipped
		if asset.Protocol == model.ProtocolSSH || asset.Protocol == model.ProtocolRDP {
			base.Error = model.ChangeSecretReasonChannelNotConfigured
		} else {
			base.Error = model.ChangeSecretReasonProtocolUnsupported
		}
		return nil, &base
	}
	// Windows 通道沒有等價於 authorized_keys 的金鑰模型（其 ACL 與檔案位置另成一套），
	// 本版不做。誠實跳過勝過以密碼路徑冒充成功
	if model.IsWindowsRotationChannel(channel) && job.secretType == model.ChangeSecretTypeSSHKey {
		base.Status = model.ChangeSecretSkipped
		base.Error = model.ChangeSecretReasonSecretTypeUnsupported
		return nil, &base
	}
	var accounts []model.AssetAccount
	if err := r.db.Where("asset_id = ?", assetID).
		Order("is_default DESC, username ASC, id ASC").Find(&accounts).Error; err != nil {
		base.Status = model.ChangeSecretFailed
		base.Error = model.ChangeSecretReasonAccountLookupFailed
		return nil, &base
	}
	scope := job.scope
	// 憑證快照一次批次取回：記錄與候選都要帶「執行當下這台用的是哪一筆憑證」，
	// 逐目標回查會讓一次計劃執行多打一輪查詢
	snapshots, err := accountsCredentialSnapshots(r.db, accounts)
	if err != nil {
		base.Status = model.ChangeSecretFailed
		base.Error = model.ChangeSecretReasonCredentialLoadFailed
		return nil, &base
	}
	var targets []changeSecretTarget
	for _, acc := range accounts {
		if !scope.Contains(acc.Username) {
			continue
		}
		snap := snapshots[acc.ID]
		targets = append(targets, changeSecretTarget{
			assetID: assetID, accountID: acc.ID, username: acc.Username, channel: channel,
			credentialID: snap.CredentialID, credentialName: snap.Name,
			sharedCredential: snap.Shared,
		})
	}
	if len(targets) == 0 {
		base.Status = model.ChangeSecretSkipped
		base.Error = model.ChangeSecretReasonNoAccountInScope
		return nil, &base
	}
	return targets, nil
}

// runTarget 單帳號改密；任何錯誤僅入 record 不上拋
func (r *ChangeSecretRunner) runTarget(job rotationJob, tgt changeSecretTarget) model.ChangeSecretRecord {
	// per-account 互斥：同一帳號的兩次改密同時跑，會有兩個候選互相覆蓋遠端狀態。
	// 鎖表與共用憑證的整組輪替共用（見 lockRotationAccount）——兩套引擎各持一份
	// 鎖表等於沒有互斥。本產品現為單實例部署，候選表的 account_id 唯一索引是最終防線
	defer lockRotationAccount(tgt.accountID)()

	rec := model.ChangeSecretRecord{
		PlanID: job.planID, BatchID: job.batchID, AssetID: tgt.assetID,
		AccountID: tgt.accountID, AccountUsername: tgt.username,
		SecretType: job.secretType, ExecutedAt: time.Now(),
		CredentialID: tgt.credentialID, CredentialName: tgt.credentialName,
	}
	finish := func(status, errMsg string) model.ChangeSecretRecord {
		rec.Status = status
		rec.Error = errMsg
		return r.save(rec)
	}

	// 掛在共用憑證上的目標不走本路徑：在共用憑證上追加一個只有這一台吃得到的版本
	// 並把它設成現行版本，會讓其餘成員的憑證庫狀態說謊。整批同一組模式例外——
	// 它的目標一律改綁到本批次新建的共用憑證，原憑證的其餘成員不受影響
	if tgt.sharedCredential && job.sharedCredentialID == 0 {
		return finish(model.ChangeSecretSkipped,
			model.ChangeSecretReasonSharedCredentialTargetRequired)
	}

	// 該帳號已有未驗證候選：不疊加第二個未知狀態
	existing, err := r.candidates.FindByAccount(tgt.accountID)
	if err != nil {
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonCandidateQueryFailed)
	}
	if existing != nil {
		return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonCandidatePending)
	}

	// 開頭解析帳號憑證一次並**釘住 AccountID**：其後讀憑證、動遠端、憑證寫回
	// 全程作用於同一帳號。若結尾改以 assetID 重解析 default，執行期間管理員切換
	// default 就會把新秘密寫進另一個帳號——遠端已改的那台留著舊憑證（鎖死），
	// 另一台的憑證則被無聲覆蓋
	creds, err := r.assetService.GetWithCredentialsForAccount(tgt.assetID, tgt.accountID)
	if err != nil {
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonCredentialLoadFailed)
	}
	if creds.AccountID != tgt.accountID || creds.Username != tgt.username {
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonAccountChanged)
	}
	if creds.Password == "" && creds.PrivateKey == "" {
		return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonNoCredential)
	}

	rt := rotationTarget{
		asset:      creds.Asset,
		channel:    tgt.channel,
		username:   tgt.username,
		secretType: job.secretType,
		addr:       rotationAddr(creds.Asset, tgt.channel),
		hostKeyCB:  r.hostKeys.Callback(tgt.assetID),
	}
	exec := r.executors(tgt.channel)

	if job.secretType == model.ChangeSecretTypeSSHKey {
		return r.rotateKey(job, tgt, creds, rt, exec, &rec, finish)
	}
	return r.rotatePassword(job, tgt, creds, rt, exec, &rec, finish)
}

// rotatePassword 密碼輪替：chpasswd（憑證經 stdin，不進 argv）
func (r *ChangeSecretRunner) rotatePassword(job rotationJob, tgt changeSecretTarget,
	creds *AssetCredentials, rt rotationTarget, exec rotationExecutor,
	rec *model.ChangeSecretRecord,
	finish func(string, string) model.ChangeSecretRecord) model.ChangeSecretRecord {

	if creds.Password == "" {
		return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonNoPasswordCredential)
	}
	// 整批同一組模式已在批次開頭產生密碼；其餘每個目標各自隨機
	newPassword := job.fixedPassword
	if newPassword == "" {
		generated, err := GeneratePassword(job.policy)
		if err != nil {
			log.Printf("[ChangeSecret] 產生新密碼失敗 asset=%d account=%d err=%v", tgt.assetID, tgt.accountID, err)
			return finish(model.ChangeSecretFailed, model.ChangeSecretReasonPasswordGenerateFailed)
		}
		newPassword = generated
	}

	ctx := context.Background()
	// 候選先於遠端落庫，並帶著轉正後要落到哪一筆憑證的哪一版：整批同一組模式下
	// 那是本批次新建的共用憑證，其餘情形沿掛載當下的憑證（版本於提交時才產生）
	cand, err := r.candidates.Create(ctx, CandidateInput{
		AssetID: tgt.assetID, AccountID: tgt.accountID, AccountUsername: tgt.username,
		PlanID: job.planID, BatchID: job.batchID,
		CredentialID:    candidateCredentialID(job, tgt),
		CredentialName:  candidateCredentialName(job, tgt),
		TargetVersionID: job.sharedVersionID,
		SecretType:      model.ChangeSecretTypePassword, Password: newPassword,
	})
	if err != nil {
		if errors.Is(err, ErrCandidateExists) {
			return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonCandidatePending)
		}
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonCandidatePersistFailed)
	}

	if err := exec.Rotate(ctx, rt, creds.Password, newPassword); err != nil {
		logRemoteCause(tgt, "改密失敗", err)
		// 本地前置驗證失敗＝完全未接觸遠端，遠端狀態並非不可知：清候選走乾淨失敗。
		// 若誤歸為 unverified，候選會一直卡著並擋住該帳號後續全部改密
		var localErr *localPreconditionError
		if errors.As(err, &localErr) {
			_ = r.candidates.Discard(cand.ID)
			return finish(model.ChangeSecretFailed, localErr.reason)
		}
		// 遠端確定未變更（登入被拒、指令非零退出）＝清候選走乾淨失敗；
		// 其他錯誤（連線中斷／逾時）＝遠端狀態不可知，保留候選交給重試
		var rejected *remoteRejectedError
		if errors.As(err, &rejected) {
			_ = r.candidates.Discard(cand.ID)
			return finish(model.ChangeSecretFailed, rejected.reason)
		}
		// 狀態不可知但成因已知（目標自驗失敗且回滾也失敗）：原因碼換成專屬碼，處置不變
		var unknown *remoteStateUnknownError
		if errors.As(err, &unknown) {
			return finish(model.ChangeSecretUnverified, unknown.reason)
		}
		return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonRemoteStateUnknown)
	}
	_ = r.candidates.MarkApplied(cand.ID)

	if err := exec.Verify(ctx, rt, newPassword); err != nil {
		// 本地憑證**不動**，候選保留待重試。硬提交是在猜遠端狀態，
		// 猜錯就把還能用的憑證改壞
		logRemoteCause(tgt, "新密驗證失敗", err)
		_, _ = r.candidates.RecordFailure(cand, model.ChangeSecretReasonVerifyFailed)
		return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonVerifyFailed)
	}

	cand.Applied = true
	if err := r.candidates.Promote(ctx, cand); err != nil {
		logRemoteCause(tgt, "憑證提交失敗", err)
		_, _ = r.candidates.RecordFailure(cand, model.ChangeSecretReasonPromoteFailed)
		return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonPromoteFailed)
	}
	rec.CredentialID = candidateCredentialID(job, tgt)
	rec.CredentialName = candidateCredentialName(job, tgt)
	rec.TargetVersionID = committedVersionID(r.db, tgt.accountID, job.sharedVersionID)
	return finish(model.ChangeSecretSuccess, "")
}

// rotateKey SSH 金鑰輪替：加新 → 驗新 → 刪舊。
//
// **本流程留在 POSIX 側而未收進 rotationExecutor**：它的三段式需要在**同一條
// 已認證的 SFTP 連線**上回寫還原（重新撥號的還原會與舊憑證是否仍有效綁在一起），
// 這條連線的生命週期跨越「動遠端」與「驗證」兩步，無法以 Rotate／Verify 兩次
// 獨立呼叫表達。金鑰輪替也只有 POSIX 通道支援——Windows 通道在 resolveTargets
// 就已跳過，故這裡不會遇到別種執行器。驗證步驟仍走介面，使重試路徑同源。
func (r *ChangeSecretRunner) rotateKey(job rotationJob, tgt changeSecretTarget,
	creds *AssetCredentials, rt rotationTarget, exec rotationExecutor,
	rec *model.ChangeSecretRecord,
	finish func(string, string) model.ChangeSecretRecord) model.ChangeSecretRecord {

	comment := fmt.Sprintf(branding.Slug+"-change-secret-%d-%d", tgt.assetID, tgt.accountID)
	newPrivate, newLine, err := GenerateSSHKeyPair(comment)
	if err != nil {
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonKeypairGenerateFailed)
	}
	// 舊的「本系統推送鑰」：僅當帳號現以私鑰認證時存在
	previousLine := ""
	if creds.PrivateKey != "" {
		if line, err := PublicLineFromPrivateKey(creds.PrivateKey); err == nil {
			previousLine = line
		}
	}

	ctx := context.Background()
	cand, err := r.candidates.Create(ctx, CandidateInput{
		AssetID: tgt.assetID, AccountID: tgt.accountID, AccountUsername: tgt.username,
		PlanID: job.planID, BatchID: job.batchID, SecretType: model.ChangeSecretTypeSSHKey,
		CredentialID: tgt.credentialID, CredentialName: tgt.credentialName,
		PrivateKey: newPrivate, PublicKey: newLine, PreviousPublicKey: previousLine,
	})
	if err != nil {
		if errors.Is(err, ErrCandidateExists) {
			return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonCandidatePending)
		}
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonCandidatePersistFailed)
	}

	if err := applySSHKeyOnTarget(ctx, exec, rt, tgt, creds.Password, creds.PrivateKey,
		newPrivate, newLine, previousLine, job.keyStrategy,
		func() { _ = r.candidates.MarkApplied(cand.ID) }); err != nil {

		// 遠端確定未變更（含還原成功）＝清候選走乾淨失敗；還原也失敗＝狀態不可知，
		// 候選必須留著，它是那把可能已在遠端生效的秘密的唯一副本
		var rejected *remoteRejectedError
		if errors.As(err, &rejected) {
			_ = r.candidates.Discard(cand.ID)
			return finish(model.ChangeSecretFailed, rejected.reason)
		}
		var unknown *remoteStateUnknownError
		if errors.As(err, &unknown) {
			_, _ = r.candidates.RecordFailure(cand, unknown.reason)
			return finish(model.ChangeSecretUnverified, unknown.reason)
		}
		_, _ = r.candidates.RecordFailure(cand, model.ChangeSecretReasonRemoteStateUnknown)
		return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonRemoteStateUnknown)
	}

	cand.Applied = true
	if err := r.candidates.Promote(ctx, cand); err != nil {
		logRemoteCause(tgt, "憑證提交失敗", err)
		_, _ = r.candidates.RecordFailure(cand, model.ChangeSecretReasonPromoteFailed)
		return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonPromoteFailed)
	}
	rec.TargetVersionID = committedVersionID(r.db, tgt.accountID, 0)
	return finish(model.ChangeSecretSuccess, "")
}

// save 落庫記錄；入庫失敗只記 log（記錄失敗不應改變改密結果）
func (r *ChangeSecretRunner) save(rec model.ChangeSecretRecord) model.ChangeSecretRecord {
	if err := r.db.Create(&rec).Error; err != nil {
		log.Printf("[ChangeSecret] record 入庫失敗: plan=%d asset=%d account=%d err=%v",
			rec.PlanID, rec.AssetID, rec.AccountID, err)
	}
	return rec
}

// normalizeSecretType 空值視為密碼（既有計劃無此欄）
func normalizeSecretType(t string) string {
	if t == model.ChangeSecretTypeSSHKey {
		return model.ChangeSecretTypeSSHKey
	}
	return model.ChangeSecretTypePassword
}

// dialSSHPassword 以密碼建立輕量 exec 用連線（不開 PTY）
func dialSSHPassword(addr, user, password string, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: hostKey,
		Timeout:         changeSecretDialTimeout,
	})
}

// dialSSHPrivateKey 以私鑰建立連線（金鑰輪替的驗證步驟）
func dialSSHPrivateKey(addr, user, privatePEM string, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privatePEM))
	if err != nil {
		return nil, fmt.Errorf("解析私鑰失敗: %w", err)
	}
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKey,
		Timeout:         changeSecretDialTimeout,
	})
}

// dialSSHCredentials 以帳號現行憑證登入（私鑰優先，其次密碼）。
//
// 收兩個秘密欄而非整包解析結果：連線與輪替兩條路徑的取密回傳型別不同，
// 讓撥號認識其中一種會逼另一種為了撥號而多轉一次型別。
func dialSSHCredentials(addr, user, password, privateKey string, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	var methods []ssh.AuthMethod
	if privateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}
	if password != "" {
		methods = append(methods, ssh.Password(password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("帳號無可用憑證")
	}
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: hostKey,
		Timeout:         changeSecretDialTimeout,
	})
}

// runChpasswd 執行改密：root 直接 chpasswd；非 root 以 sudo -S 餵舊密提權。
//
// **憑證一律經 session stdin 投遞**，SHALL NOT 進入命令列——目標機的 ps 與
// /proc/<pid>/cmdline 因此看不到任何密碼。後端側亦無子程序（全程行程內 SSH
// 客戶端），故本地 argv／environ 同樣不持有憑證。
func runChpasswd(client *ssh.Client, user, oldPassword, newPassword string) error {
	// chpasswd 自 stdin 逐行讀 user:password；user/新密含換行會拆出額外條目
	// 改到非目標帳號（stdin 注入），故在組裝 entry 前嚴格拒絕控制字元
	//
	// 本地前置驗證在**完全未接觸遠端**時失敗，故以專屬型別回傳：呼叫端據此走
	// 乾淨 failed，不得落入「狀態不可知」分支（那會留下擋住該帳號的候選）
	if strings.ContainsAny(user, "\n\r\x00:") {
		return &localPreconditionError{reason: model.ChangeSecretReasonInvalidAccountName}
	}
	if strings.ContainsAny(newPassword, "\n\r\x00") {
		return &localPreconditionError{reason: model.ChangeSecretReasonInvalidNewSecret}
	}

	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	entry := fmt.Sprintf("%s:%s", user, newPassword)
	var cmd string
	var stdin string
	if user == "root" {
		cmd = "chpasswd"
		stdin = entry + "\n"
	} else {
		// sudo -S 自 stdin 讀密碼；chpasswd 條目為 stdin 的第二行
		cmd = "sudo -S -p '' sh -c 'chpasswd'"
		stdin = oldPassword + "\n" + entry + "\n"
	}

	sess.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if err := sess.Run(cmd); err != nil {
		// 保留 *ssh.ExitError 型別供可知性分流；只在有 stderr 時附上訊息
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s: %w", sanitizeRemoteMessage(msg), err)
		}
		return err
	}
	return nil
}

// sanitizeRemoteMessage 遠端 stderr 只取首行並截長（避免把整段輸出寫進記錄欄）
func sanitizeRemoteMessage(msg string) string {
	if idx := strings.IndexAny(msg, "\r\n"); idx > 0 {
		msg = msg[:idx]
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// localPreconditionError 本地前置驗證失敗（完全未接觸遠端）。
// reason 為 model 的原因碼常數，直接落 record.error
// cause 只進後端 log，SHALL NOT 落庫或外送（同 remoteRejectedError 的理由）
type localPreconditionError struct {
	reason string
	cause  error
}

func (e *localPreconditionError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.reason, e.cause)
	}
	return e.reason
}

func (e *localPreconditionError) Unwrap() error { return e.cause }

// logRemoteCause 遠端／庫原文的**唯一**出口：只進後端 log，不落庫、不外送。
//
// 安全紅線：err 可能挾帶目標機回吐的攻擊者可控字串（stderr、SSH 交握訊息），
// 其中可能夾帶本輪產生的新秘密（目標機把收到的 stdin 回吐即可）。這條字串
// SHALL NOT 進入 record.error／candidate.last_error／告警通道。
func logRemoteCause(tgt changeSecretTarget, stage string, err error) {
	log.Printf("[ChangeSecret] %s asset=%d account=%d user=%s cause=%s",
		stage, tgt.assetID, tgt.accountID, tgt.username, sanitizeRemoteMessage(err.Error()))
}

// alertFailure 失敗推送告警通道（復用 CommandAlert 通道格式）。
//
// 告警離開產品邊界（webhook／Slack），故內容一律是機器碼＋固定文案；
// 遠端原文只留在後端 log
func (r *ChangeSecretRunner) alertFailure(job rotationJob, rec model.ChangeSecretRecord) {
	if r.notifier == nil {
		return
	}
	r.notifier.Enqueue(model.CommandAlert{
		RuleName: "改密計劃失敗",
		Command: fmt.Sprintf("%s asset_id=%d account=%s reason=%s（詳細遠端訊息見伺服器日誌）",
			job.source, rec.AssetID, rec.AccountUsername, rec.Error),
		Severity: "high",
	})
}

// applySSHKeyOnTarget SSH 金鑰輪替的遠端段：加新 → 驗新 → 刪舊。
//
// **本流程留在 POSIX 側而未收進 rotationExecutor**：它的三段式需要在**同一條
// 已認證的 SFTP 連線**上回寫還原（重新撥號的還原會與舊憑證是否仍有效綁在一起），
// 這條連線的生命週期跨越「動遠端」與「驗證」兩步，無法以 Rotate／Verify 兩次
// 獨立呼叫表達。金鑰輪替也只有 POSIX 通道支援——呼叫端已先跳過 Windows 通道，
// 故這裡不會遇到別種執行器。驗證步驟仍走介面，使重試路徑同源。
//
// **單一實作供兩條路徑共用**：逐帳號改密與共用憑證的整組輪替若各寫一份三段式，
// 兩份會在「還原失敗要算成哪一種」這件事上慢慢長出差異，而那正是最不該有差異的地方。
//
// onDelivered 於新鑰寫入 authorized_keys 之後、驗證之前呼叫：那一刻起遠端可能已經
// 接受新鑰，呼叫端據此標記候選已下達。
//
// 錯誤沿用執行器介面的分流契約：
//
//	*remoteRejectedError     遠端確定未變更（含驗證失敗但已還原）→ 清候選、乾淨失敗
//	*remoteStateUnknownError 已寫入但還原也失敗 → 保留候選、狀態不可知
func applySSHKeyOnTarget(ctx context.Context, exec rotationExecutor, rt rotationTarget,
	tgt changeSecretTarget, oldPassword, oldPrivateKey, newPrivate, newLine, previousLine,
	keyStrategy string, onDelivered func()) error {

	client, err := dialSSHCredentials(rt.addr, rt.username, oldPassword, oldPrivateKey, rt.hostKeyCB)
	if err != nil {
		logRemoteCause(tgt, "舊憑證登入失敗", err)
		return &remoteRejectedError{reason: model.ChangeSecretReasonOldCredentialLoginFailed, cause: err}
	}
	defer client.Close()

	sc, err := openSFTP(client)
	if err != nil {
		logRemoteCause(tgt, "開啟 SFTP 失敗", err)
		return &remoteRejectedError{reason: model.ChangeSecretReasonSFTPOpenFailed, cause: err}
	}
	defer sc.Close()

	current, err := ReadAuthorizedKeys(sc)
	if err != nil {
		logRemoteCause(tgt, "讀取 authorized_keys 失敗", err)
		return &remoteRejectedError{reason: model.ChangeSecretReasonAuthorizedKeysReadFailed, cause: err}
	}

	// 加新：預設策略下既有金鑰（含使用者自放的）全部保留
	next := AppendKeyLine(current.Original, newLine)
	if keyStrategy == model.KeyStrategyExclusive {
		next = newLine + "\n"
	}
	if err := WriteAuthorizedKeys(sc, next); err != nil {
		logRemoteCause(tgt, "寫入 authorized_keys 失敗", err)
		return &remoteRejectedError{reason: model.ChangeSecretReasonAuthorizedKeysWriteFailed, cause: err}
	}
	if onDelivered != nil {
		onDelivered()
	}

	// 驗新：以新私鑰對同一目標實連。此步同時是 AuthorizedKeysFile 指向他處、
	// 檔案唯讀等狀況的偵測手段——加了鑰卻登不進去即代表該檔未被 sshd 採用
	if err := exec.Verify(ctx, rt, newPrivate); err != nil {
		logRemoteCause(tgt, "新鑰驗證失敗", err)
		// 還原：在**同一條已認證的 SFTP 連線**上回寫（不重新撥號，故與舊憑證是否
		// 仍有效無關）；移除剛加入的那一行，exclusive 則回填原始內容
		restore := RemoveKeyLine(next, newLine)
		if keyStrategy == model.KeyStrategyExclusive {
			restore = current.Original
		}
		if rErr := WriteAuthorizedKeys(sc, restore); rErr != nil {
			logRemoteCause(tgt, "新鑰驗證失敗後還原 authorized_keys 失敗", rErr)
			return &remoteStateUnknownError{
				reason: model.ChangeSecretReasonKeyVerifyFailedRestoreFailed, cause: rErr,
			}
		}
		return &remoteRejectedError{reason: model.ChangeSecretReasonKeyVerifyFailedRestored, cause: err}
	}

	// 刪舊：只刪本系統先前推送的那一行，使用者自放的鑰一律不動
	if previousLine != "" && keyStrategy != model.KeyStrategyExclusive {
		pruned := RemoveKeyLine(next, previousLine)
		if pruned != next {
			if err := WriteAuthorizedKeys(sc, pruned); err != nil {
				// 新鑰已驗證可用，舊鑰沒刪掉不影響可用性；記錄但仍提交
				log.Printf("[ChangeSecret] 舊公鑰移除失敗 asset=%d account=%d: %v",
					tgt.assetID, tgt.accountID, err)
			}
		}
	}
	return nil
}
