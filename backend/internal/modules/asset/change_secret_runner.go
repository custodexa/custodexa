package asset

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/sshmaterial"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/branding"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
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

	// mgmt 背景執行前的授權重驗關卡。判定器未注入＝拒絕執行並告警（失敗即放行不可接受）；
	// 生產組裝必須注入，由組裝根守衛釘住。
	mgmt credentialManagementGate
	// auditTx 授權停止事件的審計落地面；nil＝只寫日誌與推送告警
	auditTx port.TxSink
	// ownership 整組模式建立具名共用憑證時的歸屬判定（credential_ownership.go）；未注入＝該批次建立失敗
	ownership CredentialOwnershipScopePort
	// dispatchHook 測試掛點：單帳號路徑在派送前重驗之前呼叫（stage 見 dispatchStage*）；正式組裝為 nil
	dispatchHook func(stage string, accountID uint)
	// judgeTxHook 測試掛點：判定短交易內、判定完成之後、提交之前呼叫（accountIDs 為本次判定的帳號）；
	// 不得等待被本交易擋住的交易。正式組裝為 nil
	judgeTxHook func(tx *gorm.DB, accountIDs []uint)
}

// 單帳號路徑的派送前重驗點（帳號鎖後的第一次重驗之外）。
const (
	// dispatchStageCandidate 候選落庫後、以舊秘密認證或送出新秘密之前
	dispatchStageCandidate = "candidate_persisted"
	// dispatchStageKeyWrite 金鑰流程讀完 authorized_keys、首次寫入之前
	dispatchStageKeyWrite = "key_first_write"
	// dispatchStageKeyPrune 金鑰流程新鑰驗證通過、刪除舊鑰之前
	dispatchStageKeyPrune = "key_prune_old"
)

// dispatchStoppedError 派送前重驗未通過：delivered 為假＝本次尚未對遠端送出任何變更（候選可丟棄）；
// 為真＝新秘密已送出，只停止其後的遠端寫入，候選保留交給失權後的有限收斂。
type dispatchStoppedError struct {
	reason    string
	delivered bool
}

func (e *dispatchStoppedError) Error() string { return "派送前重驗未通過: " + e.reason }

// WithManagementAuthorizer 接上授權重驗：計畫、批次的每台目標執行前，以工作發起者
// 當下的能力重驗；失權、無從判定或缺發起者即停止，遠端不被觸碰。
func (r *ChangeSecretRunner) WithManagementAuthorizer(a CredentialManagementAuthorizer) *ChangeSecretRunner {
	r.mgmt = credentialManagementGate{authorizer: a}
	return r
}

// RevalidationWired 授權重驗判定器是否已注入（組裝根自檢用：未注入時背景工作一律拒絕執行）。
func (r *ChangeSecretRunner) RevalidationWired() bool {
	return r != nil && r.mgmt.authorizer != nil && r.mgmt.restoreGenerationWired()
}

// WithAuditSink 接上授權停止事件的審計落地面。
func (r *ChangeSecretRunner) WithAuditSink(sink port.TxSink) *ChangeSecretRunner {
	r.auditTx = sink
	return r
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
	// initiatorID／initiatorName 工作的發起者（批次為請求者）。背景執行以此建立授權
	// 脈絡，使管理授權在發起者身上判定；計畫沒有持久發起者前為零值，輪替關卡會
	// 因空主體而拒絕（fail closed），不以系統身分或當前操作者替代
	initiatorID   uint
	initiatorName string
	// authorizationID 工作的授權脈絡（候選與記錄關聯用）；0＝無脈絡（未接線的組裝）
	authorizationID uint
	// manual 手動觸發：發起者是點擊的人，不改變排程的發起者
	manual bool
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
	// planAuthorizationID／planState 計畫該版的授權脈絡（掛載上界取自它，不取手動執行另存的那一列）
	// 與計畫的授權狀態（是否已在待重新確認）
	planAuthorizationID *uint
	planState           string

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

		planAuthorizationID: plan.AuthorizationID,
		planState:           plan.AuthorizationState,
	}
	if job.targetKind == "" {
		job.targetKind = model.PlanTargetAccount
	}
	if plan.TargetCredentialID != nil {
		job.targetCredentialID = *plan.TargetCredentialID
	}
	return job
}

// RunPlan 排程執行計劃：發起者取自計畫目前生效的授權脈絡，每台目標執行前以其當下能力重驗。
func (r *ChangeSecretRunner) RunPlan(plan *model.ChangeSecretPlan) []model.ChangeSecretRecord {
	return r.runPlan(context.Background(), plan, false)
}

// RunPlanAs 手動執行計劃：以點擊者為發起者並重驗其能力；不改變排程的發起者。
// 執行前另存一列以點擊者為發起者的授權脈絡，產生的候選帶此引用，之後的背景重試沿點擊者重驗。
func (r *ChangeSecretRunner) RunPlanAs(ctx context.Context, plan *model.ChangeSecretPlan) []model.ChangeSecretRecord {
	return r.runPlan(ctx, plan, true)
}

func (r *ChangeSecretRunner) runPlan(base context.Context, plan *model.ChangeSecretPlan, manual bool) []model.ChangeSecretRecord {
	job := jobFromPlan(plan)
	job.manual = manual
	if manual {
		job.initiatorID, job.initiatorName = model.UserFromContext(base)
	} else if plan.AuthorizationState == model.PlanAuthNeedsReauthorization {
		r.stopJob(job, model.ChangeSecretReasonAuthzContextMissing)
		return nil
	} else if plan.AuthorizationState == model.PlanAuthNeedsReconfirmation {
		// 待重新確認：轉入當下已告警並留痕，之後的排程不執行、不重複告警
		return nil
	} else if auth, err := loadJobAuthorization(r.db, plan.AuthorizationID); err == nil {
		job.initiatorID, job.initiatorName, job.authorizationID = auth.ActorID, auth.ActorName, auth.ID
		if reason := restoreStopReason(r.mgmt, r.db, auth); reason != "" {
			r.stopRestoredPlan(job, plan, reason)
			return nil
		}
	} else {
		// 沒有可用脈絡（舊計畫、損毀、未知格式）：不補 admin、不以當前操作者替代
		r.stopJob(job, jobAuthReason(err))
		return nil
	}
	if r.mgmt.authorizer == nil {
		// 判定器未注入：拒絕執行並告警，不以「不重驗」放行
		r.stopJob(job, model.ChangeSecretReasonAuthzUnavailable)
		return nil
	}
	if manual {
		if reason := r.recordManualRunAuthorization(&job, plan); reason != "" {
			r.stopJob(job, reason)
			return nil
		}
	}
	if job.targetKind == model.PlanTargetCredential {
		if reason := r.revalidate(job, nil, nil); reason != "" {
			r.stopJob(job, reason)
			return nil
		}
		return r.runCredentialTarget(job)
	}
	return r.run(job, AssetIDList(plan))
}

// recordManualRunAuthorization 手動執行的授權脈絡：與排程同形，另存一列以點擊者為發起者的
// 不可變脈絡（來源為本計畫、修訂沿計畫當下的修訂），計畫本身的脈絡引用不變。
// 「授權列已保存且引用非零」是手動工作進入任何遠端操作的前提：點擊者缺席以脈絡缺失停止；
// 首次判定未通過（失權或無從判定）就以該原因停止，不交給之後的逐台重驗——首次判定出錯不代表
// 第二次也會出錯，若放行到逐台重驗而那次通過，候選會以零引用送出，背景重試再以缺脈絡停下。
// 存列失敗同樣停止，不送出無脈絡的候選。
func (r *ChangeSecretRunner) recordManualRunAuthorization(job *rotationJob, plan *model.ChangeSecretPlan) string {
	if job.initiatorID == 0 {
		return model.ChangeSecretReasonAuthzContextMissing
	}
	ctx := contextWithInitiator(context.Background(), job.initiatorID, job.initiatorName)
	credentialIDs, assetIDs := planRunTargets(plan)
	decision, reason := requirePlanRun(r.mgmt, ctx, r.db, job.targetKind, credentialIDs, assetIDs, nil)
	if reason != "" {
		return reason
	}
	row, err := insertJobAuthorization(r.mgmt, r.db, jobAuthInput{
		kind: model.JobAuthSourcePlan, sourceID: plan.ID, revision: plan.Revision,
		actorID: job.initiatorID, actorName: job.initiatorName, via: model.JobAuthViaManualRun,
		authzVersion: decision.AuthzVersion, sources: decision.Sources,
		capabilities: planRunCapabilities(job.targetKind), targetBound: AssetIDList(plan),
	})
	if err != nil {
		log.Printf("[ChangeSecret] 手動執行授權留痕失敗，停止執行 plan=%d initiator=%d: %v", plan.ID, job.initiatorID, err)
		return jobAuthReason(err)
	}
	job.authorizationID = row.ID
	return ""
}

// stopRestoredPlan 授權脈絡留自還原之前（或世代讀取失敗）：背景派送停止，遠端未被觸碰。
// 還原世代不符時把計畫標為待重新授權——排程不再觸發、不重複告警，具權者以既有的
// 重新授權（或修改計畫）重新確認後恢復；告警與審計只在轉入該狀態的當下發一次。
func (r *ChangeSecretRunner) stopRestoredPlan(job rotationJob, plan *model.ChangeSecretPlan, reason string) {
	if reason != model.ChangeSecretReasonAuthzRestored {
		r.stopJob(job, reason)
		return
	}
	res := r.db.Model(&model.ChangeSecretPlan{}).
		Where("id = ? AND authorization_state = ''", plan.ID).
		Update("authorization_state", model.PlanAuthNeedsReauthorization)
	if res.Error != nil {
		log.Printf("[ChangeSecret] 標記計畫待重新授權失敗 plan=%d: %v", plan.ID, res.Error)
		r.stopJob(job, model.ChangeSecretReasonAuthzUnavailable)
		return
	}
	if res.RowsAffected == 0 {
		// 另一條路徑已標記並告警
		return
	}
	r.stopJob(job, reason)
}

// revalidate 以工作發起者當下的能力重驗；通過回空字串，否則回原因碼。
// 發起者缺席一律視為脈絡缺失；判定器未注入視為無從判定（fail closed）。
func (r *ChangeSecretRunner) revalidate(job rotationJob, assetIDs, accountIDs []uint) string {
	reason, _ := r.revalidateTarget(job, assetIDs, accountIDs)
	return reason
}

// revalidateTarget 同 revalidate，另回「未通過是否只因這一台目標不在發起者範圍內」：為真時只停這一台、
// 同批其他目標照常各自判定；能力被撤、無從判定、脈絡缺失等其餘原因停止整個工作。
// 判定交易未提交時（取鎖、判定或提交失敗）最終原因是無從判定，即使交易內先判出範圍拒絕也停止整個工作。
func (r *ChangeSecretRunner) revalidateTarget(job rotationJob, assetIDs, accountIDs []uint) (string, bool) {
	if r.mgmt.authorizer == nil {
		return model.ChangeSecretReasonAuthzUnavailable, false
	}
	if job.initiatorID == 0 {
		return model.ChangeSecretReasonAuthzContextMissing, false
	}
	ctx := contextWithInitiator(context.Background(), job.initiatorID, job.initiatorName)
	// 判定短交易（dispatch_judge_tx.go）：拓撲序列化鎖後以交易內視圖判定，提交後呼叫端才做遠端 I/O。
	// 本路徑沒有領取欄：判定本身即裁決點，與拓撲寫入經同一把鎖排成單一序列
	targetOnly := false
	reason, committed := judgeInTopologyTxCommitted(r.db, r.lockTopologyTx, func(tx *gorm.DB) (string, error) {
		err := r.judge(ctx, tx, job, assetIDs, accountIDs)
		if r.judgeTxHook != nil {
			r.judgeTxHook(tx, accountIDs)
		}
		if err == nil {
			return "", nil
		}
		if stop, ok := batchStopReason(err); ok {
			return stop, nil
		}
		targetOnly = len(assetIDs) > 0 && targetScopeDenial(err)
		return revalidationReason(err), nil
	})
	return reason, committed && reason != "" && targetOnly
}

// targetScopeDenial 拒絕是否為目標資產（或其帳號）不在範圍內。
func targetScopeDenial(err error) bool {
	var denied scopeDeniedTarget
	if !errors.As(err, &denied) {
		return false
	}
	kind := denied.ScopeDeniedTargetKind()
	return kind == scopeDeniedKindAsset || kind == scopeDeniedKindAssetAccount
}

// judge 計畫／批次的判定本體（於判定短交易內、以 tx 執行）；回判定關卡的原始錯誤（nil＝通過）。
func (r *ChangeSecretRunner) judge(ctx context.Context, tx *gorm.DB, job rotationJob, assetIDs, accountIDs []uint) error {
	if job.batchID != 0 {
		// 批次依其授權脈絡保存的能力集合重驗（見 revalidateBatch），不只帳號改密
		return r.revalidateBatch(ctx, tx, job, assetIDs, accountIDs)
	}
	var credentialIDs []uint
	if job.targetKind == model.PlanTargetCredential && job.targetCredentialID != 0 {
		// 憑證目標依目標憑證的歸屬判定（範圍化發起者的範圍外掛載屬已確認的影響，由掛載上界比對）
		credentialIDs = []uint{job.targetCredentialID}
	}
	_, err := r.mgmt.require(ctx, tx, CredentialManagementRequest{
		Operation: CredOpRun, Capabilities: planRunCapabilities(job.targetKind),
		CredentialIDs: credentialIDs, AssetIDs: assetIDs, AccountIDs: accountIDs,
	})
	return err
}

// lockTopologyTx 判定短交易的第一個動作：取與拓撲寫入相同的拓撲序列化鎖。
// 未組裝資產服務或其拓撲 port 時回 ErrTopologyPermissionPortMissing（判定以無從判定停止）。
func (r *ChangeSecretRunner) lockTopologyTx(tx *gorm.DB) error {
	if r.assetService == nil {
		return ErrTopologyPermissionPortMissing
	}
	return r.assetService.lockTopologyTx(tx)
}

// requirePlanRun 計畫／批次執行前的能力重驗（執行前重驗與重新授權承接共用同一函式）。
// 回通過時的決定與空原因碼，否則回原因碼。
func requirePlanRun(gate credentialManagementGate, ctx context.Context, db *gorm.DB, targetKind string,
	credentialIDs, assetIDs, accountIDs []uint) (CredentialManagementDecision, string) {

	d, err := gate.require(ctx, db, CredentialManagementRequest{
		Operation: CredOpRun, Capabilities: planRunCapabilities(targetKind),
		CredentialIDs: credentialIDs, AssetIDs: assetIDs, AccountIDs: accountIDs,
	})
	if err != nil {
		return d, revalidationReason(err)
	}
	return d, ""
}

// stopJob 授權重驗失敗：記日誌、審計並推送告警；不觸碰任何遠端。
func (r *ChangeSecretRunner) stopJob(job rotationJob, reason string) {
	r.stopJobAt(job, reason, nil)
}

// targetStop 逐台重驗未通過時的射程：targetOnly＝只略過這一台（同批其他目標照常各自判定）；
// delivered＝這一台的新秘密已寫到遠端、停在後續步驟之前（候選保留）。
type targetStop struct {
	tgt        changeSecretTarget
	targetOnly bool
	delivered  bool
}

// stopJobAt 同 stopJob；stop 非 nil 時告警依實際射程描述這一台與其餘目標的狀態，不一律稱工作停止、遠端未被觸碰。
func (r *ChangeSecretRunner) stopJobAt(job rotationJob, reason string, stop *targetStop) {
	logJobStop(job.source, reason, job.initiatorID)
	r.auditStop(job, reason)
	if r.notifier == nil {
		return
	}
	r.notifier.Enqueue(model.CommandAlert{
		RuleName: "改密工作因授權失效停止",
		Command:  stopAlertText(job, reason, stop),
		Severity: "high",
	})
}

// stopAlertText 授權停止告警的內文（機器碼＋固定文案，見 alertFailure）。
func stopAlertText(job rotationJob, reason string, stop *targetStop) string {
	if stop == nil {
		return fmt.Sprintf("%s reason=%s（遠端未被觸碰，需具權者重新授權或調整權限）", job.source, reason)
	}
	head := fmt.Sprintf("%s asset_id=%d account=%s reason=%s", job.source, stop.tgt.assetID, stop.tgt.username, reason)
	switch {
	case stop.targetOnly && stop.delivered:
		return head + "（僅略過此目標的後續步驟：新秘密已寫入、舊秘密未清除，候選保留待驗證；同批其他目標照常各自判定）"
	case stop.targetOnly:
		return head + "（僅略過此目標，未對其遠端做任何變更；同批其他目標照常各自判定）"
	case stop.delivered:
		return head + "（此目標新秘密已寫入、舊秘密未清除，候選保留待驗證；其後的目標不再處理，需具權者重新授權或調整權限）"
	}
	return head + "（此目標與其後的目標遠端未被觸碰，需具權者重新授權或調整權限）"
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
	ctx := contextWithInitiator(context.Background(), job.initiatorID, job.initiatorName)
	rot, err := r.rotations.StartForPlan(ctx, job.targetCredentialID, StartRotationRequest{Policy: job.policy},
		r.planMountBound(job))
	if errors.Is(err, ErrRotationPlanBoundExceeded) {
		if reason := r.manualBoundRejection(job); reason != "" {
			// 手動執行撞上界而計畫儲存者不是範圍化主體：只拒絕這一次，不改計畫的授權狀態
			r.stopJob(job, reason)
			return nil
		}
		r.pauseForReconfirmation(job)
		return nil
	}
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

// manualBoundRejection 手動執行撞上界時決定只拒絕本次（回原因碼）或轉待重新確認（回空字串）。
// 只有計畫儲存者（計畫當下生效授權脈絡的發起者）本身是範圍化主體時才轉待重新確認：點擊者是別人、
// 而儲存者經全系統來源持有憑證改密時，範圍化點擊者不能讓別人的排程停擺，只拒絕本次。
// 儲存者讀不到或無從判定時同樣只拒絕本次（不改狀態，遠端照樣零操作）。
func (r *ChangeSecretRunner) manualBoundRejection(job rotationJob) string {
	if !job.manual {
		return ""
	}
	var plan model.ChangeSecretPlan
	if err := r.db.Select("id", "authorization_id").Where("id = ?", job.planID).First(&plan).Error; err != nil {
		return model.ChangeSecretReasonScopeBoundExceeded
	}
	if !sameAuthorizationID(plan.AuthorizationID, job.planAuthorizationID) {
		// 比對上界之後計畫已存成新版：舊版的手動執行只拒絕本次，不替新版改狀態
		return model.ChangeSecretReasonScopeBoundExceeded
	}
	saver, err := loadJobAuthorization(r.db, plan.AuthorizationID)
	if err != nil {
		return model.ChangeSecretReasonScopeBoundExceeded
	}
	if saver.ActorID == job.initiatorID {
		return ""
	}
	ctx := contextWithInitiator(context.Background(), saver.ActorID, saver.ActorName)
	_, err = r.mgmt.require(ctx, r.db, CredentialManagementRequest{
		Operation: CredOpRotate, Capabilities: []string{CredCapRotate},
	})
	var denied *CapabilityDeniedError
	switch {
	case err == nil:
		return model.ChangeSecretReasonScopeBoundExceeded
	case errors.As(err, &denied):
		return ""
	default:
		return model.ChangeSecretReasonAuthzUnavailable
	}
}

// planMountBound 計畫該版的掛載上界（脈絡讀不到或欄位空白＝空集合）與是否已在待重新確認。
func (r *ChangeSecretRunner) planMountBound(job rotationJob) PlanMountBound {
	bound := PlanMountBound{Mounts: map[uint]bool{}, Reconfirming: job.planState == model.PlanAuthNeedsReconfirmation,
		PlanID: job.planID}
	if auth, err := loadJobAuthorization(r.db, job.planAuthorizationID); err == nil {
		bound.Mounts = ParsePlanMountBound(auth.TargetMountBound)
	}
	return bound
}

// pauseForReconfirmation 範圍外掛載超出上界：計畫轉待重新確認（排程不再觸發），告警與審計只在轉入當下各一次。
//
// 條件更新綁定比對上界所依的那一版授權脈絡：比對之後計畫已存成新版（授權脈絡引用已換）就放棄狀態轉換，
// 不讓舊版的執行暫停別人剛儲存的新版。
func (r *ChangeSecretRunner) pauseForReconfirmation(job rotationJob) {
	q := r.db.Model(&model.ChangeSecretPlan{}).Where("id = ? AND authorization_state = ''", job.planID)
	if job.planAuthorizationID == nil {
		q = q.Where("authorization_id IS NULL")
	} else {
		q = q.Where("authorization_id = ?", *job.planAuthorizationID)
	}
	res := q.Update("authorization_state", model.PlanAuthNeedsReconfirmation)
	if res.Error != nil {
		log.Printf("[ChangeSecret] 標記計畫待重新確認失敗 plan=%d: %v", job.planID, res.Error)
		r.stopJob(job, model.ChangeSecretReasonAuthzUnavailable)
		return
	}
	if res.RowsAffected == 0 {
		log.Printf("[ChangeSecret] 計畫已在待重新確認或已存成新版，本次不執行 plan=%d", job.planID)
		return
	}
	r.stopJob(job, model.ChangeSecretReasonScopeBoundExceeded)
}

// sameAuthorizationID 兩個授權脈絡引用是否指向同一列（皆為空亦視為相同）。
func sameAuthorizationID(a, b *uint) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
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
			rec, stopped := r.runTarget(job, tgt)
			records = append(records, rec)
			if stopped {
				// 授權重驗未通過（能力被撤、無從判定或脈絡缺失）：其後的目標不再被觸碰。
				// 只是這一台移出範圍時不在此停止，其後的目標照常各自判定
				return records
			}
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

// runTarget 單帳號改密；任何錯誤僅入 record 不上拋。stopped 為真＝授權重驗未通過且不只是這一台移出範圍，
// 呼叫端停止整個工作
func (r *ChangeSecretRunner) runTarget(job rotationJob, tgt changeSecretTarget) (model.ChangeSecretRecord, bool) {
	// per-account 互斥：同一帳號的兩次改密同時跑，會有兩個候選互相覆蓋遠端狀態。
	// 鎖表與共用憑證的整組輪替共用（見 lockRotationAccount）——兩套引擎各持一份
	// 鎖表等於沒有互斥。本產品現為單實例部署，候選表的 account_id 唯一索引是最終防線
	defer lockRotationAccount(tgt.accountID)()

	// 每台目標的遠端 I/O 之前重驗，且在取得帳號鎖**之後**：等鎖可能被另一個工作拉長，
	// 等待期間的撤權或移出範圍要在這裡以當下資料生效；建立候選與讀派送秘密都在其後
	if reason, targetOnly := r.revalidateTarget(job, []uint{tgt.assetID}, []uint{tgt.accountID}); reason != "" {
		r.stopJobAt(job, reason, &targetStop{tgt: tgt, targetOnly: targetOnly})
		return r.save(model.ChangeSecretRecord{
			PlanID: job.planID, BatchID: job.batchID, AssetID: tgt.assetID, AccountID: tgt.accountID,
			AccountUsername: tgt.username, SecretType: job.secretType,
			CredentialID: tgt.credentialID, CredentialName: tgt.credentialName,
			Status: model.ChangeSecretSkipped, Error: reason, ExecutedAt: time.Now(),
		}), !targetOnly
	}
	return r.runTargetLocked(job, tgt)
}

// runTargetLocked 已取得帳號鎖且通過重驗的單帳號改密；第二個回傳值為真＝派送前重驗未通過且應停止整個工作
func (r *ChangeSecretRunner) runTargetLocked(job rotationJob, tgt changeSecretTarget) (model.ChangeSecretRecord, bool) {
	stopped, stopJob := false, false
	// recheck 帳號鎖後第一次重驗之後的各個派送點再以發起者當下的能力與目標範圍重驗：
	// 取密、候選加密落庫與撥號都可能等待，期間的撤權或移出範圍要在送出任何秘密之前生效。
	// 只是這一台移出範圍：停這一台；其餘原因停止整個工作
	recheck := func(stage string) string {
		if r.dispatchHook != nil {
			r.dispatchHook(stage, tgt.accountID)
		}
		reason, targetOnly := r.revalidateTarget(job, []uint{tgt.assetID}, []uint{tgt.accountID})
		if reason != "" && !stopped {
			stopped, stopJob = true, !targetOnly
			// 刪舊鑰之前停下＝新鑰已寫入（候選保留）；其餘階段尚未改動遠端
			r.stopJobAt(job, reason, &targetStop{tgt: tgt, targetOnly: targetOnly, delivered: stage == dispatchStageKeyPrune})
		}
		return reason
	}
	rec := r.runTargetSteps(job, tgt, recheck)
	return rec, stopJob
}

// runTargetSteps 單帳號改密的各步驟（見 runTargetLocked）
func (r *ChangeSecretRunner) runTargetSteps(job rotationJob, tgt changeSecretTarget, recheck func(string) string) model.ChangeSecretRecord {

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
	defer creds.Destroy()
	if creds.AccountID != tgt.accountID || creds.Username != tgt.username {
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonAccountChanged)
	}
	if creds.Password.IsEmpty() && creds.PrivateKey.IsEmpty() {
		return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonNoCredential)
	}

	// 主機金鑰回呼帶撥號脈絡（host-key-verification）：改密屬背景路徑，不符時留痕後拒絕撥號、
	// 不送出任何憑證或新秘密；連線使用者為工作發起者，連線識別為計畫或批次。
	// 回呼在候選落庫之後才建立（綁定要寫到候選列），見 bindingCallback
	rt := rotationTarget{
		asset:      creds.Asset,
		channel:    tgt.channel,
		username:   tgt.username,
		secretType: job.secretType,
		addr:       rotationAddr(creds.Asset, tgt.channel),
	}
	exec := r.executors(tgt.channel)

	if job.secretType == model.ChangeSecretTypeSSHKey {
		return r.rotateKey(job, tgt, creds, rt, exec, &rec, finish, recheck)
	}
	return r.rotatePassword(job, tgt, creds, rt, exec, &rec, finish, recheck)
}

// bindingCallback 首次派送的主機金鑰回呼：第一次握手把當下的主機身分綁定到候選列，其後只比對該快照。
// 候選必須已落庫（綁定寫到該列）。
func (r *ChangeSecretRunner) bindingCallback(job rotationJob, tgt changeSecretTarget, candidateID uint) ssh.HostKeyCallback {
	cb, _ := r.hostKeys.CallbackForBinding(HostKeyDialContext{
		AssetID: tgt.assetID, Path: HostKeyPathCredentialChange,
		UserID: job.initiatorID, Username: job.initiatorName, AccountID: tgt.accountID,
		ConnectionRef: changeSecretJobRef(job),
	}, HostKeyBindTarget{CandidateID: candidateID})
	return cb
}

// rotatePassword 密碼輪替：chpasswd（憑證經 stdin，不進 argv）
func (r *ChangeSecretRunner) rotatePassword(job rotationJob, tgt changeSecretTarget,
	creds *AssetCredentials, rt rotationTarget, exec rotationExecutor,
	rec *model.ChangeSecretRecord,
	finish func(string, string) model.ChangeSecretRecord, recheck func(string) string) model.ChangeSecretRecord {

	if creds.Password.IsEmpty() {
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
		PlanID: job.planID, BatchID: job.batchID, AuthorizationID: job.authorizationID,
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

	if tgt.channel == model.RotationChannelWindowsWinRM {
		// WinRM 沒有金鑰交換：在 Rotate 之前先寫下「自始為 WinRM」的綁定，寫不進去就不派送
		if err := r.hostKeys.BindWinRM(HostKeyBindTarget{CandidateID: cand.ID}); err != nil {
			_ = r.candidates.Discard(cand.ID)
			return finish(model.ChangeSecretFailed, model.ChangeSecretReasonHostKeyCheckFailed)
		}
	} else {
		rt.hostKeyCB = r.bindingCallback(job, tgt, cand.ID)
	}
	// 候選落庫後、以舊密碼認證與送出新密碼之前再重驗一次：未通過即丟棄候選（尚未派送），遠端零觸碰
	if reason := recheck(dispatchStageCandidate); reason != "" {
		_ = r.candidates.Discard(cand.ID)
		return finish(model.ChangeSecretSkipped, reason)
	}
	newBytes := []byte(newPassword)
	defer material.Wipe(newBytes)
	if err := withProtocolSecret(creds.Password, func(oldPassword []byte) error { return exec.Rotate(ctx, rt, oldPassword, newBytes) }); err != nil {
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
	if merr := r.candidates.MarkApplied(cand.ID); merr != nil {
		log.Printf("[ChangeSecret] 標記候選已下達失敗 asset=%d account=%s err=%v", tgt.assetID, tgt.username, merr)
	}

	// 立即 Verify 也會再送一次新秘密：先重讀工作列做撥號前查庫，撥號只認綁定的金鑰
	guard := r.candidateVerifyGuard(job, tgt, cand.ID)
	verifyRT := rt
	cb, err := guard.prepare(rt.asset)
	if err == nil {
		verifyRT.hostKeyCB = cb
		err = exec.Verify(ctx, verifyRT, newBytes)
	}
	if err != nil {
		// 本地憑證**不動**，候選保留待重試。硬提交是在猜遠端狀態，
		// 猜錯就把還能用的憑證改壞
		logRemoteCause(tgt, "新密驗證失敗", err)
		if errors.Is(err, ErrHostIdentityChanged) {
			guard.recordStop(rt.asset)
		}
		reason := verifyFailureReason(err, model.ChangeSecretReasonVerifyFailed)
		_, _ = r.candidates.RecordFailure(cand, reason)
		return finish(model.ChangeSecretUnverified, reason)
	}

	cand.Applied = true
	if err := r.candidates.Promote(ctx, cand); err != nil {
		logRemoteCause(tgt, "憑證提交失敗", err)
		if errors.Is(err, ErrHostIdentityChanged) {
			guard.recordCommitStop(rt.asset)
		}
		reason := promoteFailureReason(err)
		_, _ = r.candidates.RecordFailure(cand, reason)
		return finish(model.ChangeSecretUnverified, reason)
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
	finish func(string, string) model.ChangeSecretRecord, recheck func(string) string) model.ChangeSecretRecord {

	comment := fmt.Sprintf(branding.Slug+"-change-secret-%d-%d", tgt.assetID, tgt.accountID)
	newPrivate, newLine, err := GenerateSSHKeyPair(comment)
	if err != nil {
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonKeypairGenerateFailed)
	}
	// 舊的「本系統推送鑰」：僅當帳號現以私鑰認證時存在
	previousLine := ""
	if !creds.PrivateKey.IsEmpty() {
		if line, err := publicLineFromOwnedKey(creds.PrivateKey); err == nil {
			previousLine = line
		}
	}

	ctx := context.Background()
	cand, err := r.candidates.Create(ctx, CandidateInput{
		AssetID: tgt.assetID, AccountID: tgt.accountID, AccountUsername: tgt.username,
		PlanID: job.planID, BatchID: job.batchID, AuthorizationID: job.authorizationID, SecretType: model.ChangeSecretTypeSSHKey,
		CredentialID: tgt.credentialID, CredentialName: tgt.credentialName,
		PrivateKey: newPrivate, PublicKey: newLine, PreviousPublicKey: previousLine,
	})
	if err != nil {
		if errors.Is(err, ErrCandidateExists) {
			return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonCandidatePending)
		}
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonCandidatePersistFailed)
	}

	rt.hostKeyCB = r.bindingCallback(job, tgt, cand.ID)
	guard := r.candidateVerifyGuard(job, tgt, cand.ID)
	rt.verifyHostKeyCB = func() (ssh.HostKeyCallback, error) { return guard.prepare(rt.asset) }
	// 候選落庫後、以舊憑證認證之前再重驗一次：未通過即丟棄候選（尚未派送），遠端零觸碰
	if reason := recheck(dispatchStageCandidate); reason != "" {
		_ = r.candidates.Discard(cand.ID)
		return finish(model.ChangeSecretSkipped, reason)
	}
	newBytes := []byte(newPrivate)
	defer material.Wipe(newBytes)
	if err := withProtocolPair(creds.Password, creds.PrivateKey, func(password, privateKey []byte) error {
		return applySSHKeyOnTargetChecked(ctx, exec, rt, tgt, password, privateKey,
			newBytes, newLine, previousLine, job.keyStrategy,
			func() error { return r.candidates.MarkApplied(cand.ID) }, recheck)
	}); err != nil {
		// 派送前重驗未通過：尚未寫入者丟棄候選；新鑰已寫入者保留候選、不再刪舊鑰
		var stoppedErr *dispatchStoppedError
		if errors.As(err, &stoppedErr) {
			if !stoppedErr.delivered {
				_ = r.candidates.Discard(cand.ID)
				return finish(model.ChangeSecretSkipped, stoppedErr.reason)
			}
			_, _ = r.candidates.RecordFailure(cand, stoppedErr.reason)
			return finish(model.ChangeSecretUnverified, stoppedErr.reason)
		}

		// 遠端確定未變更（含還原成功）＝清候選走乾淨失敗；還原也失敗＝狀態不可知，
		// 候選必須留著，它是那把可能已在遠端生效的秘密的唯一副本
		var rejected *remoteRejectedError
		if errors.As(err, &rejected) {
			_ = r.candidates.Discard(cand.ID)
			return finish(model.ChangeSecretFailed, rejected.reason)
		}
		var unknown *remoteStateUnknownError
		if errors.As(err, &unknown) {
			if errors.Is(err, ErrHostIdentityChanged) {
				guard.recordStop(rt.asset)
			}
			_, _ = r.candidates.RecordFailure(cand, unknown.reason)
			return finish(model.ChangeSecretUnverified, unknown.reason)
		}
		_, _ = r.candidates.RecordFailure(cand, model.ChangeSecretReasonRemoteStateUnknown)
		return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonRemoteStateUnknown)
	}

	cand.Applied = true
	if err := r.candidates.Promote(ctx, cand); err != nil {
		logRemoteCause(tgt, "憑證提交失敗", err)
		if errors.Is(err, ErrHostIdentityChanged) {
			guard.recordCommitStop(rt.asset)
		}
		reason := promoteFailureReason(err)
		_, _ = r.candidates.RecordFailure(cand, reason)
		return finish(model.ChangeSecretUnverified, reason)
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

// Authentication copies are owned by Dial, independently of rotation buffers.
func dialSSHPassword(ctx context.Context, addr, user string, password *sshmaterial.Password, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	defer password.Destroy()
	return sshmaterial.Dial(ctx, addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PasswordCallback(password.Callback)}, HostKeyCallback: hostKey, Timeout: changeSecretDialTimeout})
}

func dialSSHPrivateKey(ctx context.Context, addr, user string, privatePEM []byte, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	signer, err := ssh.ParsePrivateKey(privatePEM)
	if err != nil {
		return nil, fmt.Errorf("解析私鑰失敗: %w", err)
	}
	return sshmaterial.Dial(ctx, addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: hostKey, Timeout: changeSecretDialTimeout})
}

func dialSSHCredentials(ctx context.Context, addr, user string, password *sshmaterial.Password, privateKey *material.Secret, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	defer password.Destroy()
	defer privateKey.Destroy()
	var methods []ssh.AuthMethod
	if !privateKey.IsEmpty() {
		signer, err := material.Use(privateKey, ssh.ParsePrivateKey)
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}
	if !password.Empty() {
		methods = append(methods, ssh.PasswordCallback(password.Callback))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("帳號無可用憑證")
	}
	return sshmaterial.Dial(ctx, addr, &ssh.ClientConfig{User: user, Auth: methods, HostKeyCallback: hostKey, Timeout: changeSecretDialTimeout})
}

// runChpasswd 執行改密：root 直接 chpasswd；非 root 以 sudo -S 餵舊密提權。
//
// **憑證一律經 session stdin 投遞**，SHALL NOT 進入命令列——目標機的 ps 與
// /proc/<pid>/cmdline 因此看不到任何密碼。後端側亦無子程序（全程行程內 SSH
// 客戶端），故本地 argv／environ 同樣不持有憑證。
func runChpasswd(client *ssh.Client, user string, oldPassword, newPassword []byte) error {
	// chpasswd 自 stdin 逐行讀 user:password；user/新密含換行會拆出額外條目
	// 改到非目標帳號（stdin 注入），故在組裝 entry 前嚴格拒絕控制字元
	//
	// 本地前置驗證在**完全未接觸遠端**時失敗，故以專屬型別回傳：呼叫端據此走
	// 乾淨 failed，不得落入「狀態不可知」分支（那會留下擋住該帳號的候選）
	if strings.ContainsAny(user, "\n\r\x00:") {
		return &localPreconditionError{reason: model.ChangeSecretReasonInvalidAccountName}
	}
	if bytes.ContainsAny(newPassword, "\n\r\x00") {
		return &localPreconditionError{reason: model.ChangeSecretReasonInvalidNewSecret}
	}

	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	cmd := "chpasswd"
	if user != "root" {
		cmd = "sudo -S -p '' sh -c 'chpasswd'"
	}
	stdin := rotationStdin(user, oldPassword, newPassword)
	defer material.Wipe(stdin)
	input := newSecretInput(stdin)
	defer input.Close()
	sess.Stdin = input

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
// changeSecretJobRef 改密工作的連線識別（計畫或批次）；主機金鑰不符審計與告警引用。
func changeSecretJobRef(job rotationJob) string {
	if job.batchID != 0 {
		return fmt.Sprintf("change_secret_batch:%d", job.batchID)
	}
	return fmt.Sprintf("change_secret_plan:%d", job.planID)
}

// oldCredentialLoginReason 舊憑證撥號失敗的原因碼：主機金鑰不符被回呼拒絕（憑證未送出）記為
// 主機金鑰不符，讓管理者去確認主機而不是去查憑證；其餘維持舊憑證登入失敗。
func oldCredentialLoginReason(err error) string {
	// 主機身分變更（綁定後握手出示的鑰與綁定快照不同）優先辨識，包裝後也認得
	if errors.Is(err, ErrHostIdentityChanged) {
		return model.ChangeSecretReasonHostIdentityChanged
	}
	if errors.Is(err, ErrHostKeyChanged) {
		return model.ChangeSecretReasonHostKeyMismatch
	}
	if errors.Is(err, ErrHostKeyCheckFailed) {
		return model.ChangeSecretReasonHostKeyCheckFailed
	}
	return model.ChangeSecretReasonOldCredentialLoginFailed
}

// promoteFailureReason 本地提交失敗的原因碼：提交交易內的主機身分比對不符（ErrHostIdentityChanged，
// 含包裝）歸主機身分變更，其餘維持憑證提交失敗。
func promoteFailureReason(err error) string {
	if errors.Is(err, ErrHostIdentityChanged) {
		return model.ChangeSecretReasonHostIdentityChanged
	}
	return model.ChangeSecretReasonPromoteFailed
}

// verifyFailureReason 新秘密驗證撥號失敗的原因碼：主機金鑰不符記為主機金鑰不符（候選保留、狀態沿既有分類），
// 其餘用呼叫端的既有原因碼。查核失敗（ErrHostKeyCheckFailed）不歸主機金鑰不符。
// 主機身分已變更（ErrHostIdentityChanged）優先辨識，歸主機身分變更。
func verifyFailureReason(err error, fallback string) string {
	if errors.Is(err, ErrHostIdentityLookupFailed) {
		return model.ChangeSecretReasonAuthzUnavailable
	}
	if errors.Is(err, ErrHostIdentityChanged) {
		return model.ChangeSecretReasonHostIdentityChanged
	}
	if errors.Is(err, ErrHostKeyChanged) {
		return model.ChangeSecretReasonHostKeyMismatch
	}
	return fallback
}

func logRemoteCause(tgt changeSecretTarget, stage string, err error) {
	log.Printf("[ChangeSecret] %s asset=%d account=%d user=%s cause=%s",
		stage, tgt.assetID, tgt.accountID, tgt.username, sanitizeRemoteMessage(err.Error()))
}

// ChangeSecretStopNotifier 改密停止類事件的推送函式，供組裝根注入計畫承接、輪替授權停止與
// 排程暫停三處（WithAlertNotifier／WithStopNotifier／WithPausedPlanNotifier）。
//
// 與 alertFailure、stopJob 同一條借道：只把 CommandAlert 的**通知格式**送進告警推送佇列
// （AlertNotifier.Enqueue 只入記憶體佇列、由 worker 送 webhook，不寫任何資料列），
// 不入 command_alerts、不 tee，SHALL NOT 改走 AlertSink——這些事件沒有對應的告警規則，
// 入庫即成為審閱流程要處置的幽靈告警列。事件本身的留痕由各呼叫端的審計負責。
// 構造點收在本檔，是為了讓「借道通知」只存在於告警收口守衛已登記理由的檔內。
// n 為 nil（告警推送未啟用）時回傳的函式不做任何事。
func ChangeSecretStopNotifier(n *audit.AlertNotifier) func(rule, message string) {
	return func(rule, message string) {
		if n == nil {
			return
		}
		n.Enqueue(model.CommandAlert{RuleName: rule, Command: message, Severity: "high"})
	}
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

// applySSHKeyOnTargetChecked SSH 金鑰輪替的遠端段：加新 → 驗新 → 刪舊。
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
//	*dispatchStoppedError    首次寫入或刪舊鑰之前重驗未通過（delivered＝新鑰已寫入）
//
// recheck 在首次寫入與刪舊鑰之前各呼叫一次（單帳號路徑見 runTargetLocked、輪替成員見 deliverKey），
// 回非空原因碼即停止、不再寫入。兩條路徑都必須傳入。
func applySSHKeyOnTargetChecked(ctx context.Context, exec rotationExecutor, rt rotationTarget,
	tgt changeSecretTarget, oldPassword, oldPrivateKey, newPrivate []byte, newLine, previousLine,
	keyStrategy string, onDelivered func() error, recheck func(string) string) error {

	client, err := dialSSHCredentials(ctx, rt.addr, rt.username, sshmaterial.CopyPassword(oldPassword), material.Adopt(bytes.Clone(oldPrivateKey)), rt.hostKeyCB)
	if err != nil {
		logRemoteCause(tgt, "舊憑證登入失敗", err)
		return &remoteRejectedError{reason: oldCredentialLoginReason(err), cause: err}
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
	// 首次寫入之前再重驗：登入與讀檔期間的撤權在此生效，遠端未被改動
	if recheck != nil {
		if reason := recheck(dispatchStageKeyWrite); reason != "" {
			return &dispatchStoppedError{reason: reason}
		}
	}
	if err := WriteAuthorizedKeys(sc, next); err != nil {
		logRemoteCause(tgt, "寫入 authorized_keys 失敗", err)
		return &remoteRejectedError{reason: model.ChangeSecretReasonAuthorizedKeysWriteFailed, cause: err}
	}
	if onDelivered != nil {
		// 下達標記寫不進去只影響呈現與告警文案，不影響重試邏輯：記 log、不中止
		if derr := onDelivered(); derr != nil {
			log.Printf("[ChangeSecret] 標記候選已下達失敗 asset=%d account=%s err=%v", tgt.assetID, tgt.username, derr)
		}
	}

	// 驗新：以新私鑰對同一目標實連。此步同時是 AuthorizedKeysFile 指向他處、
	// 檔案唯讀等狀況的偵測手段——加了鑰卻登不進去即代表該檔未被 sshd 採用
	verifyRT := rt
	if rt.verifyHostKeyCB != nil {
		cb, perr := rt.verifyHostKeyCB()
		if perr != nil {
			logRemoteCause(tgt, "新鑰驗證前主機身分不放行", perr)
			return &remoteStateUnknownError{reason: precheckStopReason(perr), cause: perr}
		}
		verifyRT.hostKeyCB = cb
	}
	if err := exec.Verify(ctx, verifyRT, newPrivate); err != nil {
		logRemoteCause(tgt, "新鑰驗證失敗", err)
		// 驗證撥號被主機身分守衛擋下：新鑰已寫入、遠端狀態不可知；不還原 authorized_keys、不刪舊鑰
		if errors.Is(err, ErrHostIdentityChanged) {
			return &remoteStateUnknownError{reason: model.ChangeSecretReasonHostIdentityChanged, cause: err}
		}
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

	// 刪舊也是一次遠端寫入：先重驗，未通過即停在「新鑰已寫入、舊鑰未刪」，候選保留交給有限收斂
	if recheck != nil && previousLine != "" && keyStrategy != model.KeyStrategyExclusive {
		if reason := recheck(dispatchStageKeyPrune); reason != "" {
			return &dispatchStoppedError{reason: reason, delivered: true}
		}
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

func rotationStdin(user string, oldPassword, newPassword []byte) []byte {
	size := len(user) + 1 + len(newPassword) + 1
	if user != "root" {
		size += len(oldPassword) + 1
	}
	out := make([]byte, size)
	at := 0
	if user != "root" {
		at += copy(out, oldPassword)
		out[at] = '\n'
		at++
	}
	at += copy(out[at:], user)
	out[at] = ':'
	at++
	at += copy(out[at:], newPassword)
	out[at] = '\n'
	return out
}
