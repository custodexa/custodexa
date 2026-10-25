package asset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 背景工作的授權脈絡。
//
// # 為什麼要持久化發起者
//
// 排程、批次、輪替成員的補跑與候選重試都在請求之外執行，當下沒有「正在操作的人」。
// 若放行，等於以系統身分做任何事；若一律拒絕，等於升級後所有排程停擺。折衷：
// 工作建立（或修改）時把**伺服器端主體**存成不可變的授權脈絡，之後每次執行都以這個
// 發起者**當下**的能力重驗——授權脈絡本身不是一張票，撤權即停。
//
// - 發起者只來自伺服器端 context，不接受 client 提供的 actor、版本或「已授權」旗標。
// - 讀到未知格式版本或缺發起者的脈絡一律視為缺失，不補 admin、不以當前操作者替代。
// - 修改計畫新增一列（修訂號遞增），舊列保留；手動執行不改變排程的發起者。

var (
	// ErrJobAuthorizationMissing 工作沒有可指認的授權脈絡。
	ErrJobAuthorizationMissing = errors.New("工作沒有可指認的發起者授權脈絡")
	// ErrJobAuthorizationUnreadable 授權脈絡格式未知或內容不完整。
	ErrJobAuthorizationUnreadable = errors.New("工作授權脈絡格式未知或內容不完整")
)

// jobAuthSchemaVersion 授權列格式版本；讀到其他版本一律拒絕恢復。
const jobAuthSchemaVersion = 1

type jobAuthInput struct {
	kind         string
	sourceID     uint
	revision     int
	actorID      uint
	actorName    string
	via          string
	authzVersion int64
	sources      []string
	capabilities []string
	targetBound  []uint
	// targetMountBound 憑證目標計畫的掛載上界（JSON 陣列）；空字串＝沒有掛載上界
	targetMountBound string
}

// stampRestoreGeneration 授權脈絡記下建立當下的還原世代。讀取失敗＝無法證明世代，建立失敗（fail closed）。
func stampRestoreGeneration(gate credentialManagementGate, db *gorm.DB, row *model.CredentialJobAuthorization) error {
	gen, _, err := gate.currentRestoreGeneration(db)
	if err != nil {
		return fmt.Errorf("%w: 讀取還原世代失敗: %v", ErrCredentialAuthzUnavailable, err)
	}
	row.RestoreGeneration = gen
	return nil
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return "[]"
	}
	return string(b)
}

// insertJobAuthorization 新增一列不可變的授權脈絡。
func insertJobAuthorization(gate credentialManagementGate, tx *gorm.DB, in jobAuthInput) (*model.CredentialJobAuthorization, error) {
	if in.actorID == 0 {
		return nil, ErrJobAuthorizationMissing
	}
	now := time.Now()
	row := &model.CredentialJobAuthorization{
		SchemaVersion: jobAuthSchemaVersion, SourceKind: in.kind, SourceID: in.sourceID,
		Revision: in.revision, ActorID: in.actorID, ActorKind: "human", ActorName: in.actorName,
		AuthSource: in.via, AuthzVersion: in.authzVersion, PermissionSources: mustJSON(in.sources),
		Capabilities: mustJSON(in.capabilities), TargetBound: mustJSON(in.targetBound),
		TargetMountBound: in.targetMountBound, ConfirmedAt: now, CreatedAt: now,
	}
	if err := stampRestoreGeneration(gate, tx, row); err != nil {
		return nil, err
	}
	if err := tx.Create(row).Error; err != nil {
		return nil, fmt.Errorf("寫入工作授權脈絡失敗: %w", err)
	}
	return row, nil
}

// loadJobAuthorization 讀取授權脈絡；引用為空、列不存在、格式未知或缺發起者都回錯誤。
func loadJobAuthorization(db *gorm.DB, id *uint) (*model.CredentialJobAuthorization, error) {
	if id == nil || *id == 0 {
		return nil, ErrJobAuthorizationMissing
	}
	var row model.CredentialJobAuthorization
	if err := db.Where("id = ?", *id).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: 引用的授權列不存在", ErrJobAuthorizationUnreadable)
		}
		return nil, fmt.Errorf("%w: %v", ErrJobAuthorizationUnreadable, err)
	}
	if row.SchemaVersion != jobAuthSchemaVersion || row.ActorID == 0 {
		return nil, ErrJobAuthorizationUnreadable
	}
	return &row, nil
}

// initiatorContext 以授權脈絡的發起者建立背景脈絡（不繼承呼叫端的取消與主體）。
func initiatorContext(auth *model.CredentialJobAuthorization) context.Context {
	return contextWithInitiator(context.Background(), auth.ActorID, auth.ActorName)
}

// jobAuthReason 把脈絡載入錯誤對應到使用者可見的原因碼。
func jobAuthReason(err error) string {
	if errors.Is(err, ErrJobAuthorizationMissing) || errors.Is(err, ErrJobAuthorizationUnreadable) {
		return model.ChangeSecretReasonAuthzContextMissing
	}
	return model.ChangeSecretReasonAuthzUnavailable
}

// revalidationReason 把管理授權的拒絕對應到原因碼：權限不足與範圍拒絕（憑證歸屬或目標資產
// 已不在該主體的範圍內）＝撤權，其餘＝無法判定。
func revalidationReason(err error) string {
	if errors.Is(err, ErrCredentialBindForbidden) {
		return model.ChangeSecretReasonAuthzRevoked
	}
	var denied scopeDeniedTarget
	if errors.As(err, &denied) {
		return model.ChangeSecretReasonAuthzRevoked
	}
	return model.ChangeSecretReasonAuthzUnavailable
}

// logJobStop 停止事件只寫原因碼與識別，不寫任何秘密或遠端內容。
func logJobStop(source, reason string, actorID uint) {
	log.Printf("[ChangeSecret] 授權重驗停止工作: source=%s reason=%s initiator=%d", source, reason, actorID)
}

// auditStop 授權停止事件的審計（獨立交易：停止本身沒有本地變更要綁）。
// 落地面缺席或寫入失敗只留日誌，不阻擋停止——停止是更安全的方向。
func (r *ChangeSecretRunner) auditStop(job rotationJob, reason string) {
	if r.auditTx == nil {
		return
	}
	details, _ := json.Marshal(map[string]any{
		"resource": string(model.ResourceChangeSecretPlan), "operation": "authorization_stop",
		"plan_id": job.planID, "batch_id": job.batchID, "reason": reason, "initiator_id": job.initiatorID,
	})
	var resourceID *uint
	if job.planID != 0 {
		id := job.planID
		resourceID = &id
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		return port.WriteInTx(r.auditTx, tx, port.AuditEvent{
			OccurredAt: time.Now(),
			Actor:      gatewayapi.Actor{UserID: job.initiatorID, Username: job.initiatorName},
			Action:     string(model.ActionUpdate),
			Resource:   string(model.ResourceChangeSecretPlan),
			ResourceID: resourceID,
			Status:     string(model.StatusDenied),
			Details:    string(details),
		})
	})
	if err != nil {
		log.Printf("[ChangeSecret] 授權停止事件審計寫入失敗: %v", err)
	}
}

// authorizationCapabilities 授權脈絡建立時確認的能力集合；空或損毀時用 fallback。
func authorizationCapabilities(auth *model.CredentialJobAuthorization, fallback []string) []string {
	var caps []string
	if err := json.Unmarshal([]byte(auth.Capabilities), &caps); err != nil || len(caps) == 0 {
		return fallback
	}
	return caps
}

// strictAuthorizationCapabilities 與 authorizationCapabilities 同一份資料，但能力欄無法解析時回錯誤、
// 不退回 fallback：供「脈絡存在卻讀不出來必須 fail closed」的呼叫者使用。
// 能力欄解析成功但為空（無能力記載）仍回 nil, nil，由呼叫者決定基本鍵。
func strictAuthorizationCapabilities(auth *model.CredentialJobAuthorization) ([]string, error) {
	var caps []string
	if err := json.Unmarshal([]byte(auth.Capabilities), &caps); err != nil {
		return nil, fmt.Errorf("%w: 能力欄無法解析", ErrJobAuthorizationUnreadable)
	}
	return caps, nil
}

// revalidateAuthorization 以授權脈絡的發起者**當下**的能力重驗，回空字串＝通過，否則回原因碼。
//
// 手動觸發（caller 帶有伺服器端主體且不是發起者）時兩者都要通過：超管點擊不替原本
// 失權的發起者送出新變更，也不因發起者仍有權就讓無權的點擊者代為執行。
// 背景呼叫（caller 無主體）只驗發起者。
func revalidateAuthorization(gate credentialManagementGate, db *gorm.DB, caller context.Context,
	auth *model.CredentialJobAuthorization, req CredentialManagementRequest, fallbackCaps []string) string {

	reason, _ := revalidateAuthorizationVersion(gate, db, caller, auth, req, fallbackCaps)
	return reason
}

// restoreStopReason 授權脈絡記錄的還原世代與目前世代比對。
// 回空字串＝一致或比對未啟用；ChangeSecretReasonAuthzRestored＝這份意圖留自一次還原之前；
// 世代讀取失敗回 ChangeSecretReasonAuthzUnavailable（無法證明世代，依 fail closed 停止）。
// 只管背景派送：還原之後新建立的工作記的是新世代，不受影響。
func restoreStopReason(gate credentialManagementGate, db *gorm.DB, auth *model.CredentialJobAuthorization) string {
	mismatch, err := gate.restoreMismatch(db, auth.RestoreGeneration)
	if err != nil {
		log.Printf("[ChangeSecret] 讀取還原世代失敗，停止派送 authorization=%d: %v", auth.ID, err)
		return model.ChangeSecretReasonAuthzUnavailable
	}
	if mismatch {
		return model.ChangeSecretReasonAuthzRestored
	}
	return ""
}

// revalidateAuthorizationVersion 同 revalidateAuthorization，另回通過時發起者的權限世代版本
// （寫進 dispatch claim，供稽核「這一步是在哪一版權限下放行的」）。
func revalidateAuthorizationVersion(gate credentialManagementGate, db *gorm.DB, caller context.Context,
	auth *model.CredentialJobAuthorization, req CredentialManagementRequest, fallbackCaps []string) (string, int64) {

	req.Operation = CredOpRun
	req.Capabilities = authorizationCapabilities(auth, fallbackCaps)
	decision, err := gate.require(initiatorContext(auth), db, req)
	if err != nil {
		return revalidationReason(err), 0
	}
	if caller != nil {
		if uid, _ := model.UserFromContext(caller); uid != 0 && uid != auth.ActorID {
			if _, err := gate.require(caller, db, req); err != nil {
				return revalidationReason(err), 0
			}
		}
	}
	return "", decision.AuthzVersion
}

// revalidateMember 輪替成員的每次遠端步驟前重驗。發起者取自輪替的持久授權脈絡，
// 不使用呼叫端 context 內的主體當發起者（背景補跑沒有主體；手動補跑的點擊者另行同驗）。
func (s *CredentialRotationService) revalidateMember(ctx context.Context, rot *model.CredentialRotation,
	member *model.CredentialRotationMember) string {

	auth, err := loadJobAuthorization(s.db, rot.AuthorizationID)
	if errors.Is(err, ErrJobAuthorizationMissing) {
		// 升級前建立的輪替沒有授權脈絡：背景補跑停止（原因碼 CONTEXT_MISSING），
		// 手動補跑由具權的點擊者以其當下權限承接，否則這類成員沒有任何恢復路徑
		adopted, areason := s.reauthorizeRotationByClicker(ctx, rot, member, nil)
		if areason != "" {
			if areason == model.ChangeSecretReasonAuthzRestored {
				areason = model.ChangeSecretReasonAuthzContextMissing
			}
			return areason
		}
		auth, err = adopted, nil
	}
	if err != nil {
		return jobAuthReason(err)
	}
	if reason := restoreStopReason(s.mgmt, s.db, auth); reason != "" {
		// 背景補跑停止；手動補跑由具權的點擊者重新建立授權脈絡後繼續
		if reason != model.ChangeSecretReasonAuthzRestored {
			return reason
		}
		reauth, rreason := s.reauthorizeRotationByClicker(ctx, rot, member, auth)
		if rreason != "" {
			return rreason
		}
		auth = reauth
	}
	bound, berr := authorizationTargetBound(auth)
	if berr != nil {
		return jobAuthReason(berr)
	}
	s.claimSync(claimStageBeforeTx, nil, member.ID)
	// 判定＋領取短交易（dispatch_judge_tx.go）：拓撲序列化鎖是交易第一個動作，鎖後以交易內視圖重驗
	// 發起者、手動點擊者、重排者與目標範圍，通過才寫 dispatch claim，兩者一起提交；遠端 I/O 在提交之後。
	// claim 寫入失敗＝無法證明放行依據，整筆回滾並依 fail closed 停止
	reason := judgeInTopologyTx(s.db, s.lockTopologyTx, func(tx *gorm.DB) (string, error) {
		reason, version := s.judgeMember(ctx, tx, auth, member, bound)
		if reason != "" {
			return reason, nil
		}
		if err := tx.Model(&model.CredentialRotationMember{}).Where("id = ?", member.ID).
			Updates(map[string]any{"dispatch_claimed_at": time.Now(), "dispatch_authz_version": version}).Error; err != nil {
			return model.ChangeSecretReasonAuthzUnavailable, fmt.Errorf("寫入 dispatch claim 失敗: %w", err)
		}
		s.claimSync(claimStageClaimed, tx, member.ID)
		return "", nil
	})
	if reason == "" {
		s.claimSync(claimStageCommitted, nil, member.ID)
	}
	return reason
}

// judgeMember 成員派送的判定本體（於判定短交易內、以 tx 執行）。回原因碼與發起者通過時的權限世代版本。
func (s *CredentialRotationService) judgeMember(ctx context.Context, tx *gorm.DB, auth *model.CredentialJobAuthorization,
	member *model.CredentialRotationMember, bound []uint) (string, int64) {

	if len(bound) > 0 {
		// 由批次發起的拆分帶資產上界：以成員所在資產判定帳號改密與拆分能力（起始交易同一口徑，
		// 不要求來源共用憑證歸屬在範圍內）；能力欄不完整即停止
		return s.revalidateAssetBound(ctx, tx, auth, member, bound)
	}
	req := CredentialManagementRequest{
		CredentialIDs:   []uint{member.CredentialID},
		MountedAssetIDs: []uint{member.AssetID},
		AccountIDs:      []uint{member.AccountID},
	}
	reason, version := revalidateAuthorizationVersion(s.mgmt, tx, ctx, auth, req, []string{CredCapRotate})
	if reason == "" {
		reason = s.revalidateRequeuer(ctx, tx, auth, member, req)
	}
	return reason, version
}

// claimSync 測試同步點（正式組裝為 nil）。
func (s *CredentialRotationService) claimSync(stage string, tx *gorm.DB, memberID uint) {
	if s.claimHook != nil {
		s.claimHook(stage, tx, memberID)
	}
}

// revalidateRequeuer 成員曾被逐台補跑重新排入時，派送前另以重排者**當下**的能力重驗。
//
// 重排是把工作重新打開的那一步，而重排提交後到派送取得鎖之間有解鎖窗口：背景排程可能
// 先接手，它只帶本輪發起者的脈絡。沒有這一道，等鎖期間已失權的重排者仍能經背景以發起者
// 的脈絡把工作送出。重排者與發起者同一人、或就是本次手動派送的點擊者（上一步已驗過）時不重複判定。
func (s *CredentialRotationService) revalidateRequeuer(ctx context.Context, db *gorm.DB, auth *model.CredentialJobAuthorization,
	member *model.CredentialRotationMember, req CredentialManagementRequest) string {

	if member.RequeuedBy == 0 || member.RequeuedBy == auth.ActorID {
		return ""
	}
	if ctx != nil {
		if uid, _ := model.UserFromContext(ctx); uid == member.RequeuedBy {
			return ""
		}
	}
	req.Operation = CredOpRun
	req.Capabilities = authorizationCapabilities(auth, []string{CredCapRotate})
	requeuer := contextWithInitiator(context.Background(), member.RequeuedBy, member.RequeuedByName)
	if _, err := s.mgmt.require(requeuer, db, req); err != nil {
		return revalidationReason(err)
	}
	return ""
}

// reauthorizeRotationByClicker 還原前建立的輪替授權脈絡，由手動補跑的具權點擊者重新確認：
// 以點擊者當下的能力重驗，通過才新增一列授權脈絡（記現行還原世代）並掛到輪替上。
// 背景補跑（沒有伺服器端主體）回原因碼，不替任何人重新授權。
func (s *CredentialRotationService) reauthorizeRotationByClicker(ctx context.Context, rot *model.CredentialRotation,
	member *model.CredentialRotationMember, old *model.CredentialJobAuthorization) (*model.CredentialJobAuthorization, string) {

	uid, uname := model.UserFromContext(ctx)
	if uid == 0 {
		return nil, model.ChangeSecretReasonAuthzRestored
	}
	// old 為 nil＝升級前的輪替從沒有授權脈絡：能力集用預設，修訂號從 1 起，來源記為重新授權
	revision, caps := 1, []string{CredCapRotate}
	var bound []uint
	if old != nil {
		revision, caps = old.Revision+1, authorizationCapabilities(old, caps)
		// 資產上界隨承接延續：承接只換發起者與世代，不放寬原本確認的目標
		b, berr := authorizationTargetBound(old)
		if berr != nil {
			return nil, jobAuthReason(berr)
		}
		bound = b
	}
	req := CredentialManagementRequest{
		Operation: CredOpRun, Capabilities: caps,
		CredentialIDs: []uint{member.CredentialID}, MountedAssetIDs: []uint{member.AssetID}, AccountIDs: []uint{member.AccountID},
	}
	if len(bound) > 0 {
		// 帶上界的拆分：點擊者以成員所在資產判定，能力取嚴格解碼聯集拆分模式下限（與派送前重驗同一口徑）
		bcaps, cerr := boundedRotationCapabilities(old)
		if cerr != nil {
			return nil, jobAuthReason(cerr)
		}
		req = CredentialManagementRequest{
			Operation: CredOpRun, Capabilities: bcaps,
			AssetIDs: []uint{member.AssetID}, AccountIDs: []uint{member.AccountID},
		}
	}
	decision, err := s.mgmt.require(ctx, s.db, req)
	if err != nil {
		return nil, revalidationReason(err)
	}
	var row *model.CredentialJobAuthorization
	// 承接與它的審計同一交易：審計寫不進去即整筆回滾（授權列與輪替引用都不留），
	// 呼叫端照停止路徑處理（成員停止、候選保留、告警），遠端不開始
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		var ierr error
		row, ierr = insertJobAuthorization(s.mgmt, tx, jobAuthInput{
			kind: model.JobAuthSourceRotation, sourceID: rot.ID, revision: revision,
			actorID: uid, actorName: uname, via: model.JobAuthViaReauthorized,
			authzVersion: decision.AuthzVersion, sources: decision.Sources, capabilities: req.Capabilities,
			targetBound: bound,
		})
		if ierr != nil {
			return ierr
		}
		if err := tx.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
			Update("authorization_id", row.ID).Error; err != nil {
			return err
		}
		return s.writeRotationReauthorizationAudit(tx, rot, member, uid, uname, row.ID, old == nil)
	}); err != nil {
		log.Printf("[CredentialRotation] 承接輪替未完成（授權列或審計寫入失敗），不承接 rotation=%d: %v", rot.ID, err)
		return nil, model.ChangeSecretReasonAuthzUnavailable
	}
	rot.AuthorizationID = &row.ID
	log.Printf("[CredentialRotation] 由具權者手動補跑承接輪替 rotation=%d initiator=%d authorization=%d", rot.ID, uid, row.ID)
	return row, ""
}

// writeRotationReauthorizationAudit 具權者承接輪替（還原後或升級前無脈絡）的審計，寫在承接的交易內：
// 落地面缺席或寫入失敗回錯誤，承接隨之回滾。
func (s *CredentialRotationService) writeRotationReauthorizationAudit(tx *gorm.DB, rot *model.CredentialRotation,
	member *model.CredentialRotationMember, uid uint, uname string, authorizationID uint, legacy bool) error {

	details, _ := json.Marshal(map[string]any{
		"resource": string(model.ResourceCredential), "credential_id": member.CredentialID,
		"operation": "rotation_reauthorized", "rotation_id": rot.ID, "member_id": member.ID,
		"authorization_id": authorizationID, "legacy_without_context": legacy,
	})
	credID, assetID := member.CredentialID, member.AssetID
	return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: uid, Username: uname},
		Action:     string(model.ActionUpdate),
		Resource:   string(model.ResourceCredential),
		ResourceID: &credID,
		AssetID:    &assetID,
		Status:     string(model.StatusSuccess),
		Details:    string(details),
	})
}

// RevalidationWired 授權重驗判定器是否已注入（組裝根自檢用：未注入時成員步驟一律拒絕）。
func (s *CredentialRotationService) RevalidationWired() bool {
	return s != nil && s.mgmt.authorizer != nil && s.mgmt.restoreGenerationWired() && s.auditTx != nil
}

// WithStopNotifier 注入授權停止的推送（組裝根）；nil＝只寫日誌與審計。
func (s *CredentialRotationService) WithStopNotifier(fn func(rule, message string)) *CredentialRotationService {
	s.stopNotify = fn
	return s
}

// stopMember 授權重驗失敗：成員停止（尚未動過遠端者收束、重試中者終局失敗），
// 不再自動恢復；留記錄、審計與告警。遠端未被觸碰。
func (s *CredentialRotationService) stopMember(rot *model.CredentialRotation,
	member *model.CredentialRotationMember, reason string, run memberRun) {

	to := model.CredentialMemberAbandoned
	if member.State == model.CredentialMemberRetryWait {
		to = model.CredentialMemberTerminalFailed
	}
	if err := s.transition(member, to, memberTransition{LastError: reason}); err != nil {
		logMemberTransitionFailure(member, to, err)
		return
	}
	s.recordMember(member, model.ChangeSecretSkipped, reason, run)
	logJobStop(fmt.Sprintf("rotation=%d member=%d", rot.ID, member.ID), reason, rot.RequestedBy)
	s.auditMemberStop(rot, member, reason)
	if s.stopNotify != nil {
		s.stopNotify("改密工作因授權失效停止",
			fmt.Sprintf("rotation=%d asset_id=%d account=%s reason=%s（遠端未被觸碰，需具權者重新發起）",
				rot.ID, member.AssetID, member.Username, reason))
	}
}

func (s *CredentialRotationService) auditMemberStop(rot *model.CredentialRotation,
	member *model.CredentialRotationMember, reason string) {

	if s.auditTx == nil {
		return
	}
	details, _ := json.Marshal(map[string]any{
		"resource": string(model.ResourceCredential), "credential_id": member.CredentialID,
		"operation": "authorization_stop", "rotation_id": rot.ID, "account_id": member.AccountID,
		"reason": reason,
	})
	credID, assetID := member.CredentialID, member.AssetID
	err := s.db.Transaction(func(tx *gorm.DB) error {
		return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
			OccurredAt: time.Now(),
			Actor:      gatewayapi.Actor{UserID: rot.RequestedBy, Username: rot.RequestedByName},
			Action:     string(model.ActionUpdate),
			Resource:   string(model.ResourceCredential),
			ResourceID: &credID,
			AssetID:    &assetID,
			Status:     string(model.StatusDenied),
			Details:    string(details),
		})
	})
	if err != nil {
		log.Printf("[CredentialRotation] 授權停止事件審計寫入失敗: %v", err)
	}
}

// revalidateCandidate 候選重試前的重驗。判定器未注入＝拒絕重試並告警（不以「不重驗」放行）；
// 升級前的舊候選沒有授權脈絡，見 revalidateLegacyCandidate。
func (r *ChangeSecretRetryRunner) revalidateCandidate(caller context.Context, cand *model.ChangeSecretCandidate) string {
	if r.mgmt.authorizer == nil {
		log.Printf("[ChangeSecretRetry] 授權重驗判定器未注入，拒絕重試 id=%d", cand.ID)
		return model.ChangeSecretReasonAuthzUnavailable
	}
	if cand.AuthorizationID == nil {
		return r.revalidateLegacyCandidate(caller, cand)
	}
	auth, err := loadJobAuthorization(r.db, cand.AuthorizationID)
	if err != nil {
		return jobAuthReason(err)
	}
	if reason := restoreStopReason(r.mgmt, r.db, auth); reason != "" {
		if uid, _ := model.UserFromContext(caller); reason == model.ChangeSecretReasonAuthzRestored && uid != 0 {
			// 手動重試：具權的點擊者重新確認，新增一列授權脈絡（記現行還原世代）後送出
			return r.revalidateLegacyCandidate(caller, cand)
		}
		return reason
	}
	// 判定短交易（dispatch_judge_tx.go）：拓撲序列化鎖後以交易內視圖判定候選所屬資產，提交後才驗證或送出；
	// 候選沒有領取欄，判定本身即裁決點
	return judgeInTopologyTx(r.db, r.lockTopologyTx, func(tx *gorm.DB) (string, error) {
		return revalidateAuthorization(r.mgmt, tx, caller, auth, CredentialManagementRequest{
			AssetIDs: []uint{cand.AssetID}, AccountIDs: []uint{cand.AccountID},
		}, []string{CredCapAccountRotate}), nil
	})
}

// lockTopologyTx 候選重試判定短交易的第一個動作。未組裝資產服務或其拓撲 port 時回錯誤（判定以無從判定停止）。
func (r *ChangeSecretRetryRunner) lockTopologyTx(tx *gorm.DB) error {
	if r.assets == nil {
		return ErrTopologyPermissionPortMissing
	}
	return r.assets.lockTopologyTx(tx)
}

// revalidateLegacyCandidate 升級前的舊候選沒有發起者（或授權脈絡留自還原之前，手動重試時同走此路），
// 不能以「不重驗」放行：
//   - 背景重試（caller 無主體）：不送出、停下並告警，候選保留供人手動處理；
//   - 手動重試：以點擊者**當下**的能力做同一套重驗，通過才重試，並把點擊者記為
//     該次授權（新增一列授權脈絡並掛到候選，之後的重試沿此發起者重驗）。
func (r *ChangeSecretRetryRunner) revalidateLegacyCandidate(caller context.Context, cand *model.ChangeSecretCandidate) string {
	uid, uname := model.UserFromContext(caller)
	if uid == 0 {
		logJobStop(fmt.Sprintf("retry candidate=%d", cand.ID), model.ChangeSecretReasonAuthzContextMissing, 0)
		// 告警每個候選只發一次（由呼叫端的 alertStopOnce 判斷），不隨退避週期重複
		return model.ChangeSecretReasonAuthzContextMissing
	}
	req := CredentialManagementRequest{
		Operation: CredOpRun, Capabilities: []string{CredCapAccountRotate},
		AssetIDs: []uint{cand.AssetID}, AccountIDs: []uint{cand.AccountID},
	}
	kind, sourceID := model.JobAuthSourcePlan, cand.PlanID
	if sourceID == 0 {
		kind, sourceID = model.JobAuthSourceBatch, cand.BatchID
	}
	// 判定短交易：拓撲序列化鎖後以點擊者當下的能力判定，通過才在同一交易留下授權列與候選引用；
	// 留痕寫不進去即整筆回滾、停止重試
	var row *model.CredentialJobAuthorization
	reason := judgeInTopologyTx(r.db, r.lockTopologyTx, func(tx *gorm.DB) (string, error) {
		decision, err := r.mgmt.require(caller, tx, req)
		if err != nil {
			return revalidationReason(err), nil
		}
		if sourceID == 0 {
			return "", nil
		}
		row, err = insertJobAuthorization(r.mgmt, tx, jobAuthInput{
			kind: kind, sourceID: sourceID, revision: 0, actorID: uid, actorName: uname,
			via: model.JobAuthViaManualCandidate, authzVersion: decision.AuthzVersion, sources: decision.Sources,
			capabilities: req.Capabilities, targetBound: []uint{cand.AssetID},
		})
		if err != nil {
			return model.ChangeSecretReasonAuthzUnavailable, fmt.Errorf("舊候選授權留痕失敗 id=%d: %w", cand.ID, err)
		}
		if err := tx.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Update("authorization_id", row.ID).Error; err != nil {
			return model.ChangeSecretReasonAuthzUnavailable, fmt.Errorf("舊候選授權引用寫入失敗 id=%d: %w", cand.ID, err)
		}
		return "", nil
	})
	if reason != "" {
		return reason
	}
	if sourceID == 0 {
		// 無來源也要補記指紋：否則畫面開出的確認框按下必定失敗
		if reason := r.pinLegacyTarget(cand); reason != "" {
			return reason
		}
		// 無從掛載來源：本次仍以點擊者的重驗放行，但不留持久授權列
		log.Printf("[ChangeSecretRetry] 舊候選手動重試通過重驗（無來源可掛授權）id=%d initiator=%d", cand.ID, uid)
		return ""
	}
	cand.AuthorizationID = &row.ID
	if reason := r.pinLegacyTarget(cand); reason != "" {
		return reason
	}
	log.Printf("[ChangeSecretRetry] 舊候選由具權者手動重試 id=%d initiator=%d authorization=%d", cand.ID, uid, row.ID)
	return ""
}

// pinLegacyTarget 具權者明示重試＝確認以目前的目標為準：固定目標指紋，之後的有限驗證據此比對。
// 不能證實目標（掛載或資產已不存在）則回拒絕原因，呼叫端拒絕此次重試。
func (r *ChangeSecretRetryRunner) pinLegacyTarget(cand *model.ChangeSecretCandidate) string {
	if err := r.candidates.PinTargetFingerprint(cand.ID, cand.AccountID); err != nil {
		log.Printf("[ChangeSecretRetry] 舊候選無法證實目標，拒絕重試 id=%d: %v", cand.ID, err)
		return model.ChangeSecretReasonAuthzTargetChanged
	}
	return ""
}
