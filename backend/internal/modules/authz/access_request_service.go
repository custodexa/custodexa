package authz

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	// ErrAccessRequestNotFound 申請單不存在（含 owner-scoped 查無：不洩漏他人單存在性）
	ErrAccessRequestNotFound = errors.New("申請單不存在")
	// ErrAccessRequestConflict 狀態轉移 CAS 落敗（併發的核准/拒絕/撤回/超時僅一方成立）
	ErrAccessRequestConflict = errors.New("申請單狀態已變更，請重新整理")
	// ErrDuplicatePendingRequest 同人同資產已有 pending 在途單
	ErrDuplicatePendingRequest = errors.New("同資產已有在途申請")
	// ErrDurationExceedsPolicy 申請時長超過政策上限
	ErrDurationExceedsPolicy = errors.New("申請時長超過政策上限")
	// ErrDecisionIncrease 核准值不得優於申請值（時長上調/起始提前）
	ErrDecisionIncrease = errors.New("核准值不得優於申請值（時長僅可下修、起始僅可推遲）")
	// ErrPolicyOpenNoRequest open 段位資產不需申請
	ErrPolicyOpenNoRequest = errors.New("該資產不需申請即可連線")
	// ErrSelfApproval 禁自核硬擋（含範圍內唯一 approver 即申請人；admin 亦不得核自己的單）
	ErrSelfApproval = errors.New("不得核准或拒絕自己的申請")
	// ErrNotEligibleApprover 範圍外 approver 無決定資格
	ErrNotEligibleApprover = errors.New("申請資產不在您的審核範圍內")
	// ErrDecisionNoteRequired 拒絕須記事由
	ErrDecisionNoteRequired = errors.New("拒絕申請必須填寫事由")
	// ErrRequesterExempt admin 豁免政策閘、auditor 不應連線資產——皆不受理申請
	ErrRequesterExempt = errors.New("此角色不需或不得提出連線申請")
	// ErrStartInPast 預約起始時間早於現在
	ErrStartInPast = errors.New("預約起始時間不得早於現在")

	// ErrBreakGlassDisabled 破窗功能未開放（政策開關預設關，G 決議；403＋機器可辨）
	ErrBreakGlassDisabled = errors.New("破窗緊急連線未開放")
	// ErrBreakGlassNotEligible 破窗資格不足（需時窗內常設 connect；票證不算）
	ErrBreakGlassNotEligible = errors.New("無破窗資格（需持有該資產的常設連線授權）")
	// ErrDuplicateBreakGlass 同資產已有有效破窗票證
	ErrDuplicateBreakGlass = errors.New("同資產已有有效的破窗連線")
	// ErrTicketNotActive 無有效票證可撤（已到期或已撤銷，與撤銷語義分離）
	ErrTicketNotActive = errors.New("無有效臨時授權可撤銷")
	// ErrNotRevokeEligible 撤銷資格不足（一般單＝admin＋原核准人；
	// 自動核准/破窗單＝admin＋範圍命中 approver，六題 4）
	ErrNotRevokeEligible = errors.New("僅管理員或原核准人可撤銷此臨時授權")
	// ErrSelfReview 破窗人不得補審自己的破窗單（禁自核延伸，含 admin）
	ErrSelfReview = errors.New("不得補審自己的破窗連線")
	// ErrNotBreakGlass 補審僅適用破窗單
	ErrNotBreakGlass = errors.New("此申請單非破窗連線，無需補審")
	// ErrAlreadyReviewed 補審 CAS 落敗（已補審或併發補審僅一方成立）
	ErrAlreadyReviewed = errors.New("此破窗連線已完成補審")
	// ErrInvalidReviewDisposition 補審處置值非法
	ErrInvalidReviewDisposition = errors.New("補審處置僅接受 confirmed 或 violation")
	// ErrAlreadyApprovedByActor 同人重複核准（quorum 逐票唯一，含 admin）
	ErrAlreadyApprovedByActor = errors.New("您已核准過此申請")
)

// DurationExceedsPolicyError 申請時長超限，附政策上限（分鐘）。
//
// 上限值是使用者改單重送的必需資訊，但 handler 無法從 sentinel 反推動態值，
// 故以具名欄位帶出（同 PasswordPolicyViolation 的既有作法），由 handler 轉為
// apierror 的 {minutes} param。errors.Is(err, ErrDurationExceedsPolicy) 續可比對。
type DurationExceedsPolicyError struct {
	// MaxMinutes 政策上限（access_request_max_duration_minutes 現值）
	MaxMinutes int
}

func (e *DurationExceedsPolicyError) Error() string {
	return fmt.Sprintf("%s（上限 %d 分鐘）", ErrDurationExceedsPolicy.Error(), e.MaxMinutes)
}

// Unwrap 讓 errors.Is 可比對底層 sentinel
func (e *DurationExceedsPolicyError) Unwrap() error { return ErrDurationExceedsPolicy }

// expireBatchLimit 單輪超時掃描上限（成本紅線：長迴圈設上限）
const expireBatchLimit = 500

// SubmitAccessRequestInput 申請提出輸入
type SubmitAccessRequestInput struct {
	AssetID         uint
	Reason          string
	DurationMinutes int
	DateStart       *time.Time // 空＝立即（核准時起算）
	// Accounts 申請的帳號範圍（asset-multi-account D5）：**nil＝欄位省略＝@ALL**
	// （既有行為）；非 nil 空清單拒收（F1）。核准後原樣落到臨時授權列——
	// 申請「以 app 連」不該核出 root
	Accounts *[]string
}

// DecideInput 核准輸入：核准人可下修時長/推遲起始，不可上調（決議 C）
type DecideInput struct {
	DurationMinutes *int
	DateStart       *time.Time
	Note            string
}

// AccessRequestServiceInterface 申請核准流服務介面（handler 注入用）
type AccessRequestServiceInterface interface {
	Submit(requesterID uint, username, role string, input SubmitAccessRequestInput) (*model.AccessRequest, error)
	Cancel(requesterID uint, requestID uint) (*model.AccessRequest, error)
	Approve(actorID uint, isAdmin bool, requestID uint, input DecideInput) (*model.AccessRequest, error)
	Reject(actorID uint, isAdmin bool, requestID uint, note string) (*model.AccessRequest, error)
	ListMine(requesterID uint) ([]*model.AccessRequest, error)
	MyActiveTickets(requesterID uint, now time.Time) ([]*model.AssetAuthorization, error)
	ListPending(actorID uint, isAdmin bool, now time.Time) ([]*model.AccessRequest, error)
	ListHistory(actorID uint, isAdmin bool, page, pageSize int) ([]*model.AccessRequest, int64, error)
	ActiveTickets(actorID uint, isAdmin bool, now time.Time) ([]*model.AssetAuthorization, error)
	PendingCount(actorID uint, isAdmin bool, now time.Time) (int64, error)
	ExpireOverdue(now time.Time) (int, error)

	// break-glass-revocation：破窗、提前撤銷、補審
	BreakGlass(requesterID uint, username, role string, assetID uint, reason string) (*model.AccessRequest, error)
	Revoke(actorID uint, isAdmin bool, username string, requestID uint, note string) (*model.AccessRequest, error)
	Review(actorID uint, isAdmin bool, requestID uint, disposition, note string) (*model.AccessRequest, error)
	ListPendingReview(actorID uint, isAdmin bool) ([]*model.AccessRequest, error)
	PendingReviewCount(actorID uint, isAdmin bool) (int64, error)
	NotifyOverdueReviews(now time.Time) (int, error)
}

// AccessRequestService 申請核准流（access-policy-approval D2/D3/D5）。
// 決議鐵則：時效來源唯一（核准流）、CAS 終態不可復活、審計完整、
// 禁自核硬擋（含單人層）、payload 最小化
type AccessRequestService struct {
	db           *gorm.DB
	policies     *policy.SecurityPolicyService
	accessPolicy *policy.AccessPolicyService
	authzRepo    *assetAuthorizationRepository
	audit        *audit.AuditLogService
	notifier     *audit.AlertNotifier
	// sessions 撤銷即斷線收線（D5）；nil＝不聯動（測試路徑或政策恆關部署）
	sessions SessionTerminator
}

// SessionTerminator 撤銷授權時強制終斷該使用者對該資產的進行中會話（D5）。
//
// **消費者側窄介面（modular-architecture W7 §4.6）**：authz 不得 import session
// （矩陣 §1.4 authz→session ✗）。介面在此宣告、由組裝根注入 `*service.SessionService`，
// 故不成編譯循環。同型前例＝`user_service.go:75` 的 `SessionTerminator`
type SessionTerminator interface {
	TerminateByUserAsset(userID, assetID uint, reason string) (int, error)
}

// SetSessionService 注入會話服務（組裝端呼叫；撤銷即斷線政策開啟時收線用）
func (s *AccessRequestService) SetSessionService(sessions SessionTerminator) {
	s.sessions = sessions
}

// NewAccessRequestService 建立申請核准流服務。audit/notifier 可為 nil（測試路徑）
func NewAccessRequestService(
	db *gorm.DB,
	policies *policy.SecurityPolicyService,
	accessPolicy *policy.AccessPolicyService,
	audit *audit.AuditLogService,
	notifier *audit.AlertNotifier,
) *AccessRequestService {
	return &AccessRequestService{
		db:           db,
		policies:     policies,
		accessPolicy: accessPolicy,
		authzRepo:    newAssetAuthorizationRepository(db),
		audit:        audit,
		notifier:     notifier,
	}
}

// Submit 提出申請（D2）：事由必填、時長≤政策上限、可預約起始、去重擋在途單、
// open 段拒建單；reason 段同交易即時自動核准（決定者記 system、auto 標記）——
// 與強制審核共用同一表單與資料軌（決議 B）
func (s *AccessRequestService) Submit(requesterID uint, username, role string, input SubmitAccessRequestInput) (*model.AccessRequest, error) {
	// admin 豁免政策閘不需申請；auditor 本就不得連線資產（決議 3 的必然推論：
	// 若受理 auditor 申請，核准即繞過「auditor 不豁免」的攔截語義）
	if role == model.RoleAdmin || role == model.RoleAuditor {
		return nil, ErrRequesterExempt
	}

	var asset model.Asset
	if err := s.db.First(&asset, input.AssetID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAccessRequestNotFound
		}
		return nil, fmt.Errorf("查詢資產失敗: %w", err)
	}

	// 可視守門：不可視的資產回「不存在」語義（不洩漏存在性；三來源之一即可視）
	visible, err := s.authzRepo.CheckPermission(requesterID, asset.ID,
		[]model.PermissionType{model.PermissionView, model.PermissionConnect})
	if err != nil {
		return nil, err
	}
	if !visible {
		if covered, err := s.authzRepo.ApproverScopeCoversAsset(requesterID, asset.ID); err != nil {
			return nil, err
		} else if !covered {
			return nil, ErrAccessRequestNotFound
		}
	}

	// 區域變數改名 policy→segment（W3 搬包：`policy` 已是套件名，同名區域變數會遮蔽它）
	segment := s.accessPolicy.AccessPolicyOf(&asset)
	if segment == model.AccessPolicyOpen {
		return nil, ErrPolicyOpenNoRequest
	}

	maxDuration := s.policies.GetInt(policy.PolicyAccessRequestMaxDurationMinutes)
	if input.DurationMinutes < 1 || input.DurationMinutes > maxDuration {
		return nil, &DurationExceedsPolicyError{MaxMinutes: maxDuration}
	}
	now := time.Now()
	if input.DateStart != nil && input.DateStart.Before(now) {
		return nil, ErrStartInPast
	}

	// 帳號範圍（asset-multi-account D5）：與授權列共用同一組驗證與正規化，
	// 避免申請單接受了授權列拒收的形狀，核准時才炸在建授權那一步
	accountScope, err := NormalizeGrantAccounts(input.Accounts)
	if err != nil {
		return nil, err
	}

	timeoutHours := s.policies.GetInt(policy.PolicyAccessRequestPendingTimeoutHours)
	buildRequest := func() *model.AccessRequest {
		return &model.AccessRequest{
			RequesterID:              requesterID,
			AssetID:                  asset.ID,
			Reason:                   input.Reason,
			RequestedDurationMinutes: input.DurationMinutes,
			RequestedDateStart:       input.DateStart,
			Status:                   model.AccessRequestPending,
			PendingExpiresAt:         now.Add(time.Duration(timeoutHours) * time.Hour),
			Kind:                     model.AccessRequestKindNormal,
			Accounts:                 accountScope,
		}
	}
	createOnce := func(req *model.AccessRequest) error {
		return s.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(req).Error; err != nil {
				return err
			}
			// reason 段即時自動核准：同一狀態機軌跡（pending→approved），差別只在免等
			if segment == model.AccessPolicyReason {
				return s.approveInTx(tx, req, nil, DecideInput{}, true, now)
			}
			return nil
		})
	}

	req := buildRequest()
	err = createOnce(req)
	if err != nil && dberr.IsUniqueViolation(err) {
		// 撞去重：若在途單其實已逾時（scheduler 尚未掃到），就地 CAS 作廢後重試
		// 一次——惰性過濾只蓋讀路徑，寫路徑不補全會讓使用者卡到下一輪掃描
		// （UI 走查實測發現）。真 pending 則回在途單識別（409）
		if s.expireOverduePendingFor(requesterID, asset.ID, now) {
			req = buildRequest()
			err = createOnce(req)
		}
	}
	if err != nil {
		if dberr.IsUniqueViolation(err) {
			return nil, s.duplicatePendingError(requesterID, asset.ID)
		}
		return nil, fmt.Errorf("建立申請失敗: %w", err)
	}

	if req.AutoApproved {
		s.logAudit(requesterID, username, model.ActionApprove, req.ID,
			`{"auto":true,"decided_by":"system"}`)
		s.notify(notifycat.EventAccessRequestApproved, req.ID, asset.Name,
			map[string]string{"mode": notifycat.ApprovalModeAuto})
	} else {
		s.notify(notifycat.EventAccessRequestCreated, req.ID, asset.Name, nil)
	}
	return s.reload(req.ID)
}

// expireOverduePendingFor 就地作廢單一使用者×資產的逾期 pending 單（CAS，
// 與 scheduler 掃描同語義同審計）；有作廢任一筆回 true
func (s *AccessRequestService) expireOverduePendingFor(requesterID, assetID uint, now time.Time) bool {
	var overdue model.AccessRequest
	err := s.db.Select("id").
		Where("requester_id = ? AND asset_id = ? AND status = ? AND pending_expires_at < ?",
			requesterID, assetID, model.AccessRequestPending, now).
		First(&overdue).Error
	if err != nil {
		return false
	}
	res := s.db.Model(&model.AccessRequest{}).
		Where("id = ? AND status = ?", overdue.ID, model.AccessRequestPending).
		Updates(map[string]interface{}{"status": model.AccessRequestExpired, "updated_at": now})
	if res.Error != nil || res.RowsAffected == 0 {
		return false
	}
	s.logAudit(requesterID, "system", model.ActionExpire, overdue.ID, `{"cause":"pending_timeout_on_resubmit"}`)
	return true
}

// duplicatePendingError 查在途單識別供 409 回應
func (s *AccessRequestService) duplicatePendingError(requesterID, assetID uint) error {
	var existing model.AccessRequest
	err := s.db.Select("id").
		Where("requester_id = ? AND asset_id = ? AND status = ?", requesterID, assetID, model.AccessRequestPending).
		First(&existing).Error
	if err == nil {
		return fmt.Errorf("%w（單號 %d）", ErrDuplicatePendingRequest, existing.ID)
	}
	return ErrDuplicatePendingRequest
}

// approveInTx 核准共用路徑（人工與自動）：CAS 轉 approved＋同交易建臨時授權＋回填 FK。
// 決議 C：核准人可下修時長/推遲起始，不可上調——優於申請值即拒
func (s *AccessRequestService) approveInTx(tx *gorm.DB, req *model.AccessRequest, approverID *uint, input DecideInput, auto bool, now time.Time) error {
	duration := req.RequestedDurationMinutes
	if input.DurationMinutes != nil {
		if *input.DurationMinutes > req.RequestedDurationMinutes || *input.DurationMinutes < 1 {
			return ErrDecisionIncrease
		}
		duration = *input.DurationMinutes
	}

	// 起始：申請空值＝核准即刻起算；核准人僅可推遲（不可早於申請值/現在）
	start := now
	if req.RequestedDateStart != nil {
		start = *req.RequestedDateStart
	}
	if input.DateStart != nil {
		if input.DateStart.Before(start) {
			return ErrDecisionIncrease
		}
		start = *input.DateStart
	}
	expired := start.Add(time.Duration(duration) * time.Minute)

	note := input.Note
	if auto {
		note = "system"
	}
	updates := map[string]interface{}{
		"status":                    model.AccessRequestApproved,
		"approver_id":               approverID,
		"decided_at":                now,
		"decision_note":             note,
		"approved_duration_minutes": duration,
		"approved_date_start":       start,
		"auto_approved":             auto,
		"updated_at":                now,
	}
	// CAS 帶逾時守衛（codex 審查 #2）：scheduler 五分鐘間隙內，已逾 pending_expires_at
	// 的申請雖已從待審列表惰性過濾，直呼 approve 仍可能搶在掃描前把它合法化。
	// 加 pending_expires_at > now 讓「本應 expired 的申請」核准落敗回 409（終態語義）。
	// 自動核准路徑（Submit 同交易建單）的 expires_at 為未來值，此守衛恆過
	res := tx.Model(&model.AccessRequest{}).
		Where("id = ? AND status = ? AND pending_expires_at > ?", req.ID, model.AccessRequestPending, now).
		Updates(updates)
	if res.Error != nil {
		return fmt.Errorf("核准狀態轉移失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrAccessRequestConflict
	}

	// 臨時授權：申請人×資產×connect＋時效窗＋source=ticket（D3）。
	// granted_by 有 FK 至 users——自動核准以申請人落欄（觸發者），
	// 決定者=system 由 auto_approved＋decision_note 承載
	grantedBy := req.RequesterID
	if approverID != nil {
		grantedBy = *approverID
	}
	// 帳號範圍原樣自申請單傳遞（asset-multi-account D5）：核准人**不得上調**——
	// 沿用時長／起始「只可下修」的既有語義。核准動作沒有帳號範圍輸入欄，
	// 故此處直接取申請值即已滿足「不可上調」；日後若開放核准時調整，
	// 必須加上「新範圍 ⊆ 申請範圍」的驗證，否則核准即可授出未經申請的帳號
	auth := &model.AssetAuthorization{
		UserID:      &req.RequesterID,
		AssetID:     &req.AssetID,
		Permission:  model.PermissionConnect,
		DateStart:   &start,
		DateExpired: &expired,
		GrantedBy:   grantedBy,
		Source:      model.AuthorizationSourceTicket,
		Accounts:    req.Accounts,
	}
	if err := tx.Create(auth).Error; err != nil {
		return fmt.Errorf("建立臨時授權失敗: %w", err)
	}
	if err := tx.Model(&model.AccessRequest{}).Where("id = ?", req.ID).
		Update("authorization_id", auth.ID).Error; err != nil {
		return fmt.Errorf("回填授權關聯失敗: %w", err)
	}

	// 回寫呼叫端持有的實體（Submit 自動核准路徑回傳用）
	req.Status = model.AccessRequestApproved
	req.AutoApproved = auto
	req.AuthorizationID = &auth.ID
	return nil
}

// eligibleToDecide 決定資格＝admin 兜底 OR 審核範圍命中；禁自核先於資格判定硬擋
func (s *AccessRequestService) eligibleToDecide(actorID uint, isAdmin bool, req *model.AccessRequest) error {
	if req.RequesterID == actorID {
		return ErrSelfApproval
	}
	// admin 兜底＝具核准資格（quorum 語義下計一票、不單票繞過門檻，
	// 見 Approve 的 quorumApprove；各 isAdmin 短路點語義以此為準）
	if isAdmin {
		return nil
	}
	covered, err := s.authzRepo.ApproverScopeCoversRequest(actorID, req.AssetID, req.RequesterID)
	if err != nil {
		return err
	}
	if !covered {
		return ErrNotEligibleApprover
	}
	return nil
}

// loadPending 載入申請單（不存在→NotFound；終態交由 CAS 判 409，此處不預判）
func (s *AccessRequestService) loadPending(requestID uint) (*model.AccessRequest, error) {
	var req model.AccessRequest
	if err := s.db.First(&req, requestID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAccessRequestNotFound
		}
		return nil, fmt.Errorf("查詢申請單失敗: %w", err)
	}
	return &req, nil
}

// Approve 人工核准（範圍命中 approver 或 admin；approval-routing-quorum D-3）：
// 逐票記錄，核准數達政策門檻（access_request_min_approvals）的那一票才 CAS 轉
// approved 產生臨時授權；門檻 1＝與單人核准零行為差異。admin 兜底語義在 quorum
// 下＝「有資格投一票」而非「單票通過」（雙人完整性；各 isAdmin 短路點以此為準）。
// 併發序列化：交易起手以 CAS UPDATE 鎖申請單列（終態即擋），後續計票在鎖內正確
func (s *AccessRequestService) Approve(actorID uint, isAdmin bool, requestID uint, input DecideInput) (*model.AccessRequest, error) {
	req, err := s.loadPending(requestID)
	if err != nil {
		return nil, err
	}
	if err := s.eligibleToDecide(actorID, isAdmin, req); err != nil {
		return nil, err
	}

	required := s.policies.GetInt(policy.PolicyAccessRequestMinApprovals)
	if required < 1 {
		required = 1
	}

	now := time.Now()
	reached := false
	var votes int64
	err = s.db.Transaction(func(tx *gorm.DB) error {
		// 鎖單（可攜寫法，Postgres/SQLite 皆適用）：UPDATE 取得列鎖並驗 pending，
		// 併發核准/拒絕/撤回在此序列化；終態單 RowsAffected=0 走衝突。
		// 逾時守衛（codex gpt-5.6-sol 審查 P2）：門檻>1 時未達門檻的票不呼叫
		// approveInTx，其 pending_expires_at 守衛遂被繞過——已逾期單的部分票會被
		// 永久記入並回成功。此處鎖單即帶 pending_expires_at > now，讓逾期單鎖不命中
		// 走衝突（與 approveInTx 同一守衛，投票入庫前擋下）
		lock := tx.Model(&model.AccessRequest{}).
			Where("id = ? AND status = ? AND pending_expires_at > ?", req.ID, model.AccessRequestPending, now).
			Update("updated_at", now)
		if lock.Error != nil {
			return fmt.Errorf("鎖定申請單失敗: %w", lock.Error)
		}
		if lock.RowsAffected == 0 {
			return ErrAccessRequestConflict
		}

		// 交易內重查資格（codex #3 TOCTOU）：鎖單後、投票入庫前，操作者可能已被
		// 移出審核方群組或範圍被刪——非 admin 一律於鎖內重判，杜絕以已撤資格寫入
		// 達門檻的最後一票。admin 兜底恆具資格不需重查
		if !isAdmin {
			covered, cErr := s.authzRepo.ApproverScopeCoversRequestTx(tx, actorID, req.AssetID, req.RequesterID)
			if cErr != nil {
				return cErr
			}
			if !covered {
				return ErrNotEligibleApprover
			}
		}

		vote := &model.AccessRequestApproval{RequestID: req.ID, ApproverID: actorID, Note: input.Note}
		if err := tx.Create(vote).Error; err != nil {
			if dberr.IsUniqueViolation(err) {
				return ErrAlreadyApprovedByActor
			}
			return fmt.Errorf("寫入核准記錄失敗: %w", err)
		}
		if err := tx.Model(&model.AccessRequestApproval{}).
			Where("request_id = ?", req.ID).Count(&votes).Error; err != nil {
			return fmt.Errorf("計票失敗: %w", err)
		}
		if int(votes) >= required {
			reached = true
			return s.approveInTx(tx, req, &actorID, input, false, now)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	result, rerr := s.reload(requestID)
	if rerr != nil {
		return nil, rerr
	}
	if reached {
		s.notify(notifycat.EventAccessRequestApproved, req.ID, s.assetName(req.AssetID),
			map[string]string{"mode": notifycat.ApprovalModeManual})
	} else {
		s.notify(notifycat.EventAccessRequestApprovalProgress, req.ID, s.assetName(req.AssetID),
			map[string]string{
				"votes":    strconv.FormatInt(votes, 10),
				"required": strconv.Itoa(required),
			})
	}
	return result, nil
}

// Reject 拒絕（事由必填）
func (s *AccessRequestService) Reject(actorID uint, isAdmin bool, requestID uint, note string) (*model.AccessRequest, error) {
	if note == "" {
		return nil, ErrDecisionNoteRequired
	}
	req, err := s.loadPending(requestID)
	if err != nil {
		return nil, err
	}
	if err := s.eligibleToDecide(actorID, isAdmin, req); err != nil {
		return nil, err
	}

	now := time.Now()
	res := s.db.Model(&model.AccessRequest{}).
		Where("id = ? AND status = ?", requestID, model.AccessRequestPending).
		Updates(map[string]interface{}{
			"status":        model.AccessRequestRejected,
			"approver_id":   actorID,
			"decided_at":    now,
			"decision_note": note,
			"updated_at":    now,
		})
	if res.Error != nil {
		return nil, fmt.Errorf("拒絕狀態轉移失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, ErrAccessRequestConflict
	}

	result, rerr := s.reload(requestID)
	if rerr != nil {
		return nil, rerr
	}
	s.notify(notifycat.EventAccessRequestRejected, req.ID, s.assetName(req.AssetID), nil)
	return result, nil
}

// Cancel 申請人撤回自己的 pending 單（owner-scoped：他人單回不存在）
func (s *AccessRequestService) Cancel(requesterID uint, requestID uint) (*model.AccessRequest, error) {
	var req model.AccessRequest
	if err := s.db.Where("id = ? AND requester_id = ?", requestID, requesterID).
		First(&req).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAccessRequestNotFound
		}
		return nil, fmt.Errorf("查詢申請單失敗: %w", err)
	}

	now := time.Now()
	res := s.db.Model(&model.AccessRequest{}).
		Where("id = ? AND requester_id = ? AND status = ?", requestID, requesterID, model.AccessRequestPending).
		Updates(map[string]interface{}{
			"status":     model.AccessRequestCancelled,
			"decided_at": now,
			"updated_at": now,
		})
	if res.Error != nil {
		return nil, fmt.Errorf("撤回狀態轉移失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, ErrAccessRequestConflict
	}
	return s.reload(requestID)
}

// ExpireOverdue pending 超時作廢（scheduler 週期呼叫；讀取端另有惰性過濾雙保險）。
// 逐筆 CAS＋審計：與人工決定併發時僅一方成立，單輪上限有界
func (s *AccessRequestService) ExpireOverdue(now time.Time) (int, error) {
	var overdue []model.AccessRequest
	err := s.db.Select("id", "requester_id", "asset_id").
		Where("status = ? AND pending_expires_at < ?", model.AccessRequestPending, now).
		Limit(expireBatchLimit).
		Find(&overdue).Error
	if err != nil {
		return 0, fmt.Errorf("查詢逾期申請失敗: %w", err)
	}

	expired := 0
	for i := range overdue {
		res := s.db.Model(&model.AccessRequest{}).
			Where("id = ? AND status = ?", overdue[i].ID, model.AccessRequestPending).
			Updates(map[string]interface{}{
				"status":     model.AccessRequestExpired,
				"updated_at": now,
			})
		if res.Error != nil {
			return expired, fmt.Errorf("超時作廢失敗 (id=%d): %w", overdue[i].ID, res.Error)
		}
		if res.RowsAffected == 0 {
			continue // 併發中被人工決定/撤回，CAS 讓行
		}
		expired++
		s.logAudit(overdue[i].RequesterID, "system", model.ActionExpire, overdue[i].ID,
			`{"cause":"pending_timeout"}`)
	}
	return expired, nil
}

// ListMine 申請人自助視圖（owner-scoped，D7）
func (s *AccessRequestService) ListMine(requesterID uint) ([]*model.AccessRequest, error) {
	var reqs []*model.AccessRequest
	err := s.db.Preload("Asset").Preload("Approver").
		Where("requester_id = ?", requesterID).
		Order("created_at DESC").Limit(200).
		Find(&reqs).Error
	if err != nil {
		return nil, fmt.Errorf("查詢我的申請失敗: %w", err)
	}
	s.attachApprovalProgress(reqs)
	return reqs, nil
}

// MyActiveTickets 申請人的有效臨時授權（時窗內 source=ticket）
func (s *AccessRequestService) MyActiveTickets(requesterID uint, now time.Time) ([]*model.AssetAuthorization, error) {
	var auths []*model.AssetAuthorization
	err := s.db.Preload("Asset").
		Where("user_id = ? AND source = ? AND (date_start IS NULL OR date_start <= ?) AND (date_expired IS NULL OR date_expired > ?)",
			requesterID, model.AuthorizationSourceTicket, now, now).
		Order("date_expired ASC").
		Find(&auths).Error
	if err != nil {
		return nil, fmt.Errorf("查詢有效臨時授權失敗: %w", err)
	}
	if err := s.attachRequestIDs(auths); err != nil {
		return nil, err
	}
	return auths, nil
}

// 審核範圍列表過濾 SQL 已收斂至 repository（approval-routing-quorum D-1 整改）：
// approverScopeRouteCondition(requesterCol)——雙側聯集（資產側後代
// 方向＋申請人側成員展開），與單筆資格判定 ApproverScopeCoversRequest 同源家族。
// 禁在本檔另寫等價 SQL；涵蓋規則變更一律改 repository 家族區

// pendingScopeFilter 待審查詢共用條件：pending＋未逾期（惰性過濾）＋範圍過濾＋
// 排除本人單（對抗驗收 UX 修正：自己的申請自己不能核，出現在待審只會誤導、
// 且核准鈕點了必 403；禁自核在待審視圖就先過濾掉，admin 亦然——admin 不申請故無影響）
func (s *AccessRequestService) pendingScopeFilter(actorID uint, isAdmin bool, now time.Time) *gorm.DB {
	q := s.db.Model(&model.AccessRequest{}).
		Where("status = ? AND pending_expires_at > ? AND requester_id <> ?",
			model.AccessRequestPending, now, actorID)
	if !isAdmin {
		q = q.Where(approverScopeRouteCondition("requester_id"),
			actorID, actorID, actorID, actorID, actorID, actorID, actorID, actorID)
	}
	return q
}

// ListPending 待審列表（approver 依範圍過濾；admin 全量）
func (s *AccessRequestService) ListPending(actorID uint, isAdmin bool, now time.Time) ([]*model.AccessRequest, error) {
	var reqs []*model.AccessRequest
	err := s.pendingScopeFilter(actorID, isAdmin, now).
		Preload("Requester").Preload("Asset").
		Order("created_at ASC").Limit(200).
		Find(&reqs).Error
	if err != nil {
		return nil, fmt.Errorf("查詢待審申請失敗: %w", err)
	}
	s.attachApprovalProgress(reqs)
	return reqs, nil
}

// PendingCount 待審計數（導航 badge）
func (s *AccessRequestService) PendingCount(actorID uint, isAdmin bool, now time.Time) (int64, error) {
	var count int64
	if err := s.pendingScopeFilter(actorID, isAdmin, now).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("查詢待審計數失敗: %w", err)
	}
	return count, nil
}

// ListHistory 歷史決定（終態單）。approver 依審核範圍過濾（對抗驗收修正：
// 歷史與待審/有效臨時授權三視圖一致範圍收斂，approver 不逾範圍見他人決定紀錄）；
// admin 全量。自動核准單以 auto_approved 可辨識
func (s *AccessRequestService) ListHistory(actorID uint, isAdmin bool, page, pageSize int) ([]*model.AccessRequest, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	q := s.db.Model(&model.AccessRequest{}).
		Where("status <> ?", model.AccessRequestPending)
	if !isAdmin {
		q = q.Where(approverScopeRouteCondition("requester_id"),
			actorID, actorID, actorID, actorID, actorID, actorID, actorID, actorID)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("查詢申請歷史總數失敗: %w", err)
	}
	var reqs []*model.AccessRequest
	err := q.Preload("Requester").Preload("Asset").Preload("Approver").
		Order("decided_at DESC NULLS LAST, id DESC").
		Limit(pageSize).Offset((page - 1) * pageSize).
		Find(&reqs).Error
	if err != nil {
		return nil, 0, fmt.Errorf("查詢申請歷史失敗: %w", err)
	}
	s.attachApprovalProgress(reqs)
	return reqs, total, nil
}

// ActiveTickets 有效臨時授權清冊（審核中心視圖；admin 全量、approver 依範圍）
func (s *AccessRequestService) ActiveTickets(actorID uint, isAdmin bool, now time.Time) ([]*model.AssetAuthorization, error) {
	q := s.db.Model(&model.AssetAuthorization{}).
		Where("source = ? AND (date_start IS NULL OR date_start <= ?) AND (date_expired IS NULL OR date_expired > ?)",
			model.AuthorizationSourceTicket, now, now)
	if !isAdmin {
		// 票證持有者欄為 user_id（票證申請人＝授權主體）
		q = q.Where(approverScopeRouteCondition("user_id"),
			actorID, actorID, actorID, actorID, actorID, actorID, actorID, actorID)
	}
	var auths []*model.AssetAuthorization
	err := q.Preload("User").Preload("Asset").Preload("GrantedByUser").
		Order("date_expired ASC").Limit(500).
		Find(&auths).Error
	if err != nil {
		return nil, fmt.Errorf("查詢有效臨時授權失敗: %w", err)
	}
	if err := s.attachRequestIDs(auths); err != nil {
		return nil, err
	}
	return auths, nil
}

// attachRequestIDs 為票證回填所屬申請單 id（撤銷入口回鏈，break-glass-revocation D4）：
// 一次查 authorization_id→request_id 映射，避免 N+1
func (s *AccessRequestService) attachRequestIDs(tickets []*model.AssetAuthorization) error {
	if len(tickets) == 0 {
		return nil
	}
	authIDs := make([]uint, 0, len(tickets))
	for _, t := range tickets {
		authIDs = append(authIDs, t.ID)
	}
	var rows []struct {
		ID              uint
		AuthorizationID uint
	}
	if err := s.db.Model(&model.AccessRequest{}).
		Select("id", "authorization_id").
		Where("authorization_id IN ?", authIDs).
		Scan(&rows).Error; err != nil {
		return fmt.Errorf("查詢票證所屬申請單失敗: %w", err)
	}
	reqByAuth := make(map[uint]uint, len(rows))
	for _, r := range rows {
		reqByAuth[r.AuthorizationID] = r.ID
	}
	for _, t := range tickets {
		if rid, ok := reqByAuth[t.ID]; ok {
			id := rid
			t.RequestID = &id
		}
	}
	return nil
}

// reload 帶關聯重載（回應序列化用）
func (s *AccessRequestService) reload(id uint) (*model.AccessRequest, error) {
	var req model.AccessRequest
	err := s.db.Preload("Requester").Preload("Asset").Preload("Approver").
		First(&req, id).Error
	if err != nil {
		return nil, fmt.Errorf("重載申請單失敗: %w", err)
	}
	s.attachApprovalProgress([]*model.AccessRequest{&req})
	return &req, nil
}

// attachApprovalProgress 回填 quorum 逐票軌跡與進度（approval-routing-quorum
// D-3）：批次 Preload 防 N+1；Required 讀當下政策值（僅 pending 單語義有效，
// 終態單軌跡凍結）。查失敗不阻斷主流程（進度為顯示性欄位）
func (s *AccessRequestService) attachApprovalProgress(reqs []*model.AccessRequest) {
	if len(reqs) == 0 {
		return
	}
	ids := make([]uint, 0, len(reqs))
	for _, r := range reqs {
		ids = append(ids, r.ID)
	}
	var votes []model.AccessRequestApproval
	if err := s.db.Preload("Approver").
		Where("request_id IN ?", ids).
		Order("created_at ASC").
		Find(&votes).Error; err != nil {
		log.Printf("[AccessRequest] 核准軌跡查詢失敗（進度欄留空）: %v", err)
		return
	}
	byReq := make(map[uint][]model.AccessRequestApproval, len(reqs))
	for _, v := range votes {
		byReq[v.RequestID] = append(byReq[v.RequestID], v)
	}
	required := s.policies.GetInt(policy.PolicyAccessRequestMinApprovals)
	if required < 1 {
		required = 1
	}
	for _, r := range reqs {
		r.Approvals = byReq[r.ID]
		r.ApprovalsReceived = len(byReq[r.ID])
		r.ApprovalsRequired = required
	}
}

// assetName 通知用資產名（查失敗回空字串不阻斷）
func (s *AccessRequestService) assetName(assetID uint) string {
	var asset model.Asset
	if err := s.db.Select("name").First(&asset, assetID).Error; err != nil {
		return ""
	}
	return asset.Name
}

// logAudit service 直記審計（expire 無 HTTP 請求、自動核准的 approve 動作——
// 路由中介層蓋不到的轉移）
func (s *AccessRequestService) logAudit(userID uint, username string, action model.AuditAction, requestID uint, details string) {
	if s.audit == nil {
		return
	}
	id := requestID
	s.audit.Log(&audit.AuditLogEntry{
		UserID: userID, Username: username,
		Action: action, Resource: model.ResourceAccessRequest,
		ResourceID: &id, Status: model.StatusSuccess,
		Details: details,
	})
}

// notify 事件廣播（決議 F）：payload 最小化——單號/資產名/事件類型/事件專屬
// 結構化參數，不帶事由全文（出站去識別紅線）；通道未配置時 NotifyEvent
// 自然 no-op，保底＝審核中心必見＋badge。
//
// 簽名不收散文（design D3）：導引文字與標題一律由 notifycat 依通道語系渲染，
// 呼叫端只提供事實。extra 為該事件 EventSpec 宣告的專屬參數（可為 nil）
func (s *AccessRequestService) notify(event notifycat.Event, requestID uint, assetName string, extra map[string]string) {
	if s.notifier == nil {
		return
	}
	params := map[string]string{"request_id": strconv.FormatUint(uint64(requestID), 10)}
	if assetName != "" {
		params["asset_name"] = assetName
	}
	for k, v := range extra {
		params[k] = v
	}
	s.notifier.NotifyEvent(event, params)
	log.Printf("[AccessRequest] 事件廣播: %s request=%d", event, requestID)
}

// ---- break-glass-revocation：破窗、提前撤銷、補審 ----

// BreakGlass 破窗緊急連線（D1/D2/D3）：開關（關=拒）→ 可視守門 → 資格
// （時窗內常設 connect，票證不算）→ 段位（open 不需破窗）→ 同交易
// 鎖定申請人列＋去重（有效破窗票證擋 409）＋建單（kind=break_glass、
// review_status=pending_review）＋即時核准（固定短窗政策鍵，忽略 client 時長/起始）。
// 不動同資產在途 pending 一般單（緊急優先，原單照常裁決）
func (s *AccessRequestService) BreakGlass(requesterID uint, username, role string, assetID uint, reason string) (*model.AccessRequest, error) {
	if !s.policies.GetBool(policy.PolicyBreakGlassEnabled) {
		return nil, ErrBreakGlassDisabled
	}
	// admin 有政策豁免不需破窗（避免雙旁路語義混淆）；auditor 不得連線資產
	if role == model.RoleAdmin || role == model.RoleAuditor {
		return nil, ErrRequesterExempt
	}
	if reason == "" {
		return nil, ErrDecisionNoteRequired
	}

	var asset model.Asset
	if err := s.db.First(&asset, assetID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAccessRequestNotFound
		}
		return nil, fmt.Errorf("查詢資產失敗: %w", err)
	}

	// 可視守門先於資格（不可視回不存在語義，不洩漏）
	visible, err := s.authzRepo.CheckPermission(requesterID, asset.ID,
		[]model.PermissionType{model.PermissionView, model.PermissionConnect})
	if err != nil {
		return nil, err
	}
	if !visible {
		return nil, ErrAccessRequestNotFound
	}

	// 資格＝時窗內常設 connect（G 決議：只解除審核等待、不提升權限；
	// ticket 來源不算——破窗不得以先前票證續命）
	sources, err := s.authzRepo.ResolveConnectSources(requesterID, asset.ID, time.Now())
	if err != nil {
		return nil, err
	}
	if !sources.Standing {
		return nil, ErrBreakGlassNotEligible
	}

	if s.accessPolicy.AccessPolicyOf(&asset) == model.AccessPolicyOpen {
		return nil, ErrPolicyOpenNoRequest
	}

	duration := s.policies.GetInt(policy.PolicyBreakGlassDurationMinutes)
	now := time.Now()

	var req *model.AccessRequest
	err = s.db.Transaction(func(tx *gorm.DB) error {
		// 鎖定申請人列串行同人破窗（Postgres FOR UPDATE；SQLite 測試路徑
		// 單連線本就串行，跳過不支援的鎖語法）——去重檢查與建單間無競態窗
		if tx.Dialector.Name() == "postgres" {
			var locked model.User
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Select("id").First(&locked, requesterID).Error; err != nil {
				return fmt.Errorf("鎖定申請人失敗: %w", err)
			}
		}

		// 資格於鎖後同交易重判（codex #2）：收緊「交易外查資格、交易內建票證」
		// 窗口內常設授權被撤的 TOCTOU——Postgres 鎖後此查與授權刪除互斥
		reSources, err := s.authzRepo.ResolveConnectSourcesWithDB(tx, requesterID, asset.ID, now)
		if err != nil {
			return err
		}
		if !reSources.Standing {
			return ErrBreakGlassNotEligible
		}

		// 去重（交易內，鎖後無競態）：同資產仍有有效破窗票證即拒，
		// 帶現有單號＋票證到期供 409 回應（規格要求「帶現有票證資訊」；
		// 沿 duplicatePendingError 的單號慣例，另附到期時間）
		var existing struct {
			ID          uint
			DateExpired time.Time
		}
		derr := tx.Model(&model.AccessRequest{}).
			Joins("JOIN asset_authorizations aa ON aa.id = access_requests.authorization_id").
			Where("access_requests.requester_id = ? AND access_requests.asset_id = ? AND access_requests.kind = ?",
				requesterID, asset.ID, model.AccessRequestKindBreakGlass).
			Where("aa.deleted_at IS NULL AND aa.date_expired > ?", now).
			Select("access_requests.id AS id, aa.date_expired AS date_expired").
			First(&existing).Error
		if derr == nil {
			return fmt.Errorf("%w（單號 %d，可用至 %s）", ErrDuplicateBreakGlass,
				existing.ID, existing.DateExpired.Format("15:04"))
		} else if !errors.Is(derr, gorm.ErrRecordNotFound) {
			return fmt.Errorf("破窗去重查詢失敗: %w", derr)
		}

		req = &model.AccessRequest{
			RequesterID:              requesterID,
			AssetID:                  asset.ID,
			Reason:                   reason,
			RequestedDurationMinutes: duration, // 固定短窗政策鍵（六題 2），client 值不進入
			Status:                   model.AccessRequestPending,
			PendingExpiresAt:         now.Add(time.Duration(duration) * time.Minute),
			Kind:                     model.AccessRequestKindBreakGlass,
			ReviewStatus:             model.BreakGlassReviewPending,
		}
		if err := tx.Create(req).Error; err != nil {
			return fmt.Errorf("建立破窗單失敗: %w", err)
		}
		// 即時核准（同 reason 段自動核准軌跡：pending→approved 同交易，決定者 system）
		return s.approveInTx(tx, req, nil, DecideInput{}, true, now)
	})
	if err != nil {
		return nil, err
	}

	// 高亮審計（D2）：獨立 break_glass 標記，與 admin 豁免（policy_exemption）
	// 及一般核准可區分
	s.logAudit(requesterID, username, model.ActionApprove, req.ID,
		`{"auto":true,"break_glass":true,"decided_by":"system"}`)
	// 通知不可被靜默過濾且失敗不阻斷（緊急通道不被通知堵死，F 決議；
	// notifier 廣播全通道，審核中心待補審視圖為保底）。payload 帶破窗人（單號/
	// 資產名/破窗人/時長；username 非敏感、per-spec），無事由全文
	s.notify(notifycat.EventBreakGlassUsed, req.ID, asset.Name, map[string]string{
		"username":         username,
		"duration_minutes": strconv.Itoa(duration),
	})
	return s.reload(req.ID)
}

// Revoke 臨時授權提前撤銷（D4）：同交易軟刪票證（CAS 先到者贏）＋單附註
// 三欄（不動狀態機——approved 終態不變）；資格分流見 eligibleToRevoke；
// 政策開啟時交易後收線（D5，失敗不回滾）
func (s *AccessRequestService) Revoke(actorID uint, isAdmin bool, username string, requestID uint, note string) (*model.AccessRequest, error) {
	if note == "" {
		return nil, ErrDecisionNoteRequired
	}
	req, err := s.loadPending(requestID)
	if err != nil {
		return nil, err
	}
	if req.Status != model.AccessRequestApproved || req.AuthorizationID == nil {
		return nil, ErrTicketNotActive
	}
	if err := s.eligibleToRevoke(actorID, isAdmin, req); err != nil {
		return nil, err
	}

	now := time.Now()
	// 票證須仍有效（已到期不可撤：到期與撤銷語義分離，spec scenario）
	var ticket model.AssetAuthorization
	if err := s.db.First(&ticket, *req.AuthorizationID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrTicketNotActive // 已軟刪＝已撤銷
		}
		return nil, fmt.Errorf("查詢票證失敗: %w", err)
	}
	if ticket.DateExpired != nil && !ticket.DateExpired.After(now) {
		return nil, ErrTicketNotActive
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		// CAS 軟刪票證：並發撤銷先到者贏（RowsAffected=0＝已被撤）
		res := tx.Where("id = ? AND deleted_at IS NULL", ticket.ID).
			Delete(&model.AssetAuthorization{})
		if res.Error != nil {
			return fmt.Errorf("撤銷票證失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrAccessRequestConflict
		}
		// 單附註（非狀態轉移；revoked_at IS NULL 守衛防重複附註）
		ann := tx.Model(&model.AccessRequest{}).
			Where("id = ? AND revoked_at IS NULL", req.ID).
			Updates(map[string]interface{}{
				"revoked_at":  now,
				"revoked_by":  actorID,
				"revoke_note": note,
				"updated_at":  now,
			})
		if ann.Error != nil {
			return fmt.Errorf("撤銷附註失敗: %w", ann.Error)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.logAudit(actorID, username, model.ActionRevoke, req.ID,
		fmt.Sprintf(`{"authorization_id":%d}`, ticket.ID))

	// 斷線聯動（D5，H 決議預設關）：收線失敗不回滾——票證失效是主要目標
	if s.policies.GetBool(policy.PolicyAccessRevokeDisconnect) && s.sessions != nil {
		if n, terr := s.sessions.TerminateByUserAsset(req.RequesterID, req.AssetID, model.EndReasonRevoked); terr != nil {
			log.Printf("[AccessRequest] 撤銷收線失敗 (request=%d): %v", req.ID, terr)
		} else if n > 0 {
			log.Printf("[AccessRequest] 撤銷收線 %d 個會話 (request=%d)", n, req.ID)
		}
	}

	s.notify(notifycat.EventTicketRevoked, req.ID, s.assetName(req.AssetID), nil)
	return s.reload(req.ID)
}

// eligibleToRevoke 撤銷資格（六題 4）：一般單＝admin OR 原核准人；
// 自動核准/破窗單（無真人核准人）＝admin OR 範圍命中 approver
func (s *AccessRequestService) eligibleToRevoke(actorID uint, isAdmin bool, req *model.AccessRequest) error {
	if isAdmin {
		return nil
	}
	if req.ApproverID != nil {
		if *req.ApproverID == actorID {
			return nil
		}
		return ErrNotRevokeEligible
	}
	covered, err := s.authzRepo.ApproverScopeCoversRequest(actorID, req.AssetID, req.RequesterID)
	if err != nil {
		return err
	}
	if !covered {
		return ErrNotRevokeEligible
	}
	return nil
}

// Review 破窗事後補審（D7）：資格＝範圍命中 approver OR admin、破窗人
// 自審硬擋（含 admin）；CAS（WHERE review_status='pending_review'）不可重複
func (s *AccessRequestService) Review(actorID uint, isAdmin bool, requestID uint, disposition, note string) (*model.AccessRequest, error) {
	if disposition != model.BreakGlassDispositionConfirmed && disposition != model.BreakGlassDispositionViolation {
		return nil, ErrInvalidReviewDisposition
	}
	req, err := s.loadPending(requestID)
	if err != nil {
		return nil, err
	}
	if req.Kind != model.AccessRequestKindBreakGlass {
		return nil, ErrNotBreakGlass
	}
	if req.RequesterID == actorID {
		return nil, ErrSelfReview
	}
	if !isAdmin {
		covered, err := s.authzRepo.ApproverScopeCoversRequest(actorID, req.AssetID, req.RequesterID)
		if err != nil {
			return nil, err
		}
		if !covered {
			return nil, ErrNotEligibleApprover
		}
	}

	now := time.Now()
	res := s.db.Model(&model.AccessRequest{}).
		Where("id = ? AND review_status = ?", requestID, model.BreakGlassReviewPending).
		Updates(map[string]interface{}{
			"review_status":      model.BreakGlassReviewReviewed,
			"reviewed_by":        actorID,
			"reviewed_at":        now,
			"review_disposition": disposition,
			"review_note":        note,
			"updated_at":         now,
		})
	if res.Error != nil {
		return nil, fmt.Errorf("補審狀態轉移失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, ErrAlreadyReviewed
	}
	return s.reload(requestID)
}

// ListPendingReview 待補審破窗單（審核中心視圖；approver 依範圍過濾＋
// 排除本人單——自審必 403，列出只會誤導；admin 全量亦排除本人單）
func (s *AccessRequestService) ListPendingReview(actorID uint, isAdmin bool) ([]*model.AccessRequest, error) {
	var reqs []*model.AccessRequest
	err := s.pendingReviewFilter(actorID, isAdmin).
		Preload("Requester").Preload("Asset").Preload("Authorization").
		Order("created_at ASC").Limit(200).
		Find(&reqs).Error
	if err != nil {
		return nil, fmt.Errorf("查詢待補審破窗單失敗: %w", err)
	}
	return reqs, nil
}

// PendingReviewCount 待補審計數（併入導航 badge 輪詢回應）
func (s *AccessRequestService) PendingReviewCount(actorID uint, isAdmin bool) (int64, error) {
	var count int64
	if err := s.pendingReviewFilter(actorID, isAdmin).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("查詢待補審計數失敗: %w", err)
	}
	return count, nil
}

// pendingReviewFilter 待補審查詢共用條件（與 pendingScopeFilter 同構）
func (s *AccessRequestService) pendingReviewFilter(actorID uint, isAdmin bool) *gorm.DB {
	q := s.db.Model(&model.AccessRequest{}).
		Where("kind = ? AND review_status = ? AND requester_id <> ?",
			model.AccessRequestKindBreakGlass, model.BreakGlassReviewPending, actorID)
	if !isAdmin {
		q = q.Where(approverScopeRouteCondition("requester_id"),
			actorID, actorID, actorID, actorID, actorID, actorID, actorID, actorID)
	}
	return q
}

// overdueRenotifyInterval 補審逾期告警的重發節流間隔。
//
// **為何是固定 24h 而不是跟著 break_glass_review_timeout_hours**：首發時機該由
// 政策的超時窗決定（那是「多久算逾期」），重發是「持續提醒」，兩者關切不同。
// 綁在一起會讓「把超時窗設短以求早知道」的部署被同倍數放大轟炸（設 1h 就變每
// 小時一封）。scheduler 每 5 分鐘掃一輪，24h 節流＝每單每日至多一封升級信，
// 對「無人可補審」這種需要人介入的狀態足以持續施壓，又不至於淹沒通知管道。
const overdueRenotifyInterval = 24 * time.Hour

// NotifyOverdueReviews 補審逾期升級告警（D7，scheduler 週期呼叫）：
// 逾 break_glass_review_timeout_hours 未補審的破窗單發 break_glass_review_overdue
// 事件；單仍留在待補審視圖。
//
// **W7b 對抗輪修復（原為每單至多一次）**：D-12 收斂後 admin 不再是有效審核者，
// 系統可能進入「零有效審核者」狀態，spec 明定逾期告警是該情境下破窗單的可見性
// **保底**。只響一次不構成保底——一封信被漏看，單就永久沉沒。故改為以
// review_overdue_notified_at 節流的週期重發：仍待補審就每 overdueRenotifyInterval
// 再升級一次，直到有人補審為止（補審後 review_status 離開 pending_review，
// 查詢條件自然不再命中，正常有審核者的部署不會被製造噪音）。
func (s *AccessRequestService) NotifyOverdueReviews(now time.Time) (int, error) {
	timeoutHours := s.policies.GetInt(policy.PolicyBreakGlassReviewTimeoutHours)
	cutoff := now.Add(-time.Duration(timeoutHours) * time.Hour)
	renotifyBefore := now.Add(-overdueRenotifyInterval)

	var overdue []model.AccessRequest
	err := s.db.Select("id", "requester_id", "asset_id").
		Where("kind = ? AND review_status = ? AND created_at < ? AND (review_overdue_notified_at IS NULL OR review_overdue_notified_at < ?)",
			model.AccessRequestKindBreakGlass, model.BreakGlassReviewPending, cutoff, renotifyBefore).
		Limit(expireBatchLimit).
		Find(&overdue).Error
	if err != nil {
		return 0, fmt.Errorf("查詢逾期未補審破窗單失敗: %w", err)
	}

	notified := 0
	for i := range overdue {
		// CAS 節流：條件重述於 UPDATE，併發輪只有一方能推進時間戳
		res := s.db.Model(&model.AccessRequest{}).
			Where("id = ? AND (review_overdue_notified_at IS NULL OR review_overdue_notified_at < ?)",
				overdue[i].ID, renotifyBefore).
			Update("review_overdue_notified_at", now)
		if res.Error != nil {
			return notified, fmt.Errorf("逾期告警節流標記失敗 (id=%d): %w", overdue[i].ID, res.Error)
		}
		if res.RowsAffected == 0 {
			continue // 併發輪已發
		}
		notified++
		s.notify(notifycat.EventBreakGlassReviewOverdue, overdue[i].ID, s.assetName(overdue[i].AssetID),
			map[string]string{"timeout_hours": strconv.Itoa(timeoutHours)})
	}
	return notified, nil
}
