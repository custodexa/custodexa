package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// ApproverScopeServiceInterface 審核範圍服務接口（測試注入）
type ApproverScopeServiceInterface interface {
	List() ([]*model.ApproverScope, error)
	Create(spec authz.ApproverScopeSpec) (*model.ApproverScope, error)
	Delete(id uint) error
}

// AccessRequestHandler 申請核准流 API（access-policy-approval）
type AccessRequestHandler struct {
	requests authz.AccessRequestServiceInterface
	scopes   ApproverScopeServiceInterface
	// db 供審核端點守門即時查 roles（RequireApproverRole）
	db *gorm.DB
}

// NewAccessRequestHandler 建立申請核准流 handler
func NewAccessRequestHandler(requests authz.AccessRequestServiceInterface, scopes ApproverScopeServiceInterface, db *gorm.DB) *AccessRequestHandler {
	return &AccessRequestHandler{requests: requests, scopes: scopes, db: db}
}

// respondAccessRequestError 服務層 sentinel → 機器碼映射：404/409/400/403，
// 其餘泛化 500（internalCode 為該呼叫點的 action-scoped 內部碼）
func respondAccessRequestError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	// 時長超限先以 typed error 比對：政策上限須進 params，使用者才知道要改成多少
	var durationErr *authz.DurationExceedsPolicyError
	if errors.As(err, &durationErr) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccessRequestDurationExceeds,
			map[string]any{"minutes": durationErr.MaxMinutes})
		return
	}

	switch {
	case errors.Is(err, authz.ErrAccessRequestNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAccessRequestNotFound, nil)

	case errors.Is(err, authz.ErrAccessRequestConflict):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccessRequestStateChanged, nil)
	case errors.Is(err, authz.ErrDuplicatePendingRequest):
		apierror.Respond(c, http.StatusConflict, apierror.CodeDuplicatePendingRequest, nil)
	case errors.Is(err, authz.ErrDuplicateBreakGlass):
		apierror.Respond(c, http.StatusConflict, apierror.CodeDuplicateBreakGlass, nil)
	case errors.Is(err, authz.ErrTicketNotActive):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccessTicketNotActive, nil)
	case errors.Is(err, authz.ErrAlreadyApprovedByActor):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAlreadyApprovedByActor, nil)
	case errors.Is(err, authz.ErrAlreadyReviewed):
		apierror.Respond(c, http.StatusConflict, apierror.CodeBreakGlassAlreadyReviewed, nil)

	// 裸 sentinel 保底：service 現只回 DurationExceedsPolicyError（上方已攔），
	// 此分支保住狀態碼語義；改走無參 sibling 碼，避免帶參碼缺參剝除佔位符
	// 產生破碎文案
	case errors.Is(err, authz.ErrDurationExceedsPolicy):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccessRequestDurationExceedsNoLimit, nil)
	case errors.Is(err, authz.ErrDecisionIncrease):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccessRequestDecisionIncrease, nil)
	case errors.Is(err, authz.ErrPolicyOpenNoRequest):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccessRequestPolicyOpen, nil)
	case errors.Is(err, authz.ErrStartInPast):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccessRequestStartInPast, nil)
	// 帳號範圍與授權列共用同一驗證（asset-multi-account D5），故共用同一支碼
	case errors.Is(err, authz.ErrAccountScopeInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountScopeInvalid, nil)
	case errors.Is(err, authz.ErrNotBreakGlass):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeNotBreakGlass, nil)
	case errors.Is(err, authz.ErrInvalidReviewDisposition):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidReviewDisposition, nil)
	case errors.Is(err, authz.ErrDecisionNoteRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeDecisionNoteRequired, nil)

	case errors.Is(err, authz.ErrBreakGlassDisabled):
		// 開關關閉＝封 API，前端據此碼隱藏入口自癒
		apierror.Respond(c, http.StatusForbidden, apierror.CodeBreakGlassDisabled, nil)
	case errors.Is(err, authz.ErrSelfApproval):
		apierror.Respond(c, http.StatusForbidden, apierror.CodeAccessRequestSelfApproval, nil)
	case errors.Is(err, authz.ErrSelfReview):
		apierror.Respond(c, http.StatusForbidden, apierror.CodeBreakGlassSelfReview, nil)
	case errors.Is(err, authz.ErrNotEligibleApprover):
		apierror.Respond(c, http.StatusForbidden, apierror.CodeNotEligibleApprover, nil)
	case errors.Is(err, authz.ErrNotRevokeEligible):
		apierror.Respond(c, http.StatusForbidden, apierror.CodeNotRevokeEligible, nil)
	case errors.Is(err, authz.ErrBreakGlassNotEligible):
		apierror.Respond(c, http.StatusForbidden, apierror.CodeBreakGlassNotEligible, nil)
	case errors.Is(err, authz.ErrRequesterExempt):
		apierror.Respond(c, http.StatusForbidden, apierror.CodeRequesterExempt, nil)

	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

// requesterIdentity 從 context 取申請人身分
func requesterIdentity(c *gin.Context) (uint, string, string, bool) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return 0, "", "", false
	}
	username, _ := middleware.GetCurrentUsername(c)
	role := ""
	if v, ok := c.Get("role"); ok {
		role, _ = v.(string)
	}
	return userID, username, role, true
}

// notEffectiveAdmin D-12 收斂（W7b 8.3）：`admin` 角色本身不構成有效審核資格，
// 審核端點因此**不存在 admin 兜底身分**——範圍過濾、決定資格、quorum 計票一律依
// 審核範圍。service 層 `isAdmin` 參數自審核路徑一律傳本常數（撤銷端點例外，
// 見 `revokeIdentity`）。參數本身的移除留待後續結構波（backlog 項 B-26；該清單
// 歸檔於維護者的私有開發歷程，未隨公開倉庫發佈）
const notEffectiveAdmin = false

// approverIdentity 審核端點身分（RequireApproverRole 已放行＝操作者為有效審核者）。
//
// **W7b 8.3**：不再讀取 admin 兜底旗標——`middleware.ApproverAdminKey` 已隨 D-12 移除
func approverIdentity(c *gin.Context) (uint, bool) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return 0, false
	}
	return userID, true
}

// revokeIdentity 撤銷端點身分（RequireRevokeEligibility 已放行並寫入 admin 旗標）：
// 撤銷屬遏制動作非審核，admin 資格保留（W7b 8.2 端點分離）
func revokeIdentity(c *gin.Context) (uint, bool, bool) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return 0, false, false
	}
	isAdmin, _ := c.Get(middleware.RevokeAdminKey)
	admin, _ := isAdmin.(bool)
	return userID, admin, true
}

type createAccessRequestReq struct {
	AssetID         uint       `json:"asset_id" binding:"required"`
	Reason          string     `json:"reason" binding:"required,max=1000"`
	DurationMinutes int        `json:"duration_minutes" binding:"required,min=1"`
	DateStart       *time.Time `json:"date_start"`
	// Accounts 申請的帳號範圍（asset-multi-account D5）：省略（nil）＝@ALL（既有行為）；
	// 顯式 [] 拒收（F1）
	Accounts *[]string `json:"accounts"`
}

// Create POST /access-requests 提出申請
func (h *AccessRequestHandler) Create(c *gin.Context) {
	userID, username, role, ok := requesterIdentity(c)
	if !ok {
		return
	}
	var req createAccessRequestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccessRequestFields, nil)
		return
	}
	created, err := h.requests.Submit(userID, username, role, authz.SubmitAccessRequestInput{
		AssetID:         req.AssetID,
		Reason:          req.Reason,
		DurationMinutes: req.DurationMinutes,
		DateStart:       req.DateStart,
		Accounts:        req.Accounts,
	})
	if err != nil {
		respondAccessRequestError(c, apierror.CodeInternalAccessRequestCreate, err)
		return
	}
	c.JSON(http.StatusCreated, created)
}

// ListMine GET /access-requests/mine 我的申請（owner-scoped：一律以 JWT user_id
// 過濾，不接受 client 傳入的使用者參數）
func (h *AccessRequestHandler) ListMine(c *gin.Context) {
	userID, _, _, ok := requesterIdentity(c)
	if !ok {
		return
	}
	reqs, err := h.requests.ListMine(userID)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessRequestMineQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": reqs, "total": len(reqs)})
}

// MyTickets GET /access-requests/mine/tickets 我的有效臨時授權（時窗起迄）
func (h *AccessRequestHandler) MyTickets(c *gin.Context) {
	userID, _, _, ok := requesterIdentity(c)
	if !ok {
		return
	}
	tickets, err := h.requests.MyActiveTickets(userID, time.Now())
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessTicketQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tickets, "total": len(tickets)})
}

// Cancel POST /access-requests/:id/cancel 申請人撤回（CAS，僅本人 pending 單）
func (h *AccessRequestHandler) Cancel(c *gin.Context) {
	userID, _, _, ok := requesterIdentity(c)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAccessRequestID, nil)
		return
	}
	req, err := h.requests.Cancel(userID, uint(id))
	if err != nil {
		respondAccessRequestError(c, apierror.CodeInternalAccessRequestCancel, err)
		return
	}
	c.JSON(http.StatusOK, req)
}

// ListPending GET /access-requests/pending 待審列表（一律依審核範圍；
// D-12 起 admin 身分本身不構成審核資格，故不再有 admin 全量視圖）
func (h *AccessRequestHandler) ListPending(c *gin.Context) {
	userID, ok := approverIdentity(c)
	if !ok {
		return
	}
	reqs, err := h.requests.ListPending(userID, notEffectiveAdmin, time.Now())
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessRequestPendingQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": reqs, "total": len(reqs)})
}

// PendingCount GET /access-requests/pending/count 待審計數（導航 badge）
func (h *AccessRequestHandler) PendingCount(c *gin.Context) {
	userID, ok := approverIdentity(c)
	if !ok {
		return
	}
	count, err := h.requests.PendingCount(userID, notEffectiveAdmin, time.Now())
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessRequestPendingCount, err)
		return
	}
	// 待補審計數併入同一輪詢回應（break-glass-revocation D7，導航 badge 共用）
	reviewCount, err := h.requests.PendingReviewCount(userID, notEffectiveAdmin)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalBreakGlassReviewCount, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"count": count, "review_count": reviewCount})
}

// ListHistory GET /access-requests/history 歷史決定（分頁）
func (h *AccessRequestHandler) ListHistory(c *gin.Context) {
	userID, ok := approverIdentity(c)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	reqs, total, err := h.requests.ListHistory(userID, notEffectiveAdmin, page, pageSize)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessRequestHistoryQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": reqs, "total": total, "page": page, "page_size": pageSize})
}

// ActiveTickets GET /access-requests/tickets 有效臨時授權清冊（審核中心）
func (h *AccessRequestHandler) ActiveTickets(c *gin.Context) {
	userID, ok := approverIdentity(c)
	if !ok {
		return
	}
	tickets, err := h.requests.ActiveTickets(userID, notEffectiveAdmin, time.Now())
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessTicketQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tickets, "total": len(tickets)})
}

type approveAccessRequestReq struct {
	DurationMinutes *int       `json:"duration_minutes" binding:"omitempty,min=1"`
	DateStart       *time.Time `json:"date_start"`
	Note            string     `json:"note" binding:"max=1000"`
}

// Approve POST /access-requests/:id/approve 核准（可下修時長/推遲起始）
func (h *AccessRequestHandler) Approve(c *gin.Context) {
	userID, ok := approverIdentity(c)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAccessRequestID, nil)
		return
	}
	// 允許空 body（照申請值核准）；帶 body 則須合法
	var req approveAccessRequestReq
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
	}
	decided, err := h.requests.Approve(userID, notEffectiveAdmin, uint(id), authz.DecideInput{
		DurationMinutes: req.DurationMinutes,
		DateStart:       req.DateStart,
		Note:            req.Note,
	})
	if err != nil {
		respondAccessRequestError(c, apierror.CodeInternalAccessRequestApprove, err)
		return
	}
	c.JSON(http.StatusOK, decided)
}

type rejectAccessRequestReq struct {
	Note string `json:"note" binding:"required,max=1000"`
}

// Reject POST /access-requests/:id/reject 拒絕（事由必填）
func (h *AccessRequestHandler) Reject(c *gin.Context) {
	userID, ok := approverIdentity(c)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAccessRequestID, nil)
		return
	}
	var req rejectAccessRequestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeDecisionNoteRequired, nil)
		return
	}
	decided, err := h.requests.Reject(userID, notEffectiveAdmin, uint(id), req.Note)
	if err != nil {
		respondAccessRequestError(c, apierror.CodeInternalAccessRequestReject, err)
		return
	}
	c.JSON(http.StatusOK, decided)
}

type breakGlassReq struct {
	AssetID uint   `json:"asset_id" binding:"required"`
	Reason  string `json:"reason" binding:"required,max=1000"`
	// 不收時長/起始：破窗時窗固定政策鍵（六題 2），client 傳入即忽略（binding 不宣告）
}

// BreakGlass POST /access-requests/break-glass 破窗緊急連線（登入即可；
// 開關/資格/段位全在 service 層裁決，關閉時 403 break_glass_disabled）
func (h *AccessRequestHandler) BreakGlass(c *gin.Context) {
	userID, username, role, ok := requesterIdentity(c)
	if !ok {
		return
	}
	var req breakGlassReq
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBreakGlassFields, nil)
		return
	}
	created, err := h.requests.BreakGlass(userID, username, role, req.AssetID, req.Reason)
	if err != nil {
		respondAccessRequestError(c, apierror.CodeInternalBreakGlassSubmit, err)
		return
	}
	c.JSON(http.StatusCreated, created)
}

type revokeAccessRequestReq struct {
	Note string `json:"note" binding:"required,max=1000"`
}

// Revoke POST /access-requests/:id/revoke 臨時授權提前撤銷（事由必填；
// 資格分流在 service：一般單 admin+原核准人、auto/破窗單 admin+範圍 approver）
func (h *AccessRequestHandler) Revoke(c *gin.Context) {
	userID, isAdmin, ok := revokeIdentity(c)
	if !ok {
		return
	}
	username, _ := middleware.GetCurrentUsername(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAccessRequestID, nil)
		return
	}
	var req revokeAccessRequestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeRevokeNoteRequired, nil)
		return
	}
	revoked, err := h.requests.Revoke(userID, isAdmin, username, uint(id), req.Note)
	if err != nil {
		respondAccessRequestError(c, apierror.CodeInternalAccessTicketRevoke, err)
		return
	}
	c.JSON(http.StatusOK, revoked)
}

type reviewAccessRequestReq struct {
	Disposition string `json:"disposition" binding:"required"`
	Note        string `json:"note" binding:"max=1000"`
}

// Review POST /access-requests/:id/review 破窗事後補審（處置 confirmed/violation；
// 破窗人自審 403 硬擋在 service）
func (h *AccessRequestHandler) Review(c *gin.Context) {
	userID, ok := approverIdentity(c)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAccessRequestID, nil)
		return
	}
	var req reviewAccessRequestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReviewDispositionRequired, nil)
		return
	}
	reviewed, err := h.requests.Review(userID, notEffectiveAdmin, uint(id), req.Disposition, req.Note)
	if err != nil {
		respondAccessRequestError(c, apierror.CodeInternalBreakGlassReview, err)
		return
	}
	c.JSON(http.StatusOK, reviewed)
}

// ListPendingReview GET /access-requests/reviews/pending 待補審破窗單（審核中心）
func (h *AccessRequestHandler) ListPendingReview(c *gin.Context) {
	userID, ok := approverIdentity(c)
	if !ok {
		return
	}
	reqs, err := h.requests.ListPendingReview(userID, notEffectiveAdmin)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalBreakGlassReviewQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": reqs, "total": len(reqs)})
}

type createApproverScopeReq struct {
	// 審核方（恰一，approval-routing-quorum D-7）：個人 XOR 使用者群組
	ApproverID      uint `json:"approver_id"`
	ApproverGroupID uint `json:"approver_group_id"`
	AssetID         uint `json:"asset_id"`
	AssetGroupID    uint `json:"asset_group_id"`
	// 申請人側客體（approval-routing-quorum）：與資產側四維恰一
	SubjectUserID  uint `json:"subject_user_id"`
	SubjectGroupID uint `json:"subject_group_id"`
}

// ListScopes GET /approver-scopes 範圍清單（admin only）
func (h *AccessRequestHandler) ListScopes(c *gin.Context) {
	scopes, err := h.scopes.List()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalApproverScopeQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": scopes, "total": len(scopes)})
}

// CreateScope POST /approver-scopes 分配範圍（admin only、審計經中介層；
// 客體四維恰一：asset_id/asset_group_id/subject_user_id/subject_group_id）
func (h *AccessRequestHandler) CreateScope(c *gin.Context) {
	userID, _, _, ok := requesterIdentity(c)
	if !ok {
		return
	}
	var req createApproverScopeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	spec := authz.ApproverScopeSpec{GrantedBy: userID}
	if req.ApproverID != 0 {
		spec.ApproverID = &req.ApproverID
	}
	if req.ApproverGroupID != 0 {
		spec.ApproverGroupID = &req.ApproverGroupID
	}
	if req.AssetID != 0 {
		spec.AssetID = &req.AssetID
	}
	if req.AssetGroupID != 0 {
		spec.AssetGroupID = &req.AssetGroupID
	}
	if req.SubjectUserID != 0 {
		spec.SubjectUserID = &req.SubjectUserID
	}
	if req.SubjectGroupID != 0 {
		spec.SubjectGroupID = &req.SubjectGroupID
	}
	scope, err := h.scopes.Create(spec)
	if err != nil {
		switch {
		case errors.Is(err, authz.ErrScopeTargetInvalid):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeScopeTargetInvalid, nil)
		case errors.Is(err, authz.ErrScopeActorInvalid):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeScopeActorInvalid, nil)
		case errors.Is(err, authz.ErrNotApproverRole):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeScopeNotApproverRole, nil)
		case errors.Is(err, authz.ErrScopeExists):
			apierror.Respond(c, http.StatusConflict, apierror.CodeApproverScopeExists, nil)
		default:
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalApproverScopeCreate, err)
		}
		return
	}
	c.JSON(http.StatusCreated, scope)
}

// DeleteScope DELETE /approver-scopes/:id 移除範圍（admin only）
func (h *AccessRequestHandler) DeleteScope(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidApproverScopeID, nil)
		return
	}
	if err := h.scopes.Delete(uint(id)); err != nil {
		if errors.Is(err, authz.ErrScopeNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeApproverScopeNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalApproverScopeDelete, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

// RegisterRoutes 註冊路由：申請側登入即可（service 層拒 admin/auditor 申請）；
// 審核側 RequireApproverRole 即時查 DB roles（**D-12 後不含 admin**）；
// 撤銷側 RequireRevokeEligibility（admin OR 有效審核者，W7b 8.2 端點分離）；
// 範圍管理 admin only（＝admin 脫困路徑之一，不得加掛審核類守衛）
func (h *AccessRequestHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	requests := r.Group("/access-requests")
	requests.Use(middleware.AuthMiddleware(authService))
	{
		requests.POST("", h.Create)
		requests.GET("/mine", h.ListMine)
		requests.GET("/mine/tickets", h.MyTickets)
		requests.POST("/:id/cancel", h.Cancel)
		// 破窗（break-glass-revocation）：登入即可呼叫，開關/資格在 service 裁決
		requests.POST("/break-glass", h.BreakGlass)

		review := requests.Group("")
		review.Use(middleware.RequireApproverRole(h.db))
		{
			review.GET("/pending", h.ListPending)
			review.GET("/pending/count", h.PendingCount)
			review.GET("/history", h.ListHistory)
			review.GET("/tickets", h.ActiveTickets)
			review.GET("/reviews/pending", h.ListPendingReview)
			review.POST("/:id/approve", h.Approve)
			review.POST("/:id/reject", h.Reject)
			review.POST("/:id/review", h.Review)
		}

		// 撤銷端點分離（W7b 8.2）：遏制動作非審核，資格＝admin OR 原核准人
		// （auto/破窗單＝admin OR 範圍命中的有效審核者），細緻裁決在 service
		revocation := requests.Group("")
		revocation.Use(middleware.RequireRevokeEligibility(h.db))
		{
			revocation.POST("/:id/revoke", h.Revoke)
		}
	}

	scopes := r.Group("/approver-scopes")
	scopes.Use(middleware.AuthMiddleware(authService), middleware.RequireRole("admin"))
	{
		scopes.GET("", h.ListScopes)
		scopes.POST("", h.CreateScope)
		scopes.DELETE("/:id", h.DeleteScope)
	}
}
