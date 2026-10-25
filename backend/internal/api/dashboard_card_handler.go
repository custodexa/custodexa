package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
)

// 儀表板逐卡資料：GET /dashboard/cards/:key 每次只回一張卡。
//
// 路由登錄只要求已登入；每張卡要什麼能力由下面的卡片登錄裁決，主體取自認證結果，
// 路徑上只有 key 一個參數。未登錄的 key 一律拒絕，不以「有任一管理權」兜底，
// 也不因為路由只需登入就讓卡片資料變成登入即可讀。

// 卡片資料單位。
const (
	cardUnitCount = "count"
	cardUnitBytes = "bytes"
	cardUnitDays  = "days"
)

// dashboardCardCriterion 一張卡的裁決種類。
type dashboardCardCriterion int

const (
	// criterionPerm 主體需持有 perm。
	criterionPerm dashboardCardCriterion = iota
	// criterionSelf 本人資料：只讀認證主體自己的資料，不需任何管理能力。
	criterionSelf
	// criterionApprover 實際審核資格（即時查角色與審核方群組，admin 不兜底）。
	criterionApprover
)

// dashboardCardDef 一張卡的登錄項。
type dashboardCardDef struct {
	Key       string
	Unit      string
	Criterion dashboardCardCriterion
	Perm      authz.Permission // criterionPerm 時有值
	// ErrCode 來源 provider 讀取失敗時沿用的既有錯誤碼。
	ErrCode apierror.ErrCode
	// Resource 審計列的資源分類：本人卡記請求者本人，其餘卡依資料來源歸對應類別。
	// 路由層只能給一個固定分類，逐卡的分類由 handler 在裁決前覆寫。
	Resource model.AuditResource
}

// dashboardCardDefs 十二張卡的登錄表（以函式回傳，避免包級可變狀態）。
func dashboardCardDefs() []dashboardCardDef {
	return []dashboardCardDef{
		{Key: "assets", Unit: cardUnitCount, Criterion: criterionPerm, Perm: authz.PermAssetView, ErrCode: apierror.CodeInternalAssetQuery, Resource: model.ResourceAsset},
		{Key: "my-connections", Unit: cardUnitCount, Criterion: criterionSelf, ErrCode: apierror.CodeInternalMyConnectionQuery, Resource: model.ResourceUser},
		{Key: "my-pending-requests", Unit: cardUnitCount, Criterion: criterionSelf, ErrCode: apierror.CodeInternalAccessRequestMineQuery, Resource: model.ResourceUser},
		{Key: "active-sessions", Unit: cardUnitCount, Criterion: criterionPerm, Perm: authz.PermSessionView, ErrCode: apierror.CodeInternalSessionAdminQuery, Resource: model.ResourceSession},
		{Key: "today-sessions", Unit: cardUnitCount, Criterion: criterionPerm, Perm: authz.PermSessionView, ErrCode: apierror.CodeInternalSessionAdminQuery, Resource: model.ResourceSession},
		{Key: "total-sessions", Unit: cardUnitCount, Criterion: criterionPerm, Perm: authz.PermSessionView, ErrCode: apierror.CodeInternalSessionAdminQuery, Resource: model.ResourceSession},
		{Key: "today-alerts", Unit: cardUnitCount, Criterion: criterionPerm, Perm: authz.PermAuditView, ErrCode: apierror.CodeInternalCommandAlertQuery, Resource: model.ResourceCommandAlert},
		{Key: "recording-storage", Unit: cardUnitBytes, Criterion: criterionPerm, Perm: authz.PermAuditView, ErrCode: apierror.CodeInternalRecordingStatsQuery, Resource: model.ResourceRecording},
		{Key: "pending-approvals", Unit: cardUnitCount, Criterion: criterionApprover, ErrCode: apierror.CodeInternalAccessRequestPendingCount, Resource: model.ResourceAccessRequest},
		{Key: "unreviewed-alerts", Unit: cardUnitCount, Criterion: criterionPerm, Perm: authz.PermAuditView, ErrCode: apierror.CodeInternalCommandAlertQuery, Resource: model.ResourceCommandAlert},
		{Key: "recording-failures", Unit: cardUnitCount, Criterion: criterionPerm, Perm: authz.PermSessionView, ErrCode: apierror.CodeInternalSessionActiveQuery, Resource: model.ResourceSession},
		{Key: "last-access-review", Unit: cardUnitDays, Criterion: criterionPerm, Perm: authz.PermAuditView, ErrCode: apierror.CodeInternalAccessReviewLastQuery, Resource: model.ResourceAccessReview},
	}
}

func lookupDashboardCard(key string) (dashboardCardDef, bool) {
	for _, d := range dashboardCardDefs() {
		if d.Key == key {
			return d, true
		}
	}
	return dashboardCardDef{}, false
}

// 各卡的來源介面（取窄，測試可注入）。
type (
	dashboardSessionSource interface {
		List(filter *session.SessionFilter) (*session.SessionListResponse, error)
		GetActiveSessions() ([]model.Session, error)
	}
	dashboardMyConnectionSource interface {
		ListMyConnections(userID uint, page, pageSize int) (*session.MyConnectionListResponse, error)
	}
	dashboardAlertSource interface {
		List(filter *audit.CommandAlertFilter) (*audit.CommandAlertListResponse, error)
	}
	dashboardRecordingSource interface {
		GetRecordingStats() (*session.RecordingStats, error)
	}
	dashboardReviewSource interface {
		LastReviewDaysAgo() (int, error)
	}
	dashboardRequestSource interface {
		// CountMinePending 本人 pending 申請的全量件數（不受我的申請列表 200 筆上限影響）。
		CountMinePending(requesterID uint) (int64, error)
		PendingCount(actorID uint, isAdmin bool, now time.Time) (int64, error)
		PendingReviewCount(actorID uint, isAdmin bool) (int64, error)
	}
	// dashboardAssetSource 主體可見資產的完整總數。
	dashboardAssetSource interface {
		CountAssets(ctx context.Context, p *authz.Principal, userID uint) (int64, error)
	}
)

// dashboardAssetCounter 與資產列表同一分支：檢視捷徑主體取全量，其餘取授權集合。
type dashboardAssetCounter struct {
	assets AssetServiceInterface
	auth   AssetAuthorizationServiceInterface
	scope  AssetScopeSource // nil＝不分範圍化檢視者（與列表未注入時同口徑）
}

// NewDashboardAssetCounter 以資產列表使用的兩個服務建構資產總數來源。
// scope 至多一個：資產頁範圍化投影來源，範圍化檢視者的總數取與列表相同的可視聯集。
func NewDashboardAssetCounter(assets AssetServiceInterface, auth AssetAuthorizationServiceInterface, scope ...AssetScopeSource) (dashboardAssetSource, error) {
	if guidanceDepMissing(assets) || guidanceDepMissing(auth) {
		return nil, identity.ErrGuidanceNotWired
	}
	c := &dashboardAssetCounter{assets: assets, auth: auth}
	if len(scope) > 0 {
		c.scope = scope[0]
	}
	return c, nil
}

func (a *dashboardAssetCounter) CountAssets(ctx context.Context, p *authz.Principal, userID uint) (int64, error) {
	// 分支判定與授權集合取法皆與資產列表共用同一組函式
	if a.scope != nil && !p.ViewShortcut() {
		v, err := a.scope.View(authz.ContextWithPrincipal(ctx, p))
		if err != nil {
			return 0, err
		}
		if v != nil {
			_, _, union, err := scopedVisibleUnion(ctx, a.auth, a.scope, v, p, userID)
			if err != nil {
				return 0, err
			}
			return int64(len(union)), nil
		}
	}
	if !assetListUsesAuthorizedSet(p, false) {
		res, err := a.assets.List(&asset.AssetFilter{Page: 1, PageSize: 1})
		if err != nil {
			return 0, err
		}
		return res.Total, nil
	}
	dtos, err := authorizedAssetsOf(ctx, a.auth, p, userID)
	if err != nil {
		return 0, err
	}
	return int64(len(dtos)), nil
}

// DashboardCardDeps 逐卡資料的來源集合；任一缺少即建構失敗。
type DashboardCardDeps struct {
	Assets        dashboardAssetSource
	Sessions      dashboardSessionSource
	MyConnections dashboardMyConnectionSource
	Alerts        dashboardAlertSource
	Recordings    dashboardRecordingSource
	Reviews       dashboardReviewSource
	Requests      dashboardRequestSource
	// DB 即時查審核資格用。
	DB *gorm.DB
	// Now 取得目前時間（今日日界線的唯一來源）；nil 時用系統時鐘。
	Now func() time.Time
}

// DashboardCardHandler 儀表板逐卡資料端點。
type DashboardCardHandler struct {
	d DashboardCardDeps
}

// NewDashboardCardHandler 建構 handler；任何來源缺少即回錯，不建出請求時才回 0 的 handler。
func NewDashboardCardHandler(d DashboardCardDeps) (*DashboardCardHandler, error) {
	for _, dep := range []any{d.Assets, d.Sessions, d.MyConnections, d.Alerts, d.Recordings, d.Reviews, d.Requests, d.DB} {
		if guidanceDepMissing(dep) {
			return nil, identity.ErrGuidanceNotWired
		}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &DashboardCardHandler{d: d}, nil
}

// RegisterRoutes 註冊逐卡路由。agent token 一律拒絕：卡片是人的入口，
// 登入即可的路由類別不代表 agent 可進。
func (h *DashboardCardHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/dashboard")
	g.Use(middleware.RejectAgentTokenOnHumanPaths(), middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	{
		g.GET("/cards/:key", h.GetCard)
	}
}

// dashboardCardResponse 一張卡的回應：只有值與落點篩選，不含資源名。
type dashboardCardResponse struct {
	Key     string            `json:"key"`
	Value   int64             `json:"value"`
	Unit    string            `json:"unit"`
	Filters map[string]string `json:"filters"`
	// 待審卡：件數拆成一般待審與待補審。
	Count       *int64 `json:"count,omitempty"`
	ReviewCount *int64 `json:"review_count,omitempty"`
	// 複審卡：逾期與建議週期。
	Overdue          *bool `json:"overdue,omitempty"`
	ReviewPeriodDays *int  `json:"review_period_days,omitempty"`
}

// dayBounds 本地日的閉區間 [00:00:00.000000, 次日 00:00:00 減 1 微秒]。
func dayBounds(now time.Time) (time.Time, time.Time) {
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	return start, start.AddDate(0, 0, 1).Add(-time.Microsecond)
}

// cardTimeLayout 日界線的輸出格式：固定六位微秒，尾端 23:59:59.999999 不被截斷。
// 該字串原樣放進 filters、跳轉 query 與列表 API 參數，三處不經任何時間型別轉換。
const cardTimeLayout = "2006-01-02T15:04:05.000000Z07:00"

// 卡片 filters 的鍵就是對應列表 API 實際讀取的查詢參數名。
const (
	filterStatus         = "status"
	filterStartTime      = "start_time"
	filterEndTime        = "end_time"
	filterUnreviewed     = "unreviewed"
	filterRecordingError = "recording_error"
)

// GetCard 讀取一張卡。順序：key 在登錄內 → 該卡的裁決 → 取值。
func (h *DashboardCardHandler) GetCard(c *gin.Context) {
	def, ok := lookupDashboardCard(c.Param("key"))
	if !ok {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	// 審計分類先於裁決設定：被拒的請求同樣記在它想讀的資料類別上
	c.Set("audit_resource", def.Resource)
	userID, ok := middleware.GetCurrentUserID(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	if def.Criterion == criterionSelf {
		c.Set("audit_resource_id", userID)
	}
	p := middleware.PrincipalFrom(c)
	if p == nil {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	switch def.Criterion {
	case criterionPerm:
		if !p.Has(def.Perm) {
			// 能力拒絕：回應與其他能力拒絕同形，不帶所需權限；依據只進請求脈絡供審計取用
			middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(def.Perm))
			return
		}
	case criterionApprover:
		verdict, err := authz.EvaluateApproverRouteEligibility(h.d.DB, userID)
		if err != nil {
			code := apierror.CodeInternalApproverQuery
			if verdict.RoleQueryFailed {
				code = apierror.CodeInternalRoleQuery
			}
			apierror.RespondInternal(c, http.StatusInternalServerError, code, err)
			return
		}
		if !verdict.Allowed {
			// 審核資格屬保留條件的能力拒絕：與審核路由的資格守衛同一依據、同一形狀
			middleware.WriteCapabilityDenial(c, middleware.ReservedCapabilityDenial(authz.ReservedApproverEligibility))
			return
		}
	case criterionSelf:
		// 只讀認證主體自己的資料；沒有其他參數可以改變範圍
	}

	resp, err := h.value(c.Request.Context(), def, p, userID)
	if err != nil {
		code := def.ErrCode
		var coded *cardCodedError
		if errors.As(err, &coded) {
			code = coded.code
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, code, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// value 依卡取值。各卡的來源是目前的列表／統計 provider。
func (h *DashboardCardHandler) value(ctx context.Context, def dashboardCardDef, p *authz.Principal, userID uint) (dashboardCardResponse, error) {
	resp := dashboardCardResponse{Key: def.Key, Unit: def.Unit, Filters: map[string]string{}}
	now := h.d.Now()
	dayStart, dayEnd := dayBounds(now)
	var err error
	switch def.Key {
	case "assets":
		resp.Value, err = h.d.Assets.CountAssets(ctx, p, userID)
	case "my-connections":
		var res *session.MyConnectionListResponse
		if res, err = h.d.MyConnections.ListMyConnections(userID, 1, 1); err == nil {
			resp.Value = res.Total
		}
	case "my-pending-requests":
		resp.Value, err = h.d.Requests.CountMinePending(userID)
		resp.Filters[filterStatus] = string(model.AccessRequestPending)
	case "active-sessions":
		resp.Value, err = h.sessionTotal(&session.SessionFilter{Status: model.SessionStatusActive})
		resp.Filters[filterStatus] = string(model.SessionStatusActive)
	case "today-sessions":
		resp.Value, err = h.sessionTotal(&session.SessionFilter{StartTime: &dayStart, EndTime: &dayEnd})
		resp.Filters[filterStartTime], resp.Filters[filterEndTime] = dayStart.Format(cardTimeLayout), dayEnd.Format(cardTimeLayout)
	case "total-sessions":
		resp.Value, err = h.sessionTotal(&session.SessionFilter{})
	case "today-alerts":
		resp.Value, err = h.alertTotal(&audit.CommandAlertFilter{StartTime: &dayStart, EndTime: &dayEnd})
		resp.Filters[filterStartTime], resp.Filters[filterEndTime] = dayStart.Format(cardTimeLayout), dayEnd.Format(cardTimeLayout)
	case "unreviewed-alerts":
		resp.Value, err = h.alertTotal(&audit.CommandAlertFilter{Unreviewed: true})
		resp.Filters[filterUnreviewed] = "true"
	case "recording-storage":
		var stats *session.RecordingStats
		if stats, err = h.d.Recordings.GetRecordingStats(); err == nil {
			resp.Value = stats.TotalSize
		}
	case "recording-failures":
		var active []model.Session
		if active, err = h.d.Sessions.GetActiveSessions(); err == nil {
			resp.Value = int64(session.CountRecordingFailures(active))
		}
		resp.Filters[filterStatus] = string(model.SessionStatusActive)
		resp.Filters[filterRecordingError] = "true"
	case "pending-approvals":
		var count, review int64
		if count, err = h.d.Requests.PendingCount(userID, notEffectiveAdmin, now); err != nil {
			break
		}
		if review, err = h.d.Requests.PendingReviewCount(userID, notEffectiveAdmin); err != nil {
			err = &cardCodedError{code: apierror.CodeInternalBreakGlassReviewCount, cause: err}
			break
		}
		resp.Value, resp.Count, resp.ReviewCount = count+review, &count, &review
	case "last-access-review":
		var days int
		if days, err = h.d.Reviews.LastReviewDaysAgo(); err == nil {
			resp.Value = int64(days)
			overdue := days < 0 || days > authz.ReviewPeriodDays
			period := authz.ReviewPeriodDays
			resp.Overdue, resp.ReviewPeriodDays = &overdue, &period
		}
	default:
		err = errors.New("卡片登錄與取值分派不一致: " + def.Key)
	}
	return resp, err
}

// cardCodedError 同一張卡內某一步要用不同於卡預設的讀取錯誤碼。
type cardCodedError struct {
	code  apierror.ErrCode
	cause error
}

func (e *cardCodedError) Error() string { return e.cause.Error() }
func (e *cardCodedError) Unwrap() error { return e.cause }

func (h *DashboardCardHandler) sessionTotal(f *session.SessionFilter) (int64, error) {
	f.Page, f.PageSize = 1, 1
	res, err := h.d.Sessions.List(f)
	if err != nil {
		return 0, err
	}
	return res.Total, nil
}

func (h *DashboardCardHandler) alertTotal(f *audit.CommandAlertFilter) (int64, error) {
	f.Page, f.PageSize = 1, 1
	res, err := h.d.Alerts.List(f)
	if err != nil {
		return 0, err
	}
	return res.Total, nil
}
