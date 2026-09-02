package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/gin-gonic/gin"
)

// 輪替證據報告端點。
//
// 讀取面（資料集、記錄明細、手動產出）要稽核檢視權限；排程管理限 admin——
// 排程決定「系統每期自動產一份什麼」，那是設定而非查閱。
//
// 回應一律走顯式投影：報告資料集的每一列都取自報告建構者，其結構不含任何憑證
// 欄位，也不含改密計劃的密碼策略（計劃在報告裡只剩名稱與天數覆蓋的結果）。

// RotationReportHandler 報告資料集、手動產出與排程管理。
type RotationReportHandler struct {
	builder      *asset.RotationReportBuilder
	schedules    *asset.RotationReportScheduleService
	auditService *audit.AuditLogService
}

// NewRotationReportHandler 建立 handler。
func NewRotationReportHandler(builder *asset.RotationReportBuilder,
	schedules *asset.RotationReportScheduleService, auditService *audit.AuditLogService) *RotationReportHandler {
	return &RotationReportHandler{builder: builder, schedules: schedules, auditService: auditService}
}

// RegisterRoutes 註冊報告路由。
//
// 兩個權限層級同群不同閘：讀取面掛 audit:view，排程面另掛 admin 角色。
// 分成兩個 gin 群組是必要的——中介層是群組級的，混在一起只能取其嚴或其寬。
func (h *RotationReportHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	grp := r.Group("/rotation-report")
	grp.Use(middleware.AuthMiddleware(authService))
	{
		grp.GET("", middleware.RequirePermission(middleware.PermAuditView), h.Dataset)
		grp.GET("/records", middleware.RequirePermission(middleware.PermAuditView), h.Records)
		grp.POST("/jobs", middleware.RequirePermission(middleware.PermAuditView), h.CreateJob)
	}

	sch := r.Group("/rotation-report/schedules")
	sch.Use(middleware.AuthMiddleware(authService))
	sch.Use(middleware.RequireRole("admin"))
	{
		sch.GET("", h.ListSchedules)
		sch.POST("", h.CreateSchedule)
		sch.PUT("/:id", h.UpdateSchedule)
		sch.DELETE("/:id", h.DeleteSchedule)
		sch.POST("/:id/run", h.RunSchedule)
	}
}

// scopeFromQuery 範圍參數（缺省＝全系統）。
func scopeFromQuery(c *gin.Context) (asset.ReportScope, bool) {
	kind := c.Query("scope_kind")
	if kind == "" {
		kind = model.RotationScopeAll
	}
	id := parseUintQuery(c.Query("scope_id"))
	if err := asset.ValidateReportScope(kind, id); err != nil {
		respondInvalidQueryParam(c, "scope_kind")
		return asset.ReportScope{}, false
	}
	return asset.ReportScope{Kind: kind, ID: id}, true
}

// Dataset 報告資料集（GET /rotation-report）。
//
// 不含記錄明細——那是另一個端點的分頁面。畫面的摘要與表格都取自這裡，
// 前端不得自行再算一次，否則同一個數字會有兩套規則。
func (h *RotationReportHandler) Dataset(c *gin.Context) {
	scope, ok := scopeFromQuery(c)
	if !ok {
		return
	}
	asOf := time.Now()
	if raw := c.Query("as_of"); raw != "" {
		t, valid := parseTimeQuery(raw)
		if !valid {
			respondInvalidQueryParam(c, "as_of")
			return
		}
		asOf = t
	}
	lang := reportLanguage(c.Query("language"))
	// 區間退化為空（起迄同一時點）：資料集不帶記錄，避免為了丟掉它而先查一次
	rep, err := h.builder.Build(scope, asOf, asOf, asOf, lang)
	if err != nil {
		h.respondReportError(c, apierror.CodeInternalRotationReportBuild, err)
		return
	}
	rep.Records = nil
	c.JSON(http.StatusOK, gin.H{"data": rep})
}

// Records 區間內的改密記錄明細（GET /rotation-report/records，分頁）。
func (h *RotationReportHandler) Records(c *gin.Context) {
	scope, ok := scopeFromQuery(c)
	if !ok {
		return
	}
	start, end, ok := periodFromQuery(c)
	if !ok {
		return
	}
	page, ok := parsePositiveIntQuery(c, "page", 1)
	if !ok {
		return
	}
	pageSize, ok := parsePositiveIntQuery(c, "page_size", 20)
	if !ok {
		return
	}
	if pageSize > 100 {
		pageSize = 100
	}
	lang := reportLanguage(c.Query("language"))
	rep, err := h.builder.Build(scope, start, end, end, lang)
	if err != nil {
		h.respondReportError(c, apierror.CodeInternalRotationReportBuild, err)
		return
	}
	total := len(rep.Records)
	from := (page - 1) * pageSize
	if from > total {
		from = total
	}
	to := from + pageSize
	if to > total {
		to = total
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rep.Records[from:to], "total": total,
		"page": page, "page_size": pageSize,
		"truncated": rep.Truncation.RecordsTruncated,
	})
}

// createJobRequest 手動產出的請求體。
type createJobRequest struct {
	ScopeKind   string    `json:"scope_kind"`
	ScopeID     uint      `json:"scope_id"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Language    string    `json:"language"`
}

// CreateJob 手動產出（POST /rotation-report/jobs）：建一張下載中心工作單。
func (h *RotationReportHandler) CreateJob(c *gin.Context) {
	var req createJobRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	if req.ScopeKind == "" {
		req.ScopeKind = model.RotationScopeAll
	}
	filter := asset.ReportJobFilter{
		ScopeKind:   req.ScopeKind,
		ScopeID:     req.ScopeID,
		PeriodStart: req.PeriodStart,
		PeriodEnd:   req.PeriodEnd,
		Language:    requestedLanguage(req.Language),
	}
	name := currentRequesterName(c)
	job, err := h.schedules.CreateManualJob(filter, name, currentRequester(c))
	if err != nil {
		h.auditReport(c, model.ActionCreate, model.StatusDenied, nil,
			"rotation_report.job_created denied scope="+req.ScopeKind)
		h.respondReportError(c, apierror.CodeInternalRotationReportJob, err)
		return
	}
	h.auditReport(c, model.ActionCreate, model.StatusSuccess, &job.ID,
		fmt.Sprintf("rotation_report.job_created job=%d scope=%s/%d period=%s..%s lang=%s",
			job.ID, filter.ScopeKind, filter.ScopeID,
			filter.PeriodStart.Format(time.RFC3339), filter.PeriodEnd.Format(time.RFC3339),
			filter.Language))
	c.JSON(http.StatusAccepted, gin.H{"data": gin.H{"id": job.ID, "status": job.Status}})
}

// ListSchedules 排程列表（GET /rotation-report/schedules）。
func (h *RotationReportHandler) ListSchedules(c *gin.Context) {
	rows, err := h.schedules.List()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalRotationScheduleQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// CreateSchedule 建立排程（POST /rotation-report/schedules）。
func (h *RotationReportHandler) CreateSchedule(c *gin.Context) {
	var req model.RotationReportSchedule
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	row, err := h.schedules.Create(&req)
	if err != nil {
		h.auditReport(c, model.ActionCreate, model.StatusDenied, nil,
			"rotation_report.schedule_created denied name="+req.Name)
		h.respondReportError(c, apierror.CodeInternalRotationScheduleCreate, err)
		return
	}
	h.auditReport(c, model.ActionCreate, model.StatusSuccess, &row.ID,
		fmt.Sprintf("rotation_report.schedule_created id=%d name=%s cron=%s scope=%s/%d retention=%d lang=%s",
			row.ID, row.Name, row.Cron, row.ScopeKind, row.ScopeID, row.RetentionDays, row.Language))
	c.JSON(http.StatusCreated, gin.H{"data": row})
}

// UpdateSchedule 修改排程（PUT /rotation-report/schedules/:id）。
func (h *RotationReportHandler) UpdateSchedule(c *gin.Context) {
	id, ok := parseScheduleID(c)
	if !ok {
		return
	}
	var req model.RotationReportSchedule
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	row, err := h.schedules.Update(id, &req)
	if err != nil {
		h.auditReport(c, model.ActionUpdate, model.StatusDenied, &id,
			"rotation_report.schedule_updated denied name="+req.Name)
		h.respondReportError(c, apierror.CodeInternalRotationScheduleUpdate, err)
		return
	}
	h.auditReport(c, model.ActionUpdate, model.StatusSuccess, &row.ID,
		fmt.Sprintf("rotation_report.schedule_updated id=%d name=%s cron=%s scope=%s/%d retention=%d lang=%s",
			row.ID, row.Name, row.Cron, row.ScopeKind, row.ScopeID, row.RetentionDays, row.Language))
	c.JSON(http.StatusOK, gin.H{"data": row})
}

// DeleteSchedule 刪除排程（DELETE /rotation-report/schedules/:id）。
func (h *RotationReportHandler) DeleteSchedule(c *gin.Context) {
	id, ok := parseScheduleID(c)
	if !ok {
		return
	}
	if err := h.schedules.Delete(id); err != nil {
		h.auditReport(c, model.ActionDelete, model.StatusDenied, &id,
			"rotation_report.schedule_deleted denied")
		h.respondReportError(c, apierror.CodeInternalRotationScheduleDelete, err)
		return
	}
	h.auditReport(c, model.ActionDelete, model.StatusSuccess, &id,
		fmt.Sprintf("rotation_report.schedule_deleted id=%d", id))
	c.JSON(http.StatusOK, gin.H{})
}

// RunSchedule 立即依排程規則產一份（POST /rotation-report/schedules/:id/run）。
// 它是提前的一期，故同樣推進區間錨點——服務層承擔，這裡只轉手。
func (h *RotationReportHandler) RunSchedule(c *gin.Context) {
	id, ok := parseScheduleID(c)
	if !ok {
		return
	}
	job, err := h.schedules.Trigger(id, time.Now())
	if err != nil {
		h.auditReport(c, model.ActionCreate, model.StatusDenied, &id,
			"rotation_report.job_created denied schedule_run")
		h.respondReportError(c, apierror.CodeInternalRotationReportJob, err)
		return
	}
	h.auditReport(c, model.ActionCreate, model.StatusSuccess, &job.ID,
		fmt.Sprintf("rotation_report.job_created job=%d schedule=%d manual_run", job.ID, id))
	c.JSON(http.StatusAccepted, gin.H{"data": gin.H{"id": job.ID, "status": job.Status}})
}

// periodFromQuery 記錄區間（兩個參數都必要——一個沒有起訖的「區間」是全庫掃描）。
func periodFromQuery(c *gin.Context) (time.Time, time.Time, bool) {
	start, ok := parseTimeQuery(c.Query("period_start"))
	if !ok {
		respondInvalidQueryParam(c, "period_start")
		return time.Time{}, time.Time{}, false
	}
	end, ok := parseTimeQuery(c.Query("period_end"))
	if !ok {
		respondInvalidQueryParam(c, "period_end")
		return time.Time{}, time.Time{}, false
	}
	if !start.Before(end) {
		respondInvalidQueryParam(c, "period_end")
		return time.Time{}, time.Time{}, false
	}
	return start, end, true
}

// requestedLanguage 只補缺省，不收斂非法值。
//
// **非法值必須留到服務層被拒**：在此靜默改回預設，送錯參數的人會拿到一份
// 語言與請求不符的報告，而回應是成功的——錯誤產物比錯誤訊息難發現得多。
func requestedLanguage(lang string) string {
	if strings.TrimSpace(lang) == "" {
		return model.NotificationChannelLanguageDefault
	}
	return lang
}

// reportLanguage 語言收斂到支援集合（缺省與非法值皆回預設）。
func reportLanguage(lang string) string {
	if model.ValidNotificationChannelLanguage(lang) {
		return lang
	}
	return model.NotificationChannelLanguageDefault
}

func parseScheduleID(c *gin.Context) (uint, bool) {
	id := parseUintQuery(c.Param("id"))
	if id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReportScheduleNotFound, nil)
		return 0, false
	}
	return id, true
}

// respondReportError 服務層錯誤 → 對外機器碼。值域問題 400、名稱衝突與進行中 409、
// 不存在 404，其餘走呼叫端指定的內部碼。
func (h *RotationReportHandler) respondReportError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	switch {
	case errors.Is(err, asset.ErrReportBadScope), errors.Is(err, asset.ErrReportScopeNotFound):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReportBadScope, nil)
	case errors.Is(err, asset.ErrReportBadLanguage):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReportBadLanguage, nil)
	case errors.Is(err, asset.ErrReportBadPeriod):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReportBadPeriod, nil)
	case errors.Is(err, asset.ErrReportBadCron):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReportBadCron, nil)
	case errors.Is(err, asset.ErrReportBadRetention):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReportBadRetention, nil)
	case errors.Is(err, asset.ErrReportScheduleNameEmpty):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReportNameEmpty, nil)
	case errors.Is(err, asset.ErrReportScheduleNameTooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReportNameTooLong, nil)
	case errors.Is(err, asset.ErrReportScheduleNameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeReportNameExists, nil)
	case errors.Is(err, asset.ErrReportScheduleInflight):
		apierror.Respond(c, http.StatusConflict, apierror.CodeReportScheduleBusy, nil)
	case errors.Is(err, audit.ErrExportJobLimitExceeded):
		apierror.Respond(c, http.StatusConflict, apierror.CodeExportJobLimit, nil)
	case errors.Is(err, asset.ErrReportScheduleNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeReportScheduleNotFound, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

// auditReport 報告端點的審計出口（手動產出、排程建立／修改／刪除、立即產出
// 共用同一個字面量——拆成多份就會有多處各自演化的欄位集）。
func (h *RotationReportHandler) auditReport(c *gin.Context, action model.AuditAction,
	status model.AuditStatus, resourceID *uint, msg string) {
	if h.auditService == nil {
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     action,
		Resource:   model.ResourceRotationReport,
		ResourceID: resourceID,
		Status:     status,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   sourceip.Of(c),
		StatusCode: c.Writer.Status(),
		ErrorMsg:   msg,
	})
}
