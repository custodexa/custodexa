package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/sourceip"
)

// 合規對照的唯讀端點。
//
// **這一組不寫入對照內容**：對照的內容改在政策組管理端，設定值改在安全政策端。
// 唯一的 POST 是產出報告——它建一張下載中心工作單，把讀到的結果落檔取證，
// 不改動任何條文、要求或設定值。
// 對照頁要回答的是「現在這一刻，設定對每一個生效政策組符不符」，把寫入放進來
// 會讓同一份對照有兩個入口，而「這條要求是誰改的」就分裂成兩套記錄。
//
// 回應一次帶齊判定、逐組摘要、政策組本體與條文卡片：那四樣是同一個畫面的四個
// 區塊，分成四支端點會讓它們在不同時點各讀一次——而判定是有時點的，
// 兩個時點之間管理者改了一個值，畫面上的摘要與逐條結果就對不起來。

// ComplianceHandler 合規判定結果的讀取端（admin 與 auditor）。
type ComplianceHandler struct {
	compliance   *policy.ComplianceService
	groups       *policy.PolicyGroupRepository
	jobs         *audit.AuditExportJobService
	auditService *audit.AuditLogService
}

// NewComplianceHandler 建立合規對照 handler。jobs 與 auditService 供產出報告；
// jobs 為 nil 時產出報告回 500 內部碼，快照讀取不受影響。
func NewComplianceHandler(compliance *policy.ComplianceService,
	groups *policy.PolicyGroupRepository, jobs *audit.AuditExportJobService,
	auditService *audit.AuditLogService) *ComplianceHandler {
	return &ComplianceHandler{compliance: compliance, groups: groups, jobs: jobs, auditService: auditService}
}

// Snapshot 一份判定結果。
//
// query 參數 `group` 指定單一政策組；省略＝全部生效組。指定不存在的組回 404
// 而不是一份「每個鍵都未對照」的結果——後者與組代號打錯字在畫面上分不出來。
func (h *ComplianceHandler) Snapshot(c *gin.Context) {
	groupFilter := c.Query("group")
	snapshot, err := h.compliance.Snapshot(groupFilter, nil)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalComplianceSnapshot)
		return
	}
	payload, err := h.decorate(snapshot, groupFilter)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalPolicyGroupRead, err)
		return
	}
	c.JSON(http.StatusOK, payload)
}

// decorate 把判定結果補上畫面需要的政策組本體、逐組摘要與條文卡片。
func (h *ComplianceHandler) decorate(snapshot policy.ComplianceSnapshot,
	groupFilter string) (gin.H, error) {

	groups, err := h.groups.ListGroups()
	if err != nil {
		return nil, err
	}
	clauses, err := h.groups.ListClauses(groupFilter)
	if err != nil {
		return nil, err
	}
	controls, err := h.groups.ListControls(groupFilter)
	if err != nil {
		return nil, err
	}
	annotations, err := h.groups.ListAnnotations(groupFilter)
	if err != nil {
		return nil, err
	}

	inScope := make([]model.PolicyGroup, 0, len(groups))
	summaries := make([]policy.GroupSummary, 0, len(groups))
	for _, g := range groups {
		if groupFilter != "" && g.Code != groupFilter {
			continue
		}
		inScope = append(inScope, g)
		if g.Enabled {
			summaries = append(summaries, snapshot.GroupSummary(g.Code))
		}
	}
	return gin.H{
		"data":      snapshot,
		"groups":    inScope,
		"summaries": summaries,
		"clauses":   buildClauseViews(clauses, controls, annotations),
	}, nil
}

// RegisterRoutes 註冊合規對照路由（admin 與 auditor；唯讀快照＋產出報告）。
func (h *ComplianceHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	compliance := r.Group("/compliance")
	compliance.Use(middleware.AuthMiddleware(authService))
	compliance.Use(middleware.RequireAnyRole(model.RoleAdmin, model.RoleAuditor))
	{
		compliance.GET("/snapshot", h.Snapshot)
		compliance.POST("/report-jobs", h.CreateReportJob)
	}
}

// createReportJobRequest 手動產出的請求體。沒有期間參數：報告只有「截至現在」。
type createReportJobRequest struct {
	Group         string `json:"group"`
	Language      string `json:"language"`
	RetentionDays *int   `json:"retention_days"`
}

// CreateReportJob 手動產出合規報告（POST /compliance/report-jobs）：建一張
// 下載中心工作單，回 202。admin 與 auditor 皆可（與快照同閘）。
func (h *ComplianceHandler) CreateReportJob(c *gin.Context) {
	var req createReportJobRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Group) == "" {
		h.auditReport(c, model.StatusDenied, nil, "compliance_report.job_created denied reason=bad_params")
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	filter := policy.ComplianceReportJobFilter{
		Group:         strings.TrimSpace(req.Group),
		Language:      requestedLanguage(req.Language),
		RetentionDays: policy.ComplianceReportRetentionDefaultDays,
		GeneratedBy:   currentRequesterName(c),
	}
	if req.RetentionDays != nil {
		filter.RetentionDays = *req.RetentionDays
	}
	denied := func(reason string) {
		h.auditReport(c, model.StatusDenied, nil, fmt.Sprintf(
			"compliance_report.job_created denied reason=%s group=%s", reason, filter.Group))
	}
	if err := filter.ValidateRetention(); err != nil {
		denied("bad_retention")
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReportBadRetention, nil)
		return
	}
	if !model.ValidNotificationChannelLanguage(filter.Language) {
		denied("bad_language")
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeReportBadLanguage, nil)
		return
	}
	group, err := h.groups.GetGroup(filter.Group)
	if err != nil {
		denied("group_lookup")
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupRead)
		return
	}
	if !group.Enabled {
		denied("group_inactive")
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	filter.GroupName = group.Name
	if h.jobs == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalComplianceSnapshot, errors.New("合規報告工作單服務未接上"))
		return
	}
	job, err := h.createReportJob(filter, currentRequester(c))
	if err != nil {
		denied("job_rejected")
		if errors.Is(err, audit.ErrExportJobLimitExceeded) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeExportJobLimit, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalComplianceSnapshot, err)
		return
	}
	h.auditReport(c, model.StatusSuccess, &job.ID, fmt.Sprintf(
		"compliance_report.job_created job=%d group=%s lang=%s retention_days=%d",
		job.ID, filter.Group, filter.Language, filter.RetentionDays))
	c.JSON(http.StatusAccepted, gin.H{"data": gin.H{"id": job.ID, "status": job.Status}})
}

// createReportJob 受理：預定到期＝發起時刻加保留天數（worker 打包完成時自實際
// 打包時刻重新起算）。去重鍵不含發起者，兩人同時要同一份報告拿到同一張工作單。
func (h *ComplianceHandler) createReportJob(filter policy.ComplianceReportJobFilter,
	requesterID uint) (*model.AuditExportJob, error) {
	filterJSON, err := filter.Marshal()
	if err != nil {
		return nil, err
	}
	dedupe, err := filter.DedupeKey()
	if err != nil {
		return nil, err
	}
	expires := time.Now().AddDate(0, 0, filter.RetentionDays)
	job, _, err := h.jobs.CreateReportJob(model.ExportJobKindComplianceReport, filterJSON, dedupe,
		filter.GeneratedBy, requesterID, &expires, nil)
	return job, err
}

// auditReport 產出報告的審計出口（成功與被拒共用同一個字面量）。
func (h *ComplianceHandler) auditReport(c *gin.Context, status model.AuditStatus,
	resourceID *uint, msg string) {
	if h.auditService == nil {
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     model.ActionCreate,
		Resource:   model.ResourceComplianceMap,
		ResourceID: resourceID,
		Status:     status,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   sourceip.Of(c),
		StatusCode: c.Writer.Status(),
		ErrorMsg:   msg,
	})
}
