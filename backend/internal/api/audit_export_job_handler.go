package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/gin-gonic/gin"
)

// 證據包非同步匯出 job 端點。
//
// 與同步匯出同屬 AuditExportHandler（同一 /audit-export 路由群、同一
// audit:view 閘）；本檔只放 job 三端點：POST 發起、GET 清單、GET 下載。
//
// 下載授權綁**申請者本人**（使用者裁決，不得放寬）：非申請者（含其他具
// audit:view 帳號）一律收斂 404，不洩 job 存在性；申請者本人的不可下載態
// 收斂 410。細節只進審計。

// exportJobView job 的回應投影（顯式 DTO：ArtifactPath 是伺服器內部路徑、
// FilterJSON 是內部快照格式，皆不出站；範圍摘要走與 manifest 同源的字串化）
func exportJobView(j *model.AuditExportJob) gin.H {
	v := gin.H{
		"id":            j.ID,
		"status":        j.Status,
		"requested_at":  j.RequestedAt,
		"artifact_size": j.ArtifactSize,
	}
	if filter, err := audit.ParseExportFilterSnapshot(j.FilterJSON); err == nil {
		v["filter"] = filter.DisplayMap()
	}
	if j.ArtifactSHA256 != "" {
		v["artifact_sha256"] = j.ArtifactSHA256
	}
	if j.ErrorSummary != "" {
		v["error_summary"] = j.ErrorSummary
	}
	if j.PackagedAt != nil {
		v["packaged_at"] = j.PackagedAt
	}
	if j.ExpiresAt != nil {
		v["expires_at"] = j.ExpiresAt
	}
	return v
}

// CreateJob 發起證據包打包（POST /audit-export/jobs）。
//
// 篩選參數與同步端點同一套解析（query 形態沿用，預填入口一致）；僅受理
// 證據包模式。命中 pending/running 去重時回既有 job（冪等，deduplicated=true）；
// 額度已滿回收斂 409。發起（成功與被拒）皆入審計，含完整篩選快照。
func (h *AuditExportHandler) CreateJob(c *gin.Context) {
	filter, ok := parseExportFilter(c)
	if !ok {
		return
	}
	if filter.IsEventReport() {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeExportJobBundleOnly, nil)
		return
	}

	job, created, err := h.jobs.CreateJob(currentRequester(c), currentRequesterName(c), filter)
	if err != nil {
		if errors.Is(err, audit.ErrExportJobLimitExceeded) {
			h.auditJob(c, model.ActionCreate, model.StatusDenied, nil,
				"job_limit_exceeded "+exportFilterAuditSnapshot(filter))
			apierror.Respond(c, http.StatusConflict, apierror.CodeExportJobLimit, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalExportJob, err)
		return
	}

	// 發起入審計：申請者（審計列本體）＋完整篩選條件快照（spec 硬要求）
	msg := fmt.Sprintf("job=%d created=%t %s", job.ID, created, exportFilterAuditSnapshot(filter))
	h.auditJob(c, model.ActionCreate, model.StatusSuccess, &job.ID, msg)

	c.JSON(http.StatusAccepted, gin.H{"data": exportJobView(job), "deduplicated": !created})
}

// ListJobs 申請者本人的 job 清單（GET /audit-export/jobs，分頁、id 降冪穩定排序）。
// 清單範圍與下載授權同判準：只列本人，无跨帳號檢視面。
func (h *AuditExportHandler) ListJobs(c *gin.Context) {
	page, ok := parsePositiveIntQuery(c, "page", 1)
	if !ok {
		return
	}
	pageSize, ok := parsePositiveIntQuery(c, "page_size", 20)
	if !ok {
		return
	}
	jobs, total, err := h.jobs.ListByRequester(currentRequester(c), page, pageSize)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalExportJob, err)
		return
	}
	views := make([]gin.H, 0, len(jobs))
	for i := range jobs {
		views = append(views, exportJobView(&jobs[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": views, "total": total, "page": page, "page_size": pageSize})
}

// DownloadJob 下載產物（GET /audit-export/jobs/:id/download）。
//
// 認證＋audit:view 由路由群中介層承擔；本端點加第三道：**申請者本人**（使用者裁決，
// 不得放寬）。非申請者（含其他具 audit:view 帳號）、job 不存在、識別非法
// 三種情形收斂為同一 403 同一碼——分成 404/403 會讓具權限的探測者以狀態碼
// 枚舉 job 存在性。本人 job 的不可下載態（pending/running/failed/expired）
// 收斂 410。每次下載入審計（誰、何時、哪個包＋SHA-256）；拒絕同樣入審計，
// 真實原因只在審計。
func (h *AuditExportHandler) DownloadJob(c *gin.Context) {
	jobID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeExportJobRequesterOnly, nil)
		return
	}

	job, getErr := h.jobs.GetForRequester(uint(jobID), currentRequester(c))
	if getErr != nil {
		if errors.Is(getErr, audit.ErrExportJobNotFound) {
			// 不存在或非申請者本人：對外同一 403；真實原因只進審計
			h.auditJob(c, model.ActionRead, model.StatusDenied, nil,
				fmt.Sprintf("download_denied job=%d reason=not_found_or_not_requester", jobID))
			apierror.Respond(c, http.StatusForbidden, apierror.CodeExportJobRequesterOnly, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalExportJob, getErr)
		return
	}

	// 可下載＝done 且未逾期（過期清掃有輪詢間隙，時刻判定不等清掃）且產物在檔
	now := time.Now()
	if job.Status != model.ExportJobDone || job.ArtifactPath == "" ||
		(job.ExpiresAt != nil && !job.ExpiresAt.After(now)) {
		h.auditJob(c, model.ActionRead, model.StatusDenied, &job.ID,
			"download_denied reason=artifact_unavailable status="+job.Status)
		apierror.Respond(c, http.StatusGone, apierror.CodeExportArtifactUnavailable, nil)
		return
	}

	filename := fmt.Sprintf("audit-evidence-job-%d.zip", job.ID)
	c.FileAttachment(job.ArtifactPath, filename)
	if c.Writer.Status() != http.StatusOK {
		// 檔案缺失等交付失敗：對外已由 FileAttachment 寫出狀態，審計記實況
		h.auditJob(c, model.ActionRead, model.StatusFailure, &job.ID,
			fmt.Sprintf("download_failed status_code=%d", c.Writer.Status()))
		return
	}
	h.auditJob(c, model.ActionRead, model.StatusSuccess, &job.ID,
		fmt.Sprintf("download job=%d sha256=%s size=%d", job.ID, job.ArtifactSHA256, job.ArtifactSize))
}

// auditJob job 端點的審計出口（發起／下載／拒絕共用同一字面量——
// 各寫一份就會各自演化欄位集；沿 AP-69/AP-71 的單一字面量紀律）
func (h *AuditExportHandler) auditJob(c *gin.Context, action model.AuditAction,
	status model.AuditStatus, jobID *uint, msg string) {
	if h.auditService == nil {
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     action,
		Resource:   model.ResourceAuditExport,
		ResourceID: jobID,
		Status:     status,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   sourceip.Of(c),
		StatusCode: c.Writer.Status(),
		ErrorMsg:   msg,
	})
}

// exportFilterAuditSnapshot 篩選快照的審計字串（鍵序穩定，兩次發起可比對）
func exportFilterAuditSnapshot(filter *audit.ExportFilter) string {
	m := filter.DisplayMap()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := "filter{"
	for i, k := range keys {
		if i > 0 {
			out += " "
		}
		out += k + "=" + m[k]
	}
	return out + "}"
}

// currentRequester／currentRequesterName 申請者身分（認證中介層已保證存在）
func currentRequester(c *gin.Context) uint {
	id, _ := middleware.GetCurrentUserID(c)
	return id
}

func currentRequesterName(c *gin.Context) string {
	name, _ := middleware.GetCurrentUsername(c)
	return name
}

// parsePositiveIntQuery 解析正整數 query（缺席回預設；非法回 400 並回 false）
func parsePositiveIntQuery(c *gin.Context, field string, def int) (int, bool) {
	raw := c.Query(field)
	if raw == "" {
		return def, true
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		respondInvalidQueryParam(c, field)
		return 0, false
	}
	return v, true
}
