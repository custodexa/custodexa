package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/gin-gonic/gin"
)

// 證據包非同步匯出 job 端點。
//
// 與同步匯出同屬 AuditExportHandler（同一 /audit-export 路由群、同一
// audit:view 閘）；本檔只放 job 三端點：POST 發起、GET 清單、GET 下載。
//
// 證據包的下載授權綁**申請者本人**（使用者裁決，不得放寬）：非申請者（含其他具
// audit:view 帳號）一律收斂 **403**（`CodeExportJobRequesterOnly`），不洩 job
// 存在性；申請者本人的不可下載態收斂 410。細節只進審計。
//
// （本段原寫「收斂 404」，與 `DownloadJob` 的實作自始不符——實作回的是 403。
// 檔頭與實碼不一致的註解比沒有註解更糟：讀者會據此推斷「不存在與無權限
// 是否可分辨」，而那是本端點的安全性質。2026-08-31 順修，backlog #11。）

// exportJobView job 的回應投影（顯式 DTO：ArtifactPath 是伺服器內部路徑、
// FilterJSON 是內部快照格式，皆不出站；範圍摘要走與 manifest 同源的字串化）
func exportJobView(j *model.AuditExportJob, offsiteSHA256 string) gin.H {
	v := gin.H{
		"id":            j.ID,
		"status":        j.Status,
		"kind":          j.Kind,
		"requested_at":  j.RequestedAt,
		"artifact_size": j.ArtifactSize,
		"requester":     j.RequesterName,
	}
	// 範圍摘要的字串化依種類分流：證據包走篩選快照的顯示投影，報告走報告參數。
	// **兩者的快照格式不同**，用錯一方會靜默少一個欄位而不是報錯
	if j.Kind == model.ExportJobKindRotationReport {
		v["report"] = asset.ReportJobDisplay(j.FilterJSON)
	} else if filter, err := audit.ParseExportFilterSnapshot(j.FilterJSON); err == nil {
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
	// 離機保存狀態（evidence-offsite-storage）：下載中心的狀態欄要說得出
	// 「這個包還在不在本機、離機副本取不取得回來」。**恆輸出（含空字串）**——
	// 空字串是正常值（未排入），與「這個部署沒有這個欄位」是兩件事，
	// 而前端的十態對照表把 `''` 當成其中一態處理。
	// 不輸出 `offsite_object_id`：帳冊列的識別碼對申請者無用，
	// 重試是 admin 在離機儲存頁的動作
	v["offsite_status"] = j.OffsiteStatus
	// 帳冊列的整檔雜湊（狀態行第三列「已離機保存 · <sha256 前 12>」）。
	// 與 `artifact_sha256` **不同來源**：後者是打包當下對本機檔算的，這個是
	// 上傳當下對送出去的位元組算的，回答的是「遠端那一份是什麼」。
	// 取不到就不輸出（欄位缺席＝這一列沒有可呈現的離機雜湊）
	if offsiteSHA256 != "" {
		v["offsite_sha256"] = offsiteSHA256
	}
	return v
}

// offsiteSHA256 取帳冊列記下的整檔雜湊，供 exportJobView 的離機行使用。
//
// **只對 uploaded 態查**：其餘態的離機行不帶雜湊，查了也用不上，也就不必為
// 每一列多付一次查詢。未組裝離機子系統或帳冊列讀不到時回空字串——這一行是
// 輔助說明，取不到就少一段文字，不該讓整份清單變成錯誤。
func (h *AuditExportHandler) offsiteSHA256(j *model.AuditExportJob) string {
	if h.offsite == nil || j.OffsiteObjectID == nil || j.OffsiteStatus != offsite.StateUploaded {
		return ""
	}
	row, err := h.offsite.Object(*j.OffsiteObjectID)
	if err != nil || row == nil {
		return ""
	}
	return row.SHA256
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

	c.JSON(http.StatusAccepted, gin.H{"data": exportJobView(job, h.offsiteSHA256(job)), "deduplicated": !created})
}

// ListJobs 下載中心的清單（GET /audit-export/jobs，分頁、id 降冪穩定排序）。
//
// `kind` 缺省為證據包，此時清單範圍與下載授權同判準：只列本人，無跨帳號檢視面。
// `kind=rotation_report` 列全部報告工作單——報告是共用產物，且排程產出的沒有
// 人類申請者。種類值域為閉集，其餘值回 400。
func (h *AuditExportHandler) ListJobs(c *gin.Context) {
	page, ok := parsePositiveIntQuery(c, "page", 1)
	if !ok {
		return
	}
	pageSize, ok := parsePositiveIntQuery(c, "page_size", 20)
	if !ok {
		return
	}
	kind := c.Query("kind")
	if kind == "" {
		// 缺省維持既有呼叫端行為：這個端點在種類欄出現之前只有證據包
		kind = model.ExportJobKindEvidenceBundle
	}
	if kind != model.ExportJobKindEvidenceBundle && kind != model.ExportJobKindRotationReport {
		respondInvalidQueryParam(c, "kind")
		return
	}
	jobs, total, err := h.jobs.List(currentRequester(c), kind, page, pageSize)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalExportJob, err)
		return
	}
	views := make([]gin.H, 0, len(jobs))
	for i := range jobs {
		views = append(views, exportJobView(&jobs[i], h.offsiteSHA256(&jobs[i])))
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

	job, getErr := h.jobs.GetForDownload(uint(jobID), currentRequester(c))
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

	artifactPath, offsiteErr := h.resolveArtifact(c, job)
	if offsiteErr != nil {
		if code := offsiteFailureCode(offsiteErr); code != "" {
			// 離機副本被判不可信／取不到：**零位元組交付**＋機器碼
			h.auditJob(c, model.ActionRead, model.StatusFailure, &job.ID,
				"download_failed reason=offsite_unavailable code="+string(code))
			apierror.Respond(c, http.StatusConflict, code, nil)
			return
		}
		h.auditJob(c, model.ActionRead, model.StatusFailure, &job.ID,
			"download_failed reason=artifact_unreadable")
		apierror.Respond(c, http.StatusGone, apierror.CodeExportArtifactUnavailable, nil)
		return
	}

	filename := fmt.Sprintf("audit-evidence-job-%d.zip", job.ID)
	if job.Kind == model.ExportJobKindRotationReport {
		filename = fmt.Sprintf("rotation-report-job-%d.zip", job.ID)
	}
	c.FileAttachment(artifactPath, filename)
	if c.Writer.Status() != http.StatusOK {
		// 檔案缺失等交付失敗：對外已由 FileAttachment 寫出狀態，審計記實況
		h.auditJob(c, model.ActionRead, model.StatusFailure, &job.ID,
			fmt.Sprintf("download_failed status_code=%d", c.Writer.Status()))
		return
	}
	h.auditJob(c, model.ActionRead, model.StatusSuccess, &job.ID,
		fmt.Sprintf("download job=%d sha256=%s size=%d", job.ID, job.ArtifactSHA256, job.ArtifactSize))
}

// OffsiteArtifactRetriever 證據包產物的離機取回面（消費者側窄介面）。
//
// 由 `offsite.Fetcher` 滿足；nil＝本部署未組裝離機子系統，下載路徑逐字維持原行為。
type OffsiteArtifactRetriever interface {
	Object(objectID uint) (*model.OffsiteObject, error)
	Fetch(ctx context.Context, objectID uint) (*offsite.FetchedObject, error)
}

// SetOffsiteRetriever 接上離機取回面（組裝根）。
func (h *AuditExportHandler) SetOffsiteRetriever(r OffsiteArtifactRetriever) { h.offsite = r }

// resolveArtifact 產物的來源判定（來源判定判準套用於證據包）。
//
// **逾期語義不受影響**：本函式只在「已通過可下載判定」之後被呼叫——逾期者早已在
// 上面回 410，即使遠端物件仍在。下載窗口＝該工作單自身的保留期（證據包 24 小時，
// 報告依排程設定的天數）；遠端副本的角色是
// 窗口內的耐久性（產物目錄未掛 volume，容器重建即消失）與組織的證據寄存。
//
// 回傳的 error 非 nil＝**不得交付**（不退回「盡力給本機那個壞掉的檔」）。
func (h *AuditExportHandler) resolveArtifact(c *gin.Context, job *model.AuditExportJob) (string, error) {
	info, statErr := os.Stat(job.ArtifactPath)
	localOK := statErr == nil && (job.ArtifactSize == 0 || info.Size() == job.ArtifactSize)
	if localOK || h.offsite == nil || job.OffsiteObjectID == nil {
		return job.ArtifactPath, nil
	}
	fetched, err := h.offsite.Fetch(c.Request.Context(), *job.OffsiteObjectID)
	if err != nil {
		if errors.Is(err, offsite.ErrNoOffsiteCopy) && statErr == nil {
			// 遠端沒有可取回的副本，但本機檔還在（只是大小對不上帳冊）：
			// 交付本機那一份並在審計留痕——這是既有行為，不因離機而更差
			log.Printf("[AuditExportJob] job=%d 本機產物大小與帳冊不符且無離機副本，仍以本機交付",
				job.ID)
			return job.ArtifactPath, nil
		}
		return "", err
	}
	return fetched.Path, nil
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
