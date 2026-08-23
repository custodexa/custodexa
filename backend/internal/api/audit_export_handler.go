package api

import (
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
)

// AuditExportHandler 稽核證據匯出（audit-workflows，PCI 10.5.1）
type AuditExportHandler struct {
	exportService *audit.AuditExportService
	auditService  *audit.AuditLogService
}

// NewAuditExportHandler 建立匯出 handler
func NewAuditExportHandler(exportService *audit.AuditExportService, auditService *audit.AuditLogService) *AuditExportHandler {
	return &AuditExportHandler{exportService: exportService, auditService: auditService}
}

// Export 匯出證據包
func (h *AuditExportHandler) Export(c *gin.Context) {
	filter, ok := parseExportFilter(c)
	if !ok {
		return
	}

	exporterID, _ := middleware.GetCurrentUserID(c)
	exporterName, _ := middleware.GetCurrentUsername(c)

	// 串流前先設標頭：一旦開始寫 body 就無法改狀態碼，故錯誤只能記日誌（body 已含部分內容）
	filename := fmt.Sprintf("audit-evidence-%s.zip", time.Now().Format("20060102-150405"))
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	manifest, err := h.exportService.Export(c.Writer, filter, exporterID, exporterName)
	if err != nil {
		// body 可能已部分寫出，無法回乾淨的錯誤碼；記日誌並留下失敗審計
		log.Printf("[AuditExport] 匯出失敗 (exporter=%s): %v", exporterName, err)
		h.auditExport(c, exporterID, exporterName, model.StatusFailure, "export_failed: "+err.Error())
		return
	}

	// 匯出成功入審計（誰匯了什麼範圍、含各部分筆數與截斷標記）
	h.auditExport(c, exporterID, exporterName, model.StatusSuccess, exportSummary(manifest))
}

// parseExportFilter 解析並驗證匯出篩選；至少須有一個範圍條件（避免匯出全庫）。
//
// **參數解析失敗一律回錯誤碼**：原實作把 ParseUint／time.Parse 的錯誤丟掉，
// 打錯字的 `user_id=abc` 會被當成「沒帶這個條件」，匯出一包範圍完全不同、
// 但看起來一切正常的證據。這比直接失敗糟得多
func parseExportFilter(c *gin.Context) (*audit.ExportFilter, bool) {
	filter := &audit.ExportFilter{}

	for _, p := range []struct {
		field string
		dest  **uint
	}{
		{"session_id", &filter.SessionID},
		{"user_id", &filter.UserID},
		{"asset_id", &filter.AssetID},
	} {
		v := c.Query(p.field)
		if v == "" {
			continue
		}
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil || id == 0 {
			respondInvalidQueryParam(c, p.field)
			return nil, false
		}
		parsed := uint(id)
		*p.dest = &parsed
	}
	for _, p := range []struct {
		field string
		dest  **time.Time
	}{
		{"start_time", &filter.StartTime},
		{"end_time", &filter.EndTime},
	} {
		v := c.Query(p.field)
		if v == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			respondInvalidQueryParam(c, p.field)
			return nil, false
		}
		parsed := t
		*p.dest = &parsed
	}

	if !parseExportReportScope(c, filter) {
		return nil, false
	}

	// 至少一個範圍條件：全無條件會嘗試匯出整庫（含所有錄影），拒絕
	if filter.SessionID == nil && filter.UserID == nil && filter.AssetID == nil &&
		filter.StartTime == nil && filter.EndTime == nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAuditExportFilterRequired, nil)
		return nil, false
	}
	return filter, true
}

// parseExportReportScope 事件報告模式的參數（subject／types）。
//
// 兩者皆缺席時完全不動 filter，行為與本模式出現前相同（既有匯出入口不受影響）
func parseExportReportScope(c *gin.Context, filter *audit.ExportFilter) bool {
	subject := c.Query("subject")
	rawTypes := c.Query("types")

	if subject == "" {
		// types 只在事件報告模式下有意義。單獨帶 types 而靜默忽略，
		// 會回一包「以為篩過、其實沒篩」的證據
		if rawTypes != "" {
			respondInvalidQueryParam(c, "subject")
			return false
		}
		return true
	}

	sub := audit.TimelineSubject(subject)
	if sub != audit.SubjectUser && sub != audit.SubjectAsset {
		respondInvalidQueryParam(c, "subject")
		return false
	}
	filter.Subject = sub

	// 樞紐 id 沿用 user_id／asset_id，不另立參數
	if sub == audit.SubjectUser && filter.UserID == nil {
		respondInvalidQueryParam(c, "user_id")
		return false
	}
	if sub == audit.SubjectAsset && filter.AssetID == nil {
		respondInvalidQueryParam(c, "asset_id")
		return false
	}
	// 報告必須說得出自己涵蓋哪一段時間，故區間為必填且須有正向跨度
	if filter.StartTime == nil || filter.EndTime == nil || !filter.EndTime.After(*filter.StartTime) {
		respondInvalidQueryParam(c, "range")
		return false
	}
	// session_id 在報告模式下無處可套用；靜默忽略等於讓使用者以為篩過了
	if filter.SessionID != nil {
		respondInvalidQueryParam(c, "session_id")
		return false
	}

	if rawTypes == "" {
		return true
	}
	seen := map[string]bool{}
	for _, t := range splitCSV(rawTypes) {
		if !audit.IsTimelineEventType(t) {
			respondInvalidQueryParam(c, "types")
			return false
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		filter.Types = append(filter.Types, audit.TimelineEventType(t))
	}
	return true
}

// exportSummary 匯出摘要入審計：範圍、逐類別收錄數與範圍內總數、截斷旗標。
// 鍵序固定，事後比對兩次匯出才有意義
func exportSummary(m *audit.ExportManifest) string {
	keys := make([]string, 0, len(m.Counts))
	for k := range m.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+2)
	parts = append(parts, "mode="+m.Mode)
	if m.Scope != nil {
		parts = append(parts, fmt.Sprintf("subject=%s:%d range=%s~%s",
			m.Scope.Subject, m.Scope.SubjectID,
			m.Scope.From.Format(time.RFC3339), m.Scope.To.Format(time.RFC3339)))
	}
	for _, k := range keys {
		part := fmt.Sprintf("%s=%d", k, m.Counts[k])
		if total, ok := m.Totals[k]; ok {
			part += fmt.Sprintf("/%d", total)
		}
		if m.Truncated[k] {
			part += "(truncated)"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " ")
}

func (h *AuditExportHandler) auditExport(c *gin.Context, userID uint, username string, status model.AuditStatus, msg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     model.ActionRead, // 匯出＝讀取聚合，用 read（無專用 export action，以 resource 區分）
		Resource:   model.ResourceAuditExport,
		Status:     status,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   sourceip.Of(c),
		StatusCode: http.StatusOK,
		ErrorMsg:   msg,
	})
}

// RegisterRoutes 註冊匯出路由（限稽核角色 audit:view）。
//
// **權限無條件強制**：不隨任何部署組態進退（權限旗標已退場）
// （比照工作台端點 `AuditTimelineHandler.RegisterRoutes` 與 access-reviews 先例）。
// 這支端點把六類審計資料整包送出系統，是全站可外帶範圍最寬的出口；
// 原實作在權限開關關閉時直接放行，等於讓較嚴的調查頁長出一個較鬆的出口
func (h *AuditExportHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	grp := r.Group("/audit-export")
	grp.Use(middleware.AuthMiddleware(authService))
	grp.GET("", middleware.RequirePermission(middleware.PermAuditView), h.Export)
}
