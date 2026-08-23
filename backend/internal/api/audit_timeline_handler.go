package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// AuditTimelineHandler 稽核調查工作台的兩支唯讀端點（auditor-workbench）。
//
// **零寫入**：工作台不提供任何狀態變更端點（沿 checkpoint 驗證頁刻意唯讀的先例）。
// 稽核工具一旦能改東西，它產出的證據就要先自證沒被自己改過
type AuditTimelineHandler struct {
	timeline *audit.TimelineService
}

func NewAuditTimelineHandler(timeline *audit.TimelineService) *AuditTimelineHandler {
	return &AuditTimelineHandler{timeline: timeline}
}

// Timeline GET /api/v1/audit/timeline
func (h *AuditTimelineHandler) Timeline(c *gin.Context) {
	q := audit.TimelineQuery{
		Subject:   audit.TimelineSubject(c.Query("subject")),
		SubjectID: parseUintQuery(c.Query("subject_id")),
	}

	from, okFrom := parseTimeQuery(c.Query("from"))
	to, okTo := parseTimeQuery(c.Query("to"))
	if !okFrom || !okTo {
		respondInvalidQueryParam(c, "range")
		return
	}
	q.From, q.To = from, to

	// types 空＝全部；未知值回 400 而非靜默忽略——靜默忽略會回一份
	// 看起來完整、實際少了一整類的時間軸，而使用者無從察覺
	if raw := c.Query("types"); raw != "" {
		for _, t := range splitCSV(raw) {
			if !audit.IsTimelineEventType(t) {
				respondInvalidQueryParam(c, "types")
				return
			}
			q.Types = append(q.Types, audit.TimelineEventType(t))
		}
	}

	if raw := c.Query("cursor"); raw != "" {
		cur, err := audit.DecodeTimelineCursor(raw)
		if err != nil {
			respondInvalidQueryParam(c, "cursor")
			return
		}
		q.Cursor = &cur
	}

	if raw := c.Query("limit"); raw != "" {
		q.Limit = int(parseUintQuery(raw))
	}

	result, err := h.timeline.Query(q)
	if err != nil {
		switch {
		case errors.Is(err, audit.ErrInvalidSubject):
			respondInvalidQueryParam(c, "subject")
		case errors.Is(err, audit.ErrInvalidRange):
			respondInvalidQueryParam(c, "range")
		case errors.Is(err, audit.ErrUnknownEventType):
			respondInvalidQueryParam(c, "types")
		default:
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuditLogQuery, err)
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

// Subjects GET /api/v1/audit/subjects
func (h *AuditTimelineHandler) Subjects(c *gin.Context) {
	kind := audit.TimelineSubject(c.Query("type"))
	if kind != audit.SubjectUser && kind != audit.SubjectAsset {
		respondInvalidQueryParam(c, "subject")
		return
	}
	limit := int(parseUintQuery(c.Query("limit")))
	subjects, err := h.timeline.ListSubjects(kind, c.Query("q"), limit)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuditLogQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": subjects, "total": len(subjects)})
}

// RegisterRoutes 註冊工作台路由。
//
// **權限無條件強制**：`RequirePermission` 直接掛在群組上，不隨
// 任何部署組態進退（沿 access-reviews 先例；權限旗標已退場）。
// 這兩支端點一次橫跨六類審計資料，是全站可讀範圍最寬的讀取面之一，
// 把它交給一個開發用旁路開關等於把稽核資料的門留在外面
func (h *AuditTimelineHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/audit")
	g.Use(middleware.AuthMiddleware(authService))
	g.Use(middleware.RequirePermission(middleware.PermAuditView))
	{
		g.GET("/timeline", h.Timeline)
		g.GET("/subjects", h.Subjects)
	}
}

func respondInvalidQueryParam(c *gin.Context, field string) {
	apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidQueryParam,
		map[string]any{"field": field})
}

func parseUintQuery(s string) uint {
	if s == "" {
		return 0
	}
	// bitSize 31：保證解析結果轉 int 恆為正值、不截斷
	v, err := strconv.ParseUint(s, 10, 31)
	if err != nil {
		return 0
	}
	return uint(v)
}

// parseTimeQuery 接受 RFC3339。**不接受「只有日期」**：一個沒有時分秒的
// 時間窗端點會讓「今天」的定義落在伺服器時區上，而稽核調查跨時區時
// 那正是最容易產生爭議的一點——要求呼叫端明寫偏移量
func parseTimeQuery(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func splitCSV(s string) []string {
	out := make([]string, 0, 6)
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
