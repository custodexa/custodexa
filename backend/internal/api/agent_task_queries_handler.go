package api

import (
	"errors"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/session"
	"gorm.io/gorm"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
)

// agentReadQuery keeps new read endpoints bounded and rejects malformed filters.
func agentReadQuery(c *gin.Context, ids map[string]**uint, from, to **time.Time, offset, limit *int) bool {
	for key, target := range ids {
		if v := c.Query(key); v != "" {
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil || n == 0 {
				apierror.Respond(c, 400, apierror.CodeBadParams, nil)
				return false
			}
			id := uint(n)
			*target = &id
		}
	}
	for key, target := range map[string]**time.Time{"from": from, "to": to} {
		if v := c.Query(key); v != "" {
			at, err := time.Parse(time.RFC3339, v)
			if err != nil {
				apierror.Respond(c, 400, apierror.CodeBadParams, nil)
				return false
			}
			*target = &at
		}
	}
	if *from != nil && *to != nil && !(*to).After(**from) {
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return false
	}
	*limit = 100
	for key, target := range map[string]*int{"offset": offset, "limit": limit} {
		if v := c.Query(key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				apierror.Respond(c, 400, apierror.CodeBadParams, nil)
				return false
			}
			*target = n
		}
	}
	if *limit == 0 || *limit > 100 {
		*limit = 100
	}
	return true
}
func (h *AccessRequestHandler) AgentTasks(c *gin.Context) {
	f := authz.AgentTaskFilter{ReportStatus: c.Query("report_status")}
	if !agentReadQuery(c, map[string]**uint{"subject": &f.Subject, "owner": &f.Owner}, &f.From, &f.To, &f.Offset, &f.Limit) {
		return
	}
	switch f.ReportStatus {
	case "", "submitted", "missing", "not_submitted":
	default:
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return
	}
	rows, total, err := authz.QueryAgentTasks(c.Request.Context(), h.db, f)
	if err != nil {
		apierror.RespondInternal(c, 500, apierror.CodeInternalAuditIntegrityVerify, err)
		return
	}
	c.JSON(200, gin.H{"data": rows, "total": total})
}

func (h *AccessRequestHandler) AgentTaskDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("requestId"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return
	}
	var from, to *time.Time
	var offset, limit int
	if !agentReadQuery(c, nil, &from, &to, &offset, &limit) {
		return
	}
	c.Set("audit_details", map[string]string{"access_request_id": strconv.FormatUint(id, 10), "query": middleware.MaskCredentialQuery(c.Request.URL.RawQuery)})
	db := h.db.WithContext(c.Request.Context())
	approvalOffset := 0
	if value := c.Query("approval_offset"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			apierror.Respond(c, 400, apierror.CodeBadParams, nil)
			return
		}
		approvalOffset = n
	}
	request, approvalTotal, err := authz.ReadAgentTask(c.Request.Context(), db, uint(id), approvalOffset, limit)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apierror.Respond(c, 404, apierror.CodeAccessRequestNotFound, nil)
		return
	}
	if err != nil {
		apierror.RespondInternal(c, 500, apierror.CodeInternalAuditIntegrityVerify, err)
		return
	}
	ids, total, err := session.AgentTaskSessionIDs(db, uint(id), offset, limit)
	if err != nil {
		apierror.RespondInternal(c, 500, apierror.CodeInternalAuditIntegrityVerify, err)
		return
	}
	reports, err := audit.ReadAgentTaskReportPage(db, uint(id), request.ClosedAt, offset, limit)
	if err != nil {
		apierror.RespondInternal(c, 500, apierror.CodeInternalAuditIntegrityVerify, err)
		return
	}
	c.JSON(200, gin.H{"request": request, "approval_total": approvalTotal, "session_ids": ids, "session_total": total, "reports": reports})
}
