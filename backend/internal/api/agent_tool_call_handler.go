package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
)

// ToolCalls exposes pending calls explicitly; an unknown result is never inferred as success.
func (h *AuditIntegrityHandler) ToolCalls(c *gin.Context) {
	f := audit.AgentToolCallFilter{Decision: c.Query("decision")}
	for key, target := range map[string]**uint{"user_id": &f.UserID, "access_request_id": &f.AccessRequestID, "session_id": &f.SessionID} {
		if value := c.Query(key); value != "" {
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil || n == 0 {
				apierror.Respond(c, 400, apierror.CodeBadParams, nil)
				return
			}
			id := uint(n)
			*target = &id
		}
	}
	for key, target := range map[string]**time.Time{"from": &f.From, "to": &f.To} {
		if value := c.Query(key); value != "" {
			at, err := time.Parse(time.RFC3339, value)
			if err != nil {
				apierror.Respond(c, 400, apierror.CodeBadParams, nil)
				return
			}
			*target = &at
		}
	}
	if f.From != nil && f.To != nil && !f.To.After(*f.From) {
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return
	}
	switch f.Decision {
	case "", model.ToolCallPending, model.ToolCallAllowed, model.ToolCallDenied, model.ToolCallBreaker, model.ToolCallRateLimited:
	default:
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return
	}
	for key, target := range map[string]*int{"offset": &f.Offset, "limit": &f.Limit} {
		if value := c.Query(key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				apierror.Respond(c, 400, apierror.CodeBadParams, nil)
				return
			}
			*target = n
		}
	}
	rows, total, err := audit.NewAgentToolCallLedger(h.db, h.integrity).Query(c.Request.Context(), f)
	if err != nil {
		apierror.RespondInternal(c, 500, apierror.CodeInternalAuditIntegrityVerify, err)
		return
	}
	type response struct {
		*model.AgentToolCall
		ArgsRedacted json.RawMessage `json:"args_redacted"`
	}
	data := make([]response, 0, len(rows))
	for i := range rows {
		data = append(data, response{&rows[i], json.RawMessage(rows[i].ArgsRedacted)})
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "total": total})
}
