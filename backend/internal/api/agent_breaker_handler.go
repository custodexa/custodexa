package api

import (
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"strconv"
	"time"
)

func (h *UserHandler) ReleaseAgentBreaker(c *gin.Context) {
	var req struct {
		Reason string `json:"reason" binding:"required,max=1000"`
	}
	if c.ShouldBindJSON(&req) != nil {
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return
	}
	if err := h.agentTokens.ReleaseProbeBreaker(c.GetUint("agent_token_user_id"), req.Reason, c.GetString("role"), agentTokenActor(c)); err != nil {
		respondAgentTokenError(c, err)
		return
	}
	c.Status(204)
}

// AgentBreakerEvents uses the subject's current pending flag, never invents a
// per-event release history that the persisted observations do not contain.
func (h *UserHandler) AgentBreakerEvents(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	actor, ok := middleware.GetCurrentUserID(c)
	kind, kindOK := middleware.GetPrincipalKind(c)
	if err != nil || id == 0 {
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return
	}
	if !ok || !kindOK || kind != model.KindHuman {
		apierror.Respond(c, 403, apierror.CodePermissionDenied, nil)
		return
	}
	user, err := h.userService.GetByID(uint(id))
	role := c.GetString("role")
	if err != nil || user.Kind != model.KindAgent || (role != model.RoleAdmin && role != model.RoleAuditor && (user.OwnerUserID == nil || *user.OwnerUserID != actor)) {
		apierror.Respond(c, 403, apierror.CodePermissionDenied, nil)
		return
	}
	var from, to *time.Time
	var offset, limit int
	if !agentReadQuery(c, nil, &from, &to, &offset, &limit) {
		return
	}
	rows, total, err := audit.QueryAgentProbeEvents(c.Request.Context(), database.DB, uint(id), from, to, offset, limit)
	if err != nil {
		apierror.RespondInternal(c, 500, apierror.CodeInternalAuditIntegrityVerify, err)
		return
	}
	c.JSON(200, gin.H{"data": rows, "total": total, "breaker_pending_at": user.BreakerPendingAt})
}
