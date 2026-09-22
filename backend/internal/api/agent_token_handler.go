package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (h *UserHandler) SetAgentTokenService(s *identity.AgentTokenService) { h.agentTokens = s }
func (h *UserHandler) RequireAgentTokenManager(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	actorID, ok := middleware.GetCurrentUserID(c)
	kind, kindOK := middleware.GetPrincipalKind(c)
	if err != nil || id == 0 || !ok || !kindOK || kind != model.KindHuman {
		apierror.Respond(c, http.StatusForbidden, apierror.CodePermissionDenied, nil)
		c.Abort()
		return
	}
	target, err := h.userService.GetByID(uint(id))
	if err != nil || (c.GetString("role") != model.RoleAdmin && (target.OwnerUserID == nil || *target.OwnerUserID != actorID)) {
		apierror.Respond(c, http.StatusForbidden, apierror.CodePermissionDenied, nil)
		c.Abort()
		return
	}
	c.Set("agent_token_user_id", uint(id))
	c.Next()
}
func agentTokenActor(c *gin.Context) gatewayapi.Actor {
	id, _ := middleware.GetCurrentUserID(c)
	name, _ := middleware.GetCurrentUsername(c)
	return gatewayapi.Actor{UserID: id, Username: name}
}
func (h *UserHandler) CreateAgentToken(c *gin.Context) {
	var req identity.CreateAgentTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	result, err := h.agentTokens.Create(c.GetUint("agent_token_user_id"), req, agentTokenActor(c))
	if err != nil {
		respondAgentTokenError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, result)
}
func (h *UserHandler) ListAgentTokens(c *gin.Context) {
	result, err := h.agentTokens.List(c.GetUint("agent_token_user_id"))
	if err != nil {
		respondAgentTokenError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}
func (h *UserHandler) RevokeAgentToken(c *gin.Context) {
	tokenID, err := strconv.ParseUint(c.Param("tokenId"), 10, 32)
	if err != nil || tokenID == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	var req struct {
		Note string `json:"note" binding:"max=2000"`
	}
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
	}
	if err := h.agentTokens.Revoke(c.GetUint("agent_token_user_id"), uint(tokenID), req.Note, agentTokenActor(c)); err != nil {
		respondAgentTokenError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
func respondAgentTokenError(c *gin.Context, err error) {
	if respondPrincipalError(c, err) {
		return
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotFound, nil)
		return
	}
	apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserQuery, err)
}
