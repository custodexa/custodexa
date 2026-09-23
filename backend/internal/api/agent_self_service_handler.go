package api

import (
	"errors"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
)

type agentSelfService interface {
	CreateMyAgent(gatewayapi.Actor, identity.CreateMyAgentRequest) (*model.User, error)
	ListMyAgents(uint) ([]model.User, error)
}

func (h *UserHandler) CreateMyAgent(c *gin.Context) {
	svc, ok := h.userService.(agentSelfService)
	if !ok {
		apierror.Respond(c, 500, apierror.CodeInternalUserCreate, nil)
		return
	}
	var req identity.CreateMyAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return
	}
	user, err := svc.CreateMyAgent(agentTokenActor(c), req)
	if err != nil {
		if respondPrincipalError(c, err) {
			return
		}
		if errors.Is(err, identity.ErrUsernameExists) {
			apierror.Respond(c, 400, apierror.CodeUsernameExists, nil)
			return
		}
		apierror.RespondInternal(c, 500, apierror.CodeInternalUserCreate, err)
		return
	}
	c.JSON(201, gin.H{"data": user})
}

func (h *UserHandler) ListMyAgents(c *gin.Context) {
	svc, ok := h.userService.(agentSelfService)
	if !ok {
		apierror.Respond(c, 500, apierror.CodeInternalUserQuery, nil)
		return
	}
	var status *identity.AgentSelfCreateStatus
	if reader, ok := h.userService.(interface {
		MyAgentCreationStatus(uint) (*identity.AgentSelfCreateStatus, error)
	}); ok {
		var err error
		status, err = reader.MyAgentCreationStatus(agentTokenActor(c).UserID)
		if err != nil {
			if respondPrincipalError(c, err) {
				return
			}
			apierror.RespondInternal(c, 500, apierror.CodeInternalUserQuery, err)
			return
		}
	}
	users, err := svc.ListMyAgents(agentTokenActor(c).UserID)
	if err != nil {
		if respondPrincipalError(c, err) {
			return
		}
		apierror.RespondInternal(c, 500, apierror.CodeInternalUserQuery, err)
		return
	}
	// Listing is open to any active human owner; only creation follows the policy key,
	// which self_create_enabled reports so the caller knows whether to offer it.
	enabled := false
	if status != nil {
		enabled = status.Enabled
	}
	c.JSON(200, gin.H{"data": users, "total": len(users), "self_create": status, "self_create_enabled": enabled})
}
