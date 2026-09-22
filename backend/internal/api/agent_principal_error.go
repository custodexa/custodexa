package api

import (
	"errors"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

func respondPrincipalError(c *gin.Context, err error) bool {
	var principal *identity.PrincipalError
	if !errors.As(err, &principal) {
		return false
	}
	response := apierror.ErrorResponse{Code: principal.Code}
	if len(principal.AgentIDs) > 0 {
		response.Meta = map[string]any{"agent_ids": principal.AgentIDs}
	}
	apierror.Write(c, principal.Status, response)
	return true
}

func principalErrorStatus(err error, fallback int) int {
	var principal *identity.PrincipalError
	if errors.As(err, &principal) {
		return principal.Status
	}
	return fallback
}
