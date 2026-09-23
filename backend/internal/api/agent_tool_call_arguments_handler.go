package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
)

type ToolCallArgumentsReader interface {
	ReadArguments(context.Context, uint, audit.ToolCallArgumentsOperator) (*audit.ToolCallArgumentsView, error)
}

func (h *AuditIntegrityHandler) SetToolCallArguments(reader ToolCallArgumentsReader, reveals ClipboardSensitiveRevealReporter) {
	h.arguments = reader
	h.reveals = reveals
}

func (h *AuditIntegrityHandler) ToolCallArguments(c *gin.Context) {
	reason := strings.TrimSpace(c.Query("reason"))
	if reason == "" || len(c.Query("reason")) > 1000 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeToolCallArgumentsNotFound, nil)
		return
	}
	if h.arguments == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalToolCallArguments, errors.New("arguments reader unavailable"))
		return
	}
	op := audit.ToolCallArgumentsOperator{
		Actor: gatewayapi.Actor{UserID: c.GetUint("userID"), Username: c.GetString("username")}, Reason: reason,
		Request: gatewayapi.RequestMeta{Method: "GET", Path: c.Request.URL.Path, ClientIP: sourceip.Of(c), RequestID: c.GetString("request_id")},
	}
	view, err := h.arguments.ReadArguments(c.Request.Context(), uint(id), op)
	if err != nil {
		if errors.Is(err, audit.ErrToolCallArgumentsNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeToolCallArgumentsNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalToolCallArguments, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	if h.reveals != nil {
		sid := uint(0)
		if view.SessionID != nil {
			sid = *view.SessionID
		}
		h.reveals.Report(c.Request.Context(), audit.SensitiveRevealInput{Actor: op.Actor, SourceType: "agent_tool_call", SourceID: view.ID, SessionID: sid, AssetID: view.AssetID, AccessRequestID: view.AccessRequestID, Reason: reason, RequestID: op.Request.RequestID})
	}
	c.JSON(http.StatusOK, gin.H{"data": view})
}
