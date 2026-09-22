package api

import (
	"errors"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"net/http"
	"strconv"
)

func (h *AccessRequestHandler) SetAgentTaskReports(s *audit.AgentTaskReports) { h.reports = s }
func reportError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		apierror.Respond(c, 404, apierror.CodeAccessRequestNotFound, nil)
	case errors.Is(err, audit.ErrAgentReportForbidden):
		apierror.Respond(c, 403, apierror.CodeAuthAgentForbiddenRoute, nil)
	case errors.Is(err, audit.ErrAgentReportWindow):
		apierror.Respond(c, 409, apierror.CodeAccessRequestStateChanged, nil)
	case errors.Is(err, audit.ErrAgentReportBody):
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
	default:
		apierror.RespondInternal(c, 500, apierror.CodeInternalAccessRequestMineQuery, err)
	}
}
func (h *AccessRequestHandler) SubmitReport(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return
	}
	var req struct {
		Body string `json:"body" binding:"required"`
	}
	if c.ShouldBindJSON(&req) != nil {
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return
	}
	if h.reports == nil {
		reportError(c, errors.New("report service unavailable"))
		return
	}
	result, err := h.reports.Submit(c.Request.Context(), uint(id), agentTokenActor(c), req.Body)
	if err != nil {
		reportError(c, err)
		return
	}
	c.JSON(http.StatusCreated, result)
}
func (h *AccessRequestHandler) ReportVersions(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, 400, apierror.CodeBadParams, nil)
		return
	}
	if h.reports == nil {
		reportError(c, errors.New("report service unavailable"))
		return
	}
	actor := agentTokenActor(c)
	result, err := h.reports.Versions(c.Request.Context(), uint(id), actor.UserID, c.GetString("role"))
	if err != nil {
		reportError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}
