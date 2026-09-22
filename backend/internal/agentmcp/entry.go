package agentmcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/gin-gonic/gin"
)

type arguments struct {
	RequestID uint   `json:"request_id"`
	AssetID   uint   `json:"asset_id"`
	Handle    string `json:"session_handle"`
}

func executor(r *model.AccessRequest) uint {
	if r.ExecutorUserID != nil {
		return *r.ExecutorUserID
	}
	return r.RequesterID
}
func (h *Handler) owned(owner sessionOwner, handle string) *ownedSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.sessions[handle]
	if e == nil || e.owner != owner {
		return nil
	}
	return e
}
func (h *Handler) attribution(owner sessionOwner, tool string, raw json.RawMessage) (*model.AccessRequest, *ownedSession, string) {
	switch tool {
	case "list_assets", "request_access", "check_request":
		return nil, nil, ""
	}
	var a arguments
	if json.Unmarshal(raw, &a) != nil {
		return nil, nil, string(apierror.CodeBadRequestFormat)
	}
	var entry *ownedSession
	switch tool {
	case "open_session", "close_task":
	default:
		entry = h.owned(owner, a.Handle)
		if entry == nil {
			return nil, nil, "NOTFOUND_SESSION"
		}
		a.RequestID = *entry.connection.Session.AccessRequestID
	}
	if a.RequestID == 0 {
		return nil, nil, string(apierror.CodeAuthRequestItemMismatch)
	}
	var task model.AccessRequest
	if h.ssh.DB.First(&task, a.RequestID).Error != nil || executor(&task) != owner.User {
		return nil, nil, "NOTFOUND_ACCESS_REQUEST"
	}
	return &task, entry, ""
}

// preflight runs on the original Gin context, so the existing HTTP audit
// middleware receives the metadata even when SDK schema validation rejects.
func (h *Handler) preflight(c *gin.Context) bool {
	if c.Request.Method != http.MethodPost {
		return true
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 2<<20))
	if err != nil {
		apierror.Respond(c, 400, apierror.CodeBadRequestFormat, nil)
		return false
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if json.Unmarshal(raw, &req) != nil || req.Method != "tools/call" {
		return true
	}
	uid, _ := middleware.GetCurrentUserID(c)
	tid, _ := middleware.GetAgentTokenID(c)
	name := req.Params.Name
	if _, known := descriptions[name]; !known {
		name = "unknown"
	}
	details := map[string]string{"tool": name, "occurred_at": time.Now().UTC().Format(time.RFC3339Nano)}
	c.Set("audit_details", details)
	if name == "unknown" {
		return true
	}
	_, _, code := h.attribution(sessionOwner{MCP: c.GetHeader("Mcp-Session-Id"), User: uid, Token: tid}, name, req.Params.Arguments)
	if code == "" {
		return true
	}
	details["denial_code"] = code
	details["entry_rejected"] = "true"
	if name == "open_session" {
		var a arguments
		_ = json.Unmarshal(req.Params.Arguments, &a)
		h.ssh.AuditMCPDenied(c, proxy.ConnectDenial{UserID: uid, AssetID: a.AssetID, AccessRequestID: a.RequestID, HTTPStatus: 400, Reason: code})
	}
	// A tool error is an MCP result; the HTTP audit details identify the rejection.
	c.JSON(http.StatusOK, gin.H{"jsonrpc": "2.0", "id": req.ID, "result": codeResult(code)})
	return false
}
