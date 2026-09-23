package agentmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sensitivescan"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type toolLedger interface {
	Begin(context.Context, audit.AgentToolCallInput) (*model.AgentToolCall, error)
	Complete(context.Context, uint, audit.AgentToolCallResult) (*model.AgentToolCall, error)
}

func codeResult(code string) *mcp.CallToolResult {
	r := jsonResult(map[string]any{"code": code})
	r.IsError = true
	return r
}
func resultText(r *mcp.CallToolResult) string {
	if len(r.Content) == 0 {
		return ""
	}
	t, ok := r.Content[0].(*mcp.TextContent)
	if !ok {
		return ""
	}
	return t.Text
}
func (h *Handler) call(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if req.Extra == nil || req.Extra.TokenInfo == nil {
		return codeResult("AUTH_UNAUTHENTICATED"), nil
	}
	c, ok := req.Extra.TokenInfo.Extra["request"].(*gin.Context)
	if !ok {
		return codeResult("AUTH_UNAUTHENTICATED"), nil
	}
	uid, _ := middleware.GetCurrentUserID(c)
	tid, _ := middleware.GetAgentTokenID(c)
	owner := sessionOwner{MCP: req.Session.ID(), User: uid, Token: tid}
	h.watchMCP(req.Session)
	// Keep operation cancellation tied to this HTTP request, not initialization.
	return h.execute(c.Request.Context(), c, owner, req.Params.Name, req.Params.Arguments)
}
func (h *Handler) execute(ctx context.Context, c *gin.Context, owner sessionOwner, name string, raw json.RawMessage) (*mcp.CallToolResult, error) {
	task, entry, code := h.attribution(owner, name, raw)
	if code != "" {
		return codeResult(code), nil
	}
	var user model.User
	if h.ssh.DB.First(&user, owner.User).Error != nil || user.OwnerUserID == nil {
		return codeResult("AUTH_AGENT_TOKEN_INVALID"), nil
	}
	var args map[string]any
	if json.Unmarshal(raw, &args) != nil {
		return codeResult("VALIDATION_BAD_REQUEST"), nil
	}
	protocol := "ssh"
	if entry != nil {
		protocol = string(entry.connection.Session.Protocol)
	}
	if name == "close_task" {
		protocol = ""
	} // Reports span protocols.
	visible, sealed, argsMasked, err := h.prepareLedgerArgs(ctx, name, args, protocol)
	if err != nil {
		return codeResult("INTERNAL_OUTPUT_REDACTION"), nil
	}
	in := audit.AgentToolCallInput{PrincipalKind: model.KindAgent, UserID: owner.User, AgentTokenID: owner.Token, OwnerUserID: *user.OwnerUserID, Tool: name, Args: visible, ArgsSealed: sealed, MaskedCount: argsMasked}
	if task != nil {
		in.AccessRequestID = &task.ID
		if task.RequesterID != owner.User {
			in.OnBehalfOfUserID = &task.RequesterID
		}
	}
	if entry != nil {
		in.SessionID = &entry.connection.Session.ID
	}
	if h.ledger == nil {
		return codeResult("INTERNAL_TOOL_LEDGER"), nil
	}
	started := time.Now()
	row, err := h.ledger.Begin(ctx, in)
	if err != nil {
		return codeResult("INTERNAL_TOOL_LEDGER"), nil
	}
	result := h.dispatch(ctx, c, owner, name, raw, task, entry)
	delivered := false
	defer func() {
		if name == "open_session" && !delivered && !result.IsError {
			var opened struct {
				Handle string `json:"session_handle"`
			}
			_ = json.Unmarshal([]byte(resultText(result)), &opened)
			if e := h.owned(owner, opened.Handle); e != nil {
				e.connection.Transport.Close()
			}
		}
	}()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	} // Leave interrupted evidence pending.
	var payload any
	if json.Unmarshal([]byte(resultText(result)), &payload) != nil {
		payload = resultText(result)
	}
	value, count, err := redactResult(name, payload, protocol)
	if err != nil {
		return codeResult("INTERNAL_OUTPUT_REDACTION"), nil
	}
	final := jsonResult(value)
	final.IsError = result.IsError
	status, denial := "", ""
	if m, ok := value.(map[string]any); ok {
		if n, ok := m["masked_count"].(float64); ok && name == "close_task" {
			count += int(n)
		}
		status, _ = m["status"].(string)
		denial, _ = m["code"].(string)
	}
	decision := model.ToolCallAllowed
	if final.IsError || status == "blocked" {
		decision = model.ToolCallDenied
	}
	if denial == "RULE_AGENT_REQUEST_RATE" {
		decision = model.ToolCallRateLimited
	}
	if _, err = h.ledger.Complete(ctx, row.ID, audit.AgentToolCallResult{Decision: decision, DenialCode: denial, Status: status, RedactedOutput: resultText(final), DurationMS: time.Since(started).Milliseconds(), MaskedCount: count}); err != nil {
		return codeResult("INTERNAL_TOOL_LEDGER"), nil
	}
	delivered = true
	return final, nil
}

// redactValue processes decoded argument and delivery values,
// including query cells, before JSON encoding; recording and command taps precede it.
func redactValue(value any, protocol string) (any, int, error) {
	matcher := audit.GetAlertMatcher()
	if matcher == nil || matcher.BlockerHealth() != nil {
		return nil, 0, fmt.Errorf("output rules unavailable")
	}
	rules, err := sensitivescan.Compile(outputRules(matcher, protocol), scanProtocol(protocol))
	if err != nil {
		return nil, 0, err
	}
	count := 0
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			r, n := rules.Redact(x)
			count += n
			return r
		case map[string]any:
			m := map[string]any{}
			for k, v := range x {
				m[k] = walk(v)
			}
			return m
		case []any:
			a := make([]any, len(x))
			for i, v := range x {
				a[i] = walk(v)
			}
			return a
		default:
			return v
		}
	}
	return walk(value), count, nil
}
func (h *Handler) dispatch(ctx context.Context, c *gin.Context, owner sessionOwner, name string, raw json.RawMessage, task *model.AccessRequest, entry *ownedSession) *mcp.CallToolResult {
	switch name {
	case "list_assets":
		return h.listAssets(ctx, c, owner)
	case "request_access":
		return h.requestAccess(ctx, owner, raw)
	case "check_request":
		return h.checkRequest(ctx, owner, raw)
	case "close_task":
		return h.closeTask(ctx, owner, task, raw)
	case "open_session":
		var input OpenSessionInput
		if json.Unmarshal(raw, &input) != nil {
			return codeResult("VALIDATION_BAD_REQUEST")
		}
		if denied := h.visible(ctx, owner, input.AssetID); denied != nil {
			return denied
		}
		conn, out := h.OpenSession(c, input)
		if out != nil {
			return codeResult(out.Decision.Code)
		}
		handle := uuid.NewString()
		e := newOwnedSession(owner, conn)
		h.mu.Lock()
		h.sessions[handle] = e
		h.mu.Unlock()
		go e.read()
		go h.watchConnection(c.Copy(), e)
		return jsonResult(map[string]any{"session_handle": handle})
	case "close_session":
		entry.connection.Transport.Close()
		select {
		case <-entry.connection.Done:
			return jsonResult(map[string]any{"status": "closed"})
		case <-ctx.Done():
			return codeResult("RULE_SESSION_TERMINATED")
		}
	default:
		if entry == nil {
			return codeResult("NOTFOUND_SESSION")
		}
		if entry.terminated() {
			return terminatedResult()
		}
		return entry.operation(ctx, name, raw, h.now)
	}
}
func terminatedResult() *mcp.CallToolResult {
	r := jsonResult(map[string]any{"status": "terminated", "code": apierror.CodeSessionTerminated})
	r.IsError = true
	return r
}

// Task reports can cover multiple protocols; apply the union once per rule.
func outputRules(matcher *audit.AlertMatcher, protocol string) []model.AlertRule {
	if protocol != "" {
		return matcher.OutputRules(protocol, model.KindAgent)
	}
	seen := map[uint]bool{}
	out := []model.AlertRule{}
	for _, p := range []string{"ssh", "k8s", "mysql", "postgres", "mssql", "redis"} {
		for _, r := range matcher.OutputRules(p, model.KindAgent) {
			if !seen[r.ID] {
				seen[r.ID] = true
				r.Protocols = ""
				out = append(out, r)
			}
		}
	}
	return out
}
func scanProtocol(protocol string) string {
	if protocol == "" {
		return "ssh"
	}
	return protocol
}

// Only text evidence is redacted: enum values, codes, handles and numeric facts
// are protocol structure and must not be corrupted by a user-supplied pattern.
func redactResult(tool string, payload any, protocol string) (any, int, error) {
	m, ok := payload.(map[string]any)
	if !ok {
		return payload, 0, nil
	}
	count := 0
	var failure error
	field := func(obj map[string]any, key string) {
		if failure != nil {
			return
		}
		v, ok := obj[key]
		if !ok {
			return
		}
		masked, n, err := redactValue(v, protocol)
		if err != nil {
			failure = err
			return
		}
		obj[key] = masked
		count += n
	}
	switch tool {
	case "run_command", "send_keys":
		field(m, "output")
	case "read_screen":
		field(m, "lines")
	case "query":
		results := []any{m}
		if list, ok := m["results"].([]any); ok {
			results = list
		}
		for _, value := range results {
			result, ok := value.(map[string]any)
			if !ok {
				continue
			}
			if sets, ok := result["sets"].([]any); ok {
				for _, set := range sets {
					if set, ok := set.(map[string]any); ok {
						field(set, "rows")
						if cols, ok := set["columns"].([]any); ok {
							for _, col := range cols {
								if col, ok := col.(map[string]any); ok {
									field(col, "name")
								}
							}
						}
					}
				}
			}
			if dberr, ok := result["db_error"].(map[string]any); ok {
				for _, key := range []string{"message", "detail", "hint"} {
					field(dberr, key)
				}
			}
		}
		// close_task has already applied all-protocol rules before its report transaction.
	}
	return m, count, failure
}
