package agentmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type sessionOwner struct {
	MCP         string
	User, Token uint
}

type Handler struct {
	ssh         *sshproxy.Handler
	http        http.Handler
	mu          sync.Mutex
	sessions    map[string]*ownedSession
	ledger      toolLedger
	ledgerCodec crypto.ColumnCodec
	requests    *authz.AccessRequestService
	reports     *audit.AgentTaskReports
	watchers    map[string]bool
	now         func() time.Time
}

func NewHandler(ssh *sshproxy.Handler, requests ...*authz.AccessRequestService) *Handler {
	h := newHandler(ssh, 5*time.Minute)
	if len(requests) > 0 {
		h.requests = requests[0]
	}
	return h
}
func newHandler(ssh *sshproxy.Handler, idleTimeout time.Duration) *Handler {
	h := &Handler{ssh: ssh, sessions: make(map[string]*ownedSession), watchers: make(map[string]bool), now: time.Now}
	if ssh != nil && ssh.DB != nil {
		h.ledger = audit.NewAgentToolCallLedger(ssh.DB, audit.GetAuditIntegrity())
		h.requests = authz.NewAccessRequestService(ssh.DB, policy.NewSecurityPolicyService(ssh.DB), ssh.AccessPolicy, ssh.AuditService, nil)
		h.requests.SetAccountPresenceSource(asset.RequestAccountPresent)
		h.requests.SetSessionService(ssh.SessionService)
		h.reports = audit.NewAgentTaskReports(ssh.DB, audit.NewTxSink(), authz.ReadAgentTaskForReport, identity.ReadAgentAuditPrincipal, audit.NotifyAgentOwner)
	}
	server := NewServer(h.call)
	h.http = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{JSONResponse: true, SessionTimeout: idleTimeout})
	return h
}

// Handle runs after AuthMiddleware; the explicit credential-form check excludes
// human JWTs and cookies even if another authentication path ever admits them.
func (h *Handler) Handle(c *gin.Context) {
	kind, known := middleware.GetPrincipalKind(c)
	_, token := middleware.GetAgentTokenID(c)
	fields := strings.Fields(c.GetHeader("Authorization"))
	if !known || kind != model.KindAgent || !token || len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || !strings.HasPrefix(fields[1], "cxa_") {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	if h == nil || h.http == nil {
		apierror.Respond(c, http.StatusServiceUnavailable, apierror.CodeInternalConnectTokenIssue, nil)
		return
	}
	if !h.preflight(c) {
		return
	}
	// SDK request dispatch may outlive Gin's handler stack. Copy keys and request
	// facts; do not retain a pooled context or allow a tool to write HTTP responses.
	copy := c.Copy()
	uid, _ := middleware.GetCurrentUserID(c)
	tid, _ := middleware.GetAgentTokenID(c)
	// SDK session contexts originate at initialization. RequestExtra is the SDK's
	// per-HTTP-request carrier; using the session context here would reuse the
	// initializer's identity/address and an already-cancelled request context.
	wrapped := mcpauth.RequireBearerToken(func(context.Context, string, *http.Request) (*mcpauth.TokenInfo, error) {
		return &mcpauth.TokenInfo{UserID: fmt.Sprintf("%d/%d", uid, tid), Extra: map[string]any{"request": copy}}, nil
	}, &mcpauth.RequireBearerTokenOptions{AllowMissingExpiration: true})(h.http)
	// Expiry is checked by the existing AuthMiddleware on every request. This
	// adapter only supplies SDK metadata; it does not introduce an OAuth flow.
	wrapped.ServeHTTP(c.Writer, c.Request)
}

type OpenSessionInput struct {
	AssetID      uint   `json:"asset_id"`
	AccountID    uint   `json:"account_id"`
	RequestID    uint   `json:"request_id"`
	K8sPod       string `json:"k8s_pod"`
	K8sContainer string `json:"k8s_container"`
	K8sMode      string `json:"k8s_mode"`
}

// OpenSession uses the same issuer and one-use token manager as the human path.
// It never accepts principal or source-address declarations from tool arguments.
func (h *Handler) OpenSession(c *gin.Context, input OpenSessionInput) (*sshproxy.InProcessSession, *connectgate.Outcome) {
	uid, _ := middleware.GetCurrentUserID(c)
	deny := func(out *connectgate.Outcome) (*sshproxy.InProcessSession, *connectgate.Outcome) {
		h.ssh.AuditMCPDenied(c, proxy.ConnectDenial{UserID: uid, AssetID: input.AssetID, AccessRequestID: input.RequestID, HTTPStatus: out.Status, Reason: out.Decision.Code, RequestItemDimension: connectgate.RequestItemDimension(out)})
		return nil, out
	}
	kind, known := middleware.GetPrincipalKind(c)
	tid, token := middleware.GetAgentTokenID(c)
	if !known || kind != model.KindAgent || !token || tid == 0 {
		return deny(connectgate.Deny(401, string(apierror.CodeUnauthenticated), nil))
	}
	if input.RequestID == 0 {
		return deny(connectgate.Deny(403, string(apierror.CodeAuthRequestItemMismatch), map[string]any{"dimension": "request"}))
	}
	auth := middleware.GetAuthContext(c)
	subject := gatewayapi.ConnectSubject{UserID: uid, AuthMethod: auth.EffectiveMethod(), ProviderID: auth.ProviderID, AuthEpoch: auth.AuthEpoch, CredEpoch: auth.CredEpoch, ClientIP: sourceip.Of(c)}
	grant, out := h.ssh.IssueConnectGrant(c, subject, &sshproxy.ConnectTokenRequest{AssetID: input.AssetID, AccountID: input.AccountID, AccessRequestID: input.RequestID})
	if out != nil {
		return deny(out)
	}
	ticket, err := h.ssh.ConnectTokens.IssueConnectToken(c.Request.Context(), grant)
	if err != nil {
		if errors.Is(err, proxy.ErrConnectTokenCapacity) {
			return deny(connectgate.Deny(503, string(apierror.CodeConnectTokenCapacity), nil))
		}
		return deny(connectgate.DenyInternal(500, string(apierror.CodeInternalConnectTokenIssue), err))
	}
	// Bind only tool parameters relevant to terminal setup. The request's peer
	// address and authentication keys remain those observed by the HTTP boundary.
	request := c.Copy()
	request.Request = c.Request.Clone(c.Request.Context())
	urlCopy := *request.Request.URL
	request.Request.URL = &urlCopy
	q := urlCopy.Query()
	q.Set("cols", "80")
	q.Set("rows", "24")
	q.Set("k8s_pod", input.K8sPod)
	q.Set("k8s_container", input.K8sContainer)
	q.Set("k8s_mode", input.K8sMode)
	urlCopy.RawQuery = q.Encode()
	asset, err := h.ssh.AssetService.GetByID(input.AssetID)
	console := err == nil && dbconsole.Protocol(asset.Protocol).Supported()
	connection, failure := h.ssh.OpenInProcess(request, ticket, console)
	if failure != nil {
		if failure.Outcome != nil {
			return nil, failure.Outcome
		}
		return nil, connectgate.Deny(http.StatusServiceUnavailable, string(apierror.CodeAssetCredentialUnavailable), nil)
	}
	return connection, nil
}
func jsonResult(value any) *mcp.CallToolResult {
	raw, _ := json.Marshal(value)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}}
}
