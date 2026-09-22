package sshproxy

import (
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/gin-gonic/gin"
)

// InProcessSession owns both the client endpoint and the settlement notification.
// Closing the endpoint follows the same bridge/console cleanup as closing a WS.
type InProcessSession struct {
	Transport *InProcessTransport
	Session   *model.Session
	Done      <-chan struct{}
}

// OpenInProcess redeems the ordinary one-use ticket using the current MCP HTTP
// request facts. There is no loopback request and no address stored in the ticket.
func (h *Handler) OpenInProcess(c *gin.Context, token string, console bool) (*InProcessSession, *EstablishFailure) {
	req := h.establishRequest(c, token, console)
	audited := false
	var grant proxy.ConnectGrant
	req.Redeemed = func(g proxy.ConnectGrant) { grant = g }
	req.Deny = func(ev proxy.ConnectDenial) { audited = true; h.AuditMCPDenied(c, ev) }
	req.DenyOutcome = func(out *connectgate.Outcome, st *redeemState) {
		req.Deny(proxy.ConnectDenial{UserID: st.grant.UserID, AssetID: st.grant.AssetID, Reason: out.Decision.Code, HTTPStatus: out.Status, Cause: st.sourceDenyCause, RequestItemDimension: connectgate.RequestItemDimension(out), AccessRequestID: st.grant.AccessRequestID})
	}
	// Credential-resolution failure historically has no WS denial event. MCP's
	// contract requires one; record it here without changing either human adapter.
	recordFailure := func(f *EstablishFailure) {
		if !audited && f != nil && f.Outcome != nil {
			h.AuditMCPDenied(c, proxy.ConnectDenial{UserID: grant.UserID, AssetID: grant.AssetID, AccessRequestID: grant.AccessRequestID, Reason: f.Outcome.Decision.Code, HTTPStatus: f.Outcome.Status})
		}
	}
	done := make(chan struct{})
	if console {
		est, f := h.establishConsole(req)
		if f != nil {
			recordFailure(f)
			return nil, f
		}
		h.observeSourceIP(c, est.Session, est.grant.UserID, est.grant.AssetID)
		server, client := NewInProcessTransportPair()
		cs := h.newConsoleSession(c.Copy(), server, est.Session, est.dialect, est.protocol, est.grant, est.auditCtx)
		go func() { defer close(done); h.runConsoleSession(cs, est.release) }()
		return &InProcessSession{Transport: client, Session: est.Session, Done: done}, nil
	}
	est, f := h.establishTerminal(req)
	if f != nil {
		recordFailure(f)
		return nil, f
	}
	h.observeSourceIP(c, est.Session, est.grant.UserID, est.grant.AssetID)
	server, client := NewInProcessTransportPair()
	go func() { defer close(done); h.runTerminal(est, server) }()
	return &InProcessSession{Transport: client, Session: est.Session, Done: done}, nil
}

// AuditMCPDenied uses the existing denial writer (AP-69), with an explicit entry
// marker. It is used for issue-stage denials too: MCP has no public ticket route.
func (h *Handler) AuditMCPDenied(c *gin.Context, ev proxy.ConnectDenial) {
	ev.Via = proxy.ViaMCP
	proxy.AuditConnectDenied(h.AuditService, c, ev)
}
