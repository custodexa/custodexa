package sshproxy

import (
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
)

func (h *Handler) establishRequest(c *gin.Context, token string, console bool) establishRequest {
	via := proxy.ViaSSH
	if console {
		via = proxy.ViaDBConsole
	}
	return establishRequest{
		ConsoleAudit: func(uid, aid uint) *consoleAuditContext { return h.consoleAuditContext(c, uid, aid) },
		ConsolePreResolve: func(s gatewayapi.ConnectSubject, st *redeemState) []connectgate.Gate {
			return h.consolePreResolveGates(c, s, st)
		},
		ConsoleResolved: func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject, st *redeemState, auditCtx *consoleAuditContext, release *func()) []connectgate.Gate {
			return h.consoleResolvedAccountGates(c, s, o, st, auditCtx, release)
		},
		Context: c.Request.Context(), Token: token, ClientIP: sourceip.Of(c), Query: c.Query,
		PreResolve: func(s gatewayapi.ConnectSubject, st *redeemState) []connectgate.Gate {
			return h.redeemPreResolveGates(c, s, st)
		},
		Resolved: func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject, st *redeemState) []connectgate.Gate {
			return h.redeemResolvedAccountGates(c, s, o, st)
		},
		Deny: func(ev proxy.ConnectDenial) { h.auditRedeemDenied(c, ev, via) },
		DenyOutcome: func(out *connectgate.Outcome, st *redeemState) {
			h.auditRedeemDenied(c, proxy.ConnectDenial{UserID: st.grant.UserID, AssetID: st.grant.AssetID, Reason: out.Decision.Code, HTTPStatus: out.Status, Cause: st.sourceDenyCause, RequestItemDimension: connectgate.RequestItemDimension(out), AccessRequestID: st.grant.AccessRequestID}, via)
		},
	}
}
func (h *Handler) writeEstablishFailure(c *gin.Context, f *EstablishFailure) {
	if f.Silent {
		return
	}
	if f.Dial {
		writeDialError(c, apierror.ErrCode(f.Outcome.Decision.Code), f.Message)
		return
	}
	h.writeOutcome(c, f.Outcome)
}
