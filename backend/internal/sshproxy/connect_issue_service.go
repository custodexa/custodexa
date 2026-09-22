package sshproxy

import (
	"errors"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"net/http"
)

// IssueConnectGrant authorizes an authenticated subject using the complete issue
// sequence. In-process callers supply input and the original client IP; HTTP
// passes nil to bind its body at G-I3. The context retains audit/transport facts.
// This does not expose an HTTP route or authenticate a caller. Callers must use
// the validated principal context, never client-supplied identity fields.
func (h *Handler) IssueConnectGrant(c *gin.Context, subject gatewayapi.ConnectSubject, input *ConnectTokenRequest) (gatewayapi.ConnectGrant, *connectgate.Outcome) {
	st := &issueState{input: input}
	gate := connectgate.NewSequence(
		func(s gatewayapi.ConnectSubject) []connectgate.Gate { return h.issuePreResolveGates(c, s, st) },
		func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return h.issueResolvedAccountGates(c, s, o, st)
		},
	)
	ctx := c.Request.Context()
	if out := gate.AuthorizePreResolve(ctx, subject, gatewayapi.StageIssue); out != nil {
		return gatewayapi.ConnectGrant{}, out
	}
	identity, err := h.AssetService.ResolveAccountIdentity(st.req.AssetID, st.req.AccountID)
	if err != nil {
		if errors.Is(err, asset.ErrAssetAccountNotFound) {
			return gatewayapi.ConnectGrant{}, connectgate.Deny(http.StatusNotFound, string(apierror.CodeAssetAccountNotFound), nil)
		}
		return gatewayapi.ConnectGrant{}, connectgate.DenyInternal(http.StatusInternalServerError, string(apierror.CodeInternalAssetAccountResolve), err)
	}
	st.identity = identity
	if out := gate.AuthorizeResolvedAccount(ctx, subject, st.contractObject(), gatewayapi.StageIssue); out != nil {
		return gatewayapi.ConnectGrant{}, out
	}
	agentTokenID, _ := middleware.GetAgentTokenID(c)
	principalKind, known := middleware.GetPrincipalKind(c)
	if !known {
		principalKind = gatewayapi.PrincipalKindUnknown
	}
	return gatewayapi.ConnectGrant{
		AgentTokenID:  agentTokenID,
		PrincipalKind: principalKind,
		UserID:        subject.UserID, AssetID: st.req.AssetID, AccountID: st.req.AccountID, AccessRequestID: st.req.AccessRequestID,
		AuthMethod: subject.AuthMethod, ProviderID: subject.ProviderID, AuthEpoch: subject.AuthEpoch, CredEpoch: subject.CredEpoch,
	}, nil
}
