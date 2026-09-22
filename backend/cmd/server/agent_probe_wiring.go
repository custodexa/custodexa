package main

import (
	"context"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

func wireAgentProbeBreaker(db *gorm.DB, sink port.TxSink, alerts gatewayapi.AlertSink, authorization *authz.AssetAuthorizationService, tokens *identity.AgentTokenService, grants *proxy.ConnectTokenManager, limits func() (int, int), notify audit.OwnerEventWriter) {
	breaker := audit.NewProbeBreaker(db, sink, alerts, audit.ProbeBreakerDependencies{
		LockPrincipal: identity.LockProbePrincipal, Classify: authz.ClassifyAgentProbe,
		Trip:   tokens.TripProbeBreakerInTx,
		Finish: func(id uint) { grants.InvalidateByAgentToken(id); tokens.FinishProbeBreaker(id) },
		Limits: limits, Notify: notify,
	})
	authorization.SetAgentProbeRecorder(func(ctx context.Context, u, t, a uint, endpoint string) error {
		_, err := breaker.RecordDenied(ctx, u, t, a, endpoint)
		return err
	})
}

func agentProbeLimits(p *policy.SecurityPolicyService) func() (int, int) {
	return func() (int, int) {
		return p.GetInt(policy.PolicyAgentProbeTripCount), p.GetInt(policy.PolicyAgentProbeWindowSeconds)
	}
}
