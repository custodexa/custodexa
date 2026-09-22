package identity

import (
	"context"
	"log"
)

// TokenIssueProbe observes permission state; it never authorizes issuance.
type TokenIssueProbe interface{ ReconcileBeforeTokenIssue(context.Context) error }

func (s *AgentTokenService) SetIntegrityProbe(probe TokenIssueProbe) { s.integrityProbe = probe }
func (s *AgentTokenService) reconcileBeforeIssue() {
	if s.integrityProbe != nil {
		if err := s.integrityProbe.ReconcileBeforeTokenIssue(context.Background()); err != nil {
			log.Printf("[PrincipalState] token issuance reconciliation unknown (issuance unaffected): %v", err)
		}
	}
}
