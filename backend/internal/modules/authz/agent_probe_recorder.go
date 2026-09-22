package authz

import (
	"context"
	"errors"
)

// SetAgentProbeRecorder wires the audit-owned denied-reference service at root.
func (s *AssetAuthorizationService) SetAgentProbeRecorder(record func(context.Context, uint, uint, uint, string) error) {
	s.agentProbeRecorder = record
}
func (s *AssetAuthorizationService) RecordDeniedAgentProbe(ctx context.Context, userID, tokenID, assetID uint, endpoint string) error {
	if s.agentProbeRecorder == nil {
		return errors.New("agent probe recorder not configured")
	}
	return s.agentProbeRecorder(ctx, userID, tokenID, assetID, endpoint)
}
