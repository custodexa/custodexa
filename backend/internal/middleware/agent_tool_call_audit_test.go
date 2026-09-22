package middleware

import (
	"github.com/custodexa/backend/internal/model"
	"testing"
)

func TestAuditResourceClassAgentToolCalls(t *testing.T) {
	if got := extractResource("/api/v1/agent-tool-calls"); got != model.ResourceAgentToolCall {
		t.Fatal(got)
	}
	if !auditSensitiveResources[model.ResourceAgentToolCall] {
		t.Fatal("ledger query summary is not audited")
	}
}
