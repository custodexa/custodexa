package k8sproxy

import (
	"errors"
	"strings"
	"testing"
)

// TestClassifyErrUnknownNoLeak pins the error-code security fix:
// the "unknown" classification must NOT concatenate the raw error into the
// user-facing Message (which is emitted to clients by asset_handler/sshproxy).
func TestClassifyErrUnknownNoLeak(t *testing.T) {
	raw := "dial tcp 10.9.9.9:6443: secret-internal-host detail"
	ke := classifyErr("prod-ns", errors.New(raw))

	if ke.Kind != "unknown" {
		t.Fatalf("Kind = %q, want unknown", ke.Kind)
	}
	if strings.Contains(ke.Message, "secret-internal-host") || strings.Contains(ke.Message, "10.9.9.9") {
		t.Errorf("unknown Message leaks raw error: %q", ke.Message)
	}
	if strings.TrimSpace(ke.Message) == "" {
		t.Error("unknown Message must be a non-empty generalized string")
	}
}
