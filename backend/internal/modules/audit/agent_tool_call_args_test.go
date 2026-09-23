package audit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/stretchr/testify/require"
)

func TestToolCallArgsLegacyHMACVector(t *testing.T) {
	row := model.AgentToolCall{ID: 1, Seq: 2, UserID: 3, AgentTokenID: 4, OwnerUserID: 5, Tool: "list_assets", ArgsRedacted: `{"command":"whoami"}`, Decision: model.ToolCallPending, CreatedAt: time.Unix(1700000000, 0).UTC(), KeyVersion: 1}
	const want = "ff345b38db80f9f5efb6f8cf89799537ef21b57126dfc2b0bcf68d8be6bc37cc"
	require.Equal(t, want, computeToolCallHMAC([]byte("legacy-tool-call-vector-key"), &row))
	row.ArgsSealed = []byte("encrypted envelope")
	row.ArgsRetained = true
	retainedHMAC := computeToolCallHMAC([]byte("legacy-tool-call-vector-key"), &row)
	require.NotEqual(t, want, retainedHMAC)
	signBytes, err := toolCallSignBytes(&row)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(string(signBytes), "|retained=1"))
	row.ArgsRetained = false
	require.Equal(t, want, computeToolCallHMAC([]byte("legacy-tool-call-vector-key"), &row))
	row.ArgsRetained = true
	raw, err := json.Marshal(row)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "encrypted envelope")
	require.NotContains(t, string(raw), "args_sealed")
}

func TestToolCallArgsRetainedIntegrity(t *testing.T) {
	db := newVersionedDB(t)
	integrity, km := newVersionedIntegrity(t, db)
	const plaintext = `{"command":"echo safe"}`
	cipherA, err := km.EncryptFor(context.Background(), keyvault.RefAgentToolCallArgs, plaintext)
	require.NoError(t, err)
	cipherB, err := km.EncryptFor(context.Background(), keyvault.RefAgentToolCallArgs, plaintext)
	require.NoError(t, err)
	require.NotEqual(t, cipherA, cipherB, "a fresh AEAD nonce must change the ciphertext")
	decoded, err := km.DecryptFor(context.Background(), keyvault.RefAgentToolCallArgs, cipherB)
	require.NoError(t, err)
	require.Equal(t, plaintext, decoded)
	base := model.AgentToolCall{ID: 11, Seq: 1, UserID: 3, AgentTokenID: 4, OwnerUserID: 5,
		Tool: "list_assets", ArgsRedacted: `{}`, ArgsSealed: []byte(cipherA),
		ArgsRetained: true, Decision: model.ToolCallPending, CreatedAt: time.Unix(1700000000, 0).UTC()}
	require.NoError(t, integrity.StampToolCall(&base))
	require.True(t, integrity.VerifyToolCall(&base))

	changed := base
	changed.ArgsRetained = false
	changed.ArgsSealed = nil
	require.False(t, integrity.VerifyToolCall(&changed), "retention downgrade must invalidate the stamp")
	// Deliberately bind the retention claim, not the ciphertext: legitimate DEK
	// re-encryption changes sealed bytes without restamping the ledger row.
	changed = base
	changed.ArgsSealed = []byte(cipherB)
	require.True(t, integrity.VerifyToolCall(&changed), "valid re-encryption must preserve the stamp")
}
func TestToolCallArgsRetainedBeginAndCompletion(t *testing.T) {
	db := newVersionedDB(t)
	require.NoError(t, db.AutoMigrate(&model.AgentToolCall{}))
	integrity, _ := newVersionedIntegrity(t, db)
	ledger := NewAgentToolCallLedger(db, integrity)
	sealed := []byte("test ciphertext")
	row, err := ledger.Begin(context.Background(), AgentToolCallInput{PrincipalKind: model.KindAgent, UserID: 1, AgentTokenID: 2, OwnerUserID: 3, Tool: "list_assets", Args: map[string]any{"command": "echo [REDACTED]", "reason": "investigate", "request_id": 91, "password": "do-not-store"}, ArgsSealed: sealed, MaskedCount: 1})
	require.NoError(t, err)
	require.True(t, row.ArgsRetained)
	require.Equal(t, sealed, row.ArgsSealed)
	var saved model.AgentToolCall
	require.NoError(t, db.First(&saved, row.ID).Error)
	require.True(t, saved.ArgsRetained)
	require.Equal(t, sealed, saved.ArgsSealed)
	require.Equal(t, 1, saved.MaskedCount)
	require.Contains(t, saved.ArgsRedacted, "echo [REDACTED]")
	require.NotContains(t, saved.ArgsRedacted, "do-not-store")
	require.True(t, integrity.VerifyToolCall(&saved))
	completed, err := ledger.Complete(context.Background(), row.ID, AgentToolCallResult{Decision: model.ToolCallAllowed, RedactedOutput: "safe", MaskedCount: 2})
	require.NoError(t, err)
	require.Equal(t, 3, completed.MaskedCount)
	require.Equal(t, sealed, completed.ArgsSealed)
	require.True(t, integrity.VerifyToolCall(completed))
}
