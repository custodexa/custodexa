package agentmcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/require"
)

func TestPrepareLedgerArgsRetainsToolEvidence(t *testing.T) {
	f := newFixture(t)
	for _, tool := range []string{"list_assets", "request_access", "check_request", "open_session", "run_command", "send_keys", "read_screen", "query", "close_session", "close_task"} {
		t.Run(tool, func(t *testing.T) {
			args := map[string]any{"command": "ssh 10.0.0.9", "sql": "select 1", "keys": "ctrl-c", "report": "denied by target", "request_id": float64(91), "asset_id": float64(26), "account_id": float64(1), "items": []any{map[string]any{"asset_id": float64(26), "accounts": []any{"ops"}}}, "reason": "investigate", "lines": float64(30), "timeout_seconds": float64(10), "idempotency_key": "retry-1"}
			visible, sealed, count, err := f.h.prepareLedgerArgs(context.Background(), tool, args, "ssh")
			require.NoError(t, err)
			require.Equal(t, args, visible)
			require.Nil(t, sealed)
			require.Zero(t, count)
		})
	}
}

func TestPrepareLedgerArgsHandleFingerprint(t *testing.T) {
	f := newFixture(t)
	// SHA-256("abc") is a fixed interoperability vector, not computed by the implementation.
	for _, tool := range []string{"run_command", "send_keys", "read_screen", "query", "close_session"} {
		t.Run(tool, func(t *testing.T) {
			args := map[string]any{"session_handle": "abc", "command": "whoami"}
			visible, sealed, count, err := f.h.prepareLedgerArgs(context.Background(), tool, args, "ssh")
			require.NoError(t, err)
			require.Equal(t, "fp:ba7816bf8f01", visible["session_handle"])
			require.Equal(t, "abc", args["session_handle"])
			require.Nil(t, sealed)
			require.Zero(t, count)
		})
	}
}

func TestPrepareLedgerArgsSensitiveSealed(t *testing.T) {
	f := newFixture(t)
	addMaskRule(t, f)
	args := map[string]any{"session_handle": "abc", "command": "echo 4111111111111111", "password": "DO_NOT_STORE", "items": []any{map[string]any{"connect_token": "DO_NOT_STORE", "reason": "review 4111111111111111"}}}
	visible, sealed, count, err := f.h.prepareLedgerArgs(context.Background(), "run_command", args, "ssh")
	require.NoError(t, err)
	require.Equal(t, 2, count)
	raw, err := json.Marshal(visible)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "4111111111111111")
	require.NotContains(t, string(raw), "DO_NOT_STORE")
	require.NotContains(t, string(sealed), "4111111111111111")
	require.Contains(t, string(sealed), "enc:a1:")
	plain, err := f.h.ledgerCodec.DecryptFor(context.Background(), keyvault.RefAgentToolCallArgs, string(sealed))
	require.NoError(t, err)
	require.Contains(t, plain, "echo 4111111111111111")
	require.Contains(t, plain, `"session_handle":"fp:ba7816bf8f01"`)
	require.NotContains(t, plain, "DO_NOT_STORE")
	_, err = f.h.ledgerCodec.DecryptFor(context.Background(), keyvault.RefClipboardContent, string(sealed))
	require.Error(t, err)
	sealed[len(sealed)-5] ^= 1
	_, err = f.h.ledgerCodec.DecryptFor(context.Background(), keyvault.RefAgentToolCallArgs, string(sealed))
	require.Error(t, err)
	require.Equal(t, "echo 4111111111111111", args["command"])
}

type brokenLedgerCodec struct {
	crypto.ColumnCodec
	empty bool
}

func (c brokenLedgerCodec) EncryptFor(context.Context, crypto.CipherRef, string) (string, error) {
	if c.empty {
		return "", nil
	}
	return "", errors.New("codec unavailable")
}
func TestPrepareLedgerArgsCodecFailClosed(t *testing.T) {
	for _, tc := range []string{"missing", "failure", "empty"} {
		t.Run(tc, func(t *testing.T) {
			f := newFixture(t)
			addMaskRule(t, f)
			switch tc {
			case "missing":
				f.h.ledgerCodec = nil
			case "failure":
				f.h.ledgerCodec = brokenLedgerCodec{}
			case "empty":
				f.h.ledgerCodec = brokenLedgerCodec{empty: true}
			}
			visible, sealed, _, err := f.h.prepareLedgerArgs(context.Background(), "close_task", map[string]any{"report": "4111111111111111"}, "")
			require.Error(t, err)
			require.Nil(t, visible)
			require.Nil(t, sealed)
			r := f.invoke(t, "close_task", map[string]any{"request_id": f.task, "report": "4111111111111111"})
			require.True(t, r.IsError)
			require.Equal(t, "INTERNAL_OUTPUT_REDACTION", object(t, r)["code"])
			var rows int64
			require.NoError(t, f.db.Model(&model.AgentToolCall{}).Count(&rows).Error)
			require.Zero(t, rows)
			require.NoError(t, f.db.Model(&model.AgentTaskReport{}).Count(&rows).Error)
			require.Zero(t, rows)
			var task model.AccessRequest
			require.NoError(t, f.db.First(&task, f.task).Error)
			require.Nil(t, task.ClosedAt)
		})
	}
}
