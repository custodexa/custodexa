package agentmcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
)

// WithLedgerCodec is called by the post-unseal composition root before serving.
// The codec is the existing data DEK/KEK service, never a separate ledger key.
func (h *Handler) WithLedgerCodec(codec crypto.ColumnCodec) *Handler {
	h.ledgerCodec = codec
	return h
}

func ledgerHandleFingerprint(handle string) string {
	sum := sha256.Sum256([]byte(handle))
	return "fp:" + hex.EncodeToString(sum[:])[:12]
}

// prepareLedgerArgs preserves evidence while removing credentials before either
// the visible or encrypted representation is produced. It never mutates args.
func (h *Handler) prepareLedgerArgs(ctx context.Context, tool string, args map[string]any, protocol string) (visible map[string]any, sealed []byte, maskedCount int, err error) {
	retained := audit.StripLedgerCredentials(args)
	switch tool {
	case "run_command", "send_keys", "read_screen", "query", "close_session":
		if handle, ok := retained["session_handle"].(string); ok {
			retained["session_handle"] = ledgerHandleFingerprint(handle)
		}
	}
	value, count, err := redactValue(retained, protocol)
	if err != nil {
		return nil, nil, 0, err
	}
	visible = value.(map[string]any)
	if count == 0 {
		return visible, nil, 0, nil
	}
	if h.ledgerCodec == nil {
		return nil, nil, 0, errors.New("ledger argument codec unavailable")
	}
	plain, err := json.Marshal(retained)
	if err != nil {
		return nil, nil, 0, err
	}
	enc, err := h.ledgerCodec.EncryptFor(ctx, keyvault.RefAgentToolCallArgs, string(plain))
	if err != nil || enc == "" {
		return nil, nil, 0, errors.New("ledger argument encryption failed")
	}
	return visible, []byte(enc), count, nil
}
