package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/custodexa/backend/internal/model"
)

// Payload version 3 preserves version 2 ordered fields and appends the independent ledger interval.
type checkpointSignPayloadV3 struct {
	checkpointSignPayloadV2
	ToolCallIDFrom   uint   `json:"tool_call_id_from"`
	ToolCallIDTo     uint   `json:"tool_call_id_to"`
	ToolCallRowCount int64  `json:"tool_call_row_count"`
	ToolCallAggHash  string `json:"tool_call_agg_hash"`
}

func checkpointSignBytesV3(cp *model.AuditCheckpoint) ([]byte, error) {
	if cp.ToolCallIDFrom == nil || cp.ToolCallIDTo == nil || cp.ToolCallRowCount == nil || cp.ToolCallAggHash == nil {
		return nil, fmt.Errorf("%w: v3 requires all four ledger fields", ErrCheckpointPayloadInvalid)
	}
	if *cp.ToolCallIDFrom == 0 || *cp.ToolCallRowCount < 0 || (*cp.ToolCallIDFrom > *cp.ToolCallIDTo && *cp.ToolCallIDFrom != *cp.ToolCallIDTo+1) {
		return nil, fmt.Errorf("%w: invalid ledger interval", ErrCheckpointPayloadInvalid)
	}
	raw, err := checkpointSignBytesV2(cp)
	if err != nil {
		return nil, err
	}
	var old checkpointSignPayloadV2
	if err := json.Unmarshal(raw, &old); err != nil {
		return nil, err
	}
	return json.Marshal(checkpointSignPayloadV3{old, *cp.ToolCallIDFrom, *cp.ToolCallIDTo, *cp.ToolCallRowCount, *cp.ToolCallAggHash})
}

type toolCallAggWriter struct {
	h   hash.Hash
	n   int64
	err error
}

func newToolCallAggWriter() *toolCallAggWriter { return &toolCallAggWriter{h: sha256.New()} }

// Only the immutable send-time projection enters the checkpoint aggregate.
// Each ordered JSON row is framed by an unsigned 64-bit big-endian byte length.
type toolCallSendPayload struct {
	ID               uint   `json:"id"`
	Seq              uint   `json:"seq"`
	UserID           uint   `json:"user_id"`
	AgentTokenID     uint   `json:"agent_token_id"`
	AccessRequestID  *uint  `json:"access_request_id"`
	SessionID        *uint  `json:"session_id"`
	OnBehalfOfUserID *uint  `json:"on_behalf_of_user_id"`
	OwnerUserID      uint   `json:"owner_user_id"`
	Tool             string `json:"tool"`
	ArgsSHA256       string `json:"args_sha256"`
	CreatedAtUs      int64  `json:"created_at_us"`
	KeyVersion       int    `json:"key_version"`
}

func (w *toolCallAggWriter) Add(e model.AgentToolCall) {
	args, err := canonicalToolCallArgs(e.ArgsRedacted)
	if err != nil {
		w.err = err
		return
	}
	digest := sha256.Sum256(args)
	body, err := json.Marshal(toolCallSendPayload{e.ID, e.Seq, e.UserID, e.AgentTokenID, e.AccessRequestID, e.SessionID, e.OnBehalfOfUserID, e.OwnerUserID, e.Tool, hex.EncodeToString(digest[:]), e.CreatedAt.UnixMicro(), e.KeyVersion})
	if err != nil {
		w.err = err
		return
	}
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], uint64(len(body)))
	w.h.Write(prefix[:])
	w.h.Write(body)
	w.n++
}

func (w *toolCallAggWriter) Sum() (string, int64, error) {
	if w.err != nil {
		return "", 0, w.err
	}
	return hex.EncodeToString(w.h.Sum(nil)), w.n, nil
}
