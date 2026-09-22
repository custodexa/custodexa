package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// A separate domain prevents a ledger row from being replayed as an audit_log stamp.
type toolCallIntegrityPayload struct {
	ID               uint            `json:"id"`
	Kind             string          `json:"kind"`
	Seq              uint            `json:"seq"`
	UserID           uint            `json:"user_id"`
	AgentTokenID     uint            `json:"agent_token_id"`
	AccessRequestID  *uint           `json:"access_request_id"`
	SessionID        *uint           `json:"session_id"`
	OnBehalfOfUserID *uint           `json:"on_behalf_of_user_id"`
	OwnerUserID      uint            `json:"owner_user_id"`
	Tool             string          `json:"tool"`
	ArgsRedacted     json.RawMessage `json:"args_redacted"`
	Decision         string          `json:"decision"`
	DenialCode       string          `json:"denial_code"`
	ResultStatus     string          `json:"result_status"`
	ResultDigest     string          `json:"result_digest"`
	ResultExcerpt    string          `json:"result_excerpt"`
	MaskedCount      int             `json:"masked_count"`
	DurationMS       int64           `json:"duration_ms"`
	CreatedAtUs      int64           `json:"created_at_us"`
	KeyVersion       int             `json:"key_version"`
}

func toolCallSignBytes(a *model.AgentToolCall) ([]byte, error) {
	canonical, err := canonicalToolCallArgs(a.ArgsRedacted)
	if err != nil {
		return nil, err
	}
	return json.Marshal(toolCallIntegrityPayload{
		ID: a.ID, Kind: "agent_tool_call_v1", Seq: a.Seq, UserID: a.UserID, AgentTokenID: a.AgentTokenID,
		AccessRequestID: a.AccessRequestID, SessionID: a.SessionID, OnBehalfOfUserID: a.OnBehalfOfUserID,
		OwnerUserID: a.OwnerUserID, Tool: a.Tool, ArgsRedacted: canonical, Decision: a.Decision,
		DenialCode: a.DenialCode, ResultStatus: a.ResultStatus, ResultDigest: a.ResultDigest,
		ResultExcerpt: a.ResultExcerpt, MaskedCount: a.MaskedCount, DurationMS: a.DurationMS,
		CreatedAtUs: a.CreatedAt.UnixMicro(), KeyVersion: a.KeyVersion,
	})
}

func computeToolCallHMAC(key []byte, a *model.AgentToolCall) string {
	if len(key) == 0 {
		return ""
	}
	b, err := toolCallSignBytes(a)
	if err != nil {
		return ""
	}
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

func (s *AuditIntegrityService) StampToolCall(a *model.AgentToolCall) (err error) {
	if s == nil || s.activeFn == nil {
		return errors.New("ledger integrity unavailable")
	}
	if s.gate != nil {
		lease, e := s.gate.Borrow()
		if e != nil {
			return e
		}
		defer lease.Finish(func(valid bool) {
			if !valid {
				a.IntegrityHMAC = ""
				err = errors.New("ledger key lease revoked")
			}
		})
	}
	v, key := s.activeFn()
	if s.gate != nil {
		defer material.Wipe(key)
	}
	a.KeyVersion = v
	a.IntegrityHMAC = computeToolCallHMAC(key, a)
	if a.IntegrityHMAC == "" {
		return errors.New("ledger integrity key unavailable")
	}
	return nil
}

func (s *AuditIntegrityService) VerifyToolCall(a *model.AgentToolCall) (valid bool) {
	if s == nil || s.keyFn == nil || a.IntegrityHMAC == "" {
		return false
	}
	if s.gate != nil {
		lease, err := s.gate.Borrow()
		if err != nil {
			return false
		}
		defer lease.Finish(func(ok bool) {
			if !ok {
				valid = false
			}
		})
	}
	key := s.keyFn(a.KeyVersion)
	if s.gate != nil {
		defer material.Wipe(key)
	}
	want := computeToolCallHMAC(key, a)
	return want != "" && hmac.Equal([]byte(want), []byte(a.IntegrityHMAC))
}

func (s *AuditIntegrityService) VerifyToolCalls(db *gorm.DB, from, to time.Time) (*IntegrityReport, error) {
	return s.verifyToolCallQuery(db.Where("created_at >= ? AND created_at < ?", from, to), from, to)
}

func (s *AuditIntegrityService) verifyToolCallQuery(db *gorm.DB, from, to time.Time) (*IntegrityReport, error) {
	r := &IntegrityReport{From: from, To: to, MismatchedIDs: []uint{}}
	last := uint(0)
	for {
		var rows []model.AgentToolCall
		if err := db.Where("id > ?", last).Order("id").Limit(integrityVerifyBatch).Find(&rows).Error; err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			break
		}
		for i := range rows {
			a := &rows[i]
			last = a.ID
			r.Checked++
			if s.VerifyToolCall(a) {
				r.Passed++
			} else {
				r.Mismatched++
				if len(r.MismatchedIDs) < integrityMismatchIDCap {
					r.MismatchedIDs = append(r.MismatchedIDs, a.ID)
				}
			}
		}
	}
	return r, nil
}

func canonicalToolCallArgs(raw string) ([]byte, error) {
	if !json.Valid([]byte(raw)) {
		return nil, errors.New("invalid ledger arguments")
	}
	var args any
	dec := json.NewDecoder(bytes.NewBufferString(raw))
	dec.UseNumber()
	if err := dec.Decode(&args); err != nil {
		return nil, err
	}
	return json.Marshal(normalizeToolCallNumbers(args))
}

// A result uses the pending row's version, even if the active key has rotated.
func (s *AuditIntegrityService) restampToolCall(a *model.AgentToolCall) (err error) {
	if s == nil || s.keyFn == nil {
		return errors.New("ledger integrity unavailable")
	}
	if s.gate != nil {
		lease, e := s.gate.Borrow()
		if e != nil {
			return e
		}
		defer lease.Finish(func(valid bool) {
			if !valid {
				a.IntegrityHMAC = ""
				err = errors.New("ledger key lease revoked")
			}
		})
	}
	key := s.keyFn(a.KeyVersion)
	if s.gate != nil {
		defer material.Wipe(key)
	}
	a.IntegrityHMAC = computeToolCallHMAC(key, a)
	if a.IntegrityHMAC == "" {
		return errors.New("ledger original key unavailable")
	}
	return nil
}

// PostgreSQL jsonb expands exponents and retains decimal scale. Normalize exact
// JSON numbers without float64 rounding so both encodings prove the same value.
func normalizeToolCallNumbers(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			x[k] = normalizeToolCallNumbers(child)
		}
		return x
	case []any:
		for i, child := range x {
			x[i] = normalizeToolCallNumbers(child)
		}
		return x
	case json.Number:
		raw := string(x)
		sign := ""
		if strings.HasPrefix(raw, "-") {
			sign = "-"
			raw = raw[1:]
		}
		exp := new(big.Int)
		if i := strings.IndexAny(raw, "eE"); i >= 0 {
			exp.SetString(raw[i+1:], 10)
			raw = raw[:i]
		}
		if i := strings.IndexByte(raw, '.'); i >= 0 {
			exp.Sub(exp, big.NewInt(int64(len(raw)-i-1)))
			raw = raw[:i] + raw[i+1:]
		}
		raw = strings.TrimLeft(raw, "0")
		if raw == "" {
			return json.Number("0")
		}
		trimmed := strings.TrimRight(raw, "0")
		exp.Add(exp, big.NewInt(int64(len(raw)-len(trimmed))))
		if exp.Sign() == 0 {
			return json.Number(sign + trimmed)
		}
		return json.Number(sign + trimmed + "e" + exp.String())
	default:
		return v
	}
}
