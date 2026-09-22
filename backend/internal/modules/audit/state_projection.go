package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

const StateTablePrincipals = "user_principals"
const StateTableAgentTokens = "agent_tokens"

// StateSet contains opaque canonical elements; only the registered codec interprets them.
type StateSet map[string]bool

type PrincipalState struct {
	ID      uint64
	Kind    string
	OwnerID *uint64
}
type AgentTokenState struct {
	ID, UserID         uint64
	Revoked, Suspended bool
	Fingerprint        string
	ExpiresAt          time.Time
}
type PrincipalSource func(context.Context, *gorm.DB) ([]PrincipalState, error)
type AgentTokenSource func(context.Context, *gorm.DB) ([]AgentTokenState, error)

var principalSource PrincipalSource
var agentTokenSource AgentTokenSource

func SetPrincipalSource(src PrincipalSource)   { principalSource = src }
func SetAgentTokenSource(src AgentTokenSource) { agentTokenSource = src }

// CredentialFingerprint hashes the stored hash bytes, never the credential itself.
func CredentialFingerprint(storedHash string) string {
	sum := sha256.Sum256([]byte(storedHash))
	return hex.EncodeToString(sum[:])
}
func principalElement(p PrincipalState) string {
	b, _ := json.Marshal([]any{p.ID, p.Kind, p.OwnerID})
	return string(b)
}
func tokenElement(p AgentTokenState) string {
	b, _ := json.Marshal([]any{p.ID, p.UserID, p.Revoked, p.Suspended, p.Fingerprint, p.ExpiresAt.UTC().Format(time.RFC3339Nano)})
	return string(b)
}
func elementID(s string) uint64 {
	var fields []json.RawMessage
	_ = json.Unmarshal([]byte(s), &fields)
	var id uint64
	if len(fields) > 0 {
		_ = json.Unmarshal(fields[0], &id)
	}
	return id
}
func snapshotSet(name string, set StateSet) StateSnapshot {
	rows := make([]string, 0, len(set))
	for s := range set {
		rows = append(rows, s)
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := elementID(rows[i]), elementID(rows[j])
		if a != b {
			return a < b
		}
		return rows[i] < rows[j]
	})
	body := []byte("[")
	for i, s := range rows {
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, s...)
	}
	body = append(body, ']')
	return StateSnapshot{Table: name, Body: body, Hash: stateHash(body), Count: int64(len(rows))}
}
func decodeProjection(name string, body []byte) (StateSet, error) {
	var rows []json.RawMessage
	if len(body) == 0 || body[0] != '[' {
		return nil, fmt.Errorf("%s snapshot must be an array", name)
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	set := StateSet{}
	ids := map[uint64]bool{}
	for _, row := range rows {
		var fields []json.RawMessage
		if err := json.Unmarshal(row, &fields); err != nil {
			return nil, err
		}
		var key string
		if name == StateTablePrincipals {
			if len(fields) != 3 {
				return nil, fmt.Errorf("principal tuple fields missing")
			}
			var p PrincipalState
			if json.Unmarshal(fields[0], &p.ID) != nil || json.Unmarshal(fields[1], &p.Kind) != nil || json.Unmarshal(fields[2], &p.OwnerID) != nil || p.ID == 0 || (p.Kind != "human" && p.Kind != "agent") || (p.Kind == "human" && p.OwnerID != nil) || (p.Kind == "agent" && (p.OwnerID == nil || *p.OwnerID == 0)) {
				return nil, fmt.Errorf("invalid principal tuple")
			}
			key = principalElement(p)
		} else {
			if len(fields) != 6 {
				return nil, fmt.Errorf("token tuple fields missing")
			}
			var p AgentTokenState
			var expiry string
			if json.Unmarshal(fields[0], &p.ID) != nil || json.Unmarshal(fields[1], &p.UserID) != nil || string(fields[2]) == "null" || string(fields[3]) == "null" || json.Unmarshal(fields[2], &p.Revoked) != nil || json.Unmarshal(fields[3], &p.Suspended) != nil || json.Unmarshal(fields[4], &p.Fingerprint) != nil || json.Unmarshal(fields[5], &expiry) != nil {
				return nil, fmt.Errorf("invalid token tuple")
			}
			var err error
			p.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiry)
			hash, e := hex.DecodeString(p.Fingerprint)
			if err != nil || e != nil || len(hash) != 32 || p.ID == 0 || p.UserID == 0 || p.ExpiresAt.IsZero() {
				return nil, fmt.Errorf("invalid token state")
			}
			key = tokenElement(p)
		}
		id := elementID(key)
		if ids[id] {
			return nil, fmt.Errorf("duplicate %s id %d", name, id)
		}
		ids[id] = true
		set[key] = true
	}
	return set, nil
}
func diffState(expected, actual StateSet) (missing, extra []string) {
	for k := range expected {
		if !actual[k] {
			missing = append(missing, k)
		}
	}
	for k := range actual {
		if !expected[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return
}
func SnapshotPrincipals(ctx context.Context, tx *gorm.DB) (StateSnapshot, error) {
	if principalSource == nil {
		return StateSnapshot{}, fmt.Errorf("principal source unset")
	}
	rows, err := principalSource(ctx, tx)
	if err != nil {
		return StateSnapshot{}, err
	}
	set := StateSet{}
	for _, p := range rows {
		set[principalElement(p)] = true
	}
	snap := snapshotSet(StateTablePrincipals, set)
	_, err = decodeProjection(snap.Table, snap.Body)
	return snap, err
}
func SnapshotAgentTokens(ctx context.Context, tx *gorm.DB) (StateSnapshot, error) {
	if agentTokenSource == nil {
		return StateSnapshot{}, fmt.Errorf("agent token source unset")
	}
	rows, err := agentTokenSource(ctx, tx)
	if err != nil {
		return StateSnapshot{}, err
	}
	set := StateSet{}
	for _, p := range rows {
		set[tokenElement(p)] = true
	}
	snap := snapshotSet(StateTableAgentTokens, set)
	_, err = decodeProjection(snap.Table, snap.Body)
	return snap, err
}
func replaceElement(set StateSet, id uint64, key string, remove bool) {
	for k := range set {
		if elementID(k) == id {
			delete(set, k)
		}
	}
	if !remove {
		set[key] = true
	}
}
func applyProjection(name string, base StateSet, events []model.AuditLog) (StateSnapshot, error) {
	set := StateSet{}
	for k := range base {
		set[k] = true
	}
	for _, event := range events {
		if event.Status != model.StatusSuccess {
			continue
		}
		if name == StateTablePrincipals {
			if event.Action != model.ActionCreate && event.Action != model.ActionUpdate && event.Action != model.ActionDelete {
				continue
			}
		} else if event.Action != model.ActionCreate && event.Action != model.ActionRevoke && event.Action != model.ActionSuspend {
			continue
		}
		var d map[string]json.RawMessage
		if err := json.Unmarshal([]byte(event.Details), &d); err != nil {
			return StateSnapshot{}, err
		}
		keys := []string{"user_id", "kind", "owner_user_id"}
		if name == StateTableAgentTokens {
			keys = []string{"token_id", "user_id", "revoked", "suspended", "credential_fingerprint", "expires_at"}
		}
		fields := make([]json.RawMessage, len(keys))
		for i, k := range keys {
			value, ok := d[k]
			if !ok {
				return StateSnapshot{}, fmt.Errorf("%s audit %d missing %s", name, event.ID, k)
			}
			fields[i] = value
		}
		row, _ := json.Marshal(fields)
		body := append([]byte{'['}, row...)
		body = append(body, ']')
		decoded, err := decodeProjection(name, body)
		if err != nil {
			return StateSnapshot{}, fmt.Errorf("%s audit %d: %w", name, event.ID, err)
		}
		for key := range decoded {
			id := elementID(key)
			if event.ResourceID == nil || uint64(*event.ResourceID) != id {
				return StateSnapshot{}, fmt.Errorf("audit resource id mismatch")
			}
			replaceElement(set, id, key, event.Action == model.ActionDelete)
		}
	}
	return snapshotSet(name, set), nil
}
func projectionTable(name, resource string, snapshot func(context.Context, *gorm.DB) (StateSnapshot, error)) StateTable {
	marker := ""
	if name == StateTablePrincipals {
		marker = `"state_table":"` + name + `"`
	}
	return StateTable{Name: name, EventMarker: marker, EventResource: resource, Snapshot: snapshot, Decode: func(b []byte) (StateSet, error) { return decodeProjection(name, b) }, Apply: func(s StateSet, rows []model.AuditLog) (StateSnapshot, error) { return applyProjection(name, s, rows) }, Diff: diffState}
}
func decodeRoleSet(body []byte) (StateSet, error) {
	pairs, err := DecodeRolePairs(body)
	if err != nil {
		return nil, err
	}
	set := StateSet{}
	for _, p := range pairs {
		b, _ := EncodeRolePairs([]RolePair{p})
		set[string(b[1:len(b)-1])] = true
	}
	return set, nil
}
func roleSetPairs(set StateSet) []RolePair {
	pairs := []RolePair{}
	for k := range set {
		p, _ := DecodeRolePairs([]byte("[" + k + "]"))
		pairs = append(pairs, p...)
	}
	return pairs
}
func applyRoleSet(base StateSet, events []model.AuditLog) (StateSnapshot, error) {
	body, n := EncodeRolePairs(applyRoleEvents(roleSetPairs(base), events))
	return StateSnapshot{Table: StateTableUserRoles, Body: body, Hash: stateHash(body), Count: n}, nil
}
