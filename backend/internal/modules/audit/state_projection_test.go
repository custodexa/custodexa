package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// Older role-only fixtures intentionally inject empty new projections. New
// projection tests below replace them with controlled sources and restore them.
func init() {
	SetPrincipalSource(func(context.Context, *gorm.DB) ([]PrincipalState, error) { return nil, nil })
	SetAgentTokenSource(func(context.Context, *gorm.DB) ([]AgentTokenState, error) { return nil, nil })
}
func projectionSources(t *testing.T, p *[]PrincipalState, a *[]AgentTokenState) {
	t.Helper()
	oldP, oldA := principalSource, agentTokenSource
	t.Cleanup(func() { principalSource, agentTokenSource = oldP, oldA })
	SetPrincipalSource(func(context.Context, *gorm.DB) ([]PrincipalState, error) { return *p, nil })
	SetAgentTokenSource(func(context.Context, *gorm.DB) ([]AgentTokenState, error) { return *a, nil })
}
func principalFixture() []PrincipalState {
	owner := uint64(1)
	return []PrincipalState{{ID: 2, Kind: "agent", OwnerID: &owner}, {ID: 1, Kind: "human"}}
}
func tokenFixture() []AgentTokenState {
	return []AgentTokenState{{ID: 12, UserID: 2, Fingerprint: CredentialFingerprint("stored-secret-hash"), ExpiresAt: time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)}, {ID: 3, UserID: 2, Fingerprint: CredentialFingerprint("another-stored-hash"), ExpiresAt: time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC)}}
}

type projectionSnapshotCase struct {
	table    string
	snapshot func(context.Context, *gorm.DB) (StateSnapshot, error)
}

func projectionSnapshotCases() []projectionSnapshotCase {
	return []projectionSnapshotCase{{StateTablePrincipals, SnapshotPrincipals}, {StateTableAgentTokens, SnapshotAgentTokens}}
}
func TestStateTableSnapshotProjections(t *testing.T) {
	for _, c := range projectionSnapshotCases() {
		t.Run(c.table, func(t *testing.T) {
			p, a := principalFixture(), tokenFixture()
			projectionSources(t, &p, &a)
			before, err := c.snapshot(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			p[0], p[1] = p[1], p[0]
			a[0], a[1] = a[1], a[0]
			after, err := c.snapshot(context.Background(), nil)
			if err != nil || before.Hash != after.Hash || string(before.Body) != string(after.Body) {
				t.Fatal("order-dependent snapshot", err)
			}
			p = p[:1]
			a = a[:1]
			changed, err := c.snapshot(context.Background(), nil)
			if err != nil || changed.Hash == before.Hash {
				t.Fatal("one-row change invisible", err)
			}
			for _, forbidden := range []string{"username", "email", "token_name", "cxa_", "stored-secret-hash", "another-stored-hash", "last_used_at", "revoke_note"} {
				if strings.Contains(string(before.Body), forbidden) {
					t.Fatal("private field leaked", forbidden)
				}
			}
		})
	}
}
func TestSnapshotPrincipalCanonical(t *testing.T) {
	p, a := principalFixture(), tokenFixture()
	projectionSources(t, &p, &a)
	snap, err := SnapshotPrincipals(context.Background(), nil)
	if err != nil || string(snap.Body) != `[[1,"human",null],[2,"agent",1]]` {
		t.Fatalf("canonical %s %v", snap.Body, err)
	}
}
func TestSnapshotAgentTokenFingerprintAndExpiry(t *testing.T) {
	p, a := principalFixture(), tokenFixture()
	projectionSources(t, &p, &a)
	before, _ := SnapshotAgentTokens(context.Background(), nil)
	a[0].Fingerprint = CredentialFingerprint("replacement")
	changed, _ := SnapshotAgentTokens(context.Background(), nil)
	if before.Hash == changed.Hash {
		t.Fatal("replacement invisible")
	}
	a = tokenFixture()
	a[0].ExpiresAt = a[0].ExpiresAt.Add(time.Hour)
	changed, _ = SnapshotAgentTokens(context.Background(), nil)
	if before.Hash == changed.Hash {
		t.Fatal("expiry extension invisible")
	}
}
func auditProjectionEvent(t *testing.T, name string, action model.AuditAction, id uint, fields map[string]any) model.AuditLog {
	t.Helper()
	if name == StateTablePrincipals {
		fields["state_table"] = name
	}
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return model.AuditLog{ResourceID: &id, Action: action, Status: model.StatusSuccess, Details: string(b)}
}
func TestApplyPrincipalEvents(t *testing.T) {
	for _, action := range []string{"create", "kind", "owner", "delete", "missing_kind", "missing_owner"} {
		t.Run(action, func(t *testing.T) {
			base := StateSet{principalElement(PrincipalState{ID: 2, Kind: "human"}): true}
			fields := map[string]any{"user_id": 2, "kind": "agent", "owner_user_id": 1}
			op := model.ActionUpdate
			if action == "create" {
				base = StateSet{}
				op = model.ActionCreate
			}
			if action == "owner" {
				owner := uint64(3)
				base = StateSet{principalElement(PrincipalState{ID: 2, Kind: "agent", OwnerID: &owner}): true}
			}
			if action == "delete" {
				op = model.ActionDelete
			}
			if action == "missing_kind" {
				delete(fields, "kind")
			}
			if action == "missing_owner" {
				delete(fields, "owner_user_id")
			}
			snap, err := applyProjection(StateTablePrincipals, base, []model.AuditLog{auditProjectionEvent(t, StateTablePrincipals, op, 2, fields)})
			if strings.HasPrefix(action, "missing") {
				if err == nil {
					t.Fatal("missing fields accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := `[[2,"agent",1]]`
			if action == "delete" {
				want = "[]"
			}
			if string(snap.Body) != want {
				t.Fatalf("got %s want %s", snap.Body, want)
			}
		})
	}
}
func TestApplyAgentTokenEvents(t *testing.T) {
	for _, action := range []model.AuditAction{model.ActionCreate, model.ActionRevoke, model.ActionSuspend} {
		t.Run(string(action), func(t *testing.T) {
			fields := map[string]any{"token_id": 1, "user_id": 2, "revoked": action == model.ActionRevoke, "suspended": action == model.ActionSuspend, "credential_fingerprint": CredentialFingerprint("hash"), "expires_at": "2031-01-01T00:00:00Z"}
			event := auditProjectionEvent(t, StateTableAgentTokens, action, 1, fields)
			snap, err := applyProjection(StateTableAgentTokens, StateSet{}, []model.AuditLog{event, event})
			if err != nil || snap.Count != 1 {
				t.Fatal("replay", err)
			}
			for _, key := range []string{"token_id", "user_id", "revoked", "suspended", "credential_fingerprint", "expires_at"} {
				copyFields := map[string]any{}
				for k, v := range fields {
					if k != key {
						copyFields[k] = v
					}
				}
				_, err := applyProjection(StateTableAgentTokens, StateSet{}, []model.AuditLog{auditProjectionEvent(t, StateTableAgentTokens, action, 1, copyFields)})
				if err == nil {
					t.Fatal("missing field accepted", key)
				}
			}
		})
	}
}

type projectionFailure struct {
	events   map[string]int
	resolved map[string]int
}

func (f *projectionFailure) ReportStateMismatch(table string, _ map[string]string) error {
	f.events[table]++
	return nil
}
func (f *projectionFailure) ResolveStateMismatch(table string) error { f.resolved[table]++; return nil }
func TestStateTableReconcileIndependent(t *testing.T) {
	p, a := principalFixture(), tokenFixture()
	projectionSources(t, &p, &a)
	f := setupRoleFixture(t)
	f.sealWithRoles(t)
	sink := &projectionFailure{map[string]int{}, map[string]int{}}
	f.rec.SetStateFailureSink(sink)
	p[0].OwnerID = &p[0].ID
	a[0].Revoked = true
	for i := 0; i < 2; i++ {
		f.rec.ReconcileTables(context.Background())
	}
	if sink.events[StateTablePrincipals] != 1 || sink.events[StateTableAgentTokens] != 1 {
		t.Fatalf("dedupe suppressed projection: %v", sink.events)
	}
	SetPrincipalSource(func(context.Context, *gorm.DB) ([]PrincipalState, error) {
		return nil, fmt.Errorf("source unavailable")
	})
	reports := f.rec.ReconcileTables(context.Background())
	states := map[string]string{}
	for _, r := range reports {
		states[r.Table] = r.State
	}
	if states[StateTablePrincipals] != StateTableUnknown || states[StateTableUserRoles] != RoleStateMatch || states[StateTableAgentTokens] != RoleStateMismatch {
		t.Fatal(states)
	}
}
func TestStateTableReconcileUpgradeNotCovered(t *testing.T) {
	f := setupRoleFixture(t)
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"user_roles":[]}`
	f.mustExec(t, "UPDATE audit_checkpoints SET role_state_snapshot = ? WHERE seq <= ?", legacy, cp.Seq)
	for _, report := range f.rec.ReconcileTables(context.Background()) {
		want := RoleStateNotCovered
		if report.Table == StateTableUserRoles {
			want = RoleStateMatch
		}
		if report.State != want {
			t.Fatal(report)
		}
	}
}
func TestCheckpointProjectionSealConjunction(t *testing.T) {
	p, a := principalFixture(), tokenFixture()
	projectionSources(t, &p, &a)
	f := setupRoleFixture(t)
	f.sealWithRoles(t)
	a[0].Suspended = true
	f.seal.SetRoleStateReconciler(f.rec)
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatal(err)
	}
	if cp.RoleStateReconciled == nil || *cp.RoleStateReconciled {
		t.Fatal("one mismatch must seal false")
	}
}
func TestCheckpointOfflineRebuildThreeKeys(t *testing.T) {
	p, a := principalFixture(), tokenFixture()
	projectionSources(t, &p, &a)
	f := setupVerifyFixture(t)
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatal(err)
	}
	// Preserve this independent v2 three-key vector; v3 has its own offline test.
	cp.AggScheme = model.AggSchemeV2
	cp.ToolCallIDFrom = nil
	cp.ToolCallIDTo = nil
	cp.ToolCallRowCount = nil
	cp.ToolCallAggHash = nil
	// Independently write tuple bytes, table ordering and the length-prefix hash.
	tokenRows := fmt.Sprintf(`[[3,2,false,false,"%s","2032-01-01T00:00:00Z"],[12,2,false,false,"%s","2031-01-01T00:00:00Z"]]`, a[1].Fingerprint, a[0].Fingerprint)
	body := `{"agent_tokens":` + tokenRows + `,"user_principals":[[1,"human",null],[2,"agent",1]],"user_roles":[]}`
	if *cp.RoleStateSnapshot != body {
		t.Fatalf("manual bytes differ: %s", *cp.RoleStateSnapshot)
	}
	entries, err := checkpointStateEntries(cp)
	if err != nil {
		t.Fatal(err)
	}
	manualEntries := []string{}
	for _, entry := range entries {
		var tableBodies map[string]json.RawMessage
		_ = json.Unmarshal([]byte(body), &tableBodies)
		raw := tableBodies[entry.Table]
		var prefix [8]byte
		binary.BigEndian.PutUint64(prefix[:], uint64(len(raw)))
		sum := sha256.Sum256(append(prefix[:], raw...))
		hash := hex.EncodeToString(sum[:])
		var elements []json.RawMessage
		_ = json.Unmarshal(raw, &elements)
		manualEntries = append(manualEntries, fmt.Sprintf(`{"table":%q,"hash":%q,"count":%d}`, entry.Table, hash, len(elements)))
		if entry.Hash != hash {
			t.Fatal("offline hash differs")
		}
	}
	manualPayload := fmt.Sprintf(`{"seq":%d,"id_from":%d,"id_to":%d,"row_count":%d,"agg_hash":%q,"agg_scheme":%q,"prev_checkpoint_hash":%q,"min_created_at_us":null,"state":[%s],"role_state_reconciled":null,"max_created_at_us":null,"sealed_at_us":%d,"signing_key_version":%d}`, cp.Seq, cp.IDFrom, cp.IDTo, cp.RowCount, cp.AggHash, cp.AggScheme, cp.PrevCheckpointHash, strings.Join(manualEntries, ","), cp.SealedAt.UnixMicro(), cp.SigningKeyVersion)
	actualPayload, err := CheckpointSignBytes(cp)
	if err != nil || string(actualPayload) != manualPayload {
		t.Fatalf("offline signing bytes differ: %v\n%s\n%s", err, manualPayload, actualPayload)
	}

}
func TestCheckpointPayloadLatestSealAndDowngrade(t *testing.T) {
	f := setupVerifyFixture(t)
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatal(err)
	}
	if cp.AggScheme != model.LatestCheckpointScheme {
		t.Fatal("seal pinned to older version")
	}
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPassed {
		t.Fatal("before downgrade", got)
	}
	f.mustExec(t, "UPDATE audit_checkpoints SET agg_scheme = ? WHERE seq = ?", model.AggSchemeV1, cp.Seq)
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPayloadInvalid {
		t.Fatal("matrix failed to detect downgrade", got)
	}
	cp.AggScheme = model.AggSchemeV1
	cp.ToolCallIDFrom = nil
	cp.ToolCallIDTo = nil
	cp.ToolCallRowCount = nil
	cp.ToolCallAggHash = nil
	payload, err := CheckpointSignBytes(cp)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.signer.Verify(cp.SigningKeyVersion, payload, cp.Signature); ok {
		t.Fatal("downgraded payload accepted")
	}
}

func TestStateTableReconcileNewCoverageAfterLegacyTrue(t *testing.T) {
	f := setupRoleFixture(t)
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatal(err)
	}
	f.mustExec(t, "UPDATE audit_checkpoints SET role_state_snapshot = ?, role_state_reconciled = ? WHERE seq = ?", `{"user_roles":[]}`, true, cp.Seq)
	anchor, err := f.seal.SealNow()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range f.rec.ReconcileTables(context.Background()) {
		if r.State != RoleStateMatch {
			t.Fatal("new projection stuck uncovered", r)
		}
		if r.Table != StateTableUserRoles && r.SinceSeq != anchor.Seq {
			t.Fatal("did not select per-item anchor", r)
		}
	}
}
