package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

func aggFixture(id uint, tool string) model.AgentToolCall {
	return model.AgentToolCall{ID: id, Seq: id, UserID: 1, AgentTokenID: 2, OwnerUserID: 3, Tool: tool, ArgsRedacted: "{}", CreatedAt: time.Unix(0, 0).UTC(), KeyVersion: 1}
}
func TestToolCallAgg(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []model.AgentToolCall
		want string
	}{
		{"empty", nil, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"single", []model.AgentToolCall{aggFixture(1, "list_assets")}, "29848bb05fef66c3c7d4a03c1c1131db14e5c2b9c4f17a0f00045d0ae49035f8"},
		{"multiple", []model.AgentToolCall{aggFixture(1, "list_assets"), aggFixture(9, "check_request")}, "acab7e6635e971ba8887b60caf22c944e025499e43b18b8f4641deb41914446c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newToolCallAggWriter()
			for _, r := range tc.rows {
				w.Add(r)
			}
			h, n, err := w.Sum()
			if err != nil || h != tc.want || n != int64(len(tc.rows)) {
				t.Fatal(h, n, err)
			}
		})
	}
	a, b := newToolCallAggWriter(), newToolCallAggWriter()
	a.Add(aggFixture(1, "list_assets"))
	a.Add(aggFixture(9, "check_request"))
	b.Add(aggFixture(9, "check_request"))
	b.Add(aggFixture(1, "list_assets"))
	ha, _, _ := a.Sum()
	hb, _, _ := b.Sum()
	if ha == hb {
		t.Fatal("row order not covered")
	}
	row := aggFixture(1, "list_assets")
	row.ArgsRedacted = "invalid"
	w := newToolCallAggWriter()
	w.Add(row)
	if _, _, err := w.Sum(); err == nil {
		t.Fatal("invalid arguments accepted")
	}
}

func v3CanonicalFixture() *model.AuditCheckpoint {
	from, to := uint(1), uint(0)
	count := int64(0)
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	snapshot := `{"user_roles":[]}`
	return &model.AuditCheckpoint{Seq: 1, IDFrom: 1, IDTo: 0, RowCount: 0, AggHash: hash, AggScheme: model.AggSchemeV3, PrevCheckpointHash: "anchor", RoleStateSnapshot: &snapshot, SealedAt: time.Unix(0, 0).UTC(), SigningKeyVersion: 1, ToolCallIDFrom: &from, ToolCallIDTo: &to, ToolCallRowCount: &count, ToolCallAggHash: &hash}
}

func TestCheckpointPayloadV3(t *testing.T) {
	cp := v3CanonicalFixture()
	got, err := CheckpointSignBytes(cp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(got), `"tool_call_id_from":1,"tool_call_id_to":0,"tool_call_row_count":0,"tool_call_agg_hash":"`+*cp.ToolCallAggHash+`"}`) {
		t.Fatal(string(got))
	}
	cp.AggScheme = model.AggSchemeV2
	if _, err := CheckpointSignBytes(cp); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatal("v3 disguised as v2", err)
	}
	cp.AggScheme = model.AggSchemeV3
	cp.ToolCallAggHash = nil
	if _, err := CheckpointSignBytes(cp); err == nil {
		t.Fatal("missing v3 field accepted")
	}
}

// Independently assembles the documented bytes, without using payload structs or stateHash.
func TestCheckpointOfflineRebuildV3(t *testing.T) {
	doc, err := os.ReadFile("../../../cmd/server/testdata/docs/security/audit-checkpoint-offline-verification.md")
	if err != nil {
		t.Fatal("documentation mount unavailable: " + err.Error())
	}
	if !strings.Contains(string(doc), "tool_call_id_from, tool_call_id_to, tool_call_row_count, tool_call_agg_hash") {
		t.Fatal("documented v3 order missing")
	}
	// Literal copied from the public specification; no production projection structs.
	literal := `{"id":1,"seq":1,"user_id":1,"agent_token_id":2,"access_request_id":null,"session_id":null,"on_behalf_of_user_id":null,"owner_user_id":3,"tool":"list_assets","args_sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","created_at_us":0,"key_version":1}`
	if !strings.Contains(string(doc), literal) {
		t.Fatal("documented ledger vector differs")
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(literal)))
	manual := sha256.Sum256(append(length[:], []byte(literal)...))
	writer := newToolCallAggWriter()
	writer.Add(aggFixture(1, "list_assets"))
	actual, count, err := writer.Sum()
	if err != nil || count != 1 || actual != hex.EncodeToString(manual[:]) {
		t.Fatal("offline ledger bytes differ", actual, err)
	}
	cp := v3CanonicalFixture()
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], 2)
	body := append(prefix[:], []byte("[]")...)
	sum := sha256.Sum256(body)
	want := fmt.Sprintf(`{"seq":1,"id_from":1,"id_to":0,"row_count":0,"agg_hash":%q,"agg_scheme":"cp-agg-v3","prev_checkpoint_hash":"anchor","min_created_at_us":null,"state":[{"table":"user_roles","hash":%q,"count":0}],"role_state_reconciled":null,"max_created_at_us":null,"sealed_at_us":0,"signing_key_version":1,"tool_call_id_from":1,"tool_call_id_to":0,"tool_call_row_count":0,"tool_call_agg_hash":%q}`, cp.AggHash, hex.EncodeToString(sum[:]), *cp.ToolCallAggHash)
	got, err := CheckpointSignBytes(cp)
	if err != nil || string(got) != want {
		t.Fatalf("offline mismatch: %s\nwant: %s\n%v", got, want, err)
	}
}
