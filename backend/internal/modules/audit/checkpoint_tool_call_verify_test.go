package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// Builds a signed payload version 3 interval directly, so verification is independent of sealing implementation.
func toolCallVerifyFixture(t *testing.T) (*verifyFixture, *model.AuditCheckpoint) {
	t.Helper()
	f := setupVerifyFixture(t)
	makeHistoricalV2Fixture(t, f)
	if err := f.db.AutoMigrate(&model.AgentToolCall{}); err != nil {
		t.Fatal(err)
	}
	for seq := uint(1); seq <= 2; seq++ {
		a := model.AgentToolCall{Seq: seq, UserID: 1, AgentTokenID: 2, OwnerUserID: 3, Tool: "list_assets", ArgsRedacted: "{}", Decision: model.ToolCallAllowed, ResultExcerpt: "visible result"}
		if err := f.db.WithContext(model.WithToolCallStamp(context.Background(), f.integrity.StampToolCall)).Create(&a).Error; err != nil {
			t.Fatal(err)
		}
	}
	last, err := f.seal.Latest()
	if err != nil {
		t.Fatal(err)
	}
	link, err := CheckpointLinkHash(last)
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := ComputeAggHash(nil)
	from, to, count := uint(1), uint(2), int64(2)
	hash, _, err := f.seal.AggregateToolCalls(from, to)
	if err != nil {
		t.Fatal(err)
	}
	cp := &model.AuditCheckpoint{Seq: last.Seq + 1, IDFrom: last.IDTo + 1, IDTo: last.IDTo, AggHash: empty, PrevCheckpointHash: link, SealedAt: time.Now().UTC(), ToolCallIDFrom: &from, ToolCallIDTo: &to, ToolCallRowCount: &count, ToolCallAggHash: &hash}
	if err := f.seal.applyStateSnapshot(cp); err != nil {
		t.Fatal(err)
	}
	cp.AggScheme = model.AggSchemeV3
	if err := f.seal.signAndPersist(cp); err != nil {
		t.Fatal(err)
	}
	return f, cp
}

func TestCheckpointVerifyV3Sources(t *testing.T) {
	f, cp := toolCallVerifyFixture(t)
	got := f.statusOf(t, cp.Seq)
	if got.Status != IntervalStatusPassed || got.AuditLogs == nil || got.AuditLogs.Status != IntervalStatusPassed || got.ToolCalls == nil || got.ToolCalls.Status != IntervalStatusPassed || got.ToolCalls.RowCount != 2 {
		t.Fatalf("%+v", got)
	}
	if err := f.db.Exec("UPDATE agent_tool_calls SET result_excerpt='tampered' WHERE id=1").Error; err != nil {
		t.Fatal(err)
	}
	got = f.statusOf(t, cp.Seq)
	if got.Status != "row_hmac_mismatch" || got.AuditLogs.Status != IntervalStatusPassed || got.ToolCalls.Status != "row_hmac_mismatch" {
		t.Fatalf("sources conflated: %+v", got)
	}
	old := f.statusOf(t, 1)
	if old.Status != IntervalStatusPassed || old.ToolCalls.Status != "not_covered" {
		t.Fatalf("legacy point changed: %+v", old)
	}
}

func TestCheckpointTamperMatrixToolCalls(t *testing.T) {
	for _, tc := range []struct{ name, sql, status, detail string }{
		{"change send content", "UPDATE agent_tool_calls SET seq=100 WHERE id=1", IntervalStatusHashMismatch, "aggregate"},
		{"delete row", "DELETE FROM agent_tool_calls WHERE id=1", IntervalStatusCountMismatch, "row count"},
		{"change content", "UPDATE agent_tool_calls SET result_excerpt='changed' WHERE id=1", "row_hmac_mismatch", "row content"},
		{"change stamp", "UPDATE agent_tool_calls SET integrity_hmac='changed' WHERE id=1", "row_hmac_mismatch", "row content"},
		{"checkpoint from", "UPDATE audit_checkpoints SET tool_call_id_from=2 WHERE seq=2", IntervalStatusSignatureInvalid, "簽章"},
		{"checkpoint to", "UPDATE audit_checkpoints SET tool_call_id_to=3 WHERE seq=2", IntervalStatusSignatureInvalid, "簽章"},
		{"checkpoint count", "UPDATE audit_checkpoints SET tool_call_row_count=3 WHERE seq=2", IntervalStatusSignatureInvalid, "簽章"},
		{"checkpoint hash", "UPDATE audit_checkpoints SET tool_call_agg_hash='changed' WHERE seq=2", IntervalStatusSignatureInvalid, "簽章"},
		{"version disguise", "UPDATE audit_checkpoints SET agg_scheme='cp-agg-v2' WHERE seq=2", IntervalStatusPayloadInvalid, "downgrade"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, cp := toolCallVerifyFixture(t)
			if err := f.db.Exec(tc.sql).Error; err != nil {
				t.Fatal(err)
			}
			if tc.name == "delete row" {
				report, err := f.integrity.VerifyToolCalls(f.db, cp.SealedAt.Add(-time.Hour), cp.SealedAt.Add(time.Hour))
				if err != nil || report.Checked != 1 || report.Passed != report.Checked || report.Mismatched != 0 {
					t.Fatalf("remaining ledger rows must all pass HMAC verification: report=%+v err=%v", report, err)
				}
			}
			got := f.statusOf(t, cp.Seq)
			if got.Status != tc.status || !strings.Contains(got.Detail, tc.detail) {
				t.Fatalf("status=%s detail=%s", got.Status, got.Detail)
			}
			t.Log(got.Status, got.Detail)
		})
	}
}

// Test data predates v3; re-sign the fixture as historical v2 without changing
// either historical canonical encoder or the legacy verification assertions.
func makeHistoricalV2Fixture(t *testing.T, f *verifyFixture) {
	t.Helper()
	var rows []model.AuditCheckpoint
	if err := f.db.Order("seq").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	for i := range rows {
		cp := &rows[i]
		cp.AggScheme = model.AggSchemeV2
		cp.ToolCallIDFrom = nil
		cp.ToolCallIDTo = nil
		cp.ToolCallRowCount = nil
		cp.ToolCallAggHash = nil
		if i > 0 {
			h, err := CheckpointLinkHash(&rows[i-1])
			if err != nil {
				t.Fatal(err)
			}
			cp.PrevCheckpointHash = h
		}
		payload, err := CheckpointSignBytes(cp)
		if err != nil {
			t.Fatal(err)
		}
		_, cp.Signature = f.signer.Sign(payload)
		if err := f.db.Exec("UPDATE audit_checkpoints SET agg_scheme=?,tool_call_id_from=NULL,tool_call_id_to=NULL,tool_call_row_count=NULL,tool_call_agg_hash=NULL,prev_checkpoint_hash=?,signature=? WHERE id=?", cp.AggScheme, cp.PrevCheckpointHash, cp.Signature, cp.ID).Error; err != nil {
			t.Fatal(err)
		}
	}
}
