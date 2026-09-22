package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/custodexa/backend/internal/model"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLedgerPendingFirst(t *testing.T) {
	db := newVersionedDB(t)
	if err := db.AutoMigrate(&model.AgentToolCall{}); err != nil {
		t.Fatal(err)
	}
	integrity, km := newVersionedIntegrity(t, db)
	ledger := NewAgentToolCallLedger(db, integrity)
	in := AgentToolCallInput{PrincipalKind: model.KindAgent, UserID: 1, AgentTokenID: 2, OwnerUserID: 3, Tool: "list_assets", Args: map[string]interface{}{"password": "secret"}}
	row, err := ledger.Begin(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("exists before forwarding", func(t *testing.T) {
		var saved model.AgentToolCall
		if err := db.First(&saved, row.ID).Error; err != nil || saved.Decision != model.ToolCallPending || strings.Contains(saved.ArgsRedacted, "secret") || !integrity.VerifyToolCall(&saved) {
			t.Fatal(saved, err)
		}
	})
	if _, err := km.RotateAuditKey(); err != nil {
		t.Fatal(err)
	}
	output := strings.Repeat("結果", 600)
	result := AgentToolCallResult{Decision: model.ToolCallAllowed, Status: "success", RedactedOutput: output, DurationMS: 5}
	done, err := ledger.Complete(context.Background(), row.ID, result)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("same row after result and key rotation", func(t *testing.T) {
		var count int64
		db.Model(&model.AgentToolCall{}).Count(&count)
		sum := sha256.Sum256([]byte(output))
		if count != 1 || done.ID != row.ID || done.KeyVersion != row.KeyVersion || done.IntegrityHMAC == row.IntegrityHMAC || !integrity.VerifyToolCall(done) || done.ResultDigest != hex.EncodeToString(sum[:]) || len(done.ResultExcerpt) > 2048 || !utf8.ValidString(done.ResultExcerpt) || done.MaskedCount != 0 {
			t.Fatal(done, count)
		}
		if _, err := ledger.Complete(context.Background(), row.ID, result); err == nil {
			t.Fatal("duplicate completion allowed")
		}
	})
	t.Run("aborted result remains queryable pending", func(t *testing.T) {
		pending, err := ledger.Begin(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := ledger.Complete(ctx, pending.ID, result); err == nil {
			t.Fatal("aborted completion succeeded")
		}
		rows, n, err := ledger.Query(context.Background(), AgentToolCallFilter{Decision: model.ToolCallPending})
		if err != nil || n != 1 || rows[0].ID != pending.ID || !integrity.VerifyToolCall(&rows[0]) {
			t.Fatal(rows, n, err)
		}
	})
	t.Run("immutable fields rejected even in completion scope", func(t *testing.T) {
		for _, col := range []string{"id", "seq", "user_id", "agent_token_id", "access_request_id", "session_id", "on_behalf_of_user_id", "owner_user_id", "tool", "args_redacted", "created_at", "key_version"} {
			if err := db.WithContext(model.WithToolCallCompletion(context.Background())).Model(&model.AgentToolCall{}).Where("id=?", row.ID).Updates(map[string]interface{}{col: 99}).Error; err == nil {
				t.Fatal("immutable update allowed", col)
			}
		}
	})
	t.Run("tampered pending is not blessed", func(t *testing.T) {
		pending, err := ledger.Begin(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Exec("UPDATE agent_tool_calls SET result_excerpt='tampered' WHERE id=?", pending.ID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.Complete(context.Background(), pending.ID, result); err == nil {
			t.Fatal("invalid row restamped")
		}
	})
}

func TestCheckpointSealToolCallsPendingCompletion(t *testing.T) {
	f := setupVerifyFixture(t)
	ledger := NewAgentToolCallLedger(f.db, f.integrity)
	in := AgentToolCallInput{PrincipalKind: model.KindAgent, UserID: 1, AgentTokenID: 2, OwnerUserID: 3, Tool: "list_assets"}
	row, err := ledger.Begin(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatal(err)
	}
	if cp.AggScheme != model.AggSchemeV3 || *cp.ToolCallIDFrom != 1 || *cp.ToolCallIDTo != row.ID || *cp.ToolCallRowCount != 1 {
		t.Fatal(cp)
	}
	payload, err := CheckpointSignBytes(cp)
	if err != nil {
		t.Fatal(err)
	}
	done, err := ledger.Complete(context.Background(), row.ID, AgentToolCallResult{Decision: model.ToolCallDenied, DenialCode: "RULE_TEST", Status: "denied", RedactedOutput: "visible denial"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.integrity.VerifyToolCall(done) || f.statusOf(t, cp.Seq).Status != IntervalStatusPassed {
		t.Fatal("sealed completion broke evidence")
	}
	var saved model.AuditCheckpoint
	if err := f.db.First(&saved, cp.ID).Error; err != nil {
		t.Fatal(err)
	}
	after, _ := CheckpointSignBytes(&saved)
	if string(payload) != string(after) || cp.Signature != saved.Signature {
		t.Fatal("existing checkpoint rewritten")
	}
	empty, err := f.seal.SealNow()
	if err != nil {
		t.Fatal(err)
	}
	if *empty.ToolCallIDFrom != row.ID+1 || *empty.ToolCallIDTo != row.ID || *empty.ToolCallRowCount != 0 {
		t.Fatal("empty interval wrong", empty)
	}
	next, err := ledger.Begin(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	nextCP, err := f.seal.SealNow()
	if err != nil {
		t.Fatal(err)
	}
	if *nextCP.ToolCallIDFrom != row.ID+1 || *nextCP.ToolCallIDTo != next.ID || *nextCP.ToolCallRowCount != 1 || f.statusOf(t, nextCP.Seq).Status != IntervalStatusPassed {
		t.Fatal("range did not advance", nextCP)
	}
}

func TestCheckpointToolCallFailClose(t *testing.T) {
	f := setupVerifyFixture(t)
	before, err := f.seal.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Exec("DROP TABLE agent_tool_calls").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := f.seal.SealNow(); err == nil {
		t.Fatal("missing ledger silently sealed")
	}
	after, err := f.seal.Latest()
	if err != nil || after.Seq != before.Seq {
		t.Fatal("failed seal advanced chain", after, err)
	}
}
