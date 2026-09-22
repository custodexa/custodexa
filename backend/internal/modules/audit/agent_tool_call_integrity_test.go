package audit

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

func TestAgentToolCallHMAC(t *testing.T) {
	db := newVersionedDB(t)
	if err := db.AutoMigrate(&model.AgentToolCall{}); err != nil {
		t.Fatal(err)
	}
	s, km := newVersionedIntegrity(t, db)
	makeRow := func(seq uint) model.AgentToolCall {
		return model.AgentToolCall{Seq: seq, UserID: 1, AgentTokenID: 2, OwnerUserID: 3, Tool: "list_assets", ArgsRedacted: `{"asset_id":9,"password":"***MASKED***"}`, Decision: model.ToolCallPending}
	}
	a := makeRow(1)
	if err := db.Create(&a).Error; err != nil {
		t.Fatal(err)
	}
	if a.KeyVersion != 1 || !s.VerifyToolCall(&a) {
		t.Fatal("BeforeCreate did not stamp with current audit key")
	}
	if _, err := km.RotateAuditKey(); err != nil {
		t.Fatal(err)
	}
	b := makeRow(2)
	if err := db.Create(&b).Error; err != nil {
		t.Fatal(err)
	}
	if b.KeyVersion != 2 || !s.VerifyToolCall(&a) || !s.VerifyToolCall(&b) {
		t.Fatal("cross-version stamps invalid")
	}
	for name, mutate := range map[string]func(*model.AgentToolCall){
		"seq": func(r *model.AgentToolCall) { r.Seq++ }, "args": func(r *model.AgentToolCall) { r.ArgsRedacted = `{"asset_id":10}` },
		"result": func(r *model.AgentToolCall) { r.ResultExcerpt = "changed" }, "version": func(r *model.AgentToolCall) { r.KeyVersion = 99 },
		"decision": func(r *model.AgentToolCall) { r.Decision = model.ToolCallAllowed }, "empty stamp": func(r *model.AgentToolCall) { r.IntegrityHMAC = "" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := a
			mutate(&copy)
			if s.VerifyToolCall(&copy) {
				t.Fatal("tampering accepted")
			}
		})
	}
	if err := db.Exec("UPDATE agent_tool_calls SET result_excerpt=? WHERE id=?", "tampered", a.ID).Error; err != nil {
		t.Fatal(err)
	}
	r, err := s.VerifyToolCalls(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil || r.Checked != 2 || r.Passed != 1 || r.Mismatched != 1 {
		t.Fatal(r, err)
	}
	if db.Delete(&b).Error == nil || db.Model(&b).Update("decision", model.ToolCallAllowed).Error == nil {
		t.Fatal("generic mutation allowed")
	}
}

func TestAgentToolCallLedgerConcurrentPending(t *testing.T) {
	db := newVersionedDB(t)
	raw, _ := db.DB()
	raw.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AgentToolCall{}); err != nil {
		t.Fatal(err)
	}
	s, _ := newVersionedIntegrity(t, db)
	ledger := NewAgentToolCallLedger(db, s)
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ledger.Begin(context.Background(), AgentToolCallInput{PrincipalKind: model.KindAgent, UserID: 1, AgentTokenID: 2, OwnerUserID: 3, Tool: "list_assets", Args: map[string]interface{}{"password": "must-not-persist", "asset_id": 9}})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, total, err := ledger.Query(context.Background(), AgentToolCallFilter{Decision: model.ToolCallPending})
	if err != nil || total != n || len(rows) != n {
		t.Fatal(total, err)
	}
	seen := map[uint]bool{}
	for _, r := range rows {
		if seen[r.Seq] || r.Seq < 1 || r.Seq > n || r.MaskedCount != 0 || !s.VerifyToolCall(&r) || strings.Contains(r.ArgsRedacted, "must-not-persist") {
			t.Fatalf("invalid ledger row seq=%d", r.Seq)
		}
		seen[r.Seq] = true
	}
}

func TestAgentToolCallHMACJSONBNumbers(t *testing.T) {
	for _, pair := range [][2]string{
		{`{"n":1e30}`, `{"n":1000000000000000000000000000000}`},
		{`{"n":[1.00,-0,0.001200]}`, `{"n":[1,0,12e-4]}`},
		{`{"n":9007199254740993}`, `{"n":9007199254740993.0}`},
	} {
		a, err := canonicalToolCallArgs(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := canonicalToolCallArgs(pair[1])
		if err != nil || string(a) != string(b) {
			t.Fatal(string(a), string(b), err)
		}
	}
}
