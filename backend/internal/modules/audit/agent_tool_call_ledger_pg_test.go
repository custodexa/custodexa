package audit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestAgentToolCallLedgerConcurrentPostgres(t *testing.T) {
	db, dsn := purgeSchemaDB(t, fmt.Sprintf("w31_seq_%d", time.Now().UnixNano()))
	if err := db.AutoMigrate(&model.AgentToolCall{}); err != nil {
		t.Fatal(err)
	}
	other, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { sqlDB, _ := other.DB(); sqlDB.Close() }()
	key := []byte("ledger-pg-sequence-test-key")
	stamp := &AuditIntegrityService{activeFn: func() (int, []byte) { return 1, key }, keyFn: func(v int) []byte {
		if v != 1 {
			return nil
		}
		return key
	}}
	writers := []*AgentToolCallLedger{NewAgentToolCallLedger(db, stamp), NewAgentToolCallLedger(other, stamp)}
	const n = 32
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := writers[i%2].Begin(context.Background(), AgentToolCallInput{PrincipalKind: model.KindAgent, UserID: 9, AgentTokenID: 8, OwnerUserID: 7, Tool: "list_assets", Args: map[string]interface{}{"asset_id": 1e30}})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var got struct{ N, Distinct, Lo, Hi int64 }
	if err := db.Raw("SELECT count(*) n,count(DISTINCT seq) distinct,min(seq) lo,max(seq) hi FROM agent_tool_calls WHERE user_id=9").Scan(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.N != n || got.Distinct != n || got.Lo != 1 || got.Hi != n {
		t.Fatalf("sequence=%+v", got)
	}
	r, err := stamp.VerifyToolCalls(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil || r.Passed != n || r.Mismatched != 0 {
		t.Fatal(r, err)
	}
	t.Log("32 simultaneous Begin calls over two DB pools: distinct seq 1..32; PostgreSQL JSONB round-trip HMAC valid")
}

func TestCheckpointSealToolCallsPostgres(t *testing.T) {
	db, _ := purgeSchemaDB(t, fmt.Sprintf("w31_seal_%d", time.Now().UnixNano()))
	seal, signer := newCheckpointService(t, db, nil, nil)
	if err := seal.EnsureGenesis(); err != nil {
		t.Fatal(err)
	}
	key := []byte("ledger-pg-seal-test-key")
	integrity := &AuditIntegrityService{activeFn: func() (int, []byte) { return 1, key }, keyFn: func(v int) []byte {
		if v != 1 {
			return nil
		}
		return key
	}}
	tx := db.WithContext(model.WithToolCallStamp(context.Background(), integrity.StampToolCall)).Begin()
	defer tx.Rollback()
	row := model.AgentToolCall{Seq: 1, UserID: 1, AgentTokenID: 2, OwnerUserID: 3, Tool: "list_assets", ArgsRedacted: `{"asset_id":1e30}`, Decision: model.ToolCallPending}
	if err := tx.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		cp  *model.AuditCheckpoint
		err error
	}
	sealed := make(chan outcome, 1)
	go func() { cp, err := seal.SealNow(); sealed <- outcome{cp, err} }()
	// Observe the real SHARE lock waiting for this uncommitted INSERT.
	deadline := time.Now().Add(3 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		var count int64
		if err := db.Raw("SELECT count(*) FROM pg_locks WHERE relation='agent_tool_calls'::regclass AND mode='ShareLock' AND NOT granted").Scan(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			blocked = true
			break
		}
		select {
		case got := <-sealed:
			t.Fatalf("sealed before commit: %+v", got)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("sealer never waited for in-flight INSERT")
	}
	if err := tx.Commit().Error; err != nil {
		t.Fatal(err)
	}
	var got outcome
	select {
	case got = <-sealed:
	case <-time.After(3 * time.Second):
		t.Fatal("sealer remained blocked")
	}
	if got.err != nil || *got.cp.ToolCallRowCount != 1 || *got.cp.ToolCallIDTo != row.ID {
		t.Fatal(got)
	}
	ledger := NewAgentToolCallLedger(db, integrity)
	if _, err := ledger.Complete(context.Background(), row.ID, AgentToolCallResult{Decision: model.ToolCallAllowed, Status: "success", RedactedOutput: "caller-visible result"}); err != nil {
		t.Fatal(err)
	}
	verifier := NewCheckpointVerifier(db, seal, NewCheckpointPurger(db, signer), integrity, nil)
	report, err := verifier.VerifyContentBySeq(got.cp.Seq, got.cp.Seq)
	if err != nil || len(report.Intervals) != 1 || report.Intervals[0].Status != IntervalStatusPassed {
		t.Fatal(report, err)
	}
	t.Log("in-flight INSERT waited; pending included; sealed result completion and PostgreSQL JSONB HMAC verified")
}
