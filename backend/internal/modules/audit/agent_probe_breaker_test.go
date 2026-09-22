package audit

import (
	"context"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"sync"
	"testing"
	"time"
)

func probeFixture(t *testing.T, db *gorm.DB) *ProbeBreaker {
	t.Helper()
	if err := db.AutoMigrate(&model.User{}, &model.AgentProbeEvent{}, &model.CommandAlert{}, &model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	u := model.User{ID: 2, Username: "agent"}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	deps := ProbeBreakerDependencies{
		LockPrincipal: func(tx *gorm.DB, id uint) (uint, error) {
			var u model.User
			err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&u, id).Error
			return 1, err
		},
		Classify: func(tx *gorm.DB, u, a uint) (string, error) {
			if a == 98 {
				return "revoked", nil
			}
			if a == 99 {
				return "retired", nil
			}
			return "never_visible", nil
		},
		Trip: func(tx *gorm.DB, u, k uint, at time.Time) (bool, error) {
			r := tx.Model(&model.User{}).Where("id=? AND breaker_pending_at IS NULL", u).Update("breaker_pending_at", at)
			return r.RowsAffected == 1, r.Error
		},
		Finish: func(uint) {}, Limits: func() (int, int) { return 3, 300 }, Notify: func(uint, notifycat.Event, map[string]string) {},
	}
	return NewProbeBreaker(db, NewTxSink(), NewAlertRecorder(db), deps)
}
func probeSQLite(t *testing.T) *ProbeBreaker {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sql, _ := db.DB()
	sql.SetMaxOpenConns(1)
	t.Cleanup(func() { sql.Close() })
	return probeFixture(t, db)
}
func TestProbeBreakerCount(t *testing.T) {
	s := probeSQLite(t)
	for i, a := range []uint{98, 99, 1, 1, 2, 3} {
		r, err := s.RecordDenied(context.Background(), 2, 1, a, "GET /assets/:id")
		if err != nil {
			t.Fatal(err)
		}
		want := []int64{0, 0, 1, 1, 2, 3}[i]
		if r.Count != want || r.Tripped != (i == 5) {
			t.Fatalf("step=%d got=%+v want=%d", i, r, want)
		}
	}
	s.now = func() time.Time { return time.Now().Add(301 * time.Second) }
	r, err := s.RecordDenied(context.Background(), 2, 1, 4, "GET /assets/:id")
	if err != nil || r.Count != 1 {
		t.Fatal(r, err)
	}
}
func TestProbeBreakerCountConcurrentPostgres(t *testing.T) {
	db, dsn := purgeSchemaDB(t, fmt.Sprintf("w32_probe_%d", time.Now().UnixNano()))
	// The harness creates only two alert columns; rebuild this test-owned table.
	if err := db.Exec("DROP TABLE command_alerts").Error; err != nil {
		t.Fatal(err)
	}
	s := probeFixture(t, db)
	other, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d, _ := other.DB(); d.Close() }()
	services := []*ProbeBreaker{s, NewProbeBreaker(other, NewTxSink(), NewAlertRecorder(other), s.deps)}
	errs := make(chan error, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := services[i%2].RecordDenied(context.Background(), 2, 1, 1, "GET /assets/:id")
			if err == nil && (r.Count != 1 || r.Tripped) {
				err = fmt.Errorf("duplicate overcount: %+v", r)
			}
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
	var count int64
	db.Model(&model.CommandAlert{}).Count(&count)
	if count != 0 {
		t.Fatal(count)
	}
	t.Log("32 concurrent events through two pools: 1 distinct asset, 0 trips")
}
func TestBreakerAlert(t *testing.T) {
	s := probeSQLite(t)
	notified := 0
	closed := 0
	s.deps.Notify = func(owner uint, e notifycat.Event, p map[string]string) {
		notified++
		if owner != 1 || e != notifycat.EventAgentBreakerTripped || p["owner_id"] != "1" || p["token_id"] != "7" {
			t.Error(owner, e, p)
		}
	}
	s.deps.Finish = func(id uint) {
		closed++
		if id != 7 {
			t.Error(id)
		}
	}
	for _, a := range []uint{1, 2, 3, 4} {
		if _, err := s.RecordDenied(context.Background(), 2, 7, a, "GET /assets/:id"); err != nil {
			t.Fatal(err)
		}
	}
	var alerts []model.CommandAlert
	s.db.Find(&alerts)
	if len(alerts) != 1 || alerts[0].Kind != model.AlertKindAgentBreaker || alerts[0].SessionID != 0 || notified != 1 || closed != 1 {
		t.Fatal(alerts, notified, closed)
	}
	var count int64
	s.db.Model(&model.AuditLog{}).Where("resource=? AND action=?", model.ResourceAgentToken, model.ActionSuspend).Count(&count)
	if count != 1 {
		t.Fatal(count)
	}
	var null int
	s.db.Raw("SELECT CASE WHEN session_id IS NULL THEN 1 ELSE 0 END FROM command_alerts").Scan(&null)
	if null != 1 {
		t.Fatal("session not NULL")
	}
}
func TestProbeBreakerTripAtomicRollback(t *testing.T) {
	s := probeSQLite(t)
	s.deps.Limits = func() (int, int) { return 1, 300 }
	s.db.Migrator().DropTable(&model.CommandAlert{})
	if _, err := s.RecordDenied(context.Background(), 2, 7, 1, "GET /assets/:id"); err == nil {
		t.Fatal("missing alert storage accepted")
	}
	var u model.User
	s.db.First(&u, 2)
	var count int64
	s.db.Model(&model.AgentProbeEvent{}).Count(&count)
	if u.BreakerPendingAt != nil || count != 0 {
		t.Fatal("partial trip committed", u.BreakerPendingAt, count)
	}
}
