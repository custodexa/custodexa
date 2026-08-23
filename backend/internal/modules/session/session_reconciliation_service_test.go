package session

import (
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// fakeLiveness map 型存活查詢，模擬 ConnectionRegistry.Has
type fakeLiveness struct{ alive map[uint]bool }

func (f *fakeLiveness) Has(sessionID uint) bool { return f.alive[sessionID] }

func setupReconciliationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

var reconSeedSeq int

func seedReconSession(t *testing.T, db *gorm.DB, status model.SessionStatus, start time.Time) *model.Session {
	t.Helper()
	reconSeedSeq++
	sess := &model.Session{
		SessionID: fmt.Sprintf("recon-%d-%d", reconSeedSeq, start.UnixNano()),
		Status:    status,
		Protocol:  model.ProtocolSSH,
		UserID:    1,
		StartTime: start,
	}
	if err := db.Create(sess).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return sess
}

func reloadSession(t *testing.T, db *gorm.DB, id uint) *model.Session {
	t.Helper()
	var got model.Session
	if err := db.First(&got, id).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	return &got
}

// TestReconcileStartup_SweepsAllActive 啟動清掃：全部殘留 active 收斂為
// backend_restart，已結束的不動；再跑一次 no-op
func TestReconcileStartup_SweepsAllActive(t *testing.T) {
	db := setupReconciliationDB(t)
	svc := NewSessionReconciliationService(nil)

	now := time.Now()
	a1 := seedReconSession(t, db, model.SessionStatusActive, now.Add(-time.Hour))
	a2 := seedReconSession(t, db, model.SessionStatusActive, now.Add(-time.Minute))
	closed := seedReconSession(t, db, model.SessionStatusClosed, now.Add(-2*time.Hour))

	n, err := svc.ReconcileStartup()
	if err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if n != 2 {
		t.Fatalf("收斂數 = %d, want 2", n)
	}

	for _, id := range []uint{a1.ID, a2.ID} {
		got := reloadSession(t, db, id)
		if got.Status != model.SessionStatusDisconnected {
			t.Errorf("ID=%d status = %s, want disconnected", id, got.Status)
		}
		if got.EndReason != model.EndReasonBackendRestart {
			t.Errorf("ID=%d end_reason = %s, want backend_restart", id, got.EndReason)
		}
		if got.EndTime == nil {
			t.Errorf("ID=%d end_time 應被寫入", id)
		}
		if got.Duration < 0 {
			t.Errorf("ID=%d duration = %d 不得為負", id, got.Duration)
		}
	}

	if got := reloadSession(t, db, closed.ID); got.Status != model.SessionStatusClosed {
		t.Errorf("已結束的 session 不得被改動：status = %s", got.Status)
	}

	// 無殘留時 no-op
	n, err = svc.ReconcileStartup()
	if err != nil || n != 0 {
		t.Errorf("第二輪應 no-op：n = %d, err = %v", n, err)
	}
}

// TestReconcileStartup_NegativeDurationClamped 時鐘異常（未來 StartTime）夾 0
func TestReconcileStartup_NegativeDurationClamped(t *testing.T) {
	db := setupReconciliationDB(t)
	svc := NewSessionReconciliationService(nil)

	sess := seedReconSession(t, db, model.SessionStatusActive, time.Now().Add(time.Hour))

	if _, err := svc.ReconcileStartup(); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if got := reloadSession(t, db, sess.ID); got.Duration != 0 {
		t.Errorf("duration = %d, want 0", got.Duration)
	}
}

// TestReconcileOrphans 孤兒偵測三態：過寬限期無活連線→收斂、
// 寬限期內→跳過、有活連線→不動
func TestReconcileOrphans(t *testing.T) {
	db := setupReconciliationDB(t)

	now := time.Now()
	orphan := seedReconSession(t, db, model.SessionStatusActive, now.Add(-10*time.Minute))
	fresh := seedReconSession(t, db, model.SessionStatusActive, now.Add(-30*time.Second))
	live := seedReconSession(t, db, model.SessionStatusActive, now.Add(-10*time.Minute))

	svc := NewSessionReconciliationService(&fakeLiveness{alive: map[uint]bool{live.ID: true}})

	n, err := svc.ReconcileOrphans()
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if n != 1 {
		t.Fatalf("收斂數 = %d, want 1（僅孤兒）", n)
	}

	if got := reloadSession(t, db, orphan.ID); got.Status != model.SessionStatusDisconnected || got.EndReason != model.EndReasonOrphaned {
		t.Errorf("孤兒應收斂為 disconnected/orphaned, got %s/%s", got.Status, got.EndReason)
	}
	if got := reloadSession(t, db, fresh.ID); got.Status != model.SessionStatusActive {
		t.Errorf("寬限期內不得誤殺：status = %s", got.Status)
	}
	if got := reloadSession(t, db, live.ID); got.Status != model.SessionStatusActive {
		t.Errorf("有活連線不得誤殺：status = %s", got.Status)
	}
}

// TestNewSessionReconciliationService_TypedNil typed-nil liveness 正規化：
// 傳入 nil 指標不得使後續 Has() panic
func TestNewSessionReconciliationService_TypedNil(t *testing.T) {
	setupReconciliationDB(t)
	var nilReg *fakeLiveness // typed nil
	svc := NewSessionReconciliationService(nilReg)

	// ReconcileOrphans 不得 panic（liveness 已正規化為 interface nil，sweep 跳過 Has）
	if _, err := svc.ReconcileOrphans(); err != nil {
		t.Fatalf("typed-nil liveness 下 ReconcileOrphans 應正常返回, err=%v", err)
	}
}

// TestReconcile_KeysetPagination 超過單批上限（500）仍全數收斂且工作量有界
func TestReconcile_KeysetPagination(t *testing.T) {
	db := setupReconciliationDB(t)
	svc := NewSessionReconciliationService(nil)

	start := time.Now().Add(-time.Hour)
	rows := make([]model.Session, 0, 505)
	for i := 0; i < 505; i++ {
		rows = append(rows, model.Session{
			SessionID: fmt.Sprintf("recon-batch-%d", i),
			Status:    model.SessionStatusActive,
			Protocol:  model.ProtocolSSH,
			UserID:    1,
			StartTime: start,
		})
	}
	if err := db.CreateInBatches(rows, 100).Error; err != nil {
		t.Fatalf("seed batch: %v", err)
	}

	n, err := svc.ReconcileStartup()
	if err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if n != 505 {
		t.Fatalf("收斂數 = %d, want 505（跨批次）", n)
	}

	var remain int64
	if err := db.Model(&model.Session{}).Where("status = ?", model.SessionStatusActive).Count(&remain).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if remain != 0 {
		t.Errorf("殘留 active = %d, want 0", remain)
	}
}
