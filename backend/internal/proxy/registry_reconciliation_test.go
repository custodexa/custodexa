package proxy

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestRegistryReconciliationSymmetry 連線註冊完整性（session-reconciliation）：
// 以真 ConnectionRegistry 錨定 Register/Unregister 與孤兒清掃的存活契約——
// 登記中的 active session 不被收斂、反登記後即被收斂。兩個建線點
// （sshproxy/proxy handler）的呼叫點對稱性由 live 複驗覆蓋（真連線在
// 排程數輪後存活、斷線後收斂）
func TestRegistryReconciliationSymmetry(t *testing.T) {
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

	sess := &model.Session{
		SessionID: "recon-sym-1",
		Status:    model.SessionStatusActive,
		Protocol:  model.ProtocolSSH,
		UserID:    1,
		StartTime: time.Now().Add(-10 * time.Minute), // 已過寬限期
	}
	if err := db.Create(sess).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	registry := NewConnectionRegistry()
	registry.Register(sess.ID, func() error { return nil })
	svc := session.NewSessionReconciliationService(registry)

	// 登記中：清掃不得動它
	if n, err := svc.ReconcileOrphans(); err != nil || n != 0 {
		t.Fatalf("登記中的活連線不得被收斂：n=%d err=%v", n, err)
	}
	var got model.Session
	if err := db.First(&got, sess.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Status != model.SessionStatusActive {
		t.Fatalf("status = %s, want active（登記中不得誤殺）", got.Status)
	}

	// 反登記後：下一輪即收斂為 orphaned
	registry.Unregister(sess.ID)
	if n, err := svc.ReconcileOrphans(); err != nil || n != 1 {
		t.Fatalf("反登記後應被收斂：n=%d err=%v", n, err)
	}
	if err := db.First(&got, sess.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Status != model.SessionStatusDisconnected || got.EndReason != model.EndReasonOrphaned {
		t.Errorf("應為 disconnected/orphaned, got %s/%s", got.Status, got.EndReason)
	}
}
