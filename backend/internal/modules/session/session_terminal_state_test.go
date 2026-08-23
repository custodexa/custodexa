package session

import (
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupSessionTerminalStateDB 真 SQLite 會話環境（終態語義必須實跑 CAS 才算驗過）。
func setupSessionTerminalStateDB(t *testing.T) *gorm.DB {
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

// TestRevoke_ForceTerminatePreservesTerminalState 回歸：撤銷即斷線後，
// bridge/tunnel 自然清理呼叫 CloseWithReason 不得覆寫 Terminate 寫入的終態
// （status=disconnected、end_reason=revoked、duration）。以真 SQLite 全鏈驗
//
// **遷移說明（是否放寬：否）**：本測試原住 authz 的
// `access_request_service_test.go`，經 `AccessRequestService.Revoke` 觸發收線。
// authz→session 的具體型別相依反轉為 `SessionTerminator` 窄介面後，
// authz 的同包測試已無法 import `internal/service`（`import cycle not allowed in test`）。
// 拆法：**被測不變式本身（終態不被自然清理覆寫）與 authz 無關**，故在此直接對
// `SessionService.TerminateByUserAsset` 斷言；「Revoke 是否以正確引數委派收線」
// 另由 authz 側 `TestAccessRequest_Revoke/撤銷即斷線` 的引數精確斷言承接。
// 兩者相加涵蓋面與原本相同，且各自的失敗訊息更能指出真因。
func TestRevoke_ForceTerminatePreservesTerminalState(t *testing.T) {
	db := setupSessionTerminalStateDB(t)
	sessSvc := NewSessionService(nil)

	aid := uint(1)
	sess := &model.Session{SessionID: "term-1", Status: model.SessionStatusActive,
		Protocol: model.ProtocolSSH, UserID: 1, AssetID: &aid,
		StartTime: time.Now().Add(-10 * time.Minute)}
	if err := db.Create(sess).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// 撤銷即斷線（政策開啟時 authz 委派到此）
	n, err := sessSvc.TerminateByUserAsset(1, aid, model.EndReasonRevoked)
	if err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if n != 1 {
		t.Fatalf("應收線 1 個會話, got %d", n)
	}

	// 撤銷已設 disconnected+revoked。模擬 bridge/tunnel 結束後的自然清理：
	// CloseWithReason 應冪等（CAS status=active 落空），不覆寫終態
	err = sessSvc.CloseWithReason(sess.ID, "normal")
	if !errors.Is(err, ErrSessionAlreadyClosed) {
		t.Fatalf("自然清理應冪等回 ErrSessionAlreadyClosed, got %v", err)
	}

	var got model.Session
	db.First(&got, sess.ID)
	if got.Status != model.SessionStatusDisconnected {
		t.Fatalf("終態被覆寫: status=%s（應保持 disconnected）", got.Status)
	}
	if got.EndReason != model.EndReasonRevoked {
		t.Fatalf("end_reason 被覆寫: %s（應保持 revoked）", got.EndReason)
	}
}

// TestSessionService_IsActive High 回歸：轉發啟動前存活閘——
// active 回 true、被收線（disconnected/closed）或不存在回 false（fail-safe）
//
// **遷移說明（是否放寬：否）**：原住 authz 的 `access_request_service_test.go`
// 只是借用了那裡的 sqlite 夾具；被測對象自始至終是 `SessionService`，
// 與 authz 零關係。本次僅換夾具來源，斷言逐字未動。
func TestSessionService_IsActive(t *testing.T) {
	db := setupSessionTerminalStateDB(t)
	svc := NewSessionService(nil)

	act := &model.Session{SessionID: "act-1", Status: model.SessionStatusActive,
		Protocol: model.ProtocolSSH, UserID: 1, StartTime: time.Now()}
	db.Create(act)
	if !svc.IsActive(act.ID) {
		t.Fatal("active session 應回 true")
	}
	// 收線後（模擬撤銷/停用落窗）回 false
	db.Model(&model.Session{}).Where("id = ?", act.ID).
		Update("status", model.SessionStatusDisconnected)
	if svc.IsActive(act.ID) {
		t.Fatal("disconnected session 應回 false（存活閘攔下）")
	}
	if svc.IsActive(99999) {
		t.Fatal("不存在 session 應回 false（fail-safe）")
	}
}
