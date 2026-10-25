package audit

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 正式密鑰來源（key manager＋解封閘）下的事件驗證碼，以及段 2 之前寫下的事件在完整性服務
// 建立時由同一行程補章。
func TestPermissionEventIntegrityInit(t *testing.T) {
	db := newVersionedDB(t)
	if err := db.AutoMigrate(&model.PermissionStateEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	prev := GetAuditIntegrity()
	t.Cleanup(func() { registerAuditIntegrity(prev); DrainPendingPermissionStampsForTest() })
	registerAuditIntegrity(nil) // 段 2 之前：完整性服務尚未建立

	body := `{"restore":"body"}`
	e := &model.PermissionStateEvent{Seq: 1, Version: 3, Kind: model.PermEventRestore, OpID: "op-restore",
		BeforeDigest: "b", AfterDigest: stateHash([]byte(body)), Delta: `{"meta":{}}`, AfterBody: body,
		CreatedAt: time.Now().UTC()}
	e.Digest = permissionEventDigest(e)
	stampPermissionEvent(e)
	if e.IntegrityHMAC != "" {
		t.Fatal("沒有完整性服務時不得有驗證碼")
	}
	if err := db.Create(e).Error; err != nil {
		t.Fatalf("insert: %v", err)
	}

	svc, _ := newVersionedIntegrity(t, db) // InitAuditIntegrityVersioned：補章
	var got model.PermissionStateEvent
	if err := db.First(&got, e.ID).Error; err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.IntegrityHMAC == "" || got.KeyVersion != 1 {
		t.Fatalf("段 2 前寫下的事件應在完整性服務建立時補章，得 hmac=%q v%d", got.IntegrityHMAC, got.KeyVersion)
	}
	if !svc.VerifyPermissionEvent(&got) {
		t.Fatal("補上的驗證碼應可驗")
	}
	got.OpID = "op-other"
	got.Digest = permissionEventDigest(&got)
	if svc.VerifyPermissionEvent(&got) {
		t.Fatal("重算過摘要的竄改列不得通過驗證碼")
	}

	fresh := &model.PermissionStateEvent{Seq: 2, Kind: model.PermEventChange, OpID: "op-2", AfterBody: body,
		AfterDigest: stateHash([]byte(body)), Delta: `{}`}
	fresh.Digest = permissionEventDigest(fresh)
	if err := svc.StampPermissionEvent(fresh); err != nil || !svc.VerifyPermissionEvent(fresh) {
		t.Fatalf("現行密鑰蓋章後應可驗: %v", err)
	}
	fresh.KeyVersion = 99
	if svc.VerifyPermissionEvent(fresh) {
		t.Fatal("未知鑰版本不得通過")
	}
}
