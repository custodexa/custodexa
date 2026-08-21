package audit

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newVersionedDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}, &model.IntegrityBaseline{}, &model.DataKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func newVersionedIntegrity(t *testing.T, db *gorm.DB) (*AuditIntegrityService, *keyvault.KeyManagerService) {
	t.Helper()
	kek, err := crypto.NewEnvKEKProvider(kmTestKey(1))
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	km, err := keyvault.InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("km: %v", err)
	}
	svc, err := InitAuditIntegrityVersioned(db, km)
	if err != nil {
		t.Fatalf("integrity: %v", err)
	}
	return svc, km
}

func versionedTestLog(user string) *model.AuditLog {
	return &model.AuditLog{
		CreatedAt: time.Now(), Action: model.ActionUpdate, Resource: model.ResourceUser,
		Status: model.StatusSuccess, UserID: 3, Username: user, ClientIP: "10.0.0.1",
	}
}

// TestVersionedStampNewRowsUseV1 新列以 v1 蓋章並記 key_version
func TestVersionedStampNewRowsUseV1(t *testing.T) {
	db := newVersionedDB(t)
	svc, _ := newVersionedIntegrity(t, db)

	l := versionedTestLog("admin")
	svc.StampOne(l)
	if l.KeyVersion != 1 {
		t.Fatalf("新列應記 v1，得 v%d", l.KeyVersion)
	}
	if l.IntegrityHMAC == "" || len(l.IntegrityHMAC) != 64 {
		t.Fatalf("HMAC 應為 64 hex，得 %q", l.IntegrityHMAC)
	}
}

// TestVersionedJWTRotationNoFalsePositive JWT 輪替 SHALL NOT 影響任何列的驗證
// 結果——蓋章鑰為系統生成之版本化鑰，與 JWT_SECRET 無任何派生關係。
//
// 註：原測試以「v0 legacy 快照凍結於 DB」為載體；v0 快照已於
// release-transitional-cleanup D4 拆除，版本鏈自 v1 起，故改以「重啟後
// 同一組 v1 列仍全數驗過」表達同一性質（JWT 未進入蓋章鑰的任何路徑）。
func TestVersionedJWTRotationNoFalsePositive(t *testing.T) {
	db := newVersionedDB(t)
	svc1, _ := newVersionedIntegrity(t, db)

	for _, user := range []string{"user-a", "user-b"} {
		row := versionedTestLog(user)
		svc1.StampOne(row)
		if row.KeyVersion != 1 {
			t.Fatalf("蓋章 MUST 記 v1，得 v%d", row.KeyVersion)
		}
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("create row: %v", err)
		}
	}

	// 模擬 JWT_SECRET 輪替後重啟（蓋章鑰來源與其無關，故重載即可）
	svc2, _ := newVersionedIntegrity(t, db)
	report, err := svc2.Verify(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Checked != 2 || report.Passed != 2 || report.Mismatched != 0 {
		t.Fatalf("JWT 輪替後應全數驗過：checked=%d passed=%d mismatched=%d",
			report.Checked, report.Passed, report.Mismatched)
	}
}

// TestVersionedTamperedKeyVersionDetected 竄改 key_version 取錯鑰重算必不符
func TestVersionedTamperedKeyVersionDetected(t *testing.T) {
	db := newVersionedDB(t)
	svc, _ := newVersionedIntegrity(t, db)

	l := versionedTestLog("victim")
	svc.StampOne(l)
	if err := db.Create(l).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	// BeforeUpdate 守衛擋 ORM 路徑，模擬 DB 直改。
	// key_version=0 在終態下**必然**取不到鑰（系統無 v0 鑰）——這正是
	// 「DB DEFAULT 0＝繞過 hook 直插列預設落入不符」的 fail-visible 語義
	if err := db.Exec("UPDATE audit_logs SET key_version = 0 WHERE id = ?", l.ID).Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}

	report, err := svc.Verify(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatched != 1 {
		t.Fatalf("竄改版本應判不符，得 mismatched=%d", report.Mismatched)
	}
}

// TestVersionedUnknownVersionDetected 引用不存在版本的列判不符（不 panic 不誤過）
func TestVersionedUnknownVersionDetected(t *testing.T) {
	db := newVersionedDB(t)
	svc, _ := newVersionedIntegrity(t, db)

	l := versionedTestLog("ghost")
	svc.StampOne(l)
	if err := db.Create(l).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.Exec("UPDATE audit_logs SET key_version = 99 WHERE id = ?", l.ID).Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}

	report, err := svc.Verify(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatched != 1 {
		t.Fatalf("未知版本應判不符，得 mismatched=%d", report.Mismatched)
	}
}

// TestRotateAuditKeyCrossVersionVerify 蓋章鑰輪替不動歷史：v1/v2 兩代列全數驗過
// （v0 快照已於 release-transitional-cleanup D4 拆除，版本鏈自 v1 起）
func TestRotateAuditKeyCrossVersionVerify(t *testing.T) {
	db := newVersionedDB(t)
	svc, km := newVersionedIntegrity(t, db)

	// v1 列
	v1row := versionedTestLog("v1-user")
	svc.StampOne(v1row)
	if v1row.KeyVersion != 1 {
		t.Fatalf("應為 v1，得 %d", v1row.KeyVersion)
	}
	if err := db.Create(v1row).Error; err != nil {
		t.Fatalf("v1: %v", err)
	}

	// 輪替 → v2 列
	result, err := km.RotateAuditKey()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if result.ToVersion != 2 {
		t.Fatalf("應輪至 v2：%+v", result)
	}
	v2row := versionedTestLog("v2-user")
	svc.StampOne(v2row)
	if v2row.KeyVersion != 2 {
		t.Fatalf("輪替後新章應為 v2，得 %d", v2row.KeyVersion)
	}
	if err := db.Create(v2row).Error; err != nil {
		t.Fatalf("v2: %v", err)
	}

	// 歷史列 HMAC 未被改動（不重算）
	var v1Stored string
	db.Raw("SELECT integrity_hmac FROM audit_logs WHERE id = ?", v1row.ID).Scan(&v1Stored)
	if v1Stored != v1row.IntegrityHMAC {
		t.Fatal("輪替不得重算歷史章")
	}

	report, err := svc.Verify(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Checked != 2 || report.Passed != 2 || report.Mismatched != 0 {
		t.Fatalf("v1/v2 應全數驗過：%+v", report)
	}
}

// 註：本測試自 internal/service/key_manager_rotation_test.go 隨 W4 搬包遷入
// （modular-architecture 4.11）。它驗的是蓋章鑰輪替後的跨版本驗章，主題屬 audit
// 完整性；留在原處需把 newVersionedDB／newVersionedIntegrity／versionedTestLog
// 三個夾具複製過去，而那三者本就是本檔的東西。內容逐字未改。
