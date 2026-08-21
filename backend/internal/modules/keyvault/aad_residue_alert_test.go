package keyvault_test

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
)

// 啟動哨兵的驗收（release-transitional-cleanup D6）。
//
// 語義已自「遷移進度提示」改為「不可能態警報」：AAD 恆強制後，非 `enc:a1` 的
// 登記欄位值只可能來自程式缺陷或繞過 API 的資料庫直寫。哨兵屬**資料層
// fail-visible**——記警告＋開列失效事件，不阻塞啟動、不提供遷移入口、不自動改寫。

// setupAADAlertFixture 建立可上報失效事件的環境；db 內含發佈前過渡格式殘值
func setupAADAlertFixture(t *testing.T) (*gorm.DB, *keyvault.KeyManagerService, *audit.AuditFailureService) {
	t.Helper()
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	aadFixture(t, db, km)
	if err := db.AutoMigrate(&model.AuditFailureEvent{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	af := audit.InitAuditFailure(db, policy.NewSecurityPolicyService(db))
	return db, km, af
}

// openEventCause 目前開列中的殘值事件原因碼（無則空字串）
func openEventCause(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var ev model.AuditFailureEvent
	err := db.Where("mechanism = ? AND ended_at IS NULL", model.MechanismAADResidue).
		Order("id desc").Take(&ev).Error
	if err != nil {
		return ""
	}
	return ev.CauseCode
}

// TestAADResidueAlertImpossibleState 殘值>0 → 開列**單一**不可能態 cause。
//
// 釘住 cause 收斂：舊的 permissive／strict-mismatch 兩值描述的是已不存在的
// 模式狀態，SHALL NOT 被沿用。
func TestAADResidueAlertImpossibleState(t *testing.T) {
	db, _, af := setupAADAlertFixture(t)

	keyvault.ReportAADResidueOnStartup(db, af)
	if got := openEventCause(t, db); got != model.CauseAADResidueImpossibleState {
		t.Fatalf("殘值>0 MUST 開列 %s，實得 %q", model.CauseAADResidueImpossibleState, got)
	}
}

// TestAADResidueAlertSilentWhenClean 全部登記欄位皆為終態格式時不開列，
// 且既有開列事件自動結案（狀態可由現查謂詞導出）。
func TestAADResidueAlertSilentWhenClean(t *testing.T) {
	db, _, af := setupAADAlertFixture(t)

	// 先讓它開列，再把殘值清成終態格式，確認會自動結案
	keyvault.ReportAADResidueOnStartup(db, af)
	if openEventCause(t, db) == "" {
		t.Fatal("前置條件不成立：fixture 應含殘值並開列事件")
	}
	for _, stmt := range []string{
		"UPDATE assets SET password_enc = 'enc:a1:v1:AAAA'",
		"UPDATE asset_accounts SET password_enc = 'enc:a1:v1:AAAA', private_key_enc = 'enc:a1:v1:AAAA'",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("清理殘值失敗: %v", err)
		}
	}
	keyvault.ReportAADResidueOnStartup(db, af)
	if got := openEventCause(t, db); got != "" {
		t.Fatalf("殘值歸零後 MUST 自動結案，實得開列中的 %q", got)
	}
}

// TestAADResidueAlertNotAnExecutionPath 哨兵**不得**改寫任何值：
// 呼叫前後殘值筆數與密文內容皆須不變（fail-visible，不是自動執行路徑）。
func TestAADResidueAlertNotAnExecutionPath(t *testing.T) {
	db, _, af := setupAADAlertFixture(t)
	var before string
	if err := db.Raw("SELECT password_enc FROM assets WHERE id = 1").Scan(&before).Error; err != nil {
		t.Fatalf("讀取: %v", err)
	}
	_, beforeTotal, err := keyvault.AADResidueLowerBound(db)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if beforeTotal == 0 {
		t.Fatal("前置條件不成立：fixture 應含殘值，否則本斷言可由全零假綠")
	}

	keyvault.ReportAADResidueOnStartup(db, af)

	var after string
	if err := db.Raw("SELECT password_enc FROM assets WHERE id = 1").Scan(&after).Error; err != nil {
		t.Fatalf("讀取: %v", err)
	}
	_, afterTotal, err := keyvault.AADResidueLowerBound(db)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if before != after || beforeTotal != afterTotal {
		t.Fatal("啟動哨兵 MUST NOT 改寫任何值（殘值與密文內容須原樣不動）")
	}
}
