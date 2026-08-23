package identity

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// LDAP env→DB seed 的逐格覆蓋。
//
// 覆蓋矩陣：marker 有無 × 表空／軟刪／live × env 開關；外加
// `LDAP_ENABLED=1`、最小 5 鍵得預設值、密碼為密文非明文、基礎設施失敗不寫
// marker（可重試）、UI 建立的列被硬刪後不回灌。

// newLDAPSeedDB 建 seed 測試庫：ldap_directories＋audit_logs＋schema_migrations。
//
// **表由 AutoMigrate 建**是測試庫的刻意例外——生產走 versioned migration
// （CHECK 約束需求，見 MigrateLDAPDirectories 註解）；seed 的判定邏輯只依賴
// 表存在與列數，不依賴 CHECK，故此處以形狀等價的表即可。
// DB 層不變式的驗證在 repository 的 pg-gated 測試。
func newLDAPSeedDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫（本專案既有 flaky 真因，ff51836）
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.LDAPDirectory{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(
		"CREATE TABLE schema_migrations (version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)").Error; err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	return db
}

// newLDAPSeedCodec 真 keyvault.KeyManagerService（密文須真的可解，才測得到「非明文」那一格）
func newLDAPSeedCodec(t *testing.T, db *gorm.DB) *keyvault.KeyManagerService {
	t.Helper()
	if err := db.AutoMigrate(&model.DataKey{}); err != nil {
		t.Fatalf("migrate data_keys: %v", err)
	}
	key := kmTestKey(0x31)
	kek, err := crypto.NewEnvKEKProvider(key)
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	km, err := keyvault.InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("keyvault.InitKeyManager: %v", err)
	}
	return km
}

// setLDAPEnv 設定 env（t.Setenv 自動還原）
func setLDAPEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	// 全部 LDAP 鍵先清空，避免宿主環境（compose 的 .env）污染逐格判定
	for _, k := range []string{
		"LDAP_ENABLED", "LDAP_URL", "LDAP_BIND_DN", "LDAP_BIND_PASSWORD", "LDAP_BASE_DN",
		"LDAP_USER_FILTER", "LDAP_ATTR_EMAIL", "LDAP_ATTR_FULLNAME", "LDAP_SKIP_TLS_VERIFY",
	} {
		t.Setenv(k, "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

// fullLDAPEnv 齊全的 env 集合
func fullLDAPEnv(enabled string) map[string]string {
	return map[string]string{
		"LDAP_ENABLED":         enabled,
		"LDAP_URL":             "ldap://dir.example:389",
		"LDAP_BIND_DN":         "cn=admin,dc=example,dc=org",
		"LDAP_BIND_PASSWORD":   "s3cret-bind-pw",
		"LDAP_BASE_DN":         "ou=users,dc=example,dc=org",
		"LDAP_USER_FILTER":     "(&(objectClass=person)(uid=%s))",
		"LDAP_ATTR_EMAIL":      "email",
		"LDAP_ATTR_FULLNAME":   "displayName",
		"LDAP_SKIP_TLS_VERIFY": "false",
	}
}

func markerWritten(t *testing.T, db *gorm.DB) bool {
	t.Helper()
	ok, err := ldapSeedMarkerWritten(db)
	if err != nil {
		t.Fatalf("查 marker: %v", err)
	}
	return ok
}

func countDirectories(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Unscoped().Model(&model.LDAPDirectory{}).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestLDAPSeedTableMissingIsNoOp 判定順序 (1)：表不存在 → no-op，不記失敗、不寫 marker。
//
// 這一格是既有測試的相容性前提：多數單元測試庫沒有 ldap_directories，
// 若此格回 error，kek_provider_aad_test.go 的佇列失敗計數斷言會被打紅。
func TestLDAPSeedTableMissingIsNoOp(t *testing.T) {
	setLDAPEnv(t, fullLDAPEnv("true"))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// 連 schema_migrations 都沒有：真正的「表不存在」環境
	if err := RunLDAPEnvSeed(db, nil, audit.NewTxSink()); err != nil {
		t.Fatalf("表不存在時 MUST no-op 不回錯: %v", err)
	}
}

// TestLDAPSeedEnvDisabledWritesMarker 判定順序 (2)：env 未啟用 → 寫 marker 返回、不建列。
//
// **marker 語義是「已完成評估」**：這一格若不寫 marker，全新部署的 marker 永遠
// 缺席，日後 admin 以 UI 建立的設定被硬刪、env 又是 true 時就會靜默回灌。
func TestLDAPSeedEnvDisabledWritesMarker(t *testing.T) {
	setLDAPEnv(t, fullLDAPEnv("false"))
	db := newLDAPSeedDB(t)

	if err := RunLDAPEnvSeed(db, nil, audit.NewTxSink()); err != nil {
		t.Fatalf("env 未啟用不應回錯: %v", err)
	}
	if n := countDirectories(t, db); n != 0 {
		t.Fatalf("env 未啟用 MUST NOT 建列, got %d", n)
	}
	if !markerWritten(t, db) {
		t.Fatal("env 未啟用 MUST 寫 marker（評估已完成）")
	}
}

// TestLDAPSeedMarkerWriteIsIdempotent marker 冪等：判定順序把 (2) 排在 marker
// 檢查之前，env 關閉的部署每次啟動都會走到寫入路徑，非冪等即撞主鍵。
func TestLDAPSeedMarkerWriteIsIdempotent(t *testing.T) {
	setLDAPEnv(t, fullLDAPEnv("false"))
	db := newLDAPSeedDB(t)

	for i := 0; i < 3; i++ {
		if err := RunLDAPEnvSeed(db, nil, audit.NewTxSink()); err != nil {
			t.Fatalf("第 %d 次執行失敗（marker 寫入非冪等？）: %v", i+1, err)
		}
	}
	var n int64
	if err := db.Table("schema_migrations").Where("version = ?", ldapSeedMarker).Count(&n).Error; err != nil {
		t.Fatalf("count marker: %v", err)
	}
	if n != 1 {
		t.Fatalf("marker 列數 = %d, want 1", n)
	}
}

// TestLDAPSeedEnabledSeedsEncryptedRow 判定順序 (5)：正常 seed。
// 同時涵蓋「密碼為密文非明文」與「seed 事件入審計」。
func TestLDAPSeedEnabledSeedsEncryptedRow(t *testing.T) {
	env := fullLDAPEnv("true")
	setLDAPEnv(t, env)
	db := newLDAPSeedDB(t)
	km := newLDAPSeedCodec(t, db)

	if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
		t.Fatalf("seed 失敗: %v", err)
	}

	var row model.LDAPDirectory
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀 seed 出的列: %v", err)
	}
	if row.Singleton != 1 {
		t.Errorf("singleton = %d, want 1", row.Singleton)
	}
	if !row.Enabled {
		t.Error("seed 出的列 MUST enabled=true（env 已啟用）")
	}
	if row.URL != env["LDAP_URL"] || row.BindDN != env["LDAP_BIND_DN"] || row.BaseDN != env["LDAP_BASE_DN"] {
		t.Errorf("撥號參數未忠實入庫: %+v", row)
	}
	if row.UserFilter != env["LDAP_USER_FILTER"] || row.AttrEmail != env["LDAP_ATTR_EMAIL"] ||
		row.AttrFullName != env["LDAP_ATTR_FULLNAME"] {
		t.Errorf("搜尋參數未忠實入庫: %+v", row)
	}

	// 密碼：非明文、且為可解回原值的信封密文
	if row.BindPasswordEnc == "" {
		t.Fatal("bind 密碼未入庫")
	}
	if strings.Contains(row.BindPasswordEnc, env["LDAP_BIND_PASSWORD"]) {
		t.Fatalf("bind 密碼以明文落庫: %q", row.BindPasswordEnc)
	}
	if !strings.HasPrefix(row.BindPasswordEnc, "enc:a1:v") {
		t.Fatalf("bind 密碼非終態信封格式（DEK 輪替與引用掃描會漏掉）: %q", row.BindPasswordEnc)
	}
	plain, err := km.DecryptFor(t.Context(), keyvault.RefLDAPBindPassword, row.BindPasswordEnc)
	if err != nil {
		t.Fatalf("以 ldap_directories.bind_password_enc 身分解密失敗: %v", err)
	}
	if plain != env["LDAP_BIND_PASSWORD"] {
		t.Fatalf("解密結果 = %q, want %q", plain, env["LDAP_BIND_PASSWORD"])
	}

	if !markerWritten(t, db) {
		t.Error("seed 成功 MUST 寫 marker")
	}

	// seed 事件入審計，且不含密碼明文
	var logs []model.AuditLog
	if err := db.Where("resource = ?", model.ResourceAuth).Find(&logs).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("seed 審計事件數 = %d, want 1", len(logs))
	}
	if !strings.Contains(logs[0].Details, `"source":"seed"`) {
		t.Errorf("審計缺來源標記: %s", logs[0].Details)
	}
	if !strings.Contains(logs[0].Details, policy.RiskLDAPPlaintext) {
		t.Errorf("審計缺傳輸風險項（ldap:// 應命中明文風險）: %s", logs[0].Details)
	}
	if strings.Contains(logs[0].Details, env["LDAP_BIND_PASSWORD"]) ||
		strings.Contains(logs[0].Details, row.BindPasswordEnc) {
		t.Errorf("審計含密碼或密文: %s", logs[0].Details)
	}
}

// TestLDAPSeedAcceptsNonTrueBooleanLiteral `LDAP_ENABLED=1`。
//
// **為何單獨一格**：解析若寫成 `os.Getenv("LDAP_ENABLED") == "true"`，
// `.env` 寫 `1`（今日合法可運作）的既有部署升級後判定為未啟用 → 不 seed、
// 無錯誤、LDAP 全體使用者靜默登不進來。正是「無感升級」要保證的那一格。
func TestLDAPSeedAcceptsNonTrueBooleanLiteral(t *testing.T) {
	for _, literal := range []string{"1", "TRUE", "True", "t"} {
		t.Run(literal, func(t *testing.T) {
			setLDAPEnv(t, fullLDAPEnv(literal))
			db := newLDAPSeedDB(t)
			km := newLDAPSeedCodec(t, db)
			if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
				t.Fatalf("seed 失敗: %v", err)
			}
			if n := countDirectories(t, db); n != 1 {
				t.Fatalf("LDAP_ENABLED=%s 應被識別為已啟用並 seed, 列數 = %d", literal, n)
			}
		})
	}
	// 反向：無效值取預設 false（與 config.getEnvBool 同語義）
	t.Run("invalid_falls_back_to_default", func(t *testing.T) {
		setLDAPEnv(t, fullLDAPEnv("yes-please"))
		db := newLDAPSeedDB(t)
		if err := RunLDAPEnvSeed(db, nil, audit.NewTxSink()); err != nil {
			t.Fatalf("不應回錯: %v", err)
		}
		if n := countDirectories(t, db); n != 0 {
			t.Fatalf("無效布林值應取預設 false（不 seed）, 列數 = %d", n)
		}
	})
}

// TestLDAPSeedMinimalEnvUsesConfigDefaults 最小 5 鍵集合 → 三個搜尋參數取
// config 同組預設（(uid=%s)／mail／cn），seed 出的設定可直接用於登入。
func TestLDAPSeedMinimalEnvUsesConfigDefaults(t *testing.T) {
	setLDAPEnv(t, map[string]string{
		"LDAP_ENABLED":       "true",
		"LDAP_URL":           "ldaps://dir.example:636",
		"LDAP_BIND_DN":       "cn=admin,dc=example,dc=org",
		"LDAP_BIND_PASSWORD": "pw",
		"LDAP_BASE_DN":       "ou=users,dc=example,dc=org",
	})
	db := newLDAPSeedDB(t)
	km := newLDAPSeedCodec(t, db)

	if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
		t.Fatalf("seed 失敗: %v", err)
	}
	var row model.LDAPDirectory
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀列: %v", err)
	}
	if row.UserFilter != "(uid=%s)" {
		t.Errorf("user_filter = %q, want (uid=%%s)", row.UserFilter)
	}
	if row.AttrEmail != "mail" {
		t.Errorf("attr_email = %q, want mail", row.AttrEmail)
	}
	if row.AttrFullName != "cn" {
		t.Errorf("attr_fullname = %q, want cn", row.AttrFullName)
	}
	// ldaps 且未跳過驗證 → 無傳輸風險項
	var logs []model.AuditLog
	db.Where("resource = ?", model.ResourceAuth).Find(&logs)
	if len(logs) == 1 && strings.Contains(logs[0].Details, policy.RiskLDAPPlaintext) {
		t.Errorf("ldaps:// 不應命中明文風險: %s", logs[0].Details)
	}
}

// TestLDAPSeedSkipsWhenTableNotEmpty 判定順序 (4)：表非空（含軟刪列）→ 寫 marker 不 seed。
// 逐格覆蓋 live 列與軟刪列兩種形態。
func TestLDAPSeedSkipsWhenTableNotEmpty(t *testing.T) {
	cases := []struct {
		name    string
		softDel bool
	}{
		{"live 列", false},
		{"軟刪列", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setLDAPEnv(t, fullLDAPEnv("true"))
			db := newLDAPSeedDB(t)
			km := newLDAPSeedCodec(t, db)

			existing := &model.LDAPDirectory{Singleton: 1, Name: "由 UI 建立", URL: "ldaps://ui.example:636"}
			if err := db.Create(existing).Error; err != nil {
				t.Fatalf("建既有列: %v", err)
			}
			if tc.softDel {
				if err := db.Delete(existing).Error; err != nil {
					t.Fatalf("軟刪: %v", err)
				}
			}

			if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
				t.Fatalf("不應回錯: %v", err)
			}
			if n := countDirectories(t, db); n != 1 {
				t.Fatalf("表非空時 MUST NOT seed（軟刪列亦算已有設定）, 列數 = %d", n)
			}
			if !markerWritten(t, db) {
				t.Fatal("表非空 MUST 寫 marker（評估已完成）")
			}
			// 既有列未被覆寫
			var row model.LDAPDirectory
			if err := db.Unscoped().First(&row).Error; err != nil {
				t.Fatalf("讀既有列: %v", err)
			}
			if row.URL != "ldaps://ui.example:636" {
				t.Errorf("既有列被 seed 覆寫: %+v", row)
			}
		})
	}
}

// TestLDAPSeedDoesNotRefillAfterHardDelete marker 語義的核心保證：
// 列被硬刪後不回灌——涵蓋「seed 建立的列」與「UI 建立的列」兩種來源。
//
// UI 來源那一格正是 v2 設計（只有成功插入才寫 marker）漏掉的洞：首啟時 env
// 未啟用（marker 於該次寫入），admin 事後以 UI 建立設定、日後該列被硬刪，
// env 又為 true 時將靜默重建並**重新啟用一個外部認證來源**。
func TestLDAPSeedDoesNotRefillAfterHardDelete(t *testing.T) {
	t.Run("seed 建立的列被硬刪", func(t *testing.T) {
		setLDAPEnv(t, fullLDAPEnv("true"))
		db := newLDAPSeedDB(t)
		km := newLDAPSeedCodec(t, db)

		if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
			t.Fatalf("首次 seed: %v", err)
		}
		if n := countDirectories(t, db); n != 1 {
			t.Fatalf("首次應 seed 一列, got %d", n)
		}
		// 維運硬刪
		if err := db.Unscoped().Where("1 = 1").Delete(&model.LDAPDirectory{}).Error; err != nil {
			t.Fatalf("硬刪: %v", err)
		}
		// 重啟：env 仍為 true
		if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
			t.Fatalf("重啟執行: %v", err)
		}
		if n := countDirectories(t, db); n != 0 {
			t.Fatalf("marker 已寫，MUST NOT 回灌, 列數 = %d", n)
		}
	})

	t.Run("UI 建立的列被硬刪（首啟時 env 未啟用）", func(t *testing.T) {
		db := newLDAPSeedDB(t)
		km := newLDAPSeedCodec(t, db)

		// 首啟：env 未啟用 → 寫 marker、不建列
		setLDAPEnv(t, fullLDAPEnv("false"))
		if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
			t.Fatalf("首啟: %v", err)
		}
		if !markerWritten(t, db) {
			t.Fatal("首啟（env 未啟用）MUST 寫 marker——否則本測試要防的洞不成立")
		}

		// admin 以 UI 建立設定，日後被維運硬刪
		row := &model.LDAPDirectory{Singleton: 1, Name: "由 UI 建立", URL: "ldaps://ui.example:636", Enabled: true}
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("UI 建列: %v", err)
		}
		if err := db.Unscoped().Where("1 = 1").Delete(&model.LDAPDirectory{}).Error; err != nil {
			t.Fatalf("硬刪: %v", err)
		}

		// 重啟且 env 為 true
		setLDAPEnv(t, fullLDAPEnv("true"))
		if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
			t.Fatalf("重啟執行: %v", err)
		}
		if n := countDirectories(t, db); n != 0 {
			t.Fatalf("marker 記錄的是「評估已完成」，不因列由 UI 建立而失效；MUST NOT 回灌, 列數 = %d", n)
		}
	})
}

// TestLDAPSeedInfrastructureFailureLeavesNoMarker 基礎設施失敗（加密失敗）
// → 不寫 marker、下次啟動重試。
//
// 這是 marker 語義的另一半：**只有終局結果寫 marker**。若失敗也寫，
// 一次 KMS 抖動就會讓既有部署永久失去 LDAP 設定且無錯誤可查。
func TestLDAPSeedInfrastructureFailureLeavesNoMarker(t *testing.T) {
	setLDAPEnv(t, fullLDAPEnv("true"))
	db := newLDAPSeedDB(t)

	// codec 為 nil＝加密不可用（等價於 codec 故障）
	if err := RunLDAPEnvSeed(db, nil, audit.NewTxSink()); err == nil {
		t.Fatal("加密不可用時 MUST 回 error（佇列記錄失敗，不阻塞服務）")
	}
	if markerWritten(t, db) {
		t.Fatal("基礎設施失敗 MUST NOT 寫 marker（否則永久失去 seed 機會）")
	}
	if n := countDirectories(t, db); n != 0 {
		t.Fatalf("失敗時不得留半完成列, 列數 = %d", n)
	}

	// 下次啟動重試：codec 就緒即成功
	km := newLDAPSeedCodec(t, db)
	if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
		t.Fatalf("重試應成功: %v", err)
	}
	if n := countDirectories(t, db); n != 1 {
		t.Fatalf("重試後應 seed 一列, got %d", n)
	}
	if !markerWritten(t, db) {
		t.Fatal("重試成功後 MUST 寫 marker")
	}
}

// TestLDAPSeedAuditFailureRollsBackRowAndMarker 審計與資料列同進退。
//
// 審計表暫時不可寫時，若 seed 列與 marker 仍提交，一個外部認證來源就被永久
// 建立而**毫無審計紀錄**，且 marker 使後續啟動不再補寫——違反「全操作審計」
// 紅線且不可回頭。正確行為是整批回滾、marker 未寫，下次啟動重試。
func TestLDAPSeedAuditFailureRollsBackRowAndMarker(t *testing.T) {
	setLDAPEnv(t, fullLDAPEnv("true"))
	db := newLDAPSeedDB(t)
	km := newLDAPSeedCodec(t, db)

	// 注入審計不可寫（等價於審計表暫時不可用）。加密不經 DB，故本注入只打審計那一步
	if err := db.Exec("DROP TABLE audit_logs").Error; err != nil {
		t.Fatalf("drop audit_logs: %v", err)
	}

	if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err == nil {
		t.Fatal("審計寫入失敗時 MUST 回 error（佇列記錄失敗，下次重試）")
	}
	if n := countDirectories(t, db); n != 0 {
		t.Fatalf("審計失敗 MUST NOT 留下 LDAP 認證來源（無審計的認證來源＝違反全操作審計）, 列數 = %d", n)
	}
	if markerWritten(t, db) {
		t.Fatal("審計失敗 MUST NOT 寫 marker（否則下次啟動不再補寫審計，永久缺痕）")
	}

	// 審計恢復 → 下次啟動重試：列、審計、marker 三者齊備
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("重建 audit_logs: %v", err)
	}
	if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
		t.Fatalf("審計恢復後重試應成功: %v", err)
	}
	if n := countDirectories(t, db); n != 1 {
		t.Fatalf("重試後應 seed 一列, got %d", n)
	}
	if !markerWritten(t, db) {
		t.Fatal("重試成功後 MUST 寫 marker")
	}
	var logs []model.AuditLog
	if err := db.Where("resource = ?", model.ResourceAuth).Find(&logs).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("seed 審計事件數 = %d, want 1", len(logs))
	}
}

// TestLDAPSeedTableProbeFailurePropagates 表存在性判定的錯誤路徑。
//
// GORM `Migrator().HasTable` 只回 bool：catalog 查詢因權限、連線中斷等原因失敗時
// 與「表不存在」無從區分，seed 會誤走 no-op 並向佇列回報成功，基礎設施故障靜默。
// 只有「確定不存在」才是 no-op，其餘一律回錯讓佇列記錄並於下次啟動重試。
func TestLDAPSeedTableProbeFailurePropagates(t *testing.T) {
	t.Run("連線已關閉（查詢失敗，非表不存在）", func(t *testing.T) {
		setLDAPEnv(t, fullLDAPEnv("true"))
		db := newLDAPSeedDB(t)
		sqlDB, err := db.DB()
		if err != nil {
			t.Fatalf("sql.DB: %v", err)
		}
		if err := sqlDB.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if err := RunLDAPEnvSeed(db, nil, audit.NewTxSink()); err == nil {
			t.Fatal("catalog 查詢失敗 MUST 回 error，不得誤判為「表不存在」而靜默 no-op")
		}
	})

	// codec 給真的：否則 nil codec 那條錯誤會讓本格無論實作如何都「通過」，失去辨識力
	t.Run("未知 dialect fail-close", func(t *testing.T) {
		setLDAPEnv(t, fullLDAPEnv("true"))
		db := newLDAPSeedDB(t)
		km := newLDAPSeedCodec(t, db)
		fake := db.Session(&gorm.Session{})
		fake.Config.Dialector = unknownDialector{Dialector: db.Dialector}
		err := RunLDAPEnvSeed(fake, km, audit.NewTxSink())
		if err == nil {
			t.Fatal("未知 dialect 無可信的表存在性判定，MUST fail-close 不得猜測")
		}
		if !strings.Contains(err.Error(), "dialect") {
			t.Fatalf("錯誤應指出 dialect 不受支援，實得: %v", err)
		}
	})
}

// TestLDAPSeedRegisteredInBuiltinQueue 佇列成員的正向斷言＋命名紀律。
//
// 命名不得含 "aad"：aad_strict_guard_test.go 以子字串比對做負向成員斷言，
// 含該子字串的項名會被誤判為「AAD 正向遷移自動執行」而打紅。
func TestLDAPSeedRegisteredInBuiltinQueue(t *testing.T) {
	// 登記器由組裝根提供（斷 keyvault→identity 環）；本測試驗的是「登記後它確實在佇列裡、
	// 且名稱不含 aad」，生產側真的有登記那一行由
	// TestAssemblyRegistersPostUnsealBuiltins 對 cmd/server 獨立斷言
	registerBuiltinsLikeAssembly()
	keyvault.ResetPostUnsealQueueForTest()
	t.Cleanup(keyvault.ResetPostUnsealQueueForTest)

	names := keyvault.PostUnsealMigrationNames()
	found := false
	for _, n := range names {
		if n == PostUnsealMigrationLDAPSeed {
			found = true
		}
	}
	if !found {
		t.Fatalf("LDAP seed 未登記於內建 post-unseal 佇列（%v）——"+
			"seed 需要段 2 才存在的 codec，SHALL NOT 改回段 1 migration", names)
	}
	if strings.Contains(strings.ToLower(PostUnsealMigrationLDAPSeed), "aad") {
		t.Fatalf("佇列項名 %q 含 aad：會被 AAD 負向成員守衛誤判", PostUnsealMigrationLDAPSeed)
	}
}

// TestLDAPSeedTakesDirectoryLockAndRereadsInside 封死軟刪競態（並發線性化）。
//
// 兩件事一起釘住：
//
//  1. **seed 確實取 LDAP 目錄互斥鎖**——鎖被 CRUD 寫入路徑佔用時，seed 必須
//     失敗上傳（基礎設施性暫時失敗），而**不得**吞掉當成「已評估」而寫 marker。
//     吞掉的後果是錯過唯一一次 seed 機會，既有部署升級後 LDAP 靜默失效。
//  2. 判定在鎖內重讀——不可沿用進鎖前的舊值（見 RunLDAPEnvSeed 的 (4)(5) 註解）。
//
// 沒有這條，「加了鎖」與「加了鎖但仍用舊讀值」在測試上無從分辨。
func TestLDAPSeedTakesDirectoryLockAndRereadsInside(t *testing.T) {
	db := newLDAPSeedDB(t)
	km := newLDAPSeedCodec(t, db)
	setLDAPEnv(t, fullLDAPEnv("true"))

	// 佔住鎖，模擬併行的 CRUD 寫入。
	//
	// 刻意直接持行程鎖而非經 WithLDAPDirectoryLock：後者會一併開啟交易，而本測試
	// 庫是 sqlite :memory: 單連線（既有 flaky 真因的規避手法），持交易等於佔住唯一
	// 連線，seed 的前置查詢會拿不到連線而死鎖——測不到「取鎖失敗」這一格。
	ldapDirectoryProcessMu.Lock()
	err := RunLDAPEnvSeed(db, km, audit.NewTxSink())
	ldapDirectoryProcessMu.Unlock()

	if err == nil {
		t.Fatal("鎖被佔用時 seed 應上傳失敗（可重試），實得 nil——" +
			"若 seed 未取鎖，軟刪競態即未封死")
	}
	if !strings.Contains(err.Error(), ErrLDAPDirectoryBusy.Error()) {
		t.Fatalf("錯誤應源自取鎖失敗，實得: %v", err)
	}

	// marker 未寫：下次啟動整體重試（不可被誤記為「已評估」）
	var markers int64
	if err := db.Table("schema_migrations").
		Where("version = ?", database.LDAPSeedMarkerVersion).Count(&markers).Error; err != nil {
		t.Fatalf("查 marker: %v", err)
	}
	if markers != 0 {
		t.Fatalf("取鎖失敗時 marker 不得寫入（實得 %d 列）——寫了就永遠不會再 seed", markers)
	}

	// 未留半成品
	var rows int64
	if err := db.Unscoped().Model(&model.LDAPDirectory{}).Count(&rows).Error; err != nil {
		t.Fatalf("計數: %v", err)
	}
	if rows != 0 {
		t.Fatalf("取鎖失敗不應寫入任何列，實得 %d", rows)
	}

	// 鎖釋放後重試應成功（可重試語義成立）
	if err := RunLDAPEnvSeed(db, km, audit.NewTxSink()); err != nil {
		t.Fatalf("鎖釋放後重試應成功: %v", err)
	}
	if err := db.Unscoped().Model(&model.LDAPDirectory{}).Count(&rows).Error; err != nil {
		t.Fatalf("計數: %v", err)
	}
	if rows != 1 {
		t.Fatalf("重試後應有 1 列，實得 %d", rows)
	}
}
