package database

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/testgate"
)

// TestLDAPDirectoriesSingletonConstraintsPostgres 單列不變式的 DB 層實證
// （gating：未設 TEST_PG_DSN 即 skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
//
// **表由 baseline 建立**——這是本測試有意義的前提。壓縮前 `ldap_directories`
// 刻意排除於 AutoMigrate 清單之外（GORM 不產出 inline CHECK，先建出的表會使
// migration 的 `CREATE TABLE IF NOT EXISTS` 靜默略過，`CHECK (singleton = 1)`
// 在生產完全不存在且無外顯症狀），並以 AST 守衛
// `TestLDAPDirectoryNotInAutoMigrateList` 釘住那條排除。
//
// AutoMigrate 移除後那條排除失去對象，**但它保護的東西沒有**：CHECK 仍然可能
// 因為有人改壞 baseline 而消失。保護對象由兩條承接——
//
//	本測試              CHECK 與 partial unique index 的行為層實證（插 singleton=2 被拒）
//	TestNoAutoMigrateInProductionCode  產品程式碼零 AutoMigrate 呼叫（原排除理由的根因）
//
// 跑法（compose 內）：
//
//	docker compose exec -T backend sh -c \
//	  'TEST_PG_DSN="host=postgres user=postgres password=postgres dbname=postgres port=5432 sslmode=disable" \
//	   REQUIRE_INTEGRATION=1 go test ./internal/database -run TestLDAPDirectoriesSingleton -v'
func TestLDAPDirectoriesSingletonConstraintsPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, "ldap_dir_test")

	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}

	insert := func(singleton int) error {
		return db.Exec(`INSERT INTO ldap_directories
			(created_at, updated_at, singleton, name, url, bind_dn, bind_password_enc,
			 base_dn, user_filter, attr_email, attr_fullname, skip_tls_verify, enabled)
			VALUES (NOW(), NOW(), ?, 'x', 'ldap://h:389', '', '', '', '(uid=%s)', 'mail', 'cn', FALSE, FALSE)`,
			singleton).Error
	}

	if err := insert(1); err != nil {
		t.Fatalf("第一列應可插入: %v", err)
	}

	// CHECK：singleton=2 必須被 DB 拒絕（unique index 擋不住這一格）
	err := insert(2)
	if err == nil {
		t.Fatal("singleton=2 被接受：CHECK (singleton = 1) 缺席，" +
			"單列保證不成立（unique index 只禁止相同值重複）")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("singleton=2 被拒但不是 CHECK 約束所致（可能由其他錯誤路徑碰巧擋下）: %v", err)
	}

	// partial unique index：第二條 live 列（singleton=1）被拒
	if err := insert(1); err == nil {
		t.Fatal("第二條 live 列被接受：partial unique index 未生效")
	}

	// 軟刪列不佔 singleton：軟刪後可重建
	if err := db.Exec(`UPDATE ldap_directories SET deleted_at = NOW()`).Error; err != nil {
		t.Fatalf("軟刪失敗: %v", err)
	}
	if err := insert(1); err != nil {
		t.Fatalf("軟刪後應可重建（partial index 排除軟刪列）: %v", err)
	}
}
