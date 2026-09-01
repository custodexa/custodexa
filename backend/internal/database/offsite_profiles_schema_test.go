package database

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/testgate"
)

// `offsite_profiles` 兩條資料層不變式的**行為層實證**（沿
// ldap_directories_schema_test.go 的形態；gating：未設 TEST_PG_DSN 即 skip，
// REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
//
// 為什麼「定義文字比對」（TestBaselineStructuralInvariantsPostgres）還不夠：
// 那一層證明的是 DDL 長什麼樣，這一層證明的是 **DB 真的會拒**。
// 兩條 CHECK 與 partial unique index 的組合語義（尤其「零列合法」與
// 「stored ⇔ 密文非空」的雙向）只有插進去才看得出來。
//
// 跑法（compose 內）：
//
//	docker compose exec -T backend sh -c \
//	  'TEST_PG_DSN="host=postgres user=postgres password=postgres dbname=postgres port=5432 sslmode=disable" \
//	   REQUIRE_INTEGRATION=1 go test ./internal/database -run TestOffsiteProfiles -v'

// 兩支測試皆以**原生 SQL** 插列，不經 GORM：驗的是 DB 約束本身，
// 不是 model 的欄位對映（後者由兩層 parity 守衛負責）。

func TestOffsiteProfilesCurrentGenerationAtMostOne(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, "offsite_profiles_singleton_test")

	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	if err := applyMigrationsAfterBaseline(db); err != nil {
		t.Fatalf("增量 migration 失敗: %v", err)
	}

	// singleton 可調（驗 CHECK）；retired 決定是否佔用 partial unique index
	insert := func(singleton int, retired bool) error {
		retiredExpr := "NULL"
		if retired {
			retiredExpr = "NOW()"
		}
		return db.Exec(`INSERT INTO offsite_profiles
			(profile_fingerprint, singleton, provider, endpoint, bucket, prefix, region,
			 path_style, credential_mode, credentials_enc, credential_revision,
			 created_at, activated_at, retired_at)
			VALUES ('0123456789abcdef', ?, 's3', '', 'b', '', 'us-east-1',
			        FALSE, 'default_chain', '', 0, NOW(), NOW(), `+retiredExpr+`)`,
			singleton).Error
	}

	// 零列現行世代＝**合法終局態**（停用態的資料庫面）。
	// 這一格單獨存在的理由：把不變式寫成「恰一列」的實作會讓停用完全無法表達，
	// 而那個錯誤在「至多一列」的測試裡看不出來
	var n int64
	if err := db.Raw(`SELECT count(*) FROM offsite_profiles WHERE retired_at IS NULL`).Scan(&n).Error; err != nil {
		t.Fatalf("計數失敗: %v", err)
	}
	if n != 0 {
		t.Fatalf("初始現行世代數 = %d, want 0", n)
	}
	if err := insert(1, true); err != nil {
		t.Fatalf("已退役世代（retired_at 非空）應可插入，且零現行世代為合法態: %v", err)
	}
	if err := insert(1, true); err != nil {
		t.Fatalf("第二個已退役世代應可插入（partial index 不涵蓋退役列）: %v", err)
	}

	// CHECK：singleton=2 必須被 DB 拒（partial unique index 擋不住這一格——
	// 它只禁止相同值重複，2 與 1 是不同值）
	err := insert(2, false)
	if err == nil {
		t.Fatal("singleton=2 被接受：CHECK (singleton = 1) 缺席，" +
			"「現行世代至多一列」不成立")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("singleton=2 被拒但不是 CHECK 約束所致: %v", err)
	}

	// partial unique index：第一列現行世代可插、第二列被拒
	if err := insert(1, false); err != nil {
		t.Fatalf("第一列現行世代應可插入: %v", err)
	}
	if err := insert(1, false); err == nil {
		t.Fatal("第二列現行世代被接受：idx_offsite_profiles_current 未生效，" +
			"上傳與取回可能各自取到不同世代")
	}

	// 退役現行列後可再建新世代（世代切換與「停用後重新設定」都走這條路）
	if err := db.Exec(`UPDATE offsite_profiles SET retired_at = NOW() WHERE retired_at IS NULL`).Error; err != nil {
		t.Fatalf("退役現行列失敗: %v", err)
	}
	if err := insert(1, false); err != nil {
		t.Fatalf("退役後應可建立新世代: %v", err)
	}
}

func TestOffsiteProfilesCredentialModeConsistency(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, "offsite_profiles_credmode_test")

	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	if err := applyMigrationsAfterBaseline(db); err != nil {
		t.Fatalf("增量 migration 失敗: %v", err)
	}

	// 每格都插成「已退役世代」，使 partial unique index 不干擾本測試的判定面
	insert := func(mode, enc string) error {
		return db.Exec(`INSERT INTO offsite_profiles
			(profile_fingerprint, singleton, provider, endpoint, bucket, prefix, region,
			 path_style, credential_mode, credentials_enc, credential_revision,
			 created_at, activated_at, retired_at)
			VALUES ('0123456789abcdef', 1, 's3', '', 'b', '', 'us-east-1',
			        FALSE, ?, ?, 0, NOW(), NOW(), NOW())`, mode, enc).Error
	}

	// 三個合法格
	for _, ok := range []struct{ mode, enc string }{
		{"stored", "enc:a1:xxxx"},
		{"default_chain", ""},
		{"revoked", ""},
	} {
		if err := insert(ok.mode, ok.enc); err != nil {
			t.Fatalf("合法組合 (%s, enc空=%v) 被拒: %v", ok.mode, ok.enc == "", err)
		}
	}

	// 三個違法格。**雙向都要驗**：只驗一側時，把等價式改成單向蘊含仍會綠
	for _, bad := range []struct {
		mode, enc, why string
	}{
		{"stored", "", "stored 而密文空：取回時無憑證卻不呈現為已撤銷，" +
			"三態 fail-close 的 failed 與 revoked 無從區分"},
		{"revoked", "enc:a1:xxxx", "revoked 而密文非空：撤銷沒有真的發生，" +
			"密文仍可被解出並用於取回"},
		{"default_chain", "enc:a1:xxxx", "default_chain 而密文非空：" +
			"「刻意用預設鏈」與「有自己的憑證」同時成立，ClientFor 的分支語義失效"},
	} {
		if err := insert(bad.mode, bad.enc); err == nil {
			t.Errorf("違法組合 (%s, 密文非空=%v) 被接受：%s",
				bad.mode, bad.enc != "", bad.why)
		} else if !strings.Contains(strings.ToLower(err.Error()), "check") {
			t.Errorf("違法組合 (%s) 被拒但不是 CHECK 所致: %v", bad.mode, err)
		}
	}
}
