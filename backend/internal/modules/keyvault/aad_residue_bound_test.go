package keyvault

import (
	"testing"
)

// 自 `internal/service/aad_residue_alert_test.go` 遷入（modular-architecture W2 2.5）：
// 本測試逐項走 envelopeMigrationTargets 並呼叫 countPendingColumnValues／
// envelopeVersionOf（皆為 keyvault 未匯出內部），必須隨包遷入；
// 原檔其餘三項驗的是「哨兵上報到 AuditFailureService」的協作，W2 留在 internal/service，
// W9 該包解散後隨檔遷入本目錄的外部測試包（`aad_residue_alert_test.go`）。
// 斷言逐字未改，僅把 fixture 由 setupAADAlertFixture（含 audit failure service）
// 換成同一組 DB／KM／殘值播種的 keyvault 本地 fixture——原測試取得的第三個
// 回傳值本就被丟棄（`db, _, _ := setupAADAlertFixture(t)`）。

// TestAADResidueLowerBoundIsLowerBound SQL 前綴下界的方向性（SQL ≤ Go）：
// 帶 `enc:a1:` 前綴但格式損毀的值——SQL LIKE 計為乾淨、Go 嚴格判定計為殘值。
// 下界=0 不得被解讀為「無殘值」；此測試釘住兩個口徑的不等式方向，
// 防日後有人把哨兵或清理閘改用 SQL 計數當權威判定（原下界語義隨哨兵自
// envelope_aad_migration.go 遷出，本測試為其方向性斷言的補位）。
func TestAADResidueLowerBoundIsLowerBound(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	aadFixture(t, db, km)
	// 全部登記欄位先清成合法終態，再種入唯一一筆 malformed 前綴值
	for _, stmt := range []string{
		"UPDATE assets SET password_enc = 'enc:a1:v1:AAAA'",
		"UPDATE asset_accounts SET password_enc = 'enc:a1:v1:AAAA', private_key_enc = 'enc:a1:v1:AAAA'",
		"UPDATE assets SET password_enc = 'enc:a1:broken' WHERE id = 1",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("種入 malformed 值失敗: %v", err)
		}
	}
	_, sqlTotal, err := AADResidueLowerBound(db)
	if err != nil {
		t.Fatalf("SQL 下界: %v", err)
	}
	// Go 嚴格判定沿現行掃描原語：非有效信封（ParseEnvelopeFull 不過）即殘值
	var goTotal int64
	for _, target := range envelopeMigrationTargets {
		n, err := countPendingColumnValues(db, target, func(v string) bool {
			_, ok := envelopeVersionOf(v)
			return ok
		})
		if err != nil {
			t.Fatalf("Go 嚴格計數 %s.%s: %v", target.table, target.column, err)
		}
		goTotal += n
	}
	if sqlTotal > goTotal {
		t.Fatalf("下界方向被破壞：SQL(%d) > Go(%d)", sqlTotal, goTotal)
	}
	if sqlTotal != 0 || goTotal == 0 {
		t.Fatalf("malformed 前綴值 MUST 為「SQL 看不見、Go 看得見」：SQL=%d Go=%d", sqlTotal, goTotal)
	}
}
