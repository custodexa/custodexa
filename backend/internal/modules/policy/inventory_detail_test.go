package policy

import "testing"

// 本檔為**包內**測試（`package policy`）：所驗的 legacyDetailFromCodes 與
// detailUnsetCode／detailUnsetZh 是未匯出實作細節，外部測試套件看不到。
// 自 transmission_inventory_service_test.go 拆出（該檔於 W3 改為 policy_test）。

// TestLegacyDetailCollisionConserved detail_codes→legacy 顯示鍵碰撞時 count 守恆（codex
// impl-review I2）：髒資料使 unset 與字面 "(未設定)" 同時存在，兩者映到同一 zh 鍵須累加不覆蓋。
func TestLegacyDetailCollisionConserved(t *testing.T) {
	codes := map[string]int64{detailUnsetCode: 2, detailUnsetZh: 3, "disable": 1}
	legacy := legacyDetailFromCodes(codes)
	if legacy[detailUnsetZh] != 5 {
		t.Errorf("legacy[%q] = %d, want 5（2 unset + 3 字面，累加守恆）", detailUnsetZh, legacy[detailUnsetZh])
	}
	if legacy["disable"] != 1 {
		t.Errorf("legacy[disable] = %d, want 1", legacy["disable"])
	}
	var total int64
	for _, v := range legacy {
		total += v
	}
	if total != 6 {
		t.Errorf("legacy 總數 = %d, want 6（不遺失計數）", total)
	}
}
