package policy

import "testing"

// 鍵盤紀錄保留鍵不納入檢查點跨鍵約束：鍵盤紀錄檔不在檢查點鏈內。
// 日後若要納入，必須是刻意的改動（連同出廠 0 與升級對帳一併重新設計），而不是順手加進清單。
func TestKeystrokeRetentionKeyNotInDataRetentionKeys(t *testing.T) {
	for _, k := range dataRetentionKeys {
		if k == PolicyRetentionKeystrokeDays {
			t.Fatalf("%s 不得出現在 dataRetentionKeys", k)
		}
	}
	if len(dataRetentionKeys) != 4 {
		t.Fatalf("dataRetentionKeys 應維持四鍵，實際 %d", len(dataRetentionKeys))
	}
}

// 值域 {0} ∪ [7, 3650]，出廠 0（永久）；高風險分類與縮短確認同其他保留鍵。
func TestKeystrokeRetentionKeyDefinition(t *testing.T) {
	var def *PolicyDef
	for i := range policyDefs {
		if policyDefs[i].Key == PolicyRetentionKeystrokeDays {
			def = &policyDefs[i]
		}
	}
	if def == nil {
		t.Fatal("政策定義缺 retention_keystroke_days")
	}
	if def.Default != "0" || !def.ZeroDisables || def.Min != RetentionFloorDays || def.Max != 3650 {
		t.Fatalf("定義不符: %+v", *def)
	}
	if _, ok := highRiskClassifiers[PolicyRetentionKeystrokeDays]; !ok {
		t.Fatal("保留下調告警缺分類器")
	}
	if !RetentionShortened("365", "30") || RetentionShortened("0", "0") || !RetentionShortened("0", "365") == false {
		// 0（永久）改 365 是下調（舊值 0 新值非 0）
		if !RetentionShortened("0", "365") {
			t.Fatal("由 0 改 365 應視為下調")
		}
	}
}
