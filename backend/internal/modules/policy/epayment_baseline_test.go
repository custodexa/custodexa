package policy

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
)

// 兩組內建規範並行時的判定與收斂。
//
// 本檔的重點是**取嚴語義**：兩組規範在部分項目上方向相反，若「一次滿足所有政策」
// 實作為無條件覆寫，一個已符合其中一組的設定會被改差——「套用合規基準」這個動作
// 反而降低系統安全性。這是本塊唯一容易做錯之處。

// strictestOf 兩組要求收斂後最嚴的那一端；無要求或互相對立時回空字串。
func strictestOf(def *PolicyDef, exps []keyExpectation) string {
	if len(exps) == 0 {
		return ""
	}
	bounds, ok := resolveBounds(def, exps)
	if !ok || bounds.conflict {
		return ""
	}
	if strictest, has := bounds.strictest(); has {
		return strictest.value
	}
	return ""
}

// expectations 依比較方式把兩組要求值串成要求集合（空字串＝該組對此鍵無要求）。
func expectations(comparator string, values ...string) []keyExpectation {
	var out []keyExpectation
	for _, v := range values {
		if v == "" {
			continue
		}
		out = append(out, keyExpectation{Comparator: comparator, Value: v})
	}
	return out
}

func TestEvaluateStrictest_TakesStricterOfTwoBaselines(t *testing.T) {
	cases := []struct {
		name       string
		def        PolicyDef
		comparator string
		pci, ep    string
		want       string
	}{
		{
			// 密碼最小長度：至少型，電支 6 **寬於** PCI 12。
			// 這是真實資料，不是構造的邊界案例——兩組種子就是這樣
			name:       "至少型且電支較寬：取 PCI",
			def:        PolicyDef{Type: PolicyTypeInt, Direction: DirectionMin},
			comparator: model.PolicyControlComparatorMin,
			pci:        "12", ep: "6", want: "12",
		},
		{
			// 日誌保留：至少型，電支 730 嚴於 PCI 365
			name:       "至少型且電支較嚴：取電支",
			def:        PolicyDef{Type: PolicyTypeInt, Direction: DirectionMin},
			comparator: model.PolicyControlComparatorMin,
			pci:        "365", ep: "730", want: "730",
		},
		{
			// 登入鎖定次數：至多型，電支 5 嚴於 PCI 10
			name:       "至多型且電支較嚴：取電支",
			def:        PolicyDef{Type: PolicyTypeInt, Direction: DirectionMax},
			comparator: model.PolicyControlComparatorMax,
			pci:        "10", ep: "5", want: "5",
		},
		{
			name:       "至多型且 PCI 較嚴：取 PCI",
			def:        PolicyDef{Type: PolicyTypeInt, Direction: DirectionMax},
			comparator: model.PolicyControlComparatorMax,
			pci:        "15", ep: "30", want: "15",
		},
		{
			name:       "兩者相同：任一皆可",
			def:        PolicyDef{Type: PolicyTypeInt, Direction: DirectionMax},
			comparator: model.PolicyControlComparatorMax,
			pci:        "90", ep: "90", want: "90",
		},
		{
			name:       "電支無要求：回 PCI",
			def:        PolicyDef{Type: PolicyTypeInt, Direction: DirectionMin},
			comparator: model.PolicyControlComparatorMin,
			pci:        "12", want: "12",
		},
		{
			name:       "PCI 無要求：回電支",
			def:        PolicyDef{Type: PolicyTypeInt, Direction: DirectionMin},
			comparator: model.PolicyControlComparatorMin,
			ep:         "6", want: "6",
		},
		{
			name:       "兩組皆無要求：空字串（呼叫端據此略過該項）",
			def:        PolicyDef{Type: PolicyTypeInt, Direction: DirectionMin},
			comparator: model.PolicyControlComparatorMin,
			want:       "",
		},
		{
			// 開關與枚舉的要求是明確值：兩組要的是同一個值時就是那個值
			name:       "開關型兩組同值：取該值",
			def:        PolicyDef{Type: PolicyTypeBool},
			comparator: model.PolicyControlComparatorEquals,
			pci:        "true", ep: "true", want: "true",
		},
		{
			// **不替兩組挑一個較嚴的**：開關與枚舉的取值之間沒有強弱序，
			// 兩組要不同的值即為互相對立，該鍵不自動改（畫面上列為衝突）
			name: "枚舉型兩組要不同值：對立，不臆測取嚴",
			def: PolicyDef{
				Type: PolicyTypeEnum, EnumOrder: []string{"off", "warn", "strict"},
			},
			comparator: model.PolicyControlComparatorEquals,
			pci:        "warn", ep: "strict", want: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want,
				strictestOf(&c.def, expectations(c.comparator, c.pci, c.ep)))
		})
	}
}

// 兩組的判定各自獨立：同一項可符合其一而偏離另一。
// 合計或以其一取代另一都會使兩者都不可解讀
func TestCompliance_TwoBaselinesEvaluatedIndependently(t *testing.T) {
	// 登入鎖定次數至多型：現值 8 符合 PCI（<=10）但偏離電支（<=5）
	def := PolicyDef{Type: PolicyTypeInt, Direction: DirectionMax}

	pci, _ := compareExpectation(&def, "8", model.PolicyControlComparatorMax, "10")
	ep, _ := compareExpectation(&def, "8", model.PolicyControlComparatorMax, "5")

	require.True(t, pci, "8 <= 10 應符合 PCI")
	require.False(t, ep, "8 > 5 應偏離電支基準")
}

// 某一組沒有對照這個鍵時，該組不產生判定（不是「符合」也不是「偏離」）
func TestEPaymentCompliance_NilWhenNoBaseline(t *testing.T) {
	defs := []PolicyDef{{
		Key: PolicyPasswordMinLength, Type: PolicyTypeInt,
		Direction: DirectionMin, Default: "8", Max: 128,
	}}
	groups := []model.PolicyGroup{
		{Code: pciGroupCode, Source: model.PolicyGroupSourceBuiltin, Enabled: true},
		{Code: ePaymentGroupCode, Source: model.PolicyGroupSourceBuiltin, Enabled: true},
	}
	clauses := []model.PolicyClause{{
		GroupCode: pciGroupCode, ClauseNo: "8.3.6", Kind: model.PolicyClauseKindSetting,
	}}
	controls := []model.PolicyClauseControl{{
		GroupCode: pciGroupCode, ClauseNo: "8.3.6", PolicyKey: PolicyPasswordMinLength,
		Comparator: model.PolicyControlComparatorMin, ExpectedValue: "12",
	}}

	snap := BuildSnapshot(defs, map[string]string{PolicyPasswordMinLength: "8"},
		nil, groups, clauses, controls, nil)

	require.Empty(t, verdictResult(snap, PolicyPasswordMinLength, ePaymentGroupCode),
		"未對照本鍵的組不得產生判定")
	require.Equal(t, ComplianceResultDeviating,
		verdictResult(snap, PolicyPasswordMinLength, pciGroupCode),
		"有對照的那一組照常判定，不受另一組影響")
}

// 電支基準組最早六筆對照實際會落庫的要求。**本表即為機器可檢的權威副本**——值、
// 條號與比較方式直接寫在這裡並被逐一斷言，改動任何一格都會紅。
//
// **受測對象是內建組的種子**（不是設定鍵定義的欄位）：合規對照與判定讀的是種子
// 產生的那一批列。斷言對象是種子之後，「值被改動」「條號對錯」「該鍵整個從種子
// 消失」三種形態都會紅。
//
// **只涵蓋這六個鍵**：本組的完整條文對照另有分母測試釘住條文數與要求數。這裡是
// 六個數字本身的守衛——它們來自法源，被誤改時應該紅。
//
// `retention_audit_log_days` 的條號為 24-1 而非 19-4：兩條條文寫的是同一個要求
// （稽核軌跡至少保存二年），同一個鍵在同一組內只掛得了一次，要求掛在涵蓋四類
// 保留天數的那一條，另一條在依據裡併引。
func TestPolicyDefs_EPaymentBaselineValues(t *testing.T) {
	type expectation struct{ value, clauseNo, comparator string }
	want := map[string]expectation{
		PolicyLockoutMaxAttempts:    {"5", "4-7(五)", model.PolicyControlComparatorMax},
		PolicyPasswordMinLength:     {"6", "4-7(一)", model.PolicyControlComparatorMin},
		PolicyWebIdleMinutes:        {"10", "15-5", model.PolicyControlComparatorMax},
		PolicyPasswordMaxAgeDays:    {"90", "15-8", model.PolicyControlComparatorMax},
		PolicyAssetSecretMaxAgeDays: {"90", "15-8", model.PolicyControlComparatorMax},
		PolicyRetentionAuditLogDays: {"730", "24-1", model.PolicyControlComparatorMin},
	}

	controls, err := buildSeedControls(ePaymentPolicyGroupSeed())
	require.NoError(t, err, "電支基準組的種子建不出來")

	got := map[string]expectation{}
	for _, c := range controls {
		if _, watched := want[c.PolicyKey]; !watched {
			continue
		}
		got[c.PolicyKey] = expectation{c.ExpectedValue, c.ClauseNo, c.Comparator}
	}

	require.Equal(t, want, got,
		"電支基準組的要求與法源對照表不符——值被改動或該鍵從種子消失皆須有意識地同步本測試")
}

// 出廠預設不因新增基準而改變（使用者 2026-08-15 裁決：只做標示，不改預設）
func TestPolicyDefs_EPaymentDoesNotChangeFactoryDefaults(t *testing.T) {
	defaults := map[string]string{
		PolicyLockoutMaxAttempts:    "10",
		PolicyPasswordMinLength:     "12",
		PolicyWebIdleMinutes:        "60",
		PolicyPasswordMaxAgeDays:    "0",
		PolicyAssetSecretMaxAgeDays: "0",
		PolicyRetentionAuditLogDays: "0",
	}
	for _, def := range policyDefs {
		if want, ok := defaults[def.Key]; ok {
			require.Equal(t, want, def.Default,
				"%s 的出廠預設不得因新增電支基準而改動（合規為一鍵之遙，非強制）", def.Key)
		}
	}
}
