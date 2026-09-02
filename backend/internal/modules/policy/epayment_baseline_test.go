package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// 電支基準雙軌（塊 6）。
//
// 本檔的重點是**取嚴語義**：兩基準在部分項目上方向相反，若「套用電支基準」
// 實作為無條件覆寫，一個已符合 PCI 的設定會被改差——「套用合規基準」這個動作
// 反而降低系統安全性。這是本塊唯一容易做錯之處。

func TestEvaluateStrictest_TakesStricterOfTwoBaselines(t *testing.T) {
	cases := []struct {
		name string
		def  PolicyDef
		want string
	}{
		{
			// 密碼最小長度：min 型（值須 >= 基準），電支 6 **寬於** PCI 12。
			// 這是真實資料，不是構造的邊界案例——policyDefs 就是這樣
			name: "min 型且電支較寬：取 PCI",
			def: PolicyDef{
				Type: PolicyTypeInt, Direction: DirectionMin,
				PCIValue: "12", EPaymentValue: "6",
			},
			want: "12",
		},
		{
			// 日誌保留：min 型，電支 730 嚴於 PCI 365
			name: "min 型且電支較嚴：取電支",
			def: PolicyDef{
				Type: PolicyTypeInt, Direction: DirectionMin,
				PCIValue: "365", EPaymentValue: "730",
			},
			want: "730",
		},
		{
			// 登入鎖定次數：max 型（值須 <= 基準），電支 5 嚴於 PCI 10
			name: "max 型且電支較嚴：取電支",
			def: PolicyDef{
				Type: PolicyTypeInt, Direction: DirectionMax,
				PCIValue: "10", EPaymentValue: "5",
			},
			want: "5",
		},
		{
			name: "max 型且 PCI 較嚴：取 PCI",
			def: PolicyDef{
				Type: PolicyTypeInt, Direction: DirectionMax,
				PCIValue: "15", EPaymentValue: "30",
			},
			want: "15",
		},
		{
			name: "兩者相同：任一皆可",
			def: PolicyDef{
				Type: PolicyTypeInt, Direction: DirectionMax,
				PCIValue: "90", EPaymentValue: "90",
			},
			want: "90",
		},
		{
			name: "無電支值：回 PCI",
			def:  PolicyDef{Type: PolicyTypeInt, Direction: DirectionMin, PCIValue: "12"},
			want: "12",
		},
		{
			name: "無 PCI 值：回電支",
			def:  PolicyDef{Type: PolicyTypeInt, Direction: DirectionMin, EPaymentValue: "6"},
			want: "6",
		},
		{
			name: "兩者皆無：空字串（呼叫端據此略過該項）",
			def:  PolicyDef{Type: PolicyTypeInt, Direction: DirectionMin},
			want: "",
		},
		{
			name: "bool 型：任一要求 true 即取 true",
			def:  PolicyDef{Type: PolicyTypeBool, PCIValue: "false", EPaymentValue: "true"},
			want: "true",
		},
		{
			name: "enum 型：序位較高者較嚴",
			def: PolicyDef{
				Type: PolicyTypeEnum, EnumOrder: []string{"off", "warn", "strict"},
				PCIValue: "warn", EPaymentValue: "strict",
			},
			want: "strict",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, evaluateStrictest(&c.def))
		})
	}
}

// 兩基準的符合性各自獨立：同一項可符合其一而偏離另一。
// 合計或以其一取代另一都會使兩者都不可解讀
func TestCompliance_TwoBaselinesEvaluatedIndependently(t *testing.T) {
	// 登入鎖定次數 max 型：現值 8 符合 PCI（<=10）但偏離電支（<=5）
	def := PolicyDef{
		Type: PolicyTypeInt, Direction: DirectionMax,
		PCIValue: "10", EPaymentValue: "5",
	}

	pci := evaluateCompliance(&def, "8")
	ep := evaluateEPaymentCompliance(&def, "8")

	require.NotNil(t, pci)
	require.NotNil(t, ep)
	require.True(t, *pci, "8 <= 10 應符合 PCI")
	require.False(t, *ep, "8 > 5 應偏離電支基準")
}

// 無該基準建議值時不評估（與 PCIValue 空值的既有語義一致）
func TestEPaymentCompliance_NilWhenNoBaseline(t *testing.T) {
	def := PolicyDef{Type: PolicyTypeInt, Direction: DirectionMin, PCIValue: "12"}
	require.Nil(t, evaluateEPaymentCompliance(&def, "8"),
		"無電支建議值的項目不得參與電支符合性評估")
	require.NotNil(t, evaluateCompliance(&def, "8"), "PCI 側評估不受影響")
}

// 有電支值的政策項與其條號。**本表即為機器可檢的權威副本**——值與條號直接寫在
// 這裡並被逐一斷言，改動任何一格都會紅。
// **釘住值本身**：這些數字來自法規，被誤改時應該紅
func TestPolicyDefs_EPaymentBaselineValues(t *testing.T) {
	want := map[string]struct{ value, requirement string }{
		PolicyLockoutMaxAttempts:    {"5", "4-7(五)"},
		PolicyPasswordMinLength:     {"6", "4-7(一)"},
		PolicyWebIdleMinutes:        {"10", "15-5"},
		PolicyPasswordMaxAgeDays:    {"90", "15-8"},
		PolicyAssetSecretMaxAgeDays: {"90", "15-8"},
		PolicyRetentionAuditLogDays: {"730", "19-4"},
	}

	got := map[string]struct{ value, requirement string }{}
	for _, def := range policyDefs {
		if def.EPaymentValue != "" {
			got[def.Key] = struct{ value, requirement string }{
				def.EPaymentValue, def.EPaymentRequirement,
			}
		}
	}

	require.Equal(t, want, got,
		"電支基準值集合與法規對照表不符——多了、少了或值被改動皆須有意識地同步本測試")
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
