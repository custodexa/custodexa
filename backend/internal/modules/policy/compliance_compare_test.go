package policy

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 比較器是判定與套用共用的唯一一份比較邏輯。本檔釘住它的每一個分支，
// 並釘住「規範欄位的兩支舊函式改為薄包裝後語義不變」。

func TestCompareExpectation(t *testing.T) {
	intMin := &PolicyDef{Key: "pwd_len", Type: PolicyTypeInt, Direction: DirectionMin}
	intMax := &PolicyDef{Key: "idle", Type: PolicyTypeInt, Direction: DirectionMax}
	zeroDisables := &PolicyDef{Key: "lockout", Type: PolicyTypeInt, Direction: DirectionMax, ZeroDisables: true}
	boolDef := &PolicyDef{Key: "clipboard", Type: PolicyTypeBool}
	enumDef := &PolicyDef{Key: "transport", Type: PolicyTypeEnum, EnumOrder: []string{"off", "warn", "strict"}}
	textDef := &PolicyDef{Key: "banner", Type: PolicyTypeText, MaxLength: 10}

	cases := []struct {
		name       string
		def        *PolicyDef
		value      string
		comparator string
		expected   string
		wantOK     bool
		wantReason string
	}{
		{
			name: "至少：現值等於要求即達到", def: intMin, value: "12",
			comparator: model.PolicyControlComparatorMin, expected: "12",
			wantOK: true, wantReason: ComplianceReasonMeets,
		},
		{
			name: "至少：現值更大即達到", def: intMin, value: "16",
			comparator: model.PolicyControlComparatorMin, expected: "12",
			wantOK: true, wantReason: ComplianceReasonMeets,
		},
		{
			name: "至少：現值較小即偏離", def: intMin, value: "8",
			comparator: model.PolicyControlComparatorMin, expected: "12",
			wantOK: false, wantReason: ComplianceReasonBelowMinimum,
		},
		{
			name: "至多：現值較小即達到", def: intMax, value: "8",
			comparator: model.PolicyControlComparatorMax, expected: "10",
			wantOK: true, wantReason: ComplianceReasonMeets,
		},
		{
			name: "至多：現值較大即偏離", def: intMax, value: "15",
			comparator: model.PolicyControlComparatorMax, expected: "10",
			wantOK: false, wantReason: ComplianceReasonAboveMaximum,
		},
		{
			// 零值三態之一：零代表停用的鍵，要求非零時零值是「機制沒開」而不是「較小的數」
			name: "零值停用：要求非零時零值偏離", def: zeroDisables, value: "0",
			comparator: model.PolicyControlComparatorMax, expected: "5",
			wantOK: false, wantReason: ComplianceReasonDisabled,
		},
		{
			// 零值三態之二：同一個鍵的非零值照常比較
			name: "零值停用：非零值照常比較", def: zeroDisables, value: "3",
			comparator: model.PolicyControlComparatorMax, expected: "5",
			wantOK: true, wantReason: ComplianceReasonMeets,
		},
		{
			// 零值三態之三：沒有停用語義的鍵，零就只是零
			name: "無零值停用語義：零照常比較", def: intMax, value: "0",
			comparator: model.PolicyControlComparatorMax, expected: "10",
			wantOK: true, wantReason: ComplianceReasonMeets,
		},
		{
			// 要求本身就是「必須停用」時，零值即達到要求
			name: "零值停用：要求為零時零值達到", def: zeroDisables, value: "0",
			comparator: model.PolicyControlComparatorMax, expected: "0",
			wantOK: true, wantReason: ComplianceReasonMeets,
		},
		{
			name: "整數：現值不可解析即偏離", def: intMin, value: "abc",
			comparator: model.PolicyControlComparatorMin, expected: "12",
			wantOK: false, wantReason: ComplianceReasonNotComparable,
		},
		{
			name: "開關：等值即達到", def: boolDef, value: "false",
			comparator: model.PolicyControlComparatorEquals, expected: "false",
			wantOK: true, wantReason: ComplianceReasonMeets,
		},
		{
			name: "開關：不等值即偏離（不做強弱序）", def: boolDef, value: "true",
			comparator: model.PolicyControlComparatorEquals, expected: "false",
			wantOK: false, wantReason: ComplianceReasonValueMismatch,
		},
		{
			name: "枚舉：明確值相符即達到", def: enumDef, value: "warn",
			comparator: model.PolicyControlComparatorEquals, expected: "warn",
			wantOK: true, wantReason: ComplianceReasonMeets,
		},
		{
			// 明確值的語義：更高的等級也不算相符（強弱序不由比較器臆測）
			name: "枚舉：明確值不符即偏離", def: enumDef, value: "strict",
			comparator: model.PolicyControlComparatorEquals, expected: "warn",
			wantOK: false, wantReason: ComplianceReasonValueMismatch,
		},
		{
			// 過渡路徑：規範欄位的等級表以序位比較（弱→強），高於要求視為達到
			name: "枚舉序位：高於要求即達到", def: enumDef, value: "strict",
			comparator: model.PolicyControlComparatorMin, expected: "warn",
			wantOK: true, wantReason: ComplianceReasonMeets,
		},
		{
			name: "枚舉序位：低於要求即偏離", def: enumDef, value: "off",
			comparator: model.PolicyControlComparatorMin, expected: "warn",
			wantOK: false, wantReason: ComplianceReasonBelowMinimum,
		},
		{
			name: "枚舉：值不在允許集合即偏離", def: enumDef, value: "bogus",
			comparator: model.PolicyControlComparatorEquals, expected: "warn",
			wantOK: false, wantReason: ComplianceReasonNotComparable,
		},
		{
			name: "文字型不可作為要求的對象", def: textDef, value: "abc",
			comparator: model.PolicyControlComparatorEquals, expected: "abc",
			wantOK: false, wantReason: ComplianceReasonNotComparable,
		},
		{
			name: "要求值為空即不可比較", def: intMin, value: "12",
			comparator: model.PolicyControlComparatorMin, expected: "",
			wantOK: false, wantReason: ComplianceReasonNotComparable,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := compareExpectation(c.def, c.value, c.comparator, c.expected)
			if ok != c.wantOK {
				t.Errorf("達到要求 = %v, want %v（理由 %s）", ok, c.wantOK, reason)
			}
			if reason != c.wantReason {
				t.Errorf("理由 = %q, want %q", reason, c.wantReason)
			}
		})
	}
}
