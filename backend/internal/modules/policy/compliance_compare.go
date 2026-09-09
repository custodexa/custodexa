package policy

import (
	"strconv"

	"github.com/custodexa/backend/internal/model"
)

// 合規判定與套用計算共用的比較器。
//
// **只有一份比較邏輯**：設定頁的分區偏離數、合規對照頁的逐條結果與套用預覽表
// 三處回答的是同一個問題（現值有沒有達到這條要求）。三處各寫一份的話，某些取值
// 上的分歧不會有任何一處報錯——管理者與稽核人員在同一時點看到不同的答案，
// 而系統沒有訊號。

// 鍵層判定的四種結果。字串即對外契約（API 與前端直接使用這些值）。
const (
	// ComplianceResultCompliant 現值達到該組對該鍵的要求
	ComplianceResultCompliant = "compliant"
	// ComplianceResultDeviating 現值未達要求
	ComplianceResultDeviating = "deviating"
	// ComplianceResultNeedsReview 該組以參考值呈現、未給固定要求，待機構人工確認
	ComplianceResultNeedsReview = "needs_review"
	// ComplianceResultAuditReview 該組有條文涉及該鍵但條文未定值，附目前值待稽核判讀
	ComplianceResultAuditReview = "review"
	// ComplianceResultUnmapped 該鍵不在任何生效組的條文內
	ComplianceResultUnmapped = "unmapped"
)

// 判定理由。**是機器碼而不是句子**：呈現層要以各語系的人話說出「至少 12 字元、
// 目前 8」，句子留在呈現層才能翻譯，也才不會有兩份措辭。
const (
	// ComplianceReasonMeets 現值達到要求
	ComplianceReasonMeets = "meets_expectation"
	// ComplianceReasonBelowMinimum 現值低於「至少」型的要求
	ComplianceReasonBelowMinimum = "below_minimum"
	// ComplianceReasonAboveMaximum 現值高於「至多」型的要求
	ComplianceReasonAboveMaximum = "above_maximum"
	// ComplianceReasonValueMismatch 明確值型的要求不相符
	ComplianceReasonValueMismatch = "value_mismatch"
	// ComplianceReasonDisabled 該鍵的零值代表機制停用，而要求非零
	ComplianceReasonDisabled = "disabled_by_zero"
	// ComplianceReasonNotComparable 現值或要求值在這個鍵上無法比較
	ComplianceReasonNotComparable = "value_not_comparable"
	// ComplianceReasonReferenceUnconfirmed 參考值，機構尚未確認
	ComplianceReasonReferenceUnconfirmed = "reference_value_unconfirmed"
	// ComplianceReasonReferenceConfirmed 參考值，機構已確認
	ComplianceReasonReferenceConfirmed = "reference_value_confirmed"
	// ComplianceReasonExpectationUnspecified 條文涉及這個鍵但未定值
	ComplianceReasonExpectationUnspecified = "expectation_unspecified"
	// ComplianceReasonNoControl 沒有任何生效組對照這個鍵
	ComplianceReasonNoControl = "no_control"
)

// compareExpectation 現值是否達到一條要求，附理由碼。
//
// 比較方式由呼叫端給定而不由鍵的型別推導：同一個鍵可以被不同的政策組以不同的
// 方向要求（一組要求「至少」、另一組要求「至多」），推導會讓其中一邊被靜默改寫。
//
// 零值代表停用的鍵（ZeroDisables）在要求非零時**先判偏離**：0 在數值上小於任何
// 上限，照數值比較會把「這個機制沒開」讀成「設得比要求更嚴」。要求本身就是零時
// （條文要求該機制關閉）不適用，照數值比較。
func compareExpectation(def *PolicyDef, value, comparator, expected string) (bool, string) {
	if def == nil || expected == "" {
		return false, ComplianceReasonNotComparable
	}
	switch def.Type {
	case PolicyTypeInt:
		return compareIntExpectation(def, value, comparator, expected)
	case PolicyTypeBool, PolicyTypeEnum:
		return compareOrderedExpectation(def, value, comparator, expected)
	}
	// 文字型沒有任何一種比較方式是有意義的（寫入端已擋，這裡是最後一道）
	return false, ComplianceReasonNotComparable
}

func compareIntExpectation(def *PolicyDef, value, comparator, expected string) (bool, string) {
	n, err := strconv.Atoi(value)
	base, baseErr := strconv.Atoi(expected)
	if err != nil || baseErr != nil {
		return false, ComplianceReasonNotComparable
	}
	if def.ZeroDisables && n == 0 && base != 0 {
		return false, ComplianceReasonDisabled
	}
	return compareRanks(n, base, comparator)
}

// compareOrderedExpectation 開關與枚舉：明確值比對，或（過渡路徑）等級序位比對。
//
// 政策組的開關與枚舉要求一律是明確值——這兩類的取值之間沒有強弱序，以序位比較
// 會把要求值靜默讀成「至少這麼嚴」。序位比較只出現在設定鍵定義上的規範欄位那條
// 過渡路徑（那些欄位的語義本來就是等級表）。
func compareOrderedExpectation(def *PolicyDef, value, comparator, expected string) (bool, string) {
	rank, ok := policyValueRank(def, value)
	baseRank, baseOK := policyValueRank(def, expected)
	if !ok || !baseOK {
		return false, ComplianceReasonNotComparable
	}
	if comparator == model.PolicyControlComparatorEquals {
		if value == expected {
			return true, ComplianceReasonMeets
		}
		return false, ComplianceReasonValueMismatch
	}
	return compareRanks(rank, baseRank, comparator)
}

// compareRanks 序數的方向比較（整數即數值本身，枚舉與開關為序位）。
func compareRanks(value, expected int, comparator string) (bool, string) {
	switch comparator {
	case model.PolicyControlComparatorMin:
		if value >= expected {
			return true, ComplianceReasonMeets
		}
		return false, ComplianceReasonBelowMinimum
	case model.PolicyControlComparatorMax:
		if value <= expected {
			return true, ComplianceReasonMeets
		}
		return false, ComplianceReasonAboveMaximum
	case model.PolicyControlComparatorEquals:
		if value == expected {
			return true, ComplianceReasonMeets
		}
		return false, ComplianceReasonValueMismatch
	}
	return false, ComplianceReasonNotComparable
}

// policyValueRank 值在該鍵的強弱序上的位置。
//
// 整數即數值本身；枚舉為 EnumOrder 的序位（弱→強）；開關以「關 < 開」計，
// 供取嚴計算使用。ok=false 表示該值在這個鍵上無法比較。
func policyValueRank(def *PolicyDef, value string) (int, bool) {
	if def == nil {
		return 0, false
	}
	switch def.Type {
	case PolicyTypeInt:
		n, err := strconv.Atoi(value)
		if err != nil {
			return 0, false
		}
		return n, true
	case PolicyTypeBool:
		switch value {
		case "false":
			return 0, true
		case "true":
			return 1, true
		}
		return 0, false
	case PolicyTypeEnum:
		rank := enumRank(def.EnumOrder, value)
		if rank < 0 {
			return 0, false
		}
		return rank, true
	}
	return 0, false
}
