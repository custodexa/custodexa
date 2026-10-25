package policy

import "github.com/custodexa/backend/internal/model"

// 段位變更分類結果（單台覆寫與全域預設共用）
const (
	TierChangeUnchanged  = "unchanged"
	TierChangeTightened  = "tightened"
	TierChangeDowngraded = "downgraded"
)

// 降級型態（對應系統告警「型態」參數三值）
const (
	TierCauseOverrideLowered = "override_lowered"
	TierCauseOverrideCleared = "override_cleared"
	TierCauseDefaultLowered  = "default_lowered"
)

// TierChange 段位變更分類。Cause 只在 Result 為 downgraded 時有值。
type TierChange struct {
	Result string
	Cause  string
	// BeforeTier、AfterTier 為變更前後的有效段位
	BeforeTier string
	AfterTier  string
}

// EffectiveTier 有效段位：合法覆寫值優先；否則取合法的全域預設；
// 兩者皆不合法時為 open。政策閘、批次標註、降級分類共用此一份計算。
func EffectiveTier(override *string, globalDefault string) string {
	if override != nil && isValidAccessPolicy(*override) {
		return *override
	}
	if isValidAccessPolicy(globalDefault) {
		return globalDefault
	}
	return model.AccessPolicyOpen
}

// TierRank 段位序：open=0、reason=1、approval=2；非法值視同 open。
func TierRank(tier string) int {
	switch tier {
	case model.AccessPolicyApproval:
		return 2
	case model.AccessPolicyReason:
		return 1
	default:
		return 0
	}
}

func classifyTiers(before, after string) (result string) {
	switch rb, ra := TierRank(before), TierRank(after); {
	case ra < rb:
		return TierChangeDowngraded
	case ra > rb:
		return TierChangeTightened
	default:
		return TierChangeUnchanged
	}
}

// ClassifyOverrideChange 單台覆寫變更分類。前後有效段位都以同一個
// globalDefault 計算（呼叫端在同一交易內只讀一次預設）。
// 降級且變更後不再有合法覆寫（清除）時 cause 為 override_cleared，否則 override_lowered。
func ClassifyOverrideChange(before, after *string, globalDefault string) TierChange {
	b := EffectiveTier(before, globalDefault)
	a := EffectiveTier(after, globalDefault)
	tc := TierChange{Result: classifyTiers(b, a), BeforeTier: b, AfterTier: a}
	if tc.Result == TierChangeDowngraded {
		if after == nil || !isValidAccessPolicy(*after) {
			tc.Cause = TierCauseOverrideCleared
		} else {
			tc.Cause = TierCauseOverrideLowered
		}
	}
	return tc
}

// ClassifyDefaultChange 全域預設變更分類（同一套段位序）；降級的 cause 為 default_lowered。
func ClassifyDefaultChange(before, after string) TierChange {
	b := EffectiveTier(nil, before)
	a := EffectiveTier(nil, after)
	tc := TierChange{Result: classifyTiers(b, a), BeforeTier: b, AfterTier: a}
	if tc.Result == TierChangeDowngraded {
		tc.Cause = TierCauseDefaultLowered
	}
	return tc
}
