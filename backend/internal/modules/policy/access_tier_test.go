package policy

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestEffectiveAccessTier 有效段位與降級判定單一來源（spec 五個 Scenario 各一案例）
func TestEffectiveAccessTier(t *testing.T) {
	ap, rs, op := model.AccessPolicyApproval, model.AccessPolicyReason, model.AccessPolicyOpen
	bad := "bogus"
	empty := ""

	t.Run("覆寫調低", func(t *testing.T) {
		tc := ClassifyOverrideChange(&ap, &rs, op)
		if tc.Result != TierChangeDowngraded || tc.Cause != TierCauseOverrideLowered ||
			tc.BeforeTier != ap || tc.AfterTier != rs {
			t.Fatalf("got %+v", tc)
		}
	})
	t.Run("清除覆寫回落到較低預設", func(t *testing.T) {
		tc := ClassifyOverrideChange(&rs, nil, op)
		if tc.Result != TierChangeDowngraded || tc.Cause != TierCauseOverrideCleared {
			t.Fatalf("got %+v", tc)
		}
		tc = ClassifyOverrideChange(&rs, &empty, op)
		if tc.Result != TierChangeDowngraded || tc.Cause != TierCauseOverrideCleared {
			t.Fatalf("empty string clear: got %+v", tc)
		}
	})
	t.Run("清除覆寫回落到相同或較高預設", func(t *testing.T) {
		if tc := ClassifyOverrideChange(&rs, nil, ap); tc.Result != TierChangeTightened || tc.Cause != "" {
			t.Fatalf("higher default: got %+v", tc)
		}
		if tc := ClassifyOverrideChange(&rs, nil, rs); tc.Result != TierChangeUnchanged {
			t.Fatalf("same default: got %+v", tc)
		}
	})
	t.Run("新增與預設相同的覆寫", func(t *testing.T) {
		if tc := ClassifyOverrideChange(nil, &op, op); tc.Result != TierChangeUnchanged {
			t.Fatalf("got %+v", tc)
		}
		// 收緊
		if tc := ClassifyOverrideChange(nil, &ap, op); tc.Result != TierChangeTightened {
			t.Fatalf("tighten: got %+v", tc)
		}
	})
	t.Run("全域預設調低以同一計算判定", func(t *testing.T) {
		tc := ClassifyDefaultChange(ap, rs)
		if tc.Result != TierChangeDowngraded || tc.Cause != TierCauseDefaultLowered {
			t.Fatalf("got %+v", tc)
		}
		if tc := ClassifyDefaultChange(rs, ap); tc.Result != TierChangeTightened {
			t.Fatalf("tighten: got %+v", tc)
		}
		if tc := ClassifyDefaultChange(rs, rs); tc.Result != TierChangeUnchanged {
			t.Fatalf("same: got %+v", tc)
		}
	})
	t.Run("非法值退回規則", func(t *testing.T) {
		if got := EffectiveTier(&bad, rs); got != rs {
			t.Fatalf("invalid override should fall to default, got %q", got)
		}
		if got := EffectiveTier(nil, bad); got != op {
			t.Fatalf("invalid default should be open, got %q", got)
		}
		if got := EffectiveTier(&bad, bad); got != op {
			t.Fatalf("both invalid should be open, got %q", got)
		}
		if got := EffectiveTier(&ap, bad); got != ap {
			t.Fatalf("valid override wins, got %q", got)
		}
		if tc := ClassifyDefaultChange(bad, rs); tc.Result != TierChangeTightened || tc.BeforeTier != op {
			t.Fatalf("invalid before default: got %+v", tc)
		}
	})
	t.Run("段位序", func(t *testing.T) {
		if !(TierRank(op) < TierRank(rs) && TierRank(rs) < TierRank(ap)) {
			t.Fatal("rank order wrong")
		}
	})
}
