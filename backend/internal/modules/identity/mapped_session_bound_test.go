package identity

import (
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
)

type okRelaxRaiser struct{}

func (okRelaxRaiser) RaiseHighRiskInTx(*gorm.DB, policy.HighRiskAlert) error {
	return nil
}

// TestMappedSessionRevalidationBound 持映射支持的帳號，refresh 的絕對壽命取
// min(web_max_session_hours, 映射重新驗證時限)；輪替只縮短不延長；支持讀不到即拒絕。
func TestMappedSessionRevalidationBound(t *testing.T) {
	setup := func(t *testing.T, maxHours, revalHours string) (*oidcLifecycleEnv, *model.User, *model.User) {
		e := setupOIDCLifecycleEnv(t)
		e.policies.SetHighRiskAlertRaiser(okRelaxRaiser{})
		e.policies.Update(policy.PolicyWebIdleMinutes, "0", "admin")
		e.policies.Update(policy.PolicyWebMaxSessionHours, maxHours, "admin")
		if _, err := e.policies.UpdateBatch(map[string]string{policy.PolicyMappingRevalidationHours: revalHours}, "admin"); err != nil {
			t.Fatalf("設定時限: %v", err)
		}
		mapped := e.seedIdentityUser(t, "mapped-user", "sub-mapped", nil)
		plain := e.seedIdentityUser(t, "plain-user", "sub-plain", nil)
		if err := e.db.Exec("INSERT INTO user_role_mapping_rule_supports(user_id,role_id,channel,rule_id) VALUES (?,?,?,?)",
			mapped.ID, 1, "provider:1", 1).Error; err != nil {
			t.Fatalf("寫入支持: %v", err)
		}
		return e, mapped, plain
	}
	issue := func(t *testing.T, e *oidcLifecycleEnv, uid uint, start time.Time) time.Time {
		t.Helper()
		_, exp, err := e.auth.issueRefreshToken(uid, start, crypto.AuthContext{})
		if err != nil {
			t.Fatalf("發放: %v", err)
		}
		return exp
	}
	start := time.Now().Truncate(time.Second)
	near := func(a, b time.Time) bool { d := a.Sub(b); return d > -time.Second && d < time.Second }

	t.Run("T=12：政策 0 與 24 下持支持帳號為 12 小時，無支持帳號為政策值，政策 4 為 4 小時", func(t *testing.T) {
		for _, c := range []struct {
			policyHours string
			mapped      time.Duration
			plain       time.Duration
		}{
			{"0", 12 * time.Hour, unlimitedSessionLifetime},
			{"24", 12 * time.Hour, 24 * time.Hour},
			{"4", 4 * time.Hour, 4 * time.Hour},
		} {
			e, mapped, plain := setup(t, c.policyHours, "12")
			if got := issue(t, e, mapped.ID, start); !near(got, start.Add(c.mapped)) {
				t.Errorf("政策 %s 持支持帳號到期 %v，want +%v", c.policyHours, got.Sub(start), c.mapped)
			}
			if got := issue(t, e, plain.ID, start); !near(got, start.Add(c.plain)) {
				t.Errorf("政策 %s 無支持帳號到期 %v，want +%v", c.policyHours, got.Sub(start), c.plain)
			}
		}
	})

	t.Run("T=168 政策 0 為 168 小時；T=0 時持支持帳號只依政策值", func(t *testing.T) {
		e, mapped, _ := setup(t, "0", "168")
		if got := issue(t, e, mapped.ID, start); !near(got, start.Add(168*time.Hour)) {
			t.Errorf("T=168 到期 %v", got.Sub(start))
		}
		e, mapped, _ = setup(t, "24", "0")
		if got := issue(t, e, mapped.ID, start); !near(got, start.Add(24*time.Hour)) {
			t.Errorf("T=0 到期 %v，want 政策值 24h", got.Sub(start))
		}
	})

	t.Run("輪替沿用上限不延長；時限之後調短則輪替重新套用，到期即拒絕", func(t *testing.T) {
		e, mapped, _ := setup(t, "24", "12")
		plain, exp, err := e.auth.issueRefreshToken(mapped.ID, time.Now(), crypto.AuthContext{})
		if err != nil {
			t.Fatal(err)
		}
		// 時限調長不延長既有憑證
		if _, err := e.policies.UpdateBatch(map[string]string{policy.PolicyMappingRevalidationHours: "168"}, "admin"); err != nil {
			t.Fatal(err)
		}
		rot, err := e.auth.RefreshSession(plain, "")
		if err != nil {
			t.Fatalf("輪替: %v", err)
		}
		if !near(rot.RefreshExpiresAt, exp) {
			t.Errorf("輪替後到期 %v，want 不變 %v", rot.RefreshExpiresAt, exp)
		}
		// 時限調短到已超過：下一次輪替被拒
		old := time.Now().Add(-3 * time.Hour)
		if err := e.db.Model(&model.RefreshToken{}).Where("token_hash = ?", hashRefreshToken(rot.RefreshToken)).
			Update("session_started_at", old).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := e.policies.UpdateBatch(map[string]string{policy.PolicyMappingRevalidationHours: "2"}, "admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.auth.RefreshSession(rot.RefreshToken, ""); !errors.Is(err, ErrRefreshInvalid) {
			t.Fatalf("超過新時限的輪替應被拒: %v", err)
		}
	})

	t.Run("支持讀取失敗時發放與輪替被拒且無新 refresh 列", func(t *testing.T) {
		e, mapped, _ := setup(t, "24", "12")
		plain, _, err := e.auth.issueRefreshToken(mapped.ID, time.Now(), crypto.AuthContext{})
		if err != nil {
			t.Fatal(err)
		}
		var before int64
		e.db.Model(&model.RefreshToken{}).Count(&before)
		if err := e.db.Exec("DROP TABLE user_role_mapping_rule_supports").Error; err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.auth.issueRefreshToken(mapped.ID, time.Now(), crypto.AuthContext{}); err == nil {
			t.Fatal("讀不到支持時發放應被拒")
		}
		if _, err := e.auth.RefreshSession(plain, ""); err == nil {
			t.Fatal("讀不到支持時輪替應被拒")
		}
		var after int64
		e.db.Model(&model.RefreshToken{}).Count(&after)
		if after != before {
			t.Fatalf("refresh 列 %d → %d，不應新增", before, after)
		}
	})

	t.Run("預設 12 時與現行結果相同", func(t *testing.T) {
		e := setupOIDCLifecycleEnv(t)
		plainUser := e.seedIdentityUser(t, "default-user", "sub-default", nil)
		got := issue(t, e, plainUser.ID, start)
		if !near(got, start.Add(12*time.Hour)) {
			t.Errorf("預設到期 %v，want 12h", got.Sub(start))
		}
	})
}
