package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// auth-session 能力在 OIDC 軌道上的差異情境。
//
// 既有的 auth_refresh_service_test.go 只跑本地密碼軌道；本檔補的是 OIDC 軌道特有的
// 三件事：脈絡欄位必須跨輪替沿用、絕對壽命不因輪替而重置、達上限須重新認證。
//
// 時間控制方式：本專案的 AuthService 未提供時鐘注入，但絕對壽命的錨點
//（SessionStartedAt）是 issueRefreshToken 的入參，故以「把錨點設在過去」搭配
// 短測試期限即可精確落在窗口兩側，且走的是 production 的到期公式
//（sessionStart + webMaxSessionDuration()），不是手寫 expires_at 欄位——
// 手寫欄位等於在斷言我們剛剛寫進去的值，公式改錯不會被抓到。

// oidcSessionEnv 一個已完成 OIDC 登入的環境，回傳登入回應與該使用者
func newOIDCSessionEnv(t *testing.T, maxHours, idleMinutes string) (*oidcLifecycleEnv, *model.User) {
	t.Helper()
	e := setupOIDCLifecycleEnv(t)
	e.policies.Update(policy.PolicyWebMaxSessionHours, maxHours, "admin")
	// 閒置窗關閉：本檔要斷言的是**絕對**壽命，閒置判定會在錨點被撥到過去時
	// 一併觸發，使「因為哪一條而被拒」無法分辨
	e.policies.Update(policy.PolicyWebIdleMinutes, idleMinutes, "admin")
	user := e.seedIdentityUser(t, "sso-session", "sub-sso-session", nil)
	return e, user
}

// oidcLogin 走交棒憑證兌換取得正式會話
func (e *oidcLifecycleEnv) oidcLogin(t *testing.T, user *model.User) *LoginResponse {
	t.Helper()
	ticket := issueTestTicket(t, e.login, user, e.provider, capabilityBrowserSecret)
	resp, _, err := e.login.Exchange(ticket, capabilityBrowserSecret)
	if err != nil {
		t.Fatalf("OIDC 兌換: %v", err)
	}
	return resp
}

// Scenario: OIDC 會話同軌刷新
func TestOIDCRefreshRotatesOnSameTrack(t *testing.T) {
	e, user := newOIDCSessionEnv(t, "12", "0")
	epoch := e.providerAuthEpoch(t)

	resp := e.oidcLogin(t, user)
	before := reloadRefresh(t, e.db, hashRefreshToken(resp.RefreshToken))

	rotated, err := e.auth.RefreshSession(resp.RefreshToken, "")
	if err != nil {
		t.Fatalf("刷新: %v", err)
	}
	after := reloadRefresh(t, e.db, hashRefreshToken(rotated.RefreshToken))

	// 四個脈絡欄位逐一沿用。漏帶任一個，provider 停用的撤銷查詢就命中 0 列——
	// 正在使用中的會話一個都撤不到，可續命至絕對壽命
	if after.AuthMethod != crypto.AuthMethodOIDC {
		t.Errorf("輪替後 auth_method = %q, want %q", after.AuthMethod, crypto.AuthMethodOIDC)
	}
	if after.ProviderID != e.provider.ID {
		t.Errorf("輪替後 provider_id = %d, want %d", after.ProviderID, e.provider.ID)
	}
	if after.AuthEpoch != before.AuthEpoch || after.AuthEpoch != epoch {
		t.Errorf("輪替後 auth_epoch = %d, want %d", after.AuthEpoch, epoch)
	}
	if after.CredEpoch != before.CredEpoch {
		t.Errorf("輪替後 cred_epoch = %d, want %d", after.CredEpoch, before.CredEpoch)
	}

	// 換發的 access 亦須帶同一條軌道的脈絡，否則它在 WS 旁路與中介層上都會被
	// 當成「本地登入」而豁免 provider 維度的判定
	claims, err := e.auth.ValidateToken(rotated.Token)
	if err != nil {
		t.Fatalf("解析換發的 access: %v", err)
	}
	if claims.AuthContext.AuthMethod != crypto.AuthMethodOIDC ||
		claims.AuthContext.ProviderID != e.provider.ID ||
		claims.AuthContext.AuthEpoch != epoch {
		t.Errorf("換發的 access 脈絡 = %+v, want oidc/provider=%d/epoch=%d",
			claims.AuthContext, e.provider.ID, epoch)
	}
	// 舊憑證已標記輪替（reuse detection 的前提）
	if reloadRefresh(t, e.db, hashRefreshToken(resp.RefreshToken)).RevokedReason != model.RefreshRevokeRotated {
		t.Error("舊 refresh 應標記為 rotated")
	}
}

// Scenario: 多次輪替不重置絕對壽命
func TestOIDCRefreshRotationsDoNotResetAbsoluteLifetime(t *testing.T) {
	e, user := newOIDCSessionEnv(t, "1", "0")

	resp := e.oidcLogin(t, user)
	origin := reloadRefresh(t, e.db, hashRefreshToken(resp.RefreshToken))

	current := resp.RefreshToken
	for i := 1; i <= 3; i++ {
		rotated, err := e.auth.RefreshSession(current, "")
		if err != nil {
			t.Fatalf("第 %d 次刷新: %v", i, err)
		}
		current = rotated.RefreshToken
		row := reloadRefresh(t, e.db, hashRefreshToken(current))
		// 錨點與到期時間都必須沿用原值；任一被重設即等於「持續刷新可無限續命」，
		// 絕對壽命政策形同不存在
		if row.SessionStartedAt.Unix() != origin.SessionStartedAt.Unix() {
			t.Fatalf("第 %d 次輪替重置了會話錨點: %v → %v",
				i, origin.SessionStartedAt, row.SessionStartedAt)
		}
		if row.ExpiresAt.Unix() != origin.ExpiresAt.Unix() {
			t.Fatalf("第 %d 次輪替延長了絕對壽命: %v → %v", i, origin.ExpiresAt, row.ExpiresAt)
		}
	}
	// 政策值確實被套用（排除「因為兩者都是遠期哨兵所以看起來相等」）
	if d := origin.ExpiresAt.Sub(origin.SessionStartedAt); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("絕對壽命 = %v, want ≈1h（政策未生效則本測試無鑑別力）", d)
	}
}

// Scenario: 達絕對上限須重新認證
func TestOIDCRefreshAtAbsoluteLimitRequiresReauthentication(t *testing.T) {
	e, user := newOIDCSessionEnv(t, "1", "0")

	// 錨點設在 61 分鐘前 → expires_at 由 production 公式算出即已過期。
	// last_used_at 同樣是錨點，但閒置窗已關閉，故唯一的失效來源是絕對壽命
	plain, _, err := e.auth.issueRefreshToken(user.ID, time.Now().Add(-61*time.Minute), e.oidcCtxFor(user))
	if err != nil {
		t.Fatalf("issueRefreshToken: %v", err)
	}
	if row := reloadRefresh(t, e.db, hashRefreshToken(plain)); !time.Now().After(row.ExpiresAt) {
		t.Fatalf("前提不成立：expires_at=%v 尚未過期", row.ExpiresAt)
	}

	if _, err := e.auth.RefreshSession(plain, ""); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatalf("逾絕對壽命刷新 = %v, want ErrRefreshInvalid", err)
	}
	if reason := reloadRefresh(t, e.db, hashRefreshToken(plain)).RevokedReason; reason != model.RefreshRevokeExpired {
		t.Errorf("撤銷成因 = %q, want %q（成因不符代表被別條規則攔下）",
			reason, model.RefreshRevokeExpired)
	}

	// 「須重新認證」的另一半：重新走一次 OIDC 認證即可取得可用的新會話，
	// 不是把帳號卡死
	fresh := e.oidcLogin(t, user)
	if _, err := e.auth.RefreshSession(fresh.RefreshToken, ""); err != nil {
		t.Errorf("重新認證後的新會話應可刷新: %v", err)
	}
}

// Scenario: 換發的 access 不越過絕對期限
//
// **本測試目前為 t.Skip（實作與 tasks 要求不符，屬既有缺陷）**：
// RefreshSession 換發 access 時走 jwtManager.GenerateToken，其到期一律是
// now + tokenDuration（AccessTokenTTL 15 分），沒有以 refresh 列的 expires_at
// 做上限裁切。於是在絕對期限前 5 分鐘刷新，會拿到一枚活到期限後 10 分鐘的
// access token——而 access 在 WS 旁路（/connect、/ssh、/sessions/:id/monitor）
// 上足以開啟新的協議連線，連線建立後不再出示憑證，等於絕對壽命被繞過。
//
// 缺陷已修（GenerateTokenNotAfter 以 refresh 列的 expires_at 裁切）：修復前
// 實測換發的 access 到期越過會話絕對期限 9m59s。
func TestOIDCReissuedAccessDoesNotOutliveAbsoluteDeadline(t *testing.T) {
	e, user := newOIDCSessionEnv(t, "1", "0")

	// 距絕對期限僅剩 5 分鐘時刷新
	plain, _, err := e.auth.issueRefreshToken(user.ID, time.Now().Add(-55*time.Minute), e.oidcCtxFor(user))
	if err != nil {
		t.Fatalf("issueRefreshToken: %v", err)
	}
	deadline := reloadRefresh(t, e.db, hashRefreshToken(plain)).ExpiresAt

	rotated, err := e.auth.RefreshSession(plain, "")
	if err != nil {
		t.Fatalf("刷新: %v", err)
	}
	claims, err := e.auth.ValidateToken(rotated.Token)
	if err != nil {
		t.Fatalf("解析換發的 access: %v", err)
	}
	if claims.ExpiresAt == nil {
		t.Fatal("access token 應帶 exp")
	}
	if claims.ExpiresAt.Time.After(deadline) {
		t.Fatalf("換發的 access 到期 %v 越過會話絕對期限 %v（差 %v）",
			claims.ExpiresAt.Time, deadline, claims.ExpiresAt.Time.Sub(deadline))
	}
}
