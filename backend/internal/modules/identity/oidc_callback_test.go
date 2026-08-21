package identity

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// begin → callback → exchange 全鏈路（idp-oidc-integration tasks 4.1/4.3，design D4/D5/D7b）。
//
// 前面幾支測試各自打在流程的一段上；本檔把三段串起來跑真實的授權碼交換，
// 覆蓋 Callback 的固定順序：消費 flow state → 驗證 id_token → 查身分 →
// 求值 admission → 對應或供應 → 簽出 ticket。

// beginFlow 發起流程並取回 state 與 nonce（自授權 URL 解析，等同瀏覽器所見）。
// idp 非 nil 時一併把 code_challenge 交給 fake IdP 做 S256 實際配對
func beginFlow(t *testing.T, login *OIDCLoginService, p *model.OIDCProvider,
	browserSecret string, idp *fakeIdP) (state, nonce string) {
	t.Helper()
	res, err := login.Begin(context.Background(), p.ID, sha256Hex(browserSecret), "/dashboard")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	u, err := url.Parse(res.AuthorizationURL)
	if err != nil {
		t.Fatalf("解析授權 URL: %v", err)
	}
	q := u.Query()
	state, nonce = q.Get("state"), q.Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("授權 URL 應帶 state 與 nonce，實得 %s", res.AuthorizationURL)
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE(S256) 應恆啟用，實得 challenge=%q method=%q",
			q.Get("code_challenge"), q.Get("code_challenge_method"))
	}
	if idp != nil {
		idp.expectChallenge(q.Get("code_challenge"))
	}
	return state, nonce
}

// setupLiveFlow 一組接上 fake IdP 的完整環境
func setupLiveFlow(t *testing.T) (*OIDCLoginService, *OIDCProviderService, *fakeIdP, *model.OIDCProvider) {
	t.Helper()
	idp := newFakeIdP(t)
	login, providers, db := setupOIDCEnv(t)
	p := seedProvider(t, db, func(p *model.OIDCProvider) {
		p.Issuer = idp.issuer
		p.ClientID = "test-client"
		p.AdmissionMode = model.AdmissionJITWithRules
		p.AdmissionRules = `{"hd":["corp.example"]}`
	})
	return login, providers, idp, p
}

func TestFullFlowBeginCallbackExchange(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	state, nonce := beginFlow(t, login, p, "browser-secret", idp)

	idp.stageCode("code-1", idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: nonce,
		extra: map[string]any{
			"hd": "corp.example", "preferred_username": "bob",
			"email": "bob@corp.example", "email_verified": true,
		},
	}))

	res, err := login.Callback(context.Background(), state, "code-1")
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if res.Ticket == "" {
		t.Fatal("應簽出交棒憑證")
	}
	if res.RedirectNext != "/dashboard" {
		t.Errorf("redirect_next = %q, want /dashboard", res.RedirectNext)
	}

	// PKCE verifier 確實有送出（恆啟用而非可關閉選項）
	if _, verifier, mismatch := idp.stats(); verifier == "" || mismatch {
		t.Errorf("PKCE 配對應成立：verifier=%q mismatch=%v", verifier, mismatch)
	}

	resp, next, err := login.Exchange(res.Ticket, "browser-secret")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Token == "" {
		t.Error("應發放正式 token")
	}
	if next != "/dashboard" {
		t.Errorf("兌換回傳的 next = %q", next)
	}
	if resp.AuthSource != model.AuthSourceOIDC {
		t.Errorf("auth_source = %q, want oidc", resp.AuthSource)
	}
}

func TestCallbackRejectsReplayedState(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	state, nonce := beginFlow(t, login, p, "s", idp)
	mk := func(code string) {
		idp.stageCode(code, idp.issueIDToken(t, idTokenOpts{
			subject: "sub-1", audience: "test-client", nonce: nonce,
			extra: map[string]any{"hd": "corp.example", "preferred_username": "bob"},
		}))
	}
	mk("code-1")
	if _, err := login.Callback(context.Background(), state, "code-1"); err != nil {
		t.Fatalf("首次 callback: %v", err)
	}

	// 攔截到的 callback URL 重送：flow state 已消費，不得再走完流程
	mk("code-2")
	if _, err := login.Callback(context.Background(), state, "code-2"); !errors.Is(err, ErrOIDCFlowInvalid) {
		t.Fatalf("重放 state = %v, want ErrOIDCFlowInvalid", err)
	}
}

func TestCallbackRejectsUnknownState(t *testing.T) {
	login, _, idp, _ := setupLiveFlow(t)
	// 隨機 state 洪水：不得接觸 IdP 即應被擋（該路徑不受 flow state 容量限制）
	for i := 0; i < 5; i++ {
		if _, err := login.Callback(context.Background(), "never-issued", "code-x"); !errors.Is(err, ErrOIDCFlowInvalid) {
			t.Fatalf("未知 state = %v, want ErrOIDCFlowInvalid", err)
		}
	}
	// **不接觸 IdP** 是這條路徑的重點：否則攻擊者以隨機 state 洪水即可
	// 把流量放大轉嫁到 IdP 的 token 端點。只斷言「被拒」不足以證明這件事
	if reqs, _, _ := idp.stats(); reqs != 0 {
		t.Fatalf("未知 state 不得向 IdP 交換 code，實得 %d 次 token 請求", reqs)
	}
}

func TestCallbackRejectsAfterProviderDisabledMidFlow(t *testing.T) {
	login, providers, idp, p := setupLiveFlow(t)
	state, nonce := beginFlow(t, login, p, "s", idp)
	idp.stageCode("code-1", idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: nonce,
		extra: map[string]any{"hd": "corp.example", "preferred_username": "bob"},
	}))

	// begin 之後、callback 之前停用：使用者手上的授權重導向仍然有效，
	// 但世代已推進 → 必須拒絕（spec「停用後以先前取得的授權完成認證」情境）
	no := false
	if _, err := providers.Update(p.ID, &OIDCProviderRequest{Name: "corp", Enabled: &no}); err != nil {
		t.Fatalf("停用: %v", err)
	}

	if _, err := login.Callback(context.Background(), state, "code-1"); !errors.Is(err, ErrOIDCProviderUnavailable) {
		t.Fatalf("流程期間被停用 = %v, want ErrOIDCProviderUnavailable", err)
	}
}

func TestCallbackRejectsAfterProviderReEnabledMidFlow(t *testing.T) {
	login, providers, idp, p := setupLiveFlow(t)
	state, nonce := beginFlow(t, login, p, "s", idp)
	idp.stageCode("code-1", idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: nonce,
		extra: map[string]any{"hd": "corp.example", "preferred_username": "bob"},
	}))

	// 停用後又重新啟用：`enabled` 已復原，僅靠布林檢查會放行——
	// 世代不回退才是擋住這個窗口的機制
	no, yes := false, true
	providers.Update(p.ID, &OIDCProviderRequest{Name: "corp", Enabled: &no})
	providers.Update(p.ID, &OIDCProviderRequest{Name: "corp", Enabled: &yes})

	if _, err := login.Callback(context.Background(), state, "code-1"); !errors.Is(err, ErrOIDCProviderUnavailable) {
		t.Fatalf("停用後重新啟用，在途流程 = %v, want 仍被拒", err)
	}
}

func TestCallbackAdmissionDeniedBeforeProvisioning(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	state, nonce := beginFlow(t, login, p, "s", idp)
	idp.stageCode("code-1", idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: nonce,
		extra: map[string]any{"hd": "other.example", "preferred_username": "bob"},
	}))

	if _, err := login.Callback(context.Background(), state, "code-1"); !errors.Is(err, ErrOIDCAdmissionDenied) {
		t.Fatalf("不符准入規則 = %v, want ErrOIDCAdmissionDenied", err)
	}
	// 拒絕即不得留下任何帳號或身分（供應發生在准入之後）
	var userCnt, idCnt, ticketCnt int64
	login.db.Model(&model.User{}).Count(&userCnt)
	login.db.Model(&model.UserExternalIdentity{}).Count(&idCnt)
	login.db.Model(&model.OIDCLoginTicket{}).Count(&ticketCnt)
	if userCnt != 0 || idCnt != 0 || ticketCnt != 0 {
		t.Errorf("准入拒絕不得留下副作用，users=%d identities=%d tickets=%d",
			userCnt, idCnt, ticketCnt)
	}
}

func TestCallbackRejectsBadCodeWithoutConsumingNothing(t *testing.T) {
	login, _, _, p := setupLiveFlow(t)
	state, _ := beginFlow(t, login, p, "s", nil)

	// 未登錄的授權碼：IdP 回 invalid_grant → 收斂為流程失效
	if _, err := login.Callback(context.Background(), state, "bogus-code"); !errors.Is(err, ErrOIDCFlowInvalid) {
		t.Fatalf("無效授權碼 = %v, want ErrOIDCFlowInvalid", err)
	}
	// flow state 已於進入時消費：即使 code 換取失敗也不得留下可重試的狀態
	var cnt int64
	login.db.Model(&model.OIDCFlowState{}).Where("state = ?", state).Count(&cnt)
	if cnt != 0 {
		t.Error("flow state 應已被消費（一次性，不因後續失敗而復原）")
	}
}

func TestBeginRejectsDisabledProvider(t *testing.T) {
	login, providers, _, p := setupLiveFlow(t)
	no := false
	if _, err := providers.Update(p.ID, &OIDCProviderRequest{Name: "corp", Enabled: &no}); err != nil {
		t.Fatalf("停用: %v", err)
	}
	if _, err := login.Begin(context.Background(), p.ID, sha256Hex("s"), "/"); !errors.Is(err, ErrOIDCProviderUnavailable) {
		t.Fatalf("停用中的 provider 不得發起流程，實得 %v", err)
	}
	var cnt int64
	login.db.Model(&model.OIDCFlowState{}).Count(&cnt)
	if cnt != 0 {
		t.Error("被拒的 begin 不應留下流程狀態")
	}
}
