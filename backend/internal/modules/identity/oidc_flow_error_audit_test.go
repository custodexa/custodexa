package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// callback 失敗事件的審計面（spec OA-8「停用即失效……事件入審計」、
// OA-2「驗簽失敗拒絕」的審計面）。
//
// 拒絕行為本身已由 oidc_callback_test.go 覆蓋；本檔補的是**另一半**：
// 拒絕之後是否留下可稽核的痕跡。四個 flowError 產生點各一格，
// 外加一格反向（走得通的流程不得落 flow-error）——沒有反向格，
// 一個「無論如何都落一筆」的實作也會讓前四格全綠。
//
// **斷言對象是 Callback 交回的審計意向**：留痕改由
// handler 落地（service 拿不到 *gin.Context，自寫必然缺來源位址／路徑／方法／
// 狀態碼四欄）。故此處驗「service 有沒有交出該留的痕、狀態語義對不對」，
// 「列真的有寫進去且四欄非空」由 internal/api/oidc_login_audit_test.go 承接。

// flowErrorEvent 自審計意向還原出的 flow-error 事件
type flowErrorEvent struct {
	reason     string
	providerID uint
	status     model.AuditStatus
	resource   model.AuditResource
	details    string
}

// flowErrorEvents 取出所有 oidc_flow_error 事件。
// 以 JSON 解析而非字串比對——欄位名或型別若被改動，這裡會直接失敗而非靜默漏判
func flowErrorEvents(t *testing.T, err error) []flowErrorEvent {
	t.Helper()
	var out []flowErrorEvent
	for _, e := range OIDCAuditEventsOf(err) {
		var d map[string]any
		if jsonErr := json.Unmarshal([]byte(e.DetailsJSON()), &d); jsonErr != nil {
			t.Fatalf("審計 Details 應為合法 JSON，實得 %q: %v", e.DetailsJSON(), jsonErr)
		}
		if ev, _ := d["event"].(string); ev != "oidc_flow_error" {
			continue
		}
		reason, _ := d["reason"].(string)
		id, _ := d["provider_id"].(float64)
		out = append(out, flowErrorEvent{
			reason: reason, providerID: uint(id), status: e.Status,
			resource: e.Resource, details: e.DetailsJSON(),
		})
	}
	return out
}

// assertSingleFlowError 斷言恰落一筆 flow-error 事件，且 reason／provider_id／
// status／resource 相符。
//
// **status 是 failure 不是 denied**（狀態語義分流）：憑證交換失敗、id_token
// 驗證失敗等皆為「憑證不成立」的認證失敗；`denied` 在本庫是「身分成立但不准」的
// 授權拒絕語義（RBAC 403、OIDC 准入拒絕）。混用會使既有授權拒絕列不可解釋
func assertSingleFlowError(t *testing.T, err error,
	p *model.OIDCProvider, wantReason string) {
	t.Helper()
	got := flowErrorEvents(t, err)
	if len(got) != 1 {
		t.Fatalf("應恰落 1 筆 oidc_flow_error 事件，實得 %d 筆: %+v", len(got), got)
	}
	e := got[0]
	if e.reason != wantReason {
		t.Errorf("reason = %q, want %q（Details=%s）", e.reason, wantReason, e.details)
	}
	if e.providerID != p.ID {
		t.Errorf("provider_id = %d, want %d（Details=%s）", e.providerID, p.ID, e.details)
	}
	if e.status != model.StatusFailure {
		t.Errorf("審計狀態 = %q, want %q", e.status, model.StatusFailure)
	}
	if e.resource != model.ResourceAuth {
		t.Errorf("審計資源 = %q, want %q（不得為 user）", e.resource, model.ResourceAuth)
	}
}

// TestCallbackProviderUnavailableIsAudited 流程期間 provider 被停用 → 事件入審計。
//
// 這正是 OA-8「停用即失效」情境的審計面：既有測試斷言了「被拒」，
// 但「停用後仍有人拿著先前授權回來」本身是管理者需要看得見的訊號
func TestCallbackProviderUnavailableIsAudited(t *testing.T) {
	login, providers, idp, p := setupLiveFlow(t)
	state, nonce := beginFlow(t, login, p, "s", idp)
	idp.stageCode("code-1", idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: nonce,
		extra: map[string]any{"hd": "corp.example", "preferred_username": "bob"},
	}))

	no := false
	if _, err := providers.Update(p.ID, &OIDCProviderRequest{Name: "corp", Enabled: &no}); err != nil {
		t.Fatalf("停用: %v", err)
	}
	_, err := login.Callback(context.Background(), state, "code-1")
	if !errors.Is(err, ErrOIDCProviderUnavailable) {
		t.Fatalf("流程期間被停用 = %v, want ErrOIDCProviderUnavailable", err)
	}

	assertSingleFlowError(t, err, p, "provider_unavailable")
}

// TestCallbackProviderEpochAdvancedIsAudited 停用後又重新啟用（世代已推進）→ 亦入審計。
//
// enabled 已復原，擋住在途流程的是世代——這條路徑與上一格走的是同一個
// 判斷式的另一半，其審計不得因布林復原而消失
func TestCallbackProviderEpochAdvancedIsAudited(t *testing.T) {
	login, providers, idp, p := setupLiveFlow(t)
	state, nonce := beginFlow(t, login, p, "s", idp)
	idp.stageCode("code-1", idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: nonce,
		extra: map[string]any{"hd": "corp.example", "preferred_username": "bob"},
	}))

	no, yes := false, true
	if _, err := providers.Update(p.ID, &OIDCProviderRequest{Name: "corp", Enabled: &no}); err != nil {
		t.Fatalf("停用: %v", err)
	}
	if _, err := providers.Update(p.ID, &OIDCProviderRequest{Name: "corp", Enabled: &yes}); err != nil {
		t.Fatalf("重新啟用: %v", err)
	}
	_, err := login.Callback(context.Background(), state, "code-1")
	if !errors.Is(err, ErrOIDCProviderUnavailable) {
		t.Fatalf("在途流程 = %v, want ErrOIDCProviderUnavailable", err)
	}

	assertSingleFlowError(t, err, p, "provider_unavailable")
}

// TestCallbackCodeExchangeFailureIsAudited 授權碼交換失敗 → 事件入審計。
//
// 交換失敗代表「有人拿著我方簽發的有效 state、卻換不出 token」，
// 是重放或中間人嘗試的訊號，不該只回一個泛用錯誤就無聲消失
func TestCallbackCodeExchangeFailureIsAudited(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	state, _ := beginFlow(t, login, p, "s", idp)

	// 未登錄的授權碼：fake IdP 回 invalid_grant
	_, err := login.Callback(context.Background(), state, "bogus-code")
	if !errors.Is(err, ErrOIDCFlowInvalid) {
		t.Fatalf("無效授權碼 = %v, want ErrOIDCFlowInvalid", err)
	}

	assertSingleFlowError(t, err, p, "code_exchange_failed")
	// 授權碼是憑證等級的值，不得回填審計
	for _, e := range flowErrorEvents(t, err) {
		if strings.Contains(e.details, "bogus-code") {
			t.Errorf("審計不得回填授權碼明文，實得: %s", e.details)
		}
	}
}

// TestCallbackMissingIDTokenIsAudited token 回應缺 id_token → 事件入審計。
//
// 缺 id_token 表示對端不是（或未正確扮演）OIDC 提供者：可能是設定指向了
// 純 OAuth2 端點，也可能是回應被替換，兩者都需要管理者看得見
func TestCallbackMissingIDTokenIsAudited(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	state, _ := beginFlow(t, login, p, "s", idp)
	// 登錄一組「換得到 token 但沒有 id_token」的授權碼
	idp.stageCode("code-1", "")

	_, err := login.Callback(context.Background(), state, "code-1")
	if !errors.Is(err, ErrOIDCFlowInvalid) {
		t.Fatalf("缺 id_token = %v, want ErrOIDCFlowInvalid", err)
	}

	assertSingleFlowError(t, err, p, "id_token_missing")
}

// TestCallbackInvalidIDTokenIsAudited id_token 驗證失敗 → 事件入審計（OA-2 審計面）。
//
// 以 nonce 不符製造：token 簽章合法、iss/aud 正確，唯獨不是「這個瀏覽器發起的
// 那次流程」——驗證失敗中最接近真實攻擊（token 注入）的一種
func TestCallbackInvalidIDTokenIsAudited(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	state, _ := beginFlow(t, login, p, "s", idp)
	idp.stageCode("code-1", idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: "not-the-issued-nonce",
		extra: map[string]any{"hd": "corp.example", "preferred_username": "bob"},
	}))

	_, err := login.Callback(context.Background(), state, "code-1")
	if !errors.Is(err, ErrOIDCFlowInvalid) {
		t.Fatalf("nonce 不符 = %v, want ErrOIDCFlowInvalid", err)
	}

	assertSingleFlowError(t, err, p, "id_token_invalid")
}

// TestCallbackInvalidSignatureIsAudited 簽章驗證失敗 → 亦落同一事件。
//
// 與上一格同為 id_token_invalid，但走的是簽章而非 nonce：
// 這兩條是 OA-2 對外「不可區分」而對內「必須留痕」的分野
func TestCallbackForgedSignatureIsAudited(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	state, nonce := beginFlow(t, login, p, "s", idp)
	idp.stageCode("code-1", idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: nonce,
		signWithOtherKey: true,
		extra:            map[string]any{"hd": "corp.example", "preferred_username": "bob"},
	}))

	_, err := login.Callback(context.Background(), state, "code-1")
	if !errors.Is(err, ErrOIDCFlowInvalid) {
		t.Fatalf("偽造簽章 = %v, want ErrOIDCFlowInvalid", err)
	}

	assertSingleFlowError(t, err, p, "id_token_invalid")
}

// TestSuccessfulCallbackWritesNoFlowError 反向格：走得通的流程不得落 flow-error。
//
// 沒有這一格，一個「每次 callback 都先落一筆」的實作會讓上面五格全綠——
// 審計的價值在於「有事才響」，恆響等於沒有訊號
func TestSuccessfulCallbackWritesNoFlowError(t *testing.T) {
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
		t.Fatalf("Callback 應成功: %v", err)
	}
	if got := flowErrorEvents(t, err); len(got) != 0 {
		t.Fatalf("成功的流程不得落 oidc_flow_error，實得 %d 筆: %+v", len(got), got)
	}
	// 成功路徑的意向清單同樣不得含 flow-error（首登會有一筆建帳號事件，
	// 那是另一種事件；此處釘的是「成功的流程不得產生失敗訊號」）
	for _, e := range res.AuditEvents {
		if ev, _ := e.Details["event"].(string); ev == "oidc_flow_error" {
			t.Fatalf("成功路徑的意向不得含 oidc_flow_error: %s", e.DetailsJSON())
		}
	}
}
