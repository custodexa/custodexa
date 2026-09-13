package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/seal"
)

// 解封流程第一段（帳密驗證）與授權脈絡的守衛。
//
// 本檔守的是四件事，每一件失效的後果都不同：
//
//	(1) 回應不可區分——可區分即帳號枚舉（本階段面對的是匿名探測）；
//	(2) 退避與冷卻真的生效——封存期少了一道因子，爆破成本只剩它；
//	(3) 脈絡不是業務憑證——否則「解封」就順手變成一次不受 MFA 約束的登入；
//	(4) 解封端點無脈絡即拒且**不觸及材料**——秘密欄位在驗證之後才該被送出。

// sealAuthorizeHandler 建一個接好授權面的 handler。
func sealAuthorizeHandler(t *testing.T, verify SealCredentialVerifier) (*SealHandler, *SealGrantStore) {
	t.Helper()
	h := NewSealHandler(seal.NewUnsealed(nil), nil)
	grants := NewSealGrantStore(0)
	h.SetSealAuthorization(grants, verify)
	return h, grants
}

func postAuthorize(t *testing.T, h *SealHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := sourceTestRouter(t, h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/seal/authorize", strings.NewReader(body)))
	return w
}

func codeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("回應不是 JSON: %s", w.Body.String())
	}
	return out.Code
}

// TestSealAuthorizeRejectionsAreIndistinguishable 四種失敗的回應逐字相同。
func TestSealAuthorizeRejectionsAreIndistinguishable(t *testing.T) {
	// 驗證器把「帳號不存在」「密碼錯」「非管理角色」「帳號鎖定」都收斂為同一個
	// 錯誤（identity.VerifySealAdminCredential 的契約）；本測試守的是 handler
	// 不因輸入形態而產生不同的回應。
	// **每一例各用一個新的 handler**：退避在第一次失敗後即生效（那是所欲的，
	// 由 TestSealAuthorizeBacksOffAfterFailures 守），共用 handler 會讓第二例起
	// 一律被 429 擋下而測不到本案要守的「回應逐字相同」。
	reject := func(string, []byte) (uint, error) { return 0, errors.New("rejected") }
	bodies := []string{
		`{"username":"nobody","password":"x"}`,
		`{"username":"admin","password":"wrong"}`,
		`{"username":"operator","password":"correct"}`,
		`{"username":"locked","password":"correct"}`,
	}
	var first string
	for i, body := range bodies {
		h, _ := sealAuthorizeHandler(t, reject)
		w := postAuthorize(t, h, body)
		if w.Code != 401 {
			t.Fatalf("案例 %d 應回 401，得 %d", i, w.Code)
		}
		if codeOf(t, w) != string(apierror.CodeSealAuthorizeRejected) {
			t.Fatalf("案例 %d 的機器碼不符: %s", i, w.Body.String())
		}
		if i == 0 {
			first = w.Body.String()
			continue
		}
		if w.Body.String() != first {
			t.Fatalf("案例 %d 的回應與第一例不同——可區分即帳號枚舉\n第一例: %s\n本例: %s",
				i, first, w.Body.String())
		}
	}
}

// TestSealAuthorizeMalformedBodyIsIndistinguishable 格式錯與憑證錯同一出口。
//
// 分開回報會讓探測者用「送壞掉的 JSON」與「送合法 JSON」的回應差異，
// 零成本區分出「這個端點有沒有在驗東西」。
func TestSealAuthorizeMalformedBodyIsIndistinguishable(t *testing.T) {
	reject := func(string, []byte) (uint, error) { return 0, errors.New("rejected") }
	for _, body := range []string{
		``,
		`not json`,
		`{"username":"admin"}`,                                // 缺鍵
		`{"username":"admin","password":"x","extra":1}`,       // 未知鍵
		`{"username":"admin","password":"x","password":"y"}`,  // 重複鍵
		`{"username":"admin","password":"x"}{"username":"b"}`, // 尾隨內容
	} {
		// 同上：每一例各用一個新的 handler，避免退避掩蓋本案要守的性質。
		h, _ := sealAuthorizeHandler(t, reject)
		w := postAuthorize(t, h, body)
		if w.Code != 401 || codeOf(t, w) != string(apierror.CodeSealAuthorizeRejected) {
			t.Fatalf("本文 %q 應與憑證錯同一出口，得 %d %s", body, w.Code, w.Body.String())
		}
	}
}

// TestSealAuthorizeBacksOffAfterFailures 連續失敗進退避。
//
// 封存期不驗動態驗證碼，爆破成本只剩帳密強度加這一道；它若沒生效，
// 規格裡「攻擊面比正常登入弱一級」的緩解就只剩一句話。
func TestSealAuthorizeBacksOffAfterFailures(t *testing.T) {
	h, _ := sealAuthorizeHandler(t, func(string, []byte) (uint, error) { return 0, errors.New("rejected") })
	body := `{"username":"admin","password":"wrong"}`
	if w := postAuthorize(t, h, body); w.Code != 401 {
		t.Fatalf("第一次失敗應為 401，得 %d", w.Code)
	}
	w := postAuthorize(t, h, body)
	if w.Code != 429 {
		t.Fatalf("同來源的第二次嘗試應被退避擋下（429），得 %d %s", w.Code, w.Body.String())
	}
	if got := codeOf(t, w); got != string(apierror.CodeSealBackoffActive) && got != string(apierror.CodeSealCooldownActive) {
		t.Fatalf("退避的機器碼不符: %s", got)
	}
}

// TestSealAuthorizeIssuesUsableGrant 驗證成功簽發可用的脈絡。
func TestSealAuthorizeIssuesUsableGrant(t *testing.T) {
	h, grants := sealAuthorizeHandler(t, func(u string, p []byte) (uint, error) {
		if u == "admin" && string(p) == "correct" {
			return 7, nil
		}
		return 0, errors.New("rejected")
	})
	w := postAuthorize(t, h, `{"username":"admin","password":"correct"}`)
	if w.Code != 200 {
		t.Fatalf("正確憑證應回 200，得 %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Grant     string `json:"grant"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("回應不是 JSON: %v", err)
	}
	if out.Grant == "" || out.ExpiresAt == "" {
		t.Fatalf("回應缺欄位: %s", w.Body.String())
	}
	g, err := grants.Verify(out.Grant)
	if err != nil {
		t.Fatalf("簽發的脈絡驗不過: %v", err)
	}
	if g.UserID != 7 || g.Username != "admin" {
		t.Fatalf("脈絡的課責欄不符: %+v", g)
	}
	// 回應不得被快取：脈絡是持有型憑據。
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("授權回應應為 no-store，得 %q", w.Header().Get("Cache-Control"))
	}
}

// TestSealGrantExpiresAndRevokes 效期屆滿與撤銷後即不可用。
func TestSealGrantExpiresAndRevokes(t *testing.T) {
	store := NewSealGrantStore(time.Millisecond)
	token, _, err := store.Issue(1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(token); err != nil {
		t.Fatalf("剛簽發的脈絡應可用: %v", err)
	}
	time.Sleep(3 * time.Millisecond)
	if _, err := store.Verify(token); !errors.Is(err, ErrSealGrantInvalid) {
		t.Fatalf("屆期後應失效，得 %v", err)
	}

	store2 := NewSealGrantStore(0)
	t2, _, _ := store2.Issue(1, "admin")
	store2.Revoke(t2)
	if _, err := store2.Verify(t2); !errors.Is(err, ErrSealGrantInvalid) {
		t.Fatalf("撤銷後應失效，得 %v", err)
	}

	store3 := NewSealGrantStore(0)
	t3, _, _ := store3.Issue(1, "admin")
	store3.RevokeAll()
	if _, err := store3.Verify(t3); !errors.Is(err, ErrSealGrantInvalid) {
		t.Fatalf("全撤銷後應失效，得 %v", err)
	}
}

// TestSealGrantIsNotABusinessCredential 脈絡不得作為業務請求憑證。
//
// 解封端點以 `SealGrant` scheme 收它，業務端點以 `Bearer` 收 JWT——
// 兩者的授權語義完全不同，共用 scheme 會讓「把解封脈絡拿去打業務端點」
// 在程式碼裡看起來像對的。
func TestSealGrantIsNotABusinessCredential(t *testing.T) {
	h, grants := sealAuthorizeHandler(t, func(string, []byte) (uint, error) { return 1, nil })
	token, _, err := grants.Issue(1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	// 以 Bearer 遞送同一個字串：解封端點的脈絡解析只認 SealGrant，故不成立。
	r := sourceTestRouter(t, h)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/seal/unseal", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("以 Bearer 遞送解封脈絡應被拒，得 %d %s", w.Code, w.Body.String())
	}
	if codeOf(t, w) != string(apierror.CodeSealGrantInvalid) {
		t.Fatalf("機器碼不符: %s", w.Body.String())
	}

	// `Seal`（封存）端點走的是 Bearer 授權器，脈絡在那裡同樣不成立。
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/api/v1/seal/seal", nil)
	req2.Header.Set("Authorization", "SealGrant "+token)
	r.ServeHTTP(w2, req2)
	if w2.Code != 401 {
		t.Fatalf("解封脈絡不得授權封存操作，得 %d %s", w2.Code, w2.Body.String())
	}
}

// TestUnsealRequiresGrantBeforeTouchingMaterial 無脈絡即拒且不讀材料。
func TestUnsealRequiresGrantBeforeTouchingMaterial(t *testing.T) {
	h, grants := sealAuthorizeHandler(t, func(string, []byte) (uint, error) { return 1, nil })
	r := sourceTestRouter(t, h)

	body := &unreadSealBody{}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/seal/unseal", body))
	if w.Code != 401 || codeOf(t, w) != string(apierror.CodeSealGrantRequired) {
		t.Fatalf("無脈絡應回 SEAL_GRANT_REQUIRED，得 %d %s", w.Code, w.Body.String())
	}
	if body.reads != 0 {
		t.Fatalf("未通過驗證的請求不得觸及材料，material_reads=%d", body.reads)
	}

	// 帶一個不存在的脈絡：與「沒帶」分開回報，但同樣不觸及材料。
	body2 := &unreadSealBody{}
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/api/v1/seal/unseal", body2)
	req2.Header.Set("Authorization", "SealGrant not-a-real-grant")
	r.ServeHTTP(w2, req2)
	if w2.Code != 401 || codeOf(t, w2) != string(apierror.CodeSealGrantInvalid) {
		t.Fatalf("無效脈絡應回 SEAL_GRANT_INVALID，得 %d %s", w2.Code, w2.Body.String())
	}
	if body2.reads != 0 {
		t.Fatalf("無效脈絡的請求不得觸及材料，material_reads=%d", body2.reads)
	}
	_ = grants
}

// TestUnsealErrorDistinguishability 憑證階段的三類成因可區分；其餘維持不可區分。
func TestUnsealErrorDistinguishability(t *testing.T) {
	cases := []struct {
		name   string
		cause  error
		code   apierror.ErrCode
		status int
	}{
		{"保管處不可達", seal.ErrCustodyUnreachable, apierror.CodeSealCustodyUnreachable, 502},
		{"憑證被拒", seal.ErrCredentialRejected, apierror.CodeSealCredentialRejected, 400},
		{"金鑰不符", seal.ErrKeyMismatch, apierror.CodeSealKeyMismatch, 400},
		{"核對後拓撲變動", seal.ErrTopologyChanged, apierror.CodeSealTopologyChanged, 409},
	}
	for _, tc := range cases {
		// 狀態機把驗證錯誤原樣掛在 Cause 上（見 seal.Error.Unwrap），
		// 故 errors.Is 在 HTTP 層成立。此處直接構出同形狀的出口錯誤。
		wrapped := &seal.Error{Code: seal.CodeMaterialInvalid, Cell: "4", Cause: tc.cause}

		code, status := SealErrorResponseFor(wrapped, true)
		if code != tc.code || status != tc.status {
			t.Errorf("%s 帶脈絡時應回 %s/%d，得 %s/%d", tc.name, tc.code, tc.status, code, status)
		}
		// 無脈絡側必須與改前逐字相同：材料無效 400。
		code2, status2 := SealErrorResponseFor(wrapped, false)
		if code2 != apierror.CodeSealMaterialInvalid || status2 != 400 {
			t.Errorf("%s 無脈絡時應收斂為材料無效 400，得 %s/%d", tc.name, code2, status2)
		}
		if legacyCode, legacyStatus := SealErrorResponse(wrapped); legacyCode != code2 || legacyStatus != status2 {
			t.Errorf("%s 的既有入口與無脈絡側不一致", tc.name)
		}
	}

	// 未登記的成因即使帶脈絡也不得產生新的可區分形狀。
	unknown := &seal.Error{Code: seal.CodeMaterialInvalid, Cell: "4", Cause: errors.New("something else")}
	if code, status := SealErrorResponseFor(unknown, true); code != apierror.CodeSealMaterialInvalid || status != 400 {
		t.Errorf("未登記成因應維持材料無效 400，得 %s/%d", code, status)
	}
}

// TestUnsealAuthorizationRequiresGrantInEveryMode 三模式一律要求授權脈絡（任務 4.2）。
//
// 改前只有 `mode != "ui"` 要求 Bearer；`ui` 由「知道材料」單獨承擔授權。
// 自本版起材料證明是驗證之後的第二道。
func TestUnsealAuthorizationRequiresGrantInEveryMode(t *testing.T) {
	for _, mode := range []string{"ui", "env", "kms"} {
		h, grants := sealAuthorizeHandler(t, func(string, []byte) (uint, error) { return 1, nil })
		h.SetAuthorizer(mode, func(context.Context, string) (uint, error) { return 1, nil })
		r := sourceTestRouter(t, h)

		body := &unreadSealBody{}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/seal/unseal", body))
		if w.Code != 401 || body.reads != 0 {
			t.Fatalf("模式 %s 無脈絡時應 401 且不觸及材料：status=%d reads=%d", mode, w.Code, body.reads)
		}

		grant, _, err := grants.Issue(1, "admin")
		if err != nil {
			t.Fatal(err)
		}
		w2 := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/seal/unseal", nil)
		req.Header.Set("Authorization", "SealGrant "+grant)
		r.ServeHTTP(w2, req)
		if w2.Code == 401 {
			t.Fatalf("模式 %s 帶有效脈絡仍被拒：%s", mode, w2.Body.String())
		}
	}
}

// TestUnsealAuthorizationRevokedOnPermissionChange 權限變動即使脈絡失效（任務 4.2）。
//
// 脈絡的效期以分鐘計，而在那段窗口內帳號可能被停用、降權、鎖定或憑證世代被推進。
// 只在簽發當下判定並不滿足「權限變動 SHALL 使該脈絡失效」。
func TestUnsealAuthorizationRevokedOnPermissionChange(t *testing.T) {
	store := NewSealGrantStore(0)
	authorized := true
	store.SetRevalidator(func(uint) error {
		if authorized {
			return nil
		}
		return errors.New("no longer authorized")
	})
	token, _, err := store.Issue(1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(token); err != nil {
		t.Fatalf("仍具資格時脈絡應可用: %v", err)
	}
	authorized = false
	if _, err := store.Verify(token); !errors.Is(err, ErrSealGrantInvalid) {
		t.Fatalf("資格消失後脈絡應失效，得 %v", err)
	}
	// 失效的脈絡順手刪除：恢復資格也不得讓它復活（要求重驗）。
	authorized = true
	if _, err := store.Verify(token); !errors.Is(err, ErrSealGrantInvalid) {
		t.Fatalf("已失效的脈絡不得因資格恢復而復活，得 %v", err)
	}
}

// TestTopologyRebindRejectsStaleDigest 核對之後拓撲被改動即拒（任務 4.2）。
//
// 操作者核對的是當時顯示的那一組設定；期間被改動就代表他核對過的目的地已經不是
// 現在要送去的那一個。**舊核對結果不得授權送往新目的地。**
func TestTopologyRebindRejectsStaleDigest(t *testing.T) {
	stale := &seal.Error{Code: seal.CodeMaterialInvalid, Cell: "4", Cause: seal.ErrTopologyChanged}
	code, status := SealErrorResponseFor(stale, true)
	if code != apierror.CodeSealTopologyChanged || status != 409 {
		t.Fatalf("核對失效應回 SEAL_TOPOLOGY_CHANGED/409，得 %s/%d", code, status)
	}
	// 匿名側維持不可區分——它連這個成因都產生不出來（拓撲比對發生在帳密之後）。
	code2, status2 := SealErrorResponseFor(stale, false)
	if code2 != apierror.CodeSealMaterialInvalid || status2 != 400 {
		t.Fatalf("無脈絡側應收斂為材料無效 400，得 %s/%d", code2, status2)
	}
}
