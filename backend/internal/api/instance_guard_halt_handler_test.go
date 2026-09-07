package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// 守衛攔下端點的請求形狀、狀態碼與機器碼映射。
//
// 本檔的射程止於 handler：憑證驗證與「碼與當下持鎖者重比」都在組裝根與
// database 側，各由 cmd/server 與 internal/database 的測試承擔
//（此處以 stub 驅動五種判定結果，驗的是「每種結果對應哪個狀態碼與碼」）。
// 這個分界是刻意的——handler 若自己判斷這些，api 層就得 import identity 與 infra。

type haltAckCall struct {
	req InstanceGuardAckRequest
	n   int
}

func newHaltRouter(t *testing.T, view InstanceGuardHaltView, res InstanceGuardAckResult) (*gin.Engine, *haltAckCall) {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	calls := &haltAckCall{}
	h := NewInstanceGuardHaltHandler(
		func() InstanceGuardHaltView { return view },
		func(req InstanceGuardAckRequest) InstanceGuardAckResult {
			calls.req = req
			calls.n++
			return res
		})
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"))
	return r, calls
}

func haltedView() InstanceGuardHaltView {
	return InstanceGuardHaltView{
		State: InstanceGuardHaltStateHalted,
		Since: "2026-09-07T00:00:00Z",
		Holder: &InstanceGuardHolder{
			ApplicationName: "custodexa-instance-guard", PID: 777,
			BackendStart: "2026-09-07T00:00:00Z", Code: "abc123abc123",
			FingerprintSource: "pg_stat_activity",
		},
		RetryIntervalSeconds: 15,
	}
}

func postAck(t *testing.T, r *gin.Engine, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/instance-guard/ack", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:5555"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("回應非 JSON（%d）: %s", w.Code, w.Body.String())
	}
	return out
}

func fullAckRequest() map[string]any {
	return map[string]any{
		"confirmed_primary_down": true,
		"code":                   "abc123abc123",
		"username":               "admin",
		"password":               "secret",
	}
}

// TestInstanceGuardHaltStatus 攔下狀態查詢：持鎖者指紋與重試週期出得去。
func TestInstanceGuardHaltStatus(t *testing.T) {
	r, _ := newHaltRouter(t, haltedView(), InstanceGuardAckResult{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/instance-guard/halt", nil)
	req.RemoteAddr = "192.0.2.10:5555"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d，want 200", w.Code)
	}
	body := decodeBody(t, w)
	if body["state"] != "halted" || body["retry_interval_seconds"] != float64(15) {
		t.Fatalf("攔下狀態欄不齊：%v", body)
	}
	holder, ok := body["holder"].(map[string]any)
	if !ok || holder["code"] != "abc123abc123" || holder["application_name"] != "custodexa-instance-guard" ||
		holder["backend_start"] != "2026-09-07T00:00:00Z" || holder["fingerprint_source"] != "pg_stat_activity" {
		t.Fatalf("持鎖者指紋五欄不齊（攔下頁要顯示它們）：%v", body["holder"])
	}
}

// TestInstanceGuardAckMatrix 確認送出的判定矩陣：每格斷言狀態碼、機器碼、
// 是否觸及確認函式（＝是否可能寫 overridden）、是否計入行程內鎖定閘。
func TestInstanceGuardAckMatrix(t *testing.T) {
	cases := []struct {
		name        string
		view        InstanceGuardHaltView
		res         InstanceGuardAckResult
		body        map[string]any
		wantStatus  int
		wantCode    string
		wantConfirm int // 期望確認函式被呼叫幾次
	}{
		{
			name: "三要件齊備且相符：接受",
			view: haltedView(), res: InstanceGuardAckResult{Outcome: AckOutcomeAccepted},
			body: fullAckRequest(), wantStatus: http.StatusOK, wantCode: "", wantConfirm: 1,
		},
		{
			name: "碼對帳密錯：401，不接受確認",
			view: haltedView(), res: InstanceGuardAckResult{Outcome: AckOutcomeInvalidCredential},
			body: fullAckRequest(), wantStatus: http.StatusUnauthorized,
			wantCode: "INSTANCE_GUARD_ACK_UNAUTHORIZED", wantConfirm: 1,
		},
		{
			name: "碼錯帳密對（持鎖者已變更）：409，回新指紋",
			view: haltedView(), res: InstanceGuardAckResult{
				Outcome: AckOutcomeHolderChanged,
				Holder:  &InstanceGuardHolder{Code: "999999999999", PID: 888, FingerprintSource: "pg_stat_activity"},
			},
			body: fullAckRequest(), wantStatus: http.StatusConflict,
			wantCode: "INSTANCE_GUARD_HOLDER_CHANGED", wantConfirm: 1,
		},
		{
			name: "使用者表讀不到：503，指向環境變數路徑",
			view: haltedView(), res: InstanceGuardAckResult{Outcome: AckOutcomeUsersUnavailable},
			body: fullAckRequest(), wantStatus: http.StatusServiceUnavailable,
			wantCode: "INSTANCE_GUARD_ACK_UNAVAILABLE", wantConfirm: 1,
		},
		{
			name: "未勾選承擔：400，不觸及確認函式",
			view: haltedView(), res: InstanceGuardAckResult{Outcome: AckOutcomeAccepted},
			body: map[string]any{"confirmed_primary_down": false, "code": "abc123abc123",
				"username": "admin", "password": "secret"},
			wantStatus: http.StatusBadRequest, wantCode: "INSTANCE_GUARD_ACK_INCOMPLETE", wantConfirm: 0,
		},
		{
			name: "缺確認碼：400，不觸及確認函式",
			view: haltedView(), res: InstanceGuardAckResult{Outcome: AckOutcomeAccepted},
			body: map[string]any{"confirmed_primary_down": true, "code": "",
				"username": "admin", "password": "secret"},
			wantStatus: http.StatusBadRequest, wantCode: "INSTANCE_GUARD_ACK_INCOMPLETE", wantConfirm: 0,
		},
		{
			name: "缺帳密：400，不觸及確認函式",
			view: haltedView(), res: InstanceGuardAckResult{Outcome: AckOutcomeAccepted},
			body: map[string]any{"confirmed_primary_down": true, "code": "abc123abc123",
				"username": "", "password": ""},
			wantStatus: http.StatusBadRequest, wantCode: "INSTANCE_GUARD_ACK_INCOMPLETE", wantConfirm: 0,
		},
		{
			name: "非攔下狀態：409，在觸碰任何憑證之前返回",
			view: InstanceGuardHaltView{State: InstanceGuardHaltStateRunning},
			res:  InstanceGuardAckResult{Outcome: AckOutcomeAccepted},
			body: fullAckRequest(), wantStatus: http.StatusConflict,
			wantCode: "INSTANCE_GUARD_NOT_HALTED", wantConfirm: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, calls := newHaltRouter(t, tc.view, tc.res)
			w := postAck(t, r, tc.body)
			if w.Code != tc.wantStatus {
				t.Fatalf("狀態碼 = %d，want %d（body=%s）", w.Code, tc.wantStatus, w.Body.String())
			}
			body := decodeBody(t, w)
			if tc.wantCode == "" {
				if _, ok := body["code"]; ok {
					t.Fatalf("成功回應不應帶錯誤碼：%v", body)
				}
				if body["state"] != "running" {
					t.Fatalf("接受後 state 應轉 running（頁面據此轉「已啟動」）：%v", body)
				}
			} else if body["code"] != tc.wantCode {
				t.Fatalf("機器碼 = %v，want %s", body["code"], tc.wantCode)
			}
			if calls.n != tc.wantConfirm {
				t.Fatalf("確認函式呼叫 %d 次，want %d（0 次代表未觸及任何憑證與守衛狀態）",
					calls.n, tc.wantConfirm)
			}
			if tc.res.Outcome == AckOutcomeHolderChanged && tc.wantConfirm == 1 {
				holder, ok := body["holder"].(map[string]any)
				if !ok || holder["code"] != "999999999999" {
					t.Fatalf("持鎖者變更時 MUST 回新的指紋與確認碼，實得 %v", body["holder"])
				}
			}
		})
	}
}

// TestInstanceGuardAckPassesThroughAllThreeFactors 三要件原樣送達確認函式：
// handler 不得自行改寫或補齊任何一項。
func TestInstanceGuardAckPassesThroughAllThreeFactors(t *testing.T) {
	r, calls := newHaltRouter(t, haltedView(), InstanceGuardAckResult{Outcome: AckOutcomeAccepted})
	postAck(t, r, fullAckRequest())
	if !calls.req.ConfirmedPrimaryDown || calls.req.Code != "abc123abc123" ||
		calls.req.Username != "admin" || calls.req.Password != "secret" {
		t.Fatalf("三要件未原樣送達：%+v", calls.req)
	}
}

// TestInstanceGuardAckLocksOutAfterRepeatedCredentialFailures 憑證失敗達上限即暫停受理。
//
// 這道閘是**行程內**計數（攔下模式不得產生任何資料庫寫入，故用不了既有的帳號鎖定閘）。
// 它擋的是自動化爆破，不是有主機存取權的人；界線寫在 handler 的常數註解裡。
func TestInstanceGuardAckLocksOutAfterRepeatedCredentialFailures(t *testing.T) {
	r, calls := newHaltRouter(t, haltedView(), InstanceGuardAckResult{Outcome: AckOutcomeInvalidCredential})
	for i := 0; i < haltAckMaxFailures; i++ {
		if w := postAck(t, r, fullAckRequest()); w.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次失敗應回 401，實得 %d", i+1, w.Code)
		}
	}
	w := postAck(t, r, fullAckRequest())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("達上限後應回 429，實得 %d（body=%s）", w.Code, w.Body.String())
	}
	if body := decodeBody(t, w); body["code"] != "INSTANCE_GUARD_ACK_LOCKED" {
		t.Fatalf("機器碼 = %v，want INSTANCE_GUARD_ACK_LOCKED", body["code"])
	}
	if calls.n != haltAckMaxFailures {
		t.Fatalf("鎖定後不得再觸及確認函式（＝不再比對憑證），呼叫 %d 次", calls.n)
	}
}

// TestInstanceGuardHaltSourceRestriction 來源網段限制涵蓋兩條端點。
//
// 兩條各驗一次：只驗狀態查詢而漏驗確認送出時，受限的是無害的那一條、
// 敞開的是會驗憑證的那一條，而測試照綠。
func TestInstanceGuardHaltSourceRestriction(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	_, allowed, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	h := NewInstanceGuardHaltHandler(
		func() InstanceGuardHaltView { return haltedView() },
		func(InstanceGuardAckRequest) InstanceGuardAckResult {
			t.Fatal("來源不符時 MUST NOT 觸及確認函式")
			return InstanceGuardAckResult{}
		})
	h.SetSourceControls(false, []*net.IPNet{allowed})
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"))

	for _, tc := range []struct {
		method, path string
		body         []byte
	}{
		{http.MethodGet, "/api/v1/instance-guard/halt", nil},
		{http.MethodPost, "/api/v1/instance-guard/ack", []byte(`{"confirmed_primary_down":true,"code":"abc123abc123","username":"a","password":"b"}`)},
	} {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.10:5555" // 不在 10.0.0.0/8 內
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s：允許網段外應回 403，實得 %d", tc.method, tc.path, w.Code)
		}
		if body := decodeBody(t, w); body["code"] != "SEAL_SOURCE_NOT_ALLOWED" {
			t.Fatalf("%s %s：機器碼 = %v", tc.method, tc.path, body["code"])
		}
	}
}
