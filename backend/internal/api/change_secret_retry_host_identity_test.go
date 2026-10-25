package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/gin-gonic/gin"
)

// 候選重試端點的主機身分契約：不帶 body 的既有形狀不變、停止時多一個 host_identity、
// 帶明示確認時交給承接服務，以及所有不合法 body 在碰到任何狀態之前就被拒絕。

// fakeHostIdentityConfirmer 計數並回放固定結果的承接服務替身。
type fakeHostIdentityConfirmer struct {
	calls  int
	kind   string
	jobID  uint
	req    asset.HostIdentityConfirmRequest
	result error
}

func (f *fakeHostIdentityConfirmer) ConfirmHostIdentityAndVerify(_ context.Context, kind string, jobID uint,
	req asset.HostIdentityConfirmRequest) error {
	f.calls++
	f.kind, f.jobID, f.req = kind, jobID, req
	return f.result
}

// retryHostIdentityEnv 候選重試的請求環境：沿用零外洩守衛的夾具（與基準版同一份檔）。
type retryHostIdentityEnv struct {
	router    *gin.Engine
	confirmer *fakeHostIdentityConfirmer
	candID    uint
	assetID   uint
	auditID   *uint // 最近一次請求被標記的資產
	attempts  func() int
	lastError func() string
	stopped   func()
}

func newRetryHostIdentityEnv(t *testing.T) *retryHostIdentityEnv {
	t.Helper()
	h, _, db, cand := setupCandidateLeakEnv(t)
	env := &retryHostIdentityEnv{confirmer: &fakeHostIdentityConfirmer{}, candID: cand.ID, assetID: cand.AssetID}
	h.confirmer = env.confirmer

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "admin")
		middleware.SetPrincipal(c, legacyPrincipal("admin"))
		c.Next()
		env.auditID = nil
		if v, ok := c.Get(auditAssetIDKey); ok {
			id := v.(uint)
			env.auditID = &id
		}
	})
	r.POST("/change-secret-candidates/:id/retry", h.RetryCandidate)
	env.router = r
	env.attempts = func() int {
		var n int
		db.Raw("SELECT attempt_count FROM change_secret_candidates WHERE id = ?", cand.ID).Scan(&n)
		return n
	}
	env.lastError = func() string {
		var e string
		db.Raw("SELECT last_error FROM change_secret_candidates WHERE id = ?", cand.ID).Scan(&e)
		return e
	}
	// 讓候選落在「升級前、已送出」的身分停止狀態
	env.stopped = func() {
		if err := db.Exec("UPDATE change_secret_candidates SET host_key_binding = ?, applied = ? WHERE id = ?",
			"legacy", true, cand.ID).Error; err != nil {
			t.Fatalf("seed stopped candidate: %v", err)
		}
	}
	return env
}

func (e *retryHostIdentityEnv) post(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(http.MethodPost, "/change-secret-candidates/1/retry", nil)
	} else {
		req = httptest.NewRequest(http.MethodPost, "/change-secret-candidates/1/retry", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("回應非 JSON（%d）: %q", w.Code, w.Body.String())
	}
	return w.Code, out
}

func retryBodySortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// 任何深度出現的秘密類鍵
func assertNoSecretKeys(t *testing.T, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			switch k {
			case "password", "private_key", "public_key", "password_enc", "private_key_enc":
				t.Fatalf("回應不得含秘密類鍵 %q", k)
			}
			assertNoSecretKeys(t, child)
		}
	case []any:
		for _, child := range x {
			assertNoSecretKeys(t, child)
		}
	}
}

const validSSHConfirm = `{"confirm_host_identity":{"transport":"ssh","record_id":7,"algorithm":"ssh-ed25519","fingerprint":"SHA256:abc","generation":3,"accept_different_key":false}}`

func TestChangeSecretCandidateRetryHostIdentityAPI(t *testing.T) {
	t.Run("不帶body對未停止的工作_回應只有promoted_與基準版逐鍵相同", func(t *testing.T) {
		env := newRetryHostIdentityEnv(t)
		for _, body := range []string{"", "{}", `{"confirm_host_identity":null}`} {
			code, got := env.post(t, body)
			if code != http.StatusOK {
				t.Fatalf("body=%q: status=%d", body, code)
			}
			// 基準版 handler 的回應是 gin.H{"promoted": promoted}（此夾具連不上目標、不會轉正）
			want := map[string]any{"promoted": false}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("body=%q: 回應 %v 與基準 %v 不同", body, got, want)
			}
			if _, has := got["host_identity"]; has {
				t.Fatalf("body=%q: 未停止的工作不得帶 host_identity", body)
			}
		}
		if env.confirmer.calls != 0 {
			t.Fatalf("不帶確認不得呼叫承接服務，實際 %d 次", env.confirmer.calls)
		}
	})

	t.Run("不帶body對身分停止的工作_200且host_identity結構完整且無秘密", func(t *testing.T) {
		env := newRetryHostIdentityEnv(t)
		env.stopped()
		code, got := env.post(t, "")
		if code != http.StatusOK {
			t.Fatalf("status=%d", code)
		}
		if got["promoted"] != false {
			t.Fatalf("promoted=%v", got["promoted"])
		}
		hi, ok := got["host_identity"].(map[string]any)
		if !ok {
			t.Fatalf("缺少 host_identity：%v", got)
		}
		wantKeys := []string{"candidate_applied", "confirmable", "current", "deadline", "detail", "expired",
			"original", "phase", "status", "verification_sent"}
		if g := retryBodySortedKeys(hi); !reflect.DeepEqual(g, wantKeys) {
			t.Fatalf("host_identity 鍵 %v，預期 %v", g, wantKeys)
		}
		if hi["status"] != "unbound_legacy" || hi["phase"] != "precheck" || hi["verification_sent"] != "false" ||
			hi["confirmable"] != true || hi["candidate_applied"] != true || hi["expired"] != false {
			t.Fatalf("host_identity 內容不符：%v", hi)
		}
		assertNoSecretKeys(t, got)
		if env.confirmer.calls != 0 {
			t.Fatalf("不帶確認不得呼叫承接服務")
		}
	})

	t.Run("帶確認成功_promoted為true且服務收到完整確認", func(t *testing.T) {
		env := newRetryHostIdentityEnv(t)
		before := env.attempts()
		code, got := env.post(t, validSSHConfirm)
		if code != http.StatusOK || !reflect.DeepEqual(got, map[string]any{"promoted": true}) {
			t.Fatalf("status=%d body=%v", code, got)
		}
		if env.confirmer.calls != 1 || env.confirmer.kind != "candidate" || env.confirmer.jobID != env.candID {
			t.Fatalf("服務呼叫 %d 次 kind=%q job=%d", env.confirmer.calls, env.confirmer.kind, env.confirmer.jobID)
		}
		want := asset.HostIdentityConfirmRequest{Transport: "ssh", RecordID: 7, Algorithm: "ssh-ed25519",
			Fingerprint: "SHA256:abc", Generation: 3}
		if env.confirmer.req != want {
			t.Fatalf("確認內容 %+v，預期 %+v", env.confirmer.req, want)
		}
		if env.attempts() != before {
			t.Fatalf("帶確認時不得另外跑一次一般重試")
		}
	})

	t.Run("帶WinRM確認_不帶身分欄位也進服務", func(t *testing.T) {
		env := newRetryHostIdentityEnv(t)
		code, _ := env.post(t, `{"confirm_host_identity":{"transport":"winrm"}}`)
		if code != http.StatusOK || env.confirmer.calls != 1 || env.confirmer.req.Transport != "winrm" {
			t.Fatalf("status=%d calls=%d req=%+v", code, env.confirmer.calls, env.confirmer.req)
		}
	})

	t.Run("驗證未通過_200且promoted為false_候選保留", func(t *testing.T) {
		env := newRetryHostIdentityEnv(t)
		env.confirmer.result = errors.Join(asset.ErrHostIdentityVerifyFailed, errors.New("x"))
		code, got := env.post(t, validSSHConfirm)
		if code != http.StatusOK || !reflect.DeepEqual(got, map[string]any{"promoted": false}) {
			t.Fatalf("status=%d body=%v", code, got)
		}
	})

	t.Run("身分已移動_409_CONFLICT_HOST_IDENTITY_MOVED且細節只含受控值", func(t *testing.T) {
		cases := []struct {
			name       string
			err        error
			wantDetail string
		}{
			{"身分已變動", &asset.HostIdentityConflictError{}, ""},
			{"不可確認", &asset.HostIdentityConflictError{Detail: "not_confirmable"}, "not_confirmable"},
			{"確認進行中", &asset.HostIdentityConflictError{Detail: "confirmation_pending"}, "confirmation_pending"},
			{"不同公鑰未同意", &asset.HostIdentityConflictError{Detail: "different_key_not_accepted"}, "different_key_not_accepted"},
			{"哨兵錯誤", asset.ErrHostIdentityMoved, ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				env := newRetryHostIdentityEnv(t)
				env.confirmer.result = tc.err
				code, got := env.post(t, validSSHConfirm)
				if code != http.StatusConflict || got["code"] != string(apierror.CodeConflictHostIdentityMoved) {
					t.Fatalf("status=%d body=%v", code, got)
				}
				if d, has := got["detail"]; tc.wantDetail == "" && has {
					t.Fatalf("不應帶 detail：%v", d)
				} else if tc.wantDetail != "" && d != tc.wantDetail {
					t.Fatalf("detail=%v，預期 %q", d, tc.wantDetail)
				}
			})
		}
	})

	t.Run("目標已改變_200且reason為既有原因碼_不是身分移動_候選列不被改寫", func(t *testing.T) {
		env := newRetryHostIdentityEnv(t)
		env.stopped()
		env.confirmer.result = asset.ErrHostIdentityConfirmTargetChanged
		attemptsBefore, errBefore := env.attempts(), env.lastError()
		code, got := env.post(t, validSSHConfirm)
		want := map[string]any{"promoted": false, "reason": "CHANGE_SECRET_AUTHZ_TARGET_CHANGED"}
		if code != http.StatusOK || !reflect.DeepEqual(got, want) {
			t.Fatalf("status=%d body=%v", code, got)
		}
		raw, _ := json.Marshal(got)
		if strings.Contains(string(raw), string(apierror.CodeConflictHostIdentityMoved)) || strings.Contains(string(raw), "target_changed") {
			t.Fatalf("目標變更不得呈現為身分移動：%s", raw)
		}
		if env.attempts() != attemptsBefore || env.lastError() != errBefore {
			t.Fatalf("工作列被改寫：attempts %d->%d last_error %q->%q", attemptsBefore, env.attempts(), errBefore, env.lastError())
		}
	})

	t.Run("不合法body_400且承接服務與重試都沒被呼叫", func(t *testing.T) {
		bad := map[string]string{
			"確認內容多餘欄位":    `{"confirm_host_identity":{"transport":"ssh","record_id":7,"algorithm":"ssh-ed25519","fingerprint":"SHA256:abc","generation":3,"actor":"someone"}}`,
			"頂層force鍵":    `{"force":true,"confirm_host_identity":{"transport":"winrm"}}`,
			"只有force鍵":    `{"force":true}`,
			"確認內容含force":  `{"confirm_host_identity":{"transport":"winrm","force":true}}`,
			"未知transport": `{"confirm_host_identity":{"transport":"telnet"}}`,
			"ssh缺身分欄位":    `{"confirm_host_identity":{"transport":"ssh"}}`,
			"winrm帶身分欄位":  `{"confirm_host_identity":{"transport":"winrm","record_id":7}}`,
			"非JSON":       `not json`,
			"尾端多餘內容":      `{"confirm_host_identity":null} {}`,
		}
		for name, body := range bad {
			t.Run(name, func(t *testing.T) {
				env := newRetryHostIdentityEnv(t)
				before := env.attempts()
				code, got := env.post(t, body)
				if code != http.StatusBadRequest || got["code"] != string(apierror.CodeBadRequestFormat) {
					t.Fatalf("status=%d body=%v", code, got)
				}
				if env.confirmer.calls != 0 {
					t.Fatalf("不合法 body 不得進服務，實際 %d 次", env.confirmer.calls)
				}
				if env.attempts() != before {
					t.Fatalf("不合法 body 不得觸發一般重試")
				}
			})
		}
	})

	t.Run("嚴格解碼/尾隨內容_400且服務都沒被呼叫", func(t *testing.T) {
		bad := map[string]string{
			"尾隨右中括號":     `{"confirm_host_identity":{"transport":"winrm"}}]`,
			"尾隨右大括號":     `{"confirm_host_identity":{"transport":"winrm"}}}`,
			"ssh後尾隨右大括號": `{"confirm_host_identity":{"transport":"ssh","record_id":7,"algorithm":"ssh-ed25519","fingerprint":"SHA256:abc","generation":3}}}`,
			"第二個JSON值":   `{"confirm_host_identity":{"transport":"winrm"}} {"confirm_host_identity":{"transport":"winrm"}}`,
			"尾隨數字":       `{"confirm_host_identity":{"transport":"winrm"}} 1`,
		}
		for name, body := range bad {
			t.Run(name, func(t *testing.T) {
				env := newRetryHostIdentityEnv(t)
				code, got := env.post(t, body)
				if code != http.StatusBadRequest || got["code"] != string(apierror.CodeBadRequestFormat) {
					t.Fatalf("status=%d body=%v", code, got)
				}
				if env.confirmer.calls != 0 {
					t.Fatalf("尾隨內容不得進服務，實際 %d 次", env.confirmer.calls)
				}
			})
		}
		env := newRetryHostIdentityEnv(t)
		code, _ := env.post(t, `{"confirm_host_identity":{"transport":"winrm"}}`+"\n")
		if code == http.StatusBadRequest {
			t.Fatalf("合法 body（尾端空白）不應被拒")
		}
		if env.confirmer.calls != 1 {
			t.Fatalf("合法 body 應進服務一次，實際 %d", env.confirmer.calls)
		}
	})

	t.Run("無權_403形狀與一般權限不足相同", func(t *testing.T) {
		env := newRetryHostIdentityEnv(t)
		env.confirmer.result = asset.ErrCredentialBindForbidden
		code, got := env.post(t, validSSHConfirm)
		if code != http.StatusForbidden || got["code"] != string(apierror.CodePermissionDenied) {
			t.Fatalf("status=%d body=%v", code, got)
		}
		for _, k := range retryBodySortedKeys(got) {
			if k != "code" && k != "error" {
				t.Fatalf("403 回應不得帶額外鍵 %q", k)
			}
		}
	})

	t.Run("資產主體鍵_三種路徑都標記候選所屬資產", func(t *testing.T) {
		env := newRetryHostIdentityEnv(t)
		for name, body := range map[string]string{"不帶body": "", "帶確認": validSSHConfirm} {
			env.auditID = nil
			env.post(t, body)
			if env.auditID == nil || *env.auditID != env.assetID {
				t.Fatalf("%s: 審計資產 %v，預期 %d", name, env.auditID, env.assetID)
			}
		}
		env.confirmer.result = &asset.HostIdentityConflictError{}
		env.auditID = nil
		env.post(t, validSSHConfirm)
		if env.auditID == nil || *env.auditID != env.assetID {
			t.Fatalf("409 路徑: 審計資產 %v，預期 %d", env.auditID, env.assetID)
		}
	})

	t.Run("合法body與無body都照常進各自的路徑", func(t *testing.T) {
		env := newRetryHostIdentityEnv(t)
		env.post(t, "")
		if env.confirmer.calls != 0 {
			t.Fatalf("無 body 不得進承接服務")
		}
		env.post(t, validSSHConfirm)
		if env.confirmer.calls != 1 {
			t.Fatalf("合法 body 必須進承接服務一次，實際 %d", env.confirmer.calls)
		}
	})
}
