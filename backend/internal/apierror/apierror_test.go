package apierror

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/notifycat"
)

func testCtx() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	return c, w
}

// TestRegistryWellFormed asserts every registered code matches grammar and has
// a non-empty fallback (register panics on grammar/dup at load, so reaching
// here already proves uniqueness; this guards fallback emptiness too).
func TestRegistryWellFormed(t *testing.T) {
	codes := AllCodes()
	if len(codes) == 0 {
		t.Fatal("registry is empty")
	}
	for _, c := range codes {
		if !CodeGrammar.MatchString(string(c)) {
			t.Errorf("code %q violates grammar", c)
		}
		d, _ := DescriptorOf(c)
		if strings.TrimSpace(d.ZhFallback) == "" {
			t.Errorf("code %q has empty ZhFallback", c)
		}
	}
}

func TestWriteEnvelope(t *testing.T) {
	c, w := testCtx()
	Respond(c, http.StatusUnauthorized, CodeUnauthenticated, nil)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	body := decode(t, w)
	if body["error"] != "未認證" {
		t.Errorf("error = %v, want 未認證", body["error"])
	}
	if body["code"] != "AUTH_UNAUTHENTICATED" {
		t.Errorf("code = %v, want AUTH_UNAUTHENTICATED", body["code"])
	}
	if _, has := body["params"]; has {
		t.Errorf("unexpected params: %v", body["params"])
	}
}

func TestWriteRendersParams(t *testing.T) {
	c, w := testCtx()
	Respond(c, http.StatusBadRequest, CodeInvalidID, map[string]any{"resource": "asset"})

	body := decode(t, w)
	if body["error"] != "無效的資產 ID" {
		t.Errorf("error = %v, want 無效的資產 ID (zh label rendered)", body["error"])
	}
	if body["code"] != "VALIDATION_INVALID_ID" {
		t.Errorf("code = %v", body["code"])
	}
	p, ok := body["params"].(map[string]any)
	if !ok || p["resource"] != "asset" {
		t.Errorf("params = %v, want {resource: asset}", body["params"])
	}
}

func TestWriteRejectsUnknownOrDisallowedParams(t *testing.T) {
	// unknown key -> params dropped, fallback template kept
	c, w := testCtx()
	Respond(c, http.StatusBadRequest, CodeInvalidID, map[string]any{"bogus": "x"})
	body := decode(t, w)
	if _, has := body["params"]; has {
		t.Errorf("invalid params should be dropped, got %v", body["params"])
	}

	// enum value outside allowlist -> dropped
	c2, w2 := testCtx()
	Respond(c2, http.StatusBadRequest, CodeInvalidID, map[string]any{"resource": "../../etc"})
	body2 := decode(t, w2)
	if _, has := body2["params"]; has {
		t.Errorf("disallowed enum value should be dropped, got %v", body2["params"])
	}
	if strings.Contains(w2.Body.String(), "etc") {
		t.Errorf("disallowed value leaked into body: %s", w2.Body.String())
	}
}

// --- ParamOpaque（自由字串 param）---
//
// 契約：型別錯才拒發，內容一律淨化不拒發。以 registry 內真實使用 opaque 的碼
// （CONFLICT_DAILY_REVIEW_SIGNED）驗證，而非測試專用碼——後者會與正式註冊路徑
// 脫鉤（register 的 schema 檢查、模板佔位符綁定都測不到）。

func TestParamOpaqueTravelsOnWire(t *testing.T) {
	c, w := testCtx()
	Respond(c, http.StatusConflict, CodeDailyReviewAlreadySigned,
		map[string]any{"time": "09:30", "signer": "auditor-a"})

	body := decode(t, w)
	if body["error"] != "當日已完成簽核（09:30 由 auditor-a 簽核）" {
		t.Errorf("error = %v", body["error"])
	}
	p, ok := body["params"].(map[string]any)
	if !ok || p["time"] != "09:30" || p["signer"] != "auditor-a" {
		t.Errorf("params = %v, want {time: 09:30, signer: auditor-a}", body["params"])
	}
}

func TestParamOpaqueSanitizesContent(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ANSI 逸出序列剝除", "a\x1b[31mred\x1b[0m", "ared"},
		{"換行折成空白", "line1\nline2", "line1 line2"},
		{"控制字元移除", "ok\x07\x00", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, w := testCtx()
			Respond(c, http.StatusConflict, CodeDailyReviewAlreadySigned,
				map[string]any{"time": "09:30", "signer": tc.in})

			body := decode(t, w)
			p, ok := body["params"].(map[string]any)
			if !ok {
				t.Fatalf("params 遭丟棄（opaque 內容不得成為拒發理由）: %v", body)
			}
			if p["signer"] != tc.want {
				t.Errorf("params[signer] = %q, want %q", p["signer"], tc.want)
			}
			if strings.ContainsRune(w.Body.String(), 0x1b) {
				t.Errorf("回應仍含 ESC: %q", w.Body.String())
			}
		})
	}
}

func TestParamOpaqueTruncatesOverLimit(t *testing.T) {
	c, w := testCtx()
	long := strings.Repeat("漢", 300)
	Respond(c, http.StatusConflict, CodeDailyReviewAlreadySigned,
		map[string]any{"time": "09:30", "signer": long})

	body := decode(t, w)
	p, ok := body["params"].(map[string]any)
	if !ok {
		t.Fatalf("超長 opaque 不得使 params 遭丟棄: %v", body)
	}
	got, _ := p["signer"].(string)
	if n := len([]rune(got)); n != notifycat.MaxOpaqueRunes {
		t.Errorf("signer 長度 = %d rune, want %d（截斷至上限）", n, notifycat.MaxOpaqueRunes)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("截斷後未附截斷標記: %q", got[len(got)-8:])
	}
}

// TestParamOpaqueValueCannotForgePlaceholder opaque 值內的 {…} 不得被當成模板
// 佔位符處理（先插值再掃描會把它整段吃掉，屬渲染注入面）。
func TestParamOpaqueValueCannotForgePlaceholder(t *testing.T) {
	c, w := testCtx()
	Respond(c, http.StatusConflict, CodeDailyReviewAlreadySigned,
		map[string]any{"time": "09:30", "signer": "{signer}{bogus}"})

	body := decode(t, w)
	errText, _ := body["error"].(string)
	if !strings.Contains(errText, "{signer}{bogus}") {
		t.Errorf("error = %q, want 原樣保留 opaque 值內的大括號文字", errText)
	}
}

func TestParamOpaqueRejectsNonString(t *testing.T) {
	c, w := testCtx()
	Respond(c, http.StatusConflict, CodeDailyReviewAlreadySigned,
		map[string]any{"time": "09:30", "signer": 42})

	body := decode(t, w)
	if _, has := body["params"]; has {
		t.Errorf("非字串 opaque 應使 params 遭丟棄, got %v", body["params"])
	}
	// 佔位符被剝除，不得有裸 {signer} 外洩
	if strings.Contains(w.Body.String(), "{signer}") {
		t.Errorf("裸佔位符外洩: %s", w.Body.String())
	}
}

// TestRegisterRejectsOpaqueWithLabels opaque 不得宣告 ZhLabels/EnumNS（會讀成
// 一個它並不具備的允許清單）。
func TestRegisterRejectsOpaqueWithLabels(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("opaque param 帶 ZhLabels 未 panic")
		}
	}()
	register("TEST_OPAQUE_WITH_LABELS", Descriptor{
		ZhFallback: "x {k}",
		Params:     []ParamSpec{{Key: "k", Kind: ParamOpaque, ZhLabels: map[string]string{"a": "A"}}},
	})
}

func TestWriteMeta(t *testing.T) {
	c, w := testCtx()
	Write(c, http.StatusForbidden, ErrorResponse{
		Code: CodePermissionDenied,
		Meta: map[string]any{"required_permission": "asset:connect"},
	})
	body := decode(t, w)
	if body["required_permission"] != "asset:connect" {
		t.Errorf("required_permission = %v, want asset:connect", body["required_permission"])
	}
	if body["error"] != "權限不足" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestRespondInternalHidesCause(t *testing.T) {
	c, w := testCtx()
	c.Set("userID", uint(7))

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(log.Writer())

	RespondInternal(c, http.StatusBadGateway, CodeInternalAssetQuery,
		errors.New("pq: connection refused at 10.0.0.5:5432"))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	body := decode(t, w)
	if body["error"] != "查詢資產失敗" {
		t.Errorf("error = %v, want 查詢資產失敗", body["error"])
	}
	if strings.Contains(w.Body.String(), "connection refused") {
		t.Error("response leaks internal cause")
	}
	if !strings.Contains(logBuf.String(), "connection refused") {
		t.Error("server log missing original cause")
	}
	if !strings.Contains(logBuf.String(), "user=7") {
		t.Error("server log missing user context")
	}
}

// TestParamValidationLogIsInjectionSafe 參數違規的 log 不得被請求內容操縱。
//
// validateParams 的錯誤訊息帶被拒的值（"value not in allowlist: <值>"），
// 而該值來自請求。修正前直接 %v 進 log：一個帶換行的值即可在日誌檔裡偽造
// 一整行看似獨立的事件（掩蓋真實事件、餵髒 log 分析），帶 ESC 的值還能操縱
// 讀 log 的終端。現一律先淨化再以 %q 引用。
func TestParamValidationLogIsInjectionSafe(t *testing.T) {
	c, w := testCtx()
	c.Request = httptest.NewRequest("GET", "/api/v1/assets/1", nil)

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(log.Writer())

	// 值域外的 enum 值，內含換行（偽造 log 行）與 ESC（終端逸出序列）
	evil := "x\n2026/01/01 00:00:00 [apierror] 一切正常\x1b[31m"
	Respond(c, http.StatusBadRequest, CodeInvalidID, map[string]any{"resource": evil})

	logged := logBuf.String()
	if !strings.Contains(logged, "param validation failed") {
		t.Fatalf("違規仍須留下 log，實得 %q", logged)
	}
	if strings.Count(strings.TrimSuffix(logged, "\n"), "\n") != 0 {
		t.Errorf("log 被注入額外行（可偽造事件）: %q", logged)
	}
	if strings.ContainsRune(logged, 0x1b) {
		t.Errorf("log 含未逸出的 ESC（可操縱讀 log 的終端）: %q", logged)
	}
	// 回應本體照舊：params 丟棄、值不外洩
	body := decode(t, w)
	if _, has := body["params"]; has {
		t.Errorf("違規 params 仍須丟棄，實得 %v", body["params"])
	}
	if strings.Contains(w.Body.String(), "2026/01/01") {
		t.Errorf("被拒的值洩漏至回應: %s", w.Body.String())
	}
}

// TestUnregisteredCodeLogIsInjectionSafe 未註冊碼的 log 同樣淨化＋引用
// （碼理應只由 register 產生，但這條路徑本身就是「不該發生卻發生了」的分支）
func TestUnregisteredCodeLogIsInjectionSafe(t *testing.T) {
	c, w := testCtx()
	c.Request = httptest.NewRequest("GET", "/api/v1/x", nil)

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(log.Writer())

	Write(c, http.StatusTeapot, ErrorResponse{Code: ErrCode("BOGUS\n2026/01/01 00:00:00 偽造\x1b[31m")})

	logged := logBuf.String()
	if strings.Count(strings.TrimSuffix(logged, "\n"), "\n") != 0 {
		t.Errorf("log 被注入額外行: %q", logged)
	}
	if strings.ContainsRune(logged, 0x1b) {
		t.Errorf("log 含未逸出的 ESC: %q", logged)
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("未註冊碼應降級為 500，實得 %d", w.Code)
	}
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return body
}
