package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// 換鑰精靈 discriminated union 的解析與 handler 行為（伺服端部分）。

// apiTestKEKMaterial 產生合格且互不相同的測試材料（32 字元、KEKAlphabet 值域）
func apiTestKEKMaterial(n int) string {
	m := fmt.Sprintf("ApiTestKEKMaterial%014d", n)
	if len(m) != crypto.KEKMaterialLength {
		panic("測試材料長度不符")
	}
	return m
}

// localRewrapBody 合法的本地變體請求體
func localRewrapBody(material string) string {
	return fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true}`, material, material)
}

// doRewrap 直接打 handler，回傳 recorder 與請求體
func doRewrap(t *testing.T, h *KeyManagementHandler, body string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/keys/rewrap", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Rewrap(c)
	return w, body
}

// countKeyRows data_keys 列數（「零寫入」斷言的觀測量）
func countKeyRows(t *testing.T, h *KeyManagementHandler) int64 {
	t.Helper()
	var n int64
	if err := h.db.Model(&model.DataKey{}).Count(&n).Error; err != nil {
		t.Fatalf("count data_keys: %v", err)
	}
	return n
}

// responseCode 取回應信封的機器碼
func responseCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var doc struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("回應非 JSON: %v (%s)", err, w.Body.String())
	}
	if doc.Code == "" {
		t.Fatalf("回應未帶機器碼: %s", w.Body.String())
	}
	if doc.Error == "" {
		t.Fatalf("回應未帶 zh fallback 文字: %s", w.Body.String())
	}
	return doc.Code
}

// TestDecodeRewrapPayloadUnion union 解析：混合 payload、mode 與欄位不符、
// 未知欄位、缺欄位一律 fail-close；兩個確認欄位各有專屬錯誤
func TestDecodeRewrapPayloadUnion(t *testing.T) {
	m := apiTestKEKMaterial(1)
	other := apiTestKEKMaterial(2)
	cases := []struct {
		name string
		body string
		want error // nil＝應接受
	}{
		{"本地變體合法", localRewrapBody(m), nil},
		{"委託變體合法（解析層）", `{"mode":"kms","key_ref":"arn:aws:kms:x:1:key/a"}`, nil},
		{"混合：本地欄＋委託欄", fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true,"key_ref":"arn"}`, m, m), errRewrapPayloadMixed},
		{"混合：宣告 kms 卻帶本地欄", fmt.Sprintf(`{"mode":"kms","key_ref":"arn","new_kek":%q}`, m), errRewrapPayloadMixed},
		{"mode 與欄位不符：宣告 local 卻只帶 key_ref", `{"mode":"local","key_ref":"arn"}`, errRewrapPayloadMixed},
		{"缺 confirm_saved", fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q}`, m, m), errRewrapPayloadMixed},
		{"缺 new_kek_confirm", fmt.Sprintf(`{"mode":"local","new_kek":%q,"confirm_saved":true}`, m), errRewrapPayloadMixed},
		{"未知欄位", fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true,"force":true}`, m, m), errRewrapPayloadMalformed},
		{"缺 mode", fmt.Sprintf(`{"new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true}`, m, m), errRewrapModeInvalid},
		{"mode 不在白名單", `{"mode":"env","key_ref":"x"}`, errRewrapModeInvalid},
		{"mode 大小寫不符", `{"mode":"LOCAL","key_ref":"x"}`, errRewrapModeInvalid},
		{"mode 型別錯", `{"mode":123,"key_ref":"x"}`, errRewrapPayloadMalformed},
		{"paste-back 不符", fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true}`, m, other), errRewrapConfirmMismatch},
		{"confirm_saved 非真", fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":false}`, m, m), errRewrapNotSaved},
		{"confirm_saved 型別錯", fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":"true"}`, m, m), errRewrapPayloadMalformed},
		{"空請求體", "", errRewrapPayloadMalformed},
		{"非 JSON", "not-json", errRewrapPayloadMalformed},
		{"JSON 陣列", `[{"mode":"local"}]`, errRewrapPayloadMalformed},
		{"尾隨第二份文件", localRewrapBody(m) + `{"mode":"kms","key_ref":"x"}`, errRewrapPayloadMalformed},
		{"超出大小上限", `{"mode":"local","new_kek":"` + strings.Repeat("A", maxRewrapBodyBytes) + `"}`, errRewrapPayloadMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeRewrapPayload([]byte(tc.body))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("應接受，得 %v", err)
				}
				if got == nil || got.Mode == "" {
					t.Fatalf("接受時應回傳已判別的 payload，得 %+v", got)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("錯誤應為 %v，得 %v", tc.want, err)
			}
			if got != nil {
				t.Fatalf("拒絕時不得回傳 payload，得 %+v", got)
			}
		})
	}
}

// TestRewrapHandlerRejectionsProduceZeroKeyWrites 每一條拒絕路徑：狀態碼、機器碼，
// 且 data_keys **零寫入**（硬條件——繞過 paste-back 即不得觸發重包）
func TestRewrapHandlerRejectionsProduceZeroKeyWrites(t *testing.T) {
	m := apiTestKEKMaterial(3)
	other := apiTestKEKMaterial(4)
	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"paste-back 不符", fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true}`, m, other),
			http.StatusBadRequest, "VALIDATION_KEY_REWRAP_CONFIRM"},
		{"confirm_saved 非真", fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":false}`, m, m),
			http.StatusBadRequest, "VALIDATION_KEY_REWRAP_NOT_SAVED"},
		{"混合 payload", fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true,"key_ref":"arn"}`, m, m),
			http.StatusBadRequest, "VALIDATION_KEY_REWRAP_PAYLOAD_MIXED"},
		{"未知欄位", fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true,"force":true}`, m, m),
			http.StatusBadRequest, "VALIDATION_KEY_REWRAP_PAYLOAD"},
		{"mode 無效", `{"mode":"env","key_ref":"x"}`, http.StatusBadRequest, "VALIDATION_KEY_REWRAP_MODE"},
		{"材料過短", `{"mode":"local","new_kek":"short","new_kek_confirm":"short","confirm_saved":true}`,
			http.StatusBadRequest, "VALIDATION_KEY_REWRAP_MATERIAL"},
		{"材料字元集外", `{"mode":"local","new_kek":"Api-TestKEKMaterial0000000000001","new_kek_confirm":"Api-TestKEKMaterial0000000000001","confirm_saved":true}`,
			http.StatusBadRequest, "VALIDATION_KEY_REWRAP_MATERIAL"},
		{"委託目標尚未交付", `{"mode":"kms","key_ref":"arn:aws:kms:x:1:key/a"}`,
			http.StatusNotImplemented, "VALIDATION_KEY_REWRAP_TARGET_UNSUPPORTED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newKeyMgmtTestHandler(t)
			before := countKeyRows(t, h)
			w, _ := doRewrap(t, h, tc.body)
			if w.Code != tc.wantStatus {
				t.Fatalf("狀態碼 = %d，want %d（body=%s）", w.Code, tc.wantStatus, w.Body.String())
			}
			if code := responseCode(t, w); code != tc.wantCode {
				t.Fatalf("機器碼 = %q，want %q", code, tc.wantCode)
			}
			if after := countKeyRows(t, h); after != before {
				t.Fatalf("拒絕路徑不得寫入 data_keys：%d → %d", before, after)
			}
			// 回應不得回吐材料（錯誤訊息不可成為材料回音管道）
			if strings.Contains(w.Body.String(), apiTestKEKMaterial(3)) {
				t.Fatalf("錯誤回應洩漏材料: %s", w.Body.String())
			}
		})
	}
}

// TestRewrapHandlerAcceptsValidLocalTarget 正向案例（敏感度）：合法請求確實
// 寫出重包列——否則上面「零寫入」的斷言可能只是因為 handler 永遠不寫
func TestRewrapHandlerAcceptsValidLocalTarget(t *testing.T) {
	h := newKeyMgmtTestHandler(t)
	before := countKeyRows(t, h)
	w, _ := doRewrap(t, h, localRewrapBody(apiTestKEKMaterial(5)))
	if w.Code != http.StatusOK {
		t.Fatalf("合法請求應成功，得 %d body=%s", w.Code, w.Body.String())
	}
	after := countKeyRows(t, h)
	if after <= before {
		t.Fatalf("合法重包應寫出 pending clone 列：%d → %d", before, after)
	}
}

// TestRewrapResponseCarriesNoPlaintext 回應形狀守衛（wire 層）：
// 成功回應的鍵集恰為契約三鍵，且**整個回應體不含材料字串**
func TestRewrapResponseCarriesNoPlaintext(t *testing.T) {
	h := newKeyMgmtTestHandler(t)
	material := apiTestKEKMaterial(6)
	w, _ := doRewrap(t, h, localRewrapBody(material))
	if w.Code != http.StatusOK {
		t.Fatalf("合法請求應成功，得 %d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, material) {
		t.Fatalf("回應洩漏 KEK 明文: %s", body)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("回應非 JSON: %v", err)
	}
	for key := range doc {
		switch key {
		case "target_mode", "new_kek_id", "rewrapped_keys":
		default:
			t.Fatalf("回應出現契約外欄位 %q（形狀漂移）: %s", key, body)
		}
	}
	// 下界：確有三鍵（防「回了個空物件也算沒有明文」）
	if len(doc) != 3 {
		t.Fatalf("回應鍵數 = %d，契約為 3: %s", len(doc), body)
	}
}

// TestRewrapRejectsSameAndSeenKEK 目標守衛在 handler 面的對照：
// 現行 KEK 與曾出現過的 KEK 各有專屬 409 機器碼
func TestRewrapRejectsSameAndSeenKEK(t *testing.T) {
	material := apiTestKEKMaterial(7)
	h := newKeyMgmtTestHandlerWithMaterial(t, material)

	// 目標＝現行 KEK
	before := countKeyRows(t, h)
	w, _ := doRewrap(t, h, localRewrapBody(material))
	if w.Code != http.StatusConflict {
		t.Fatalf("目標等於現行 KEK 應 409，得 %d body=%s", w.Code, w.Body.String())
	}
	if code := responseCode(t, w); code != "CONFLICT_KEY_REWRAP_TARGET_CURRENT" {
		t.Fatalf("機器碼 = %q", code)
	}
	if after := countKeyRows(t, h); after != before {
		t.Fatalf("拒絕路徑不得寫入 data_keys：%d → %d", before, after)
	}

	// 曾出現過的 KEK：先重包再放棄，留下指紋史
	seen := apiTestKEKMaterial(8)
	if w, _ := doRewrap(t, h, localRewrapBody(seen)); w.Code != http.StatusOK {
		t.Fatalf("首次重包應成功，得 %d body=%s", w.Code, w.Body.String())
	}
	if _, err := h.km.AbandonRewrap(); err != nil {
		t.Fatalf("AbandonRewrap: %v", err)
	}
	before = countKeyRows(t, h)
	w2, _ := doRewrap(t, h, localRewrapBody(seen))
	if w2.Code != http.StatusConflict {
		t.Fatalf("曾出現過的 KEK 應 409，得 %d body=%s", w2.Code, w2.Body.String())
	}
	if code := responseCode(t, w2); code != "CONFLICT_KEY_REWRAP_TARGET_SEEN" {
		t.Fatalf("機器碼 = %q", code)
	}
	if after := countKeyRows(t, h); after != before {
		t.Fatalf("拒絕路徑不得寫入 data_keys：%d → %d", before, after)
	}
}

// TestDecodeRewrapPayloadRejectsDuplicateKeysAndTrailing 重複鍵與尾隨內容一律拒絕。
//
// 兩者都是「逐變體精確鍵集」看不見的歧義：
//   - `map[string]json.RawMessage` 對重複鍵靜默採最後值，於是判別子可以
//     「送兩個、驗一個」——呼叫端與伺服端對於「這是哪一個變體」的認知可以不同，
//     而那正是精確鍵集要消滅的 provider-confusion。
//   - `Decoder.More()` 只回答「還有沒有下一個元素」，對 `{...}]`／`{...}}`
//     這類尾隨結束符回 false，壞掉的輸入因此被當成乾淨的單一文件接受。
func TestDecodeRewrapPayloadRejectsDuplicateKeysAndTrailing(t *testing.T) {
	m := apiTestKEKMaterial(11)
	cases := map[string]string{
		"重複 mode（local 後接 kms）": fmt.Sprintf(
			`{"mode":"local","mode":"kms","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true}`, m, m),
		"重複 mode（kms 後接 local）": fmt.Sprintf(
			`{"mode":"kms","mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true}`, m, m),
		"重複 new_kek（送兩份材料）": fmt.Sprintf(
			`{"mode":"local","new_kek":%q,"new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true}`,
			apiTestKEKMaterial(12), m, m),
		"重複 key_ref": `{"mode":"kms","key_ref":"a","key_ref":"b"}`,
		"尾隨右中括號":     localRewrapBody(m) + `]`,
		"尾隨右大括號":     localRewrapBody(m) + `}`,
		"尾隨純量":       localRewrapBody(m) + `1`,
		"尾隨逗號與第二份文件": localRewrapBody(m) + `,{"mode":"kms","key_ref":"x"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := decodeRewrapPayload([]byte(body))
			if err == nil {
				t.Fatalf("%s 竟被接受（解析結果 %+v）——歧義輸入可繞過 union 的精確鍵集", name, got)
			}
			if got != nil {
				t.Fatalf("拒絕時不得回傳 payload，得 %+v", got)
			}
		})
	}

	// 正向：合法請求體加上尾隨空白仍須被接受（否則帶換行的客戶端全被拒）。
	if _, err := decodeRewrapPayload([]byte(localRewrapBody(m) + "\n \t")); err != nil {
		t.Fatalf("尾隨空白的合法請求體被拒: %v", err)
	}
}

// TestRewrapZeroizeDefersArePresent 釘住三個 defer 銷毀點。
//
// 明文的可控副本只有三份：原始請求體 []byte、payload 的欄位參考、
// target 的材料副本。三個 defer 中任何一個被拿掉，都不會有任何行為測試變紅
// ——副本的存活是記憶體事實，不是可觀察的回應差異。故以 AST 釘住其存在。
//
// **不可控的副本已在註解中誠實載明**（json.Decoder 內部緩衝、string 的
// backing array、provider 內展開的 AES 金鑰表），本守衛不宣稱涵蓋它們。
func TestRewrapZeroizeDefersArePresent(t *testing.T) {
	src, err := readSourceFile("key_management_handler.go")
	if err != nil {
		t.Fatalf("讀取 handler 原始檔失敗: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "key_management_handler.go", src, 0)
	if err != nil {
		t.Fatalf("解析 handler 失敗: %v", err)
	}

	// funcName → 必須存在的 defer 呼叫（以「接收者.方法」或「函式」名比對）
	want := map[string][]string{
		"Rewrap":            {"payload.Zeroize", "target.Destroy"},
		"buildRewrapTarget": {"zeroRewrapBody"},
	}
	found := map[string]map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		names, watched := want[fn.Name.Name]
		if !watched {
			return true
		}
		found[fn.Name.Name] = map[string]bool{}
		ast.Inspect(fn, func(inner ast.Node) bool {
			d, ok := inner.(*ast.DeferStmt)
			if !ok {
				return true
			}
			for _, name := range names {
				if deferCallName(d) == name {
					found[fn.Name.Name][name] = true
				}
			}
			return true
		})
		return true
	})

	for fnName, names := range want {
		got, ok := found[fnName]
		if !ok {
			t.Fatalf("找不到函式 %s——守衛已與實碼脫節", fnName)
		}
		for _, name := range names {
			if !got[name] {
				t.Errorf("%s 缺 `defer %s(...)`——該份明文副本不再有銷毀路徑", fnName, name)
			}
		}
	}
}

// deferCallName 取出 defer 呼叫的名稱（`f` 或 `x.f`）。
func deferCallName(d *ast.DeferStmt) string {
	switch fn := d.Call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok {
			return x.Name + "." + fn.Sel.Name
		}
	}
	return ""
}
