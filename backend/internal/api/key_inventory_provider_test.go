package api

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// readSourceFile 讀取本套件內的原始檔。
// 以 runtime.Caller 解出目錄而非相對路徑：go test 的工作目錄雖然是套件目錄，
// 但那是慣例而非契約，寫死相對路徑會在任何改變工作目錄的執行方式下靜默失敗。
func readSourceFile(name string) (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", os.ErrNotExist
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), name))
	return string(b), err
}

// 金鑰清冊 provider 欄的自證循環防線。
//
// 清冊要回答的是「這個行程**實際**跑的是哪一個 KEK provider」。若它自己去讀
// 環境變數，回答的就只是「環境變數寫了什麼」——被稽核的對象自己宣稱自己的
// 身分，稽核價值歸零。故 provider 欄 SHALL 由 runtime provider 物件的 Mode()
// 導出，SHALL NOT 重讀 os.Getenv。
//
// 以 AST 釘住而非以行為測試：行為測試無法區分「由 provider 導出」與「剛好
// env 也寫了同一個值」——而那正是自證循環最典型的偽裝。

// inventoryProviderSource 是被守衛的原始檔。
const inventoryProviderSource = "key_management_handler.go"

// inventoryProviderViolations 掃描一份原始碼，回報 provider 欄的自證循環違規。
//
// 兩條規則：
//  1. 檔內任何位置都不得呼叫 os.Getenv——清冊的資料來源只能是注入的服務物件；
//  2. 回應 map 中的 "provider" 鍵，其值必須是對 KEKMode() 的呼叫。
func inventoryProviderViolations(src string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	providerSeen := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" && sel.Sel.Name == "Getenv" {
					out = append(out, "清冊原始檔呼叫了 os.Getenv——provider 欄可能改由環境變數推導（自證循環）")
				}
			}
		case *ast.KeyValueExpr:
			key, ok := v.Key.(*ast.BasicLit)
			if !ok || key.Kind != token.STRING || strings.Trim(key.Value, `"`) != "provider" {
				return true
			}
			providerSeen = true
			call, ok := v.Value.(*ast.CallExpr)
			if !ok {
				out = append(out, "provider 欄的值不是函式呼叫——必須由 runtime provider 物件導出")
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "KEKMode" {
				out = append(out, "provider 欄的值不是 KEKMode() 呼叫——必須由 runtime provider 物件的 Mode() 導出")
			}
		}
		return true
	})
	if !providerSeen {
		out = append(out, "回應中找不到 provider 欄——清冊欄位已消失")
	}
	return out, nil
}

// TestInventoryProviderNotDerivedFromEnv 正向：實碼不得以 env 導出 provider 欄。
func TestInventoryProviderNotDerivedFromEnv(t *testing.T) {
	src, err := readSourceFile(inventoryProviderSource)
	if err != nil {
		t.Fatalf("讀取 %s 失敗: %v", inventoryProviderSource, err)
	}
	got, err := inventoryProviderViolations(src)
	if err != nil {
		t.Fatalf("解析 %s 失敗: %v", inventoryProviderSource, err)
	}
	if len(got) > 0 {
		t.Fatalf("%s 違反自證循環防線：\n  %s", inventoryProviderSource, strings.Join(got, "\n  "))
	}
}

// TestInventoryProviderGuardCatchesEnvRegression 負向自檢：守衛必須真的抓得到。
//
// 缺這一半時，守衛可能因為（例如）走錯 AST 分支而恆綠——一個永遠不會紅的
// 守衛與沒有守衛完全等價，且更危險，因為它看起來像有保護。
func TestInventoryProviderGuardCatchesEnvRegression(t *testing.T) {
	cases := map[string]string{
		"provider 改讀 env": `package api
import "os"
func f() any { return map[string]any{"provider": os.Getenv("KEK_PROVIDER")} }`,
		"provider 改為常數字面": `package api
func f() any { return map[string]any{"provider": "env"} }`,
		"provider 改由組態推導": `package api
func f() any { return map[string]any{"provider": cfg.Mode()} }`,
		"provider 欄整個消失": `package api
func f() any { return map[string]any{"kek_id": h.km.KEKKeyID()} }`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := inventoryProviderViolations(src)
			if err != nil {
				t.Fatalf("解析失敗: %v", err)
			}
			if len(got) == 0 {
				t.Fatalf("%s 未被守衛攔下——守衛恆綠即等同沒有守衛", name)
			}
		})
	}

	// 正向自檢：合規寫法不得誤報。
	ok := `package api
func f() any { return map[string]any{"provider": h.km.KEKMode(), "key_ref": h.km.KEKRef().String()} }`
	got, err := inventoryProviderViolations(ok)
	if err != nil {
		t.Fatalf("解析失敗: %v", err)
	}
	if len(got) > 0 {
		t.Fatalf("合規寫法被誤報：%v", got)
	}
}

// TestInventoryExposesProviderFields 清冊回應帶齊自證循環防線要求的四個欄位。
//
// 欄位名為前後端契約（前端採「欄位存在才渲染」），故正向斷言逐個欄位名，
// 而不是只驗「回應非空」。
func TestInventoryExposesProviderFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newKeyMgmtTestHandler(t)

	unsealedAt := time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC)
	h.SetSealStateProbe(func() (string, time.Time) { return "unsealed", unsealedAt })

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	h.Inventory(c)

	if w.Code != http.StatusOK {
		t.Fatalf("清冊回 %d：%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析清冊回應失敗: %v", err)
	}

	// provider 由 runtime provider 導出：測試 handler 以 env 模式建構，故為 "env"。
	if got := body["provider"]; got != "env" {
		t.Errorf("provider = %v，期望 env（由 runtime provider 的 Mode() 導出）", got)
	}
	keyRef, _ := body["key_ref"].(string)
	if !strings.HasPrefix(keyRef, "local:") || len(keyRef) <= len("local:") {
		t.Errorf("key_ref = %q，期望 provider:key_id 形式且 key_id 非空", keyRef)
	}
	// key_ref 的 key_id 必須就是清冊既有的 kek_id（同一把鑰的兩種呈現不得漂移）
	if kekID, _ := body["kek_id"].(string); !strings.HasSuffix(keyRef, kekID) || kekID == "" {
		t.Errorf("key_ref=%q 與 kek_id=%v 不一致", keyRef, body["kek_id"])
	}
	if got := body["seal_state"]; got != "unsealed" {
		t.Errorf("seal_state = %v，期望 unsealed", got)
	}
	if got := body["unsealed_at"]; got != "2026-08-02T03:04:05Z" {
		t.Errorf("unsealed_at = %v，期望 RFC3339 的解封時點", got)
	}
}

// TestInventoryOmitsSealStateWhenUnwired 未注入探針時省略而非以預設值頂替。
//
// 「未知」與「已解封」在稽核面是完全不同的事實：回一個猜測值會讓清冊自己
// 成為錯誤來源，而前端無從分辨那是真實狀態還是佔位。
func TestInventoryOmitsSealStateWhenUnwired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newKeyMgmtTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	h.Inventory(c)

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析清冊回應失敗: %v", err)
	}
	if _, ok := body["seal_state"]; ok {
		t.Error("未注入探針卻回了 seal_state——未知狀態被以猜測值頂替")
	}
	// provider／key_ref 不依賴探針，任何情況下都必須在。
	for _, k := range []string{"provider", "key_ref"} {
		if _, ok := body[k]; !ok {
			t.Errorf("清冊缺 %s 欄", k)
		}
	}
}
