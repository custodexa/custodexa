package auditmask

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/modules/audit"
)

// 守衛的比對軸：**端點 × 鍵名**。
//
// # 為什麼軸要改
//
// 遮罩自本次起是端點感知的：放行集合＝全域集 ∪ 該端點的專屬集。守衛若仍只按
// 鍵名比對，就會把「在 A 端點已放行、在 B 端點仍全遮」判成已補齊——課責空白
// 因此靜默逃掉。
//
// **舊的僅按鍵名比對軸已刪除，不與新軸並存**：並存時一條在新軸已補齊的登記仍會
// 被舊軸赦免，等於守衛靜默失效。
//
// # 端點從哪裡來
//
// 讀路由 golden（`cmd/server/testdata/route-golden/dev-auditon.json`）——那是
// **伺服端實際註冊的路由樹**的快照，由 `TestRoutesMatchGolden` 釘住。不自己再掃一次
// 路由註冊碼：第二份推導會與真正生效的那一份分歧，而分歧的方向恰好是「守衛以為
// 某個 handler 沒有端點，於是不判它」。

// routeGoldenRel 路由 golden 相對 backend 模組根的路徑。
const routeGoldenRel = "cmd/server/testdata/route-golden/dev-auditon.json"

// internalPkgPrefix golden 內 handler 字串的套件前綴。
const internalPkgPrefix = "github.com/custodexa/backend/internal/"

// routeGoldenLowerBound 路由數下界（fail-close）。
//
// golden 讀不到或解析退化時會安靜地回空 map，於是每個綁定點都「沒有端點」而
// 全部免判——三個守衛同時消失。盤查當下逾 600 條，下界取 300。
const routeGoldenLowerBound = 200

var handlerSuffix = regexp.MustCompile(`-fm$`)

// siteEndpoints 綁定點識別字 → 它服務的端點（`"<METHOD> <路由樣板>"`，已排序）。
func siteEndpoints(t *testing.T) map[string][]string {
	t.Helper()
	path := filepath.Join(auditMaskModuleRoot(t), filepath.FromSlash(routeGoldenRel))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取路由 golden 失敗（%s）：守衛讀不到端點事實即等於沒有守衛: %v", path, err)
	}
	var doc struct {
		Routes []struct {
			Method  string `json:"method"`
			Path    string `json:"path"`
			Handler string `json:"handler"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析路由 golden 失敗: %v", err)
	}
	if len(doc.Routes) < routeGoldenLowerBound {
		t.Fatalf("路由 golden 只有 %d 條（下界 %d）：比對基準已失真，拒絕在殘缺輸入上判定",
			len(doc.Routes), routeGoldenLowerBound)
	}
	out := map[string][]string{}
	for _, r := range doc.Routes {
		if !strings.HasPrefix(r.Handler, internalPkgPrefix) {
			continue
		}
		key := handlerSuffix.ReplaceAllString(strings.TrimPrefix(r.Handler, internalPkgPrefix), "")
		out[key] = append(out[key], r.Method+" "+r.Path)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// voidKey 課責空白登記表的鍵：端點 ＋ 綁定點。
//
// 兩段都要：同一個 handler 可掛在多個端點上，而「這個端點的審計列答不出動了
// 什麼」是逐端點成立或不成立的事實。
func voidKey(endpoint, site string) string { return endpoint + " | " + site }

// allowedFieldSetFor 某端點的實際放行集＝全域集 ∪ 該端點專屬集。
func allowedFieldSetFor(endpoint string) map[string]bool {
	allowed := map[string]bool{}
	for _, k := range audit.SafeAuditFieldNames() {
		allowed[k] = true
	}
	for _, k := range audit.EndpointAuditFieldNames(endpoint) {
		allowed[k] = true
	}
	return allowed
}

// TestEndpointAuditSetsAreEnumerated 端點專屬集的列舉與實作不得分歧。
//
// `AuditMaskEndpoints()` 是守衛列舉端點專屬登記的唯一入口；它若漏掉一個端點，
// 那個端點放行了什麼就不受任何檢查——而漏掉的那個正是「有人偷偷加了一條放行」
// 最可能的藏身處。本測試反向確認：列舉出的每個端點都真的有登記，且列舉之外的
// 端點在 golden 內都沒有專屬放行。
func TestEndpointAuditSetsAreEnumerated(t *testing.T) {
	listed := audit.AuditMaskEndpoints()
	if len(listed) == 0 {
		t.Fatal("AuditMaskEndpoints() 為空：端點專屬集的守衛失去輸入")
	}
	for _, e := range listed {
		if len(audit.EndpointAuditFieldNames(e)) == 0 {
			t.Errorf("AuditMaskEndpoints 列了 %q，但它沒有任何端點專屬放行——"+
				"登記已成化石，請刪除或補上", e)
		}
	}
	// 反向：golden 內的每一條端點，若有專屬放行就必須被列舉。
	seen := map[string]bool{}
	for _, e := range listed {
		seen[e] = true
	}
	for _, endpoints := range siteEndpoints(t) {
		for _, e := range endpoints {
			if len(audit.EndpointAuditFieldNames(e)) > 0 && !seen[e] {
				t.Errorf("端點 %q 有專屬放行卻不在 AuditMaskEndpoints() 內："+
					"守衛列舉不到它，該端點放行了什麼將不受檢查", e)
			}
		}
	}
}

// TestEndpointAuditSetsRejectSecretishKeys 端點專屬集同受 G3 約束。
//
// 端點感知放寬的是**判準 1 的全域性**（同名鍵在別的端點上是不是機密），
// 不是判準 1 本身（這個值是不是機密）。憑證欄位在任何端點都不得登記。
func TestEndpointAuditSetsRejectSecretishKeys(t *testing.T) {
	for _, endpoint := range audit.AuditMaskEndpoints() {
		for _, key := range audit.EndpointAuditFieldNames(endpoint) {
			lower := strings.ToLower(key)
			for _, marker := range secretishKeyMarkers {
				if strings.Contains(lower, marker) {
					t.Errorf("端點 %q 的專屬放行含機密語義的鍵 %q（命中片段 %q）——"+
						"端點感知放寬的是鍵名的全域語義，不是「值是不是機密」這條判準",
						endpoint, key, marker)
				}
			}
		}
	}
}
