// Package apitokenroutes 守衛：API token 的路由範圍登錄必須與伺服端實際註冊的路由雙向相符。
//
// 端點事實取自路由 golden（`cmd/server/testdata/route-golden/*.json`），那是伺服端實際註冊的路由樹的快照，
// 由路由 golden 測試釘住；四種組態（開發／正式 × 稽核開關）取聯集，任一組態註冊的路由都要登錄。
// 比對以「方法 樣板路徑」的集合做雙向差集，不以筆數相等為準：新路由未登錄即失敗，登錄了已不存在的路由也失敗。
package apitokenroutes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/middleware"
)

const modulePath = "github.com/custodexa/backend"

var routeGoldenStates = []string{"dev-auditoff", "dev-auditon", "release-auditoff", "release-auditon"}

// routeGoldenLowerBound 聯集路由數下界：讀檔或解析退化成空集合時，兩個空集合比對會假綠。
const routeGoldenLowerBound = 300

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("無法取得本檔路徑")
	}
	dir := filepath.Dir(self)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == "module "+modulePath {
					return dir
				}
			}
			t.Fatalf("%s 的 go.mod 不是 %s", dir, modulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("找不到 go.mod")
		}
		dir = parent
	}
}

// registeredRoutes 四種組態路由 golden 的「方法 樣板路徑」聯集。
func registeredRoutes(t *testing.T) map[string]bool {
	t.Helper()
	root := moduleRoot(t)
	out := map[string]bool{}
	for _, state := range routeGoldenStates {
		raw, err := os.ReadFile(filepath.Join(root, "cmd", "server", "testdata", "route-golden", state+".json"))
		if err != nil {
			t.Fatalf("讀取路由 golden %s 失敗：%v", state, err)
		}
		var doc struct {
			Routes []struct {
				Method string `json:"method"`
				Path   string `json:"path"`
			} `json:"routes"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("解析路由 golden %s 失敗：%v", state, err)
		}
		for _, r := range doc.Routes {
			out[r.Method+" "+r.Path] = true
		}
	}
	if len(out) < routeGoldenLowerBound {
		t.Fatalf("路由聯集只有 %d 條（下界 %d）", len(out), routeGoldenLowerBound)
	}
	return out
}

// diffRouteSets 回傳 (路由有而登錄沒有, 登錄有而路由沒有)，皆已排序。
func diffRouteSets(routes map[string]bool, registry []string) (unregistered, stale []string) {
	reg := map[string]bool{}
	for _, k := range registry {
		reg[k] = true
		if !routes[k] {
			stale = append(stale, k)
		}
	}
	for k := range routes {
		if !reg[k] {
			unregistered = append(unregistered, k)
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)
	return unregistered, stale
}

// TestAPITokenRouteRegistryCoversRouteInventory 登錄與路由清冊雙向相符。
func TestAPITokenRouteRegistryCoversRouteInventory(t *testing.T) {
	routes := registeredRoutes(t)
	keys := middleware.APITokenRouteRegistryKeys()
	unregistered, stale := diffRouteSets(routes, keys)
	if len(unregistered) > 0 {
		t.Errorf("路由未在 API token 路由範圍登錄（新路由須登錄，預設為不開放）：%v", unregistered)
	}
	if len(stale) > 0 {
		t.Errorf("API token 路由範圍登錄了不存在的路由：%v", stale)
	}
	for _, k := range keys {
		method, path, _ := strings.Cut(k, " ")
		if _, registered := middleware.APITokenRouteDecision(method, path); !registered {
			t.Errorf("登錄鍵 %q 無法經判定函式查到", k)
		}
	}
	t.Logf("路由 %d 條、登錄 %d 條，雙向差集皆為空", len(routes), len(keys))
}

// TestAPITokenRouteRegistryDiffDetectsDrift 比對函式本身能發現兩個方向的漂移（防止比對退化成恆真）。
func TestAPITokenRouteRegistryDiffDetectsDrift(t *testing.T) {
	routes := map[string]bool{"GET /a": true, "POST /b": true}
	if u, s := diffRouteSets(routes, []string{"GET /a"}); len(u) != 1 || u[0] != "POST /b" || len(s) != 0 {
		t.Fatalf("未登錄的路由未被發現：%v %v", u, s)
	}
	if u, s := diffRouteSets(routes, []string{"GET /a", "POST /b", "PUT /c"}); len(u) != 0 || len(s) != 1 || s[0] != "PUT /c" {
		t.Fatalf("登錄了不存在的路由未被發現：%v %v", u, s)
	}
}
