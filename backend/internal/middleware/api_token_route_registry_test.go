package middleware

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// apiTokenRouteScopeFile 路由範圍的逐條清單（方法、樣板路徑、開放與否），登錄須與它逐條相同。
const apiTokenRouteScopeFile = "testdata/api-token-route-scope.tsv"

// apiTokenRouteScopeLowerBound 清單筆數下界：讀檔退化成空集合時，比對兩個空集合會假綠。
const apiTokenRouteScopeLowerBound = 300

func loadAPITokenRouteScope(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open(filepath.FromSlash(apiTokenRouteScopeFile))
	if err != nil {
		t.Fatalf("讀取路由範圍清單失敗：%v", err)
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		if line == 1 {
			if sc.Text() != "method\tpath\tdecision" {
				t.Fatalf("清單表頭不符：%q", sc.Text())
			}
			continue
		}
		cols := strings.Split(sc.Text(), "\t")
		if len(cols) != 3 {
			t.Fatalf("第 %d 行欄數 %d，應為 3", line, len(cols))
		}
		key := cols[0] + " " + cols[1]
		if _, dup := out[key]; dup {
			t.Fatalf("第 %d 行重複：%s", line, key)
		}
		switch cols[2] {
		case "open":
			out[key] = true
		case "closed":
			out[key] = false
		default:
			t.Fatalf("第 %d 行的開放與否無法辨識：%q", line, cols[2])
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) < apiTokenRouteScopeLowerBound {
		t.Fatalf("清單只有 %d 筆（下界 %d）", len(out), apiTokenRouteScopeLowerBound)
	}
	return out
}

// TestAPITokenRouteRegistryMatchesScopeList 登錄與逐條清單雙向相同：鍵集合相同，且每一條的開放與否相同。
func TestAPITokenRouteRegistryMatchesScopeList(t *testing.T) {
	want := loadAPITokenRouteScope(t)
	var missing, extra, differ []string
	for k, open := range want {
		got, ok := apiTokenRouteRegistry[k]
		switch {
		case !ok:
			missing = append(missing, k)
		case got != open:
			differ = append(differ, k)
		}
	}
	for k := range apiTokenRouteRegistry {
		if _, ok := want[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(differ)
	if len(missing)+len(extra)+len(differ) > 0 {
		t.Fatalf("登錄與清單不符\n清單有、登錄沒有：%v\n登錄有、清單沒有：%v\n開放與否不同：%v", missing, extra, differ)
	}
	open := 0
	for _, v := range apiTokenRouteRegistry {
		if v {
			open++
		}
	}
	t.Logf("登錄 %d 條，開放 %d、不開放 %d，與清單逐條相同", len(apiTokenRouteRegistry), open, len(apiTokenRouteRegistry)-open)
}

// TestAPITokenRouteDecisionDefaultDeny 未登錄、查無路由（空樣板）、登錄為不開放皆不開放；登錄為開放者開放。
func TestAPITokenRouteDecisionDefaultDeny(t *testing.T) {
	cases := []struct {
		method, path      string
		allowed, register bool
	}{
		{"POST", "/api/v1/future-unregistered", false, false},
		{"GET", "", false, false},
		{"", "/api/v1/assets", false, false},
		{"POST", "/api/v1/connect-tokens", false, true},
		{"GET", "/api/v1/ssh", false, true},
		{"GET", "/api/v1/ping", false, true},
		{"POST", "/api/v1/assets/:id/test-connection", false, true},
		{"GET", "/api/v1/assets", true, true},
		{"POST", "/api/v1/assets", true, true},
	}
	for _, c := range cases {
		allowed, registered := APITokenRouteDecision(c.method, c.path)
		if allowed != c.allowed || registered != c.register {
			t.Errorf("%s %s：得到 (%v,%v)，應為 (%v,%v)", c.method, c.path, allowed, registered, c.allowed, c.register)
		}
	}
}
