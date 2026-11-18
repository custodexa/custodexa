package middleware

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// apiTokenRouteScopeFile 路由範圍的逐條清單（方法、樣板路徑、開放與否、性質、對外連線），登錄須與它逐條相同。
const apiTokenRouteScopeFile = "testdata/api-token-route-scope.tsv"

// apiTokenRouteScopeLowerBound 清單筆數下界：讀檔退化成空集合時，比對兩個空集合會假綠。
const apiTokenRouteScopeLowerBound = 300

func loadAPITokenRouteScope(t *testing.T) map[string]APITokenRouteClass {
	t.Helper()
	f, err := os.Open(filepath.FromSlash(apiTokenRouteScopeFile))
	if err != nil {
		t.Fatalf("讀取路由範圍清單失敗：%v", err)
	}
	defer f.Close()
	out := map[string]APITokenRouteClass{}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		if line == 1 {
			if sc.Text() != "method\tpath\tdecision\tnature\toutbound" {
				t.Fatalf("清單表頭不符：%q", sc.Text())
			}
			continue
		}
		cols := strings.Split(sc.Text(), "\t")
		if len(cols) != 5 {
			t.Fatalf("第 %d 行欄數 %d，應為 5", line, len(cols))
		}
		key := cols[0] + " " + cols[1]
		if _, dup := out[key]; dup {
			t.Fatalf("第 %d 行重複：%s", line, key)
		}
		c := APITokenRouteClass{Access: APITokenRouteAccess(cols[2]), Nature: APITokenRouteNature(cols[3]), Outbound: APITokenRouteOutbound(cols[4])}
		if !c.Known() {
			t.Fatalf("第 %d 行有列舉外的值：%q", line, cols[2:])
		}
		out[key] = c
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) < apiTokenRouteScopeLowerBound {
		t.Fatalf("清單只有 %d 筆（下界 %d）", len(out), apiTokenRouteScopeLowerBound)
	}
	return out
}

// TestAPITokenRouteRegistryMatchesScopeList 登錄與逐條清單雙向相同：鍵集合相同，且每一條的三項分類相同。
func TestAPITokenRouteRegistryMatchesScopeList(t *testing.T) {
	want := loadAPITokenRouteScope(t)
	var missing, extra, differ []string
	for k, c := range want {
		got, ok := apiTokenRouteRegistry[k]
		switch {
		case !ok:
			missing = append(missing, k)
		case got != c:
			differ = append(differ, fmt.Sprintf("%s（登錄 %v，清單 %v）", k, got, c))
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
		t.Fatalf("登錄與清單不符\n清單有、登錄沒有：%v\n登錄有、清單沒有：%v\n分類不同：%v", missing, extra, differ)
	}
	counts := map[string]int{}
	for _, c := range apiTokenRouteRegistry {
		counts[string(c.Access)+"/"+string(c.Nature)+"/"+string(c.Outbound)]++
	}
	t.Logf("登錄 %d 條，與清單逐條相同；分類分佈 %v", len(apiTokenRouteRegistry), counts)
}

// withRegistryEntries 測試期間暫時加入登錄列與清單列，結束時移除（只用於判定函式的輸入空間測試）。
func withRegistryEntries(t *testing.T, entries map[string]APITokenRouteClass, mismatch, immediate []string) {
	t.Helper()
	for k, c := range entries {
		if _, exists := apiTokenRouteRegistry[k]; exists {
			t.Fatalf("測試鍵與既有登錄重複：%s", k)
		}
		apiTokenRouteRegistry[k] = c
	}
	for _, k := range mismatch {
		apiTokenMethodNatureMismatch[k] = "test"
	}
	for _, k := range immediate {
		apiTokenImmediateOutboundExceptions[k] = "test"
	}
	t.Cleanup(func() {
		for k := range entries {
			delete(apiTokenRouteRegistry, k)
		}
		for _, k := range mismatch {
			delete(apiTokenMethodNatureMismatch, k)
		}
		for _, k := range immediate {
			delete(apiTokenImmediateOutboundExceptions, k)
		}
	})
}

// TestLookupAPITokenRouteFailsClosed 判定函式的輸入空間：三項任一為空值、拼錯、unclassified 或之後新增而
// 不認得的值，一律不開放；查無路由與空樣板不開放也不算登錄；immediate 不在例外清單內不開放；
// 性質為讀而方法不是 GET、又不在不符清單內，比照寫；開放的讀與寫各自回報性質。
func TestLookupAPITokenRouteFailsClosed(t *testing.T) {
	const p = "/api/v1/__lookup_probe"
	withRegistryEntries(t, map[string]APITokenRouteClass{
		"GET " + p + "/open-read":             {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
		"POST " + p + "/open-write":           {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
		"GET " + p + "/get-write":             {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
		"POST " + p + "/post-read-unlisted":   {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
		"POST " + p + "/post-read-listed":     {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
		"GET " + p + "/nature-empty":          {RouteAccessOpen, "", RouteOutboundNone},
		"GET " + p + "/nature-typo":           {RouteAccessOpen, "Read", RouteOutboundNone},
		"GET " + p + "/nature-future":         {RouteAccessOpen, "append", RouteOutboundNone},
		"GET " + p + "/nature-unclassified":   {RouteAccessOpen, RouteNatureUnclassified, RouteOutboundNone},
		"GET " + p + "/outbound-empty":        {RouteAccessOpen, RouteNatureRead, ""},
		"GET " + p + "/outbound-typo":         {RouteAccessOpen, RouteNatureRead, "None"},
		"GET " + p + "/outbound-unclassified": {RouteAccessOpen, RouteNatureRead, RouteOutboundUnclassified},
		"GET " + p + "/access-empty":          {"", RouteNatureRead, RouteOutboundNone},
		"GET " + p + "/access-typo":           {"OPEN", RouteNatureRead, RouteOutboundNone},
		"GET " + p + "/access-closed":         {RouteAccessClosed, RouteNatureRead, RouteOutboundNone},
		"GET " + p + "/zero":                  {},
		"GET " + p + "/immediate-unlisted":    {RouteAccessOpen, RouteNatureRead, RouteOutboundImmediate},
		"GET " + p + "/immediate-listed":      {RouteAccessOpen, RouteNatureRead, RouteOutboundImmediate},
	}, []string{"POST " + p + "/post-read-listed"}, []string{"GET " + p + "/immediate-listed"})

	cases := []struct {
		method, path string
		want         APITokenRouteVerdict
		countsAll    bool
	}{
		{"GET", p + "/open-read", APITokenRouteVerdict{true, true, RouteNatureRead}, true},
		{"POST", p + "/open-write", APITokenRouteVerdict{true, true, RouteNatureWrite}, false},
		{"GET", p + "/get-write", APITokenRouteVerdict{true, true, RouteNatureWrite}, false},
		{"POST", p + "/post-read-unlisted", APITokenRouteVerdict{true, true, RouteNatureWrite}, false},
		{"POST", p + "/post-read-listed", APITokenRouteVerdict{true, true, RouteNatureRead}, true},
		{"GET", p + "/nature-empty", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/nature-typo", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/nature-future", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/nature-unclassified", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/outbound-empty", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/outbound-typo", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/outbound-unclassified", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/access-empty", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/access-typo", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/access-closed", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/zero", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/immediate-unlisted", APITokenRouteVerdict{Registered: true}, false},
		{"GET", p + "/immediate-listed", APITokenRouteVerdict{true, true, RouteNatureRead}, true},
		{"GET", p + "/not-registered", APITokenRouteVerdict{}, false},
		{"POST", p + "/open-read", APITokenRouteVerdict{}, false},
		{"GET", "", APITokenRouteVerdict{}, false},
		{"", p + "/open-read", APITokenRouteVerdict{}, false},
	}
	for _, c := range cases {
		got := LookupAPITokenRoute(c.method, c.path)
		if got != c.want || got.CountsAllGrantedRoles() != c.countsAll {
			t.Errorf("%s %s：得到 %+v（計入全部=%v），應為 %+v（計入全部=%v）", c.method, c.path, got, got.CountsAllGrantedRoles(), c.want, c.countsAll)
		}
		allowed, registered := APITokenRouteDecision(c.method, c.path)
		if allowed != c.want.Open || registered != c.want.Registered {
			t.Errorf("%s %s：APITokenRouteDecision 與 LookupAPITokenRoute 不一致", c.method, c.path)
		}
	}
}

// TestAPITokenVerdictZeroValueCountsReadWriteOnly 判定的零值（查無、不開放）不計入全部授權角色。
func TestAPITokenVerdictZeroValueCountsReadWriteOnly(t *testing.T) {
	for _, v := range []APITokenRouteVerdict{{}, {Registered: true}, {Registered: true, Open: true}, {Registered: true, Nature: RouteNatureRead}} {
		if v.CountsAllGrantedRoles() {
			t.Errorf("%+v 不應計入全部授權角色", v)
		}
	}
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

// TestAPITokenRouteScopeCredentialAttachOpen 把既有憑證掛到資產（掛載）與更換一筆掛載所引用的憑證開放；
// 讓一筆掛載脫離共用憑證（系統須以保存的秘密登入資產並改寫密碼）不開放。
func TestAPITokenRouteScopeCredentialAttachOpen(t *testing.T) {
	cases := []struct {
		method, path string
		allowed      bool
	}{
		{"POST", "/api/v1/credentials/:id/bindings", true},
		{"PUT", "/api/v1/assets/:id/accounts/:accountId/credential", true},
		{"POST", "/api/v1/credentials/:id/bindings/:accountId/detach", false},
	}
	for _, c := range cases {
		allowed, registered := APITokenRouteDecision(c.method, c.path)
		if !registered || allowed != c.allowed {
			t.Errorf("%s %s：得到 (開放=%v, 登錄=%v)，應為 (開放=%v, 登錄=true)", c.method, c.path, allowed, registered, c.allowed)
		}
	}
}

// TestAPITokenDialOutRoutesClosed 會讓平台立刻以保存的秘密對外連線的動作對 API token 不開放：
// 脫離共用、資產連線測試、立即改密（整組輪替、成員重試、計劃立即執行、建立改密批次、候選重試）、
// 專用帳號的設定或更換與登入測試。專用帳號的清除與讀取開放。
func TestAPITokenDialOutRoutesClosed(t *testing.T) {
	closed := []string{
		"POST /api/v1/credentials/:id/bindings/:accountId/detach",
		"POST /api/v1/assets/:id/test-connection",
		"POST /api/v1/credentials/:id/rotations",
		"POST /api/v1/credentials/:id/rotations/:rid/members/:mid/retry",
		"POST /api/v1/change-secret-plans/:id/run",
		"POST /api/v1/change-secret-batches",
		"POST /api/v1/change-secret-candidates/:id/retry",
		"PUT /api/v1/assets/:id/executor",
		"POST /api/v1/assets/:id/executor/login-check",
	}
	open := []string{
		"DELETE /api/v1/assets/:id/executor",
		"GET /api/v1/assets/:id/executor",
		"GET /api/v1/assets/:id/executor/login-check",
	}
	check := func(key string, want bool) {
		method, path, _ := strings.Cut(key, " ")
		allowed, registered := APITokenRouteDecision(method, path)
		if !registered || allowed != want {
			t.Errorf("%s：得到 (開放=%v, 登錄=%v)，應為 (開放=%v, 登錄=true)", key, allowed, registered, want)
		}
	}
	for _, k := range closed {
		check(k, false)
	}
	for _, k := range open {
		check(k, true)
	}
}
