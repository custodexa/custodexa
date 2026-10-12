package main

import (
	"fmt"
	"strings"
	"testing"
)

// 產品 nginx 設定的回應標頭守衛。
//
// nginx 的 add_header 只在「當層完全沒有 add_header」時才繼承上一層的宣告。只要某個
// location（或其內的巢狀區塊）寫了一行 add_header，server 層級宣告的安全標頭就在那條
// location 的回應上全部消失，而且不會有任何錯誤或警告。故兩份出貨設定的 location 區塊內
// 一律不得有 add_header；需要依路徑變化的標頭，以 http 層級的 map 產生變數、在 server
// 層級用單一 add_header 輸出。
//
// 前端站台設定另有快取規則要守：入口頁與路由回退 no-cache（升級後瀏覽器才拿得到新版）、
// /assets/ 下帶雜湊的產物長快取並標不可變、其餘路徑不得標不可變。
//
// 掃描以大括號深度剖析設定，不靠逐行正規式：區塊的開合可能跨行，也可能多層巢狀。

// nginxDirective 一條以分號結尾的指令，以及它所在的區塊路徑（由外而內的區塊標頭）。
type nginxDirective struct {
	Name    string
	Args    string
	Context []string
	Line    int
}

// inLocation 回傳最外層的 location 區塊標頭；不在任何 location 內時回空字串。
func (d nginxDirective) inLocation() string {
	for _, h := range d.Context {
		if h == "location" || strings.HasPrefix(h, "location ") {
			return h
		}
	}
	return ""
}

// atServerLevel 指令直接寫在 server 區塊內（不在其下任何巢狀區塊）。
func (d nginxDirective) atServerLevel() bool {
	return len(d.Context) == 1 && (d.Context[0] == "server" || strings.HasPrefix(d.Context[0], "server "))
}

// scanNginxDirectives 剖析 nginx 設定為指令清單。
//
// 處理的語法：`#` 到行尾為註解（引號內除外）、單雙引號字串內的 ; { } # 不算語法、
// envsubst 範本的 `${VAR}` 不算區塊開合。大括號不平衡時回錯誤——剖析失準的守衛
// 只會給出錯誤的綠燈。
func scanNginxDirectives(body string) ([]nginxDirective, error) {
	var (
		out       []nginxDirective
		stack     []string
		buf       strings.Builder
		line      = 1
		stmtLine  = 0
		quote     rune
		inComment bool
	)
	rs := []rune(body)
	flushHeader := func() string {
		s := strings.Join(strings.Fields(buf.String()), " ")
		buf.Reset()
		stmtLine = 0
		return s
	}
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if c == '\n' {
			line++
			inComment = false
			if quote == 0 {
				buf.WriteRune(' ')
				continue
			}
		}
		if inComment {
			continue
		}
		if quote != 0 {
			buf.WriteRune(c)
			if c == '\\' && i+1 < len(rs) {
				i++
				buf.WriteRune(rs[i])
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch {
		case c == '#':
			inComment = true
		case c == '"' || c == '\'':
			if stmtLine == 0 {
				stmtLine = line
			}
			quote = c
			buf.WriteRune(c)
		case c == '$' && i+1 < len(rs) && rs[i+1] == '{':
			// ${VAR}：變數的大括號形式，整段原樣保留。
			end := -1
			for j := i + 2; j < len(rs) && rs[j] != '\n'; j++ {
				if rs[j] == '}' {
					end = j
					break
				}
			}
			if end < 0 {
				return nil, fmt.Errorf("第 %d 行的 ${ 沒有對應的 }", line)
			}
			if stmtLine == 0 {
				stmtLine = line
			}
			buf.WriteString(string(rs[i : end+1]))
			i = end
		case c == '{':
			stack = append(stack, flushHeader())
		case c == '}':
			if strings.TrimSpace(buf.String()) != "" {
				return nil, fmt.Errorf("第 %d 行：區塊結束前有未以分號結尾的內容 %q", line, strings.TrimSpace(buf.String()))
			}
			if len(stack) == 0 {
				return nil, fmt.Errorf("第 %d 行：多出一個 }", line)
			}
			stack = stack[:len(stack)-1]
			buf.Reset()
			stmtLine = 0
		case c == ';':
			startLine := stmtLine
			if startLine == 0 {
				startLine = line
			}
			stmt := flushHeader()
			if stmt == "" {
				continue
			}
			name, args, _ := strings.Cut(stmt, " ")
			ctx := append([]string(nil), stack...)
			out = append(out, nginxDirective{Name: name, Args: args, Context: ctx, Line: startLine})
		default:
			if stmtLine == 0 && c != ' ' && c != '\t' && c != '\r' {
				stmtLine = line
			}
			buf.WriteRune(c)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("引號 %c 沒有結束", quote)
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("檔尾仍有 %d 個區塊未關閉（最內層：%q）", len(stack), stack[len(stack)-1])
	}
	if strings.TrimSpace(buf.String()) != "" {
		return nil, fmt.Errorf("檔尾有未以分號結尾的內容 %q", strings.TrimSpace(buf.String()))
	}
	return out, nil
}

// nginxAddHeaderInLocations 列出所有落在 location 區塊（含其下巢狀區塊）內的 add_header。
func nginxAddHeaderInLocations(body string) ([]string, error) {
	ds, err := scanNginxDirectives(body)
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, d := range ds {
		if d.Name != "add_header" {
			continue
		}
		if loc := d.inLocation(); loc != "" {
			bad = append(bad, fmt.Sprintf("第 %d 行 `%s { ... add_header %s; }`", d.Line, loc, d.Args))
		}
	}
	return bad, nil
}

const (
	nginxCacheMapHeader   = "map $uri $cx_cache_control"
	nginxCacheLongValue   = `"public, max-age=31536000, immutable"`
	nginxCacheNoCacheVal  = `"no-cache"`
	nginxCacheAddHeaderOK = "Cache-Control $cx_cache_control"
)

// checkFrontendNginxHeaders 前端站台設定的標頭與快取規則；回傳全部問題，空表示通過。
func checkFrontendNginxHeaders(body string) []string {
	ds, err := scanNginxDirectives(body)
	if err != nil {
		return []string{"剖析失敗：" + err.Error()}
	}
	var problems []string

	serverHeaders := map[string]string{}
	for _, d := range ds {
		if d.Name == "add_header" && d.atServerLevel() {
			serverHeaders[d.Args] = d.Args
		}
	}
	for _, want := range []string{
		`X-Content-Type-Options "nosniff" always`,
		`X-Frame-Options "SAMEORIGIN" always`,
	} {
		if _, ok := serverHeaders[want]; !ok {
			problems = append(problems, fmt.Sprintf("server 層級缺 `add_header %s;`", want))
		}
	}
	if _, ok := serverHeaders[nginxCacheAddHeaderOK]; !ok {
		// 帶 always 也算缺：always 會讓 404 等錯誤回應帶上一年長快取。
		problems = append(problems, fmt.Sprintf("server 層級缺 `add_header %s;`（不得加 always，"+
			"否則錯誤回應也會被瀏覽器長期快取）", nginxCacheAddHeaderOK))
	}

	var (
		mapFound      bool
		assetsOK      bool
		defaultOK     bool
		immutableElse []string
	)
	for _, d := range ds {
		if len(d.Context) == 1 && d.Context[0] == nginxCacheMapHeader {
			mapFound = true
			switch d.Name {
			case "~^/assets/":
				assetsOK = d.Args == nginxCacheLongValue
			case "default":
				defaultOK = d.Args == nginxCacheNoCacheVal
			}
			if d.Name != "~^/assets/" && strings.Contains(d.Args, "immutable") {
				immutableElse = append(immutableElse, fmt.Sprintf("第 %d 行 map 項 %s", d.Line, d.Name))
			}
			continue
		}
		if strings.Contains(d.Name+" "+d.Args, "immutable") {
			immutableElse = append(immutableElse, fmt.Sprintf("第 %d 行 `%s %s;`", d.Line, d.Name, d.Args))
		}
		if d.Name == "expires" {
			problems = append(problems, fmt.Sprintf("第 %d 行 `expires %s;`：expires 會另外輸出 Cache-Control，"+
				"快取規則一律只走 $cx_cache_control", d.Line, d.Args))
		}
	}
	if !mapFound {
		problems = append(problems, fmt.Sprintf("缺 http 層級的 `%s { ... }`", nginxCacheMapHeader))
	} else {
		if !assetsOK {
			problems = append(problems, fmt.Sprintf("map 缺 `~^/assets/ %s;`（帶雜湊產物的長快取）", nginxCacheLongValue))
		}
		if !defaultOK {
			problems = append(problems, fmt.Sprintf("map 缺 `default %s;`（入口頁與路由回退）", nginxCacheNoCacheVal))
		}
	}
	for _, s := range immutableElse {
		problems = append(problems, s+"：/assets/ 以外的路徑不得標 immutable（檔名不帶雜湊，內容更新後使用者拿不到新版）")
	}
	return problems
}

// TestNginxNoAddHeaderInsideLocation 兩份出貨設定的 location 區塊內不得有 add_header。
func TestNginxNoAddHeaderInsideLocation(t *testing.T) {
	for _, rel := range nginxProxyConfRel {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			bad, err := nginxAddHeaderInLocations(readDeployFile(t, rel))
			if err != nil {
				t.Fatalf("%s 剖析失敗：%v", rel, err)
			}
			if len(bad) > 0 {
				t.Fatalf("%s 的 location 區塊內有 add_header，會讓 server 層級的安全標頭在該路徑的回應上消失"+
					"（nginx 只在當層沒有任何 add_header 時才繼承上層）。改用 http 層級 map 產生變數、"+
					"在 server 層級輸出：\n  %s", rel, strings.Join(bad, "\n  "))
			}
		})
	}
}

// TestNginxFrontendHeadersAndCacheRules 前端站台設定的安全標頭與快取規則。
func TestNginxFrontendHeadersAndCacheRules(t *testing.T) {
	rel := "docker/frontend/nginx.conf"
	if problems := checkFrontendNginxHeaders(readDeployFile(t, rel)); len(problems) > 0 {
		t.Fatalf("%s：\n  %s", rel, strings.Join(problems, "\n  "))
	}
}

// TestNginxHeadersGuardScanner 守衛本身的正負例：註解不算數、巢狀區塊會被抓到、
// 引號與 ${VAR} 不干擾大括號計數、不平衡時報錯而不是放行。
func TestNginxHeadersGuardScanner(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    int
		wantErr bool
	}{
		{"server 層級不算", "server {\n  add_header A b always;\n  location / { try_files $uri /index.html; }\n}\n", 0, false},
		{"location 內被抓", "server {\n  location / {\n    add_header A b;\n  }\n}\n", 1, false},
		{"註解行不算", "server {\n  location / {\n    # add_header A b;\n    try_files $uri /index.html;\n  }\n}\n", 0, false},
		{"行尾註解不算", "server {\n  location / { root /x; # add_header A b; }\n  }\n}\n", 0, false},
		{"巢狀 location 被抓", "server {\n  location / {\n    location /x {\n      add_header A b;\n    }\n  }\n}\n", 1, false},
		{"location 內 if 被抓", "server {\n  location / {\n    if ($x) {\n      add_header A b;\n    }\n  }\n}\n", 1, false},
		{"同行多條指令", "server { location / { root /x; add_header A b; } }\n", 1, false},
		{"跨行的 location 標頭", "server {\n  location ~*\n    \\.(js)$\n  {\n    add_header A b;\n  }\n}\n", 1, false},
		{"引號內的語法字元", "server {\n  add_header A \"x;}{#y\";\n  location / { add_header B \"p;#q\"; }\n}\n", 1, false},
		{"範本變數的大括號", "server {\n  server_name ${TLS_DOMAIN};\n  location / { add_header A ${X}; }\n}\n", 1, false},
		{"多出的右括號", "server {\n}\n}\n", 0, true},
		{"未關閉的區塊", "server {\n  location / {\n}\n", 0, true},
	}
	for _, tc := range cases {
		got, err := nginxAddHeaderInLocations(tc.body)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%s：期望剖析錯誤，實得 %v", tc.name, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s：剖析錯誤 %v", tc.name, err)
		}
		if len(got) != tc.want {
			t.Fatalf("%s：抓到 %d 筆 %v，期望 %d 筆", tc.name, len(got), got, tc.want)
		}
	}
}

// TestNginxHeadersGuardMutations 以真設定的副本做突變，每一種退化都必須被抓到並指出位置。
func TestNginxHeadersGuardMutations(t *testing.T) {
	rel := "docker/frontend/nginx.conf"
	orig := readDeployFile(t, rel)
	if p := checkFrontendNginxHeaders(orig); len(p) > 0 {
		t.Fatalf("基準設定本身不通過，突變結果無意義：%v", p)
	}

	mutate := func(t *testing.T, old, new string) string {
		t.Helper()
		if strings.Count(orig, old) != 1 {
			t.Fatalf("突變錨點 %q 在 %s 內出現 %d 次（須恰為 1）——設定改了就要更新本測試",
				old, rel, strings.Count(orig, old))
		}
		return strings.Replace(orig, old, new, 1)
	}

	t.Run("location 內加回 add_header", func(t *testing.T) {
		body := mutate(t, "try_files $uri /index.html;", "try_files $uri /index.html;\n        add_header X-Test 1;")
		bad, err := nginxAddHeaderInLocations(body)
		if err != nil {
			t.Fatal(err)
		}
		if len(bad) != 1 || !strings.Contains(bad[0], "location /") || !strings.Contains(bad[0], "X-Test") {
			t.Fatalf("期望指出 location / 內的 X-Test，實得 %v", bad)
		}
	})

	checks := []struct {
		name, old, new, wantSub string
	}{
		{"拿掉 nosniff", `add_header X-Content-Type-Options "nosniff" always;`, "", "X-Content-Type-Options"},
		{"拿掉 X-Frame-Options", `add_header X-Frame-Options "SAMEORIGIN" always;`, "", "X-Frame-Options"},
		{"快取標頭加 always", "add_header Cache-Control $cx_cache_control;", "add_header Cache-Control $cx_cache_control always;", "Cache-Control"},
		{"拿掉 /assets/ 長快取", "~^/assets/         \"public, max-age=31536000, immutable\";", "", "~^/assets/"},
		{"預設改成不可變", "default            \"no-cache\";", "default            \"public, max-age=31536000, immutable\";", "default"},
		{"加回副檔名長快取", "location /api {", "location ~* \\.(js|png)$ {\n        expires 1y;\n    }\n\n    location /api {", "expires"},
	}
	for _, c := range checks {
		c := c
		t.Run(c.name, func(t *testing.T) {
			problems := checkFrontendNginxHeaders(mutate(t, c.old, c.new))
			if len(problems) == 0 {
				t.Fatalf("突變後守衛仍通過")
			}
			if !strings.Contains(strings.Join(problems, "\n"), c.wantSub) {
				t.Fatalf("問題訊息未指出 %q：%v", c.wantSub, problems)
			}
		})
	}
}
