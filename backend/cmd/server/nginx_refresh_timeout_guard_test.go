package main

import (
	"fmt"
	"strings"
	"testing"
)

// 前端站台設定對刷新端點的等候上限守衛。
//
// 前端的跨分頁換發鎖持有到換發請求落地為止；後端不回應時，鎖的持有時間由前端反向
// 代理等候上游回應的上限決定。這個上限只對刷新端點設定，且比前端換發逾時（10 秒）短，
// 留往返的餘裕。後端容器只掛 docker/，讀不到前端常數，故秒數以字面值釘住。
//
// 形狀的要點：
//   - 區塊必須巢狀在 location /api 之內：放到 server 層就不再繼承 /api 的轉送標頭，
//     Host 退成上游位址、同源判定拒絕換發。
//   - 區塊內不得有 proxy_set_header：nginx 只在當層完全沒有 proxy_set_header 時才繼承
//     外層的宣告，寫一行就讓其餘轉送標頭全部消失。
//   - location /api 本層不得設 proxy_read_timeout：/api 也承載終端與圖形連線的
//     WebSocket，整段改短會切斷閒置連線。

const (
	refreshTimeoutConf       = "docker/frontend/nginx.conf"
	refreshLocationHeader    = "location = /api/v1/auth/refresh"
	apiLocationHeader        = "location /api"
	refreshProxyPassWant     = "http://backend:8080"
	refreshReadTimeoutWant   = "8s"
)

func lastContext(d nginxDirective) string {
	if len(d.Context) == 0 {
		return ""
	}
	return d.Context[len(d.Context)-1]
}

func isServerHeader(h string) bool {
	return h == "server" || strings.HasPrefix(h, "server ")
}

// checkRefreshReadTimeout 回傳全部問題，空表示通過。
func checkRefreshReadTimeout(body string) []string {
	ds, err := scanNginxDirectives(body)
	if err != nil {
		return []string{"剖析失敗：" + err.Error()}
	}
	var problems []string

	// (a) 恰有一個刷新端點區塊，且緊鄰外層是 location /api、再外層是 server。
	paths := map[string][]string{}
	var inner []nginxDirective
	for _, d := range ds {
		if lastContext(d) != refreshLocationHeader {
			continue
		}
		key := strings.Join(d.Context, " > ")
		paths[key] = d.Context
		inner = append(inner, d)
	}
	switch {
	case len(paths) == 0:
		problems = append(problems, fmt.Sprintf("找不到 `%s` 區塊（或區塊內沒有任何指令）", refreshLocationHeader))
	case len(paths) > 1:
		var keys []string
		for k := range paths {
			keys = append(keys, k)
		}
		problems = append(problems, fmt.Sprintf("`%s` 區塊出現在多處：%s", refreshLocationHeader, strings.Join(keys, "；")))
	default:
		for key, ctx := range paths {
			n := len(ctx)
			if n != 3 || ctx[n-2] != apiLocationHeader || !isServerHeader(ctx[n-3]) {
				problems = append(problems, fmt.Sprintf(
					"`%s` 區塊不在 `server > %s` 之內（實際位置：%s）；放在 /api 之外就不再繼承 /api 的轉送標頭",
					refreshLocationHeader, apiLocationHeader, key))
			}
		}
	}

	// (b) 區塊內有 proxy_pass 與上限；(c) 區塊內沒有 proxy_set_header。
	var hasPass, hasTimeout bool
	for _, d := range inner {
		switch d.Name {
		case "proxy_pass":
			if strings.TrimSpace(d.Args) == refreshProxyPassWant {
				hasPass = true
			}
		case "proxy_read_timeout":
			if strings.TrimSpace(d.Args) == refreshReadTimeoutWant {
				hasTimeout = true
			}
		case "proxy_set_header":
			problems = append(problems, fmt.Sprintf(
				"第 %d 行：`%s` 區塊內多了轉送標頭 `proxy_set_header %s`；本層一寫，外層的轉送標頭就全部不再繼承",
				d.Line, refreshLocationHeader, d.Args))
		}
	}
	if len(inner) > 0 && !hasPass {
		problems = append(problems, fmt.Sprintf("`%s` 區塊缺少 `proxy_pass %s`", refreshLocationHeader, refreshProxyPassWant))
	}
	if len(inner) > 0 && !hasTimeout {
		problems = append(problems, fmt.Sprintf("`%s` 區塊缺少等候上限 `proxy_read_timeout %s`", refreshLocationHeader, refreshReadTimeoutWant))
	}

	// (d) location /api 本層（不含巢狀區塊）沒有 proxy_read_timeout。
	for _, d := range ds {
		if d.Name == "proxy_read_timeout" && lastContext(d) == apiLocationHeader {
			problems = append(problems, fmt.Sprintf(
				"第 %d 行：`%s` 本層被設了 `proxy_read_timeout %s`；/api 也承載 WebSocket，整段改短會切斷閒置連線",
				d.Line, apiLocationHeader, d.Args))
		}
	}
	return problems
}

func TestNginxRefreshReadTimeoutCapped(t *testing.T) {
	body := readDeployFile(t, refreshTimeoutConf)
	for _, p := range checkRefreshReadTimeout(body) {
		t.Errorf("%s：%s", refreshTimeoutConf, p)
	}
}
