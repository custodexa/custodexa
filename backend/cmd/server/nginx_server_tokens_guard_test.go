package main

import (
	"regexp"
	"testing"
)

// 產品出貨的兩份 nginx 設定不得在回應標頭與錯誤頁帶出版本號。
//
// 兩份設定都是 conf.d 下的 http 層級檔，`server_tokens off;` 寫在任何 server
// 區塊之外即對其下全部 server 生效。本守衛同時擋兩種退化：指令消失，以及被改成
// `on`／`build` 等仍會帶出版本的值。

// nginxServerTokensDirective 抓行首的 `server_tokens <值>;`（註解行不算）。
var nginxServerTokensDirective = regexp.MustCompile(`(?m)^[ \t]*server_tokens[ \t]+([^;]+);`)

func TestNginxConfsHideServerVersion(t *testing.T) {
	for _, rel := range nginxProxyConfRel {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			body := readDeployFile(t, rel)
			matches := nginxServerTokensDirective.FindAllStringSubmatch(body, -1)
			if len(matches) == 0 {
				t.Fatalf("%s 缺 `server_tokens off;`：nginx 預設會在 Server 標頭與錯誤頁帶出版本號", rel)
			}
			for _, m := range matches {
				if m[1] != "off" {
					t.Fatalf("%s 的 server_tokens 為 %q，應為 off", rel, m[1])
				}
			}
		})
	}
}

// TestNginxServerTokensDirectivePattern 守衛本身的正負例：註解掉的指令不算數，
// 非 off 的值要被抓出來。
func TestNginxServerTokensDirectivePattern(t *testing.T) {
	cases := []struct {
		body string
		want []string
	}{
		{"server_tokens off;\n", []string{"off"}},
		{"    server_tokens on;\n", []string{"on"}},
		{"# server_tokens off;\n", nil},
		{"server {\n    listen 80;\n}\n", nil},
	}
	for _, tc := range cases {
		got := nginxServerTokensDirective.FindAllStringSubmatch(tc.body, -1)
		if len(got) != len(tc.want) {
			t.Fatalf("%q：抓到 %d 筆，期望 %d 筆", tc.body, len(got), len(tc.want))
		}
		for i := range got {
			if got[i][1] != tc.want[i] {
				t.Fatalf("%q：值為 %q，期望 %q", tc.body, got[i][1], tc.want[i])
			}
		}
	}
}
