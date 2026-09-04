package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 代理鏈 Host 標頭守衛。
//
// 後端在 release 模式下未設 CORS_ALLOWED_ORIGINS 時只接受同源請求，判斷方式是把請求的
// Origin 與 Request.Host 相比（見 buildCORSConfig 與 cors_config_test.go）。這個判斷成立的
// 前提，是代理鏈把使用者實際連上的「主機名＋對外埠」原樣送到後端。
//
// nginx 的 $host 只保有主機名、丟掉埠號。對外埠是 443 時兩者字串剛好相等，看不出差別；
// 換成任何其他埠，瀏覽器送出的 Origin 帶著埠、Host 卻沒有，帶憑證的請求就被判成跨源而
// 拒絕（症狀：登入或解封回 403 且 body 為空）。
//
// 兩跳各有正確寫法，故本守衛只斷言「不得是 $host」而不指定唯一答案：
//   - tls-proxy（範本）：用範本自己以 $host 與 ${TLS_HTTPS_PORT} 組出的 $public_host。
//     那一跳 http2 on，而 HTTP/2 沒有 Host 標頭，$http_host 會是空值。
//   - frontend：原樣傳遞收到的 $http_host——它前面一定還有一跳，補不回上游丟掉的資訊。
//
// 正式版建置驗證另有同判準的 shell 斷言。兩處並存是刻意的：正式版建置驗證
// 不見得每次都跑，而 go test 是日常動作。

// nginxProxyHostDirective 抓 `proxy_set_header Host <值>;`，值本身留給呼叫端判讀。
var nginxProxyHostDirective = regexp.MustCompile(`(?m)^[ \t]*proxy_set_header[ \t]+Host[ \t]+([^;]+);`)

// nginxProxyConfRel 受管的兩份 nginx 設定，路徑相對於專案根。
var nginxProxyConfRel = []string{
	"docker/frontend/nginx.conf",
	"docker/reverse-proxy/nginx-tls.conf.template",
}

// TestNginxProxyChainKeepsHostPort 兩份 nginx 設定都不得把 Host 降級成 $host。
func TestNginxProxyChainKeepsHostPort(t *testing.T) {
	for _, rel := range nginxProxyConfRel {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			body := readDeployFile(t, rel)

			matches := nginxProxyHostDirective.FindAllStringSubmatch(body, -1)
			if len(matches) == 0 {
				// 指令消失有兩種可能：改用 proxy_pass 預設 Host（那是 upstream 名稱，
				// 更糟），或這份設定不再轉發。兩者都要求回頭重新檢視本守衛的前提，
				// 靜默放行等於守衛從此不存在。
				t.Fatalf("%s 內找不到任何 `proxy_set_header Host ...;`——"+
					"沒有這一行時 nginx 會把 upstream 名稱當成 Host 送出，同源判斷必然失敗；"+
					"若這份設定確實不再轉發，請一併修正本守衛", rel)
			}

			var bad []string
			for _, m := range matches {
				value := strings.TrimSpace(m[1])
				if value == "$host" {
					bad = append(bad, value)
				}
			}
			if len(bad) > 0 {
				t.Fatalf("%s 有 %d 處 `proxy_set_header Host $host;`：$host 不含埠號，"+
					"對外埠不是 443 時會讓同源請求被判成跨源（症狀：登入或解封回 403 且 body 為空）。"+
					"tls-proxy 那跳用範本裡的 $public_host，frontend 那跳用 $http_host",
					rel, len(bad))
			}
		})
	}
}

// TestNginxTLSTemplateDerivesPublicHost 範本必須真的定義出帶埠的 $public_host。
//
// 前一個測試只擋掉 $host。若有人把值改成 $public_host 卻沒定義該 map，nginx 會以空字串
// 展開未定義變數，Host 變成空的——前一個測試照樣綠，而症狀與原缺陷一模一樣。
func TestNginxTLSTemplateDerivesPublicHost(t *testing.T) {
	rel := "docker/reverse-proxy/nginx-tls.conf.template"
	body := readDeployFile(t, rel)

	if !strings.Contains(body, "$public_host") {
		t.Fatalf("%s 未使用 $public_host——本守衛假設該範本以它承載「主機名＋對外埠」，"+
			"換了做法就要回頭修守衛", rel)
	}

	mapDecl := regexp.MustCompile(`(?m)^[ \t]*map[ \t]+"\$\{TLS_HTTPS_PORT\}"[ \t]+\$public_host[ \t]*\{`)
	if !mapDecl.MatchString(body) {
		t.Fatalf("%s 找不到由 ${TLS_HTTPS_PORT} 推導 $public_host 的 map。"+
			"未定義的 nginx 變數展開成空字串，Host 會變空值而不是報錯", rel)
	}

	// 443 分支必須存在：https 的預設埠不會出現在瀏覽器送出的 Origin 裡，
	// 少了這一支就變成反過來多帶一個埠，同樣對不上。
	if !regexp.MustCompile(`(?m)^[ \t]*"443"[ \t]+\$host;`).MatchString(body) {
		t.Fatalf("%s 的 $public_host map 缺少 \"443\" -> $host 分支："+
			"對外埠為 443 時 Origin 不帶埠，Host 也不能帶", rel)
	}

	// envsubst 只展開 NGINX_ENVSUBST_FILTER 列出的變數；$public_host 不在其中，
	// 但若有人把它寫成 ${public_host} 就會被當成環境變數替換成空字串。
	if strings.Contains(body, "${public_host}") {
		t.Fatalf("%s 出現 ${public_host}：大括號形式會被啟動時的 envsubst 當成環境變數"+
			"替換成空字串，請寫成 $public_host", rel)
	}
}

// deployFilesRODir 專案根 docker/ 在容器內的唯讀掛載點（module 內，供 go test 快取追蹤）。
const deployFilesRODir = "testdata/deploy"

// readDeployFile 讀取專案根的部署設定檔，雙路徑比照 readReleaseFile：
// 容器內走 deployFilesRODir 的唯讀掛載點、host 直跑走 module 根上一層的專案根。
func readDeployFile(t *testing.T, rel string) string {
	t.Helper()
	// 掛載點只掛 docker/ 一層，故容器內路徑要去掉開頭的 "docker/"。
	inContainer := strings.TrimPrefix(rel, "docker/")
	candidates := []string{
		filepath.Join(cmdServerDir(t), filepath.FromSlash(deployFilesRODir), filepath.FromSlash(inContainer)),
		filepath.Join(filepath.Dir(guardModuleRoot(t)), filepath.FromSlash(rel)),
	}
	var tried []string
	for _, p := range candidates {
		body, err := os.ReadFile(p)
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s (%v)", p, err))
			continue
		}
		if strings.TrimSpace(string(body)) == "" {
			t.Fatalf("%s 為空——bind mount 沒生效時容器會生出空的掛載點副產物，"+
				"守衛拿空內容比對只會紅得莫名其妙", p)
		}
		return string(body)
	}
	t.Fatalf("找不到專案根 %s（容器內應唯讀掛於 cmd/server/%s；見 docker-compose.dev.yml "+
		"backend volumes）——讀不到被驗證對象即等於沒有守衛，故 fail 而非 skip。已試：%s",
		rel, deployFilesRODir, strings.Join(tried, "; "))
	return ""
}
