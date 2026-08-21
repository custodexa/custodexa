package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestQuickstartPlaceholderCoupling 守衛 scripts/quickstart.sh 與 .env.example 的
// placeholder 耦合（change quickstart-bootstrap-script design「風險：placeholder 字面值耦合」）。
//
// 腳本以「值等於範本出貨值」判定使用者未設定並代為生成；範本改了出貨值而腳本未同步時，
// 腳本會把新出貨值當成「使用者已設定」而跳過生成——部署者就帶著範本的公開值上線，
// 且腳本輸出「已設定，未動」看起來一切正常（靜默失效，正是需要機械守衛的形態）。
// 斷言方向：範本內三鍵的**現行出貨值**必須以雙引號字面出現在腳本中。
func TestQuickstartPlaceholderCoupling(t *testing.T) {
	root := backendRoot(t)
	scriptBody := readQuickstartScript(t, root)
	tmpl := envExamplePath(t, root)

	for key, val := range parseShippedValues(t, tmpl, []string{"JWT_SECRET", "ADMIN_INITIAL_PASSWORD", "DB_PASSWORD"}) {
		if val == "" {
			// 出貨值改為空＝「空即未設定」已足夠判定，字面耦合斷言失去對象；
			// 此時應回頭重審腳本判定邏輯，故直接紅，不靜默通過。
			t.Fatalf("範本 %s 的出貨值為空——本守衛的耦合前提失效，請同步檢視 quickstart.sh 的未設定判定", key)
		}
		needle := `"` + val + `"`
		if !strings.Contains(scriptBody, needle) {
			t.Errorf("quickstart.sh 內找不到 %s 的範本出貨值字面 %s：範本已改而腳本未同步，腳本會把該值當成使用者已設定而跳過生成", key, needle)
		}
	}
}

// readQuickstartScript 定位並讀取 scripts/quickstart.sh，雙路徑比照 envExamplePath：
// 容器內走 config/testdata/scripts/（目錄掛載，避免檔案級掛載的 inode 陳舊問題）、
// host 直跑走 module 上一層的專案根。
func readQuickstartScript(t *testing.T, root string) string {
	t.Helper()
	for _, p := range []string{
		filepath.Join(root, "config", "testdata", "scripts", "quickstart.sh"), // 容器唯讀掛載點（module 內）
		filepath.Join(root, "..", "scripts", "quickstart.sh"),                 // host 專案根
	} {
		if body, err := os.ReadFile(p); err == nil {
			return string(body)
		}
	}
	t.Fatalf("找不到 scripts/quickstart.sh（容器內應唯讀掛於 config/testdata/scripts/；見 docker-compose.dev.yml backend volumes）")
	return ""
}

// parseShippedValues 取範本中指定鍵的出貨值（第一個未註解的 KEY=val 行）。
func parseShippedValues(t *testing.T, path string, keys []string) map[string]string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取範本失敗：%v", err)
	}
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	got := make(map[string]string, len(keys))
	for _, line := range strings.Split(string(body), "\n") {
		eq := strings.IndexByte(line, '=')
		if eq <= 0 || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		k := line[:eq]
		if want[k] {
			if _, dup := got[k]; !dup {
				got[k] = line[eq+1:]
			}
		}
	}
	for _, k := range keys {
		if _, ok := got[k]; !ok {
			t.Fatalf("範本內找不到未註解的 %s= 行——鍵已改名或轉為註解，請同步檢視腳本", k)
		}
	}
	return got
}
