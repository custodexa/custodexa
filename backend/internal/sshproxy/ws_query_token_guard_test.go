package sshproxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 連線與觀看的 WebSocket 一律以一次性票認證，**query 上不得再有 session JWT**。
//
// # 為什麼需要這個守衛
//
// query 參數逐字進入 URL、瀏覽器歷程與各層存取日誌，而 session token 的壽命以
// 分鐘計、射程是整個 API；一次性票只能開一條連線、用過即失效。收口完成後，
// 「認證不得自 query 收 session token」這條規則在 WebSocket 路徑上不再有例外——
// 但沒有任何編譯期機制阻止有人為了「除錯方便」把那條分支加回來，而加回來之後
// 所有既有測試依然全綠（舊分支只是多一條認證路徑，不影響票證路徑）。
//
// # 突變自檢
//
// 在 `authenticate` 內加回 `tokenStr := c.Query("token")` 分支 ⇒ 本守衛轉紅。
//
// # 射程邊界（明載而非靠讀者發現）
//
// 只掃這兩個連線包的**非測試**原始碼。錄影播放的 `rtoken`、OIDC 的 `code`／
// `state` 是另一種憑證、另一套判定，不在本守衛射程內；測試檔以字面量描述被拒的
// 舊形態是合法的，故排除。
func TestNoQueryTokenAuthInConnectionPackages(t *testing.T) {
	// 兩種寫法都禁：gin 的 Query／GetQuery，以及直接讀 URL 查詢字串的 Get("token")
	forbidden := regexp.MustCompile(`(?:Query|Get)\(\s*"token"\s*\)`)

	// 掃描根：鍵為回報用的包名，值為相對本測試檔的目錄
	roots := map[string]string{
		"internal/sshproxy": ".",
		"internal/proxy":    "../proxy",
	}
	scanned := 0
	var hits []string
	for name, base := range roots {
		entries, err := os.ReadDir(base)
		if err != nil {
			t.Fatalf("讀取 %s: %v", name, err)
		}
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") ||
				strings.HasSuffix(ent.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(base, ent.Name())
			data, err := os.ReadFile(path) //nolint:gosec // 測試掃描本包原始碼
			if err != nil {
				t.Fatalf("讀取 %s: %v", path, err)
			}
			scanned++
			for i, line := range strings.Split(string(data), "\n") {
				if forbidden.MatchString(line) {
					hits = append(hits, name+"/"+ent.Name()+":"+itoa(uint(i+1))+
						" → "+strings.TrimSpace(line))
				}
			}
		}
	}

	// 掃描檔數下限：路徑寫錯時 scanned 會是 0，而「零命中」看起來與「守住了」一樣
	const minScanned = 20
	if scanned < minScanned {
		t.Fatalf("只掃到 %d 個檔（下限 %d）——掃描路徑可能已失效，零命中不代表守住了",
			scanned, minScanned)
	}
	if len(hits) > 0 {
		t.Fatalf("連線包內仍有自 query 取 session token 的認證分支（%d 處）：\n  %s\n"+
			"WebSocket 一律走一次性票；query 上的長效憑證會進入 URL、瀏覽器歷程與存取日誌",
			len(hits), strings.Join(hits, "\n  "))
	}
}
