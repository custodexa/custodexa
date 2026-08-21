// Package sourceip 是全庫**唯一**的「請求來源位址」取法。
//
// 它存在的理由不是共用程式碼，而是**共用紀律**：來源位址是否採信轉送標頭，
// 必須全庫同一個答案。分家的實作會演化出「一半路徑可信、一半不可信」的混合
// 狀態，而那種偏差不會讓任何測試轉紅——審計列上照樣有一個看起來很正常的 IP。
//
// 本包的判定：**未顯式約定可信代理鏈時，只採信 socket peer IP**
// （`Request.RemoteAddr`），不採 `c.ClientIP()`。後者依 `X-Forwarded-For`／
// `X-Real-IP`／`Forwarded` 等轉送標頭改寫來源，而 gin 在未呼叫
// `SetTrustedProxies` 時**信任全部代理**——那些標頭此時完全由呼叫端控制。
// 以它為審計來源位址，任何能發出請求的人都可以為自己那筆列指定任何 IP，
// 稽核追人時追到的是他挑的那個位址；以它為限流／網段鍵，攻擊者每個請求換一個
// 標頭即得到全新額度。「未設定」正是最需要收窄的組態，不是可沿用預設的組態。
//
// 已約定可信代理（`TRUSTED_PROXIES`，非法即拒絕啟動，見 cmd/server/stage1.go）
// 時才用 `c.ClientIP()`：此時轉送標頭經 gin 的可信代理鏈判定，鏈由部署方顯式宣告。
//
// **本檔是全庫唯一允許出現 `c.ClientIP()` 的地方**，由
// cmd/server/source_ip_guard_test.go 以 AST 機械強制。
package sourceip

import (
	"net"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/config"
)

// From 依「是否已約定可信代理鏈」決定來源位址。
//
// 給呼叫端已經持有該判定的場合（handler 建構時讀一次、中介層閉包外讀一次、
// 測試要同時驗兩側行為）。**零值 false＝安全側**：未經建構子的實例、忘記接線
// 的新呼叫點，自動落在「不採信轉送標頭」那一邊。
func From(c *gin.Context, trustProxy bool) string {
	if c == nil || c.Request == nil {
		return ""
	}
	if trustProxy {
		if ip := c.ClientIP(); ip != "" {
			return ip
		}
	}
	// gin 的 RemoteIP() 只解析 Request.RemoteAddr，不看任何標頭
	if ip := c.RemoteIP(); ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(c.Request.RemoteAddr); err == nil {
		return host
	}
	// 無埠號形式（部分測試與 unix socket）：原樣採用，仍不採信任何標頭
	return c.Request.RemoteAddr
}

// Of 供沒有持有可信代理判定的呼叫點使用：現讀組態後委派 From。
//
// **不快取**：TRUSTED_PROXIES 是啟動期組態，讀取成本是幾次 os.Getenv，
// 而包級快取會讓「第一個呼叫者決定其餘所有人的判定」，測試順序即可改變行為。
// 判定來源與 cmd/server 的可信代理接線同一個函式（config.LoadSeal），
// 不另寫第二套解析——第二套一旦與 gin 實際生效的設定分歧，就會出現
// 「以為採信、實際不採信」（或反之）而無人察覺。
func Of(c *gin.Context) string {
	return From(c, config.LoadSeal().TrustedProxyConfigured())
}
