package api

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/sourceip"
)

// 登入完成點的帳號新來源位址觀察。
//
// # 為何登入只留審計標記、不進告警表
//
// 告警列的 `session_id` 是 NOT NULL，而登入沒有會話可綁。更關鍵的是重響：
// 典型流程是「登入 → 建線」，若登入也響，同一個位址會在幾秒內響兩次；
// 若登入時就把位址記成「已見」而不響，建線點的告警對典型流程就永遠不會觸發
// （登入已經把「新」抹掉了）。故基準以「首次建線」單獨追蹤，登入只把位址
// 納入已見並寫一筆審計標記——它在稽核頁與工作台查得到，但不推通知。
//
// # 觀察點＝正式會話的發放點
//
// 五處：密碼登入、多因素完成、強制註冊完成、改密完成、OIDC 交換。
// refresh 是**換發**不是新登入，不觀察——否則每 15 分鐘的透明續期都會
// 更新一次「最近見到」，那個欄位就不再代表「他什麼時候真的登入過」。
// 各點一律在正式會話確定發出**之後**呼叫（受限票證分支不觀察：
// 拿到 pending／enrollment／change 票證的人還沒進來）。

// observeLoginSource 於正式會話發出後把來源位址納入基準。
//
// **失敗不阻登入**：基準是旁路功能，DB 一時抖動不該讓正當使用者登不進來。
// 但不得靜默——一律記 log，且交易失敗即整筆回滾，下次登入補寫。
//
// 兩個 handler（本地認證與 OIDC）共用本函式而非各寫一份：判準只要分岔一次，
// 就會出現「某一條登入路徑不進基準」而該路徑的新位址從此永遠不算新。
func observeLoginSource(baseline *audit.SourceIPBaseline, c *gin.Context, resp *identity.LoginResponse) {
	if baseline == nil || resp == nil || resp.User == nil {
		return
	}
	// RefreshToken 非空＝確實發出了正式會話（受限票證分支不帶它）。
	// 沿 RefreshCookieWriter.SetFromLogin 的同一個判準，兩處不得分歧——
	// 分歧的症狀是「有 cookie 卻沒進基準」或反之
	if resp.RefreshToken == "" {
		return
	}
	if _, err := baseline.ObserveLogin(c.Request.Context(), audit.LoginObservation{
		UserID:   resp.User.ID,
		Username: resp.User.Username,
		IP:       sourceip.Of(c),
		Method:   c.Request.Method,
		Path:     c.Request.URL.Path,
		Now:      time.Now(),
	}); err != nil {
		audit.LogObserveError(audit.ObserveSiteLogin, resp.User.ID, err)
	}
}

// observeLoginSource 本地認證流（密碼登入、多因素完成、強制註冊完成、改密完成）
func (h *AuthHandler) observeLoginSource(c *gin.Context, resp *identity.LoginResponse) {
	observeLoginSource(h.sourceIPBaseline, c, resp)
}

// observeLoginSource OIDC 交換流
func (h *OIDCHandler) observeLoginSource(c *gin.Context, resp *identity.LoginResponse) {
	observeLoginSource(h.sourceIPBaseline, c, resp)
}

// SetSourceIPBaseline 注入基準服務（組裝端呼叫）。
//
// 走 setter 而非建構子參數：AuthHandler 的建構子被大量既有測試呼叫，
// 加參數會把「這些測試不需要基準服務」變成一次全樹改寫。
func (h *AuthHandler) SetSourceIPBaseline(b *audit.SourceIPBaseline) {
	h.sourceIPBaseline = b
}

// SetSourceIPBaseline 同上（OIDC 流）
func (h *OIDCHandler) SetSourceIPBaseline(b *audit.SourceIPBaseline) {
	h.sourceIPBaseline = b
}
