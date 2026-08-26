package sshproxy

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sourceip"
)

// observeSourceIP 建線點的帳號新來源位址觀察（文字終端側）。
//
// # 為何在 session 建立之後
//
// 告警列的 `session_id` 是 NOT NULL，且它就是本類告警的自然鍵與冪等鍵——
// 在 session 主鍵拿到之前觀察，等於沒有可綁的會話。此處也已越過 fail-close：
// 走到這一行代表這場連線確定成立，不會出現「告警說他連進來了、實際被拒」。
//
// # 為何失敗不阻連線
//
// 基準與告警是**旁路**功能。旁路無權殺主流程——DB 一時抖動不該讓正當使用者
// 連不上被稽核的主機。但它也不得靜默：一律記 log，且整筆交易回滾使基準不轉態，
// 下一次自同一位址建線會再取得資格並補發告警。
func (h *Handler) observeSourceIP(c *gin.Context, sess *model.Session, userID, assetID uint) {
	if h.SourceIPBaseline == nil || sess == nil {
		return
	}
	aid := assetID
	if _, err := h.SourceIPBaseline.ObserveSession(c.Request.Context(), userID,
		sourceip.Of(c), sess.ID, &aid, time.Now()); err != nil {
		audit.LogObserveError(audit.ObserveSiteTerminal, userID, err)
	}
}
