package api

import (
	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/sourceip"
)

// requestSourceIP 本套件內「已持有可信代理判定」的呼叫面（封印端點限流鍵、
// OIDC 濫用守衛限流鍵、認證審計來源位址）取來源位址的入口。
//
// **只是薄委派，不含判定**：判定與說明在 internal/sourceip（全庫唯一實作）。
// 保留這個名字是為了不動三個既有呼叫面的簽名；沒有持有判定的呼叫點請直接用
// `sourceip.Of(c)`，不要在本套件內再長出第二種取法。
func requestSourceIP(c *gin.Context, trustProxy bool) string {
	return sourceip.From(c, trustProxy)
}
