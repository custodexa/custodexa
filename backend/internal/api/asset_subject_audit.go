package api

import (
	"github.com/gin-gonic/gin"
)

// 資產主體鍵的 handler 覆寫入口（auditor-workbench D4）。
//
// # 為何需要 handler 顯式指定，而不是全交給中介層推導
//
// `middleware.AuditLogMiddleware` 只能由路由推導主體：`resource == asset` 且路由帶 `:id`
// 時，`resource_id` 就是資產 id。但有一整類端點**作用於資產、路徑上卻沒有資產 id**——
// 授權建立（客體在 body）、候選憑證處置（資產在候選列上）。這些端點若不由 handler 補，
// 工作台的資產樞紐就會漏掉它們；而若讓中介層去猜（例如把任何 `:id` 當資產），
// 產出的是掛錯機器的假事件，比漏掉更糟。
//
// # 為何是「只在單一資產時才填」
//
// 群組／批次端點（節點授權、批次授權、改密計畫）一次作用於多台資產，沒有單一主體。
// 這類一律留空——挑其中一台填等於偽稱其餘幾台沒被動過。

// auditAssetIDKey 中介層讀取 handler 覆寫值的 gin context 鍵。
// 與 middleware 端的字面量對應；此處集中一份，避免各 handler 各自手打字串而漂移。
const auditAssetIDKey = "audit_asset_id"

// setAuditAssetID 標記本請求作用的單一資產。
//
// nil 或 0 一律不設：兩者都代表「這次請求沒有單一資產主體」，
// 而設下 0 會讓中介層寫出一筆指向不存在資產的列。
func setAuditAssetID(c *gin.Context, assetID *uint) {
	if assetID == nil || *assetID == 0 {
		return
	}
	c.Set(auditAssetIDKey, *assetID)
}

// setAuditAssetIDValue 同上的值型入口（呼叫端已握有非指標的資產 id）。
func setAuditAssetIDValue(c *gin.Context, assetID uint) {
	setAuditAssetID(c, &assetID)
}
