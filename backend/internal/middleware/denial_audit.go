package middleware

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/gin-gonic/gin"
)

// 拒絕分類標記與審計細節。
//
// 能力拒絕與範圍拒絕的回應不帶拒絕依據，依據只在審計列上留下。兩種拒絕的寫出函式在請求脈絡
// 設分類標記（authzDenialKey），審計中介層據此判定狀態並把依據併進 details：
//   - 有標記即 denied（範圍拒絕的 404 因此為 denied，其他 404 仍為 failure）。
//   - details 只新增 denial、basis、required、scope_reason、count 五鍵；同名鍵已存在時保留既有值，
//     既有的 deny_reason 與查詢摘要不被覆寫。
//
// 規則拒絕（含與能力拒絕同碼者）不經這兩個寫出函式，不留標記。

// authzDenialKey 拒絕分類標記在請求脈絡中的鍵；值為 denialKindCapability 或 denialKindScope。
const authzDenialKey = "authz_denial"

const (
	denialKindCapability = "capability"
	denialKindScope      = "scope"
)

// markAuthzDenial 設分類標記。已設過者不改：回應以先寫出者為準，標記與依據跟著先寫出者。
func markAuthzDenial(c *gin.Context, kind string) {
	if _, exists := c.Get(authzDenialKey); exists {
		return
	}
	c.Set(authzDenialKey, kind)
}

// authzDenialKind 取本請求的分類標記；未經能力或範圍拒絕寫出函式回 false。
func authzDenialKind(c *gin.Context) (string, bool) {
	v, ok := c.Get(authzDenialKey)
	if !ok {
		return "", false
	}
	kind, ok := v.(string)
	return kind, ok && kind != ""
}

// determineStatus 審計狀態：有拒絕分類標記即 denied；否則 2xx 為 success、403 為 denied、其餘為 failure。
func determineStatus(c *gin.Context, statusCode int) model.AuditStatus {
	if _, marked := authzDenialKind(c); marked {
		return model.StatusDenied
	}
	if statusCode >= 200 && statusCode < 300 {
		return model.StatusSuccess
	}
	if statusCode == 403 {
		return model.StatusDenied
	}
	return model.StatusFailure
}

// denialAuditDetails 依分類標記組出拒絕細節；未標記回 nil。值只取受控集合：
// basis 為四種依據之一、required 為權限點鍵或保留條件值（逗號分隔，unregistered 為空字串）、
// scope_reason 為受控原因碼、count 為整數。不含目標、節點、使用者或群組的名稱或識別碼。
func denialAuditDetails(c *gin.Context) map[string]string {
	kind, ok := authzDenialKind(c)
	if !ok {
		return nil
	}
	switch kind {
	case denialKindCapability:
		d, _ := CapabilityDenialFrom(c)
		return map[string]string{
			"denial":   denialKindCapability,
			"basis":    string(d.Basis),
			"required": strings.Join(d.Required, ","),
		}
	case denialKindScope:
		d, _ := ScopeDenialFrom(c)
		return d.AuditDetails()
	}
	return nil
}

// mergeDenialDetails 把拒絕細節併進既有 details（JSON 物件字串）：只新增不存在的鍵，
// 同名鍵保留既有值。既有 details 無法解析時原樣保留並記日誌，不以拒絕細節取代。
func mergeDenialDetails(details string, extra map[string]string) string {
	if len(extra) == 0 {
		return details
	}
	merged := map[string]interface{}{}
	if details != "" {
		if err := json.Unmarshal([]byte(details), &merged); err != nil {
			log.Printf("[Audit] details 非 JSON 物件，拒絕細節未併入：%v", err)
			return details
		}
	}
	for k, v := range extra {
		if _, exists := merged[k]; exists {
			continue
		}
		merged[k] = v
	}
	data, err := json.Marshal(merged)
	if err != nil {
		return details
	}
	return string(data)
}
