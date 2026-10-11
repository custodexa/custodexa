package model

import (
	"fmt"
	"regexp"
)

// PolicyChangeAuditMessage 非文字型政策鍵變更審計列的訊息欄格式：
// `policy=<鍵> old=<舊值> new=<新值>`。
//
// **寫入端與讀取端共用這一支**：政策變更的審計由 handler 寫入，操作日誌依鍵篩選、
// 升級遷移重建每日簽核的啟用歷史都要讀回這個格式。兩邊各寫一份字面值，
// 格式一旦分岔，遷移就會把每一筆變更都略過而靜默推定。
func PolicyChangeAuditMessage(key, oldValue, newValue string) string {
	return fmt.Sprintf("policy=%s old=%s new=%s", key, oldValue, newValue)
}

// policyChangeAuditRe 解析 PolicyChangeAuditMessage 的輸出（值不含空白的鍵適用）
var policyChangeAuditRe = regexp.MustCompile(`^policy=(\S+) old=(\S*) new=(\S*)$`)

// ParsePolicyChangeAuditMessage 解析非文字型政策鍵的變更訊息；不符格式回 ok=false。
// 只適用值不含空白的鍵（int／bool／enum），文字型鍵的審計列只留鍵名
func ParsePolicyChangeAuditMessage(msg string) (key, oldValue, newValue string, ok bool) {
	m := policyChangeAuditRe.FindStringSubmatch(msg)
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}
