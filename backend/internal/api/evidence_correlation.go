package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// newEvidenceCorrelationID 證據保存類設定變更（syslog、金鑰拓撲）的審計列與系統告警共用的
// 關聯識別（隨機、不含任何輸入內容）。隨機來源失敗時回錯，由呼叫端讓整筆變更失敗：
// 退回固定值會讓不同變更共用同一個關聯識別，審計列與告警就無法互相回查。
func newEvidenceCorrelationID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("產生設定變更關聯識別失敗: %w", err)
	}
	return "evd-" + hex.EncodeToString(b), nil
}
