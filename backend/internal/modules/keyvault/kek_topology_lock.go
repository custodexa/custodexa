package keyvault

import (
	"fmt"

	"gorm.io/gorm"
)

// KEKTopologyLockKey 拓撲讀改寫序列化用的交易級鎖鍵（pg advisory lock）。
// 用諮詢鎖而非列鎖：初次設定時拓撲列不存在，列鎖鎖不到
const KEKTopologyLockKey int64 = 0x6b65_6b74_6f70 // "kektop"

// LockKEKTopologyTx 於呼叫端交易內取拓撲的交易級鎖，持有到交易結束。
// 兩個並行變更若都在鎖外讀到同一個舊值，後提交者會以舊快照判前後相同而漏掉一次告警，
// 並把審計的 before 記錯；呼叫端取鎖後再經 SaveKEKTopologyTx 讀舊值。
// SQLite 單一寫入者本身已序列化，不另取。
func LockKEKTopologyTx(tx *gorm.DB) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", KEKTopologyLockKey).Error; err != nil {
		return fmt.Errorf("取得委託拓撲寫入鎖失敗: %w", err)
	}
	return nil
}
