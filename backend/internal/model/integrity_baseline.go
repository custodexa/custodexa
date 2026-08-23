package model

import "time"

// IntegrityBaseline 完整性功能啟用基準（單列 id=1，首次啟動時寫入）。
// Verify 原本把空 HMAC 一律歸 Legacy，
// 攻擊者竄改內容並同時清空 integrity_hmac 即可規避偵測。基準之後
// 寫入的列必帶 HMAC，空 HMAC 改判不符。
// 限制（誠實邊界）：具 DB 寫入權者可改此基準或整列刪除——
// 該層級攻擊依賴 DB 權限收斂與 SIEM 側對帳補位
type IntegrityBaseline struct {
	ID         uint      `gorm:"primarykey" json:"id"`
	BaselineAt time.Time `gorm:"not null" json:"baseline_at"`
	// MaxLogID 基準建立當下 audit_logs 最大 id：
	// 空 HMAC 判 legacy 改以 id <= MaxLogID 為準——
	// created_at 可隨列回填偽裝歷史列，自增 id 不可。既有部署由 migration
	// 以 created_at 邊界一次性回填。不帶 default tag（GORM default 觸發
	// RETURNING 破壞 sqlmock），寫入端顯式設值
	MaxLogID uint `json:"max_log_id"`
}

// TableName 指定表名
func (IntegrityBaseline) TableName() string {
	return "integrity_baselines"
}
