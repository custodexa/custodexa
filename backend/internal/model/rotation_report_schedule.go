package model

import "time"

// 報告範圍的種類（閉集）。ScopeID 的語義隨之改變，故兩欄必須成對讀。
const (
	// RotationScopeAll 全系統：ScopeID 恆為 0
	RotationScopeAll = "all"
	// RotationScopeNode 某節點含子樹：ScopeID 為節點 id
	RotationScopeNode = "node"
	// RotationScopePlan 某改密計劃涵蓋的帳號：ScopeID 為計劃 id
	RotationScopePlan = "plan"
)

// RotationReportSchedule 輪替證據報告的排程：一列一排程。
//
// # PeriodAnchor 為什麼存在
//
// 報告的記錄區間必須與排程週期一致，而週期不能自 cron 反推——cron 只說「何時
// 觸發」，不說「上一次是什麼時候」。若以「觸發時刻往回推一個週期」計算，任何
// 一次錯過的觸發（服務重啟、主機停機）都會在區間上留下一段沒有任何報告涵蓋的
// 空白，而空白在報告上看不出來。
//
// 錨點是「下一份報告的區間起點」：建立排程時＝建立時刻，每次成功建單後＝本次
// 觸發時刻，修改 cron 時＝修改時刻。區間一律為 [錨點, 觸發時刻)，故連續兩期
// 首尾相接。修改 cron 會使當期區間以修改時刻切開，這是刻意的——週期換了之後，
// 舊週期的區間對讀報告的人已經沒有意義。
type RotationReportSchedule struct {
	ID uint `gorm:"primarykey" json:"id"`
	// Name 排程名：報告封面上的人可讀識別，全庫唯一
	Name string `gorm:"size:128;not null;uniqueIndex" json:"name"`
	// Cron 標準 5 欄 cron；與改密計劃共用同一個解析器
	Cron    string `gorm:"size:64;not null" json:"cron"`
	Enabled bool   `gorm:"default:true" json:"enabled"`

	// ScopeKind／ScopeID 報告範圍，見 RotationScope* 常數
	ScopeKind string `gorm:"size:16;not null" json:"scope_kind"`
	ScopeID   uint   `gorm:"not null" json:"scope_id"`

	// RetentionDays 產物保留天數：打包完成時刻加上本值即為到期時刻，
	// 逾期由既有的匯出工作單清掃流程清除產物
	RetentionDays int `gorm:"not null" json:"retention_days"`
	// Language 報告語言（一份報告一種語言）
	Language string `gorm:"size:8;not null" json:"language"`

	// PeriodAnchor 下一份報告的記錄區間起點，見型別說明
	PeriodAnchor time.Time `gorm:"not null" json:"period_anchor"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (RotationReportSchedule) TableName() string {
	return "rotation_report_schedules"
}
