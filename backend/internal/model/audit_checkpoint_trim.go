package model

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// ErrCheckpointTrimImmutable 修剪記錄守衛的統一錯誤
var ErrCheckpointTrimImmutable = errors.New("audit_checkpoint_trims 為不可變證據：不得經 ORM 修改或刪除")

// AuditCheckpointTrim 檢查點鏈的修剪記錄（audit-checkpoint-chain D8 步驟 5／log-retention spec）。
//
// **落點決策（tasks 6.10 要求明記）＝獨立表，不是 audit_log 型別**：
// 修剪記錄是「殘餘鏈的新起點錨定」，它必須活得比被它記錄的檢查點久。
// 若寫成 audit_log 列，它自己就會落入某個檢查點區間並在保留期到期時
// 被 retention 清掉——鏈頭錨定隨之消失，殘鏈自此永遠無法與被修剪段接續，
// 驗證端只能回報「鏈頭無法錨定」。獨立表另掛 BeforeUpdate／BeforeDelete
// 全拒守衛（與 audit_checkpoints 同級），符合「落點本身必須不可被 ORM 刪改」。
//
// 修剪動作**另外**寫一筆 audit_log 留痕（人可讀的操作記錄），兩者職責不同：
// 留痕會過期，錨定不會。
type AuditCheckpointTrim struct {
	ID uint `gorm:"primarykey" json:"id"`

	// FromSeq／LastTrimmedSeq 本次修剪掉的連續 seq 閉區間（自鏈頭起）
	FromSeq        uint `gorm:"not null" json:"from_seq"`
	LastTrimmedSeq uint `gorm:"not null;uniqueIndex:idx_checkpoint_trims_last_seq" json:"last_trimmed_seq"`
	// TrimmedCount 實際刪除的檢查點列數
	TrimmedCount int64 `gorm:"not null" json:"trimmed_count"`

	// LastTrimmedLinkHash 被修剪的最後一個檢查點的鏈接雜湊。
	// 它正是殘鏈新鏈頭的 prev_checkpoint_hash——驗證端據此確認
	// 「鏈頭 seq 不為 1」是合法修剪而非有人挖掉了鏈頭
	LastTrimmedLinkHash string `gorm:"type:varchar(64);not null" json:"last_trimmed_link_hash"`

	// GenesisIDFrom 修剪前鏈上最小的 id_from（＝原 genesis 的 id_from）。
	// 修剪會使 MIN(id_from) 上移，若不保存此值，pre-genesis 逐列路徑的
	// 上界會隨修剪自動放寬而刪到本應由區間路徑處理的列
	GenesisIDFrom uint `gorm:"not null" json:"genesis_id_from"`

	// PolicyDays 觸發本次修剪的 retention_checkpoint_days 值
	PolicyDays int       `gorm:"not null" json:"policy_days"`
	TrimmedAt  time.Time `gorm:"not null" json:"trimmed_at"`

	SigningKeyVersion int    `gorm:"not null" json:"signing_key_version"`
	Signature         string `gorm:"type:varchar(128);not null" json:"signature"`

	CreatedAt time.Time `json:"created_at"`
}

// TableName 指定表名
func (AuditCheckpointTrim) TableName() string {
	return "audit_checkpoint_trims"
}

// BeforeUpdate 全拒：修剪記錄一經寫入即為定局
func (AuditCheckpointTrim) BeforeUpdate(tx *gorm.DB) error {
	return ErrCheckpointTrimImmutable
}

// BeforeDelete 全拒：刪掉修剪記錄＝殘鏈失去錨定，等同把「合法修剪」變回
// 「鏈頭被挖」的不可解釋狀態
func (AuditCheckpointTrim) BeforeDelete(tx *gorm.DB) error {
	return ErrCheckpointTrimImmutable
}
