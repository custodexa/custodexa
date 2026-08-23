package model

import (
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

// AnchorStatus 檢查點的離機錨定狀態（audit-checkpoint-chain）
const (
	// AnchorStatusEnqueued 已入 syslog 轉發佇列（**不等於送達**，誠實邊界 R4）
	AnchorStatusEnqueued = "enqueued"
	// AnchorStatusDropped 佇列已滿被丟棄（另發審計失效事件，不靜默）
	AnchorStatusDropped = "dropped"
	// AnchorStatusDisabled 部署未啟用 syslog 轉發（無離機錨定，誠實邊界 R3）
	AnchorStatusDisabled = "disabled"
)

// AggSchemeV1 聚合演算法版本標識（audit-checkpoint-chain）：
// canonical 編碼一經釘定不再變更，任何編碼演進以新的 scheme 值表示，
// 舊檢查點續以其原 scheme 重算驗證
const AggSchemeV1 = "cp-agg-v1"

// ErrCheckpointImmutable 檢查點守衛的統一錯誤（改／刪皆回此值）
var ErrCheckpointImmutable = errors.New("audit_checkpoints 為不可變證據：不得經 ORM 刪除，且僅允許更新錨定與清除狀態欄")

// AuditCheckpoint 審計檢查點（audit-checkpoint-chain）。
//
// 列級 HMAC 能偵測「列被改」，偵測不了「列被刪」——DB 直寫 DELETE 抽掉中段列
// 後殘列全數驗過。檢查點以 audit_logs 的 **id 閉區間 [id_from, id_to]** 為覆蓋
// 單位，週期性把區間內每列的 (id, key_version, integrity_hmac) 聚合成一個雜湊、
// 鏈接前一檢查點、以 Ed25519 簽章並向 syslog 錨定，使「少了列」成為可偵測事件。
//
// **區間主軸是 id 不是 created_at**：封印期回灌列的 created_at 是過去
// 事件時刻而 id 是新取號（seal_replay_sink.go:216-218），時間區間必然被後來長出
// 的列打破；自增 id 是唯一 append-closed 的切法。
//
// **空區間照蓋**：`row_count=0` 時 `id_from = 前一檢查點 id_to + 1 > id_to`，
// 「那一小時沒事發生」本身成為被簽章的主張。
type AuditCheckpoint struct {
	ID uint `gorm:"primarykey" json:"id"`

	// Seq 鏈序號，自 1（genesis）起嚴格連續遞增。UNIQUE 是並發封章下
	// 「不產生分叉鏈」的最後防線（單實例假設之外的兜底）
	Seq uint `gorm:"not null;uniqueIndex:idx_audit_checkpoints_seq" json:"seq"`

	// IDFrom／IDTo 覆蓋的 audit_logs id **閉區間**（含兩端）。
	// 空區間以 IDFrom = IDTo + 1 表示（全設計一律閉區間，
	// 半開區間會漏掉 IDFrom 那一列）
	IDFrom uint `gorm:"not null;index:idx_audit_checkpoints_range,priority:1" json:"id_from"`
	IDTo   uint `gorm:"not null;index:idx_audit_checkpoints_range,priority:2" json:"id_to"`

	// RowCount 區間內實際列數（軟刪列計入，掃描與列級驗證一致用 Unscoped）
	RowCount int64 `gorm:"not null" json:"row_count"`

	// AggHash 區間聚合雜湊（hex SHA-256）；AggScheme 為其演算法版本標識
	AggHash   string `gorm:"type:varchar(64);not null" json:"agg_hash"`
	AggScheme string `gorm:"type:varchar(32);not null" json:"agg_scheme"`

	// PrevCheckpointHash 前一檢查點「被簽章欄位＋signature」canonical 序列化的
	// SHA-256（hex）。genesis 錨定 integrity_baselines 的 max_log_id 與 baseline_at
	PrevCheckpointHash string `gorm:"type:varchar(64);not null" json:"prev_checkpoint_hash"`

	// MinCreatedAt／MaxCreatedAt 區間內實際列的時間跨度（空區間為 NULL）。
	// **僅供人讀與時間查詢的近似映射，不參與完整性判定**
	MinCreatedAt *time.Time `json:"min_created_at,omitempty"`
	MaxCreatedAt *time.Time `json:"max_created_at,omitempty"`

	// SealedAt 封章時刻（本機時鐘；完整性語義不依賴時鐘單調）
	SealedAt time.Time `gorm:"not null" json:"sealed_at"`

	// SigningKeyVersion 簽章所用的 checkpoint_signing_keys.version；
	// 驗證依此版本取鑰，版本不存在計為 signature_invalid（不得靜默略過）
	SigningKeyVersion int    `gorm:"not null" json:"signing_key_version"`
	Signature         string `gorm:"type:varchar(128);not null" json:"signature"`

	// AnchorStatus 離機錨定狀態（封章後才發生，**不在簽章涵蓋內**）；
	// 本地盡力記錄，證明力最終取決於收集端留存（誠實邊界 R4）
	AnchorStatus string `gorm:"type:varchar(16);not null" json:"anchor_status"`

	// PurgedAt／PurgeSignature／PurgeSigningKeyVersion 合法清除的 tombstone
	// （同樣不在檢查點簽章涵蓋內，其真實性由 PurgeSignature 自行承擔）。
	// PurgeSigningKeyVersion 為實作階段增列：無此欄則簽章鑰輪替後 tombstone 不可驗
	PurgedAt               *time.Time `json:"purged_at,omitempty"`
	PurgeSignature         *string    `gorm:"type:varchar(128)" json:"purge_signature,omitempty"`
	PurgeSigningKeyVersion *int       `json:"purge_signing_key_version,omitempty"`
	// PurgePolicyDays 清除當下生效的保留天數。
	//
	// **不存它，tombstone 的可驗期就只到下一次政策調整為止**：purge 簽章
	// 涵蓋 policy_days，驗證端若拿「現行政策值」重算，admin 把保留期
	// 由 365 改成 730 的那一刻，全部歷史 tombstone 一起驗不過而回報
	// purged_invalid——系統對自己的合法清除發出大規模竄改告警。
	// 與 PurgeSigningKeyVersion 是同一種錯誤的兩個面（簽章的輸入必須隨簽章保存）
	PurgePolicyDays *int `json:"purge_policy_days,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// TableName 指定表名
func (AuditCheckpoint) TableName() string {
	return "audit_checkpoints"
}

// checkpointUpdatableColumns BeforeUpdate 的欄位白名單（audit-checkpoint-chain）。
//
// 只有「封章之後才發生、且不在簽章涵蓋內」的狀態欄可更新：錨定結果與清除
// tombstone。任何被簽章欄位可改＝鏈可被系統自己改寫＝在稽核面前一文不值。
var checkpointUpdatableColumns = map[string]bool{
	"anchor_status":             true,
	"purged_at":                 true,
	"purge_signature":           true,
	"purge_signing_key_version": true,
	"purge_policy_days":         true,
}

// BeforeUpdate 僅放行白名單欄位的更新，且**只認 map 形式的 Updates**。
//
// 為何拒絕 struct 形式：`Save(&cp)`／`Updates(AuditCheckpoint{...})` 送進來的是
// 結構體，GORM 於此 hook 尚無可靠的「哪些欄位真的會寫」清單（v2 無 Statement.Changed
// 的完整語義），放行等於讓全欄位更新從結構體路徑溜過守衛。呼叫端一律寫成
// `Model(&cp).Updates(map[string]any{"anchor_status": ...})`，白名單才有意義。
func (AuditCheckpoint) BeforeUpdate(tx *gorm.DB) error {
	dest, ok := tx.Statement.Dest.(map[string]interface{})
	if !ok || len(dest) == 0 {
		return ErrCheckpointImmutable
	}
	for col := range dest {
		if !checkpointUpdatableColumns[strings.ToLower(col)] {
			return ErrCheckpointImmutable
		}
	}
	return nil
}

// BeforeDelete 全拒：檢查點是不可變證據，到期清除只得經保留政策定義的鏈修剪
// 路徑（log-retention），不存在任何 ORM 刪除入口
func (AuditCheckpoint) BeforeDelete(tx *gorm.DB) error {
	return ErrCheckpointImmutable
}
