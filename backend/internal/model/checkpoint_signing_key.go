package model

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// ErrCheckpointSigningKeyImmutable 檢查點簽章鑰守衛的統一錯誤
var ErrCheckpointSigningKeyImmutable = errors.New("checkpoint_signing_keys 不可改刪：刪除任一曾用於簽章的版本，將使該版本簽的歷史檢查點永久不可驗")

// CheckpointSigningKey 檢查點鏈的 Ed25519 簽章鑰（audit-checkpoint-chain D5）。
//
// 形態沿匯出簽章鑰（ExportSigningKey）的專表＋ColumnCodec AAD 包裹，但
// **自始帶 version 與 active 語義**——匯出鑰無版本欄是既有缺陷，本表不重蹈。
// 檢查點記錄其 SigningKeyVersion，驗證依該版本取鑰。
//
// **不進 DataKey purpose／NeverPurgeable 登記表**：那套版本鏈、輪替、重加密與
// 清理機器全為**對稱包裹材料**而設，把非對稱私鑰塞進去要捏造 CountRefs 語義並
// 讓私鑰材料流經 KeyManager 的通用 API 面——擴大暴露面換一個本可用「無刪除路徑」
// 達成的保障。防刪保障＝無任何刪除／匯出 API ＋ 本檔的 ORM 守衛。
//
// 本 change 不提供輪替 UI／API；資料形狀使日後新增輪替不需資料遷移
// （多版本並存、version 唯一、active 明確）。屆時放行 active 翻轉必須是**刻意**
// 修改 BeforeUpdate 守衛的一次審查，而非現在先留一個縫。
type CheckpointSigningKey struct {
	ID uint `gorm:"primarykey" json:"id"`

	// Version 鑰版本（自 1 起）。UNIQUE：同版本兩把鑰會使歷史檢查點驗證取到錯鑰
	Version int `gorm:"not null;uniqueIndex:idx_checkpoint_signing_keys_version" json:"version"`

	// Active 現行簽章鑰標記（本 change 恆僅 v1 為 true）
	Active bool `gorm:"not null;default:false" json:"active"`

	// PublicKey base64 Ed25519 公鑰（非機密，明文欄；供離線驗章與清冊指紋）
	PublicKey string `gorm:"type:varchar(64);not null" json:"public_key"`

	// PrivateKeyEnc 經 ColumnCodec 以 RefCheckpointSigningPrivateKey 綁定 AAD
	// 包裹的私鑰密文（enc:a1）。json 標籤為 "-"：任何回應皆不得攜出
	PrivateKeyEnc string `gorm:"type:text;not null" json:"-"`

	CreatedAt time.Time `json:"created_at"`
}

// TableName 指定表名
func (CheckpointSigningKey) TableName() string {
	return "checkpoint_signing_keys"
}

// BeforeUpdate 全拒（key-management spec：ORM 改刪一律拒絕）
func (CheckpointSigningKey) BeforeUpdate(tx *gorm.DB) error {
	return ErrCheckpointSigningKeyImmutable
}

// BeforeDelete 全拒：刪除舊版本鑰＝以該版本簽的歷史檢查點永久不可驗，
// 是單向不可逆的證據損毀，不存在任何路徑可達成
func (CheckpointSigningKey) BeforeDelete(tx *gorm.DB) error {
	return ErrCheckpointSigningKeyImmutable
}
