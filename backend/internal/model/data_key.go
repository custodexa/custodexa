package model

import "time"

// DataKey 用途（key-management-envelope D2）
const (
	// DataKeyPurposeData 落庫資料加密 DEK（資產憑證、通知 secret/URL、MFA secret、簽章私鑰）
	DataKeyPurposeData = "data"
	// DataKeyPurposeAuditIntegrity 審計日誌 HMAC 蓋章鑰（版本化，v0 為 legacy 派生鑰快照）
	DataKeyPurposeAuditIntegrity = "audit_integrity"
)

// DataKey 狀態
const (
	DataKeyStatusActive  = "active"
	DataKeyStatusRetired = "retired"
)

// KEK 退役原因（kek-rewrap-hygiene-hardening D9）
const (
	// KEKRetireReasonSwitched 切換退役：現行 KEK 已指向新列
	KEKRetireReasonSwitched = "switched"
	// KEKRetireReasonAbandoned 放棄退役：重包放棄，clone 未曾成為現行
	KEKRetireReasonAbandoned = "abandoned"
)

// DataKey 信封加密金鑰表（key-management-envelope D2）：每列一把被 KEK
// 包裹的金鑰材料。每 purpose 同時僅一把 active；retired 鑰永久保留供舊資料
// 解密/驗章，不得刪除。KEK 重包過渡期同一 (purpose, version) 允許新舊
// kek_id 各一列並存（D5），新 KEK 開機驗證成功後軟退役舊列。
// 金鑰明文不落庫：wrapped_key 為 KEK 包裹後材料的 base64。
// 唯一索引為 partial（WHERE kek_retired_at IS NULL，migration 20260801 轉換）：
// 退役列保留指紋史不阻擋同 KEK 重試（kek-rewrap-hygiene-hardening D9）。
type DataKey struct {
	ID uint `gorm:"primarykey" json:"id"`
	// Purpose 用途（data / audit_integrity）
	Purpose string `gorm:"type:varchar(32);not null;uniqueIndex:idx_data_keys_purpose_version_kek,priority:1" json:"purpose"`
	// Version 版本（每 purpose 獨立遞增；audit_integrity 的 0 為 legacy 快照）
	Version int `gorm:"not null;uniqueIndex:idx_data_keys_purpose_version_kek,priority:2" json:"version"`
	// WrappedKey KEK 包裹後金鑰材料（base64），不經 API 回傳
	WrappedKey string `gorm:"type:text;not null" json:"-"`
	// KEKID 包裹所用 KEK 的**金鑰引用識別**（開機一致性篩選、重包過渡識別）。
	// 本地模式為材料指紋（16 hex 字元）；委託模式為外部金鑰識別
	// （KMS 正規 key ARN 約 75 字元、PKCS#11 token:label 可更長），
	// 故欄寬自 varchar(32) 擴至 varchar(255)（kek-provider-modularization D4）。
	// **執行期模式（env／ui）SHALL NOT 進入本欄**——否則同材料在兩模式下寫出的列不同。
	KEKID string `gorm:"type:varchar(255);not null;uniqueIndex:idx_data_keys_purpose_version_kek,priority:3" json:"kek_id"`
	// Status active / retired
	Status string `gorm:"type:varchar(16);not null" json:"status"`

	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`

	// KEK 切換狀態機（key-inventory-transparency＋kek-rewrap-hygiene-hardening D9）
	// ——與 DEK Status 正交。合法欄位形狀三種：
	// live（Pending=false,RetiredAt=NULL,RetiredBy='',Reason='',Wrapped!=''）、
	// pending（Pending=true,RetiredAt=NULL,RetiredBy='',Reason='',Wrapped!=''）、
	// retired（Pending=false,RetiredAt!=NULL,Reason!=''；switched 退役 RetiredBy!=''、
	// abandoned 退役 RetiredBy=''；Wrapped 保留至顯式清理後為 ''——軟刪除優先，
	// 材料銷毀僅發生於使用者顯式清理）。
	// KEKPending 待切換 pending 標記：RewrapKEK 以新 KEK 重包的過渡列；
	// 切換完成（現行 KEK 指向此 clone）後轉 false 成為現行。
	KEKPending bool `gorm:"not null;default:false" json:"kek_pending"`
	// KEKRetiredAt KEK 退役時間（軟刪除）：非 NULL 表此列 KEK 已退役，
	// 僅存指紋與軌跡作永久歷史，不參與現行金鑰解析；材料保留至顯式清理。
	KEKRetiredAt *time.Time `gorm:"index" json:"kek_retired_at,omitempty"`
	// KEKRetiredBy 退役時記錄的 replacement KEK 指紋（切換到的新 KEK），
	// 供 KEK 退役史正確呈現 from→to（多次 A→B→C 切換不誤配）；
	// abandoned 退役無 replacement，允許空。
	KEKRetiredBy string `gorm:"type:varchar(255);not null;default:''" json:"kek_retired_by,omitempty"`
	// KEKRetiredReason 退役原因（switched／abandoned；live 與 pending 列為空）
	KEKRetiredReason string `gorm:"type:varchar(16);not null;default:''" json:"kek_retired_reason,omitempty"`
}

// TableName 指定表名
func (DataKey) TableName() string {
	return "data_keys"
}
