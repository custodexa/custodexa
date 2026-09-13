package model

import "time"

// KEKTopology 委託模式的**非秘密拓撲**（單列表）。
//
// # 為什麼是單列專用表而不是 security_policies 的 key-value
//
//  1. **原子性**：一次拓撲更新是三到四個欄位；key-value 一列一鍵，中途失敗會留下
//     「位址已改、角色未改」的半套目的地，而半套目的地正是本表要防的那件事。
//     單列表一次 UPDATE 即全有全無。
//  2. **政策面污染**：security_policies 是合規政策面（一鍵套用、偏離摘要、政策組
//     與允許清單守衛）。拓撲不是合規旋鈕，沒有建議值也不該出現在偏離摘要。
//  3. **具型別的設定**：位址須為 HTTPS、角色識別有長度與字元約束——同型前例是
//     ldap_directories 與 syslog_settings。
//
// # 全部欄位皆為明文，**不得走信封加密**
//
// 本表的讀取時點在**已封存狀態**（解封頁載入時），此時資料金鑰尚未解出，任何受
// 信封保護的欄位都讀不到。拓撲是非秘密（位址、區域、角色識別、Transit 金鑰名），
// 明文儲存不降低保護等級；日後若有人「順手加密」其中一欄，解封頁會在封存狀態白屏。
// 同一條警語寫在 migration 的檔頭。
//
// # 秘密不在本表
//
// AWS 的存取金鑰、GCP 的服務帳號金鑰檔內容、Vault 的角色密鑰或權杖一律**不落本表、
// 不落任何持久化位置**，只存在於該解封世代的記憶體憑證持有者。
//
// # 金鑰識別不在本表（Vault 的 Transit 金鑰名除外）
//
// 既有部署的金鑰識別沿金鑰列的 kek_id，本表 SHALL NOT 另存一份可與之分歧的副本
// ——分歧時解封頁顯示的金鑰與實際解包用的金鑰不同，核對就失去意義。Vault 的
// TransitKeyName 是例外：Vault 的金鑰引用需搭配位址才完整，且位址本來就在本表。
type KEKTopology struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Singleton 單列守衛欄；恆為 1，由 DB 的 CHECK 與 unique index 保證。
	Singleton uint8 `gorm:"not null;default:1;uniqueIndex:idx_kek_topologies_singleton" json:"-"`

	// Provider 服務商（aws／gcp／vault）。**非事實源**：實際生效的服務商由部署檔
	// 的 KEK_KMS_PROVIDER 宣告，本欄只記錄這一列是為哪一家設定的，供服務商改變時
	// 拒用陳舊拓撲。
	Provider string `gorm:"size:16;not null;default:''" json:"provider"`

	// Address 保管處位址（Vault 專屬，須 https://）。
	Address string `gorm:"size:255;not null;default:''" json:"address"`

	// TransitKeyName Vault Transit 具名金鑰（Vault 專屬）。
	TransitKeyName string `gorm:"size:128;not null;default:''" json:"transit_key_name"`

	// RoleID Vault AppRole 的角色識別（Vault 專屬；**非秘密**，秘密是 SecretID）。
	RoleID string `gorm:"size:128;not null;default:''" json:"role_id"`

	// Region 服務區域（AWS 專屬；GCP 不使用，Vault 不要求）。
	Region string `gorm:"size:64;not null;default:''" json:"region"`

	// UpdatedBy 最後變更者的帳號名（課責；變更前後值另入審計）。
	UpdatedBy string `gorm:"size:100;not null;default:''" json:"updated_by"`
}

// TableName 指定表名
func (KEKTopology) TableName() string {
	return "kek_topologies"
}
