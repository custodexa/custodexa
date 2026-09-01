package model

import "time"

// 離機儲存憑證模式（`offsite_profiles.credential_mode` 值域）。
//
// 三值明確分立以消除「空密文」的歧義——空密文若同時代表「用 SDK 預設鏈」與
// 「已撤銷」，撤銷後仍可能靜默走預設鏈繼續取回。`stored ⇔ credentials_enc <> ''`
// 由具名 CHECK `offsite_profiles_credential_mode_check` 釘住（交給應用層等於沒有
// 機器盯著）。
const (
	// OffsiteCredentialStored 用該世代自己的憑證（credentials_enc 非空）
	OffsiteCredentialStored = "stored"
	// OffsiteCredentialDefaultChain 部署方**刻意**選 SDK 預設鏈／ADC（密文必空）
	OffsiteCredentialDefaultChain = "default_chain"
	// OffsiteCredentialRevoked 曾有憑證、已由管理員撤銷（密文必空且
	// credentials_cleared_at 非空）。**絕不 fallback 預設鏈**：取回一律以
	// offsite.foreign_credentials_missing 失敗，零 driver 建構、零預設鏈探測
	OffsiteCredentialRevoked = "revoked"
)

// OffsiteProfile 離機儲存的設定世代。
//
// **每列一個世代**：世代識別 `GenerationID` 為不可重用的 bigserial，
// 帳冊（`offsite_objects.storage_generation_id`）以它為邏輯外鍵。
// `ProfileFingerprint`（指紋）**可重複**——它是連線參數的函數，
// 「A→B→切回 A」會算出與第一世代相同的指紋，故它只作世代切換的觸發判準與顯示，
// **識別一律用 GenerationID**。
//
// **現行世代＝`retired_at IS NULL` 至多一列（0 或 1）**。零列有兩種語義，
// 由帳冊區分：`offsite_profiles` 完全零列＝從未設定（行為完全不變的機械保證繫於此）；
// 有歷史世代而零現行世代＝**停用態**（管理介面的「停止離機」），此時不建 uploader、
// 上傳佇列指標缺席，但**取回子系統照常組裝**、歷史物件仍可取回。
// 唯一性由 `Singleton` 常數欄 ＋ CHECK `(singleton = 1)` ＋ partial unique index
// `(singleton) WHERE retired_at IS NULL` 三者共同保證——**CHECK 不可省**，
// 單靠 unique index 只禁止相同值重複，`singleton=2` 仍可並存。
//
// **建表走增量 migration，兩條 CHECK 就在建表語句裡**
// （`internal/database/migration_evidence_offsite.go`），索引亦同。
// 現行保護者（改 DDL 前先確認它們會紅）：
//
//	TestBaselineStructuralInvariantsPostgres        逐條比對索引定義與 CHECK 具名清單
//	TestOffsiteProfilesCurrentGenerationAtMostOne   行為層實證：兩列現行被拒、singleton=2 被拒、零列合法
//	TestOffsiteProfilesCredentialModeConsistency    行為層實證：三值 × 密文空否的六格
//
// 安全紅線：`CredentialsEnc` 必須登記於 keyvault 的 `cipher_refs.go`
// （`RefOffsiteCredentials`）與 `envelopeMigrationTargets`——該清單同時驅動 DEK 輪替
// 重加密與退役 DEK 銷毀前的引用掃描，漏登會誤判零引用而銷毀仍在用的金鑰材料，
// **歷史世代憑證即永久不可解、該世代的遠端物件永不可取回**。
// AST 守衛 `envelope_targets_guard_test.go` 強制此約束。
type OffsiteProfile struct {
	// GenerationID 世代識別，不可重用（序列不回頭）
	GenerationID uint `gorm:"column:generation_id;primarykey" json:"generation_id"`

	// ProfileFingerprint 設定指紋（16 位十六進位）；**可重複**，非識別
	ProfileFingerprint string `gorm:"size:16;not null" json:"profile_fingerprint"`

	// Singleton 現行世代唯一性的常數載體；恆為 1。
	// 型別取 int32 使 GORM 在 pg 映射為 `integer`，與 DDL 逐欄一致
	// （Go `int` 會映射為 `bigint` 而需要一條 parity 例外；新表不欠這筆歷史債）
	Singleton int32 `gorm:"not null;default:1" json:"-"`

	// Provider 值域同 internal/offsite.ProviderS3／ProviderGCS
	Provider string `gorm:"size:8;not null" json:"provider"`
	// Endpoint **完整正規化含 path**（端點淨化已擋 userinfo／query／fragment）。
	// 顯示面只印 origin，path 不顯示、不入日誌
	Endpoint  string `gorm:"type:text;not null;default:''" json:"-"`
	Bucket    string `gorm:"size:255;not null" json:"bucket"`
	Prefix    string `gorm:"size:255;not null;default:''" json:"prefix"`
	Region    string `gorm:"size:64;not null;default:''" json:"region"`
	PathStyle bool   `gorm:"not null;default:false" json:"path_style"`

	// CredentialMode 三值：stored／default_chain／revoked（見本檔常數）
	CredentialMode string `gorm:"size:16;not null" json:"credential_mode"`
	// CredentialsEnc 信封加密的憑證 JSON（s3＝access key 兩欄、gcs＝SA JSON 原文）。
	// **write-only**：任何讀取 DTO、API 回應與審計皆不含此欄與其遮罩
	CredentialsEnc string `gorm:"type:text;not null;default:''" json:"-"`
	// CredentialRevision 每次憑證變更或撤銷 +1；per-generation client cache 的失效依據。
	// 跨程序與重啟的正確性不靠行程內事件：ClientFor 每次取用前核對 cache 內記載的
	// revision 與該列現值，不等即丟棄重建
	CredentialRevision int64 `gorm:"not null;default:0" json:"-"`

	CreatedAt   time.Time `json:"created_at"`
	ActivatedAt time.Time `json:"activated_at"`
	// RetiredAt NULL＝現行世代
	RetiredAt *time.Time `json:"retired_at,omitempty"`
	// CredentialsClearedAt 憑證撤銷時刻（credential_mode='revoked' 時非空）
	CredentialsClearedAt *time.Time `json:"credentials_cleared_at,omitempty"`
}

// TableName 指定資料表名
func (OffsiteProfile) TableName() string {
	return "offsite_profiles"
}
