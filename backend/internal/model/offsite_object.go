package model

import "time"

// OffsiteObject 離機儲存的保管帳冊列：每個上傳目標一列，
// 是遠端物件的**身分與狀態機**所在，同時**即是佇列**
// （`state='pending'` 的 partial index 就是取件查詢面）。
//
// **擁有表只留指標與快取**：`sessions`／`audit_export_jobs` 各加
// `offsite_object_id`（指標）與 `offsite_status`（顯示用快取；值域＝本表 `state`
// ∪ 回填分類 `{skipped_missing, skipped_expired}` ∪ `{''}`）。
// **所有決策邏輯只讀帳冊**，快取只供列表與詳情頁免 join。
//
// **表所有權歸 `internal/offsite`**（`tableOwner["offsite_objects"]="offsite"`）：
// 物件身分、狀態機、租約與世代規則全部由該包定義；`session`／`audit` 模組若直接
// gorm 或 SQL 碰本表，資料邊界閘門立即判紅——模組只能經 `offsite.Ledger` 的方法取物件。
//
// 狀態與 kind／origin 的**值域常數在 `internal/offsite`**（`state.go`），不在本檔：
// 那裡是不變式的擁有者，值域跟著擁有者走。本 model 只承載欄位形狀。
//
// 欄位刻意不帶 gorm default tag（沿 AuditExportJob 的既有取捨）：GORM 對帶 default
// 的欄位遇零值會交由 DB 填值，本表所有欄位一律由 Ledger 顯式賦值。
//
// # 索引
//
//   - `uniq_offsite_objects_owner_generation` (kind, owner_id, storage_generation_id)：
//     同一擁有者在同一設定世代只追蹤一個物件，重傳更新同列；世代含在鍵內，
//     故新世代可有新物件而舊世代的列不被覆蓋。**EnqueueTx 的冪等衝突目標**。
//   - `idx_offsite_objects_due` (origin, next_attempt_at, id) WHERE state='pending'：
//     雙佇列取件（各自 ORDER BY id DESC）。
//   - `idx_offsite_objects_lease` (lease_until) WHERE state='uploading'：租約回收。
//   - `idx_offsite_objects_state` (state)：各態計數與失敗清單。
type OffsiteObject struct {
	ID uint `gorm:"primarykey;index:idx_offsite_objects_due,priority:3,where:state = 'pending'"`

	// Kind recording／export（值域見 internal/offsite）
	Kind string `gorm:"size:16;not null;uniqueIndex:uniq_offsite_objects_owner_generation,priority:1"`
	// OwnerID sessions.id／audit_export_jobs.id
	OwnerID uint `gorm:"not null;uniqueIndex:uniq_offsite_objects_owner_generation,priority:2"`
	// Origin live（會話結束／打包完成即排入）／backfill（回填掃描排入）；雙佇列配額用
	Origin string `gorm:"size:8;not null;index:idx_offsite_objects_due,priority:1,where:state = 'pending'"`
	// Provider 上傳當時的 provider（冗餘明文身分欄：對帳與顯示直讀，免 join）
	Provider string `gorm:"size:8;not null"`
	// StorageGenerationID 上傳當時的設定世代（→ offsite_profiles.generation_id 的
	// 邏輯外鍵，不建 FK 約束）。**取回一律以本欄取世代、用該世代的憑證與 driver**
	StorageGenerationID uint `gorm:"not null;uniqueIndex:uniq_offsite_objects_owner_generation,priority:3"`

	// Bucket 上傳當時的 bucket（設定世代變更後仍可指認）
	Bucket string `gorm:"size:255;not null"`
	// ObjectKey 物件 key
	ObjectKey string `gorm:"size:1024;not null"`
	// VersionID 儲存端回的版本識別；**參考性記錄**（任何路徑不依賴），
	// 非版本化 bucket 為空字串
	VersionID string `gorm:"size:255;not null"`
	// SHA256／Size 上傳當下讀到的位元組的整檔雜湊與大小。
	// **不是**錄製當下、也不保證等於磁碟最終內容（誠實邊界）
	SHA256 string `gorm:"column:sha256;size:64;not null"`
	Size   int64  `gorm:"not null"`

	// State 狀態機（值域見 internal/offsite）
	State string `gorm:"size:20;not null;index:idx_offsite_objects_state"`
	// Attempts 上傳嘗試次數；達上限（5）即轉 failed
	Attempts int `gorm:"not null"`
	// LeaseExpiries 租約到期回收次數；≥2 即卡死判準（不等到 attempts 上限）
	LeaseExpiries int `gorm:"not null"`

	// NextAttemptAt 退避時點（退避表 1m/5m/15m/1h/6h）
	NextAttemptAt *time.Time `gorm:"index:idx_offsite_objects_due,priority:2,where:state = 'pending'"`
	// LeaseUntil 上傳中租約；到期回收回 pending
	LeaseUntil *time.Time `gorm:"index:idx_offsite_objects_lease,where:state = 'uploading'"`
	// UploadedAt 上傳成功時刻（本機快取清除的計時起點）
	UploadedAt *time.Time

	// ErrorCode 機器碼 offsite.*；原始錯誤只進 log（沿 audit_export_jobs 的既有慣例）
	ErrorCode string `gorm:"size:64;not null"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// TableName 指定資料表名
func (OffsiteObject) TableName() string {
	return "offsite_objects"
}
