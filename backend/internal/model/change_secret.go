package model

import "time"

// 改密秘密型別
const (
	// ChangeSecretTypePassword 密碼輪替（chpasswd）
	ChangeSecretTypePassword = "password"
	// ChangeSecretTypeSSHKey SSH 金鑰輪替（authorized_keys 三段式）
	ChangeSecretTypeSSHKey = "ssh_key"
)

// SSH 金鑰輪替策略
const (
	// KeyStrategyAppendReplace 加新 → 驗新 → 刪舊（預設，零鎖死）：新公鑰先併存，
	// 驗證成功才刪除**本系統先前推送的那一行**，使用者自放的鑰一律不動
	KeyStrategyAppendReplace = "append_replace"
	// KeyStrategyExclusive 清空重寫：authorized_keys 只留新公鑰。用於清除來路不明的
	// 金鑰；失敗時的還原是在同一條已認證的 SFTP 連線上回寫原內容（不重新撥號），
	// 該連線已中斷即還原不可能成功（UI 須標風險）
	KeyStrategyExclusive = "exclusive"
)

// 密碼策略邊界：大小寫與數字恆為必要字類，不開放關閉
const (
	PasswordLengthMin     = 12
	PasswordLengthMax     = 64
	PasswordLengthDefault = 16
)

// 帳號範圍別名沿用 AssetAuthorization 既有的 AccountScopeAll（`@ALL`）常數
// （asset_authorization.go）——不另立第二個同義常數，避免兩份定義漂移。

// ChangeSecretPlan 改密計劃（change-secret）：資產集合 × 帳號範圍 ＋ 排程 ＋ 秘密型別與策略
type ChangeSecretPlan struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	Name     string `gorm:"size:128;not null;uniqueIndex" json:"name"`
	AssetIDs string `gorm:"type:text;not null" json:"asset_ids"` // JSON 陣列字串，如 "[1,3]"
	// Accounts 帳號範圍：JSON 字串陣列，`["@ALL"]` ＝ 該資產全部帳號，
	// 否則為帳號 username 明列集合。空值一律讀成 @ALL（回歸安全方向）
	Accounts string `gorm:"type:text" json:"accounts"`
	Cron     string `gorm:"size:64" json:"cron"` // 空值＝僅手動觸發
	Enabled  bool   `gorm:"default:true" json:"enabled"`

	// SecretType 見 ChangeSecretType* 常數
	SecretType string `gorm:"size:16;default:password" json:"secret_type"`
	// KeyStrategy 僅 SecretType=ssh_key 時有意義，見 KeyStrategy* 常數
	KeyStrategy string `gorm:"size:16;default:append_replace" json:"key_strategy"`

	// 密碼策略（per-plan，不進全域政策鍵——那域管的是平台使用者密碼）。
	// shell 敏感字元與控制字元為系統級硬排除，不在此開放設定
	PasswordLength           int  `gorm:"default:16" json:"password_length"`
	PasswordIncludeSymbol    bool `gorm:"default:true" json:"password_include_symbol"`
	PasswordExcludeAmbiguous bool `gorm:"default:true" json:"password_exclude_ambiguous"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// 改密記錄狀態
const (
	ChangeSecretSuccess = "success"
	// ChangeSecretFailed 遠端**確定未變更**（指令跑完但非零退出）：帳號憑證原樣、候選已清
	ChangeSecretFailed = "failed"
	// ChangeSecretUnverified 遠端狀態**不可知**（連線中斷／逾時／驗證失敗）：
	// 帳號憑證維持舊值、候選保留待系統重試
	ChangeSecretUnverified = "unverified"
	ChangeSecretSkipped    = "skipped"
)

// ChangeSecretRecord 單帳號改密執行記錄：不存任何秘密材料。
//
// AccountID ＋ AccountUsername 雙快照沿 session 的不可否認性慣例——帳號可能隨後
// 改名或刪除，只留 ID 則事後回答不了「當時改的是哪個帳號」。
type ChangeSecretRecord struct {
	ID      uint `gorm:"primarykey" json:"id"`
	PlanID  uint `gorm:"index;not null" json:"plan_id"`
	AssetID uint `gorm:"index;not null" json:"asset_id"`
	// AccountID 執行時釘住的帳號；0 表示尚未解析到帳號即失敗（如資產無帳號）
	AccountID       uint   `gorm:"index" json:"account_id"`
	AccountUsername string `gorm:"size:100" json:"account_username"`
	SecretType      string `gorm:"size:16" json:"secret_type"`

	Status     string    `gorm:"size:16;not null" json:"status"`
	Error      string    `gorm:"size:512" json:"error"`
	ExecutedAt time.Time `json:"executed_at"`
}

// ChangeSecretCandidate 未驗證的候選憑證。
//
// **一帳號至多一筆**（AccountID 唯一索引）：候選列的存在即代表該帳號憑證處於
// 「未驗證」狀態，不另設會與之漂移的狀態欄位。
//
// 秘密於**動遠端之前**落庫——後端在「已下達改密、尚未驗證」的窗口被砍時，
// 候選若只在記憶體即永久遺失，帳號直接鎖死。
//
// 安全紅線：PasswordEnc／PrivateKeyEnc 必須登記於 keyvault 的
// envelopeMigrationTargets（AST 守衛 envelope_targets_guard_test.go 強制），
// 漏登會使退役 DEK 銷毀前的引用掃描看不見本表密文而誤判零引用。
// 兩欄一律 json:"-"；API 回應走專屬 DTO，任何路徑皆不得回傳候選秘密。
type ChangeSecretCandidate struct {
	ID uint `gorm:"primarykey" json:"id"`
	// AccountID 唯一：同一帳號不疊加第二個未知狀態
	AccountID uint `gorm:"uniqueIndex;not null" json:"account_id"`
	AssetID   uint `gorm:"index;not null" json:"asset_id"`
	PlanID    uint `json:"plan_id"`
	// AccountUsername 執行當下的快照（同 record 的理由）
	AccountUsername string `json:"account_username" gorm:"size:100"`
	SecretType      string `gorm:"size:16;not null" json:"secret_type"`

	// 候選秘密（信封加密；絕不出現於 JSON、日誌與審計）
	PasswordEnc   string `gorm:"type:text" json:"-"`
	PrivateKeyEnc string `gorm:"type:text" json:"-"`

	// PublicKey 新公鑰的 authorized_keys 行（公鑰非機密，明文保存供刪舊／還原比對）
	PublicKey string `gorm:"type:text" json:"public_key"`
	// PreviousPublicKey 本系統先前推送的公鑰行；空值＝先前無系統推送鑰（無舊行可刪）
	PreviousPublicKey string `gorm:"type:text" json:"previous_public_key"`

	// Applied 遠端變更指令已回報成功。false ＝ 遠端狀態不可知（下達中被中斷）。
	// 只影響呈現與告警文案，不影響重試邏輯——兩者都以候選登入重試
	Applied bool `gorm:"default:false" json:"applied"`
	// Abandoned 超過重試期限：停止重試並告警。**列不自動刪除**——它是那把可能已在
	// 遠端生效的秘密的唯一副本，自動刪等同製造永久鎖死；清除須 admin 顯式操作
	Abandoned bool `gorm:"default:false;index" json:"abandoned"`

	AttemptCount  int       `gorm:"default:0" json:"attempt_count"`
	LastAttemptAt time.Time `json:"last_attempt_at"`
	NextAttemptAt time.Time `gorm:"index" json:"next_attempt_at"`
	LastError     string    `gorm:"size:512" json:"last_error"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (ChangeSecretCandidate) TableName() string {
	return "change_secret_candidates"
}
