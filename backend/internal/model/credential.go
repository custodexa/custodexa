package model

import (
	"time"

	"gorm.io/gorm"
)

// 帳號憑證庫的四張表：憑證本體、不可變的密文版本、一次輪替、輪替的逐掛載成員。
//
// # 為什麼憑證要自成一張表
//
// 登入秘密原本內嵌在資產帳號列上，同一組秘密掛在多台主機時系統只能各存一份副本，
// 於是「這組秘密被哪些主機使用」無從回答，整組改密也無從表達。憑證獨立成表之後，
// 資產帳號列退化為**掛載列**（哪台主機以哪筆憑證登入），共用關係由 `scope` 與掛載
// 列直接表達，可命名、可檢視、可整組輪替。
//
// # 安全紅線
//
// CredentialSecretVersion 的 PasswordEnc／PrivateKeyEnc 必須與本 model 同版登記於
// keyvault 的 envelopeMigrationTargets（internal/modules/keyvault/envelope_migration_service.go）
// ——該清單同時驅動 DEK 輪替重加密與退役金鑰銷毀前的引用掃描，漏登會使銷毀前掃描
// 看不見本表密文而誤判零引用，該欄資料即永久不可解。AST 守衛
// envelope_targets_guard_test.go 強制此約束。兩欄一律 json:"-"。

// 憑證範圍。
const (
	// CredentialScopeDedicated 專用憑證：恰有一個掛載，隨掛載建立與刪除，名稱為空值
	CredentialScopeDedicated = "dedicated"
	// CredentialScopeShared 共用憑證：具名、可掛多台，整組輪替的對象
	CredentialScopeShared = "shared"
)

// 協定族：憑證與資產的相容性判準。
//
// **windows 涵蓋 RDP 資產與開啟 Windows OpenSSH 的 SSH 資產**——族別回答的是
// 「這組秘密拿去登入什麼樣的系統」，而 Windows 主機在本系統可能以 rdp 或 ssh 登記，
// 兩者的帳號語義相同（本機帳號／網域帳號），故同族。
const (
	ProtocolFamilySSH      = "ssh"
	ProtocolFamilyWindows  = "windows"
	ProtocolFamilyVNC      = "vnc"
	ProtocolFamilyDatabase = "database"
	ProtocolFamilyK8s      = "k8s"
)

// 密文版本的建立原因（供憑證庫與稽核辨識這一版秘密從哪來）。
const (
	// CredentialVersionReasonManual 操作者宣告的密文（建立、直接寫入）
	CredentialVersionReasonManual = "manual"
	// CredentialVersionReasonRotation 系統改密產生
	CredentialVersionReasonRotation = "rotation"
	// CredentialVersionReasonMigration 既有帳號資料轉換時原樣搬入
	CredentialVersionReasonMigration = "migration"
	// CredentialVersionReasonDetach 單台脫離共用時產生
	CredentialVersionReasonDetach = "detach"
)

// 輪替模式。
const (
	// CredentialRotationModeGroup 整組改密：全部掛載換到同一個新版本
	CredentialRotationModeGroup = "group"
	// CredentialRotationModeSplit 拆分：各掛載各自產生新秘密，收斂後各自成為專用憑證
	CredentialRotationModeSplit = "split"
)

// 輪替狀態。
const (
	CredentialRotationRunning   = "running"
	CredentialRotationCompleted = "completed"
	CredentialRotationAbandoned = "abandoned"
)

// 輪替成員狀態（七值）。
//
// 對就位版本的影響只有一個入口：**只有 applied 會改寫掛載的 EffectiveVersionID**，
// 其餘六個狀態一律不動——遠端是否收下新秘密未知時，謊稱新版已生效會使該台連不上
// 且看不出原因。
const (
	// CredentialMemberQueued 已排入本輪，尚未領取
	CredentialMemberQueued = "queued"
	// CredentialMemberChanging 候選密文已落庫，開始對遠端下達
	CredentialMemberChanging = "changing"
	// CredentialMemberChangedUnverified 遠端已下達但尚未以新值驗證成功（含遠端狀態不可知）
	CredentialMemberChangedUnverified = "changed_unverified"
	// CredentialMemberApplied 已驗證並就位（本輪終態）
	CredentialMemberApplied = "applied"
	// CredentialMemberRetryWait 可重試的失敗且未達上限，帶下次嘗試時刻
	CredentialMemberRetryWait = "retry_wait"
	// CredentialMemberTerminalFailed 達重試上限或不可重試的確定失敗，待逐台補跑
	CredentialMemberTerminalFailed = "terminal_failed"
	// CredentialMemberAbandoned 本輪被放棄，且該成員從未動過遠端
	CredentialMemberAbandoned = "abandoned"
)

// Credential 登入秘密的唯一真相。資產帳號列只以外鍵引用之。
//
// **Name 為指標**：專用憑證的名稱是 NULL 而非空字串——共用憑證名稱的唯一索引是
// partial unique（`(name) WHERE scope = 'shared' AND deleted_at IS NULL`），
// 專用以 NULL 表達「沒有名稱」才不會在任何情況下互撞；專用的顯示名由
// 「資產名 / 帳號名」計算，不落庫。
type Credential struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Name 共用憑證必填且唯一；專用為 NULL
	Name *string `gorm:"size:128" json:"name"`
	// Scope 見 CredentialScope* 常數。
	// 列表過濾用的複合索引 (scope, deleted_at) 只在建表 DDL 內宣告——
	// 同一欄位掛兩條索引（DeletedAt 已有單欄索引）表達不進 gorm tag，
	// 沿 asset_accounts 的 (asset_id, username) partial unique 同一慣例
	Scope string `gorm:"size:16;not null" json:"scope"`
	// Username 登入帳號名，沿用既有的帳號名驗證規則
	Username string `gorm:"size:100;not null;index" json:"username"`
	// SecretType 見 ChangeSecretType* 常數（password｜ssh_key）。
	// **不新增 token 值域**：K8s 的 token 存 PasswordEnc，顯示層依 ProtocolFamily
	// 呈現為 Token 即可；多一個值域會讓改密引擎多一條永遠走不到的分支
	SecretType string `gorm:"size:16;not null" json:"secret_type"`
	// AuthMethod 認證類型：sql｜domain。1.0 只接受 sql，domain 由驗證層明確拒絕
	AuthMethod string `gorm:"size:20;not null;default:sql" json:"auth_method"`
	// ProtocolFamily 見 ProtocolFamily* 常數：掛載時與資產協定比對相容性。
	// **憑證自持而非由成員推導**——零掛載的新建共用憑證無成員可推導，
	// 而資產表單的「只列此協定可用的憑證」正需要在那個時候就能過濾
	ProtocolFamily string `gorm:"size:16;not null" json:"protocol_family"`
	Note           string `gorm:"size:255" json:"note"`

	// CurrentVersionID 現行版本：最後一次全組收斂完成的版本，
	// 或操作者宣告密文時直接指向的版本。空＝尚無任何密文
	CurrentVersionID *uint `json:"current_version_id"`
	// PendingVersionID 本次整組輪替的目標版本；同一憑證同時至多一個
	PendingVersionID *uint `json:"pending_version_id"`
	// ActiveRotationID 非空＝輪替進行中。列鎖之外的第二道判定：
	// 掛載、卸載、直接寫入密文、範圍轉換、刪除與再輪替一律先取列鎖再讀本欄
	ActiveRotationID *uint `json:"active_rotation_id"`
	// RotationEpoch 每次啟動輪替遞增，成員列快照此值——同一憑證的兩輪輪替
	// 若只靠 rotation_id 區分，事後查詢分不出成員列屬於哪一代
	RotationEpoch int64 `gorm:"not null;default:0" json:"rotation_epoch"`
}

// TableName 指定表名
func (Credential) TableName() string {
	return "credentials"
}

// CredentialSecretVersion 憑證的密文版本，**不可變**。
//
// 已建立的列不得 UPDATE：變更秘密一律新增版本。就位指標（掛載的
// EffectiveVersionID）之所以能表達「這台用舊版、那台用新版」，前提正是舊版列
// 的密文原封不動；就地覆寫會讓尚未就位的主機失去可用的秘密。
//
// 安全紅線：PasswordEnc／PrivateKeyEnc 必須登記於 keyvault 的
// envelopeMigrationTargets（見本檔檔頭），兩欄一律 json:"-"。
type CredentialSecretVersion struct {
	ID           uint `gorm:"primarykey" json:"id"`
	CredentialID uint `gorm:"not null;uniqueIndex:idx_credential_secret_versions_no,priority:1" json:"credential_id"`
	// VersionNo 該憑證內遞增的版本序號（自 1 起）
	VersionNo int `gorm:"not null;uniqueIndex:idx_credential_secret_versions_no,priority:2" json:"version_no"`
	// SecretType 見 ChangeSecretType* 常數
	SecretType string `gorm:"size:16;not null" json:"secret_type"`

	// 秘密本體（信封加密；絕不出現於 JSON、日誌與審計）
	PasswordEnc   string `gorm:"type:text" json:"-"`
	PrivateKeyEnc string `gorm:"type:text" json:"-"`

	// PublicKey 新公鑰的 authorized_keys 行（公鑰非機密，明文保存供刪舊／還原比對）
	PublicKey string `gorm:"type:text" json:"public_key"`
	// PreviousPublicKey 本系統先前推送的公鑰行；空值＝先前無系統推送鑰
	PreviousPublicKey string `gorm:"type:text" json:"previous_public_key"`

	// CreatedReason 見 CredentialVersionReason* 常數
	CreatedReason string    `gorm:"size:16;not null" json:"created_reason"`
	CreatedAt     time.Time `json:"created_at"`
}

// TableName 指定表名
func (CredentialSecretVersion) TableName() string {
	return "credential_secret_versions"
}

// CredentialRotation 一次輪替（整組或拆分）。
type CredentialRotation struct {
	ID           uint `gorm:"primarykey" json:"id"`
	CredentialID uint `gorm:"not null;index" json:"credential_id"`
	// Epoch 啟動當下憑證的 RotationEpoch 快照
	Epoch int64 `gorm:"not null" json:"epoch"`
	// Mode 見 CredentialRotationMode* 常數
	Mode string `gorm:"size:16;not null" json:"mode"`
	// TargetVersionID 整組模式的目標版本；拆分模式為空（每台目標不同）
	TargetVersionID *uint `json:"target_version_id"`
	// Status 見 CredentialRotation* 狀態常數
	Status string `gorm:"size:16;not null" json:"status"`

	// RequestedBy 發起者 id 與名字快照（使用者可能隨後改名或刪除）
	RequestedBy     uint   `json:"requested_by"`
	RequestedByName string `gorm:"size:100" json:"requested_by_name"`

	// 密碼策略：語義與改密計劃相同
	PasswordLength           int  `gorm:"default:16" json:"password_length"`
	PasswordIncludeSymbol    bool `gorm:"default:true" json:"password_include_symbol"`
	PasswordExcludeAmbiguous bool `gorm:"default:true" json:"password_exclude_ambiguous"`

	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (CredentialRotation) TableName() string {
	return "credential_rotations"
}

// CredentialRotationMember 輪替的逐掛載成員。
//
// **四個快照欄（Username／AssetID／AssetName／CredentialID）是刻意的冗餘**：
// 拆分收斂後掛載列會改指向別的憑證，歷史查詢若只靠 AccountID 回頭 join，
// 讀到的是「現在」的憑證與帳號名，而不是那一輪動的是誰。
type CredentialRotationMember struct {
	ID         uint `gorm:"primarykey" json:"id"`
	RotationID uint `gorm:"not null;uniqueIndex:idx_credential_rotation_members_target,priority:1" json:"rotation_id"`
	// AccountID 掛載列 id
	AccountID uint `gorm:"not null;uniqueIndex:idx_credential_rotation_members_target,priority:2" json:"account_id"`

	// 快照欄：本輪執行當下的事實，事後不隨現況改寫
	CredentialID uint   `gorm:"not null" json:"credential_id"`
	Username     string `gorm:"size:100" json:"username"`
	AssetID      uint   `gorm:"not null" json:"asset_id"`
	AssetName    string `gorm:"size:128" json:"asset_name"`

	// FromVersionID 本輪開始時該掛載的就位版本；空＝當時尚無就位版本
	FromVersionID *uint `json:"from_version_id"`
	// TargetVersionID 本成員要就位的版本
	TargetVersionID *uint `json:"target_version_id"`
	// State 見 CredentialMember* 常數
	State string `gorm:"size:24;not null" json:"state"`

	AttemptCount  int        `gorm:"default:0" json:"attempt_count"`
	NextAttemptAt *time.Time `json:"next_attempt_at"`
	// LastError 機器可讀的失敗原因碼，不落任何秘密材料或主機回應原文
	LastError string     `gorm:"size:64" json:"last_error"`
	AppliedAt *time.Time `json:"applied_at"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (CredentialRotationMember) TableName() string {
	return "credential_rotation_members"
}

// ProtocolFamilyForAsset 由資產協定與改密通道推導憑證的協定族。
//
// **以改密通道判斷 Windows 而非另設欄位**：一台機器只有一種進得去的遠端管理方式，
// 通道值已經表達了「這是 Windows」這件事（windows_winrm／windows_ssh），
// 另開一個布林欄會製造第二個可能與之矛盾的事實。
func ProtocolFamilyForAsset(a *Asset) string {
	if a == nil {
		return ""
	}
	if IsWindowsRotationChannel(a.EffectiveRotationChannel()) {
		return ProtocolFamilyWindows
	}
	switch {
	case a.Protocol == ProtocolRDP:
		return ProtocolFamilyWindows
	case a.Protocol == ProtocolVNC:
		return ProtocolFamilyVNC
	case a.Protocol == ProtocolK8s:
		return ProtocolFamilyK8s
	case a.Protocol.IsDatabase():
		return ProtocolFamilyDatabase
	default:
		return ProtocolFamilySSH
	}
}

// IsCredentialScope 回報字串是否為合法的憑證範圍
func IsCredentialScope(s string) bool {
	return s == CredentialScopeDedicated || s == CredentialScopeShared
}

// IsProtocolFamily 回報字串是否為合法的協定族
func IsProtocolFamily(s string) bool {
	switch s {
	case ProtocolFamilySSH, ProtocolFamilyWindows, ProtocolFamilyVNC,
		ProtocolFamilyDatabase, ProtocolFamilyK8s:
		return true
	default:
		return false
	}
}
