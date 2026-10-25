package model

import (
	"strings"
	"time"
)

// AssetHostKey 資產的 SSH host key 記錄（host-key-verification）：
// TOFU——首連記錄；之後的比對判定見 HostKeyService。
//
// Host／Port 是記錄當時的撥號位址（見 HostKeyAddress），讓同位址的新資產可沿用既有指紋；
// 推不出位址的舊列留空，下一次自身列相符時補上。ResetPending 是「本資產重置待記錄」標記：
// 下一次連線不比對，直接記錄當次指紋並清除標記。
type AssetHostKey struct {
	ID          uint      `gorm:"primarykey" json:"id"`
	AssetID     uint      `gorm:"uniqueIndex;not null" json:"asset_id"`
	Algorithm   string    `gorm:"size:64;not null" json:"algorithm"`
	Fingerprint string    `gorm:"size:128;not null" json:"fingerprint"` // SHA256:xxx 格式
	PublicKey   string    `gorm:"type:text;not null" json:"-"`          // base64 公鑰本體不外露
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	Host         string `gorm:"size:255;not null;default:'';index:idx_asset_host_keys_address,priority:1" json:"-"`
	Port         int    `gorm:"not null;default:0;index:idx_asset_host_keys_address,priority:2" json:"-"`
	ResetPending bool   `gorm:"not null;default:false" json:"-"`
	// TrustGeneration 主機信任世代：採用、生效的重置、重置後首連出示另一把金鑰時，由應用程式在
	// 同一交易以欄位運算推進；新建列為 1。比較時與列 ID 併用（刪列重建後從 1 起）。
	TrustGeneration int64 `gorm:"not null;default:1" json:"-"`

	// Inherited 不入庫：檢視時沿用同位址記錄（本資產尚無自身列）的標示，
	// 此時 ID 為 0、AssetID 為被查資產，來源列的識別不外露。
	Inherited bool `gorm:"-" json:"-"`
}

// NormalizeHostKeyHost 撥號位址主機部分的正規化：去空白、小寫、去 IPv6 方括號。
// 不做 DNS 解析：主機名與 IP 視為不同位址。
func NormalizeHostKeyHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return strings.ToLower(h)
}

// HostKeyAddress 資產的 SSH 撥號位址（已正規化）；沒有 SSH 撥號的資產回 ok=false。
//
// 協定 ssh 取 (host, port)；rdp 且改密通道為 windows_ssh 取 (host, rotation_ssh_port，0＝22)；
// 其餘無 SSH 撥號。記錄、重置、檢視與回填共用此函式，使用點以測試比對實際撥號目標與本函式一致。
func (a *Asset) HostKeyAddress() (host string, port int, ok bool) {
	switch {
	case a.Protocol == ProtocolSSH:
		host, port = a.Host, a.Port
	case a.Protocol == ProtocolRDP && a.EffectiveRotationChannel() == RotationChannelWindowsSSH:
		host, port = a.Host, a.EffectiveRotationSSHPort()
	default:
		return "", 0, false
	}
	host = NormalizeHostKeyHost(host)
	if host == "" || port <= 0 {
		return "", 0, false
	}
	return host, port, true
}

// AssetHostKeyMismatch 資產連線時觀察到、與記錄不符且尚未被確認的主機金鑰（host-key-verification）。
//
// 鍵是（資產、出示的指紋）：同一指紋再出現只累計次數與最近時間，不新增列。
// ObservedPublicKey 保存公鑰本體，供超級管理者採用時寫成完整記錄；檢視不外露。
// FirstAllowedAt 是這個指紋第一次在互動連線（終端、檔案傳輸、連線測試）被放行、
// 登入憑證第一次送出的時刻；只在背景作業被拒絕過的指紋為空。
// 採用或重置後重新記錄時，同一交易清除該資產的全部觀察列。
type AssetHostKeyMismatch struct {
	ID                  uint       `gorm:"primarykey" json:"id"`
	AssetID             uint       `gorm:"not null;uniqueIndex:idx_asset_host_key_mismatches_asset_fp,priority:1" json:"asset_id"`
	Host                string     `gorm:"size:255;not null;default:''" json:"-"`
	Port                int        `gorm:"not null;default:0" json:"-"`
	RecordedFingerprint string     `gorm:"size:128;not null" json:"-"`
	ObservedAlgorithm   string     `gorm:"size:64;not null" json:"algorithm"`
	ObservedFingerprint string     `gorm:"size:128;not null;uniqueIndex:idx_asset_host_key_mismatches_asset_fp,priority:2" json:"fingerprint"`
	ObservedPublicKey   string     `gorm:"type:text;not null" json:"-"`
	FirstSeenAt         time.Time  `gorm:"not null" json:"first_seen_at"`
	LastSeenAt          time.Time  `gorm:"not null" json:"last_seen_at"`
	FirstAllowedAt      *time.Time `json:"-"`
	SeenCount           int        `gorm:"not null;default:1" json:"seen_count"`
}

// 工作列（候選、輪替成員）的主機身分綁定狀態。
const (
	// HostKeyBindingLegacy 升級前建立，沒有歷史身分
	HostKeyBindingLegacy = "legacy"
	// HostKeyBindingPending 新版建立，尚未完成任何金鑰交換（沒有送出過任何認證）
	HostKeyBindingPending = "pending"
	// HostKeyBindingBound 已在首次金鑰交換、認證之前綁定
	HostKeyBindingBound = "bound"
)

// 綁定當時的傳輸種類。
const (
	HostKeyTransportSSH   = "ssh"
	HostKeyTransportWinRM = "winrm"
)

// CredentialHostIdentityConfirmation 逐工作、只驗證的主機身分人工承接紀錄。
//
// 不覆寫工作列的原快照。**無外鍵、不 cascade**：一般候選轉正後會被刪，承接證據必須留下。
// Kind 為 candidate／member；（Kind, JobID, Revision）唯一。
type CredentialHostIdentityConfirmation struct {
	ID    uint   `gorm:"primarykey" json:"-"`
	Kind  string `gorm:"size:16;not null;uniqueIndex:idx_credential_host_identity_confirmations_job,priority:1;index:idx_credential_host_identity_confirmations_consumed,priority:1" json:"-"`
	JobID uint   `gorm:"not null;uniqueIndex:idx_credential_host_identity_confirmations_job,priority:2;index:idx_credential_host_identity_confirmations_consumed,priority:2" json:"-"`
	// Revision 同一工作的第幾次確認，從 1 起
	Revision  int64 `gorm:"not null;default:1;uniqueIndex:idx_credential_host_identity_confirmations_job,priority:3" json:"-"`
	AssetID   uint  `gorm:"not null" json:"-"`
	AccountID uint  `gorm:"not null;default:0" json:"-"`

	ConfirmedBy          uint   `gorm:"not null" json:"-"`
	ConfirmedByName      string `gorm:"size:100;not null;default:''" json:"-"`
	ConfirmedTransport   string `gorm:"size:16;not null" json:"-"`
	ConfirmedRecordID    uint   `gorm:"not null;default:0" json:"-"`
	ConfirmedAlgorithm   string `gorm:"size:64;not null;default:''" json:"-"`
	ConfirmedFingerprint string `gorm:"size:128;not null;default:''" json:"-"`
	ConfirmedGeneration  int64  `gorm:"not null;default:0" json:"-"`
	AcceptDifferentKey   bool   `gorm:"not null;default:false" json:"-"`

	OriginalBinding          string `gorm:"size:16;not null;default:''" json:"-"`
	OriginalTransport        string `gorm:"size:16;not null;default:''" json:"-"`
	OriginalRecordID         uint   `gorm:"not null;default:0" json:"-"`
	OriginalFingerprint      string `gorm:"size:128;not null;default:''" json:"-"`
	OriginalGeneration       int64  `gorm:"not null;default:0" json:"-"`
	OriginalInitiatorID      uint   `gorm:"not null;default:0" json:"-"`
	OriginalInitiatorUnknown bool   `gorm:"not null;default:false" json:"-"`

	AuthzVersion      int64  `gorm:"not null;default:0" json:"-"`
	RestoreGeneration string `gorm:"size:64;not null;default:''" json:"-"`
	ClientIP          string `gorm:"size:64;not null;default:''" json:"-"`

	CreatedAt  time.Time  `json:"-"`
	StartedAt  *time.Time `json:"-"`
	ConsumedAt *time.Time `gorm:"index:idx_credential_host_identity_confirmations_consumed,priority:3" json:"-"`
	// Outcome ''／verified／verify_failed／identity_moved／commit_failed／unknown
	Outcome string `gorm:"size:24;not null;default:''" json:"-"`
}

// TableName 指定表名
func (CredentialHostIdentityConfirmation) TableName() string {
	return "credential_host_identity_confirmations"
}

// AuditOpHostIdentityStop 改密工作因主機身分異動而停止的審計 operation 值（details.operation）。
// 審計列的動作仍是 update；候選歸 change_secret_plan 資源，輪替成員歸 credential 資源。
const AuditOpHostIdentityStop = "host_identity_stop"

// AuditOpHostIdentityConfirm 具權者承接新主機身分、建立承接紀錄的審計 operation 值（details.operation）。
// 審計列的動作是 update、狀態 success；資源歸屬同 AuditOpHostIdentityStop。
const AuditOpHostIdentityConfirm = "host_identity_confirm"
