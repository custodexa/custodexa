package model

import (
	"time"

	"gorm.io/gorm"
)

// SessionStatus 連線狀態
type SessionStatus string

const (
	SessionStatusActive       SessionStatus = "active"
	SessionStatusDisconnected SessionStatus = "disconnected"
	SessionStatusClosed       SessionStatus = "closed"
)

// Session 斷線原因（end_reason 欄，VARCHAR(20)；連線層的 idle_timeout/
// max_duration 常數定義於各 proxy 套件）
const (
	EndReasonAdminTerminate = "admin_terminate"
	EndReasonUserTerminate  = "user_terminate"
	EndReasonBackendRestart = "backend_restart"
	EndReasonOrphaned       = "orphaned"
	EndReasonRevoked        = "revoked" // 臨時授權提前撤銷收線（break-glass-revocation D5）
	// EndReasonAssetDisabled 資產被停用而收線（security-backlog-settlement）：
	// 與帳號停用收線（走 admin_terminate）分開記，使審計能區分「人被停」與「機器被停」
	EndReasonAssetDisabled = "asset_disabled"
)

// Session 連線 session 模型
type Session struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	SessionID string        `gorm:"uniqueIndex;not null;size:100" json:"session_id"`
	Status    SessionStatus `gorm:"not null;size:20" json:"status"`
	Protocol  ProtocolType  `gorm:"not null;size:10" json:"protocol"`

	// 關聯資訊
	UserID  uint   `gorm:"not null" json:"user_id"`
	User    *User  `gorm:"foreignKey:UserID" json:"user,omitempty"`
	AssetID *uint  `json:"asset_id,omitempty"` // 可選：手動連線時可能沒有資產 ID
	Asset   *Asset `gorm:"foreignKey:AssetID" json:"asset,omitempty"`

	// 連線資訊
	ClientIP  string     `gorm:"size:50" json:"client_ip"`
	StartTime time.Time  `json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Duration  int        `json:"duration"` // 秒數

	// 斷線原因（session-timeout/session-reconciliation）：normal/idle_timeout/
	// max_duration/admin_terminate/user_terminate/backend_restart/orphaned/
	// revoked/block_clear_failed（阻斷後清行失敗的 fail-close 收線，
	// backend-i18n-unification A1；值定義於 sshproxy.bridge）
	EndReason string `gorm:"size:20;default:normal" json:"end_reason,omitempty"`

	// 錄製資訊
	RecordingPath string `gorm:"size:500" json:"recording_path,omitempty"`
	RecordingSize int64  `json:"recording_size,omitempty"` // bytes
	HasRecording  bool   `gorm:"default:false" json:"has_recording"`
	// RecordingError 錄影失敗原因（recording-failure-handling D3）：非空＝
	// 本會話錄影缺失或不完整，前端據此顯「無錄影」標示；空＝正常
	RecordingError string `gorm:"type:text" json:"recording_error,omitempty"`
	// RecordingStartedAt 錄影本身的時間原點（workbench-exits-and-export D2）。
	// **不等於 StartTime**：回放的 elapsed=0 是錄製器啟動當下，而 StartTime 是
	// 會話建檔當下。深連結帶的秒數 t 以 StartTime 為基準，正確的回放位置是
	// p = t −（RecordingStartedAt − StartTime）——沒有這一欄就只能直接 seek(t)，
	// 誤差恆等於那個差，方向依協議而異：
	//   文字終端：錄製器在會話建檔「之後」才啟動（認證＋PTY 就緒），差為正，
	//             未校正的落點**偏晚、會跳過目標事件**（危險側，且隨認證耗時放大）；
	//   圖形：guacd 握手在會話建檔「之前」完成，差為負，未校正的落點偏早。
	// NULL＝無錄影或存量資料，此時前端退回未校正值並明示（見 SessionDetail 的降級文案）。
	RecordingStartedAt *time.Time `json:"recording_started_at,omitempty"`

	// 帳號雙快照（asset-multi-account D7）：連線當下所用的資產帳號 ID 與 username
	// 同時釘住——只存 FK 不足以保證不可否認性（帳號改名／刪除會洗掉歷史語義），
	// 只存 username 又無法回指帳號物件。0／空＝該會話未帶帳號（歷史資料、
	// 零帳號路徑）。沿 k8s 六欄不可變快照先例：寫入後永不隨帳號變動更新。
	AccountID       uint   `gorm:"index" json:"account_id,omitempty"`
	AccountUsername string `gorm:"size:100" json:"account_username,omitempty"`

	// 認證溯源（idp-oidc-integration 1.9）：建立此會話的憑證是經哪個 OIDC provider
	// 認證的，以及當下的 provider 世代。NULL／0＝本地或 LDAP 登入。
	//
	// **定位是溯源快照，不是授權快照**：授權一律 DB 現查。它的用途是
	// 「停用某 provider 時要砍哪些進行中的連線」——**禁止以「查外部身分表反推
	// provider」代替**，混合帳號（同時有本地密碼與外部身分）會被誤標，
	// 導致停用 provider 時連帶砍掉該帳號用本地密碼建立的會話。
	AuthProviderID *uint `gorm:"index" json:"auth_provider_id,omitempty"`
	AuthEpoch      int   `gorm:"not null;default:0" json:"-"`

	// K8s 會話不可變快照（k8s-exec 對抗審查 mustFix #2）：pod 短命且名稱可複用，
	// 連線當下由 get pod 釘住 uid/image/node 才有不可否認性。
	K8sNamespace string `gorm:"size:63" json:"k8s_namespace,omitempty"`
	K8sPod       string `gorm:"size:253" json:"k8s_pod,omitempty"`
	K8sPodUID    string `gorm:"size:40" json:"k8s_pod_uid,omitempty"`
	K8sContainer string `gorm:"size:63" json:"k8s_container,omitempty"`
	K8sImage     string `gorm:"size:255" json:"k8s_image,omitempty"`
	K8sNode      string `gorm:"size:253" json:"k8s_node,omitempty"`
}

// TableName 指定表名
func (Session) TableName() string {
	return "sessions"
}
