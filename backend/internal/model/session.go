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
	EndReasonRevoked        = "revoked" // 臨時授權提前撤銷收線
	// EndReasonAssetDisabled 資產被停用而收線：
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

	// 連線資訊。
	// ClientIP／StartTime 的複合索引供稽核工作台以來源位址為樞紐時查會話、
	// 以及指令／告警／剪貼簿三表經 session_id 帶出位址的 join 使用；
	// 時間窗 keyset 需要第二鍵，故不是單欄索引
	ClientIP  string     `gorm:"size:50;index:idx_sessions_client_ip_start,priority:1" json:"client_ip"`
	StartTime time.Time  `gorm:"index:idx_sessions_client_ip_start,priority:2" json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Duration  int        `json:"duration"` // 秒數

	// 斷線原因（session-timeout/session-reconciliation）：normal/idle_timeout/
	// max_duration/admin_terminate/user_terminate/backend_restart/orphaned/
	// revoked/block_clear_failed（阻斷後清行失敗的 fail-close 收線，
	// 值定義於 sshproxy.bridge）
	EndReason string `gorm:"size:20;default:normal" json:"end_reason,omitempty"`

	// 錄製資訊
	RecordingPath string `gorm:"size:500" json:"recording_path,omitempty"`
	RecordingSize int64  `json:"recording_size,omitempty"` // bytes
	HasRecording  bool   `gorm:"default:false" json:"has_recording"`
	// RecordingError 錄影失敗原因：非空＝
	// 本會話錄影缺失或不完整，前端據此顯「無錄影」標示；空＝正常
	RecordingError string `gorm:"type:text" json:"recording_error,omitempty"`
	// RecordingStartedAt 錄影本身的時間原點。
	// **不等於 StartTime**：回放的 elapsed=0 是錄製器啟動當下，而 StartTime 是
	// 會話建檔當下。深連結帶的秒數 t 以 StartTime 為基準，正確的回放位置是
	// p = t −（RecordingStartedAt − StartTime）——沒有這一欄就只能直接 seek(t)，
	// 誤差恆等於那個差，方向依協議而異：
	//   文字終端：錄製器在會話建檔「之後」才啟動（認證＋PTY 就緒），差為正，
	//             未校正的落點**偏晚、會跳過目標事件**（危險側，且隨認證耗時放大）；
	//   圖形：guacd 握手在會話建檔「之前」完成，差為負，未校正的落點偏早。
	// NULL＝無錄影或存量資料，此時前端退回未校正值並明示（見 SessionDetail 的降級文案）。
	RecordingStartedAt *time.Time `json:"recording_started_at,omitempty"`

	// 離機儲存（evidence-offsite-storage）：**指標＋顯示用快取兩欄**，
	// 遠端物件的身分與狀態機在 `offsite_objects`（OffsiteObject），不在這裡。
	//
	// OffsiteObjectID 指向帳冊列；NULL＝本會話的錄影尚未（或不會）進入離機佇列。
	// OffsiteStatus 是帳冊 `state` 的快取，值域另含回填掃描的兩個分類
	// （`skipped_missing`／`skipped_expired`——那兩者**不建帳冊列**）與空字串。
	// **所有決策邏輯只讀帳冊**：本欄只供會話列表與詳情頁免 join 顯示，
	// 與帳冊短暫不一致不影響正確性。
	//
	// 兩條 partial index 只存在於 migration DDL（`idx_sessions_offsite_backfill`
	// 的 WHERE 涉及 `has_recording`、`idx_sessions_offsite_retention` 涉及本欄的
	// IS NOT NULL，gorm tag 表達得出但會使本 model 承載離機子系統的查詢面知識；
	// 沿 audit_export_jobs 部分索引只留 DDL 的既有取捨）。
	OffsiteObjectID *uint  `json:"offsite_object_id,omitempty"`
	OffsiteStatus   string `gorm:"size:20;not null;default:''" json:"offsite_status"`

	// 帳號雙快照：連線當下所用的資產帳號 ID 與 username
	// 同時釘住——只存 FK 不足以保證不可否認性（帳號改名／刪除會洗掉歷史語義），
	// 只存 username 又無法回指帳號物件。0／空＝該會話未帶帳號（歷史資料、
	// 零帳號路徑）。沿 k8s 六欄不可變快照先例：寫入後永不隨帳號變動更新。
	AccountID       uint   `gorm:"index" json:"account_id,omitempty"`
	AccountUsername string `gorm:"size:100" json:"account_username,omitempty"`

	// 認證溯源：建立此會話的憑證是經哪個 OIDC provider
	// 認證的，以及當下的 provider 世代。NULL／0＝本地或 LDAP 登入。
	//
	// **定位是溯源快照，不是授權快照**：授權一律 DB 現查。它的用途是
	// 「停用某 provider 時要砍哪些進行中的連線」——**禁止以「查外部身分表反推
	// provider」代替**，混合帳號（同時有本地密碼與外部身分）會被誤標，
	// 導致停用 provider 時連帶砍掉該帳號用本地密碼建立的會話。
	AuthProviderID *uint `gorm:"index" json:"auth_provider_id,omitempty"`
	AuthEpoch      int   `gorm:"not null;default:0" json:"-"`

	// K8s 會話不可變快照：pod 短命且名稱可複用，
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
