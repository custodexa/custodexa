package model

import (
	"time"

	"gorm.io/gorm"
)

// ProtocolType 協議類型
type ProtocolType string

const (
	ProtocolSSH ProtocolType = "ssh"
	ProtocolRDP ProtocolType = "rdp"
	ProtocolVNC ProtocolType = "vnc"
	// 資料庫協議（database-protocol）：本地 CLI 子程序代理，文字流走 sshproxy bridge
	ProtocolMySQL    ProtocolType = "mysql"
	ProtocolPostgres ProtocolType = "postgres"
	ProtocolRedis    ProtocolType = "redis"
	// ProtocolMSSQL 取 mssql 而非 sqlserver：Protocol 欄為 size:10，sqlserver 佔 9
	// 字元無餘裕。此值屬本系統自有值域，與外部系統常用的
	// sqlserver 字面值不同——未來若做資產匯入需映射表。
	ProtocolMSSQL ProtocolType = "mssql"
	// K8s 容器 exec（k8s-exec）：kubectl exec 本地 PTY，同走 bridge
	ProtocolK8s ProtocolType = "k8s"
)

// IsDatabase 是否為資料庫 CLI 協議
func (p ProtocolType) IsDatabase() bool {
	return p == ProtocolMySQL || p == ProtocolPostgres || p == ProtocolRedis || p == ProtocolMSSQL
}

// SupportsQueryConsole 是否為查詢主控台支援的協議。
//
// **與 IsDatabase 刻意不同**：redis 是資料庫協議但沒有 SQL 執行單位、
// 沒有結果集、沒有交易態，主控台的整套模型對它不成立。
// 允許資料庫清單、主控台入口與協議閘一律以本判定為準。
func (p ProtocolType) SupportsQueryConsole() bool {
	return p == ProtocolMySQL || p == ProtocolPostgres || p == ProtocolMSSQL
}

// IsTextTerminal 是否為文字終端類協議（SSH、資料庫 CLI 與 K8s exec）：
// 此類會話走 sshproxy bridge，指令審計/錄製/監看/阻斷全沿用
func (p ProtocolType) IsTextTerminal() bool {
	return p == ProtocolSSH || p.IsDatabase() || p == ProtocolK8s
}

// Asset 資產（遠端主機）模型
type Asset struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name        string       `gorm:"not null;size:100;index" json:"name"`
	Protocol    ProtocolType `gorm:"not null;size:10;index" json:"protocol"`
	Host        string       `gorm:"not null;size:255" json:"host"`
	Port        int          `gorm:"not null" json:"port"`
	Description string       `gorm:"size:500" json:"description"`
	Active      bool         `gorm:"default:true;index" json:"active"`

	// 創建者（用於審計與權限控制）
	CreatedBy uint `gorm:"not null;index" json:"created_by"`

	// 認證資訊（加密儲存）
	Username      string `gorm:"size:100" json:"username"`
	PasswordEnc   string `gorm:"type:text" json:"-"` // AES-256-GCM 加密
	PrivateKeyEnc string `gorm:"type:text" json:"-"` // SSH private key (加密)
	HasPassword   bool   `json:"has_password"`       // 是否有密碼
	HasPrivateKey bool   `json:"has_private_key"`    // 是否有私鑰

	// 節點掛載（多歸屬）：資產×節點成員在 asset_nodes 表，
	// 單欄 group_id 已移除。以下為 service 層組裝的非 DB 欄——
	// NodeIDs＝掛載節點 id 集（零節點＝未分組）、NodePaths＝對應全路徑顯示
	NodeIDs   []uint   `gorm:"-" json:"node_ids,omitempty"`
	NodePaths []string `gorm:"-" json:"node_paths,omitempty"`

	// 存取政策段位：open/reason/approval；
	// NULL＝走全域預設政策鍵 access_policy_default。政策掛資產本身，
	// 與分組/節點等組織結構徹底解耦（多歸屬樹化前提）
	AccessPolicy *string `gorm:"type:varchar(20)" json:"access_policy,omitempty"`

	// 標籤
	Tags string `gorm:"size:500" json:"tags"` // 逗號分隔的標籤

	// 連測性：最近一次手動測試結果，''=未測
	LastTestStatus    string     `gorm:"size:20;default:''" json:"last_test_status"`
	LastTestAt        *time.Time `json:"last_test_at,omitempty"`
	LastTestLatencyMS int64      `gorm:"default:0" json:"last_test_latency_ms"`

	// RDP 傳輸安全（僅 protocol=rdp 使用）：
	// RDPSecurity ''＝沿現狀 any（自動協商）/ nla / tls；RDPVerifyCert 預設 false
	//（＝ignore-cert=true，與現狀一致）。strict 檔的修復路徑：調 nla＋開驗證
	RDPSecurity   string `gorm:"size:10" json:"rdp_security,omitempty"`
	RDPVerifyCert bool   `gorm:"default:false" json:"rdp_verify_cert"`

	// DB CLI 目標資料庫（database-protocol；僅 mysql/postgres/redis 使用，空＝連預設庫）
	DBName string `gorm:"size:128" json:"db_name,omitempty"`
	// DB TLS 模式（per-asset 可選）：''＝client 預設(不破壞既有) / disable / require / verify-ca / verify-full
	DBTLSMode string `gorm:"size:20" json:"db_tls_mode,omitempty"`
	DBCACert  string `gorm:"type:text" json:"db_ca_cert,omitempty"` // verify-ca/verify-full 用 CA（PEM，選填）

	// AllowedDatabases 查詢主控台的執行目標限制（僅 mysql/postgres/mssql 可非空）。
	//
	// 空清單＝不限制。非空時主控台只列本清單與目標端可見清單的交集，並在每個
	// 執行單位之前確認當前目標庫落在清單內。
	//
	// **射程只到主控台的執行目標**：它不是資料庫級的存取控制（那由目標端帳號權限
	// 承擔），也不解析 SQL——單位內的 `USE`、跨庫限定名都不在它的辨識範圍；
	// 命令列會話完全不受本欄影響。
	//
	// 協議自上述三者改為其他協議時本欄由伺服端自動清空並留痕：留下不套用的殘值，
	// 會在協議改回時靜默恢復一份沒人記得設過的限制。
	AllowedDatabases StringList `gorm:"type:text;not null;default:'[]'" json:"allowed_databases"`

	// K8s exec 目標（k8s-exec；僅 protocol=k8s 使用，Token 沿用 PasswordEnc）
	// 設計改為「綁 namespace、連線時選 pod」：K8sNamespace 必填；K8sPod/K8sContainer
	// 保留以相容舊 fixed-pod 資料，新設計不再於 service 層強制必填。
	K8sNamespace string `gorm:"size:63" json:"k8s_namespace,omitempty"`
	K8sPod       string `gorm:"size:253" json:"k8s_pod,omitempty"`
	K8sContainer string `gorm:"size:63" json:"k8s_container,omitempty"`
	// control plane TLS：CA 驗證；insecure 預設關閉
	K8sCACert          string `gorm:"type:text" json:"k8s_ca_cert,omitempty"`     // API server CA（PEM，選填）
	K8sInsecureSkipTLS bool   `gorm:"default:false" json:"k8s_insecure_skip_tls"` // 顯式略過 TLS 驗證（預設 false）

	// VNC SFTP 側車（vnc-file-transfer；僅 protocol=vnc 使用）：VNC/RFB 無檔案通道，
	// 檔案傳輸經 guacd 對「同一資產 host」另建 SSH/SFTP 連線。獨立憑證，不與 VNC 密碼混用。
	SftpEnabled     bool   `gorm:"default:false" json:"sftp_enabled"`
	SftpPort        int    `gorm:"default:22" json:"sftp_port,omitempty"`
	SftpUsername    string `gorm:"size:100" json:"sftp_username,omitempty"`
	SftpPasswordEnc string `gorm:"type:text" json:"-"` // AES-256-GCM 加密
	HasSftpPassword bool   `json:"has_sftp_password"`

	// 改密通道側車（windows-account-rotation）：本組欄位描述「改密要怎麼連上這台
	// 機器」，與會話用的協定欄位分開——Windows 主機以 rdp 登記卻要走 WinRM 或
	// PowerShell over SSH 改密，兩者的目標埠、傳輸與指令集都不同。
	//
	// RotationChannel 空字串＝未設定，由 EffectiveRotationChannel() 依協定推導
	//（ssh→posix_ssh，其餘→none）。**推導而非回填**：升級後既有列一律留空，
	// 行為與升級前逐項相同，而管理員之後顯式設定的值不會與推導值混淆。
	RotationChannel string `gorm:"size:16;not null;default:''" json:"rotation_channel"`
	// WinrmScheme http／https（僅 windows_winrm）
	WinrmScheme string `gorm:"size:8" json:"winrm_scheme,omitempty"`
	// WinrmPort 0＝依 scheme 取預設（http 5985／https 5986）
	WinrmPort int `json:"winrm_port,omitempty"`
	// WinrmTLSMode system／ca／insecure（僅 https）
	WinrmTLSMode string `gorm:"size:16" json:"winrm_tls_mode,omitempty"`
	// WinrmCACert ca 模式的信任錨（PEM）。**列表投影不回本欄**（見 HasWinrmCACert）
	WinrmCACert string `gorm:"type:text" json:"winrm_ca_cert,omitempty"`
	// RotationSSHPort windows_ssh 走 SSH 改密的目標埠，0＝22。
	// 協定為 ssh 的資產沿用 Port（同一條 SSH 服務），本欄不參與推導
	RotationSSHPort int `json:"rotation_ssh_port,omitempty"`

	// EffectiveChannel 推導後的有效改密通道；非 DB 欄，讀取端填入。
	// 前端的資產選擇以它為準——把推導邏輯留在前端會讓兩側的預設漂移
	EffectiveChannel string `gorm:"-" json:"effective_rotation_channel,omitempty"`
	// HasWinrmCACert 是否已設定 CA 憑證；非 DB 欄，列表投影以它取代 PEM 本體
	HasWinrmCACert bool `gorm:"-" json:"has_winrm_ca_cert"`

	// TransmissionRisks 傳輸風險項（徽章恆顯示，
	// 判定在後端單一所在、前端純呈現）；非 DB 欄位，列表讀取時由 service 填入
	TransmissionRisks []TransmissionRisk `gorm:"-" json:"transmission_risks,omitempty"`
}

// TransmissionRisk 一項傳輸風險（key 穩定識別、label 供人讀；
// service 層 RiskItem 為本型別的別名——單一定義防漂移）
type TransmissionRisk struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// TableName 指定表名
func (Asset) TableName() string {
	return "assets"
}

// RDP security 欄位合法值
const (
	RDPSecurityNLA = "nla"
	RDPSecurityTLS = "tls"
)

// EffectiveRDPParams 回傳 RDP 最終 guacd 安全參數（security, ignore-cert）。
// proxy 參數注入與傳輸風險判定都必須經此取值——單一事實源，
// 否則清冊與閘門對同一資產給出不同答案。
// 空欄位＝沿現狀：security=any、ignore-cert=true
func (a *Asset) EffectiveRDPParams() (security string, ignoreCert bool) {
	security = a.RDPSecurity
	if security == "" {
		security = "any"
	}
	return security, !a.RDPVerifyCert
}

// 存取政策段位：弱→強 open < reason < approval
const (
	AccessPolicyOpen     = "open"     // 不需申請（現狀行為）
	AccessPolicyReason   = "reason"   // 填理由即過（自動核准，留痕免等）
	AccessPolicyApproval = "approval" // 強制審核（蓋過常設 connect）
)

// AssetGroup 資產節點（分組升級為節點樹）。
// parent_id 自參照、NULL＝根節點；同層名稱唯一由 migration partial 索引保證
// （COALESCE(parent_id,0)+name WHERE deleted_at IS NULL，取代全域名稱唯一）；
// 深度上限與環路檢查在 service 層。政策不掛節點（鐵則）
type AssetGroup struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name        string `gorm:"not null;size:100" json:"name"`
	Description string `gorm:"size:500" json:"description"`
	ParentID    *uint  `gorm:"index" json:"parent_id,omitempty"`
}

// TableName 指定表名
func (AssetGroup) TableName() string {
	return "asset_groups"
}

// AssetNode 資產×節點成員關係（多歸屬）：node_id 即
// asset_groups.id；(asset_id, node_id) 唯一由 migration 索引保證。
// 硬刪語義（掛/摘即增刪列，無軟刪——授權才需留痕），變更審計在 service 層
type AssetNode struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	AssetID   uint      `gorm:"not null;index" json:"asset_id"`
	NodeID    uint      `gorm:"not null;index" json:"node_id"`
}

// TableName 指定表名
func (AssetNode) TableName() string {
	return "asset_nodes"
}

// AssetChange 資產變更記錄
type AssetChange struct {
	Field string      `json:"field"`
	Old   interface{} `json:"old"`
	New   interface{} `json:"new"`
}

// AssetChangeDetails 資產變更詳情
type AssetChangeDetails struct {
	Changes []AssetChange `json:"changes"`

	// AllowedDatabasesCleared 本次更新因協議改離查詢主控台支援的協議，
	// 由伺服端自動清空允許資料庫清單。
	//
	// **與 Changes 內的同名 diff 並存而不重複**：diff 記的是「值從 A 變成 B」，
	// 這一對欄位記的是「這不是管理者送的值，是伺服端替他清的」——
	// 兩者在稽核上是不同的問題，靠 diff 反推清空原因會把使用者的顯式清空
	// 與伺服端的自動清空混為一談
	AllowedDatabasesCleared bool `json:"allowed_databases_cleared,omitempty"`
	// PreviousAllowedDatabaseCount 清空前的項數（僅 AllowedDatabasesCleared 為真時出現）
	PreviousAllowedDatabaseCount int `json:"previous_count,omitempty"`

	// RotationChannelCleared 本次更新因協定改為與改密通道不相容，
	// 由伺服端自動清空通道與其附屬欄位。理由同 AllowedDatabasesCleared：
	// 稽核要分得出「管理者自己關掉的」與「伺服端替他清掉的」
	RotationChannelCleared bool `json:"rotation_channel_cleared,omitempty"`
	// PreviousRotationChannel 清空前的通道值（僅 RotationChannelCleared 為真時出現）
	PreviousRotationChannel string `json:"previous_rotation_channel,omitempty"`
}
