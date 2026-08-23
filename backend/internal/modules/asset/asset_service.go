package asset

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/kernel"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

var (
	// ErrAssetNotFound 資產不存在
	ErrAssetNotFound = errors.New("資產不存在")
	// ErrAssetNameExists 資產名稱已存在
	ErrAssetNameExists = errors.New("資產名稱已存在")
	// ErrUsernameRequired SSH/RDP 需要使用者名稱
	ErrUsernameRequired = errors.New("此協議需要使用者名稱")
	// ErrSftpUsernameRequired VNC SFTP 啟用時須提供 SSH 帳號（vnc-file-transfer）
	ErrSftpUsernameRequired = errors.New("啟用 SFTP 檔案傳輸需要目標主機的 SSH 使用者名稱")
	// ErrInvalidRDPSecurity RDP 安全模式白名單
	ErrInvalidRDPSecurity = errors.New("rdp_security 僅允許空值（沿現狀）、nla 或 tls")
	// ErrInvalidAccessPolicy 存取政策段位白名單
	ErrInvalidAccessPolicy = errors.New("access_policy 僅允許空值（跟隨全域預設）、open、reason 或 approval")
	// ErrInvalidDBTLSMode DB TLS 模式白名單：未定義值在 dbproxy 不加任何 TLS 旗標
	// （postgres 落回可降級的 prefer、redis 落回明文），且會騙過傳輸風險判定，必須擋
	ErrInvalidDBTLSMode = errors.New("db_tls_mode 僅允許空值（沿現狀）、disable、require、verify-ca 或 verify-full")
	// ErrInvalidProtocol 無效的協議
	ErrInvalidProtocol = errors.New("無效的協議，僅支援 ssh, rdp, vnc, mysql, postgres, redis, mssql, k8s")
	// ErrMSSQLHostComma mssql 主機含逗號：sqlcmd 的 -S host,port
	// 以逗號分隔埠，host 內含逗號會被解讀成埠。只擋 mssql，不動 localpty.SafeArg
	// 的通用語義（逗號對其餘協議合法）
	ErrMSSQLHostComma = errors.New("mssql 主機不得含逗號（與連線字串的埠分隔語義衝突）")
	// ErrK8sTargetRequired K8s 資產缺目標
	ErrK8sTargetRequired = errors.New("K8s 資產需要 namespace")
)

// 連線測試錯誤碼（ConnectionTestResult.ErrorCode 的粗分類值域，前端徽章沿用）
const (
	ErrorCodeConnectionRefused = "connection_refused"
	ErrorCodeAuthFailed        = "authentication_failed"
	ErrorCodeTimeout           = "timeout"
	ErrorCodeProtocolError     = "protocol_error"
	ErrorCodeUnknown           = "unknown"
	// 以下四支為新增／既有字面量收編
	ErrorCodeConnectionFailed  = "connection_failed"
	ErrorCodeProtocolUnsupport = "protocol_unsupported"
	ErrorCodeExecForbidden     = "exec_forbidden"
	ErrorCodeNamespaceNotFound = "namespace_not_found"
	ErrorCodeTLSFailed         = "tls_failed"
	ErrorCodeNoUsableAccount   = "no_usable_account"
)

// AssetService 資產管理服務
type AssetService struct {
	// crypto 憑證加解密。**ColumnCodec**：
	// 介面上**沒有** Encrypt(plaintext)，故持有者在**建構上**不可能寫出無 AAD 的
	// enc:v 密文——「cutover 後只產 enc:a1」是結構保證而非執行期政策判斷。
	// 建構時注入（三職拆解）：不再於建構期由 env 材料自建 codec、
	// 也不再有 SetCodec 事後覆寫，使無本地 KEK 材料的模式（ui／kms／hsm）可建構
	crypto    crypto.ColumnCodec
	guacdHost string
	guacdPort int
	// hostKeys SSH 直連測試的 host key 驗證（setter 注入避免改建構簽名）
	hostKeys *HostKeyService
	// transmission 傳輸風險徽章判定；nil＝列表不附風險
	transmission *policy.TransmissionPolicyService
	// auditTx 交易內審計落地面（T-2 收口）。
	// **nil 即 fail-close**：`port.WriteInTx` 對 nil sink 回 ErrTxSinkMissing，
	// 使業務交易回滾——「沒接線」與「寫失敗」落在同一格，不會靜默 no-op。
	auditTx port.TxSink
	// authzRevoker 資產刪除時的 authz 級聯撤銷（tx-taking 窄 port）。
	// **nil 即 fail-close**：Delete 拒絕在不撤銷授權的情況下完成
	authzRevoker assetAuthorizationRevoker
	// sessions 資產停用時的收線面。
	// 介面而非直接依賴 SessionService，避免 service 相互耦合（沿 identity.SessionTerminator 形狀）。
	// **nil 即不收線**：測試建構路徑可略，生產組裝一律注入
	sessions SessionTerminator
}

// SessionTerminator 停用資產時強制終斷該資產上全部進行中協議會話。
// 介面而非直接依賴 SessionService，
// 沿 identity.SessionTerminator 的既有形狀
type SessionTerminator interface {
	TerminateByAsset(assetID uint, reason string) (int, error)
}

// assetAuthorizationRevoker 資產刪除時對 authz 表的級聯撤銷。
//
// **消費者側窄介面**：asset 不得 import authz（矩陣 asset→authz ✗），
// 故在此宣告意圖、由組裝根注入 authz 的實作。形狀與
// `assetGroupAuthorizationRevoker` 對稱——節點刪除與資產刪除是同一類問題的兩個粒度。
//
// **誠實邊界**：本介面把整個 `*gorm.DB` 交出去，**編譯器管不到對方寫哪張表**
// （白名單見 `cmd/server/tx_taking_whitelist_test.go`）。
type assetAuthorizationRevoker interface {
	RevokeByAsset(tx *gorm.DB, assetID uint) (revokedAuthorizations, revokedApproverScopes int64, err error)
}

// SetAuthorizationRevoker 注入 authz 級聯撤銷面（main 組裝時）
func (s *AssetService) SetAuthorizationRevoker(r assetAuthorizationRevoker) {
	s.authzRevoker = r
}

// SetSessionTerminator 注入會話收線面（main 組裝時）
func (s *AssetService) SetSessionTerminator(t SessionTerminator) {
	s.sessions = t
}

// SetTransmissionPolicy 注入傳輸政策服務（main 組裝時）
func (s *AssetService) SetTransmissionPolicy(tp *policy.TransmissionPolicyService) {
	s.transmission = tp
}

// SetHostKeyService 注入 host key 服務（main 啟動時）
func (s *AssetService) SetHostKeyService(h *HostKeyService) {
	s.hostKeys = h
}

// NewAssetService 創建資產服務；codec 為必要參數（建構期零 env 依賴）。
// auditTx 為交易內審計落地面——刻意以建構子注入而非 setter，
// 使「忘記接線」在組裝期就看得見，而不是在某條稀有路徑上才回 ErrTxSinkMissing。
func NewAssetService(codec crypto.ColumnCodec, guacdHost string, guacdPort int, auditTx port.TxSink) (*AssetService, error) {
	if codec == nil {
		return nil, fmt.Errorf("初始化資產服務失敗: codec 為必要參數（不得於建構期自 env 材料自建）")
	}
	return &AssetService{
		crypto:    codec,
		guacdHost: guacdHost,
		guacdPort: guacdPort,
		auditTx:   auditTx,
	}, nil
}

// AssetFilter 資產過濾條件
type AssetFilter struct {
	Search   string             // 搜尋關鍵字（名稱、主機）
	Protocol model.ProtocolType // 協議過濾
	Active   *bool              // 啟用狀態過濾
	Page     int                // 頁碼（從 1 開始）
	PageSize int                // 每頁大小

	// 節點過濾：NodeID 非 nil＝僅列掛該節點的資產；
	// IncludeSubtree 含子樹（預設開，顯式 toggle 關）；Ungrouped＝僅列零掛載資產
	NodeID         *uint
	IncludeSubtree bool
	Ungrouped      bool

	// 標籤篩選：整詞比對、多標籤 AND；
	// 僅 admin/auditor 全量分支使用（一般 user 帶參數由 handler 拒 400）
	Tags []string
}

// AssetListResponse 資產列表回應
type AssetListResponse struct {
	Data     []model.Asset `json:"data"`
	Total    int64         `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
}

// CreateAssetRequest 創建資產請求
type CreateAssetRequest struct {
	Name        string             `json:"name" binding:"required"`
	// binding 的 oneof 清單必須與 assetProtocols 逐項對齊（順序無關）——
	// gin 的 binding 在 service 的 validateProtocol 之前先擋，清單漏一項就等於該協議
	// 整條建資產路徑不可用（mssql 曾漏在此處，服務層清單有但 API 回 VALIDATION_BAD_REQUEST）。
	// 由 TestCreateAssetProtocolBindingMatchesTable 釘住兩者一致。
	Protocol    model.ProtocolType `json:"protocol" binding:"required,oneof=ssh rdp vnc mysql postgres redis mssql k8s"`
	Host        string             `json:"host" binding:"required"`
	Port        int                `json:"port" binding:"required,min=1,max=65535"`
	Username    string             `json:"username"`    // VNC 無 username，於 Create 中按協議驗證
	Password    string             `json:"password"`    // 選填
	PrivateKey  string             `json:"private_key"` // 選填（SSH only）
	Description string             `json:"description"`
	Tags        string             `json:"tags"`
	CreatedBy   uint               `json:"-"` // 從 JWT token 取得，不從請求接收
	// CreatedByName 操作者顯示名（同樣自 JWT context 取，不從請求接收）：
	// 建資產時連帶建 default 帳號，該筆帳號審計的 username 欄不該是空白
	CreatedByName string `json:"-"`

	// 掛載節點集（多歸屬）：空＝未分組；節點須存在
	NodeIDs []uint `json:"node_ids"`

	// 存取政策段位：''＝跟隨全域預設（NULL）
	AccessPolicy string `json:"access_policy"`

	// RDP 傳輸安全（僅 protocol=rdp）：
	// ''＝沿現狀 any；驗證白名單擋未定義值
	RDPSecurity   string `json:"rdp_security" binding:"omitempty,oneof=nla tls"`
	RDPVerifyCert bool   `json:"rdp_verify_cert"`

	// DB CLI 目標資料庫（database-protocol；僅 mysql/postgres/redis，空＝連預設庫）
	DBName    string `json:"db_name"`
	DBTLSMode string `json:"db_tls_mode"` // ''/disable/require/verify-ca
	DBCACert  string `json:"db_ca_cert"`  // verify-ca 用 CA（PEM，選填）

	// K8s exec 目標（k8s-exec；僅 protocol=k8s，Token 走 Password 欄加密儲存）
	// 連線時選 pod：namespace 必填，pod/container 選填（保留以相容舊資料）
	K8sNamespace       string `json:"k8s_namespace"`
	K8sPod             string `json:"k8s_pod"`
	K8sContainer       string `json:"k8s_container"`
	K8sCACert          string `json:"k8s_ca_cert"`
	K8sInsecureSkipTLS bool   `json:"k8s_insecure_skip_tls"`

	// VNC SFTP 側車（vnc-file-transfer；僅 protocol=vnc）
	SftpEnabled  bool   `json:"sftp_enabled"`
	SftpPort     int    `json:"sftp_port"`
	SftpUsername string `json:"sftp_username"`
	SftpPassword string `json:"sftp_password"` // 選填；僅後端加密存放
}

// UpdateAssetRequest 更新資產請求
type UpdateAssetRequest struct {
	Name        *string             `json:"name"`
	Protocol    *model.ProtocolType `json:"protocol"`
	Host        *string             `json:"host"`
	Port        *int                `json:"port"`
	Username    *string             `json:"username"`
	Password    *string             `json:"password"` // 如果為空字串則不更新
	PrivateKey  *string             `json:"private_key"`
	Description *string             `json:"description"`
	Tags        *string             `json:"tags"`
	Active      *bool               `json:"active"`

	// 掛載節點集：nil＝不動、空陣列＝清空全部掛載（未分組）
	NodeIDs *[]uint `json:"node_ids"`

	// 存取政策段位：nil＝不動、''＝清回跟隨全域（NULL）。
	// 白名單在 service 驗（指標欄位 omitempty 不放行顯式空字串）
	AccessPolicy *string `json:"access_policy"`

	// RDP 傳輸安全：顯式 ''＝重設回沿現狀。
	// 不用 binding oneof——指標欄位的 omitempty 不放行顯式空字串，白名單在 service 驗
	RDPSecurity   *string `json:"rdp_security"`
	RDPVerifyCert *bool   `json:"rdp_verify_cert"`

	// DB CLI 目標資料庫（database-protocol）
	DBName    *string `json:"db_name"`
	DBTLSMode *string `json:"db_tls_mode"`
	DBCACert  *string `json:"db_ca_cert"`

	// K8s exec 目標（k8s-exec）
	K8sNamespace       *string `json:"k8s_namespace"`
	K8sPod             *string `json:"k8s_pod"`
	K8sContainer       *string `json:"k8s_container"`
	K8sCACert          *string `json:"k8s_ca_cert"`
	K8sInsecureSkipTLS *bool   `json:"k8s_insecure_skip_tls"`

	// VNC SFTP 側車（vnc-file-transfer）：SftpPassword 空字串＝沿用既有（比照 Password）
	SftpEnabled  *bool   `json:"sftp_enabled"`
	SftpPort     *int    `json:"sftp_port"`
	SftpUsername *string `json:"sftp_username"`
	SftpPassword *string `json:"sftp_password"`
}

// validateRDPSecurity RDP 安全模式白名單：
// 空值＝沿現狀 any；service 層驗證使繞 HTTP binding 的內部呼叫同受約束
func validateRDPSecurity(v string) error {
	switch v {
	case "", model.RDPSecurityNLA, model.RDPSecurityTLS:
		return nil
	default:
		return ErrInvalidRDPSecurity
	}
}

// validateAccessPolicy 存取政策段位白名單：
// 空值＝清為 NULL（跟隨全域預設鍵）；service 層驗證使內部呼叫同受約束
func validateAccessPolicy(v string) error {
	switch v {
	case "", model.AccessPolicyOpen, model.AccessPolicyReason, model.AccessPolicyApproval:
		return nil
	default:
		return ErrInvalidAccessPolicy
	}
}

// validateDBTLSMode DB TLS 模式白名單，值集合與 dbproxy/command.go 的檔位
// switch 一致；大小寫、前後空白一律不寬容——寬容會讓判定與 dbproxy 行為分岔
func validateDBTLSMode(v string) error {
	switch v {
	case "", "disable", "require", "verify-ca", "verify-full":
		return nil
	default:
		return ErrInvalidDBTLSMode
	}
}

// validateMSSQLHost mssql 資產主機欄的協議專屬驗證。非 mssql 一律放行。
func validateMSSQLHost(protocol model.ProtocolType, host string) error {
	if protocol == model.ProtocolMSSQL && strings.Contains(host, ",") {
		return ErrMSSQLHostComma
	}
	return nil
}

// Create 創建資產
func (s *AssetService) Create(req *CreateAssetRequest) (*model.Asset, error) {
	// ctx 僅供 codec 的取消／逾時語義（同 GetWithCredentialsForAccount 註解）：
	// AAD 綁 (table, column) 不綁 pk，故 create 路徑無須「先 insert 取得 pk 再回寫密文」
	// 的兩階段寫入——這正是 AAD 綁欄位而非綁主鍵的主要收益
	ctx := context.Background()
	// 驗證協議
	if err := s.validateProtocol(req.Protocol); err != nil {
		return nil, err
	}
	if err := validateRDPSecurity(req.RDPSecurity); err != nil {
		return nil, err
	}
	if err := validateDBTLSMode(req.DBTLSMode); err != nil {
		return nil, err
	}
	if err := validateMSSQLHost(req.Protocol, req.Host); err != nil {
		return nil, err
	}
	if err := validateAccessPolicy(req.AccessPolicy); err != nil {
		return nil, err
	}
	nodeIDs := kernel.DedupeUint(req.NodeIDs)

	// SSH/RDP/MySQL/Postgres 需要 username；VNC/Redis/K8s 僅密碼（Token）認證
	if req.Protocol != model.ProtocolVNC && req.Protocol != model.ProtocolRedis &&
		req.Protocol != model.ProtocolK8s && req.Username == "" {
		return nil, ErrUsernameRequired
	}

	// K8s 綁 namespace（連線時選 pod，故 pod/container 不在此強制）
	if req.Protocol == model.ProtocolK8s && req.K8sNamespace == "" {
		return nil, ErrK8sTargetRequired
	}

	// 檢查名稱是否重複
	var existing model.Asset
	result := database.DB.Where("name = ?", req.Name).First(&existing)
	if result.Error == nil {
		return nil, ErrAssetNameExists
	}

	// 標籤正規化：trim/去空/canonical 去重/
	// 歸一至既有書寫形＋文法驗證
	normalizedTags, err := s.NormalizeTagsForWrite(req.Tags)
	if err != nil {
		return nil, err
	}

	// 創建資產
	asset := &model.Asset{
		Name:               req.Name,
		Protocol:           req.Protocol,
		Host:               req.Host,
		Port:               req.Port,
		Username:           req.Username,
		Description:        req.Description,
		Tags:               normalizedTags,
		Active:             true,
		AccessPolicy:       normalizeAccessPolicy(req.AccessPolicy),
		CreatedBy:          req.CreatedBy,
		RDPSecurity:        req.RDPSecurity,
		RDPVerifyCert:      req.RDPVerifyCert,
		DBName:             req.DBName,
		DBTLSMode:          req.DBTLSMode,
		DBCACert:           req.DBCACert,
		K8sNamespace:       req.K8sNamespace,
		K8sPod:             req.K8sPod,
		K8sContainer:       req.K8sContainer,
		K8sCACert:          req.K8sCACert,
		K8sInsecureSkipTLS: req.K8sInsecureSkipTLS,
	}

	// 憑證加密：密文只落 asset_accounts 的
	// default 帳號，assets 內嵌憑證欄位自本階段起凍結不再寫入（單向切換）。
	// assets 上仍維護 HasPassword/HasPrivateKey 顯示旗標——它們不是憑證本體，
	// 而是列表與表單的「已設定憑證」標記，不同步會讓既有畫面說謊。
	var passwordEnc, privateKeyEnc string
	if req.Password != "" {
		encryptedPassword, err := s.crypto.EncryptFor(ctx, keyvault.RefAccountPassword, req.Password)
		if err != nil {
			return nil, fmt.Errorf("加密密碼失敗: %w", err)
		}
		passwordEnc = encryptedPassword
		asset.HasPassword = true
	}

	// 加密私鑰（SSH only）
	if req.PrivateKey != "" && req.Protocol == model.ProtocolSSH {
		encryptedKey, err := s.crypto.EncryptFor(ctx, keyvault.RefAccountPrivateKey, req.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("加密私鑰失敗: %w", err)
		}
		privateKeyEnc = encryptedKey
		asset.HasPrivateKey = true
	}

	// VNC SFTP 側車（vnc-file-transfer；僅 protocol=vnc 生效）
	if req.Protocol == model.ProtocolVNC && req.SftpEnabled {
		if req.SftpUsername == "" {
			return nil, ErrSftpUsernameRequired
		}
		asset.SftpEnabled = true
		asset.SftpUsername = req.SftpUsername
		asset.SftpPort = req.SftpPort
		if asset.SftpPort <= 0 || asset.SftpPort > 65535 {
			asset.SftpPort = 22
		}
		if req.SftpPassword != "" {
			enc, err := s.crypto.EncryptFor(ctx, keyvault.RefAssetsSftpPassword, req.SftpPassword)
			if err != nil {
				return nil, fmt.Errorf("加密 SFTP 密碼失敗: %w", err)
			}
			asset.SftpPasswordEnc = enc
			asset.HasSftpPassword = true
		}
	}

	// 儲存到資料庫（節點掛載同交易——建資產與掛節點不可分離；
	// 新資產必無舊成員，僅 insert 不清除）。節點驗證移入交易＋treeStructMu
	// 互斥（驗證後節點被並發刪除會留下懸掛成員，無 FK 兜底）
	treeStructMu.Lock()
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		if err := validateNodeIDsTx(tx, nodeIDs); err != nil {
			return err
		}
		if err := tx.Create(asset).Error; err != nil {
			return fmt.Errorf("創建資產失敗: %w", err)
		}
		// 建立表單的單帳號快速欄位透明成為 default 帳號：與資產同交易——
		// 建了資產卻沒建帳號，該資產自階段 2 起即為「無身分可連」的死資產。
		// 建帳判準與階段 1 migration 一致：username／密碼／私鑰三者全空才算
		// 零帳號資產（靠 SSH agent 等免密路徑者仍需帳號承載 username）
		if asset.Username != "" || passwordEnc != "" || privateKeyEnc != "" {
			account := &model.AssetAccount{
				AssetID:       asset.ID,
				Username:      asset.Username,
				PasswordEnc:   passwordEnc,
				PrivateKeyEnc: privateKeyEnc,
				IsDefault:     true,
			}
			if err := tx.Create(account).Error; err != nil {
				return fmt.Errorf("建立預設帳號失敗: %w", err)
			}
			if err := writeAssetAccountAudit(s.auditTx, tx, model.AssetAccountAudit{
				AssetID:   asset.ID,
				AccountID: account.ID,
				Username:  account.Username,
				Operation: model.AccountOpCreate,
				Fields:    changedSecretFields(passwordEnc != "", privateKeyEnc != "", true),
			}, req.CreatedBy, req.CreatedByName); err != nil {
				return fmt.Errorf("記錄預設帳號建立審計失敗: %w", err)
			}
		}
		for _, nodeID := range nodeIDs {
			if err := tx.Create(&model.AssetNode{AssetID: asset.ID, NodeID: nodeID}).Error; err != nil {
				return fmt.Errorf("掛載節點失敗: %w", err)
			}
		}
		// 初始掛載留痕（AfterCreate hook 只記建立事件無 node_ids 明細）
		if len(nodeIDs) > 0 && req.CreatedBy != 0 {
			if err := writeAssetNodeChangeAudit(s.auditTx, tx, asset.ID, nil, nodeIDs, req.CreatedBy, ""); err != nil {
				log.Printf("記錄初始節點掛載失敗: %v", err)
			}
		}
		return nil
	})
	treeStructMu.Unlock()
	if err != nil {
		return nil, err
	}
	asset.NodeIDs = nodeIDs

	return asset, nil
}

// List 列出資產（支援分頁與過濾）
func (s *AssetService) List(filter *AssetFilter) (*AssetListResponse, error) {
	query := database.DB.Model(&model.Asset{})

	// 搜尋過濾
	if filter.Search != "" {
		searchPattern := "%" + strings.ToLower(filter.Search) + "%"
		query = query.Where("LOWER(name) LIKE ? OR LOWER(host) LIKE ?", searchPattern, searchPattern)
	}

	// 協議過濾
	if filter.Protocol != "" {
		query = query.Where("protocol = ?", filter.Protocol)
	}

	// 啟用狀態過濾
	if filter.Active != nil {
		query = query.Where("active = ?", *filter.Active)
	}

	// 標籤篩選：補逗號整詞比對＋萬用字元跳脫，
	// 多標籤疊 AND；與其餘條件同 query，COUNT 與分頁前生效
	for _, tag := range filter.Tags {
		query = query.Where(tagWholeWordCondition, tagWholeWordPattern(tag))
	}

	// 節點過濾：含子樹＝節點自身＋全部後代的掛載聯集
	if filter.Ungrouped {
		query = query.Where("NOT EXISTS (SELECT 1 FROM asset_nodes an WHERE an.asset_id = assets.id)")
	} else if filter.NodeID != nil {
		if filter.IncludeSubtree {
			query = query.Where(`id IN (SELECT an.asset_id FROM asset_nodes an WHERE an.node_id IN (
				WITH RECURSIVE sub(id) AS (
					SELECT id FROM asset_groups WHERE id = ? AND deleted_at IS NULL
					UNION
					SELECT g.id FROM asset_groups g JOIN sub ON g.parent_id = sub.id
					WHERE g.deleted_at IS NULL
				) SELECT id FROM sub
			))`, *filter.NodeID)
		} else {
			query = query.Where("id IN (SELECT an.asset_id FROM asset_nodes an WHERE an.node_id = ?)", *filter.NodeID)
		}
	}

	// 計算總數
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("查詢資產總數失敗: %w", err)
	}

	// 分頁
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// 查詢資料
	var assets []model.Asset
	if err := query.
		Order("created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&assets).Error; err != nil {
		return nil, fmt.Errorf("查詢資產列表失敗: %w", err)
	}

	// 節點掛載資訊：批次填 NodeIDs 與全路徑
	if err := FillNodeInfo(database.DB, assets); err != nil {
		return nil, err
	}

	// 傳輸風險徽章：不分政策等級恆填——
	// 政策管「攔不攔」，徽章管「看不看得見」；未注入（既有測試路徑）不填
	if s.transmission != nil {
		for i := range assets {
			assets[i].TransmissionRisks = s.transmission.AssetRisks(&assets[i])
		}
	}

	return &AssetListResponse{
		Data:     assets,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// UpdatePassword 更新**指定帳號**的密碼憑證（change-secret；記憶體內加密，明文不落日誌）。
//
// 簽名帶 accountID 是硬性要求：改密 runner 必須在執行開頭釘住帳號、
// 讀憑證與寫回全程作用於同一 AccountID。若此處仍以 assetID 重解析 default，
// 執行期間管理員切換 default 就會把新密寫進另一個帳號（遠端已改密的那台反而
// 留著舊密＝鎖死，另一台的憑證則被無聲覆蓋）。
//
// **驗證與寫入同一交易，且以 RowsAffected 判成敗**：舊寫法在交易外
// 驗完帳號才進交易寫，中間帳號被軟刪時 UPDATE 影響零列卻回 nil——runner 會據此
// 記 success，但遠端密碼已經改掉、庫內沒有任何地方存著新密＝該機器永久鎖死且
// 審計說一切正常。零列一律回錯，runner 走既有「憑證提交失敗，需人工介入」路徑。
//
// pinnedUsername 為 runner 開頭釘住的 username：帳號在執行期間被改名時，該列
// 已代表另一個系統身分，把新密寫進去等於改錯對象。以 WHERE 條件
// 帶入，改名即零列＝失敗，同樣走人工介入路徑。
//
// accountID 必須為該資產的有效帳號（fail-close）；零帳號資產無處可寫，回錯。
func (s *AssetService) UpdatePassword(assetID, accountID uint, pinnedUsername, newPassword string) error {
	if accountID == 0 {
		return ErrAssetAccountNotFound
	}
	encrypted, err := s.crypto.EncryptFor(context.Background(), keyvault.RefAccountPassword, newPassword)
	if err != nil {
		return fmt.Errorf("加密密碼失敗: %w", err)
	}
	return database.DB.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, assetID); err != nil {
			return err
		}
		// 交易內重讀（軟刪 scope 由 GORM 自動套用），取得 IsDefault 與現況 username
		account, err := resolveAssetAccount(tx, assetID, accountID)
		if err != nil {
			return err
		}
		if account == nil || account.Username != pinnedUsername {
			return ErrAssetAccountNotFound
		}
		res := tx.Model(&model.AssetAccount{}).
			Where("id = ? AND asset_id = ? AND username = ?", account.ID, assetID, pinnedUsername).
			Update("password_enc", encrypted)
		if res.Error != nil {
			return fmt.Errorf("更新帳號密碼失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			// 零列＝帳號於本交易內被移除或改名；絕不記成功審計
			return ErrAssetAccountNotFound
		}
		if account.IsDefault {
			account.PasswordEnc = encrypted
			if err := mirrorDefaultAccountToAsset(tx, account); err != nil {
				return err
			}
		}
		return writeAssetAccountAudit(s.auditTx, tx, model.AssetAccountAudit{
			AssetID:   assetID,
			AccountID: account.ID,
			Username:  account.Username,
			Operation: model.AccountOpUpdate,
			Fields:    []string{"password"},
		}, 0, "system")
	})
}

// UpdatePrivateKey 系統路徑更新帳號私鑰（金鑰輪替）。
//
// 不變式與 UpdatePassword 逐條相同：釘住的 accountID ＋ pinnedUsername 為 WHERE
// 條件（執行期間改名即零列＝失敗，不改錯對象）、驗證與寫入同一交易、RowsAffected
// 零列一律回錯（遠端已換鑰而庫內沒存新私鑰＝該機器鎖死，絕不記成功）。
//
// 只動 private_key_enc：帳號的密碼欄位不在金鑰輪替的範圍內，清掉它會讓原本
// 密碼可登入的帳號在金鑰失效時失去唯一的備援入口。
func (s *AssetService) UpdatePrivateKey(assetID, accountID uint, pinnedUsername, newPrivateKey string) error {
	if accountID == 0 {
		return ErrAssetAccountNotFound
	}
	encrypted, err := s.crypto.EncryptFor(context.Background(), keyvault.RefAccountPrivateKey, newPrivateKey)
	if err != nil {
		return fmt.Errorf("加密私鑰失敗: %w", err)
	}
	return database.DB.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, assetID); err != nil {
			return err
		}
		account, err := resolveAssetAccount(tx, assetID, accountID)
		if err != nil {
			return err
		}
		if account == nil || account.Username != pinnedUsername {
			return ErrAssetAccountNotFound
		}
		res := tx.Model(&model.AssetAccount{}).
			Where("id = ? AND asset_id = ? AND username = ?", account.ID, assetID, pinnedUsername).
			Update("private_key_enc", encrypted)
		if res.Error != nil {
			return fmt.Errorf("更新帳號私鑰失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrAssetAccountNotFound
		}
		if account.IsDefault {
			account.PrivateKeyEnc = encrypted
			if err := mirrorDefaultAccountToAsset(tx, account); err != nil {
				return err
			}
		}
		return writeAssetAccountAudit(s.auditTx, tx, model.AssetAccountAudit{
			AssetID:   assetID,
			AccountID: account.ID,
			Username:  account.Username,
			Operation: model.AccountOpUpdate,
			Fields:    []string{"private_key"},
		}, 0, "system")
	})
}

// GetByID 根據 ID 取得資產

func (s *AssetService) GetByID(id uint) (*model.Asset, error) {
	var asset model.Asset
	result := database.DB.First(&asset, id)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrAssetNotFound
		}
		return nil, result.Error
	}

	single := []model.Asset{asset}
	if err := FillNodeInfo(database.DB, single); err != nil {
		return nil, err
	}

	return &single[0], nil
}

// GetWithCredentialsForAccount 取得資產與**指定帳號**的 username／解密憑證（用於連線）。
//
// accountID = 0 代表預設帳號（系統路徑與未指定帳號的連線）。找不到帳號、帳號已軟刪、
// 或帳號屬於別的資產一律回 ErrAssetAccountNotFound——**不靜默退回預設帳號**
// （fail-close：靜默退回會讓跨資產 account id 注入拿到目標資產的預設憑證）。
//
// 階段 2 起 username 與憑證皆自帳號取得（兩者必須同帳號），Asset 內嵌憑證
// 欄位不再被讀取。零帳號資產（原本即無 username 與憑證者）回空憑證束，合法。
func (s *AssetService) GetWithCredentialsForAccount(assetID, accountID uint) (*AssetCredentials, error) {
	// ctx 僅供 codec 的取消／逾時語義：AAD 綁定維度為 (table, column)（不綁自增主鍵），
	// 不需由 ctx 攜帶列身分，故此處不為加密而擾動 13 個呼叫端簽名。
	// 日後若要傳遞 request context，逐函式加參數即可，AAD 語義不受影響
	ctx := context.Background()
	asset, err := s.GetByID(assetID)
	if err != nil {
		return nil, err
	}
	account, err := resolveAssetAccount(database.DB, assetID, accountID)
	if err != nil {
		return nil, err
	}
	creds := &AssetCredentials{Asset: asset}
	if account == nil {
		return creds, nil
	}
	creds.AccountID = account.ID
	creds.Username = account.Username

	if account.PasswordEnc != "" {
		creds.Password, err = s.crypto.DecryptFor(ctx, keyvault.RefAccountPassword, account.PasswordEnc)
		if err != nil {
			return nil, fmt.Errorf("解密密碼失敗: %w", err)
		}
	}
	if account.PrivateKeyEnc != "" {
		creds.PrivateKey, err = s.crypto.DecryptFor(ctx, keyvault.RefAccountPrivateKey, account.PrivateKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("解密私鑰失敗: %w", err)
		}
	}
	return creds, nil
}

// GetWithCredentialsDefault 取資產的預設帳號憑證（系統路徑：改密 runner、
// k8s、SFTP 側車、連測；連線鏈於階段 3 帶入 account 前亦暫走此路徑）
func (s *AssetService) GetWithCredentialsDefault(assetID uint) (*AssetCredentials, error) {
	return s.GetWithCredentialsForAccount(assetID, 0)
}

// ListK8sPods 列 K8s 資產 namespace 內的活 pod（連線時選 pod 用）。
// 走 in-memory client（免落檔）；錯誤已分類為五類人話（*k8sproxy.K8sError）。
// K8s 固定單一 default account：不帶 account 參數，語義維持不變。
func (s *AssetService) ListK8sPods(ctx context.Context, id uint) ([]k8sproxy.PodInfo, error) {
	creds, err := s.GetWithCredentialsDefault(id)
	if err != nil {
		return nil, err
	}
	asset, token := creds.Asset, creds.Password
	if asset.Protocol != model.ProtocolK8s {
		return nil, ErrInvalidProtocol
	}
	// 零帳號＝空 token：kubernetes client 會以匿名身分打叢集
	if creds.AccountID == 0 || token == "" {
		return nil, ErrAssetNoUsableAccount
	}
	target := k8sproxy.Target{
		Server:    fmt.Sprintf("https://%s:%d", asset.Host, asset.Port),
		Token:     token,
		Namespace: asset.K8sNamespace,
		CACert:    asset.K8sCACert,
		Insecure:  asset.K8sInsecureSkipTLS,
	}
	return k8sproxy.ListPods(ctx, target)
}

// k8sTarget 組 K8s 資產的連線目標（含選定 pod/container）。
// 同 ListK8sPods：k8s 固定 default account。
func (s *AssetService) k8sTarget(id uint, pod, container string) (k8sproxy.Target, error) {
	creds, err := s.GetWithCredentialsDefault(id)
	if err != nil {
		return k8sproxy.Target{}, err
	}
	asset, token := creds.Asset, creds.Password
	if asset.Protocol != model.ProtocolK8s {
		return k8sproxy.Target{}, ErrInvalidProtocol
	}
	// 同 ListK8sPods：空 token 一律拒，不以匿名身分做 exec／kubectl cp
	if creds.AccountID == 0 || token == "" {
		return k8sproxy.Target{}, ErrAssetNoUsableAccount
	}
	return k8sproxy.Target{
		Server:    fmt.Sprintf("https://%s:%d", asset.Host, asset.Port),
		Token:     token,
		Namespace: asset.K8sNamespace,
		Pod:       pod,
		Container: container,
		CACert:    asset.K8sCACert,
		Insecure:  asset.K8sInsecureSkipTLS,
	}, nil
}

// K8sCopyToPod 上傳本地檔到 K8s 資產的指定 pod/container（kubectl cp）
func (s *AssetService) K8sCopyToPod(ctx context.Context, id uint, pod, container, destPath, localPath string) error {
	target, err := s.k8sTarget(id, pod, container)
	if err != nil {
		return err
	}
	return k8sproxy.CopyToPod(ctx, target, localPath, destPath)
}

// K8sCopyFromPod 從 K8s 資產的指定 pod/container 下載檔到本地（kubectl cp）
func (s *AssetService) K8sCopyFromPod(ctx context.Context, id uint, pod, container, srcPath, localPath string) error {
	target, err := s.k8sTarget(id, pod, container)
	if err != nil {
		return err
	}
	return k8sproxy.CopyFromPod(ctx, target, srcPath, localPath)
}

// GetSftpPassword 解密 VNC SFTP 側車密碼（vnc-file-transfer；僅後端記憶體內使用）
func (s *AssetService) GetSftpPassword(asset *model.Asset) (string, error) {
	if asset == nil || !asset.SftpEnabled || asset.SftpPasswordEnc == "" {
		return "", nil
	}
	pwd, err := s.crypto.DecryptFor(context.Background(), keyvault.RefAssetsSftpPassword, asset.SftpPasswordEnc)
	if err != nil {
		return "", fmt.Errorf("解密 SFTP 密碼失敗: %w", err)
	}
	return pwd, nil
}

// Update 更新資產
func (s *AssetService) Update(ctx context.Context, id uint, req *UpdateAssetRequest) (*model.Asset, error) {
	// 查詢原始資產（用於 diff）
	oldAsset, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}

	// 複製一份用於比較
	asset := &model.Asset{}
	*asset = *oldAsset

	// 更新欄位
	if req.Name != nil {
		// 檢查名稱是否重複（排除自己）
		var existing model.Asset
		result := database.DB.Where("name = ? AND id != ?", *req.Name, id).First(&existing)
		if result.Error == nil {
			return nil, ErrAssetNameExists
		}
		asset.Name = *req.Name
	}

	if req.Protocol != nil {
		if err := s.validateProtocol(*req.Protocol); err != nil {
			return nil, err
		}
		asset.Protocol = *req.Protocol
	}

	if req.Host != nil {
		asset.Host = *req.Host
	}

	// 協議與主機皆可能在本次更新中變動，故以套用後的最終值驗證，
	// 而非各自在自己的分支內驗（只改協議或只改主機都可能造出違規組合）
	if err := validateMSSQLHost(asset.Protocol, asset.Host); err != nil {
		return nil, err
	}

	if req.Port != nil {
		asset.Port = *req.Port
	}

	if req.Username != nil {
		asset.Username = *req.Username
	}

	// 憑證欄位透明轉寫 default 帳號：舊前端／腳本仍打 PUT /assets/:id 帶
	// password/private_key，語義不變，但密文只落帳號表，assets 內嵌憑證欄位凍結。
	var passwordEnc, privateKeyEnc string
	if req.Password != nil && *req.Password != "" {
		encryptedPassword, err := s.crypto.EncryptFor(ctx, keyvault.RefAccountPassword, *req.Password)
		if err != nil {
			return nil, fmt.Errorf("加密密碼失敗: %w", err)
		}
		passwordEnc = encryptedPassword
		asset.HasPassword = true
	}

	if req.PrivateKey != nil && *req.PrivateKey != "" {
		encryptedKey, err := s.crypto.EncryptFor(ctx, keyvault.RefAccountPrivateKey, *req.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("加密私鑰失敗: %w", err)
		}
		privateKeyEnc = encryptedKey
		asset.HasPrivateKey = true
	}

	if req.Description != nil {
		asset.Description = *req.Description
	}

	if req.Tags != nil {
		normalizedTags, err := s.NormalizeTagsForWrite(*req.Tags)
		if err != nil {
			return nil, err
		}
		asset.Tags = normalizedTags
	}

	if req.Active != nil {
		asset.Active = *req.Active
	}

	// 掛載節點集：nil＝不動；驗證/差集同步/成員審計
	// 皆在下方交易內（treeStructMu 互斥消除驗證後節點被刪窗口）
	var newNodeIDs []uint
	if req.NodeIDs != nil {
		newNodeIDs = kernel.DedupeUint(*req.NodeIDs)
	}

	if req.AccessPolicy != nil {
		if err := validateAccessPolicy(*req.AccessPolicy); err != nil {
			return nil, err
		}
		asset.AccessPolicy = normalizeAccessPolicy(*req.AccessPolicy)
	}

	if req.RDPSecurity != nil {
		if err := validateRDPSecurity(*req.RDPSecurity); err != nil {
			return nil, err
		}
		asset.RDPSecurity = *req.RDPSecurity
	}
	if req.RDPVerifyCert != nil {
		asset.RDPVerifyCert = *req.RDPVerifyCert
	}

	if req.DBName != nil {
		asset.DBName = *req.DBName
	}
	if req.DBTLSMode != nil {
		if err := validateDBTLSMode(*req.DBTLSMode); err != nil {
			return nil, err
		}
		asset.DBTLSMode = *req.DBTLSMode
	}
	if req.DBCACert != nil {
		asset.DBCACert = *req.DBCACert
	}

	if req.K8sNamespace != nil {
		asset.K8sNamespace = *req.K8sNamespace
	}
	if req.K8sPod != nil {
		asset.K8sPod = *req.K8sPod
	}
	if req.K8sContainer != nil {
		asset.K8sContainer = *req.K8sContainer
	}
	if req.K8sCACert != nil {
		asset.K8sCACert = *req.K8sCACert
	}
	if req.K8sInsecureSkipTLS != nil {
		asset.K8sInsecureSkipTLS = *req.K8sInsecureSkipTLS
	}

	// VNC SFTP 側車（vnc-file-transfer）：密碼空值＝沿用既有，不靜默清空
	if req.SftpEnabled != nil {
		asset.SftpEnabled = *req.SftpEnabled
	}
	if req.SftpUsername != nil {
		asset.SftpUsername = *req.SftpUsername
	}
	if req.SftpPort != nil && *req.SftpPort > 0 && *req.SftpPort <= 65535 {
		asset.SftpPort = *req.SftpPort
	}
	if req.SftpPassword != nil && *req.SftpPassword != "" {
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefAssetsSftpPassword, *req.SftpPassword)
		if err != nil {
			return nil, fmt.Errorf("加密 SFTP 密碼失敗: %w", err)
		}
		asset.SftpPasswordEnc = enc
		asset.HasSftpPassword = true
	}
	if asset.SftpEnabled && asset.Protocol == model.ProtocolVNC && asset.SftpUsername == "" {
		return nil, ErrSftpUsernameRequired
	}

	// 提取用戶資訊並儲存到 context（供 GORM Hooks 使用）
	userID, _ := ctx.Value("userID").(uint)
	username, _ := ctx.Value("username").(string)

	// 使用事務來記錄變更（涉節點掛載時以 treeStructMu 與樹結構變更互斥）
	if req.NodeIDs != nil {
		treeStructMu.Lock()
		defer treeStructMu.Unlock()
	}
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		// 在 context 中傳遞用戶資訊
		txCtx := context.WithValue(ctx, "userID", userID)
		txCtx = context.WithValue(txCtx, "username", username)

		// 儲存到資料庫（會觸發 AfterUpdate Hook）
		if err := tx.WithContext(txCtx).Save(asset).Error; err != nil {
			return fmt.Errorf("更新資產失敗: %w", err)
		}

		// 憑證／username 透明轉寫 default 帳號，與資產更新同交易
		if req.Username != nil || passwordEnc != "" || privateKeyEnc != "" {
			if err := syncDefaultAccountFromAsset(s.auditTx, tx, asset, passwordEnc, privateKeyEnc, userID, username); err != nil {
				return err
			}
		}

		// 節點掛載同步：M2M 不經 hook diff，
		// 成員變更在此顯式審計（node_ids 舊→新）；驗證在交易內
		if req.NodeIDs != nil {
			if err := validateNodeIDsTx(tx, newNodeIDs); err != nil {
				return err
			}
			oldNodeIDs, err := assetNodeIDs(tx, asset.ID)
			if err != nil {
				return err
			}
			if err := replaceAssetNodes(tx, asset.ID, newNodeIDs); err != nil {
				return err
			}
			if userID != 0 && !uintSetEqual(oldNodeIDs, newNodeIDs) {
				if err := writeAssetNodeChangeAudit(s.auditTx, tx, asset.ID, oldNodeIDs, newNodeIDs, userID, username); err != nil {
					log.Printf("記錄節點掛載變更失敗: %v", err)
				}
			}
		}

		// 記錄詳細變更（使用 diffAsset）
		if userID != 0 {
			if err := writeAssetChangeAudit(s.auditTx, tx, oldAsset, asset, userID, username, model.ActionUpdate); err != nil {
				log.Printf("記錄資產變更失敗: %v", err)
				// 不中斷事務，只記錄錯誤
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// 停用即收線：只在 true→false 的**躍遷**觸發。
	// 對已停用資產的其他編輯不重複收線——否則審計上會出現一連串「因停用而斷線」
	// 而其實沒有停用動作發生。收線失敗**不回滾停用**（停用的主要目標是阻斷後續
	// 存取，收線是縱深；沿 access_request_service 撤銷收線的既有裁決）
	if oldAsset.Active && !asset.Active && s.sessions != nil {
		if n, terr := s.sessions.TerminateByAsset(id, model.EndReasonAssetDisabled); terr != nil {
			log.Printf("[AssetService] 資產停用收線失敗 (asset=%d): %v", id, terr)
		} else if n > 0 {
			log.Printf("[AssetService] 資產停用收線 %d 個會話 (asset=%d)", n, id)
		}
	}

	// 回應帶最新節點資訊（掛載於交易內同步，
	// 回傳物件須重填避免舊值誤導前端）
	single := []model.Asset{*asset}
	if err := FillNodeInfo(database.DB, single); err != nil {
		log.Printf("節點資訊填充失敗（回應不帶節點欄）: %v", err)
		return asset, nil
	}

	return &single[0], nil
}

// Delete 刪除資產（軟刪除）；節點成員同交易硬刪（
// 成員殘留會讓「空節點」永遠數到幽靈成員而不可刪）。treeStructMu 與節點
// Delete 的空節點判定互斥
func (s *AssetService) Delete(id uint) error {
	treeStructMu.Lock()
	defer treeStructMu.Unlock()

	// 檢查資產是否存在
	_, err := s.GetByID(id)
	if err != nil {
		return err
	}

	return database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("asset_id = ?", id).Delete(&model.AssetNode{}).Error; err != nil {
			return fmt.Errorf("清除節點成員失敗: %w", err)
		}
		// 授權與審核範圍隨資產失效（塊 2）：權限查詢只查
		// asset_authorizations 單表、不 join assets，故資產被刪後授權仍會命中。
		// 兩張表皆屬 authz，**故經 tx-taking 窄 port 交由擁有者寫入**，asset 不直接
		// 碰他模組的表（tx-taking 窄 port，同 AssetGroupService.Delete 的處置）。
		// 未注入即 fail-close——靜默略過會留下幽靈授權與懸掛審核範圍
		if s.authzRevoker == nil {
			return fmt.Errorf("authz 級聯撤銷面未注入：資產刪除不得在不撤銷授權的情況下完成")
		}
		if _, _, err := s.authzRevoker.RevokeByAsset(tx, id); err != nil {
			return err
		}
		if err := tx.Delete(&model.Asset{}, id).Error; err != nil {
			return fmt.Errorf("刪除資產失敗: %w", err)
		}
		return nil
	})
}

// normalizeAccessPolicy ”＝跟隨全域預設，正規化為 nil（NULL 落庫）
func normalizeAccessPolicy(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// ErrNodeNotFound 掛載節點不存在
var ErrNodeNotFound = errors.New("掛載節點不存在")

// validateNodeIDsTx 節點集存在性驗證（軟刪節點視同不存在）。吃 tx——
// 與掛載寫入同交易＋treeStructMu 互斥，消除「驗證後節點被刪」窗口（
// asset_nodes 無 FK 可兜底）
func validateNodeIDsTx(tx *gorm.DB, nodeIDs []uint) error {
	if len(nodeIDs) == 0 {
		return nil
	}
	var count int64
	if err := tx.Model(&model.AssetGroup{}).Where("id IN ?", nodeIDs).Count(&count).Error; err != nil {
		return fmt.Errorf("驗證節點失敗: %w", err)
	}
	if count != int64(len(nodeIDs)) {
		return ErrNodeNotFound
	}
	return nil
}

// assetNodeIDs 資產目前掛載節點 id 集
func assetNodeIDs(db *gorm.DB, assetID uint) ([]uint, error) {
	var ids []uint
	if err := db.Model(&model.AssetNode{}).Where("asset_id = ?", assetID).
		Order("node_id").Pluck("node_id", &ids).Error; err != nil {
		return nil, fmt.Errorf("查詢資產節點失敗: %w", err)
	}
	return ids, nil
}

// replaceAssetNodes 以真差集同步資產掛載：僅刪多餘、
// 補缺少——保留未變動成員的 created_at（掛載時間是稽核時間線的一部分，
// 整刪重建會改寫）
func replaceAssetNodes(db *gorm.DB, assetID uint, nodeIDs []uint) error {
	current, err := assetNodeIDs(db, assetID)
	if err != nil {
		return err
	}
	want := make(map[uint]bool, len(nodeIDs))
	for _, id := range nodeIDs {
		want[id] = true
	}
	have := make(map[uint]bool, len(current))
	for _, id := range current {
		have[id] = true
	}

	toRemove := make([]uint, 0)
	for _, id := range current {
		if !want[id] {
			toRemove = append(toRemove, id)
		}
	}
	if len(toRemove) > 0 {
		if err := db.Where("asset_id = ? AND node_id IN ?", assetID, toRemove).
			Delete(&model.AssetNode{}).Error; err != nil {
			return fmt.Errorf("清除資產節點失敗: %w", err)
		}
	}
	for _, nodeID := range nodeIDs {
		if have[nodeID] {
			continue
		}
		if err := db.Create(&model.AssetNode{AssetID: assetID, NodeID: nodeID}).Error; err != nil {
			return fmt.Errorf("掛載節點失敗: %w", err)
		}
	}
	return nil
}

// uintSetEqual 集合等值（輸入已去重）
func uintSetEqual(a, b []uint) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[uint]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if !set[v] {
			return false
		}
	}
	return true
}

// FillNodeInfo 批次填資產的 NodeIDs 與 NodePaths：
// 全節點單查組路徑 map（百級節點規模，無需快取），成員單查分組
func FillNodeInfo(db *gorm.DB, assets []model.Asset) error {
	if len(assets) == 0 {
		return nil
	}
	assetIDs := make([]uint, 0, len(assets))
	for i := range assets {
		assetIDs = append(assetIDs, assets[i].ID)
	}
	var members []model.AssetNode
	if err := db.Where("asset_id IN ?", assetIDs).Order("node_id").Find(&members).Error; err != nil {
		return fmt.Errorf("查詢節點成員失敗: %w", err)
	}
	// 全部未掛載時免查路徑（常見於未分組清單與 sqlmock 測試路徑）
	if len(members) == 0 {
		return nil
	}
	paths, err := NodePathMap(db)
	if err != nil {
		return err
	}
	byAsset := make(map[uint][]uint, len(assets))
	for _, m := range members {
		byAsset[m.AssetID] = append(byAsset[m.AssetID], m.NodeID)
	}
	for i := range assets {
		ids := byAsset[assets[i].ID]
		assets[i].NodeIDs = ids
		nodePaths := make([]string, 0, len(ids))
		for _, id := range ids {
			if p, ok := paths[id]; ok {
				nodePaths = append(nodePaths, p)
			}
		}
		assets[i].NodePaths = nodePaths
	}
	return nil
}

// AssetIDsForNodeFilter 節點過濾的資產 id 集：
// ungrouped＝零掛載資產集；nodeID＝該節點（含子樹時含全部後代）掛載資產集。
// 授權分支在記憶體集合過濾用（admin 分支走 List 的 SQL 過濾）
func (s *AssetService) AssetIDsForNodeFilter(nodeID *uint, includeSubtree, ungrouped bool) (map[uint]bool, error) {
	var ids []uint
	var err error
	switch {
	case ungrouped:
		err = database.DB.Model(&model.Asset{}).
			Where("NOT EXISTS (SELECT 1 FROM asset_nodes an WHERE an.asset_id = assets.id)").
			Pluck("id", &ids).Error
	case nodeID != nil && includeSubtree:
		err = database.DB.Raw(`SELECT DISTINCT an.asset_id FROM asset_nodes an WHERE an.node_id IN (
			WITH RECURSIVE sub(id) AS (
				SELECT id FROM asset_groups WHERE id = ? AND deleted_at IS NULL
				UNION
				SELECT g.id FROM asset_groups g JOIN sub ON g.parent_id = sub.id
				WHERE g.deleted_at IS NULL
			) SELECT id FROM sub
		)`, *nodeID).Scan(&ids).Error
	case nodeID != nil:
		err = database.DB.Model(&model.AssetNode{}).Where("node_id = ?", *nodeID).
			Distinct("asset_id").Pluck("asset_id", &ids).Error
	default:
		return map[uint]bool{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("節點過濾查詢失敗: %w", err)
	}
	set := make(map[uint]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, nil
}

// NodePathMap 全節點 id→全路徑（如 prod / kafka）映射：單查全表記憶體組裝，
// 樹深上限 10、節點百級——O(n·深度) 可忽略。孤環防禦：走訪逾深度上限即截斷
func NodePathMap(db *gorm.DB) (map[uint]string, error) {
	var nodes []model.AssetGroup
	if err := db.Find(&nodes).Error; err != nil {
		return nil, fmt.Errorf("查詢節點失敗: %w", err)
	}
	byID := make(map[uint]*model.AssetGroup, len(nodes))
	for i := range nodes {
		byID[nodes[i].ID] = &nodes[i]
	}
	paths := make(map[uint]string, len(nodes))
	for _, n := range nodes {
		path := n.Name
		cur := n.ParentID
		for depth := 0; cur != nil && depth < 10; depth++ {
			parent, ok := byID[*cur]
			if !ok {
				break
			}
			path = parent.Name + " / " + path
			cur = parent.ParentID
		}
		paths[n.ID] = path
	}
	return paths, nil
}

// assetProtocols 可建立資產的協議清單——**撥測對照表與協議驗證的單一事實源**。
//
// 新增協議時只改這裡與 connection_probe.go 的 connectionProbes 兩處；
// 兩者的雙向完備性由 TestConnectionProbeTableComplete 釘住：
// 清單有而對照表沒登記＝紅，對照表有而清單沒有（如把 k8s 誤寫成 kubernetes）＝紅。
// 這取代了原本「白名單 SSH、其餘一律送 guacd」的否定式分派——後者讓
// mysql/postgres/redis/k8s 四種協議被 else 靜默吞進 guacd 而永不返回。
var assetProtocols = []model.ProtocolType{
	model.ProtocolSSH,
	model.ProtocolRDP,
	model.ProtocolVNC,
	model.ProtocolMySQL,
	model.ProtocolPostgres,
	model.ProtocolRedis,
	model.ProtocolMSSQL,
	model.ProtocolK8s,
}

// validateProtocol 驗證協議類型（查 assetProtocols 清單）
func (s *AssetService) validateProtocol(protocol model.ProtocolType) error {
	for _, p := range assetProtocols {
		if p == protocol {
			return nil
		}
	}
	return ErrInvalidProtocol
}

// ConnectionTestResult 連線測試結果。
//
// 失敗原因改以 Code（apierror 機器碼）承載，前端查譯；
// Message 過渡期保留，值一律取同一支碼的 ZhFallback（不再有獨立中文字面量，也不
// 再回填 guacd 原始訊息——原始訊息只落伺服端日誌）。前端 Assets.vue 直顯 message
// 的讀點改查譯後，本欄即可移除（F 段）。
type ConnectionTestResult struct {
	Success bool `json:"success"`
	// Message 過渡 fallback：Code 的 zh-TW 文案；成功時為空
	Message string `json:"message"`
	// Code 失敗原因機器碼（apierror registry），成功時為空
	Code      apierror.ErrCode `json:"code,omitempty"`
	LatencyMs int64            `json:"latency_ms,omitempty"`
	ErrorCode string           `json:"error_code,omitempty"`
	Protocol  string           `json:"protocol"`
	TestedAt  time.Time        `json:"tested_at"`
}

// setFailure 設定失敗原因：機器碼 + 同碼 ZhFallback 的過渡文案。
// errorCode 為既有的粗分類機器欄（前端徽章沿用），維持不動。
func (r *ConnectionTestResult) setFailure(code apierror.ErrCode, errorCode string) {
	r.Code = code
	r.ErrorCode = errorCode
	if d, ok := apierror.DescriptorOf(code); ok {
		r.Message = d.ZhFallback
	}
}

// testResultCodeFor 撥測粗分類（ErrorCode*）→ 使用者可見的機器碼。
func testResultCodeFor(errorCode string) apierror.ErrCode {
	switch errorCode {
	case ErrorCodeConnectionRefused:
		return apierror.CodeAssetTestConnectionRefused
	case ErrorCodeAuthFailed:
		return apierror.CodeAssetTestAuthFailed
	case ErrorCodeTimeout:
		return apierror.CodeAssetTestTimeout
	case ErrorCodeProtocolError:
		return apierror.CodeAssetTestProtocolError
	default:
		return apierror.CodeAssetTestUnknownError
	}
}

// TestConnection 測試資產連線並持久化結果
func (s *AssetService) TestConnection(ctx context.Context, assetID uint, timeout int) (*ConnectionTestResult, error) {
	result, err := s.testConnection(ctx, assetID, timeout)
	if result != nil {
		s.persistTestResult(assetID, result)
	}
	return result, err
}

// persistTestResult 落庫最近一次連測結果（best-effort，失敗僅記日誌不影響回傳）。
// 用 UpdateColumns 跳過 updated_at：連測屬探針行為，不應更動資產的修改時間語意。
func (s *AssetService) persistTestResult(assetID uint, result *ConnectionTestResult) {
	status := "unreachable"
	if result.Success {
		status = "reachable"
	}
	err := database.DB.Model(&model.Asset{}).Where("id = ?", assetID).UpdateColumns(map[string]interface{}{
		"last_test_status":     status,
		"last_test_at":         result.TestedAt,
		"last_test_latency_ms": result.LatencyMs,
	}).Error
	if err != nil {
		log.Printf("[TestConnection] 連測結果落庫失敗: Asset ID=%d, err=%v", assetID, err)
	}
}

func (s *AssetService) testConnection(ctx context.Context, assetID uint, timeout int) (*ConnectionTestResult, error) {
	// 1. 獲取資產及憑證（連測維持 default 帳號語義，不帶 account 參數）
	creds, err := s.GetWithCredentialsDefault(assetID)
	if err != nil {
		return nil, err
	}
	asset := creds.Asset

	// 零帳號資產：空密碼撥測對允許空密碼的伺服器可能回「成功」，給出假象。
	// 早退維持在分派之前、對所有協議一體適用——DB 的 TCP 探測技術上不需憑證，
	// 但「無可用帳號」時「我連得上嗎」的答案恆為否，下放到各 probe 會讓 DB 資產
	// 在沒有帳號時回報 reachable。
	if creds.AccountID == 0 {
		result := &ConnectionTestResult{Protocol: string(asset.Protocol), TestedAt: time.Now()}
		result.setFailure(apierror.CodeAssetTestNoAccount, ErrorCodeNoUsableAccount)
		return result, nil
	}

	// 逾時夾制：1..30 秒，預設 10。夾制在分派之前，故所有 probe 收到的都是已夾制值。
	timeout = clampTestTimeout(timeout)

	log.Printf("[TestConnection] 開始測試資產連線: ID=%d, Protocol=%s, Host=%s:%d, Timeout=%ds",
		assetID, asset.Protocol, asset.Host, asset.Port, timeout)

	// 顯式對照表分派：查表命中即呼叫對應 probe。
	// 未命中一律回 protocol_unsupported，**絕不 fallthrough 到 guacd 或任何中介**
	// ——比照 identity/local_admin_invariant.go 的 default: return error 慣例。
	probe, ok := connectionProbes[asset.Protocol]
	if !ok {
		result := &ConnectionTestResult{Protocol: string(asset.Protocol), TestedAt: time.Now()}
		result.setFailure(apierror.CodeAssetTestProtocolUnsupported, ErrorCodeProtocolUnsupport)
		log.Printf("[TestConnection] 協議未登記撥測方式: Asset ID=%d, Protocol=%s", assetID, asset.Protocol)
		return result, nil
	}

	testResult := probe.run(s, ctx, creds, timeout)
	if testResult.Success {
		log.Printf("[TestConnection] 連線測試成功: Asset ID=%d, Probe=%s, Latency=%dms",
			assetID, probe.name, testResult.LatencyMs)
	} else {
		log.Printf("[TestConnection] 連線測試失敗: Asset ID=%d, Probe=%s, Code=%s",
			assetID, probe.name, testResult.Code)
	}
	return testResult, nil
}

// testSSHDirect SSH 資產直連測試（test-connection 修復：guacd 退場後 SSH 撥測走原生路徑）。
// 吃 AssetCredentials 而非拆散的 asset+password：username 與密碼必須同帳號。
// 由 connectionProbes["ssh"] 呼叫；timeout 已於分派前夾制。
func (s *AssetService) testSSHDirect(assetID uint, creds *AssetCredentials, timeout int) *ConnectionTestResult {
	asset := creds.Asset
	result := &ConnectionTestResult{Protocol: string(asset.Protocol), TestedAt: time.Now()}
	if s.hostKeys == nil {
		result.setFailure(apierror.CodeAssetTestHostKeyUnavailable, "host_key_unavailable")
		return result
	}
	if timeout <= 0 {
		timeout = 10
	}

	// 空密碼不包成 ssh.Password("")：對允許空密碼的伺服器，
	// 空密碼認證可能「成功」而讓 UI 顯示資產可連——那是假象，不是可用憑證。
	// 撥測只走密碼認證（金鑰撥測未實作），故無密碼即無從測起，直接判失敗
	if creds.Password == "" {
		result.setFailure(apierror.CodeAssetTestNoAccount, ErrorCodeNoUsableAccount)
		return result
	}

	start := time.Now()
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", asset.Host, asset.Port), &ssh.ClientConfig{
		User:            creds.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(creds.Password)},
		HostKeyCallback: s.hostKeys.Callback(assetID),
		Timeout:         time.Duration(timeout) * time.Second,
	})
	result.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		// 碼化：host key 變更與認證失敗直接复用 RULE_SSH_*（同一事實同一文案）
		switch {
		case errors.Is(err, ErrHostKeyChanged):
			result.setFailure(apierror.CodeSSHHostKeyChanged, "host_key_changed")
		case strings.Contains(err.Error(), "unable to authenticate"):
			result.setFailure(apierror.CodeSSHAuthFailed, "auth_failed")
		default:
			result.setFailure(apierror.CodeAssetTestConnectionFailed, ErrorCodeConnectionFailed)
		}
		log.Printf("[TestConnection] SSH 直連失敗: ID=%d err=%v", assetID, err)
		return result
	}
	client.Close()
	result.Success = true
	// 成功不帶 UI 文案：前端以 $t('assets.testSuccess') 自有文案提示
	return result
}
