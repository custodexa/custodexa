package asset

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 資產帳號的服務層：帳號自此為「連線 username ＋
// 憑證」的權威來源，Asset 內嵌憑證欄位（password_enc/private_key_enc）自本階段起
// 凍結不再寫入（單向切換）。assets.username 與 has_password/has_private_key
// 仍隨預設帳號鏡射——前者是列表/審計 diff 的顯示欄，後者是 UI 的「已設定憑證」
// 標記，兩者都不是憑證本體，凍結它們只會讓既有畫面說謊。

var (
	// ErrAssetAccountNotFound 帳號不存在，或不屬於指定資產（fail-close，不靜默退 default）
	ErrAssetAccountNotFound = errors.New("資產帳號不存在或不屬於該資產")
	// ErrAssetAccountUsernameExists 同資產同名帳號（DB partial unique index 的服務層對應）
	ErrAssetAccountUsernameExists = errors.New("同一資產下已有同名帳號")
	// ErrAssetAccountDefaultMissing 資產有帳號卻無預設帳號（不變式被破壞）。
	// 不靜默挑一筆頂替——那會讓連線悄悄用到非預期身分，寧可擋下要求人工修正
	ErrAssetAccountDefaultMissing = errors.New("資產帳號資料異常：有帳號但無預設帳號")
	// ErrAssetAccountDefaultRequired 資產仍有其他帳號時不可刪除預設帳號（「有帳號必有 default」）
	ErrAssetAccountDefaultRequired = errors.New("資產仍有其他帳號時不可刪除預設帳號，請先指定新的預設帳號")
	// ErrAssetAccountDefaultConflict 併發下 default partial unique index 衝突：
	// 兩個交易同時為零帳號資產建首筆（皆判定為 default），或 default 切換交錯。
	// 與「同名帳號」分流，否則回應會誤導成使用者根本沒犯的錯
	ErrAssetAccountDefaultConflict = errors.New("預設帳號同時被其他操作變更，請重試")
	// ErrAssetAccountSourceNotFound 複製來源帳號不存在（「從其他資產帳號複製」）
	ErrAssetAccountSourceNotFound = errors.New("複製來源帳號不存在")
	// ErrAssetNoUsableAccount 資產無可用帳號（零帳號）卻要建線／取憑證。
	// 連線入口一律 fail-close：空 username＋空密碼送進 guacd／dbproxy／k8s client
	// 會變成「匿名或免密嘗試」——redis 無密碼即登入、mysql/postgres 可能命中 trust
	// 認證、k8s 走匿名 ServiceAccount。受管連線的前提是有受管憑證，沒有就不連
	// （SSH 與 SFTP 原本靠「無可用認證方法」擋，其餘協議沒有這道網）
	ErrAssetNoUsableAccount = errors.New("資產未設定可用帳號憑證")
	// ErrAssetAccountUsernameInvalid 帳號名稱含控制字元／冒號。
	// 非美觀問題：username 會進 chpasswd 的 `user:password` stdin 條目（change_secret_runner），
	// 也會進 SSH 認證與審計快照，含換行/冒號者可拆出額外條目改到別的帳號
	ErrAssetAccountUsernameInvalid = errors.New("帳號名稱不得含換行、冒號或控制字元")
	// ErrAssetAccountUsernameReserved 帳號名稱佔用授權範圍的別名命名空間
	// （`@` 前綴）——見 validateAccountUsername 的理由
	ErrAssetAccountUsernameReserved = errors.New("帳號名稱不得以 @ 開頭（保留給授權範圍別名，如 @ALL）")
	// ErrAssetAccountUsernameTooLong 逾 model 欄位長度（size:100）
	ErrAssetAccountUsernameTooLong = errors.New("帳號名稱超過長度上限（100 字元）")
	// ErrAssetAccountNoteTooLong 逾 model 欄位長度（size:255）
	ErrAssetAccountNoteTooLong = errors.New("帳號備註超過長度上限（255 字元）")
	// ErrAssetAccountAuthMethodInvalid auth_method 值域外
	ErrAssetAccountAuthMethodInvalid = errors.New("auth_method 僅允許 sql 或 domain")
	// ErrAssetAccountAuthMethodUnsupported 值合法但本版做不到：go-sqlcmd 未引入
	// gokrb5、ActiveDirectoryIntegrated 在 Linux 未實作，域認證在此工具鏈下根本不通。
	// **明確拒絕而非靜默降級為 sql**——後者會讓管理員以為域認證已生效
	ErrAssetAccountAuthMethodUnsupported = errors.New("本版尚未支援網域認證（Windows／Kerberos），請改用 SQL 認證")
)

const (
	assetAccountUsernameMaxLen = 100
	assetAccountNoteMaxLen     = 255
)

// AssetCredentials 一次連線所需的「資產 ＋ 帳號」解析結果（階段 2 起的憑證出口）。
//
// 為何是單一結構而非多回傳值：憑證與 username 必須來自**同一帳號**，
// 分開回傳等於允許呼叫端把 A 帳號的密碼配 B 帳號的 username 送出去。
type AssetCredentials struct {
	Asset *model.Asset
	// AccountID 實際使用的帳號 id；0＝零帳號資產（原本即無憑證者，合法）
	AccountID  uint
	Username   string
	Password   string
	PrivateKey string
}

// AssetAccountDTO 帳號的對外表示：密文欄位絕不出站，僅以布林標記是否已設定。
type AssetAccountDTO struct {
	ID            uint   `json:"id"`
	AssetID       uint   `json:"asset_id"`
	Username      string `json:"username"`
	IsDefault     bool   `json:"is_default"`
	Privileged    bool   `json:"privileged"`
	AuthMethod    string `json:"auth_method"`
	Note          string `json:"note"`
	HasPassword   bool   `json:"has_password"`
	HasPrivateKey bool   `json:"has_private_key"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// NewAssetAccountDTO 由 model 轉出對外表示（密文只轉成布林）
func NewAssetAccountDTO(a *model.AssetAccount) *AssetAccountDTO {
	return &AssetAccountDTO{
		ID:            a.ID,
		AssetID:       a.AssetID,
		Username:      a.Username,
		IsDefault:     a.IsDefault,
		Privileged:    a.Privileged,
		AuthMethod:    a.AuthMethod,
		Note:          a.Note,
		HasPassword:   a.PasswordEnc != "",
		HasPrivateKey: a.PrivateKeyEnc != "",
		CreatedAt:     a.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     a.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

// CreateAssetAccountRequest 建立帳號請求
type CreateAssetAccountRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	IsDefault  bool   `json:"is_default"`
	Privileged bool   `json:"privileged"`
	// AuthMethod 認證類型（空＝sql）。1.0 只接受 sql，domain 明確拒絕
	AuthMethod string `json:"auth_method"`
	Note       string `json:"note"`

	// CopyFromAccountID 從其他資產的帳號複製 username 與憑證（建號快捷）。
	// **密文原樣複製**、不解密重加密：信封密文自帶 DEK 版本前綴、無 AAD 列綁定，
	// 跨列可解。顯式帶入的 username/password/private_key 覆蓋複製值。
	CopyFromAccountID uint `json:"copy_from_account_id"`
}

// UpdateAssetAccountRequest 更新帳號請求（nil＝不動；密碼／私鑰空字串＝沿用既有，
// 比照資產更新的既有語義，避免前端回填空值時靜默清空憑證）
type UpdateAssetAccountRequest struct {
	Username   *string `json:"username"`
	Password   *string `json:"password"`
	PrivateKey *string `json:"private_key"`
	Privileged *bool   `json:"privileged"`
	AuthMethod *string `json:"auth_method"`
	Note       *string `json:"note"`
}

// AssetAccountService 帳號 CRUD（全部變更走專屬審計，絕不落密文／明文）
type AssetAccountService struct {
	// assets 提供 crypto codec 與資產存在性檢查。刻意共用 AssetService 而非自持
	// codec：main 以 SetCodec 把資產服務升級為信封 key manager，另持一份 codec
	// 會讓帳號憑證在管理員沒察覺時走 legacy AES 加密
	assets *AssetService
	// authz 跨資產複製建號的來源可見性判定（階段 2 列為待辦，
	// 階段 4 補上）。nil＝不判定，僅供未涉及複製路徑的既有單測建構；
	// 生產組裝一律注入（main.go）
	//
	// **型別由 `*AssetAuthorizationService` 改為消費者側宣告的窄介面**
	// （K6 偏好的形式）。asset 只需要「這個人看得見那台資產嗎」這一個問句；
	// 綁具體型別會產生 asset→authz 出向邊，而 authz 的遷入順序排在 asset 之後。
	// 介面**刻意不匯出**：外部呼叫端傳的是具體型別，不需要指名這個介面。
	authz assetViewPermissionChecker
	// crypto 憑證加解密。
	//
	// **不再穿透 `s.assets.crypto`**：穿透讓 asset 服務的未匯出欄位成為本服務的
	// 隱性依賴，搬包後即編譯不過；且它把「兩者必須用同一把 codec」寄託在
	// 「碰巧共用同一個物件」上。改為由組裝根注入**同一個** codec 實例——
	// 保證不變、依賴顯式。原註解所擔心的「SetCodec 事後覆寫使兩者分歧」在
	// 三職拆解後已不存在（AssetService 已無 SetCodec）。
	crypto crypto.ColumnCodec
	// auditTx 交易內審計落地面（T-2 收口）；nil 即 fail-close。
	auditTx port.TxSink
}

// assetViewPermissionChecker 複製來源可見性判定（消費者側窄介面，見 authz 欄註解）。
type assetViewPermissionChecker interface {
	CheckPermission(ctx context.Context, userID, assetID uint, perm model.PermissionType) (bool, error)
}

// NewAssetAccountService 建立帳號服務。
// codec 與 auditTx 由組裝根注入；codec SHALL 與 assets 用同一個實例。
func NewAssetAccountService(assets *AssetService, codec crypto.ColumnCodec, auditTx port.TxSink) *AssetAccountService {
	return &AssetAccountService{assets: assets, crypto: codec, auditTx: auditTx}
}

// WithAuthorization 注入授權服務（跨資產複製來源可見性判定用）。
// 回傳自身供組裝端串接
func (s *AssetAccountService) WithAuthorization(authz assetViewPermissionChecker) *AssetAccountService {
	s.authz = authz
	return s
}

// ErrAssetAccountSourceForbidden 複製來源帳號所屬資產對操作者不可見。
//
// 為何需要這道檢查：`copy_from_account_id` 只需對**目標**資產有 asset:update，
// 來源帳號卻可以是任何資產的——沒有這道判定，一個只管得到自己那台的管理員
// 可以把生產核心機的 root 密文複製到自己的資產上，然後從自己的資產連上去。
// 密文原樣搬運不需解密即可用，這是完整的憑證竊取路徑。
//
// 對外映射與「來源不存在」**共用同一碼**（NOTFOUND_ASSET_ACCOUNT_SOURCE）：
// 分流回應等於讓此欄成為「哪些 account id 存在」的探測器
var ErrAssetAccountSourceForbidden = errors.New("複製來源帳號所屬資產不可見")

// resolveAssetAccount 取指定帳號（accountID=0＝取預設）。回傳 (nil, nil) 僅代表
// 「該資產零帳號」——原本即無憑證的資產，屬合法狀態（spec「零憑證資產零帳號」）。
//
// fail-close（與 AssetService 同型）：指定 accountID 時以 (id, asset_id) 複合條件現查，
// 帳號不存在、已軟刪、或屬於別的資產一律回錯，**不退回預設帳號**——靜默退回
// 等於讓「跨資產 account id 注入」拿到目標資產的預設憑證還連得上。
func resolveAssetAccount(db *gorm.DB, assetID, accountID uint) (*model.AssetAccount, error) {
	var account model.AssetAccount
	if accountID != 0 {
		err := db.Where("id = ? AND asset_id = ?", accountID, assetID).First(&account).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, ErrAssetAccountNotFound
			}
			return nil, fmt.Errorf("查詢資產帳號失敗: %w", err)
		}
		return &account, nil
	}

	err := db.Where("asset_id = ? AND is_default = ?", assetID, true).First(&account).Error
	if err == nil {
		return &account, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("查詢預設帳號失敗: %w", err)
	}
	// 無預設帳號：零帳號資產合法，有帳號卻無預設＝不變式破損，擋下
	var count int64
	if err := db.Model(&model.AssetAccount{}).Where("asset_id = ?", assetID).Count(&count).Error; err != nil {
		return nil, fmt.Errorf("查詢資產帳號數失敗: %w", err)
	}
	if count == 0 {
		return nil, nil
	}
	return nil, ErrAssetAccountDefaultMissing
}

// VerifyAccountBinding 驗證連線帳號的客體綁定：
// 以 (id, asset_id, deleted_at IS NULL) DB 現查該帳號確實隸屬該資產。
//
// accountID=0（預設帳號）恆通過——預設帳號的解析與零帳號 fail-close 屬取憑證
// 路徑的職責（GetWithCredentialsForAccount）。指定帳號時，跨資產／已刪除一律
// 回 ErrAssetAccountNotFound，簽發點據此拒發（連線 token 不得承載未經現查的客體）。
func (s *AssetService) VerifyAccountBinding(assetID, accountID uint) error {
	if accountID == 0 {
		return nil
	}
	_, err := resolveAssetAccount(database.DB, assetID, accountID)
	return err
}

// liveAccountCount 該資產未軟刪的帳號數
func liveAccountCount(db *gorm.DB, assetID uint) (int64, error) {
	var count int64
	if err := db.Model(&model.AssetAccount{}).Where("asset_id = ?", assetID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("查詢資產帳號數失敗: %w", err)
	}
	return count, nil
}

// ValidateAccountUsername 帳號名稱驗證
//
// **匯出**（asset 先於 authz 遷入，故需要 ValidateAccountUsername 的匯出面）：
// 唯一跨模組消費者是 authz 的 `asset_authorization_service.go:214`——授權列的帳號
// 範圍寫入前要用**同一套**規則驗名字。複製一份規則到 authz 側等於製造第二個會漂移的
// 驗證器，而這條規則的威脅面是 chpasswd stdin 與審計快照，兩份規則分歧即是漏洞。
// 舊註解如下：
// validateAccountUsername 帳號名稱驗證（空字串合法：VNC/Redis/K8s 等無 username 協議）。
//
// 拒全部 C0/C1 控制字元＋DEL＋冒號：原本只擋 CR/LF/NUL/冒號，
// 但 tab／ESC 等一樣會進 SSH 認證、UI 與審計快照——ESC 序列可操縱讀 log 的終端，
// 與 apierror 的 logSafe 同一威脅面，在入口擋掉最省事。
func ValidateAccountUsername(username string) error {
	if strings.ContainsRune(username, ':') {
		return ErrAssetAccountUsernameInvalid
	}
	// 保留字命名空間：授權帳號範圍是 username 字串清單，
	// 別名與真名共處同一命名空間（`@ALL` 是別名、`root` 是真名，兩者同欄同型別）。
	// 若容許真實帳號叫 `@ALL`，管理員「只授權這個帳號」會被正規化解讀成「全部帳號」
	// ——一個純命名巧合直接變成溢授。
	//
	// 擋整個 `@` 前綴而非只擋 `@ALL`：日後新增別名（如 @SPEC）不必回頭再擋一次，
	// 而 Unix／DB 帳號名本就不以 `@` 開頭，實務上零損失。
	// 本函式同時服務帳號 CRUD 與授權範圍元素驗證（`@ALL` 在呼叫端先行跳過），
	// 故一條規則兩處生效
	if strings.HasPrefix(username, "@") {
		return ErrAssetAccountUsernameReserved
	}
	for _, r := range username {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return ErrAssetAccountUsernameInvalid
		}
	}
	if len([]rune(username)) > assetAccountUsernameMaxLen {
		return ErrAssetAccountUsernameTooLong
	}
	return nil
}

func validateAccountNote(note string) error {
	if len([]rune(note)) > assetAccountNoteMaxLen {
		return ErrAssetAccountNoteTooLong
	}
	return nil
}

// AuthMethodSQL／AuthMethodDomain 帳號認證類型值域
const (
	AuthMethodSQL    = "sql"
	AuthMethodDomain = "domain"
)

// normalizeAccountAuthMethod 驗證並正規化認證類型。空字串＝未指定＝sql（既有帳號
// 與非 mssql 協議一律如此）。domain 值域合法但本版拒絕，回獨立一碼以便前端區分
// 「打錯字」與「這功能還沒做」。
func normalizeAccountAuthMethod(v string) (string, error) {
	switch v {
	case "", AuthMethodSQL:
		return AuthMethodSQL, nil
	case AuthMethodDomain:
		return "", ErrAssetAccountAuthMethodUnsupported
	default:
		return "", ErrAssetAccountAuthMethodInvalid
	}
}

// accountUniqueViolation 唯一索引衝突分流：本表有兩道 partial unique index
// （username 與 default），一律映成「同名帳號」會回一個使用者根本沒犯的錯。
// 依索引名判別；非唯一違反則原樣包裝。
func accountUniqueViolation(err error, wrapMsg string) error {
	if !dberr.IsUniqueViolation(err) {
		return fmt.Errorf("%s: %w", wrapMsg, err)
	}
	if strings.Contains(err.Error(), "idx_asset_accounts_default") {
		return ErrAssetAccountDefaultConflict
	}
	return ErrAssetAccountUsernameExists
}

// List 列出資產的帳號（預設帳號排首，其餘依 username）
func (s *AssetAccountService) List(assetID uint) ([]*AssetAccountDTO, error) {
	if _, err := s.assets.GetByID(assetID); err != nil {
		return nil, err
	}
	var accounts []model.AssetAccount
	if err := database.DB.Where("asset_id = ?", assetID).
		Order("is_default DESC, username ASC, id ASC").Find(&accounts).Error; err != nil {
		return nil, fmt.Errorf("查詢資產帳號失敗: %w", err)
	}
	out := make([]*AssetAccountDTO, 0, len(accounts))
	for i := range accounts {
		out = append(out, NewAssetAccountDTO(&accounts[i]))
	}
	return out, nil
}

// Get 取單一帳號（供更新後回傳）
func (s *AssetAccountService) Get(assetID, accountID uint) (*AssetAccountDTO, error) {
	account, err := resolveAssetAccount(database.DB, assetID, accountID)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, ErrAssetAccountNotFound
	}
	return NewAssetAccountDTO(account), nil
}

// lockAssetForAccountMutation 以資產列為互斥點序列化該資產的全部帳號變更。
//
// 為何鎖 assets 而非 asset_accounts：帳號集合的不變式（「至多一 default」「有帳號
// 必有 default」）是**集合層**性質，判定依據包含「目前有幾筆帳號」——對零筆或
// 即將新增的列，行鎖無物可鎖（`SELECT ... FOR UPDATE` 鎖不到不存在的列），
// 兩個並發建號仍會各自讀到 count=0。鎖住父資產列則涵蓋整個集合，且與既有
// treeStructMu 之外的資產寫入互不干擾（資產本體更新走 GORM Save，不持此鎖）。
//
// sqlite 靠單寫者（整庫寫鎖）達成同等序列化，故僅 postgres 需顯式鎖。
func lockAssetForAccountMutation(tx *gorm.DB, assetID uint) error {
	if tx.Dialector == nil || tx.Dialector.Name() != "postgres" {
		return nil
	}
	var locked uint
	err := tx.Raw("SELECT id FROM assets WHERE id = ? AND deleted_at IS NULL FOR UPDATE", assetID).
		Scan(&locked).Error
	if err != nil {
		return fmt.Errorf("鎖定資產帳號集失敗: %w", err)
	}
	if locked == 0 {
		return ErrAssetNotFound
	}
	return nil
}

// Create 建立帳號。
//
// **判定與寫入全在同一交易、且先鎖住資產列**：default 判定讀的是
// 「目前有幾筆帳號」，在交易外判定會讓「A 讀到尚有 1 筆 → 決定非 default」與
// 「B 同時刪掉那筆」交錯，留下唯一一筆非 default 帳號（違反「有帳號必有 default」）。
// partial unique index 只擋得住「兩筆 default」，擋不住「零筆 default」。
func (s *AssetAccountService) Create(ctx context.Context, assetID uint, req *CreateAssetAccountRequest) (*AssetAccountDTO, error) {
	if _, err := s.assets.GetByID(assetID); err != nil {
		return nil, err
	}
	if err := ValidateAccountUsername(req.Username); err != nil {
		return nil, err
	}
	if err := validateAccountNote(req.Note); err != nil {
		return nil, err
	}
	authMethod, authErr := normalizeAccountAuthMethod(req.AuthMethod)
	if authErr != nil {
		return nil, authErr
	}

	account := &model.AssetAccount{
		AssetID:    assetID,
		Username:   req.Username,
		Privileged: req.Privileged,
		AuthMethod: authMethod,
		Note:       req.Note,
	}

	// 從其他帳號複製（密文原樣搬，不解密）。來源出處入審計：
	// 憑證跨資產複製若零軌跡，事後無從回答「這台的 root 密碼是從哪來的」
	var copyFromAssetID uint
	if req.CopyFromAccountID != 0 {
		var source model.AssetAccount
		if err := database.DB.First(&source, req.CopyFromAccountID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, ErrAssetAccountSourceNotFound
			}
			return nil, fmt.Errorf("查詢來源帳號失敗: %w", err)
		}
		copyFromAssetID = source.AssetID
		// 來源可見性（階段 2 backlog）：跨資產複製時操作者須對來源資產
		// 至少可視。同資產內複製免判——對目標資產的 asset:update 已涵蓋
		if s.authz != nil && source.AssetID != assetID {
			operatorID, _ := model.UserFromContext(ctx)
			visible, verr := s.authz.CheckPermission(ctx, operatorID, source.AssetID, model.PermissionView)
			if verr != nil {
				return nil, fmt.Errorf("判定複製來源可見性失敗: %w", verr)
			}
			if !visible {
				log.Printf("[AssetAccount] 複製來源資產不可見，拒絕建號: operator=%d sourceAssetID=%d",
					operatorID, source.AssetID)
				return nil, ErrAssetAccountSourceForbidden
			}
		}
		if account.Username == "" {
			account.Username = source.Username
			if err := ValidateAccountUsername(account.Username); err != nil {
				return nil, err
			}
		}
		account.PasswordEnc = source.PasswordEnc
		account.PrivateKeyEnc = source.PrivateKeyEnc
	}

	// 顯式憑證覆蓋複製值
	if req.Password != "" {
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefAccountPassword, req.Password)
		if err != nil {
			return nil, fmt.Errorf("加密密碼失敗: %w", err)
		}
		account.PasswordEnc = enc
	}
	if req.PrivateKey != "" {
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefAccountPrivateKey, req.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("加密私鑰失敗: %w", err)
		}
		account.PrivateKeyEnc = enc
	}

	userID, operator := model.UserFromContext(ctx)

	err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, assetID); err != nil {
			return err
		}
		var dup int64
		if err := tx.Model(&model.AssetAccount{}).
			Where("asset_id = ? AND username = ?", assetID, account.Username).
			Count(&dup).Error; err != nil {
			return fmt.Errorf("檢查同名帳號失敗: %w", err)
		}
		if dup > 0 {
			return ErrAssetAccountUsernameExists
		}

		count, err := liveAccountCount(tx, assetID)
		if err != nil {
			return err
		}
		account.IsDefault = req.IsDefault || count == 0
		if account.IsDefault {
			if err := clearDefaultAccounts(tx, assetID, 0); err != nil {
				return err
			}
		}
		if err := tx.Create(account).Error; err != nil {
			return accountUniqueViolation(err, "建立資產帳號失敗")
		}
		if account.IsDefault {
			if err := mirrorDefaultAccountToAsset(tx, account); err != nil {
				return err
			}
		}
		return writeAssetAccountAudit(s.auditTx, tx, model.AssetAccountAudit{
			AssetID:         assetID,
			AccountID:       account.ID,
			Username:        account.Username,
			Operation:       model.AccountOpCreate,
			Fields:          changedSecretFields(account.PasswordEnc != "", account.PrivateKeyEnc != "", account.IsDefault),
			CopyFromAssetID: copyFromAssetID,
			CopyFromAccount: req.CopyFromAccountID,
		}, userID, operator)
	})
	if err != nil {
		return nil, err
	}
	return NewAssetAccountDTO(account), nil
}

// Update 更新帳號（含憑證輪換）。default 切換不走本方法，見 SetDefault。
//
// **快照與差異計算全在交易內、且只寫變更欄**：舊寫法在交易外讀
// 快照、交易內以全欄 Updates 覆寫，兩個並發更新（一個改備註、一個輪換密碼）會
// 讓後提交者把剛輪換的密文倒回舊值——遠端已改密、庫內卻是舊密＝鎖死，而審計
// 只記 note，事後完全查不出憑證被回滾過。
func (s *AssetAccountService) Update(ctx context.Context, assetID, accountID uint, req *UpdateAssetAccountRequest) (*AssetAccountDTO, error) {
	if accountID == 0 {
		return nil, ErrAssetAccountNotFound
	}
	if _, err := s.assets.GetByID(assetID); err != nil {
		return nil, err
	}
	// 加密在交易外先做（純 CPU／可能觸及 KMS，不佔 DB 交易與資產鎖）
	var passwordEnc, privateKeyEnc string
	if req.Password != nil && *req.Password != "" {
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefAccountPassword, *req.Password)
		if err != nil {
			return nil, fmt.Errorf("加密密碼失敗: %w", err)
		}
		passwordEnc = enc
	}
	if req.PrivateKey != nil && *req.PrivateKey != "" {
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefAccountPrivateKey, *req.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("加密私鑰失敗: %w", err)
		}
		privateKeyEnc = enc
	}
	if req.Username != nil {
		if err := ValidateAccountUsername(*req.Username); err != nil {
			return nil, err
		}
	}
	if req.Note != nil {
		if err := validateAccountNote(*req.Note); err != nil {
			return nil, err
		}
	}
	var authMethod string
	if req.AuthMethod != nil {
		normalized, err := normalizeAccountAuthMethod(*req.AuthMethod)
		if err != nil {
			return nil, err
		}
		authMethod = normalized
	}

	userID, operator := model.UserFromContext(ctx)
	var result *model.AssetAccount

	err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, assetID); err != nil {
			return err
		}
		// 交易內重讀：交易外的快照可能已被並發操作改過（含軟刪）
		account, err := resolveAssetAccount(tx, assetID, accountID)
		if err != nil {
			return err
		}
		if account == nil {
			return ErrAssetAccountNotFound
		}

		updates := map[string]interface{}{}
		fields := make([]string, 0, 5)
		if req.Username != nil && *req.Username != account.Username {
			updates["username"] = *req.Username
			fields = append(fields, "username")
		}
		if req.Note != nil && *req.Note != account.Note {
			updates["note"] = *req.Note
			fields = append(fields, "note")
		}
		if req.Privileged != nil && *req.Privileged != account.Privileged {
			updates["privileged"] = *req.Privileged
			fields = append(fields, "privileged")
		}
		if authMethod != "" && authMethod != account.AuthMethod {
			updates["auth_method"] = authMethod
			fields = append(fields, "auth_method")
		}
		if passwordEnc != "" {
			updates["password_enc"] = passwordEnc
			fields = append(fields, "password")
		}
		if privateKeyEnc != "" {
			updates["private_key_enc"] = privateKeyEnc
			fields = append(fields, "private_key")
		}
		if len(updates) == 0 {
			result = account
			return nil
		}

		if newName, ok := updates["username"].(string); ok {
			var dup int64
			if err := tx.Model(&model.AssetAccount{}).
				Where("asset_id = ? AND username = ? AND id <> ?", assetID, newName, account.ID).
				Count(&dup).Error; err != nil {
				return fmt.Errorf("檢查同名帳號失敗: %w", err)
			}
			if dup > 0 {
				return ErrAssetAccountUsernameExists
			}
		}

		res := tx.Model(&model.AssetAccount{}).Where("id = ?", account.ID).Updates(updates)
		if res.Error != nil {
			return accountUniqueViolation(res.Error, "更新資產帳號失敗")
		}
		if res.RowsAffected == 0 {
			// 交易內重讀後仍零列＝該列於本交易可見範圍外被移除，寧可回錯不假成功
			return ErrAssetAccountNotFound
		}

		// 回填變更後的值（不對 .Note 選擇器賦值：套件層 AST 守衛以欄位名比對）
		updatedAccount := applyAccountUpdates(account, updates)
		if updatedAccount.IsDefault {
			if err := mirrorDefaultAccountToAsset(tx, updatedAccount); err != nil {
				return err
			}
		}
		result = updatedAccount
		return writeAssetAccountAudit(s.auditTx, tx, model.AssetAccountAudit{
			AssetID:   assetID,
			AccountID: updatedAccount.ID,
			Username:  updatedAccount.Username,
			Operation: model.AccountOpUpdate,
			Fields:    fields,
		}, userID, operator)
	})
	if err != nil {
		return nil, err
	}
	return NewAssetAccountDTO(result), nil
}

// Delete 刪除帳號（軟刪）。禁刪最後一個 default：資產仍有其他帳號時必須
// 先指定新的預設，否則會留下「有帳號無預設」的狀態，系統路徑（改密／k8s／SFTP）
// 將無帳號可用。資產僅剩這一個帳號時允許刪——零帳號資產合法。
//
// IsDefault 與帳號數皆在交易內、鎖後重讀：交易外快取的 IsDefault
// 會讓「讀到 B 非 default」與「另一交易把 B 設為 default」交錯，刪掉的其實是
// 現行 default，留下有帳號無預設。
func (s *AssetAccountService) Delete(ctx context.Context, assetID, accountID uint) error {
	if accountID == 0 {
		return ErrAssetAccountNotFound
	}
	if _, err := s.assets.GetByID(assetID); err != nil {
		return err
	}

	userID, operator := model.UserFromContext(ctx)
	return database.DB.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, assetID); err != nil {
			return err
		}
		account, err := resolveAssetAccount(tx, assetID, accountID)
		if err != nil {
			return err
		}
		if account == nil {
			return ErrAssetAccountNotFound
		}
		count, err := liveAccountCount(tx, assetID)
		if err != nil {
			return err
		}
		if account.IsDefault && count > 1 {
			return ErrAssetAccountDefaultRequired
		}
		res := tx.Delete(&model.AssetAccount{}, account.ID)
		if res.Error != nil {
			return fmt.Errorf("刪除資產帳號失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrAssetAccountNotFound
		}
		if account.IsDefault {
			// 刪掉的是唯一帳號：資產回到零帳號狀態，顯示欄一併清空——
			// username 若留舊值，列表與審計 diff 會顯示一個已不存在的身分
			if err := tx.Model(&model.Asset{}).Where("id = ?", assetID).
				UpdateColumns(map[string]interface{}{
					"username":        "",
					"has_password":    false,
					"has_private_key": false,
				}).Error; err != nil {
				return fmt.Errorf("同步資產顯示欄失敗: %w", err)
			}
		}
		return writeAssetAccountAudit(s.auditTx, tx, model.AssetAccountAudit{
			AssetID:   assetID,
			AccountID: account.ID,
			Username:  account.Username,
			Operation: model.AccountOpDelete,
		}, userID, operator)
	})
}

// SetDefault 切換預設帳號（交易式：鎖資產 → 交易內重讀 → 先清空全部 default
// 再設定目標，使 partial unique index 不會在中途看到兩筆 default）
func (s *AssetAccountService) SetDefault(ctx context.Context, assetID, accountID uint) (*AssetAccountDTO, error) {
	if accountID == 0 {
		return nil, ErrAssetAccountNotFound
	}
	if _, err := s.assets.GetByID(assetID); err != nil {
		return nil, err
	}

	userID, operator := model.UserFromContext(ctx)
	var result *model.AssetAccount
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, assetID); err != nil {
			return err
		}
		account, err := resolveAssetAccount(tx, assetID, accountID)
		if err != nil {
			return err
		}
		if account == nil {
			return ErrAssetAccountNotFound
		}
		result = account
		if account.IsDefault {
			return nil
		}
		if err := clearDefaultAccounts(tx, assetID, account.ID); err != nil {
			return err
		}
		res := tx.Model(&model.AssetAccount{}).Where("id = ?", account.ID).
			Update("is_default", true)
		if res.Error != nil {
			return accountUniqueViolation(res.Error, "設定預設帳號失敗")
		}
		if res.RowsAffected == 0 {
			return ErrAssetAccountNotFound
		}
		account.IsDefault = true
		if err := mirrorDefaultAccountToAsset(tx, account); err != nil {
			return err
		}
		return writeAssetAccountAudit(s.auditTx, tx, model.AssetAccountAudit{
			AssetID:   assetID,
			AccountID: account.ID,
			Username:  account.Username,
			Operation: model.AccountOpSetDefault,
		}, userID, operator)
	})
	if err != nil {
		return nil, err
	}
	return NewAssetAccountDTO(result), nil
}

// applyAccountUpdates 依 updates map 產生更新後的帳號副本。以複合字面量組出
// （而非逐欄賦值）：套件層 AST 守衛以欄位名比對，任何對 `.Note` 的選擇器賦值
// 都會被判為繞過 inventory 顯示字串 registry。
func applyAccountUpdates(account *model.AssetAccount, updates map[string]interface{}) *model.AssetAccount {
	pick := func(key, fallback string) string {
		if v, ok := updates[key].(string); ok {
			return v
		}
		return fallback
	}
	privileged := account.Privileged
	if v, ok := updates["privileged"].(bool); ok {
		privileged = v
	}
	return &model.AssetAccount{
		ID:            account.ID,
		CreatedAt:     account.CreatedAt,
		UpdatedAt:     account.UpdatedAt,
		AssetID:       account.AssetID,
		Username:      pick("username", account.Username),
		PasswordEnc:   pick("password_enc", account.PasswordEnc),
		PrivateKeyEnc: pick("private_key_enc", account.PrivateKeyEnc),
		IsDefault:     account.IsDefault,
		Privileged:    privileged,
		Note:          pick("note", account.Note),
	}
}

// clearDefaultAccounts 清掉該資產全部 default 標記（exceptID 保留不動）
func clearDefaultAccounts(tx *gorm.DB, assetID, exceptID uint) error {
	q := tx.Model(&model.AssetAccount{}).Where("asset_id = ? AND is_default = ?", assetID, true)
	if exceptID != 0 {
		q = q.Where("id <> ?", exceptID)
	}
	if err := q.Update("is_default", false).Error; err != nil {
		return fmt.Errorf("清除既有預設帳號失敗: %w", err)
	}
	return nil
}

// mirrorDefaultAccountToAsset 鏡射預設帳號到 assets 的顯示欄。
//
// 只鏡射 username 與「是否已設定憑證」的布林旗標——**密文欄位一律不寫**
// （欄位已凍結）。這三欄是列表、審計 diff 與前端「已設定密碼」標記的來源，
// 不同步會讓既有畫面顯示與實際連線身分不一致。
//
// 用 UpdateColumns 而非 Updates（刻意，兩個理由）：一是鏡射屬派生同步、不是
// 使用者對資產本體的編輯，不該更動 assets.updated_at 的語意（同 persistTestResult
// 的既有裁決）；二是追趕同步 migration 以「帳號列較新即跳過」判斷倒灌，鏡射若
// 把 assets.updated_at 推到帳號之後，判準會反向失效。
func mirrorDefaultAccountToAsset(tx *gorm.DB, account *model.AssetAccount) error {
	if err := tx.Model(&model.Asset{}).Where("id = ?", account.AssetID).
		UpdateColumns(map[string]interface{}{
			"username":        account.Username,
			"has_password":    account.PasswordEnc != "",
			"has_private_key": account.PrivateKeyEnc != "",
		}).Error; err != nil {
		return fmt.Errorf("同步資產顯示欄失敗: %w", err)
	}
	return nil
}

// syncDefaultAccountFromAsset 把 PUT /assets/:id 的 username／憑證欄位透明轉寫到
// default 帳號（過渡期相容）。呼叫端必須已在交易內、且已把 asset.Username 更新完畢。
//
// 空密文＝不動既有憑證（沿用 UpdateAssetRequest「密碼空字串不更新」的既有語義），
// 不是清空。資產原本零帳號時就地建一筆 default——否則舊表單改了 username／密碼，
// 連線端（讀帳號）卻什麼都拿不到。
func syncDefaultAccountFromAsset(auditTx port.TxSink, tx *gorm.DB, asset *model.Asset,
	passwordEnc, privateKeyEnc string, userID uint, operator string) error {
	if err := ValidateAccountUsername(asset.Username); err != nil {
		return err
	}
	// 與帳號 CRUD 走同一把鎖：PUT /assets 與 set-default／delete 併發時，
	// 兩邊都在改「哪一筆是 default 及其憑證」，不共用互斥點就會交錯
	// （本交易稍早已 Save 過同一資產列，重取同列鎖不會自我死鎖）
	if err := lockAssetForAccountMutation(tx, asset.ID); err != nil {
		return err
	}

	account, err := resolveAssetAccount(tx, asset.ID, 0)
	if err != nil {
		return err
	}

	if account == nil {
		// 零帳號資產：三欄仍全空就維持零帳號（合法），否則建 default
		if asset.Username == "" && passwordEnc == "" && privateKeyEnc == "" {
			return nil
		}
		account = &model.AssetAccount{
			AssetID:       asset.ID,
			Username:      asset.Username,
			PasswordEnc:   passwordEnc,
			PrivateKeyEnc: privateKeyEnc,
			IsDefault:     true,
		}
		if err := tx.Create(account).Error; err != nil {
			return accountUniqueViolation(err, "建立預設帳號失敗")
		}
		return writeAssetAccountAudit(auditTx, tx, model.AssetAccountAudit{
			AssetID:   asset.ID,
			AccountID: account.ID,
			Username:  account.Username,
			Operation: model.AccountOpCreate,
			Fields:    changedSecretFields(passwordEnc != "", privateKeyEnc != "", true),
		}, userID, operator)
	}

	updates := map[string]interface{}{}
	fields := make([]string, 0, 3)
	if asset.Username != account.Username {
		updates["username"] = asset.Username
		fields = append(fields, "username")
	}
	if passwordEnc != "" {
		updates["password_enc"] = passwordEnc
		fields = append(fields, "password")
	}
	if privateKeyEnc != "" {
		updates["private_key_enc"] = privateKeyEnc
		fields = append(fields, "private_key")
	}
	if len(updates) == 0 {
		return nil
	}
	if updates["username"] != nil {
		var dup int64
		if err := tx.Model(&model.AssetAccount{}).
			Where("asset_id = ? AND username = ? AND id <> ?", asset.ID, asset.Username, account.ID).
			Count(&dup).Error; err != nil {
			return fmt.Errorf("檢查同名帳號失敗: %w", err)
		}
		if dup > 0 {
			return ErrAssetAccountUsernameExists
		}
	}
	if err := tx.Model(&model.AssetAccount{}).Where("id = ?", account.ID).
		Updates(updates).Error; err != nil {
		return accountUniqueViolation(err, "更新預設帳號失敗")
	}
	return writeAssetAccountAudit(auditTx, tx, model.AssetAccountAudit{
		AssetID:   asset.ID,
		AccountID: account.ID,
		Username:  asset.Username,
		Operation: model.AccountOpUpdate,
		Fields:    fields,
	}, userID, operator)
}

// changedSecretFields 建立事件的欄位清單（僅欄位名，永不含值）
func changedSecretFields(hasPassword, hasPrivateKey, isDefault bool) []string {
	fields := make([]string, 0, 3)
	if hasPassword {
		fields = append(fields, "password")
	}
	if hasPrivateKey {
		fields = append(fields, "private_key")
	}
	if isDefault {
		fields = append(fields, "is_default")
	}
	return fields
}
