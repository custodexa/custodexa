package asset

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/branding"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// 堡壘機專用帳號（執行身分）：平台代為執行管理工作時登入目標機的身分。
//
// 每台至多一筆未刪除的執行身分掛載（唯一索引），永不為預設、標為特權。它不進人員連線、
// 帳號列表、授權與申請路徑；本服務是設定、更換、清除、讀取與公鑰匯出的唯一入口。
//
// 寫入的鎖序沿掛載（Bind）：拓撲序列化鎖與範圍判定 → 資產列鎖 → 憑證列鎖（識別升冪）。
// 同一台的並行設定以 expected_account_id 比對當下狀態，不符回 ErrExecutorStateChanged，
// 不讓後到者把先到者的設定當成更換對象（遺失更新）。

// 執行身分的設定來源
const (
	ExecutorSourceGenerate = "generate"
	ExecutorSourceInline   = "inline"
	ExecutorSourceShared   = "shared"
	ExecutorSourceConvert  = "convert"
)

var (
	// ErrExecutorSourceInvalid 請求缺少來源、來源不明、缺 expected_account_id 或來源欄位不完整
	ErrExecutorSourceInvalid = errors.New("執行身分設定請求格式不正確")
	// ErrExecutorProtocolUnsupported 只有 ssh 與 rdp 資產可設定執行身分
	ErrExecutorProtocolUnsupported = errors.New("此資產協定不支援堡壘機專用帳號")
	// ErrExecutorSecretTypeUnsupported Windows 族資產不接受金鑰型執行身分（既連不上也輪替不了）
	ErrExecutorSecretTypeUnsupported = errors.New("此資產不支援以金鑰作為堡壘機專用帳號")
	// ErrExecutorStateChanged 送出時認定的執行身分與當下不符（已被他人設定、更換或清除）
	ErrExecutorStateChanged = errors.New("堡壘機專用帳號已被變更，請重新載入後再試")
	// ErrExecutorConvertCandidatePending 要轉換的帳號仍有未驗證的候選秘密
	ErrExecutorConvertCandidatePending = errors.New("此帳號仍有未驗證的候選秘密，請先收斂後再轉換")
	// ErrAssetExecutorNotFound 資產沒有執行身分
	ErrAssetExecutorNotFound = errors.New("此資產尚未設定堡壘機專用帳號")
	// ErrAssetExecutorPublicKeyNotFound 無可匯出的公鑰（非金鑰型、無公鑰或不可見，三者同形）
	ErrAssetExecutorPublicKeyNotFound = errors.New("此堡壘機專用帳號沒有可匯出的公鑰")
)

// ExecutorSharedHostCountError 共用來源的台數確認缺漏或不符；Count 為當下應確認的總台數（含本台）。
// 只帶台數，不帶任何資產識別或名稱。
type ExecutorSharedHostCountError struct {
	Count int
}

func (e *ExecutorSharedHostCountError) Error() string {
	return fmt.Sprintf("這組秘密設定後將在 %d 台主機上作為堡壘機專用帳號，請確認台數後再送出", e.Count)
}

// ExecutorScopePort 執行身分管理的範圍判定（消費者側窄介面）：主體對該資產持有執行身分管理能力。
// 範圍外與不存在回同一個不存在拒絕。
type ExecutorScopePort interface {
	AuthorizeExecutorManage(ctx context.Context, db *gorm.DB, assetID uint) error
}

// ErrExecutorScopePortMissing 範圍判定未注入：寧可拒絕，也不在沒有判定的情況下讀寫。
var ErrExecutorScopePortMissing = errors.New("asset: executor scope port not injected")

// SetExecutorRequest PUT 請求。ExpectedAccountID 必帶：0＝送出者認為目前沒有執行身分。
type SetExecutorRequest struct {
	Source                string `json:"source"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	PrivateKey            string `json:"private_key"`
	CredentialID          uint   `json:"credential_id"`
	AccountID             uint   `json:"account_id"`
	AcknowledgedHostCount *int   `json:"acknowledged_host_count"`
	ExpectedAccountID     *uint  `json:"expected_account_id"`
}

// AssetExecutorDTO 讀取與設定的回應。不含任何秘密與公鑰本體；未設定時只有 configured=false。
type AssetExecutorDTO struct {
	Configured bool   `json:"configured"`
	AccountID  uint   `json:"account_id,omitempty"`
	Username   string `json:"username,omitempty"`
	SecretType string `json:"secret_type,omitempty"`
	// HasPublicKey／Fingerprint 只在金鑰型、有公鑰且所引用憑證對主體可見時出現
	HasPublicKey *bool  `json:"has_public_key,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	// Source 設定來源（generate｜inline｜shared｜convert）；未記錄時整欄省略
	Source string `json:"source,omitempty"`
	// Row 執行身分的帳號列（完整版）。**不直接出站**（json:"-"）：對外的 credential 欄
	// 只經帳號列投影器換形（範圍外共用憑證只帶共用與範圍外標記）
	Row *AssetAccountDTO `json:"-"`
}

// AssetExecutorService 執行身分服務。共用帳號服務的加密、授權關卡與審計 sink。
type AssetExecutorService struct {
	accounts *AssetAccountService
	scope    ExecutorScopePort
	// credVisibility 共用憑證可見性（公鑰揭露用）；未注入時共用憑證一律不可見
	credVisibility ExecutorCredentialVisibility
	// setTxHook 測試接縫：設定交易內、取資產列鎖之前呼叫（並行測試以屏障讓兩筆同時進交易）
	setTxHook func()
}

// NewAssetExecutorService 組裝根建立。
func NewAssetExecutorService(accounts *AssetAccountService, scope ExecutorScopePort) *AssetExecutorService {
	return &AssetExecutorService{accounts: accounts, scope: scope}
}

// authorize 範圍判定（系統呼叫者略過）。
func (s *AssetExecutorService) authorize(ctx context.Context, db *gorm.DB, assetID uint) error {
	if isSystemCaller(ctx) {
		return nil
	}
	if s.scope == nil {
		return ErrExecutorScopePortMissing
	}
	return s.scope.AuthorizeExecutorManage(ctx, db, assetID)
}

// authorizeTx 寫入交易的第一個動作：取拓撲序列化鎖並判定（系統呼叫者略過）。
func (s *AssetExecutorService) authorizeTx(ctx context.Context, tx *gorm.DB, assetID uint) error {
	if isSystemCaller(ctx) {
		return nil
	}
	if err := s.accounts.assets.lockTopologyTx(tx); err != nil {
		return err
	}
	return s.authorize(ctx, tx, assetID)
}

// findExecutor 讀資產當下的執行身分掛載（無則 nil, nil）。
func findExecutor(db *gorm.DB, assetID uint) (*model.AssetAccount, error) {
	var rows []model.AssetAccount
	if err := db.Where("asset_id = ? AND purpose = ?", assetID, model.AccountPurposeExecutor).
		Limit(1).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢執行身分失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// executorDTO 組回應：秘密型別取所引用憑證。
func executorDTO(db *gorm.DB, a *model.AssetAccount) (*AssetExecutorDTO, error) {
	if a == nil {
		return &AssetExecutorDTO{Configured: false}, nil
	}
	var cred model.Credential
	if err := db.Select("id", "secret_type").Where("id = ?", a.CredentialID).First(&cred).Error; err != nil {
		return nil, fmt.Errorf("查詢執行身分憑證失敗: %w", err)
	}
	row, err := newAccountDTO(db, a)
	if err != nil {
		return nil, err
	}
	return &AssetExecutorDTO{Configured: true, AccountID: a.ID, Username: a.Username, SecretType: cred.SecretType,
		Source: a.ExecutorSource, Row: row}, nil
}

// Get 讀取執行身分。範圍外與不存在同形。
func (s *AssetExecutorService) Get(ctx context.Context, assetID uint) (*AssetExecutorDTO, error) {
	if _, err := s.accounts.assets.GetByID(assetID); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, database.DB, assetID); err != nil {
		return nil, err
	}
	exec, err := findExecutor(database.DB, assetID)
	if err != nil {
		return nil, err
	}
	dto, err := executorDTO(database.DB, exec)
	if err != nil {
		return nil, err
	}
	if err := s.fillPublicKeyView(ctx, dto, exec); err != nil {
		return nil, err
	}
	return dto, nil
}

// normalizeExecutorRequest 400 類格式檢查：來源與該來源必要欄位、expected_account_id 必帶。
func normalizeExecutorRequest(req *SetExecutorRequest) error {
	if req == nil || req.ExpectedAccountID == nil {
		return ErrExecutorSourceInvalid
	}
	switch req.Source {
	case ExecutorSourceGenerate:
		if req.Username == "" || req.Password != "" || req.PrivateKey != "" || req.CredentialID != 0 || req.AccountID != 0 {
			return ErrExecutorSourceInvalid
		}
	case ExecutorSourceInline:
		if req.Username == "" || (req.Password == "") == (req.PrivateKey == "") || req.CredentialID != 0 || req.AccountID != 0 {
			return ErrExecutorSourceInvalid
		}
	case ExecutorSourceShared:
		if req.CredentialID == 0 || req.Username != "" || req.Password != "" || req.PrivateKey != "" || req.AccountID != 0 {
			return ErrExecutorSourceInvalid
		}
	case ExecutorSourceConvert:
		if req.AccountID == 0 || req.Username != "" || req.Password != "" || req.PrivateKey != "" || req.CredentialID != 0 {
			return ErrExecutorSourceInvalid
		}
	default:
		return ErrExecutorSourceInvalid
	}
	return nil
}

// requireSourceCaps 依來源判憑證語義能力（只認語義鍵，相容鍵不放行）。db 為 nil＝交易外先判。
func (s *AssetExecutorService) requireSourceCaps(ctx context.Context, db *gorm.DB, req *SetExecutorRequest,
	assetID, convertCredentialID uint) error {

	if isSystemCaller(ctx) {
		return nil
	}
	r := CredentialManagementRequest{AssetIDs: []uint{assetID}}
	switch req.Source {
	case ExecutorSourceGenerate, ExecutorSourceInline:
		r.Operation, r.Capabilities = CredOpCreate, []string{CredCapCreate}
	case ExecutorSourceShared:
		r.Operation, r.Capabilities, r.CredentialIDs = CredOpBind, []string{CredCapBind}, []uint{req.CredentialID}
	case ExecutorSourceConvert:
		r.Operation, r.Capabilities = CredOpUpdate, []string{CredCapUpdate}
		if convertCredentialID != 0 {
			r.CredentialIDs = []uint{convertCredentialID}
		}
	}
	_, err := s.accounts.mgmt.require(ctx, db, r)
	return err
}

// preparedSecret 交易外先做的加密（純 CPU／可能觸及 KMS，不佔交易與資產鎖）。
type preparedSecret struct {
	passwordEnc   string
	privateKeyEnc string
	publicKey     string
}

func (s *AssetExecutorService) prepareSecret(ctx context.Context, req *SetExecutorRequest) (preparedSecret, error) {
	var out preparedSecret
	codec := s.accounts.crypto
	switch req.Source {
	case ExecutorSourceGenerate:
		private, line, err := GenerateSSHKeyPair(branding.Slug)
		if err != nil {
			return out, err
		}
		enc, err := codec.EncryptFor(ctx, keyvault.RefCredentialVersionPrivateKey, private)
		if err != nil {
			return out, fmt.Errorf("加密私鑰失敗: %w", err)
		}
		out.privateKeyEnc = enc
		// 只存金鑰本體（型別與 base64），comment 於匯出時依憑證識別產生
		fields := strings.Fields(line)
		out.publicKey = fields[0] + " " + fields[1]
	case ExecutorSourceInline:
		if req.Password != "" {
			enc, err := codec.EncryptFor(ctx, keyvault.RefCredentialVersionPassword, req.Password)
			if err != nil {
				return out, fmt.Errorf("加密密碼失敗: %w", err)
			}
			out.passwordEnc = enc
		}
		if req.PrivateKey != "" {
			enc, err := codec.EncryptFor(ctx, keyvault.RefCredentialVersionPrivateKey, req.PrivateKey)
			if err != nil {
				return out, fmt.Errorf("加密私鑰失敗: %w", err)
			}
			out.privateKeyEnc = enc
		}
	}
	return out, nil
}

// Set 設定或更換執行身分。
func (s *AssetExecutorService) Set(ctx context.Context, assetID uint, req *SetExecutorRequest) (*AssetExecutorDTO, error) {
	if _, err := s.accounts.assets.GetByID(assetID); err != nil {
		return nil, err
	}
	// 範圍外與不存在先於格式與能力判定回同一個不存在
	if err := s.authorize(ctx, database.DB, assetID); err != nil {
		return nil, err
	}
	if err := normalizeExecutorRequest(req); err != nil {
		return nil, err
	}
	if err := s.requireSourceCaps(ctx, nil, req, assetID, 0); err != nil {
		return nil, err
	}
	if req.Source == ExecutorSourceGenerate || req.Source == ExecutorSourceInline {
		if err := ValidateAccountUsername(req.Username); err != nil {
			return nil, err
		}
		if err := ValidatePrivateKey(req.PrivateKey); err != nil {
			return nil, err
		}
	}
	secret, err := s.prepareSecret(ctx, req)
	if err != nil {
		return nil, err
	}

	userID, operator := model.UserFromContext(ctx)
	var result *model.AssetAccount
	txErr := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.authorizeTx(ctx, tx, assetID); err != nil {
			return err
		}
		if s.setTxHook != nil {
			s.setTxHook()
		}
		if err := lockAssetForAccountMutation(tx, assetID); err != nil {
			return err
		}
		var asset model.Asset
		if err := tx.Where("id = ?", assetID).First(&asset).Error; err != nil {
			return fmt.Errorf("查詢資產失敗: %w", err)
		}
		if asset.Protocol != model.ProtocolSSH && asset.Protocol != model.ProtocolRDP {
			return ErrExecutorProtocolUnsupported
		}
		previous, err := findExecutor(tx, assetID)
		if err != nil {
			return err
		}
		var previousID uint
		if previous != nil {
			previousID = previous.ID
		}
		if *req.ExpectedAccountID != previousID {
			return ErrExecutorStateChanged
		}
		windows := model.ProtocolFamilyForAsset(&asset) == model.ProtocolFamilyWindows

		w := executorWrite{asset: &asset, previous: previous, req: req, secret: secret, windows: windows}
		var hostCount int
		switch req.Source {
		case ExecutorSourceGenerate, ExecutorSourceInline:
			result, err = s.setDedicated(ctx, tx, &w)
		case ExecutorSourceShared:
			result, hostCount, err = s.setShared(ctx, tx, &w)
		case ExecutorSourceConvert:
			result, err = s.setConvert(ctx, tx, &w)
		}
		if err != nil {
			return err
		}

		if err := tx.Model(&model.AssetAccount{}).Where("id = ?", result.ID).
			Update("executor_source", req.Source).Error; err != nil {
			return fmt.Errorf("記錄執行身分來源失敗: %w", err)
		}
		result.ExecutorSource = req.Source

		audit := model.AssetAccountAudit{
			AssetID:        assetID,
			AccountID:      result.ID,
			Username:       result.Username,
			Operation:      model.AccountOpExecutorSet,
			ExecutorSource: req.Source,
			HostCount:      hostCount,
		}
		if previous != nil {
			audit.Operation = model.AccountOpExecutorReplace
			audit.PreviousAccountID = previous.ID
			audit.PreviousCredentialID = previous.CredentialID
		}
		audit.CredentialID, audit.CredentialScope = credentialAuditRef(tx, result.CredentialID)
		return writeAssetAccountAudit(s.accounts.auditTx, tx, audit, userID, operator)
	})
	if txErr != nil {
		return nil, txErr
	}
	return executorDTO(database.DB, result)
}

// executorWrite 一次設定交易內的共用狀態（交易句柄另以參數傳遞，不存進結構）。
type executorWrite struct {
	asset    *model.Asset
	previous *model.AssetAccount
	req      *SetExecutorRequest
	secret   preparedSecret
	windows  bool
}

// removePrevious 更換時移除舊執行身分掛載並回收隨之孤兒的專用憑證（與帳號刪除同一組步驟）。
// 所引用憑證正在輪替時拒絕。
func removePrevious(tx *gorm.DB, previous *model.AssetAccount) error {
	if previous == nil {
		return nil
	}
	return removeExecutorBinding(tx, previous)
}

func removeExecutorBinding(tx *gorm.DB, binding *model.AssetAccount) error {
	creds, err := lockCredentialsForBindingRemoval(tx, []model.AssetAccount{*binding})
	if err != nil {
		return err
	}
	res := tx.Delete(&model.AssetAccount{}, binding.ID)
	if res.Error != nil {
		return fmt.Errorf("移除執行身分掛載失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrExecutorStateChanged
	}
	return reclaimDedicatedCredentials(tx, creds)
}

// assertUsernameAvailable 帳號名在這台未被佔用（憑證表與掛載列副本兩處）。exceptAccountID 為更換時
// 即將移除的舊執行身分掛載（不計入）；0＝不排除。
func assertUsernameAvailable(tx *gorm.DB, assetID uint, username string, exceptAccountID uint) error {
	if err := assertUsernameFreeOnAsset(tx, assetID, username, exceptAccountID); err != nil {
		return err
	}
	q := tx.Model(&model.AssetAccount{}).Where("asset_id = ? AND username = ?", assetID, username)
	if exceptAccountID != 0 {
		q = q.Where("id <> ?", exceptAccountID)
	}
	var dup int64
	if err := q.Count(&dup).Error; err != nil {
		return fmt.Errorf("檢查同名帳號失敗: %w", err)
	}
	if dup > 0 {
		return ErrAssetAccountUsernameExists
	}
	return nil
}

// assertCredentialNotBoundExcept 這筆憑證在這台沒有其他掛載（exceptAccountID 不計入；0＝不排除）。
func assertCredentialNotBoundExcept(tx *gorm.DB, assetID, credentialID, exceptAccountID uint) error {
	if exceptAccountID == 0 {
		return assertCredentialNotBound(tx, assetID, credentialID)
	}
	var dup int64
	if err := tx.Model(&model.AssetAccount{}).
		Where("asset_id = ? AND credential_id = ? AND id <> ?", assetID, credentialID, exceptAccountID).
		Count(&dup).Error; err != nil {
		return fmt.Errorf("檢查既有掛載失敗: %w", err)
	}
	if dup > 0 {
		return ErrCredentialBindingExists
	}
	return nil
}

// newExecutorBinding 新執行身分掛載的固定欄位。
func newExecutorBinding(assetID uint, username, authMethod string) *model.AssetAccount {
	return &model.AssetAccount{
		AssetID:    assetID,
		Username:   username,
		AuthMethod: authMethod,
		Purpose:    model.AccountPurposeExecutor,
		IsDefault:  false,
		Privileged: true,
	}
}

// setDedicated 平台產生金鑰或直填秘密：同交易建專用憑證與 v1。
func (s *AssetExecutorService) setDedicated(ctx context.Context, tx *gorm.DB, w *executorWrite) (*model.AssetAccount, error) {
	if err := s.requireSourceCaps(ctx, tx, w.req, w.asset.ID, 0); err != nil {
		return nil, err
	}
	if w.windows && w.secret.privateKeyEnc != "" {
		return nil, ErrExecutorSecretTypeUnsupported
	}
	if err := removePrevious(tx, w.previous); err != nil {
		return nil, err
	}
	if err := assertUsernameAvailable(tx, w.asset.ID, w.req.Username, 0); err != nil {
		return nil, err
	}
	account := newExecutorBinding(w.asset.ID, w.req.Username, "")
	reason := model.CredentialVersionReasonManual
	if w.req.Source == ExecutorSourceGenerate {
		reason = model.CredentialVersionReasonGenerated
	}
	// 公鑰與密文同列建立：版本列建立後不得就地覆寫（版本表只准新增）。
	var versionOpts []credentialVersionOption
	if w.secret.publicKey != "" {
		versionOpts = append(versionOpts, withVersionPublicKey(w.secret.publicKey))
	}
	if err := bindNewDedicatedCredential(tx, account, w.asset, "", w.secret.passwordEnc, w.secret.privateKeyEnc, reason,
		versionOpts...); err != nil {
		return nil, err
	}
	if err := tx.Create(account).Error; err != nil {
		return nil, executorUniqueViolation(err)
	}
	return account, nil
}

// setShared 選用共用憑證：沿掛載的檢查鏈，另加用途一致與台數確認。
func (s *AssetExecutorService) setShared(ctx context.Context, tx *gorm.DB, w *executorWrite) (*model.AssetAccount, int, error) {
	ids := []uint{w.req.CredentialID}
	if w.previous != nil && w.previous.CredentialID != 0 {
		ids = append(ids, w.previous.CredentialID)
	}
	locked, err := lockCredentialRowsOrdered(tx, ids...)
	if err != nil {
		return nil, 0, err
	}
	cred := locked[w.req.CredentialID]
	if cred == nil {
		return nil, 0, ErrCredentialNotFound
	}
	if err := s.requireSourceCaps(ctx, tx, w.req, w.asset.ID, 0); err != nil {
		return nil, 0, err
	}
	if err := assertNoActiveRotation(cred); err != nil {
		return nil, 0, err
	}
	if err := assertCredentialConverged(tx, cred); err != nil {
		return nil, 0, err
	}
	if cred.Scope != model.CredentialScopeShared {
		return nil, 0, ErrCredentialDedicatedSingleBinding
	}
	if err := assertProtocolFamilyMatch(cred, w.asset); err != nil {
		return nil, 0, err
	}
	if w.windows && cred.SecretType == model.ChangeSecretTypeSSHKey {
		return nil, 0, ErrExecutorSecretTypeUnsupported
	}
	if err := assertCredentialPurpose(tx, cred.ID, model.AccountPurposeExecutor); err != nil {
		return nil, 0, err
	}
	// 未重複掛、帳號名未佔用先於台數確認（不讓使用者先確認台數、送出後才被拒）。
	// 更換時舊執行身分掛載即將移除，不計入（同一筆憑證重新設定照樣可行）。
	var except uint
	if w.previous != nil {
		except = w.previous.ID
	}
	if err := assertCredentialNotBoundExcept(tx, w.asset.ID, cred.ID, except); err != nil {
		return nil, 0, err
	}
	if err := assertUsernameAvailable(tx, w.asset.ID, cred.Username, except); err != nil {
		return nil, 0, err
	}
	// 台數：設定後這組秘密作為執行身分的總台數（含本台）。舊掛載引用同一筆憑證時不加一
	var live int64
	if err := tx.Model(&model.AssetAccount{}).
		Where("credential_id = ? AND purpose = ?", cred.ID, model.AccountPurposeExecutor).
		Count(&live).Error; err != nil {
		return nil, 0, fmt.Errorf("計算共用台數失敗: %w", err)
	}
	count := int(live) + 1
	if w.previous != nil && w.previous.CredentialID == cred.ID {
		count = int(live)
	}
	if w.req.AcknowledgedHostCount == nil || *w.req.AcknowledgedHostCount != count {
		return nil, 0, &ExecutorSharedHostCountError{Count: count}
	}
	if err := removePrevious(tx, w.previous); err != nil {
		return nil, 0, err
	}
	account := newExecutorBinding(w.asset.ID, cred.Username, cred.AuthMethod)
	account.CredentialID = cred.ID
	account.EffectiveVersionID = cred.CurrentVersionID
	if err := tx.Create(account).Error; err != nil {
		return nil, 0, executorUniqueViolation(err)
	}
	return account, count, nil
}

// setConvert 把這台既有的登入帳號就地轉為執行身分。
func (s *AssetExecutorService) setConvert(ctx context.Context, tx *gorm.DB, w *executorWrite) (*model.AssetAccount, error) {
	var target model.AssetAccount
	err := tx.Where("id = ? AND asset_id = ?", w.req.AccountID, w.asset.ID).First(&target).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAssetAccountNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查詢資產帳號失敗: %w", err)
	}
	if err := s.requireSourceCaps(ctx, tx, w.req, w.asset.ID, target.CredentialID); err != nil {
		return nil, err
	}
	if target.Purpose != model.AccountPurposeLogin {
		return nil, ErrAssetAccountNotFound
	}
	if target.IsDefault {
		return nil, ErrAssetAccountDefaultRequired
	}
	ids := []uint{target.CredentialID}
	if w.previous != nil && w.previous.CredentialID != 0 {
		ids = append(ids, w.previous.CredentialID)
	}
	locked, err := lockCredentialRowsOrdered(tx, ids...)
	if err != nil {
		return nil, err
	}
	cred := locked[target.CredentialID]
	if cred == nil {
		return nil, ErrBindingWithoutCredential
	}
	if cred.Scope != model.CredentialScopeDedicated {
		return nil, ErrCredentialPurposeMismatch
	}
	if err := assertNoActiveRotation(cred); err != nil {
		return nil, err
	}
	if err := assertCredentialConverged(tx, cred); err != nil {
		return nil, err
	}
	var pending int64
	if err := tx.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", target.ID).
		Count(&pending).Error; err != nil {
		return nil, fmt.Errorf("查詢候選秘密失敗: %w", err)
	}
	if pending > 0 {
		return nil, ErrExecutorConvertCandidatePending
	}
	if w.windows && cred.SecretType == model.ChangeSecretTypeSSHKey {
		return nil, ErrExecutorSecretTypeUnsupported
	}
	if err := removePrevious(tx, w.previous); err != nil {
		return nil, err
	}
	if err := tx.Model(&model.AssetAccount{}).Where("id = ?", target.ID).
		Updates(map[string]any{"purpose": model.AccountPurposeExecutor, "privileged": true}).Error; err != nil {
		return nil, executorUniqueViolation(err)
	}
	target.Purpose = model.AccountPurposeExecutor
	target.Privileged = true
	return &target, nil
}

// executorUniqueViolation 唯一索引衝突：同台第二筆執行身分（並行設定）歸為狀態已變，
// 同名歸為帳號名已佔用，其餘原樣包裝。
func executorUniqueViolation(err error) error {
	if !dberr.IsUniqueViolation(err) {
		return fmt.Errorf("寫入執行身分失敗: %w", err)
	}
	if strings.Contains(err.Error(), "idx_asset_accounts_executor") {
		return ErrExecutorStateChanged
	}
	return accountUniqueViolation(err, "寫入執行身分失敗")
}

// Clear 清除執行身分：移除掛載並回收專用憑證。平台不動目標機上的帳號或金鑰。
//
// expectedAccountID 與 PUT 同語義：nil＝不比對；0＝送出者認定目前沒有（此時已有執行身分回狀態已變）；
// 其餘＝送出者認定的執行身分識別，與當下不符回狀態已變。
func (s *AssetExecutorService) Clear(ctx context.Context, assetID uint, expectedAccountID *uint) error {
	if _, err := s.accounts.assets.GetByID(assetID); err != nil {
		return err
	}
	if err := s.authorize(ctx, database.DB, assetID); err != nil {
		return err
	}
	userID, operator := model.UserFromContext(ctx)
	return database.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.authorizeTx(ctx, tx, assetID); err != nil {
			return err
		}
		if err := lockAssetForAccountMutation(tx, assetID); err != nil {
			return err
		}
		exec, err := findExecutor(tx, assetID)
		if err != nil {
			return err
		}
		var currentID uint
		if exec != nil {
			currentID = exec.ID
		}
		if expectedAccountID != nil && *expectedAccountID != currentID {
			return ErrExecutorStateChanged
		}
		if exec == nil {
			return ErrAssetExecutorNotFound
		}
		credID, credScope := credentialAuditRef(tx, exec.CredentialID)
		if err := removeExecutorBinding(tx, exec); err != nil {
			return err
		}
		return writeAssetAccountAudit(s.accounts.auditTx, tx, model.AssetAccountAudit{
			AssetID:         assetID,
			AccountID:       exec.ID,
			Username:        exec.Username,
			Operation:       model.AccountOpExecutorClear,
			CredentialID:    credID,
			CredentialScope: credScope,
		}, userID, operator)
	})
}
