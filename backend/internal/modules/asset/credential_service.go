package asset

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
)

// 憑證的管理面：建立、更新、列表與詳情、範圍轉換、刪除。
//
// # 憑證與掛載的分工
//
// 憑證持有「這組秘密是誰、長什麼樣」——登入帳號名、秘密型別、認證方式、協定族；
// 掛載列持有「哪台主機以它登入」——資產、是否預設、是否特權、該台當下的就位版本。
// 特權標記刻意留在掛載列：同一組秘密在不同主機上的特權性可以不同，存進憑證會讓
// 一台機器上的分類錯誤擴散到全部成員。
//
// # 兩種範圍的生滅語義不同
//
// 專用憑證恰有一個掛載，隨掛載建立與刪除（同一交易），名稱為 NULL、顯示名由
// 「資產名 / 帳號名」計算；共用憑證具名、可掛多台，是整組輪替的對象。
// 兩者之間的轉換一律是顯式操作，不因卸載到剩一個掛載就自動發生——自動轉換會讓
// 「這組秘密還共用嗎」這個問題的答案在管理者沒有下過任何指令時改變。
//
// # 為什麼共用憑證的帳號名不可改
//
// 「同一資產上同一登入帳號名只掛一次」是掛載列的不變式，而共用憑證掛在 N 台上，
// 改名要在 N 台各自重驗一次不撞名；任一台撞名時，改名要嘛整筆失敗（於是管理者
// 面對一個沒有指出是哪一台的錯誤），要嘛部分成立（於是同一組秘密在不同機器上叫
// 不同名字，那已經不是同一個身分了）。專用憑證恰有一個掛載，沒有這個問題，故可改。

// 憑證名稱長度上限，與 model 的 size:128 同源。
const credentialNameMaxLen = 128

var (
	// ErrCredentialNameRequired 共用憑證必須具名（對應 VALIDATION_CREDENTIAL_NAME_REQUIRED）
	ErrCredentialNameRequired = errors.New("共用憑證必須提供名稱")
	// ErrCredentialNameTooLong 逾 model 欄位長度（VALIDATION_CREDENTIAL_NAME_TOO_LONG）
	ErrCredentialNameTooLong = errors.New("憑證名稱超過長度上限（128 字元）")
	// ErrCredentialNameInvalid 名稱含控制字元（VALIDATION_CREDENTIAL_NAME_INVALID）。
	// 與帳號名同一威脅面：名稱會進審計快照與稽核報告，ESC 序列可操縱讀 log 的終端
	ErrCredentialNameInvalid = errors.New("憑證名稱不得含換行或控制字元")
	// ErrCredentialNameExists 同名共用憑證已存在（CONFLICT_CREDENTIAL_NAME）。
	// 唯一性只在未軟刪的共用憑證之間成立：軟刪後名稱立即可被重用
	ErrCredentialNameExists = errors.New("已有同名的共用憑證")
	// ErrCredentialUsernameImmutable 共用憑證的登入帳號名建立後不可改
	// （VALIDATION_CREDENTIAL_USERNAME_IMMUTABLE）
	ErrCredentialUsernameImmutable = errors.New("共用憑證的登入帳號名建立後不可修改，請另建憑證並重新掛載")
	// ErrCredentialScopeInvalid 範圍值域外（VALIDATION_CREDENTIAL_SCOPE_INVALID）
	ErrCredentialScopeInvalid = errors.New("憑證範圍僅允許 dedicated 或 shared")
	// ErrCredentialSecretTypeInvalid 秘密型別值域外（VALIDATION_CREDENTIAL_SECRET_TYPE_INVALID）
	ErrCredentialSecretTypeInvalid = errors.New("秘密型別僅允許 password 或 ssh_key")
	// ErrCredentialSecretRequired 建立憑證未提供任何秘密（VALIDATION_CREDENTIAL_SECRET_REQUIRED）
	ErrCredentialSecretRequired = errors.New("建立共用憑證必須提供密碼或私鑰")
	// ErrCredentialProtocolFamilyInvalid 協定族值域外
	ErrCredentialProtocolFamilyInvalid = errors.New("協定族不在值域內")
	// ErrCredentialInUse 仍有掛載時拒刪（RULE_CREDENTIAL_IN_USE）。
	// 掛載資產名單以 CredentialInUseError 帶回，僅具憑證管理權限者看得到
	ErrCredentialInUse = errors.New("憑證仍被資產掛載，請先卸載後再刪除")
	// ErrCredentialHasPendingCandidate 仍有未決候選秘密時拒刪：
	// 候選是「已下達遠端、尚未驗證」的秘密，刪掉憑證即失去把它提交回來的去處
	ErrCredentialHasPendingCandidate = errors.New("憑證仍有未決的候選秘密，請先收斂後再刪除")
	// ErrCredentialRotationActive 輪替進行中的衝突操作（RULE_CREDENTIAL_ROTATION_ACTIVE）
	ErrCredentialRotationActive = errors.New("憑證的改密進行中，暫不接受此操作")
	// ErrCredentialSharedRequiresName 轉共用未提供名稱（RULE_CREDENTIAL_SHARED_REQUIRES_NAME）
	ErrCredentialSharedRequiresName = errors.New("轉為共用憑證必須提供名稱")
	// ErrCredentialToDedicatedMultiBinding 多掛載不可轉專用
	// （RULE_CREDENTIAL_TO_DEDICATED_MULTI_BINDING）
	ErrCredentialToDedicatedMultiBinding = errors.New("憑證掛載於多個資產，不可轉為專用")
	// ErrCredentialToDedicatedNoBinding 零掛載不可轉專用
	// （RULE_CREDENTIAL_TO_DEDICATED_NO_BINDING）。專用憑證的顯示名由它唯一的掛載
	// 算出，零掛載轉專用會產生一筆沒有顯示名、沒有人能用、也沒有掛載可以把它帶走的
	// 憑證；零掛載的共用憑證要的是刪除，不是換範圍
	ErrCredentialToDedicatedNoBinding = errors.New("憑證沒有任何掛載，不可轉為專用")
)

// CredentialInUseError 憑證仍有掛載時的拒刪結果，帶回掛載該憑證的資產名單。
//
// **包著 ErrCredentialInUse**（`errors.Is` 對只看哨兵的呼叫端仍成立），只多帶名單：
// 沒有名單，管理者面對的就是一句「還有人在用」而無從下手；名單本身是共用拓撲的
// 一部分，故只對具憑證管理權限者回傳（路由層授權點承擔可見性）。
type CredentialInUseError struct {
	Assets []string
}

func (e *CredentialInUseError) Error() string { return ErrCredentialInUse.Error() }

func (e *CredentialInUseError) Unwrap() error { return ErrCredentialInUse }

// CreateCredentialRequest 建立共用憑證（憑證庫「新增」與資產表單的就地新建共用皆走此）。
type CreateCredentialRequest struct {
	Name           string `json:"name"`
	Username       string `json:"username"`
	SecretType     string `json:"secret_type"`
	AuthMethod     string `json:"auth_method"`
	ProtocolFamily string `json:"protocol_family"`
	Note           string `json:"note"`
	Password       string `json:"password"`
	PrivateKey     string `json:"private_key"`
}

// UpdateCredentialRequest 更新憑證（nil＝不動）。
//
// Username 對共用憑證一律拒絕；對專用憑證允許，並於其唯一掛載所屬的資產內重驗
// 不撞名，同時同步掛載列上過渡期的顯示副本。
type UpdateCredentialRequest struct {
	Name     *string `json:"name"`
	Note     *string `json:"note"`
	Username *string `json:"username"`
}

// ConvertCredentialScopeRequest 範圍轉換：轉共用時 Name 必填。
type ConvertCredentialScopeRequest struct {
	Scope string `json:"scope"`
	Name  string `json:"name"`
}

// CredentialFilter 列表過濾條件（空字串＝該條件不生效）。
type CredentialFilter struct {
	Scope    string
	Username string
	Search   string
	// SecretType 秘密型別（password｜ssh_key）；值域外回 ErrCredentialSecretTypeInvalid
	SecretType string
	// ProtocolFamily 協定族；值域外回 ErrCredentialProtocolFamilyInvalid。
	//
	// 呼叫端不直接給族別，而是給「資產協定＋Windows OpenSSH 開關」由接入層以
	// model.ProtocolFamilyForAsset 推導後填入此欄——族別是協定與改密通道共同決定的
	// 計算值，讓呼叫端自己算會在通道規則改變時開始說謊。
	ProtocolFamily string
}

// CredentialService 憑證的管理面服務。
//
// 與 AssetAccountService 共用同一個 codec 實例（由組裝根注入）：兩份 codec 會讓
// 憑證在管理員沒察覺時走不同的加密路徑，寫得進去卻讀不回來。
type CredentialService struct {
	assets  *AssetService
	crypto  crypto.ColumnCodec
	authz   assetViewPermissionChecker
	auditTx port.TxSink
}

// NewCredentialService 建立憑證服務。codec SHALL 與 assets 用同一個實例。
func NewCredentialService(assets *AssetService, codec crypto.ColumnCodec, auditTx port.TxSink) *CredentialService {
	return &CredentialService{assets: assets, crypto: codec, auditTx: auditTx}
}

// WithAuthorization 注入資產可見性判定（受影響資產的權限檢核，檢核面見
// credential_binding.go 檔頭）。
func (s *CredentialService) WithAuthorization(authz assetViewPermissionChecker) *CredentialService {
	s.authz = authz
	return s
}

// ValidateCredentialName 憑證名稱驗證。
//
// 拒全部 C0/C1 控制字元與 DEL，理由同帳號名：名稱會進審計快照、稽核報告與 UI，
// ESC 序列可操縱讀 log 的終端。空字串於此視為合法（共用必填由呼叫端另行判定），
// 使「沒有名稱」與「名稱寫壞了」兩件事分開回應。
func ValidateCredentialName(name string) error {
	for _, r := range name {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return ErrCredentialNameInvalid
		}
	}
	if len([]rune(name)) > credentialNameMaxLen {
		return ErrCredentialNameTooLong
	}
	return nil
}

// Create 建立一筆共用憑證與其 v1 密文版本（零掛載）。
//
// **密文屬操作者宣告**：管理者在此輸入的秘密表達的是「遠端現況就是這樣」，故同一
// 交易把憑證的現行版本指向 v1。這不宣稱該秘密在任何主機上有效——憑證此刻零掛載，
// 有效與否由第一次掛載後的連線或改密揭露。
func (s *CredentialService) Create(ctx context.Context, req *CreateCredentialRequest) (*CredentialDTO, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, ErrCredentialNameRequired
	}
	if err := ValidateCredentialName(name); err != nil {
		return nil, err
	}
	if err := ValidateAccountUsername(req.Username); err != nil {
		return nil, err
	}
	if err := validateAccountNote(req.Note); err != nil {
		return nil, err
	}
	authMethod, err := normalizeAccountAuthMethod(req.AuthMethod)
	if err != nil {
		return nil, err
	}
	if !model.IsProtocolFamily(req.ProtocolFamily) {
		return nil, ErrCredentialProtocolFamilyInvalid
	}
	if req.SecretType != "" && req.SecretType != model.ChangeSecretTypePassword &&
		req.SecretType != model.ChangeSecretTypeSSHKey {
		return nil, ErrCredentialSecretTypeInvalid
	}
	if req.Password == "" && req.PrivateKey == "" {
		return nil, ErrCredentialSecretRequired
	}

	// 加密在交易外先做（純 CPU／可能觸及 KMS，不佔 DB 交易）
	var passwordEnc, privateKeyEnc string
	if req.Password != "" {
		enc, eerr := s.crypto.EncryptFor(ctx, keyvault.RefCredentialVersionPassword, req.Password)
		if eerr != nil {
			return nil, fmt.Errorf("加密密碼失敗: %w", eerr)
		}
		passwordEnc = enc
	}
	if req.PrivateKey != "" {
		enc, eerr := s.crypto.EncryptFor(ctx, keyvault.RefCredentialVersionPrivateKey, req.PrivateKey)
		if eerr != nil {
			return nil, fmt.Errorf("加密私鑰失敗: %w", eerr)
		}
		privateKeyEnc = enc
	}
	secretType := credentialSecretTypeFor(passwordEnc != "", privateKeyEnc != "")
	if req.SecretType != "" {
		secretType = req.SecretType
	}

	userID, operator := model.UserFromContext(ctx)
	cred := &model.Credential{
		Name:           &name,
		Scope:          model.CredentialScopeShared,
		Username:       req.Username,
		SecretType:     secretType,
		AuthMethod:     authMethod,
		ProtocolFamily: req.ProtocolFamily,
		Note:           req.Note,
	}
	txErr := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := assertSharedNameFree(tx, name, 0); err != nil {
			return err
		}
		if err := tx.Create(cred).Error; err != nil {
			return credentialUniqueViolation(err, "建立憑證失敗")
		}
		version, verr := appendCredentialVersion(tx, cred.ID, secretType,
			passwordEnc, privateKeyEnc, model.CredentialVersionReasonManual)
		if verr != nil {
			return verr
		}
		if err := setCredentialCurrentVersion(tx, cred.ID, version.ID); err != nil {
			return err
		}
		cred.CurrentVersionID = &version.ID
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    model.AccountOpCreate,
			Scope:        cred.Scope,
			Fields:       changedSecretFields(passwordEnc != "", privateKeyEnc != "", false),
		}, userID, operator)
	})
	if txErr != nil {
		return nil, txErr
	}
	return s.credentialDTO(database.DB, cred)
}

// Update 更新憑證的名稱、備註與（僅專用憑證的）登入帳號名。
//
// 秘密不在此更動：變更秘密一律產生新版本，走專屬的寫入路徑。
func (s *CredentialService) Update(ctx context.Context, id uint, req *UpdateCredentialRequest) (*CredentialDTO, error) {
	if req.Name != nil {
		if err := ValidateCredentialName(strings.TrimSpace(*req.Name)); err != nil {
			return nil, err
		}
	}
	if req.Note != nil {
		if err := validateAccountNote(*req.Note); err != nil {
			return nil, err
		}
	}
	if req.Username != nil {
		if err := ValidateAccountUsername(*req.Username); err != nil {
			return nil, err
		}
	}

	userID, operator := model.UserFromContext(ctx)
	var result *model.Credential
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		// **全域鎖次序＝先資產列、後憑證列**（見 credential_binding.go 檔頭）。
		// 改名要同步掛載列上的帳號名副本，那是資產帳號集合的寫入，故受影響資產的
		// 列鎖必須在憑證列鎖之前取得；只有改名路徑會動到掛載，其餘欄位不必取
		if req.Username != nil {
			if err := lockAssetsOfCredential(tx, id); err != nil {
				return err
			}
		}
		cred, err := lockCredentialRow(tx, id)
		if err != nil {
			return err
		}
		if err := assertNoActiveRotation(cred); err != nil {
			return err
		}

		updates := map[string]interface{}{}
		fields := make([]string, 0, 3)

		if req.Name != nil {
			name := strings.TrimSpace(*req.Name)
			if cred.Scope == model.CredentialScopeShared {
				if name == "" {
					return ErrCredentialNameRequired
				}
				if cred.Name == nil || *cred.Name != name {
					if err := assertSharedNameFree(tx, name, cred.ID); err != nil {
						return err
					}
					updates["name"] = name
					fields = append(fields, "name")
				}
			}
			// 專用憑證的名稱是計算值：送來的名稱一律忽略，不落庫、不報錯——
			// 前端把整份表單回填送回時不該因為一個唯讀欄位而整筆失敗
		}
		if req.Note != nil && *req.Note != cred.Note {
			updates["note"] = *req.Note
			fields = append(fields, "note")
		}
		if req.Username != nil && *req.Username != cred.Username {
			if cred.Scope == model.CredentialScopeShared {
				return ErrCredentialUsernameImmutable
			}
			if err := s.renameDedicatedCredential(tx, cred, *req.Username); err != nil {
				return err
			}
			updates["username"] = *req.Username
			fields = append(fields, "username")
		}
		if len(updates) == 0 {
			result = cred
			return nil
		}
		res := tx.Model(&model.Credential{}).Where("id = ?", cred.ID).Updates(updates)
		if res.Error != nil {
			return credentialUniqueViolation(res.Error, "更新憑證失敗")
		}
		if res.RowsAffected == 0 {
			// 交易內重讀後仍零列＝該列於本交易可見範圍外被移除，寧可回錯不假成功
			return ErrCredentialNotFound
		}
		var reloaded model.Credential
		if err := tx.Where("id = ?", cred.ID).First(&reloaded).Error; err != nil {
			return fmt.Errorf("重讀憑證失敗: %w", err)
		}
		result = &reloaded
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    model.AccountOpUpdate,
			Scope:        cred.Scope,
			Fields:       fields,
		}, userID, operator)
	})
	if err != nil {
		return nil, err
	}
	return s.credentialDTO(database.DB, result)
}

// renameDedicatedCredential 專用憑證改名：於其唯一掛載所屬的資產內重驗不撞名，
// 並同步掛載列上過渡期的帳號名副本。
//
// 撞名判定在**資產列鎖之內**——「同資產同帳號名只掛一次」是跨表條件，DB 層沒有
// 單一唯一鍵表達得了它，序列化的責任在服務層。
//
// 此處的資產列鎖是**再取一次**：呼叫端已在取憑證列鎖之前先鎖過同一批資產
// （lockAssetsOfCredential），全域鎖次序由那一步保證；同一交易內重取同一列是無操作。
func (s *CredentialService) renameDedicatedCredential(tx *gorm.DB, cred *model.Credential, username string) error {
	var bindings []model.AssetAccount
	if err := tx.Where("credential_id = ?", cred.ID).Find(&bindings).Error; err != nil {
		return fmt.Errorf("查詢憑證掛載失敗: %w", err)
	}
	for i := range bindings {
		b := &bindings[i]
		if err := lockAssetForAccountMutation(tx, b.AssetID); err != nil {
			return err
		}
		if err := assertUsernameFreeOnAsset(tx, b.AssetID, username, b.ID); err != nil {
			return err
		}
		if err := tx.Model(&model.AssetAccount{}).Where("id = ?", b.ID).
			Update("username", username).Error; err != nil {
			return accountUniqueViolation(err, "同步掛載帳號名失敗")
		}
	}
	return nil
}

// List 列出憑證（範圍、秘密型別、帳號名、顯示名搜尋）。
//
// 搜尋比對的是**畫面上看得到的那個名字**：共用憑證是落庫的名稱，專用憑證是
// 「資產名 / 帳號名」的計算值。後者的 name 欄是空的，只比對 name 會讓每一筆專用
// 憑證都搜不到，而搜不到不會有任何錯誤——使用者只會以為那筆憑證不存在。
func (s *CredentialService) List(_ context.Context, filter CredentialFilter) ([]*CredentialDTO, error) {
	q := database.DB.Model(&model.Credential{})
	if filter.Scope != "" {
		if !model.IsCredentialScope(filter.Scope) {
			return nil, ErrCredentialScopeInvalid
		}
		q = q.Where("scope = ?", filter.Scope)
	}
	if filter.SecretType != "" {
		if filter.SecretType != model.ChangeSecretTypePassword &&
			filter.SecretType != model.ChangeSecretTypeSSHKey {
			return nil, ErrCredentialSecretTypeInvalid
		}
		q = q.Where("secret_type = ?", filter.SecretType)
	}
	if filter.ProtocolFamily != "" {
		if !model.IsProtocolFamily(filter.ProtocolFamily) {
			return nil, ErrCredentialProtocolFamilyInvalid
		}
		q = q.Where("protocol_family = ?", filter.ProtocolFamily)
	}
	if filter.Username != "" {
		q = q.Where("username = ?", filter.Username)
	}
	if filter.Search != "" {
		pattern := "%" + strings.ToLower(filter.Search) + "%"
		q = q.Where(`LOWER(credentials.name) LIKE ? OR LOWER(credentials.username) LIKE ?
			OR (credentials.scope = ? AND credentials.id IN (
				SELECT aa.credential_id FROM asset_accounts aa
				JOIN assets a ON a.id = aa.asset_id AND a.deleted_at IS NULL
				WHERE aa.deleted_at IS NULL AND LOWER(a.name) LIKE ?))`,
			pattern, pattern, model.CredentialScopeDedicated, pattern)
	}
	var creds []model.Credential
	if err := q.Order("scope ASC, username ASC, id ASC").Find(&creds).Error; err != nil {
		return nil, fmt.Errorf("查詢憑證失敗: %w", err)
	}
	out := make([]*CredentialDTO, 0, len(creds))
	for i := range creds {
		dto, err := s.credentialDTO(database.DB, &creds[i])
		if err != nil {
			return nil, err
		}
		out = append(out, dto)
	}
	return out, nil
}

// Get 憑證詳情：基本資料＋掛載清單（每台帶其就位版本與特權標記）。
func (s *CredentialService) Get(_ context.Context, id uint) (*CredentialDetailDTO, error) {
	cred, err := loadCredential(database.DB, id)
	if err != nil {
		return nil, err
	}
	base, err := s.credentialDTO(database.DB, cred)
	if err != nil {
		return nil, err
	}
	bindings, err := credentialBindingDTOs(database.DB, cred)
	if err != nil {
		return nil, err
	}
	return &CredentialDetailDTO{CredentialDTO: *base, Bindings: bindings}, nil
}

// ConvertScope 顯式的範圍轉換。
//
// 兩個方向都**不動任何密文版本、就位版本與遠端主機**：範圍講的是「這組秘密被幾台
// 機器共用」，改變的是管理語義而不是秘密本身。轉換後各掛載仍以轉換前的就位版本連線。
func (s *CredentialService) ConvertScope(ctx context.Context, id uint, req *ConvertCredentialScopeRequest) (*CredentialDTO, error) {
	if !model.IsCredentialScope(req.Scope) {
		return nil, ErrCredentialScopeInvalid
	}
	name := strings.TrimSpace(req.Name)
	if req.Scope == model.CredentialScopeShared {
		if name == "" {
			return nil, ErrCredentialSharedRequiresName
		}
		if err := ValidateCredentialName(name); err != nil {
			return nil, err
		}
	}

	userID, operator := model.UserFromContext(ctx)
	var result *model.Credential
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		cred, err := lockCredentialRow(tx, id)
		if err != nil {
			return err
		}
		if err := assertNoActiveRotation(cred); err != nil {
			return err
		}
		// 範圍轉換改的是整組的管理語義，後果落在全部掛載上：逐台驗權
		if err := s.assertBoundAssetsPermission(ctx, tx, cred.ID); err != nil {
			return err
		}
		if cred.Scope == req.Scope {
			result = cred
			return nil
		}

		updates := map[string]interface{}{"scope": req.Scope}
		switch req.Scope {
		case model.CredentialScopeShared:
			if err := assertSharedNameFree(tx, name, cred.ID); err != nil {
				return err
			}
			updates["name"] = name
		default:
			// 專用憑證**恰有一個**掛載：多掛載與零掛載都不成立。判定寫成
			// 「不是多掛載就放行」會讓零掛載那一格靜默通過，而它產出的是一筆
			// 沒有顯示名也沒有人能用的憑證——那一格在畫面上看不出任何差別
			count, cerr := credentialBindingCount(tx, cred.ID)
			if cerr != nil {
				return cerr
			}
			if count > 1 {
				return ErrCredentialToDedicatedMultiBinding
			}
			if count == 0 {
				return ErrCredentialToDedicatedNoBinding
			}
			// 專用憑證的名稱是計算值，同交易清空——留著舊名會讓顯示名有兩個來源
			updates["name"] = nil
		}
		res := tx.Model(&model.Credential{}).Where("id = ?", cred.ID).Updates(updates)
		if res.Error != nil {
			return credentialUniqueViolation(res.Error, "轉換憑證範圍失敗")
		}
		if res.RowsAffected == 0 {
			return ErrCredentialNotFound
		}
		var reloaded model.Credential
		if err := tx.Where("id = ?", cred.ID).First(&reloaded).Error; err != nil {
			return fmt.Errorf("重讀憑證失敗: %w", err)
		}
		result = &reloaded
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    credentialOpScope,
			Scope:        req.Scope,
			Fields:       []string{"scope"},
		}, userID, operator)
	})
	if err != nil {
		return nil, err
	}
	return s.credentialDTO(database.DB, result)
}

// SetCredentialSecretRequest 對既有憑證直接寫入新密文（補登遠端現況用）。
type SetCredentialSecretRequest struct {
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
}

// SetSecret 直接寫入新密文：建立一筆新版本並立即生效，**不觸碰遠端**。
//
// 這是操作者宣告的密文——他說的是「這組秘密現在長這樣」，那句話的射程是整組，
// 故同一交易把憑證的現行版本與**全部掛載**的就位版本一併指向新版本。只改其中
// 一台會讓其餘各台停在舊版，而畫面上看不出任何差別。
//
// 未被本次更動的那一欄自現行版本原樣帶過來（密文原樣搬、不解密）：只補登密碼
// 不得順手清掉私鑰——使用者的操作裡沒有任何一步表達過這個意思。
func (s *CredentialService) SetSecret(ctx context.Context, id uint, req *SetCredentialSecretRequest) (*CredentialDTO, error) {
	if req == nil || (req.Password == "" && req.PrivateKey == "") {
		return nil, ErrCredentialSecretRequired
	}
	var passwordEnc, privateKeyEnc string
	if req.Password != "" {
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefCredentialVersionPassword, req.Password)
		if err != nil {
			return nil, fmt.Errorf("加密密碼失敗: %w", err)
		}
		passwordEnc = enc
	}
	if req.PrivateKey != "" {
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefCredentialVersionPrivateKey, req.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("加密私鑰失敗: %w", err)
		}
		privateKeyEnc = enc
	}

	userID, operator := model.UserFromContext(ctx)
	var result *model.Credential
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		cred, err := lockCredentialRow(tx, id)
		if err != nil {
			return err
		}
		if err := assertNoActiveRotation(cred); err != nil {
			return err
		}
		// 操作者宣告的密文射程是整組：新版本會同時就位到每一台，故逐台驗權
		if err := s.assertBoundAssetsPermission(ctx, tx, cred.ID); err != nil {
			return err
		}
		pwEnc, keyEnc := passwordEnc, privateKeyEnc
		if cred.CurrentVersionID != nil {
			var cerr error
			pwEnc, keyEnc, cerr = carryOverVersionCiphertext(tx, cred.ID, *cred.CurrentVersionID, pwEnc, keyEnc)
			if cerr != nil {
				return cerr
			}
		}
		secretType := credentialSecretTypeFor(pwEnc != "", keyEnc != "")
		version, verr := appendCredentialVersion(tx, cred.ID, secretType,
			pwEnc, keyEnc, model.CredentialVersionReasonManual)
		if verr != nil {
			return verr
		}
		if err := setCredentialCurrentVersion(tx, cred.ID, version.ID); err != nil {
			return err
		}
		if cred.SecretType != secretType {
			if err := tx.Model(&model.Credential{}).Where("id = ?", cred.ID).
				Update("secret_type", secretType).Error; err != nil {
				return fmt.Errorf("更新憑證秘密型別失敗: %w", err)
			}
		}
		if err := setAllBindingsEffectiveVersion(tx, cred.ID, version.ID); err != nil {
			return err
		}
		// 上一輪尚未收斂時，這句宣告是**取代**而不是與它並存：同一交易清掉待生效
		// 版本並收束該輪未就位的成員，否則一次補跑就會把遠端改回上一輪的秘密
		if err := supersedePendingRotation(tx, cred); err != nil {
			return err
		}
		var reloaded model.Credential
		if err := tx.Where("id = ?", cred.ID).First(&reloaded).Error; err != nil {
			return fmt.Errorf("重讀憑證失敗: %w", err)
		}
		result = &reloaded
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    model.AccountOpUpdate,
			Scope:        cred.Scope,
			Fields:       changedSecretFields(req.Password != "", req.PrivateKey != "", false),
		}, userID, operator)
	})
	if err != nil {
		return nil, err
	}
	return s.credentialDTO(database.DB, result)
}

// Delete 軟刪憑證（引用檢查）。
//
// 仍有掛載時拒刪並回掛載資產名單：靜默連帶刪除掛載等於讓一句「刪除憑證」把幾台
// 機器變成沒有身分可連的死資產，而操作者在按下去的當下看不到那個後果。
// 零掛載且無未決候選者可刪，軟刪即釋放名稱（共用名稱的唯一索引只涵蓋未軟刪者）。
func (s *CredentialService) Delete(ctx context.Context, id uint) error {
	userID, operator := model.UserFromContext(ctx)
	return database.DB.Transaction(func(tx *gorm.DB) error {
		cred, err := lockCredentialRow(tx, id)
		if err != nil {
			return err
		}
		if err := assertNoActiveRotation(cred); err != nil {
			return err
		}
		// 逐台驗權先於引用檢查：名單本身是共用拓撲的一部分，先回名單再談權限
		// 等於讓無權者以一次必然失敗的刪除，問出這組秘密還用在哪幾台
		if err := s.assertBoundAssetsPermission(ctx, tx, cred.ID); err != nil {
			return err
		}
		names, err := credentialBoundAssetNames(tx, cred.ID)
		if err != nil {
			return err
		}
		if len(names) > 0 {
			return &CredentialInUseError{Assets: names}
		}
		pending, err := credentialPendingCandidates(tx, cred.ID)
		if err != nil {
			return err
		}
		if pending > 0 {
			return ErrCredentialHasPendingCandidate
		}
		res := tx.Delete(&model.Credential{}, cred.ID)
		if res.Error != nil {
			return fmt.Errorf("刪除憑證失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrCredentialNotFound
		}
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    model.AccountOpDelete,
			Scope:        cred.Scope,
		}, userID, operator)
	})
}

// --- 共同判定 ---

// assertSharedNameFree 共用名稱唯一性的服務層判定（exceptID 為自身，改名時排除）。
//
// **不只靠 DB 的 partial unique index**：那條索引只存在於正式庫的 DDL，服務層要在
// 唯一違反之前就給出可辨識的錯誤；索引則是並行下的最後一道網（credentialUniqueViolation
// 把它翻回同一個哨兵）。
func assertSharedNameFree(tx *gorm.DB, name string, exceptID uint) error {
	if name == "" {
		return ErrCredentialNameRequired
	}
	q := tx.Model(&model.Credential{}).
		Where("scope = ? AND name = ?", model.CredentialScopeShared, name)
	if exceptID != 0 {
		q = q.Where("id <> ?", exceptID)
	}
	var dup int64
	if err := q.Count(&dup).Error; err != nil {
		return fmt.Errorf("檢查憑證名稱失敗: %w", err)
	}
	if dup > 0 {
		return ErrCredentialNameExists
	}
	return nil
}

// assertNoActiveRotation 輪替進行中一律拒絕操作者宣告與管理類寫入路徑。
func assertNoActiveRotation(cred *model.Credential) error {
	if cred != nil && cred.ActiveRotationID != nil && *cred.ActiveRotationID != 0 {
		return ErrCredentialRotationActive
	}
	return nil
}

// credentialBindingCount 掛載此憑證的（未軟刪）掛載列數。
func credentialBindingCount(db *gorm.DB, credentialID uint) (int64, error) {
	var count int64
	if err := db.Model(&model.AssetAccount{}).
		Where("credential_id = ?", credentialID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("查詢憑證掛載數失敗: %w", err)
	}
	return count, nil
}

// credentialBoundAssetNames 掛載此憑證的資產名單（拒刪時回給操作者處置）。
func credentialBoundAssetNames(db *gorm.DB, credentialID uint) ([]string, error) {
	var bindings []model.AssetAccount
	if err := db.Where("credential_id = ?", credentialID).
		Order("asset_id ASC").Find(&bindings).Error; err != nil {
		return nil, fmt.Errorf("查詢憑證掛載失敗: %w", err)
	}
	names := make([]string, 0, len(bindings))
	for i := range bindings {
		var asset model.Asset
		if err := db.Where("id = ?", bindings[i].AssetID).First(&asset).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			return nil, fmt.Errorf("查詢資產失敗: %w", err)
		}
		names = append(names, asset.Name)
	}
	return names, nil
}

// credentialPendingCandidates 指向此憑證的未決候選秘密數。
//
// 候選表在部分測試裝配中不存在（該裝配不涉及改密）：表不存在時視為零，
// 而不是讓一個與改密無關的刪除操作因為缺表而失敗。
func credentialPendingCandidates(db *gorm.DB, credentialID uint) (int64, error) {
	if db.Migrator() != nil && !db.Migrator().HasTable(&model.ChangeSecretCandidate{}) {
		return 0, nil
	}
	var count int64
	if err := db.Model(&model.ChangeSecretCandidate{}).
		Where("credential_id = ?", credentialID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("查詢未決候選失敗: %w", err)
	}
	return count, nil
}

// credentialUniqueViolation 憑證表的唯一索引衝突分流。
func credentialUniqueViolation(err error, wrapMsg string) error {
	if !dberr.IsUniqueViolation(err) {
		return fmt.Errorf("%s: %w", wrapMsg, err)
	}
	if strings.Contains(err.Error(), "idx_credentials_shared_name") {
		return ErrCredentialNameExists
	}
	return fmt.Errorf("%s: %w", wrapMsg, err)
}
