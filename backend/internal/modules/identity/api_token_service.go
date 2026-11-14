package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// 個人 API token：人類帳號為自己建立、交給程式化工具代表本人呼叫管理 API 的憑證。
//
// 明文為固定前綴加 256 位元密碼學亂數的編碼字串，只在建立的回傳值中出現一次；資料庫只存 SHA-256。
// 建立、撤銷與撤銷全部都在所屬帳號的帳號層級鎖（WithUserCredentialLock）內進行：建立資格、授權角色
// 與名稱占用都在鎖內以交易狀態重判。名稱占用沒有資料庫索引（是否到期隨時間改變，索引無法表達），
// 唯一性完全依賴這把鎖；刪除帳號持同一把鎖並在同一交易標記該帳號的 token，兩者因此互斥。

// APITokenPrefix API token 明文的固定前綴（與 agent 鑰匙的前綴不同，便於憑證掃描工具辨識）。
const APITokenPrefix = "cxp_"

// APITokenAuthMethod 以 API token 認證的請求主體在事實上的認證方法。
const APITokenAuthMethod = "api_token"

const (
	// APITokenNameMaxRunes 名稱上限（以字元計，非位元組）
	APITokenNameMaxRunes = 100
	// APITokenNoteMaxRunes 撤銷原因上限（以字元計）
	APITokenNoteMaxRunes = 2000
	// APITokenExpiringSoonWindow 「即將到期」的門檻：到期時刻在此期間內
	APITokenExpiringSoonWindow = 7 * 24 * time.Hour
)

// GenerateAPIToken 產生明文與其摘要。亂數取自密碼學亂數源。
func GenerateAPIToken() (plaintext, digest string, err error) {
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return "", "", err
	}
	plaintext = APITokenPrefix + base64.RawURLEncoding.EncodeToString(entropy[:])
	return plaintext, apiTokenDigest(plaintext), nil
}

func apiTokenDigest(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// APITokenError 建立與撤銷的業務錯誤，帶對外錯誤碼與 HTTP 狀態。錯誤訊息只含錯誤碼。
type APITokenError struct {
	Code   apierror.ErrCode
	Status int
}

func (e *APITokenError) Error() string { return string(e.Code) }

var (
	ErrAPITokenNameInvalid      = &APITokenError{Code: apierror.CodeAPITokenNameInvalid, Status: 400}
	ErrAPITokenRoleRequired     = &APITokenError{Code: apierror.CodeAPITokenRoleRequired, Status: 400}
	ErrAPITokenRoleNotGrantable = &APITokenError{Code: apierror.CodeAPITokenRoleNotGrantable, Status: 400}
	ErrAPITokenExpiryRequired   = &APITokenError{Code: apierror.CodeAPITokenExpiryRequired, Status: 400}
	// ErrAPITokenExpiryInvalid 到期時刻不在未來，或同時指定到期時刻與永不到期
	ErrAPITokenExpiryInvalid = &APITokenError{Code: apierror.CodeAPITokenExpiryInvalid, Status: 400}
	ErrAPITokenNotEligible   = &APITokenError{Code: apierror.CodeAPITokenNotEligible, Status: 403}
	ErrAPITokenNameConflict  = &APITokenError{Code: apierror.CodeConflictAPITokenName, Status: 409}
	// ErrAPITokenCredentialForbidden 以 API token 認證的請求不能建立或撤銷 API token
	ErrAPITokenCredentialForbidden = &APITokenError{Code: apierror.CodeAuthAPITokenForbiddenRoute, Status: 403}
	// ErrAPITokenNoteTooLong 撤銷原因超過上限
	ErrAPITokenNoteTooLong = &APITokenError{Code: apierror.CodeBadParams, Status: 400}
	// ErrAPITokenOperatorRequired 操作者不是由請求建構（缺主體、主體不符或為系統操作者）
	ErrAPITokenOperatorRequired = &APITokenError{Code: apierror.CodePermissionDenied, Status: 403}
)

// ErrAPITokenNotFound token 不存在或不屬於指定帳號（兩者同形，不洩漏他人 token 的存在）。
var ErrAPITokenNotFound = errors.New("api token not found")

// errAPITokenRecorderMissing 留痕落地面未注入：建立與撤銷必有對應留痕，未注入即拒絕寫入。
var errAPITokenRecorderMissing = errors.New("api token 留痕落地面未注入：建立與撤銷不得在沒有留痕的情況下完成")

// APITokenCreatedEvent 建立成功時交給留痕落地面的內容（不含明文或雜湊）。
type APITokenCreatedEvent struct {
	Operator       Operator
	TokenID        uint
	OwnerID        uint
	OwnerUsername  string
	Name           string
	GrantedRoles   []APITokenRoleRef
	PrivilegedKeys []string // 授權角色中的超級管理者、系統安全管理員內建識別
	ExpiresAt      *time.Time
}

// APITokenRevokedEvent 撤銷成功時交給留痕落地面的內容（不含明文或雜湊）。重複撤銷不產生事件。
type APITokenRevokedEvent struct {
	Operator      Operator
	TokenID       uint
	OwnerID       uint
	OwnerUsername string
	Name          string
	Note          string
	RevokedAt     time.Time
}

// APITokenEventRecorder 建立與撤銷在同一交易內的留痕（稽核、系統告警）。回錯即整筆回滾。
type APITokenEventRecorder interface {
	APITokenCreated(tx *gorm.DB, ev APITokenCreatedEvent) error
	APITokenRevoked(tx *gorm.DB, ev APITokenRevokedEvent) error
}

// APITokenRoleRef 角色的識別、名稱與內建識別（自訂角色的內建識別為空）。
type APITokenRoleRef struct {
	RoleID     uint   `json:"role_id"`
	Name       string `json:"name"`
	BuiltinKey string `json:"builtin_key"`
}

// APITokenService token 的建立、撤銷與清單投影。
type APITokenService struct {
	db         *gorm.DB
	recorder   APITokenEventRecorder
	restoreGen RestoreGenerationSource
	restoredAt func(db *gorm.DB) (*time.Time, error)
	now        func() time.Time
}

// NewAPITokenService 建立服務。recorder 為建立與撤銷的交易內留痕；nil 時建立與撤銷一律失敗。
func NewAPITokenService(db *gorm.DB, recorder APITokenEventRecorder) *APITokenService {
	return &APITokenService{db: db, recorder: recorder, now: time.Now}
}

// SetRestoreGenerationSource 注入目前還原世代的讀取函式（組裝根注入 authz.RestoreGeneration）。
// 未注入時建立記空世代、清單不判定「已因還原失效」，與認證入口未注入時的行為一致。
func (s *APITokenService) SetRestoreGenerationSource(src RestoreGenerationSource) { s.restoreGen = src }

// CreateAPITokenInput 建立請求。ExpiresAt 與 NeverExpires 恰擇一。
type CreateAPITokenInput struct {
	Name         string
	RoleIDs      []uint
	ExpiresAt    *time.Time
	NeverExpires bool
}

// CreatedAPIToken 建立結果：清單投影加一次性明文。明文只在這個回傳值中出現。
type CreatedAPIToken struct {
	View  APITokenView
	Token string
}

// rejectNonSessionOperator 建立與撤銷只接受由請求建構、帶請求主體的操作者，且不接受以 API token
// 認證的請求（API token 不能替自己再發一把或撤銷 token）。
func rejectNonSessionOperator(op Operator) error {
	if op.IsSystem() || op.UserID == 0 || op.Principal == nil || op.Principal.UserID != op.UserID {
		return ErrAPITokenOperatorRequired
	}
	if op.Principal.Facts.RoleFilter != nil || op.Principal.Facts.AuthMethod == APITokenAuthMethod {
		return ErrAPITokenCredentialForbidden
	}
	return nil
}

// normalizeAPITokenName 去除前後空白後須有 1 至 100 個字元，且為合法 UTF-8、不含控制字元。
func normalizeAPITokenName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > APITokenNameMaxRunes {
		return "", ErrAPITokenNameInvalid
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", ErrAPITokenNameInvalid
		}
	}
	return name, nil
}

// resolveAPITokenExpiry 到期時刻與永不到期恰擇一；到期時刻須嚴格晚於現在。回傳 nil 表示永不到期。
func resolveAPITokenExpiry(in CreateAPITokenInput, now time.Time) (*time.Time, error) {
	switch {
	case in.ExpiresAt != nil && in.NeverExpires:
		return nil, ErrAPITokenExpiryInvalid
	case in.NeverExpires:
		return nil, nil
	case in.ExpiresAt == nil:
		return nil, ErrAPITokenExpiryRequired
	}
	at := in.ExpiresAt.UTC().Truncate(time.Microsecond)
	if !at.After(now) {
		return nil, ErrAPITokenExpiryInvalid
	}
	return &at, nil
}

func uniqueRoleIDs(ids []uint) []uint {
	seen := map[uint]bool{}
	out := make([]uint, 0, len(ids))
	for _, id := range ids {
		if id != 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// apiTokenPreWriteHook 測試用同步點：建立流程在鎖內完成全部判定之後、寫入之前呼叫。
// 讓並發測試在精確位置製造交錯；生產路徑恆為 nil，改寫者僅限測試。
var apiTokenPreWriteHook func()

// Create 為操作者本人建立一把 API token。輸入檢查在鎖外；資格、授權角色與名稱占用在帳號層級鎖內重判。
func (s *APITokenService) Create(op Operator, in CreateAPITokenInput) (*CreatedAPIToken, error) {
	if err := rejectNonSessionOperator(op); err != nil {
		return nil, err
	}
	name, err := normalizeAPITokenName(in.Name)
	if err != nil {
		return nil, err
	}
	roleIDs := uniqueRoleIDs(in.RoleIDs)
	if len(roleIDs) == 0 {
		return nil, ErrAPITokenRoleRequired
	}
	now := s.now().UTC()
	expiresAt, err := resolveAPITokenExpiry(in, now)
	if err != nil {
		return nil, err
	}
	if s.recorder == nil {
		return nil, errAPITokenRecorderMissing
	}
	plaintext, digest, err := GenerateAPIToken()
	if err != nil {
		return nil, fmt.Errorf("產生 API token 失敗: %w", err)
	}
	var view APITokenView
	err = WithUserCredentialLock(s.db, op.UserID, func(tx *gorm.DB) error {
		elig, err := apiTokenEligibilityTx(tx, op.UserID)
		if err != nil {
			return err
		}
		if !elig.CanCreate {
			return ErrAPITokenNotEligible
		}
		grantable := map[uint]APITokenRoleView{}
		for _, r := range elig.GrantableRoles {
			grantable[r.RoleID] = r
		}
		granted := make([]APITokenRoleView, 0, len(roleIDs))
		for _, id := range roleIDs {
			r, ok := grantable[id]
			if !ok {
				return ErrAPITokenRoleNotGrantable
			}
			granted = append(granted, r)
		}
		gen, err := currentRestoreGeneration(s.restoreGen, tx)
		if err != nil {
			return err
		}
		occupied, err := apiTokenNameOccupied(tx, op.UserID, name, gen, now)
		if err != nil {
			return err
		}
		if occupied {
			return ErrAPITokenNameConflict
		}
		if apiTokenPreWriteHook != nil {
			apiTokenPreWriteHook()
		}
		row := model.APIToken{UserID: op.UserID, Name: name, TokenHash: digest, CreatedAt: now, ExpiresAt: expiresAt, RestoreGeneration: gen}
		// 參數含 token 雜湊：這條語句的 SQL 紀錄不帶參數值
		if err := database.WithheldSQLParams(tx).Create(&row).Error; err != nil {
			return fmt.Errorf("寫入 API token 失敗: %w", err)
		}
		links := make([]model.APITokenRole, 0, len(roleIDs))
		for _, id := range roleIDs {
			links = append(links, model.APITokenRole{APITokenID: row.ID, RoleID: id})
		}
		if err := tx.Create(&links).Error; err != nil {
			return fmt.Errorf("寫入 API token 授權角色失敗: %w", err)
		}
		view = projectAPIToken(row, granted, apiTokenOwnerState{Active: true, Effective: elig.effective}, gen, now)
		refs := make([]APITokenRoleRef, 0, len(granted))
		for _, r := range granted {
			refs = append(refs, r.APITokenRoleRef)
		}
		return s.recorder.APITokenCreated(tx, APITokenCreatedEvent{Operator: op, TokenID: row.ID, OwnerID: op.UserID,
			OwnerUsername: elig.username, Name: name, GrantedRoles: refs, PrivilegedKeys: privilegedKeys(refs), ExpiresAt: expiresAt})
	})
	if err != nil {
		return nil, err
	}
	return &CreatedAPIToken{View: view, Token: plaintext}, nil
}

// apiTokenNameOccupied 同一帳號下是否已有占用該名稱的 token：未撤銷、未到期、還原世代與目前相同。
// 因帳號停用或角色收回而暫停者仍占用（它們會恢復）。
func apiTokenNameOccupied(tx *gorm.DB, userID uint, name, gen string, now time.Time) (bool, error) {
	var n int64
	err := tx.Model(&model.APIToken{}).
		Where("user_id = ? AND name = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?) AND restore_generation = ?", userID, name, now, gen).
		Count(&n).Error
	if err != nil {
		return false, fmt.Errorf("檢查 API token 名稱失敗: %w", err)
	}
	return n > 0, nil
}

func privilegedKeys(roles []APITokenRoleRef) []string {
	var out []string
	for _, r := range roles {
		if r.BuiltinKey == model.BuiltinSuperAdmin || r.BuiltinKey == model.BuiltinSecurityAdmin {
			out = append(out, r.BuiltinKey)
		}
	}
	sort.Strings(out)
	return out
}

// RevokeOwn 本人撤銷自己的一把 token。不是自己的或不存在回 ErrAPITokenNotFound。
func (s *APITokenService) RevokeOwn(op Operator, tokenID uint, note string) error {
	if err := rejectNonSessionOperator(op); err != nil {
		return err
	}
	return s.revoke(op, op.UserID, tokenID, note)
}

// RevokeForUser 管理者撤銷某個帳號的一把 token。對象持有超級管理者或系統安全管理員身分（任一來源）時
// 只限超級管理者（ErrProtectedAccountOperation）。帳號管理能力由路由判定。
func (s *APITokenService) RevokeForUser(op Operator, ownerID, tokenID uint, note string) error {
	if err := rejectNonSessionOperator(op); err != nil {
		return err
	}
	return s.revoke(op, ownerID, tokenID, note)
}

func (s *APITokenService) revoke(op Operator, ownerID, tokenID uint, note string) error {
	note, err := normalizeAPITokenNote(note)
	if err != nil {
		return err
	}
	if s.recorder == nil {
		return errAPITokenRecorderMissing
	}
	return WithUserCredentialLock(s.db, ownerID, func(tx *gorm.DB) error {
		if err := gateAPITokenRevocation(tx, op, ownerID); err != nil {
			return err
		}
		var token model.APIToken
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("user_id = ?", ownerID).First(&token, tokenID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAPITokenNotFound
			}
			return fmt.Errorf("讀取 API token 失敗: %w", err)
		}
		if token.RevokedAt != nil {
			return nil // 冪等：不覆寫既有紀錄、不另寫留痕
		}
		return s.revokeLocked(tx, op, &token, note)
	})
}

// RevokeAllForUser 管理者一次撤銷某個帳號全部尚可使用的 token（未撤銷、未到期、還原世代相同；
// 暫停中的也算，它們會恢復）。回傳本次實際撤銷的數量。受保護帳號的規則同 RevokeForUser。
func (s *APITokenService) RevokeAllForUser(op Operator, ownerID uint, note string) (int, error) {
	if err := rejectNonSessionOperator(op); err != nil {
		return 0, err
	}
	note, err := normalizeAPITokenNote(note)
	if err != nil {
		return 0, err
	}
	if s.recorder == nil {
		return 0, errAPITokenRecorderMissing
	}
	revoked := 0
	err = WithUserCredentialLock(s.db, ownerID, func(tx *gorm.DB) error {
		if err := gateAPITokenRevocation(tx, op, ownerID); err != nil {
			return err
		}
		gen, err := currentRestoreGeneration(s.restoreGen, tx)
		if err != nil {
			return err
		}
		var tokens []model.APIToken
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?) AND restore_generation = ?", ownerID, s.now().UTC(), gen).
			Order("id").Find(&tokens).Error; err != nil {
			return fmt.Errorf("讀取 API token 失敗: %w", err)
		}
		for i := range tokens {
			if err := s.revokeLocked(tx, op, &tokens[i], note); err != nil {
				return err
			}
		}
		revoked = len(tokens)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return revoked, nil
}

func (s *APITokenService) revokeLocked(tx *gorm.DB, op Operator, token *model.APIToken, note string) error {
	now := s.now().UTC()
	changes := map[string]any{"revoked_at": now, "revoked_by": op.UserID, "revoke_note": note}
	if err := tx.Model(&model.APIToken{}).Where("id = ? AND revoked_at IS NULL", token.ID).Updates(changes).Error; err != nil {
		return fmt.Errorf("撤銷 API token 失敗: %w", err)
	}
	var owner model.User
	if err := tx.Unscoped().Select("id", "username").First(&owner, token.UserID).Error; err != nil {
		return fmt.Errorf("讀取 API token 所屬帳號失敗: %w", err)
	}
	return s.recorder.APITokenRevoked(tx, APITokenRevokedEvent{Operator: op, TokenID: token.ID, OwnerID: token.UserID,
		OwnerUsername: owner.Username, Name: token.Name, Note: note, RevokedAt: now})
}

func normalizeAPITokenNote(note string) (string, error) {
	note = strings.TrimSpace(note)
	if !utf8.ValidString(note) || utf8.RuneCountInString(note) > APITokenNoteMaxRunes {
		return "", ErrAPITokenNoteTooLong
	}
	return note, nil
}

// gateAPITokenRevocation 撤銷他人 token 的受保護帳號判定：與停用帳號同一界線（對象持有超級管理者或
// 系統安全管理員身分時只限超級管理者），沿用帳號身分操作關卡（操作者帶請求主體的事實、對象維持完整身分）。
// 撤銷自己的 token 不經此判定。
func gateAPITokenRevocation(tx *gorm.DB, op Operator, ownerID uint) error {
	if op.UserID == ownerID {
		return nil
	}
	_, err := accountOpsOrDefault(nil).Gate(tx, op, ownerID, AccountOpDisable)
	return err
}

// markAPITokensRevokedForDeletedUserTx 帳號刪除時在同一交易標記其尚未撤銷的 token（清單呈現為已撤銷）。
// 呼叫端必須已持該帳號的帳號層級鎖：與建立互斥，刪除與並發建立交錯後不會留下未標記的 token。
// 撤銷者為刪除的操作者；系統路徑（無操作者）留空。不另寫留痕：帳號刪除本身已留痕。
func markAPITokensRevokedForDeletedUserTx(tx *gorm.DB, userID uint, op *Operator) error {
	changes := map[string]any{"revoked_at": time.Now().UTC(), "revoked_by": nil}
	if op != nil && !op.IsSystem() && op.UserID != 0 {
		changes["revoked_by"] = op.UserID
	}
	if err := tx.Model(&model.APIToken{}).Where("user_id = ? AND revoked_at IS NULL", userID).Updates(changes).Error; err != nil {
		return fmt.Errorf("標記已刪除帳號的 API token 失敗: %w", err)
	}
	return nil
}
