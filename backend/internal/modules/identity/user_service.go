package identity

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
)

// emailValidator 沿用 gin binding 所用的 go-playground validator 的 `email` 語義：
// Update 端點放寬 binding 後，由 service 於 trim/小寫正規化
// 「之後」以「同一套 validator」把關格式——與原 binding:"email" 完全一致（不比其寬鬆），
// 且讓「僅前後空白差異的既有 email」能被 trim 後偵測為衝突回 409，而非在 binding 層被 400
var emailValidator = validator.New()

var (
	// ErrUsernameExists 使用者名稱已存在
	ErrUsernameExists = errors.New("使用者名稱已存在")
	// ErrLastAdmin 不能刪除最後一個管理員
	ErrLastAdmin = errors.New("不能刪除最後一個管理員")
	// ErrRoleNotFound 角色不存在
	ErrRoleNotFound = errors.New("角色不存在")
	// ErrLDAPUserPassword LDAP 使用者的密碼由目錄管理，本地不可修改。
	// 保留供既有呼叫端相容；新路徑一律用 ErrExternalUserPassword
	ErrLDAPUserPassword = errors.New("LDAP 使用者的密碼由目錄服務管理，無法在本系統修改")
	// ErrExternalUserPassword 外部身分帳號（LDAP／OIDC）的密碼由身分提供者管理。
	// 判定經 user.IsExternal() 取三訊號聯集，
	// 不直讀 is_ldap——OIDC 供應帳號的 is_ldap 為 false，只認該欄會讓 admin
	// 得以為其設定本地密碼，形成繞過 IdP 的 MFA 與條件式存取的永久後門
	ErrExternalUserPassword = errors.New("此帳號的密碼由外部身分提供者管理，無法在本系統修改")
	// ErrOldPasswordMismatch 自助改密時目前密碼驗證失敗
	ErrOldPasswordMismatch = errors.New("目前密碼錯誤")
	// ErrEmailConflict admin 更新 email 撞其他 live 帳號：
	// handler 據此回 409（非通用 500）
	ErrEmailConflict = errors.New("此 email 已被其他帳號使用")
	// ErrInvalidEmail 正規化後仍非合法 email 格式（Update 端點放寬 binding 後由 service 把關）
	ErrInvalidEmail = errors.New("email 格式不正確")
)

// normalizeEmail 正規化 email：trim + 小寫；空字串（未知）回 nil，以 NULL 儲存
// （未知 email 存 NULL，唯一性僅約束非 NULL 值）
func normalizeEmail(raw string) *string {
	t := strings.ToLower(strings.TrimSpace(raw))
	if t == "" {
		return nil
	}
	return &t
}

// emailInUseByOther 回報是否有「其他 live 帳號」已使用此 email（trim/小寫正規化後
// 僅非 NULL 比對）。GORM 預設 scope 已排除 soft-deleted，故僅比對 live 帳號
func (s *UserService) emailInUseByOther(normalizedEmail string, excludeID uint) (bool, error) {
	var count int64
	q := s.db.Model(&model.User{}).Where("LOWER(email) = ?", normalizedEmail)
	if excludeID > 0 {
		q = q.Where("id <> ?", excludeID)
	}
	if err := q.Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// authorizationCascadeRevoker 刪除使用者／使用者群組時對 authz 表的級聯撤銷。
//
// **消費者側窄介面**：介面在消費者側宣告、由組裝根注入 authz 的實作，
// 使 identity 的呼叫面收斂為兩個具名方法而非「任意對 authz 的表下 Delete」。
//
// **誠實邊界（不得高估）**：identity **本來就 import authz**
// （`auth_service.go` 的 `IsEffectiveApprover`，矩陣 identity→authz ✔），
// 故此介面的價值是**窄化寫入面**，**不是**阻斷 import——這一點與 asset 側不同
// （asset→authz 為禁止邊，那一側的介面確實由 `go list -deps` 證得零 import）。
// 且介面把整個 `*gorm.DB` 交出去，**編譯器管不到對方寫哪張表**
// （白名單見 `cmd/server/tx_taking_whitelist_test.go`）。
type authorizationCascadeRevoker interface {
	RevokeByUserGroup(tx *gorm.DB, groupID uint) (revokedAuthorizations int64, err error)
	RevokeByUser(tx *gorm.DB, userID uint) error
}

// SessionTerminator 停用帳號時強制終斷該使用者全部進行中協議會話（
// 沿用 admin_terminate 語義）。介面而非直接依賴 SessionService，避免 service 相互耦合
type SessionTerminator interface {
	TerminateAllByUser(userID uint) (int, error)
}

// UserService 使用者管理服務
type UserService struct {
	db *gorm.DB
	// policies 安全政策服務（密碼 validator 與強制改密開關）；
	// nil 表示不啟用政策驗證（僅測試建構路徑，生產組裝一律注入）
	policies *policy.SecurityPolicyService
	// sessionTerminator 停用帳號的即時撤權收線（8.2.5）；nil 時僅撤 refresh 不斷協議會話
	sessionTerminator SessionTerminator
	// subscriptions 唯讀訂閱（監看／分享觀看）的按-user 收線管道。
	// 訂閱不建 sessions 列，sessionTerminator 掃不到它；nil 時該管道不生效
	subscriptions SubscriptionTerminator
	// recordingTokens 錄影存取 token 的按-user 撤銷管道（同上，nil 時不生效）
	recordingTokens RecordingTokenRevoker
	// audit 外部身分管理四操作的審計出口；nil 表示停用（僅測試建構路徑）
	audit oidcAuditSink
	// authzRevoker 刪除使用者時的 authz 級聯撤銷（tx-taking 窄 port）
	authzRevoker authorizationCascadeRevoker
}

// NewUserService 創建使用者服務。
// authzRevoker 為級聯撤銷面（窄 port），未注入時 Delete 會 fail-close。
func NewUserService(db *gorm.DB, authzRevoker authorizationCascadeRevoker) *UserService {
	return &UserService{
		db:           db,
		authzRevoker: authzRevoker,
	}
}

// SetSecurityPolicies 注入安全政策服務。
// 比照 AuthService.SetLDAPResolver 的 setter 模式：既有呼叫端零改動
func (s *UserService) SetSecurityPolicies(policies *policy.SecurityPolicyService) {
	s.policies = policies
}

// SetSessionTerminator 注入會話終斷器（停用帳號即時收線用）
func (s *UserService) SetSessionTerminator(t SessionTerminator) {
	s.sessionTerminator = t
}

// ListUsersRequest 獲取使用者列表請求
type ListUsersRequest struct {
	Search string // 搜尋使用者名稱或郵箱
	Active *bool  // 篩選啟用狀態（nil = 全部）
	// ProvisioningOrigin 供應來源篩選（local/ldap/oidc；空＝全部）。
	// **必須是伺服端篩選**：列表是分頁的，在前端篩當頁資料會讓使用者看到
	// 「第 2 頁明明有 oidc 帳號，篩選後卻說沒有」
	ProvisioningOrigin string
	// AuthProviderID 依已綁定的 OIDC provider 實例篩選（0＝不篩）
	AuthProviderID uint
	Page           int // 頁碼（從 1 開始）
	PageSize       int // 每頁大小
}

// UserListResponse 使用者列表回應
type UserListResponse struct {
	Data  []model.User `json:"data"`
	Total int64        `json:"total"`
}

// CreateUserRequest 創建使用者請求
type CreateUserRequest struct {
	Username string   `json:"username" binding:"required,min=3,max=50"`
	Password string   `json:"password" binding:"required,min=6"`
	Email    string   `json:"email" binding:"required,email"`
	FullName string   `json:"full_name"`
	Roles    []string `json:"roles"` // 角色名稱列表
}

// UpdateUserRequest 更新使用者請求。
// Email 不在 binding 層做 email 格式驗證：改由 service 於 trim/小寫正規化「之後」
// 校驗格式（emailFormatRe），使「僅前後空白差異的既有 email」能被 trim 後偵測為
// 衝突回 409（spec：surrounding whitespace → conflict），而非在 binding 層被 400 擋下
type UpdateUserRequest struct {
	Email    string `json:"email"`
	FullName string `json:"full_name"`
}

// CountLocalAdmins 現存本地 admin 數（管理端警示用的唯讀查詢）。
//
// 刻意只是 local_admin_invariant.go 的 CountLocalAdmins 的薄轉發，**不得在此
// 另寫查詢**：警示的判準與不變式的拒絕判準必須同一事實源，否則會出現
// 「擋你的條件」與「告訴你的條件」漂移。此處存在的唯一理由是讓 handler
// 經 UserServiceInterface 取得該計數（handler 不持有 *gorm.DB）
func (s *UserService) CountLocalAdmins() (int64, error) {
	return CountLocalAdmins(s.db)
}

// ListRoles 角色清單。
//
// 原本住在 `api/role_handler.go:28`——handler 自持 `*gorm.DB` 直查 `model.Role`，
// 是 api 層繞過 service 直接碰資料層的四處之一。查詢本體逐字搬入，行為位元相同
// （`Find` 的排序、錯誤傳遞、`RowsAffected` 語義皆由呼叫端沿用）。
// 角色主檔屬 identity 域，故落在 `UserService`。
func (s *UserService) ListRoles() ([]model.Role, int64, error) {
	var roles []model.Role
	result := s.db.Find(&roles)
	if result.Error != nil {
		return nil, 0, result.Error
	}
	return roles, result.RowsAffected, nil
}

// GetByID 根據 ID 獲取使用者（含角色）
func (s *UserService) GetByID(id uint) (*model.User, error) {
	var user model.User
	result := s.db.Preload("Roles").First(&user, id)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}

	return &user, nil
}

// List 獲取使用者列表（支援分頁、搜尋）
func (s *UserService) List(req *ListUsersRequest) (*UserListResponse, error) {
	var users []model.User
	var total int64

	// 設定預設分頁參數
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 {
		req.PageSize = 20
	}

	// 構建查詢
	query := s.db.Model(&model.User{})

	// 搜尋條件：使用者名稱或郵箱
	if req.Search != "" {
		query = query.Where("username LIKE ? OR email LIKE ?",
			"%"+req.Search+"%", "%"+req.Search+"%")
	}

	// 啟用狀態篩選
	if req.Active != nil {
		query = query.Where("active = ?", *req.Active)
	}

	// 供應來源篩選
	if req.ProvisioningOrigin != "" {
		query = query.Where("provisioning_origin = ?", req.ProvisioningOrigin)
	}

	// 依 provider 實例篩選：以子查詢而非 JOIN——JOIN 會讓綁多個身分的帳號
	// 在結果中重複出現，連帶使 Count 與分頁失準
	if req.AuthProviderID != 0 {
		query = query.Where("id IN (?)",
			s.db.Model(&model.UserExternalIdentity{}).
				Select("user_id").
				Where("provider_id = ? AND deleted_at IS NULL", req.AuthProviderID))
	}

	// 計算總數
	if err := query.Count(&total).Error; err != nil {
		log.Printf("[UserService] List: Count error: %v", err)
		return nil, fmt.Errorf("計算使用者總數失敗: %w", err)
	}

	// 分頁查詢
	offset := (req.Page - 1) * req.PageSize
	result := query.
		Preload("Roles").
		Order("username").
		Offset(offset).
		Limit(req.PageSize).
		Find(&users)

	if result.Error != nil {
		log.Printf("[UserService] List: Query error: %v", result.Error)
		return nil, fmt.Errorf("查詢使用者列表失敗: %w", result.Error)
	}

	s.fillAuthProviderNames(users)

	return &UserListResponse{
		Data:  users,
		Total: total,
	}, nil
}

// fillAuthProviderNames 為當頁使用者填入已綁定的 provider 實例名（來源欄）。
//
// 單次批量查詢而非逐列查——列表頁一次 20 筆，逐列查即 20 次往返。
// 查詢失敗只記錄不中斷：來源欄是輔助資訊，不值得讓整個列表 500
func (s *UserService) fillAuthProviderNames(users []model.User) {
	if len(users) == 0 {
		return
	}
	ids := make([]uint, 0, len(users))
	for i := range users {
		ids = append(ids, users[i].ID)
	}

	var rows []struct {
		UserID uint
		Name   string
	}
	err := s.db.Model(&model.UserExternalIdentity{}).
		Select("user_external_identities.user_id AS user_id, oidc_providers.name AS name").
		Joins("JOIN oidc_providers ON oidc_providers.id = user_external_identities.provider_id").
		Where("user_external_identities.user_id IN ?", ids).
		Where("user_external_identities.deleted_at IS NULL").
		Order("oidc_providers.name").
		Scan(&rows).Error
	if err != nil {
		log.Printf("[UserService] fillAuthProviderNames: %v", err)
		return
	}

	byUser := make(map[uint][]string, len(rows))
	for _, r := range rows {
		byUser[r.UserID] = append(byUser[r.UserID], r.Name)
	}
	for i := range users {
		users[i].AuthProviderNames = byUser[users[i].ID]
	}
}

// Create 創建使用者
func (s *UserService) Create(req *CreateUserRequest) (*model.User, error) {
	// 檢查使用者名稱是否已存在
	var existingUser model.User
	err := s.db.Where("username = ?", req.Username).First(&existingUser).Error
	if err == nil {
		return nil, ErrUsernameExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Printf("[UserService] Create: Check username error: %v", err)
		return nil, fmt.Errorf("檢查使用者名稱失敗: %w", err)
	}

	// 密碼政策驗證（單一 validator；新帳號無歷史，userID=0 跳過歷史比對）
	if err := s.ValidateNewPassword(0, req.Password); err != nil {
		return nil, err
	}

	// 加密密碼
	hashedPassword, err := crypto.DefaultPasswordHasher().Hash([]byte(req.Password))
	if err != nil {
		log.Printf("[UserService] Create: Hash password error: %v", err)
		return nil, fmt.Errorf("密碼加密失敗: %w", err)
	}

	// 創建使用者。last_login_at 以建立時間起算（閒置停用以「距最後登入」判定，
	// 新建卻未登入者若 last_login_at 為 NULL 亦以 created_at 起算，此處顯式填入更直觀）
	now := time.Now()
	// 身分欄位顯式賦值：GORM 對 struct literal 未列的
	// 欄位交由 DB default，雖然本路徑的值恰與 default 相同，仍顯式寫出——
	// 三個建號路徑各自顯式賦值是不變式守衛的前提，靠 default 巧合成立的語義
	// 會在日後有人改 default 時無聲失效
	user := &model.User{
		Username:           req.Username,
		Password:           string(hashedPassword),
		Email:              normalizeEmail(req.Email),
		FullName:           req.FullName,
		Active:             true,
		LastLoginAt:        &now,
		ProvisioningOrigin: model.AuthSourceLocal,
		ExternalCredential: false,
	}

	// 開始事務
	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("開始事務失敗: %w", tx.Error)
	}

	// 創建使用者記錄
	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		log.Printf("[UserService] Create: Create user error: %v", err)
		return nil, fmt.Errorf("創建使用者失敗: %w", err)
	}

	// 初始密碼寫入歷史（否則首次改密可設回原密碼）
	if err := s.recordPasswordHistory(tx, user.ID, user.Password); err != nil {
		tx.Rollback()
		log.Printf("[UserService] Create: Record password history error: %v", err)
		return nil, err
	}

	// 如果指定了角色，分配角色
	if len(req.Roles) > 0 {
		var roles []model.Role
		result := tx.Where("name IN ?", req.Roles).Find(&roles)
		if result.Error != nil {
			tx.Rollback()
			log.Printf("[UserService] Create: Query roles error: %v", result.Error)
			return nil, fmt.Errorf("查詢角色失敗: %w", result.Error)
		}

		// 檢查是否所有角色都存在
		if len(roles) != len(req.Roles) {
			tx.Rollback()
			return nil, ErrRoleNotFound
		}

		// 分配角色
		if err := tx.Model(user).Association("Roles").Append(roles); err != nil {
			tx.Rollback()
			log.Printf("[UserService] Create: Assign roles error: %v", err)
			return nil, fmt.Errorf("分配角色失敗: %w", err)
		}
	}

	// 提交事務
	if err := tx.Commit().Error; err != nil {
		log.Printf("[UserService] Create: Commit error: %v", err)
		return nil, fmt.Errorf("提交事務失敗: %w", err)
	}

	// 預加載角色後返回
	if err := s.db.Preload("Roles").First(user, user.ID).Error; err != nil {
		log.Printf("[UserService] Create: Reload user error: %v", err)
		// 使用者已創建，但預加載失敗，返回不帶角色的使用者
		return user, nil
	}

	log.Printf("[UserService] Create: User created successfully, ID: %d, Username: %s", user.ID, user.Username)
	return user, nil
}

// Update 更新使用者（基本資訊，不含密碼和角色）。
// 回傳的 diff 為欄位級 before/after 變更（key 形如 "email.before"/"email.after"，
// 僅含實際變更的欄位），供 handler 注入審計日誌（稽核可查）
func (s *UserService) Update(id uint, req *UpdateUserRequest) (*model.User, map[string]string, error) {
	// 檢查使用者是否存在
	var user model.User
	if err := s.db.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrUserNotFound
		}
		log.Printf("[UserService] Update: Query user error: %v", err)
		return nil, nil, fmt.Errorf("查詢使用者失敗: %w", err)
	}

	// 更新欄位與 before/after 差異（僅記實際變更者）
	updates := map[string]interface{}{}
	diff := map[string]string{}

	if req.Email != "" {
		normalized := strings.ToLower(strings.TrimSpace(req.Email))
		// binding 已放寬，service 於 trim/小寫後以同一 validator 把關格式（無效→400）
		if err := emailValidator.Var(normalized, "email"); err != nil {
			return nil, nil, ErrInvalidEmail
		}
		if normalized != user.EmailString() {
			// email 唯一性預查：trim/小寫正規化後與其他 live 帳號比對，
			// 撞則回 typed ErrEmailConflict → handler 回 409（取代原直寫撞 DB 唯一索引的通用 500）
			conflict, err := s.emailInUseByOther(normalized, id)
			if err != nil {
				return nil, nil, fmt.Errorf("檢查 email 衝突失敗: %w", err)
			}
			if conflict {
				return nil, nil, ErrEmailConflict
			}
			updates["email"] = normalized
			diff["email.before"] = user.EmailString()
			diff["email.after"] = normalized
		}
	}
	if req.FullName != "" && req.FullName != user.FullName {
		updates["full_name"] = req.FullName
		diff["full_name.before"] = user.FullName
		diff["full_name.after"] = req.FullName
	}

	// 執行更新
	if len(updates) > 0 {
		if err := s.db.Model(&user).Updates(updates).Error; err != nil {
			// 預查與 UPDATE 非原子：兩併發更新皆過預查後、後寫者撞 DB 唯一索引，
			// 轉成 ErrEmailConflict 回 409（defense in depth，非通用 500）
			if dberr.IsUniqueViolation(err) {
				return nil, nil, ErrEmailConflict
			}
			log.Printf("[UserService] Update: Update user error: %v", err)
			return nil, nil, fmt.Errorf("更新使用者失敗: %w", err)
		}
	}

	// 預加載角色後返回
	if err := s.db.Preload("Roles").First(&user, id).Error; err != nil {
		log.Printf("[UserService] Update: Reload user error: %v", err)
		return &user, diff, nil
	}

	log.Printf("[UserService] Update: User updated successfully, ID: %d", id)
	return &user, diff, nil
}

// Delete 刪除使用者（軟刪除）
func (s *UserService) Delete(id uint) error {
	// 檢查使用者是否存在
	var user model.User
	if err := s.db.Preload("Roles").First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		log.Printf("[UserService] Delete: Query user error: %v", err)
		return fmt.Errorf("查詢使用者失敗: %w", err)
	}

	// 檢查是否為管理員
	isAdmin := false
	for _, role := range user.Roles {
		if role.Name == model.RoleAdmin {
			isAdmin = true
			break
		}
	}

	// 如果是管理員，檢查是否為最後一個
	if isAdmin {
		var adminCount int64
		err := s.db.Model(&model.User{}).
			Joins("JOIN user_roles ON user_roles.user_id = users.id").
			Joins("JOIN roles ON roles.id = user_roles.role_id").
			Where("roles.name = ? AND users.deleted_at IS NULL AND users.id != ?", model.RoleAdmin, id).
			Count(&adminCount).Error

		if err != nil {
			log.Printf("[UserService] Delete: Count admins error: %v", err)
			return fmt.Errorf("檢查管理員數量失敗: %w", err)
		}

		if adminCount == 0 {
			return ErrLastAdmin
		}
	}

	// 執行軟刪除＋連動清理（同交易：不留幽靈引用）：
	// 審核範圍（作審核方 approver_id 或作申請人 subject_user_id）連動軟刪；
	// 群組成員關係（join 表無軟刪）直接清——否則殘留成員列可回復審核方群組資格
	//
	// 外層為「本地 admin 不變式」的系統級鎖（2.7）：上方 isAdmin 的既有檢查問的是
	// 「還有沒有 admin」且在鎖外，擋不住「刪掉最後一個**本地** admin（其他 admin 皆為
	// 外部身分）」，也擋不住兩個並發刪除各自看見對方仍在。判定於鎖內重讀且與寫入同交易
	//
	// 憑證失效與軟刪除同交易（spec「帳號刪除」情境）：
	// 原本此路徑**連 refresh 與協議會話都不動**，是三條生命週期路徑中缺口最大的一條
	// ——帳號已不存在，其持有者卻仍有活著的 shell、活著的監看訂閱，以及可再撐一個
	// TTL 的 access token。取鎖順序 system → user
	if err := WithLocalAdminInvariant(s.db, id, func(tx *gorm.DB) error {
		return withUserCredentialLockTx(tx, id, func(tx *gorm.DB) error {
			// **必須早於軟刪除**：軟刪後 Model(&User{}).Where("id = ?") 帶
			// deleted_at IS NULL，世代推進會匹配 0 列而回 ErrUserNotFound
			if err := s.invalidateCredentialsLocked(tx, id, "account_deleted"); err != nil {
				return err
			}
			// 審核範圍屬 authz：經 tx-taking 窄 port 交由擁有者寫入。
			// 未注入即 fail-close——靜默略過會留下可回復審核資格的幽靈範圍
			if s.authzRevoker == nil {
				return fmt.Errorf("authz 級聯撤銷面未注入：刪帳號不得在不撤銷審核範圍的情況下完成")
			}
			if err := s.authzRevoker.RevokeByUser(tx, id); err != nil {
				return err
			}
			if err := tx.Exec("DELETE FROM user_group_members WHERE user_id = ?", id).Error; err != nil {
				return fmt.Errorf("清除使用者群組成員關係失敗: %w", err)
			}
			if err := tx.Delete(&user).Error; err != nil {
				return fmt.Errorf("刪除使用者失敗: %w", err)
			}
			return nil
		})
	}); err != nil {
		log.Printf("[UserService] Delete: Delete user error: %v", err)
		return err
	}

	// 鎖外收線三管道（同停用路徑；世代閘只能拒絕「下一次出示憑證」的請求，
	// 已建立的長連線與訂閱建立後不再出示憑證，對世代完全免疫）
	s.revokeUserAccess(id, "account_deleted")

	log.Printf("[UserService] Delete: User deleted successfully, ID: %d", id)
	return nil
}

// AddRole 冪等追加單一角色（一站式代配用）：
// 不觸碰既有角色——避免以舊快照呼叫全量 AssignRoles 的 lost update
// （併發 admin 剛授予的 admin/auditor 被靜默覆蓋）。
// 已具該角色時為 no-op（先查後寫，跨 PG/SQLite 可攜的冪等）
func (s *UserService) AddRole(userID uint, roleName string) error {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("查詢使用者失敗: %w", err)
	}
	var role model.Role
	if err := s.db.Where("name = ?", roleName).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("查詢角色失敗: %w", err)
	}
	// 原子冪等追加：ON CONFLICT DO NOTHING 讓兩 admin
	// 併發代配同一人時，敗方 no-op 而非撞 user_roles 複合主鍵回 500——先查後寫有
	// TOCTOU 窗會退化 idempotent 端點。單條 upsert 不觸碰其他角色列，Postgres/SQLite 皆支援
	if err := s.db.Exec(
		"INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
		userID, role.ID).Error; err != nil {
		return fmt.Errorf("追加角色失敗: %w", err)
	}
	return nil
}

// roleSetDiffers 現行角色集是否異於待寫入角色集（集合語義，不計順序）。
//
// 供 AssignRoles 判定「角色是否**實際**變動」：僅變動時才推進 credential_epoch。
// 呼叫端 SHALL 於使用者級憑證鎖內、與 Replace 同交易呼叫——鎖外預讀會讓兩個並發
// 替換各自讀到舊集合，其一誤判為「無變動」而漏推進世代（write-skew 的同一形狀）。
//
// 直接查關聯表而非走 Association("Roles").Find：後者會覆寫傳入 user 的 Roles 欄位，
// 而該欄位隨後即被 Replace 使用，避免任何隱性耦合。
// 重複角色名不需在此處理——AssignRoles 前段已以 len(roles) != len(roleNames) 擋下
func roleSetDiffers(tx *gorm.DB, userID uint, want []model.Role) (bool, error) {
	var currentIDs []uint
	if err := tx.Table("user_roles").Where("user_id = ?", userID).
		Pluck("role_id", &currentIDs).Error; err != nil {
		return false, fmt.Errorf("讀取現行角色失敗: %w", err)
	}
	if len(currentIDs) != len(want) {
		return true, nil
	}
	current := make(map[uint]struct{}, len(currentIDs))
	for _, id := range currentIDs {
		current[id] = struct{}{}
	}
	for _, r := range want {
		if _, ok := current[r.ID]; !ok {
			return true, nil
		}
	}
	return false, nil
}

// AssignRoles 分配角色（替換現有角色）。
// 角色集實際變動時 SHALL 於同一交易內推進 credential_epoch 並撤銷 refresh（C-1，見下方註解）
func (s *UserService) AssignRoles(userID uint, roleNames []string) error {
	// 檢查使用者是否存在
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		log.Printf("[UserService] AssignRoles: Query user error: %v", err)
		return fmt.Errorf("查詢使用者失敗: %w", err)
	}

	// 查詢角色
	var roles []model.Role
	if len(roleNames) > 0 {
		result := s.db.Where("name IN ?", roleNames).Find(&roles)
		if result.Error != nil {
			log.Printf("[UserService] AssignRoles: Query roles error: %v", result.Error)
			return fmt.Errorf("查詢角色失敗: %w", result.Error)
		}

		// 檢查是否所有角色都存在
		if len(roles) != len(roleNames) {
			return ErrRoleNotFound
		}
	}

	// 替換角色（使用 GORM Association Replace）。
	// 新角色集不含 admin ＝ 本操作會移除該帳號的 admin 資格，須受「本地 admin 不變式」
	// 約束（2.7）：判定於系統級鎖內重讀且與 Replace 同交易。保留 admin 的角色重設
	// 不減少本地 admin 數，不取系統級鎖（避免無謂爭用）——但**兩條分支都要取使用者級
	// 憑證鎖**，因為兩者都可能變動角色集而須推進世代（C-1：只覆蓋其一等於留一半漏洞）
	keepsAdmin := false
	for _, r := range roleNames {
		if r == model.RoleAdmin {
			keepsAdmin = true
			break
		}
	}
	// applyRoles 鎖內三步：重讀現行角色 → 比對 → 替換＋（有變動時）失效既有憑證。
	//
	// 角色變更 SHALL 推進 credential_epoch：管理面的權限判定讀的是 JWT 內的
	// **角色快照**（middleware/auth.go 的 RequireRole、permission.go 的 RequirePermission），
	// 世代閘只比對 epoch 不重查角色。不推進世代，被撤除 admin 者在其 access token 的
	// 剩餘壽命內仍以 admin 通過管理端判定，據以呼叫本端點把自己的角色改回來——
	// 降權可被當事人自行復原。
	//
	// **必須與 Replace 同交易**：停在「角色已改、世代未推進」的中間態即為漏洞原形。
	//
	// **角色集無變動時不推進**：管理端重存同一組角色是常態操作，推進等於無故把人踢下線。
	// 比對必須在鎖內重讀（鎖外預讀會讓兩個並發替換各自看見舊集合而其一誤判無變動）。
	//
	// 刻意**不呼叫 revokeUserAccess**：終斷協議會話／唯讀訂閱／錄影 token 是「此帳號
	// 整體不該再有存取」的語義（停用、刪除、解綁），角色縮減不屬之——同改密路徑的取捨。
	// 惟此類比不完全成立：改密是使用者自身的例行操作，降權是管理者發動的權限剝奪，
	// 兩者威脅模型不等價。進行中唯讀監看訂閱的殘留（monitor 不受 -01 約束）
	// 已另行記錄，非本函式邏輯需處理範圍。
	// 降權後**新的**特權連線已由 -01 的 DB 現查角色擋下
	applyRoles := func(tx *gorm.DB) error {
		changed, err := roleSetDiffers(tx, userID, roles)
		if err != nil {
			return err
		}
		if err := tx.Model(&user).Association("Roles").Replace(roles); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		if err := BumpCredentialEpoch(tx, userID, "roles_changed"); err != nil {
			return err
		}
		// 撤 refresh 比照 invalidateCredentialsLocked：換發本就會被世代閘拒，撤銷是為了
		// 讓失效原因可稽核，並避免留下一批 revoked_at IS NULL 卻實際不可用的憑證列
		if _, err := RevokeAllRefreshTokens(tx, userID, model.RefreshRevokeCredentialEpoch); err != nil {
			return fmt.Errorf("撤銷刷新憑證失敗: %w", err)
		}
		return nil
	}
	var assignErr error
	if keepsAdmin {
		assignErr = WithUserCredentialLock(s.db, userID, applyRoles)
	} else {
		// 取鎖順序 system → user，與停用路徑同形
		assignErr = WithLocalAdminInvariant(s.db, userID, func(tx *gorm.DB) error {
			return withUserCredentialLockTx(tx, userID, applyRoles)
		})
	}
	if assignErr != nil {
		if errors.Is(assignErr, ErrLastAdmin) {
			return assignErr
		}
		log.Printf("[UserService] AssignRoles: Replace roles error: %v", assignErr)
		return fmt.Errorf("分配角色失敗: %w", assignErr)
	}

	log.Printf("[UserService] AssignRoles: Roles assigned successfully, UserID: %d, Roles: %v", userID, roleNames)
	return nil
}

// UpdateStatus 更新使用者狀態（啟用/禁用）
func (s *UserService) UpdateStatus(userID uint, active bool) error {
	// 檢查使用者是否存在
	var user model.User
	if err := s.db.Preload("Roles").First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		log.Printf("[UserService] UpdateStatus: Query user error: %v", err)
		return fmt.Errorf("查詢使用者失敗: %w", err)
	}

	// 如果要禁用管理員，檢查是否為最後一個
	if !active {
		isAdmin := false
		for _, role := range user.Roles {
			if role.Name == model.RoleAdmin {
				isAdmin = true
				break
			}
		}

		if isAdmin {
			var activeAdminCount int64
			err := s.db.Model(&model.User{}).
				Joins("JOIN user_roles ON user_roles.user_id = users.id").
				Joins("JOIN roles ON roles.id = user_roles.role_id").
				Where("roles.name = ? AND users.active = ? AND users.deleted_at IS NULL AND users.id != ?",
					model.RoleAdmin, true, userID).
				Count(&activeAdminCount).Error

			if err != nil {
				log.Printf("[UserService] UpdateStatus: Count active admins error: %v", err)
				return fmt.Errorf("檢查活動管理員數量失敗: %w", err)
			}

			if activeAdminCount == 0 {
				return ErrLastAdmin
			}
		}
	}

	// 更新狀態。停用時經「本地 admin 不變式」的系統級鎖：判定於鎖內重讀且與寫入同交易
	//（2.7）——上方 isAdmin 的既有檢查在鎖外、且只問「還有沒有 active admin」，
	// 對「最後一個本地 admin，但另有外部身分 admin」與並發停用兩種情形皆無感。
	// 啟用（active=true）不減少本地 admin，也不使任何憑證失效，無需取鎖
	writeStatus := func(tx *gorm.DB) error {
		return tx.Model(&model.User{}).Where("id = ?", userID).Update("active", active).Error
	}
	var statusErr error
	if active {
		statusErr = writeStatus(s.db)
	} else {
		// 停用同時推進 credential_epoch（spec「帳號停用」情境）：**access token
		// 是 stateless 的**，只撤 refresh 對它毫無作用，攻擊者手上的 access 與尚未兌換的
		// ticket／MFA pending／connect grant 會全數撐滿一個 TTL。
		// 三步同交易同鎖（active=false ＋ 世代推進 ＋ 撤 refresh）：中途失敗一律整筆回滾，
		// 不得停在「已停用但憑證仍有效」的中間態。取鎖順序 system → user
		statusErr = WithLocalAdminInvariant(s.db, userID, func(tx *gorm.DB) error {
			return withUserCredentialLockTx(tx, userID, func(tx *gorm.DB) error {
				if err := writeStatus(tx); err != nil {
					return err
				}
				if err := BumpCredentialEpoch(tx, userID, "account_disabled"); err != nil {
					return err
				}
				// 撤銷成因沿用 disabled（既有稽核語義，非 credential_epoch）
				if _, err := RevokeAllRefreshTokens(tx, userID, model.RefreshRevokeDisabled); err != nil {
					return fmt.Errorf("撤銷刷新憑證失敗: %w", err)
				}
				return nil
			})
		})
	}
	if statusErr != nil {
		if errors.Is(statusErr, ErrLastAdmin) {
			return statusErr
		}
		log.Printf("[UserService] UpdateStatus: Update status error: %v", statusErr)
		return fmt.Errorf("更新使用者狀態失敗: %w", statusErr)
	}

	// 停用即時撤權（8.2.5）：鎖外收線三管道——
	// 協議會話（活著的目標機 shell 不得等閒置逾時）、唯讀訂閱（監看／分享不建
	// sessions 列，會話掃描完全掃不到）、錄影 token（in-memory 且不做世代比對）。
	// 與外部身分四操作共用 revokeUserAccess 出口，避免各寫一份而漏掉其中一條。
	// 個別失敗不回滾停用本身——停用已生效是主要安全目標，收線失敗記日誌人工跟進
	if !active {
		s.revokeUserAccess(userID, "account_disabled")
	}

	log.Printf("[UserService] UpdateStatus: Status updated successfully, UserID: %d, Active: %v", userID, active)
	return nil
}

// SetInactivityExempt 設定閒置停用豁免旗標（PCI 8.2.6；呼叫端負責權限與審計）
func (s *UserService) SetInactivityExempt(userID uint, exempt bool) error {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("查詢使用者失敗: %w", err)
	}
	if err := s.db.Model(&model.User{}).Where("id = ?", userID).
		Update("inactivity_exempt", exempt).Error; err != nil {
		return fmt.Errorf("更新豁免旗標失敗: %w", err)
	}
	log.Printf("[UserService] SetInactivityExempt: UserID=%d, exempt=%v", userID, exempt)
	return nil
}

// ChangePassword 管理員重設他人密碼。
// 依政策 force_change_on_reset 設 must_change_password（PCI 8.3.5：重設後首次使用須改密）
func (s *UserService) ChangePassword(userID uint, newPassword string) error {
	forceChange := s.policies != nil && s.policies.GetBool(policy.PolicyForceChangeOnReset)
	return s.setPassword(userID, newPassword, forceChange)
}

// SelfChangePassword 自助改密（/auth/change-password）：
// userID 一律取自 token claims；須驗證目前密碼，防 token 被竊後直接奪取帳號
func (s *UserService) SelfChangePassword(userID uint, oldPassword, newPassword string) error {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("查詢使用者失敗: %w", err)
	}
	if user.IsExternal() {
		return ErrExternalUserPassword
	}
	if err := crypto.DefaultPasswordVerifier().Verify(user.Password, []byte(oldPassword)); err != nil {
		return ErrOldPasswordMismatch
	}
	return s.setPassword(userID, newPassword, false)
}

// setPassword 密碼設定共用路徑：政策驗證 → 更新密碼與強制改密旗標 → 寫入歷史（同事務）
func (s *UserService) setPassword(userID uint, newPassword string, mustChange bool) error {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		log.Printf("[UserService] setPassword: Query user error: %v", err)
		return fmt.Errorf("查詢使用者失敗: %w", err)
	}

	// 外部身分帳號的密碼真身在身分提供者端；本地設定只會製造「改了卻沒生效」的假象，
	// 更嚴重的是 OIDC 帳號一旦有可用本地密碼，即取得繞過 IdP（連同其 MFA、條件式存取、
	// provider 停用治理）的永久後門，必須明確拒絕
	if user.IsExternal() {
		return ErrExternalUserPassword
	}

	// 新密碼須異於目前密碼：獨立於歷史政策，history_count=0 時仍成立——
	// 否則 must_change 用戶可「改」成相同值卻清掉強制改密旗標，8.3.5 形同虛設
	if crypto.DefaultPasswordVerifier().Verify(user.Password, []byte(newPassword)) == nil {
		return &policy.PasswordPolicyViolation{
			Reason:  policy.ErrPasswordReused,
			Message: "新密碼不可與目前密碼相同",
			Code:    apierror.CodePasswordSameAsCurrent,
		}
	}

	// 密碼政策驗證（單一 validator，含歷史重用比對）
	if err := s.ValidateNewPassword(userID, newPassword); err != nil {
		return err
	}

	hashedPassword, err := crypto.DefaultPasswordHasher().Hash([]byte(newPassword))
	if err != nil {
		log.Printf("[UserService] setPassword: Hash password error: %v", err)
		return fmt.Errorf("密碼加密失敗: %w", err)
	}

	// 寫入與世代推進同交易同鎖：改密 SHALL 推進 credential_epoch——
	// **access token 是 stateless 的**，撤 refresh 對它毫無作用，不推進世代則
	// 「密碼可能已洩漏所以改掉」之後，竊得舊 access 者仍可用滿一整個 TTL，
	// 且未兌換的 connect grant／MFA pending 一併存活。
	// 改密者本人不會被自己的推進鎖在門外：換發路徑以**現查**世代簽新會話
	now := time.Now()
	err = WithUserCredentialLock(s.db, userID, func(tx *gorm.DB) error {
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
			"password":             string(hashedPassword),
			"password_changed_at":  now,
			"must_change_password": mustChange,
		}).Error; err != nil {
			return fmt.Errorf("更新密碼失敗: %w", err)
		}
		if err := s.recordPasswordHistory(tx, userID, string(hashedPassword)); err != nil {
			return err
		}
		return BumpCredentialEpoch(tx, userID, "password_changed")
	})
	if err != nil {
		log.Printf("[UserService] setPassword: Transaction error: %v", err)
		return err
	}

	// 改密撤銷全部會話（spec：自助或 admin 重設皆同）——密碼可能因洩漏而改，
	// 各裝置既存會話須重新驗證。強制改密流程隨後由 handler 換發新會話，順序不受影響。
	//
	// **刻意不呼叫 revokeUserAccess**：spec 對改密只要求推進世代，未列入收線；
	// 改密是使用者自己的例行操作，連帶砍掉其正在進行的維運 shell 與監看不是該條款的
	// 意圖（停用／刪除／解綁才是「此人不該再有存取」的語義）
	if n, err := RevokeAllRefreshTokens(s.db, userID, model.RefreshRevokePasswordChange); err != nil {
		log.Printf("[UserService] setPassword: 改密撤銷 refresh 憑證失敗 (UserID=%d): %v", userID, err)
	} else if n > 0 {
		log.Printf("[UserService] setPassword: 已撤銷 %d 個 refresh 憑證 (UserID=%d)", n, userID)
	}

	log.Printf("[UserService] setPassword: Password changed successfully, UserID: %d", userID)
	return nil
}

// Unlock 管理員手動解鎖帳號（8.3.4）：清零計數與鎖定時間（呼叫端負責權限與審計）
func (s *UserService) Unlock(userID uint) error {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("查詢使用者失敗: %w", err)
	}

	if err := s.db.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"failed_login_attempts": 0,
		"locked_until":          nil,
	}).Error; err != nil {
		return fmt.Errorf("解鎖帳號失敗: %w", err)
	}

	log.Printf("[UserService] Unlock: Account unlocked, UserID: %d", userID)
	return nil
}
