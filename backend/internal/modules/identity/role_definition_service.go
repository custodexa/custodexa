package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// 自訂角色定義服務。
//
// **僅供內部使用，不註冊任何對外路由**：既有 /roles 與指派入口維持相容目錄，
// 指派守衛、風險確認與補償控制完成後才把本服務接到新入口。
// 每次寫入在服務邊界以伺服器解析的內建超級管理者身分裁決；持有全部可指派權限、
// 或顯示名稱叫 admin 都不構成定義權。

// 錯誤哨兵（對外機器碼由 apierror 登錄；無權沿既有 forbidden，不把角色／權限名放進拒絕）。
var (
	ErrRoleDefinitionForbidden = errors.New("role definition: forbidden")
	ErrRoleDefinitionLocked    = errors.New("role definition: locked")
	ErrRoleDefinitionInUse     = errors.New("role definition: in use")
	ErrRoleDefinitionConflict  = errors.New("role definition: conflict")
	ErrRoleDefinitionNotFound  = errors.New("role definition: not found")
	ErrRoleDefinitionInput     = errors.New("role definition: invalid input")
	// ErrRoleStateEventWriterMissing 狀態事件寫入面未注入（fail-close，不當成功略過）。
	ErrRoleStateEventWriterMissing = errors.New("role definition: state event writer missing")
	// ErrRoleGraderMissing 授權變更分級器未注入，而被修改的角色有持有者或引用（fail-close）。
	ErrRoleGraderMissing = errors.New("role definition: grant grader missing")
)

// legacyRoleCatalogCond 升級前存量的相容角色目錄（definition_version = 0）。
// 舊的列舉、替換、追加、建帳號帶角色、釘住與映射寫入口只認這個目錄：新範本與新建自訂角色
// 即使知道名稱或 ID 也不能從舊入口寫入。不靠可改的名稱區分；本邊界在後續段以新入口取代。
const legacyRoleCatalogCond = "definition_version = 0"

const (
	roleNameMaxRunes        = 50
	roleDescriptionMaxRunes = 200
)

// RoleDefinitionEvent 交給權限狀態事件寫入面的可重放事件（只含穩定識別、鍵與版本）。
type RoleDefinitionEvent struct {
	Action            string
	RoleID            uint
	DefinitionVersion int64
	AuthzVersion      int64
	Before, After     []string
	BuiltinKey        string
}

// RoleStateEventWriter 在呼叫端交易內補足權限狀態事件證據（失敗須逸出交易，使整筆回滾）。
// 生產實作是 NewPermissionChainEventWriter：權限事件鏈本身由 authz.AdvanceVersion 在版本推進時
// 同交易寫入（快照含角色定義與權限集合），此介面再於交易結尾對齊鏈頭與實際狀態。
type RoleStateEventWriter interface {
	WriteRoleDefinitionEvent(tx *gorm.DB, ev RoleDefinitionEvent) error
}

type permissionChainEventWriter struct{}

// NewPermissionChainEventWriter 以權限狀態事件鏈（authz.SettlePermissionChange）實作 RoleStateEventWriter。
// 事件鏈尚未啟用或來源未注入時為 no-op（與其他權限寫入點一致）。
func NewPermissionChainEventWriter() RoleStateEventWriter { return permissionChainEventWriter{} }

func (permissionChainEventWriter) WriteRoleDefinitionEvent(tx *gorm.DB, _ RoleDefinitionEvent) error {
	return authz.SettlePermissionChange(tx)
}

// RoleDefinition 服務層讀取形狀（不直接回 ORM 的 Users 關聯）。
type RoleDefinition struct {
	ID                uint
	Name              string
	Description       string
	BuiltinKey        string
	Locked            bool
	DefinitionVersion int64
	Permissions       []string
	TemplateRoleID    *uint
	// MissingDependencies／BlockedScreens：集合缺必要依賴時明示缺漏與持有者無法使用的畫面
	// （允許儲存、不補授；皆齊備時為空切片）。
	MissingDependencies []authz.MissingDependency
	BlockedScreens      []authz.BlockedScreen
	// Scopable／NodeRangeNoEffect 節點限定的兩個布林，由 authz 三態判定轉出。
	// NodeScopedBindingCount 只在單筆讀取與寫入回應填入（列表不查）。
	Scopable               bool
	NodeRangeNoEffect      bool
	NodeScopedBindingCount int64
}

// RoleDefinitionService 角色定義服務。
type RoleDefinitionService struct {
	db     *gorm.DB
	audit  port.TxSink
	events RoleStateEventWriter
	// grader 角色內容修改的授權變更分級與告警落地；nil 時修改有持有者或引用的角色一律拒絕。
	grader *GrantGrader
	now    func() time.Time
	// afterCommitHook 修改提交之後、角色側重查之前的暫停點；只供測試排出並發排程，生產恆為 nil。
	afterCommitHook func()
}

// NewRoleDefinitionService 建立服務。audit／events 為 nil 時所有寫入 fail-close（回錯、整筆回滾）；
// grader 為 nil 時修改有持有者或引用的角色同樣回錯（無持有者也無引用者照常修改）。
func NewRoleDefinitionService(db *gorm.DB, audit port.TxSink, events RoleStateEventWriter, grader *GrantGrader) *RoleDefinitionService {
	return &RoleDefinitionService{db: db, audit: audit, events: events, grader: grader, now: time.Now}
}

// RoleInput 新增與修改的輸入。
type RoleInput struct {
	Name        string
	Description string
	Permissions []string
	// TemplateRoleID 新建時可選的起手來源（只作說明）；須為未刪除、非超級管理者的角色，修改時忽略。
	TemplateRoleID *uint
}

func permStrings(ps []authz.Permission) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return out
}

func validateRoleText(name, desc string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > roleNameMaxRunes || utf8.RuneCountInString(desc) > roleDescriptionMaxRunes {
		return "", "", ErrRoleDefinitionInput
	}
	return name, desc, nil
}

// requireSuperAdmin 在交易內重驗操作者：存在、啟用、人類主體、且全域生效的內建超管身分。
func requireSuperAdmin(tx *gorm.DB, actorID uint) (*model.User, error) {
	var u model.User
	if err := tx.First(&u, actorID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleDefinitionForbidden
		}
		return nil, fmt.Errorf("讀取操作者失敗: %w", err)
	}
	if !u.Active || u.Kind == model.KindAgent {
		return nil, ErrRoleDefinitionForbidden
	}
	p, err := authz.ResolveUserOn(tx, actorID, authz.TokenFacts{SubjectKind: model.KindHuman})
	if err != nil {
		return nil, err
	}
	if !p.IsSuperAdmin() {
		return nil, ErrRoleDefinitionForbidden
	}
	return &u, nil
}

// permissionsOf 角色的權限鍵集合：內建與範本取程式中的集合，自訂取 role_permissions。
func permissionsOf(tx *gorm.DB, r *model.Role) ([]string, error) {
	if r.BuiltinKey != nil {
		return permStrings(authz.TemplatePermissions(*r.BuiltinKey)), nil
	}
	if r.DefinitionVersion == 0 {
		return []string{}, nil // 存量非內建角色：沒有新集合
	}
	var keys []string
	if err := tx.Model(&model.RolePermission{}).Where("role_id = ?", r.ID).Order("permission_key").Pluck("permission_key", &keys).Error; err != nil {
		return nil, fmt.Errorf("讀取角色權限集合失敗: %w", err)
	}
	if keys == nil {
		keys = []string{}
	}
	return keys, nil
}

func toDefinition(tx *gorm.DB, r *model.Role) (*RoleDefinition, error) {
	perms, err := permissionsOf(tx, r)
	if err != nil {
		return nil, err
	}
	d := &RoleDefinition{ID: r.ID, Name: r.Name, Description: r.Description, DefinitionVersion: r.DefinitionVersion,
		Permissions: perms, TemplateRoleID: r.TemplateRoleID, Locked: r.BuiltinKey != nil || r.DefinitionVersion == 0}
	ps := make([]authz.Permission, len(perms))
	for i, k := range perms {
		ps[i] = authz.Permission(k)
	}
	d.MissingDependencies = authz.MissingDependencies(ps)
	d.BlockedScreens = authz.BlockedScreens(ps)
	class, _ := authz.ClassifyRoleNodeScopability(*r, ps)
	d.Scopable, d.NodeRangeNoEffect = scopeFlags(class)
	if r.BuiltinKey != nil {
		d.BuiltinKey = *r.BuiltinKey
	}
	return d, nil
}

// ListDefinitions 全部未刪除角色（含鎖定範本與自訂角色）。唯讀，不推進任何版本。
func (s *RoleDefinitionService) ListDefinitions(_ context.Context) ([]RoleDefinition, error) {
	var roles []model.Role
	if err := s.db.Order("id").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("讀取角色失敗: %w", err)
	}
	out := make([]RoleDefinition, 0, len(roles))
	for i := range roles {
		d, err := toDefinition(s.db, &roles[i])
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, nil
}

// GetDefinition 單一角色。
func (s *RoleDefinitionService) GetDefinition(_ context.Context, roleID uint) (*RoleDefinition, error) {
	var r model.Role
	if err := s.db.First(&r, roleID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleDefinitionNotFound
		}
		return nil, fmt.Errorf("讀取角色失敗: %w", err)
	}
	return toDefinitionWithCount(s.db, &r)
}

// toDefinitionWithCount 單筆回應用：加上以節點範圍持有此角色的指派筆數。
func toDefinitionWithCount(tx *gorm.DB, r *model.Role) (*RoleDefinition, error) {
	d, err := toDefinition(tx, r)
	if err != nil {
		return nil, err
	}
	n, err := nodeScopedBindingCount(tx, r.ID)
	if err != nil {
		return nil, err
	}
	d.NodeScopedBindingCount = n
	return d, nil
}

// nodeScopedBindingCount 角色目前的節點範圍指派筆數：直接指派列加使用者群組指派列。
func nodeScopedBindingCount(tx *gorm.DB, roleID uint) (int64, error) {
	var direct int64
	if err := tx.Raw("SELECT COUNT(*) FROM user_roles WHERE role_id = ? AND scope_kind = ?", roleID, model.ScopeKindNodes).Scan(&direct).Error; err != nil {
		return 0, fmt.Errorf("讀取節點範圍指派數失敗: %w", err)
	}
	group, err := authz.CountNodeScopedGroupRoleBindings(tx, roleID)
	if err != nil {
		return 0, err
	}
	return direct + group, nil
}

// State 目前的角色定義權限狀態（稽核附證與備份核對用）：自訂角色集合、定義版本、範本識別，
// 以及相容目錄與內建角色的 ID。只含穩定識別與權限鍵，不含名稱與說明。唯讀。
func (s *RoleDefinitionService) State(_ context.Context) (authz.RoleDefinitionState, error) {
	var roles []model.Role
	if err := s.db.Order("id").Find(&roles).Error; err != nil {
		return authz.RoleDefinitionState{}, fmt.Errorf("讀取角色失敗: %w", err)
	}
	st := authz.RoleDefinitionState{Format: authz.RoleDefinitionStateFormat,
		LegacyCatalogIDs: []uint{}, BuiltinRoleIDs: []uint{}, Roles: []authz.RoleDefinitionStateRole{}}
	for i := range roles {
		r := &roles[i]
		switch {
		case r.BuiltinKey != nil:
			st.BuiltinRoleIDs = append(st.BuiltinRoleIDs, r.ID)
		case r.DefinitionVersion == 0:
			st.LegacyCatalogIDs = append(st.LegacyCatalogIDs, r.ID)
		default:
			keys, err := permissionsOf(s.db, r)
			if err != nil {
				return authz.RoleDefinitionState{}, err
			}
			st.Roles = append(st.Roles, authz.RoleDefinitionStateRole{RoleID: r.ID,
				DefinitionVersion: r.DefinitionVersion, TemplateRoleID: r.TemplateRoleID, Keys: keys})
		}
	}
	return st.Canonical(), nil
}

// Create 新增自訂角色（明確權限集合，無內建身分）。
func (s *RoleDefinitionService) Create(ctx context.Context, actorID uint, in RoleInput) (*RoleDefinition, error) {
	return s.write(ctx, actorID, model.ActionRoleDefinitionCreate, func(tx *gorm.DB, actor *model.User) (*writeResult, error) {
		return s.insertRole(tx, in, nil)
	})
}

// Copy 以一般內建範本或既有角色為起手來源新增自訂角色：只複製可指派集合，來源只作說明。
// 超級管理者範本不可複製（整個請求拒絕）；審核資格與連線豁免不隨複製取得。
func (s *RoleDefinitionService) Copy(ctx context.Context, actorID, sourceRoleID uint, name, description string) (*RoleDefinition, error) {
	return s.write(ctx, actorID, model.ActionRoleDefinitionCopy, func(tx *gorm.DB, actor *model.User) (*writeResult, error) {
		var src model.Role
		if err := tx.First(&src, sourceRoleID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, ErrRoleDefinitionNotFound
			}
			return nil, fmt.Errorf("讀取來源角色失敗: %w", err)
		}
		if src.BuiltinKey != nil && *src.BuiltinKey == model.BuiltinSuperAdmin {
			return nil, ErrRoleDefinitionLocked
		}
		perms, err := permissionsOf(tx, &src)
		if err != nil {
			return nil, err
		}
		sid := src.ID
		return s.insertRole(tx, RoleInput{Name: name, Description: description, Permissions: perms}, &sid)
	})
}

// Update 修改自訂角色的名稱、說明與權限集合（整組取代），帶期望定義版本。
func (s *RoleDefinitionService) Update(ctx context.Context, actorID, roleID uint, expectedVersion int64, in RoleInput) (*RoleDefinition, error) {
	return s.write(ctx, actorID, model.ActionRoleDefinitionUpdate, func(tx *gorm.DB, actor *model.User) (*writeResult, error) {
		role, err := lockCustomRole(tx, roleID, expectedVersion)
		if err != nil {
			return nil, err
		}
		name, desc, err := validateRoleText(in.Name, in.Description)
		if err != nil {
			return nil, err
		}
		perms, err := authz.NormalizeRolePermissions(in.Permissions)
		if err != nil {
			return nil, err
		}
		// 鎖定角色列之後以已提交讀取重驗持有者；不加新鎖，並發的指派由提交後偵測補上。
		if err := rejectRoleUpdateForAgents(tx, role.ID, perms); err != nil {
			return nil, err
		}
		if name != role.Name {
			if err := ensureNameFree(tx, name, role.ID); err != nil {
				return nil, err
			}
		}
		before, err := permissionsOf(tx, role)
		if err != nil {
			return nil, err
		}
		if err := tx.Where("role_id = ?", role.ID).Delete(&model.RolePermission{}).Error; err != nil {
			return nil, fmt.Errorf("清除角色權限集合失敗: %w", err)
		}
		if err := insertPermissions(tx, role.ID, perms); err != nil {
			return nil, err
		}
		grade, err := s.gradeContentChange(tx, actor, role, name, before, perms)
		if err != nil {
			return nil, err
		}
		if err := bumpDefinition(tx, role, map[string]any{"name": name, "description": desc}); err != nil {
			return nil, err
		}
		return &writeResult{role: role, before: before, after: permStrings(perms), grade: grade}, nil
	})
}

// Delete 刪除自訂角色（軟刪）。仍有直接／群組指派或有效映射支持即拒絕，不級聯撤權；
// 僅作說明的範本來源參照清除，已複製角色的集合與版本不變。
func (s *RoleDefinitionService) Delete(ctx context.Context, actorID, roleID uint, expectedVersion int64) error {
	_, err := s.write(ctx, actorID, model.ActionRoleDefinitionDelete, func(tx *gorm.DB, actor *model.User) (*writeResult, error) {
		role, err := lockCustomRole(tx, roleID, expectedVersion)
		if err != nil {
			return nil, err
		}
		refs, err := roleReferenceCounts(tx, role.ID)
		if err != nil {
			return nil, err
		}
		if refs.Total() > 0 {
			return nil, ErrRoleDefinitionInUse
		}
		before, err := permissionsOf(tx, role)
		if err != nil {
			return nil, err
		}
		if err := tx.Model(&model.Role{}).Where("template_role_id = ?", role.ID).Update("template_role_id", nil).Error; err != nil {
			return nil, fmt.Errorf("清除範本來源參照失敗: %w", err)
		}
		// 軟刪並釋出名稱（roles.name 唯一索引含已刪列）；歷史以角色 ID 對應審計。
		suffix := fmt.Sprintf("~del%d", role.ID)
		base := []rune(role.Name)
		if len(base)+len(suffix) > roleNameMaxRunes {
			base = base[:roleNameMaxRunes-len(suffix)]
		}
		if err := bumpDefinition(tx, role, map[string]any{"name": string(base) + suffix, "deleted_at": s.now().UTC()}); err != nil {
			return nil, err
		}
		return &writeResult{role: role, before: before, after: []string{}}, nil
	})
	return err
}

type writeResult struct {
	role          *model.Role
	before, after []string
	template      *uint
	// grade 角色內容修改的授權變更分級；沒有分類命中時為 nil。
	grade *roleContentGrade
}

func ensureNameFree(tx *gorm.DB, name string, exceptID uint) error {
	var n int64
	if err := tx.Unscoped().Model(&model.Role{}).Where("name = ? AND id <> ?", name, exceptID).Count(&n).Error; err != nil {
		return fmt.Errorf("檢查角色名稱失敗: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("%w: 名稱已被使用", ErrRoleDefinitionConflict)
	}
	return nil
}

func insertPermissions(tx *gorm.DB, roleID uint, perms []authz.Permission) error {
	for _, p := range perms {
		if err := tx.Create(&model.RolePermission{RoleID: roleID, PermissionKey: string(p)}).Error; err != nil {
			return fmt.Errorf("寫入角色權限失敗: %w", err)
		}
	}
	return nil
}

// checkTemplateSource 新建時由呼叫端指定的起手來源：交易內重讀，必須存在、未刪除，且不是超級管理者範本
// （與 Copy 的來源規則一致）。不合格一律視為輸入錯誤，避免寫出還原核對會拒絕的懸空參照。
func checkTemplateSource(tx *gorm.DB, id uint) error {
	var src model.Role
	if err := tx.First(&src, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: 起手來源不存在", ErrRoleDefinitionInput)
		}
		return fmt.Errorf("讀取起手來源失敗: %w", err)
	}
	if src.BuiltinKey != nil && *src.BuiltinKey == model.BuiltinSuperAdmin {
		return fmt.Errorf("%w: 超級管理者不可作為起手來源", ErrRoleDefinitionInput)
	}
	return nil
}

func (s *RoleDefinitionService) insertRole(tx *gorm.DB, in RoleInput, template *uint) (*writeResult, error) {
	name, desc, err := validateRoleText(in.Name, in.Description)
	if err != nil {
		return nil, err
	}
	perms, err := authz.NormalizeRolePermissions(in.Permissions)
	if err != nil {
		return nil, err
	}
	if err := ensureNameFree(tx, name, 0); err != nil {
		return nil, err
	}
	if template == nil && in.TemplateRoleID != nil {
		if err := checkTemplateSource(tx, *in.TemplateRoleID); err != nil {
			return nil, err
		}
		template = in.TemplateRoleID
	}
	role := &model.Role{Name: name, Description: desc, DefinitionVersion: 1, TemplateRoleID: template}
	// 保留名稱的 BeforeCreate 會帶入內建識別；此處已因名稱唯一而擋下同名，這裡再確認不會冒認。
	if err := tx.Create(role).Error; err != nil {
		return nil, fmt.Errorf("建立角色失敗: %w", err)
	}
	if role.BuiltinKey != nil {
		return nil, ErrRoleDefinitionLocked
	}
	if err := insertPermissions(tx, role.ID, perms); err != nil {
		return nil, err
	}
	return &writeResult{role: role, before: []string{}, after: permStrings(perms), template: template}, nil
}

// lockCustomRole 交易內重讀目標並鎖列；內建、範本與存量角色一律鎖定；版本不符為衝突。
func lockCustomRole(tx *gorm.DB, roleID uint, expected int64) (*model.Role, error) {
	var r model.Role
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&r, roleID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleDefinitionNotFound
		}
		return nil, fmt.Errorf("讀取角色失敗: %w", err)
	}
	if r.BuiltinKey != nil || r.DefinitionVersion == 0 {
		return nil, ErrRoleDefinitionLocked
	}
	if r.DefinitionVersion != expected {
		return nil, fmt.Errorf("%w: 版本已變動", ErrRoleDefinitionConflict)
	}
	return &r, nil
}

// bumpDefinition 以條件式更新推進定義版本（WHERE 帶舊版本，防止覆蓋）。
func bumpDefinition(tx *gorm.DB, r *model.Role, set map[string]any) error {
	set["definition_version"] = r.DefinitionVersion + 1
	res := tx.Model(&model.Role{}).Where("id = ? AND definition_version = ?", r.ID, r.DefinitionVersion).Updates(set)
	if res.Error != nil {
		return fmt.Errorf("更新角色失敗: %w", res.Error)
	}
	if res.RowsAffected != 1 {
		return fmt.Errorf("%w: 版本已變動", ErrRoleDefinitionConflict)
	}
	r.DefinitionVersion++
	return nil
}

// write 共同流程：重驗超管 → 驗輸入／參照並寫角色內容 → 兩個版本 → 服務審計 → 狀態事件。
// 任一步失敗整筆回滾；被拒絕的操作不產生成功審計或事件。
func (s *RoleDefinitionService) write(ctx context.Context, actorID uint, action model.AuditAction,
	body func(tx *gorm.DB, actor *model.User) (*writeResult, error)) (*RoleDefinition, error) {
	var out *RoleDefinition
	var committed *writeResult
	var committedActor Operator
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		actor, err := requireSuperAdmin(tx, actorID)
		if err != nil {
			return err
		}
		committedActor = Operator{UserID: actor.ID, Username: actor.Username}
		// 先比對事件鏈鏈頭與目前狀態，繞過應用層的直寫記成無來源變動，不混進本次合法事件的差集。
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		res, err := body(tx, actor)
		if err != nil {
			return err
		}
		committed = res
		if err := authz.AdvanceVersion(tx); err != nil {
			return err
		}
		authzVersion, err := authz.CurrentVersion(tx)
		if err != nil {
			return err
		}
		details, err := json.Marshal(roleDefinitionAuditDetails(action, res, authzVersion))
		if err != nil {
			return fmt.Errorf("序列化角色定義稽核詳情失敗: %w", err)
		}
		rid := res.role.ID
		if err := port.WriteInTx(s.audit, tx, port.AuditEvent{
			Actor:      gatewayapi.Actor{UserID: actor.ID, Username: actor.Username},
			Action:     string(action),
			Resource:   string(model.ResourceRole),
			ResourceID: &rid,
			Status:     string(model.StatusSuccess),
			Details:    string(details),
		}); err != nil {
			return fmt.Errorf("角色定義留痕失敗: %w", err)
		}
		if err := s.grader.raiseRoleContent(tx, Operator{UserID: actor.ID, Username: actor.Username}, res); err != nil {
			return err
		}
		if s.events == nil {
			return ErrRoleStateEventWriterMissing
		}
		if err := s.events.WriteRoleDefinitionEvent(tx, RoleDefinitionEvent{Action: string(action), RoleID: rid,
			DefinitionVersion: res.role.DefinitionVersion, AuthzVersion: authzVersion, Before: res.before, After: res.after}); err != nil {
			return fmt.Errorf("寫入權限狀態事件失敗: %w", err)
		}
		if action != model.ActionRoleDefinitionDelete {
			var fresh model.Role
			if err := tx.First(&fresh, rid).Error; err != nil {
				return fmt.Errorf("讀回角色失敗: %w", err)
			}
			out, err = toDefinitionWithCount(tx, &fresh)
			return err
		}
		return nil
	})
	authz.NotifyVersionCommittedAfter(s.db, err)
	if err != nil {
		return nil, err
	}
	if action == model.ActionRoleDefinitionUpdate && committed != nil {
		if s.afterCommitHook != nil {
			s.afterCommitHook()
		}
		// 提交後在同一請求內以新交易重查持有者（角色側）；失敗不回復已提交的修改。
		s.grader.detectRestrictedAgentHolders(s.db, agentDetection{
			by: DetectedByRoleUpdate, op: committedActor, roleID: committed.role.ID,
			action: model.ActionRoleDefinitionUpdate, resource: string(model.ResourceRole), resourceID: committed.role.ID,
			before: committed.before, after: committed.after,
		})
	}
	return out, nil
}

// roleDefinitionAuditDetails 審計詳情：角色 ID、權限集合增減、定義版本、範本來源；不含秘密。
func roleDefinitionAuditDetails(action model.AuditAction, res *writeResult, authzVersion int64) map[string]any {
	added, removed := setDiff(res.before, res.after)
	d := map[string]any{"role_id": res.role.ID, "definition_version": res.role.DefinitionVersion,
		"authz_version": authzVersion, "added": added, "removed": removed}
	if res.template != nil {
		d["template_role_id"] = *res.template
	}
	if g := res.grade; g != nil && len(g.op.Marks) > 0 {
		d["grant_marks"] = g.op.Marks
		d["correlation_id"] = g.corr
		d["holder_count"] = len(g.impact.HolderIDs)
		d["group_binding_count"] = g.impact.GroupBindings
		d["mapping_rule_count"] = g.impact.MappingRules
	}
	// 缺必要依賴時允許儲存，明示缺漏與持有者無法使用的畫面並留痕（沿用同一 action，不新增）。
	ps := make([]authz.Permission, len(res.after))
	for i, k := range res.after {
		ps[i] = authz.Permission(k)
	}
	if md := authz.MissingDependencies(ps); len(md) > 0 {
		d["missing_dependencies"] = md
		d["blocked_screens"] = authz.BlockedScreens(ps)
	}
	return d
}

func setDiff(before, after []string) (added, removed []string) {
	b, a := map[string]bool{}, map[string]bool{}
	for _, k := range before {
		b[k] = true
	}
	for _, k := range after {
		a[k] = true
	}
	added, removed = []string{}, []string{}
	for k := range a {
		if !b[k] {
			added = append(added, k)
		}
	}
	for k := range b {
		if !a[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}
