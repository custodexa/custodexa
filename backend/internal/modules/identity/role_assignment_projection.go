package identity

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 角色與帳號的唯讀判定投影。
//
// 投影只讀、不寫任何資料、不經寫入關卡的 Check：每個欄位都直接呼叫寫入側已經在用的判定函式
// （保護身分、目標集合、直接映射 allowlist、群組可綁定、管理類分類、帳號身分操作分類），
// 畫面據此呈現狀態，伺服器對寫入的裁決仍是最終結果。

// 角色在目前操作者與組裝目標集合下的指派狀態。
const (
	// AssignmentStateOpen 沒有保護身分與目標集合這兩層限制（不代表操作者一定能指派：
	// 指派能力、目標主體種類、agent 限制等仍由原服務裁決）。
	AssignmentStateOpen = "open"
	// AssignmentStateNotOpen 不在組裝注入的目標集合。
	AssignmentStateNotOpen = "not_open"
	// AssignmentStateProtected 保護角色（超級管理者或系統安全管理員內建身分，或含系統安全管理員專屬權限點的角色），而操作者不是超級管理者。
	AssignmentStateProtected = "protected"
)

// 帳號身分操作在保護身分這一層的分類。
const (
	AccountOpClassAllowed   = "allowed"
	AccountOpClassNotify    = "notify"
	AccountOpClassSuperOnly = "super_only"
)

// AccountOpKeys 帳號操作分類的八個鍵（回應的鍵集合與順序）。
var AccountOpKeys = []string{
	"set_password", "disable_mfa", "bind_identity", "unbind_identity",
	"unbind_and_disable", "disable", "enable", "delete",
}

// RoleReferenceCounts 角色被引用的三種來源計數；刪除角色與投影共用同一個查詢。
type RoleReferenceCounts struct {
	Direct        int64 `json:"direct"`
	GroupBindings int64 `json:"group_bindings"`
	MappingRules  int64 `json:"mapping_rules"`
}

// Total 三種來源合計；大於 0 時角色不可刪除。
func (c RoleReferenceCounts) Total() int64 { return c.Direct + c.GroupBindings + c.MappingRules }

// roleReferenceCounts 角色的引用計數：直接指派列、使用者群組指派列、未刪除的映射規則（含已停用）。
func roleReferenceCounts(tx *gorm.DB, roleID uint) (RoleReferenceCounts, error) {
	var c RoleReferenceCounts
	if err := tx.Raw("SELECT COUNT(*) FROM user_roles WHERE role_id = ?", roleID).Scan(&c.Direct).Error; err != nil {
		return c, fmt.Errorf("檢查角色引用失敗: %w", err)
	}
	n, err := authz.CountUserGroupRoleBindings(tx, roleID)
	if err != nil {
		return c, err
	}
	c.GroupBindings = n
	m, err := RoleMappingRuleCount(tx, roleID)
	if err != nil {
		return c, err
	}
	c.MappingRules = m
	return c, nil
}

// RoleMappingRuleCount 指向角色的未刪除映射規則數（含已停用）；引用計數、刪除檢查與
// 授權模組的預覽分類共用這一個查詢。
func RoleMappingRuleCount(tx *gorm.DB, roleID uint) (int64, error) {
	var n int64
	if err := tx.Raw("SELECT COUNT(*) FROM group_role_mappings WHERE role_id = ? AND deleted_at IS NULL", roleID).Scan(&n).Error; err != nil {
		return 0, fmt.Errorf("檢查角色引用失敗: %w", err)
	}
	return n, nil
}

// roleGroupBindable 角色本身可否給使用者群組：審核者內建角色不行（審核資格另依審核範圍設定）。
func roleGroupBindable(r model.Role) bool {
	return r.BuiltinKey == nil || *r.BuiltinKey != model.BuiltinApprover
}

// roleDirectMappable 角色是否在直接映射的內建鍵 allowlist 內（自訂角色與非 allowlist 內建角色改走使用者群組）。
func roleDirectMappable(r model.Role) bool {
	if r.BuiltinKey == nil {
		return false
	}
	_, ok := mappingDirectKeys[*r.BuiltinKey]
	return ok
}

// RoleProjection 一個角色的唯讀判定。欄位名即對外 JSON 鍵。
type RoleProjection struct {
	AssignmentState string              `json:"assignment_state"`
	ManagementClass bool                `json:"management_class"`
	DirectMappable  bool                `json:"direct_mappable"`
	GroupBindable   bool                `json:"group_bindable"`
	UserCount       int64               `json:"user_count"`
	References      RoleReferenceCounts `json:"references"`
	// Scopable／NodeRangeNoEffect 節點限定的兩個布林（rejected→假／假、effective→真／假、no_effect→真／真），
	// 以角色的內建識別加集合呼叫 authz 的三態判定。
	Scopable          bool `json:"scopable"`
	NodeRangeNoEffect bool `json:"node_range_no_effect"`
}

// RoleProjectionSet 對某位操作者的整批角色投影。
type RoleProjectionSet struct {
	// CanDefine 操作者可否定義角色（伺服器解析的內建超級管理者身分）。
	CanDefine bool
	ByRole    map[uint]RoleProjection
}

// RoleProjector 唯讀投影器。目標集合與寫入關卡取同一個實例，兩邊不會看到不同的集合。
type RoleProjector struct {
	db      *gorm.DB
	catalog AssignableCatalog
}

// NewRoleProjector 建立投影器；guard 為 nil 時用相容目錄。
func NewRoleProjector(db *gorm.DB, guard *AssignmentGuard) *RoleProjector {
	if guard == nil {
		guard = NewAssignmentGuard(nil)
	}
	return &RoleProjector{db: db, catalog: guard.Catalog()}
}

// operatorIsSuper 操作者是否為超級管理者（與關卡同一判定）；查無操作者視為不是。
func operatorIsSuper(db *gorm.DB, operatorID uint) (bool, error) {
	if operatorID == 0 {
		return false, nil
	}
	var u model.User
	if err := db.First(&u, operatorID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("查詢操作者失敗: %w", err)
	}
	p, err := authz.ResolveUserOn(db, operatorID, authz.TokenFacts{SubjectKind: u.Kind})
	if err != nil {
		return false, err
	}
	return p.IsSuperAdmin(), nil
}

// ProjectRoles 全部未刪除角色的投影。
func (p *RoleProjector) ProjectRoles(operatorID uint) (*RoleProjectionSet, error) {
	opSuper, err := operatorIsSuper(p.db, operatorID)
	if err != nil {
		return nil, err
	}
	canDefine := false
	if operatorID != 0 {
		if _, err := requireSuperAdmin(p.db, operatorID); err == nil {
			canDefine = true
		} else if !errors.Is(err, ErrRoleDefinitionForbidden) {
			return nil, err
		}
	}
	var roles []model.Role
	if err := p.db.Order("id").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("讀取角色失敗: %w", err)
	}
	custom, err := p.customPermissions(roles)
	if err != nil {
		return nil, err
	}
	counts, err := p.userCounts()
	if err != nil {
		return nil, err
	}
	out := &RoleProjectionSet{CanDefine: canDefine, ByRole: make(map[uint]RoleProjection, len(roles))}
	for _, r := range roles {
		refs, err := roleReferenceCounts(p.db, r.ID)
		if err != nil {
			return nil, err
		}
		class, _ := authz.ClassifyRoleNodeScopability(r, custom[r.ID])
		scopable, noEffect := scopeFlags(class)
		out.ByRole[r.ID] = RoleProjection{
			Scopable: scopable, NodeRangeNoEffect: noEffect,
			AssignmentState: p.assignmentState(r, custom[r.ID], opSuper),
			ManagementClass: roleManagementClass(r, custom[r.ID]),
			DirectMappable:  roleDirectMappable(r),
			GroupBindable:   roleGroupBindable(r),
			UserCount:       counts[r.ID],
			References:      refs,
		}
	}
	return out, nil
}

// assignmentState 保護判定在前，其次目標集合。
func (p *RoleProjector) assignmentState(r model.Role, perms []authz.Permission, operatorSuper bool) string {
	if isProtectedRole(r, perms) && !operatorSuper {
		return AssignmentStateProtected
	}
	if !p.catalog.Allows(r) {
		return AssignmentStateNotOpen
	}
	return AssignmentStateOpen
}

// roleManagementClass 與授權變更分類器相同的管理類判定（全域範圍下的單筆指派）。
func roleManagementClass(r model.Role, custom []authz.Permission) bool {
	a := authz.Assignment{RoleID: r.ID, RoleName: r.Name, Via: authz.ViaDirect, Scope: model.ScopeKindGlobal}
	if r.BuiltinKey != nil {
		a.BuiltinKey = *r.BuiltinKey
	} else if r.DefinitionVersion >= 1 {
		a.Custom, a.Permissions = true, custom
	}
	return authz.AssignmentIsManagement(a)
}

// customPermissions 自訂角色（無內建識別、定義版本 >= 1）的權限集合；目錄外的鍵不計。
func (p *RoleProjector) customPermissions(roles []model.Role) (map[uint][]authz.Permission, error) {
	var ids []uint
	for _, r := range roles {
		if r.BuiltinKey == nil && r.DefinitionVersion >= 1 {
			ids = append(ids, r.ID)
		}
	}
	out := map[uint][]authz.Permission{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []model.RolePermission
	if err := p.db.Where("role_id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取自訂角色權限集合失敗: %w", err)
	}
	for _, rp := range rows {
		out[rp.RoleID] = append(out[rp.RoleID], authz.Permission(rp.PermissionKey))
	}
	return out, nil
}

// userCounts 每個角色的使用者人數：未刪除帳號中有效角色集含該角色者，直接、群組、映射任一來源，
// 同一人只算一次；停用中的帳號計入。映射角色已落在直接指派列，不重複加算。
func (p *RoleProjector) userCounts() (map[uint]int64, error) {
	type row struct {
		RoleID uint
		UserID uint
	}
	var direct []row
	if err := p.db.Raw(`SELECT user_roles.role_id AS role_id, user_roles.user_id AS user_id
 FROM user_roles JOIN users ON users.id = user_roles.user_id AND users.deleted_at IS NULL`).Scan(&direct).Error; err != nil {
		return nil, fmt.Errorf("計算角色使用者人數失敗: %w", err)
	}
	viaGroup, err := authz.GroupRoleHolders(p.db)
	if err != nil {
		return nil, err
	}
	seen := make(map[row]struct{}, len(direct)+len(viaGroup))
	out := map[uint]int64{}
	count := func(r row) {
		if _, dup := seen[r]; dup {
			return
		}
		seen[r] = struct{}{}
		out[r.RoleID]++
	}
	for _, r := range direct {
		count(r)
	}
	for _, h := range viaGroup {
		count(row{RoleID: h.RoleID, UserID: h.UserID})
	}
	return out, nil
}

// AccountOps 目標帳號對目前操作者的八種帳號操作，在保護身分這一層的分類。
//
// 這不是完整的可執行性：超管操作者在這一層一律放行，而 agent、外部帳號、MFA 是否啟用、
// 帳號狀態、可用登入途徑等既有條件由各服務自行裁決，伺服器拒絕仍是最終結果。
// 目標身分以伺服器解析的有效指派（直接、群組、映射任一來源）判定。
func (p *RoleProjector) AccountOps(operatorID, targetID uint) (map[string]string, error) {
	out := make(map[string]string, len(AccountOpKeys))
	var operator model.User
	if operatorID == 0 {
		return fillAccountOps(out, AccountOpClassSuperOnly), nil
	}
	if err := p.db.First(&operator, operatorID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fillAccountOps(out, AccountOpClassSuperOnly), nil
		}
		return nil, fmt.Errorf("查詢操作者失敗: %w", err)
	}
	op, err := authz.ResolveUserOn(p.db, operatorID, authz.TokenFacts{SubjectKind: operator.Kind})
	if err != nil {
		return nil, err
	}
	if op.IsSuperAdmin() {
		return fillAccountOps(out, AccountOpClassAllowed), nil
	}
	var target model.User
	if err := p.db.First(&target, targetID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("查詢目標帳號失敗: %w", err)
	}
	tp, err := authz.ResolveUserOn(p.db, targetID, authz.TokenFacts{SubjectKind: target.Kind})
	if err != nil {
		return nil, err
	}
	class := func(actions ...AccountOperation) string {
		result := AccountOpClassAllowed
		for _, a := range actions {
			notify, refused := classifyAccountOp(false, tp, a)
			if refused {
				return AccountOpClassSuperOnly
			}
			if notify {
				result = AccountOpClassNotify
			}
		}
		return result
	}
	out["set_password"] = class(AccountOpPasswordChange)
	out["disable_mfa"] = class(AccountOpMFADisabled)
	out["bind_identity"] = class(AccountOpExternalBound)
	out["unbind_identity"] = class(AccountOpExternalUnbound)
	// 解綁並停用：先過停用的生命週期關卡，再過解綁
	out["unbind_and_disable"] = class(AccountOpDisable, AccountOpExternalUnbound)
	out["disable"] = class(AccountOpDisable)
	out["enable"] = class(AccountOpEnable)
	out["delete"] = class(AccountOpDelete)
	return out, nil
}

func fillAccountOps(m map[string]string, v string) map[string]string {
	for _, k := range AccountOpKeys {
		m[k] = v
	}
	return m
}
