package identity

import (
	"errors"
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 共用指派關卡。
//
// 六條取得路徑（替換、追加、建帳號帶角色、釘住、外部映射、加入帶角色指派的群組）加上
// 群組角色指派本身，全部經 AssignmentGuard.Check 裁決同一組規則，避免「同一件事兩條路
// 結果相反」。關卡只做讀取與判定，不寫任何資料；呼叫端 SHALL 在取得使用者或群組鎖之後、
// 與寫入同一個交易內呼叫，使判定讀到的是現值而不是 handler 預查的舊值。
//
// 判定順序固定（先拒絕者勝出）：
//  1. 對象可寫：目標帳號持有內建超管身分而操作者不是超管。
//  2. 保護目標：被新增或移除的項目含保護角色（超管或系統安全管理員內建身分，或含系統安全
//     管理員專屬權限點的自訂角色）；成員異動與刪除群組看群組目前帶的指派。讓任何帳號取得或
//     失去保護身分的寫入限超管，保護身分不變的不限。
//  3. 指派能力：操作者有效能力不含指派角色權限點。只比對持不持有。
//  4. 範圍：請求帶任何範圍欄位。
//  5. agent：對象或群組成員含 agent，而新值含管理、稽核、審核類能力的角色。
//  6. 開放邊界：新值含可指派目錄以外的角色。
//
// 拒絕回應只帶機器碼，不帶角色名或權限名。被拒的規則以 AssignmentDenial 的原因碼
// （DenyReason* 之一）帶出，API 層把它寫進該次請求審計列的 details（只寫原因碼，
// 不寫角色、權限或任何請求值）。

// 關卡的拒絕。沿用 PrincipalError 的形狀，API 層的 respondPrincipalError 原樣轉成機器碼回應。
// ErrRoleAssignmentForbidden 是能力拒絕（操作者缺指派能力），與其他同碼的規則拒絕以哨兵區分（errors.Is），
// 不以碼區分；API 層經能力拒絕的單一寫出函式寫出。
var (
	ErrProtectedRoleAssignment     = &PrincipalError{Code: apierror.CodeAuthProtectedRoleAssignment, Status: 403}
	ErrProtectedAccountOperation   = &PrincipalError{Code: apierror.CodeAuthProtectedAccountOperation, Status: 403}
	ErrRoleAssignmentForbidden     = &PrincipalError{Code: apierror.CodePermissionDenied, Status: 403}
	ErrRoleBindingScopeUnsupported = &PrincipalError{Code: apierror.CodeValidationRoleBindingScopeUnsupported, Status: 400}
	ErrRoleNotGroupBindable        = &PrincipalError{Code: apierror.CodeValidationRoleNotGroupBindable, Status: 400}
)

// 節點範圍的四個拒絕：每次拒絕新建一個錯誤值，不是包級哨兵（呼叫端以機器碼區分，不比對錯誤值）。
func errRoleNodesKeyNotListed() error {
	return &PrincipalError{Code: apierror.CodeBadParams, Status: 400}
}
func errRoleNotNodeScopable() error {
	return &PrincipalError{Code: apierror.CodeValidationRoleNotNodeScopable, Status: 400}
}
func errRoleBindingNodesEmpty() error {
	return &PrincipalError{Code: apierror.CodeValidationRoleBindingNodesEmpty, Status: 400}
}
func errRoleBindingNodesInvalid() error {
	return &PrincipalError{Code: apierror.CodeValidationRoleBindingNodesInvalid, Status: 400}
}

// 關卡拒絕的原因碼（審計 details 的 deny_reason 值），對應判定順序的各條規則。
const (
	DenyReasonOperatorMissing   = "operator_missing"
	DenyReasonProtectedAccount  = "protected_account"
	DenyReasonProtectedRole     = "protected_role"
	DenyReasonCapabilityMissing = "assign_capability_missing"
	DenyReasonScopeUnsupported  = "scope_unsupported"
	DenyReasonAgentRole         = "agent_role_forbidden"
	DenyReasonRoleNotAssignable = "role_not_assignable"
	DenyReasonNotNodeScopable   = "role_not_node_scopable"
	DenyReasonNodesEmpty        = "role_binding_nodes_empty"
	DenyReasonNodesInvalid      = "role_binding_nodes_invalid"
)

// AssignmentDenial 關卡的拒絕：包著回給呼叫端的錯誤（errors.Is／errors.As 照舊比對得到），
// 另帶被拒規則的原因碼供審計。
type AssignmentDenial struct {
	Reason string
	Err    error
}

func (d *AssignmentDenial) Error() string { return d.Err.Error() }
func (d *AssignmentDenial) Unwrap() error { return d.Err }

func deny(reason string, err error) error { return &AssignmentDenial{Reason: reason, Err: err} }

// AssignmentDenyReason 取出關卡拒絕的原因碼；不是關卡拒絕時回空字串。
func AssignmentDenyReason(err error) string {
	var d *AssignmentDenial
	if errors.As(err, &d) {
		return d.Reason
	}
	return ""
}

// AssignmentPath 取得路徑代碼；同時是告警摘要 path 欄的值。
type AssignmentPath string

const (
	PathReplace     AssignmentPath = "replace"
	PathAdd         AssignmentPath = "add"
	PathCreate      AssignmentPath = "create"
	PathGroupRoles  AssignmentPath = "group_roles"
	PathGroupMember AssignmentPath = "group_member"
	PathGroupDelete AssignmentPath = "group_delete"
	PathMapping     AssignmentPath = "mapping"
	PathPin         AssignmentPath = "pin"
)

// Operator 寫入的操作者。UserID 為 0 代表沒有可指認的操作者，關卡一律拒絕（fail-close）。
type Operator struct {
	UserID   uint
	Username string
	ClientIP string
}

// AssignableCatalog 可被這些入口指派的角色目錄。
//
// 這是組裝時注入的目標集合，不是使用者可切換的設定：新範本與自訂角色開放之前是相容目錄
// （升級前存量角色），開放後換成完整集合。Scope 用在角色查詢，Allows 用在已載入的角色列。
type AssignableCatalog interface {
	Scope(db *gorm.DB) *gorm.DB
	Allows(r model.Role) bool
}

type compatCatalog struct{}

func (compatCatalog) Scope(db *gorm.DB) *gorm.DB { return db.Where(legacyRoleCatalogCond) }
func (compatCatalog) Allows(r model.Role) bool   { return r.DefinitionVersion == 0 }

type fullCatalog struct{}

func (fullCatalog) Scope(db *gorm.DB) *gorm.DB { return db }
func (fullCatalog) Allows(model.Role) bool     { return true }

// CompatCatalog 升級前存量的相容目錄（現行預設）。
func CompatCatalog() AssignableCatalog { return compatCatalog{} }

// FullCatalog 完整集合（新範本與自訂角色）；只在放行條件成立後的組裝使用。
func FullCatalog() AssignableCatalog { return fullCatalog{} }

// AssignmentChange 一次指派變更。直接路徑的 OldRoleIDs／NewRoleIDs 是管理者指派集的前後；
// 群組路徑的舊值由關卡自行讀現值（成員異動與刪除的新值等於舊值）。
type AssignmentChange struct {
	Path           AssignmentPath
	TargetUserID   uint   // 直接路徑的既有目標帳號；建帳號為 0
	TargetKind     string // 建帳號時的主體種類
	GroupID        uint   // 群組路徑
	OldRoleIDs     []uint
	NewRoleIDs     []uint
	ScopeRequested bool // 請求帶了只收全域的入口不接受的範圍或節點欄位
	// NodeScopes 本次請求為這些角色帶的節點範圍新值（角色編號 → 節點集合；空集合保留為空，
	// 由關卡以空範圍碼拒絕）。全域與省略（保留）不在其中。節點是否存在由 CheckNodesLive 在
	// 取得拓撲序列化鎖之後判定。
	NodeScopes     map[uint][]uint
	AddedMemberIDs []uint // 成員加入：新加入的成員
}

// AssignmentGuard 共用指派關卡。無狀態，可共用。
type AssignmentGuard struct {
	catalog AssignableCatalog
	nodes   NodeExistenceReader
	cover   NodeCoverageReader
}

// NodeExistenceReader 接受呼叫方交易的節點存在讀取（由 asset 提供，組裝時注入）。
type NodeExistenceReader interface {
	LiveNodesTx(tx *gorm.DB, ids []uint) (map[uint]bool, error)
}

// SetNodeExistenceReader 注入節點存在讀取。未注入時帶節點範圍的寫入一律拒絕（fail-close）。
func (g *AssignmentGuard) SetNodeExistenceReader(r NodeExistenceReader) { g.nodes = r }

// NodeCoverageReader 節點自身加未刪除祖先的唯讀查詢（由 asset 的拓撲讀取器提供，組裝時注入）。
// 供範圍縮小判定使用；已刪除的節點 exists 為 false。
type NodeCoverageReader interface {
	NodeCoverNodes(tx *gorm.DB, nodeID uint) (nodeIDs []uint, exists bool, err error)
}

// SetNodeCoverageReader 注入節點涵蓋讀取。未注入時縮小判定退回只比節點編號
// （祖先補回涵蓋的情形也視為縮小，方向保守：多推進一次世代，不會少推）。
func (g *AssignmentGuard) SetNodeCoverageReader(r NodeCoverageReader) { g.cover = r }

// nodeCover 節點的涵蓋節點集合；沒有讀取器時只有自己。
func (g *AssignmentGuard) nodeCover(tx *gorm.DB, id uint) ([]uint, bool, error) {
	if g.cover == nil {
		return []uint{id}, true, nil
	}
	return g.cover.NodeCoverNodes(tx, id)
}

// CheckNodesLive 節點範圍新值指向的節點都必須存在且未刪除。呼叫端 SHALL 已取得拓撲序列化鎖，
// 使檢查與寫入之間節點不會被刪除。不存在與已刪除同形，拒絕只記原因碼。
func (g *AssignmentGuard) CheckNodesLive(tx *gorm.DB, scopes map[uint][]uint) error {
	var ids []uint
	for _, nodes := range scopes {
		ids = append(ids, nodes...)
	}
	if len(ids) == 0 {
		return nil
	}
	if g.nodes == nil {
		return deny(DenyReasonScopeUnsupported, ErrRoleBindingScopeUnsupported)
	}
	live, err := g.nodes.LiveNodesTx(tx, ids)
	if err != nil {
		return fmt.Errorf("查詢節點失敗: %w", err)
	}
	for _, id := range ids {
		if !live[id] {
			return deny(DenyReasonNodesInvalid, errRoleBindingNodesInvalid())
		}
	}
	return nil
}

// NewAssignmentGuard 建立關卡；catalog 為 nil 時用相容目錄。
func NewAssignmentGuard(catalog AssignableCatalog) *AssignmentGuard {
	if catalog == nil {
		catalog = CompatCatalog()
	}
	return &AssignmentGuard{catalog: catalog}
}

// Catalog 關卡注入的目標集合。
func (g *AssignmentGuard) Catalog() AssignableCatalog { return g.catalog }

// isProtectedRole 保護角色：超管或系統安全管理員內建身分，或權限集合含任一高風險權限點的角色
// （authz.ProtectedAssignmentPermissions，系統安全管理員專屬點的子集：能刪除證據、關閉或改道
// 告警、放寬安全控制或管理金鑰）。後者使含這些能力、但不是內建身分的自訂角色同樣只有超管能讓人
// 取得或失去；只含其餘專屬點（唯讀檢視、排程、清冊）的自訂角色不受此限。perms 是該角色的權限
// 集合，只在非內建角色時被看（內建的其他範本依定義不含專屬點）。
func isProtectedRole(r model.Role, perms []authz.Permission) bool {
	if r.BuiltinKey != nil {
		return *r.BuiltinKey == model.BuiltinSuperAdmin || *r.BuiltinKey == model.BuiltinSecurityAdmin
	}
	return authz.HoldsProtectedAssignmentPermission(perms)
}

// roleIsProtectedOn 依交易內的現值判定保護角色；自訂角色讀其權限集合。
func roleIsProtectedOn(tx *gorm.DB, r model.Role) (bool, error) {
	if r.BuiltinKey != nil || r.DefinitionVersion < 1 {
		return isProtectedRole(r, nil), nil
	}
	perms, err := customRolePermissions(tx, r.ID)
	if err != nil {
		return false, err
	}
	return isProtectedRole(r, perms), nil
}

// RoleNodeScopability 依交易內的現值判定角色可否限定節點（內建取範本、自訂讀其權限集合）。
func RoleNodeScopability(tx *gorm.DB, r model.Role) (authz.NodeScopability, authz.NodeScopeNoEffectReason, error) {
	var perms []authz.Permission
	if r.BuiltinKey == nil && r.DefinitionVersion >= 1 {
		var err error
		if perms, err = customRolePermissions(tx, r.ID); err != nil {
			return "", "", err
		}
	}
	class, reason := authz.ClassifyRoleNodeScopability(r, perms)
	return class, reason, nil
}

// customRolePermissions 自訂角色的權限集合（role_permissions）。
func customRolePermissions(tx *gorm.DB, roleID uint) ([]authz.Permission, error) {
	var keys []string
	if err := tx.Table("role_permissions").Where("role_id = ?", roleID).Pluck("permission_key", &keys).Error; err != nil {
		return nil, fmt.Errorf("讀取自訂角色權限集合失敗: %w", err)
	}
	perms := make([]authz.Permission, 0, len(keys))
	for _, k := range keys {
		perms = append(perms, authz.Permission(k))
	}
	return perms, nil
}

// Check 依固定順序裁決。回 nil 即放行；任何非 nil 都是整筆拒絕，呼叫端不得寫入。
func (g *AssignmentGuard) Check(tx *gorm.DB, op Operator, ch AssignmentChange) error {
	if op.UserID == 0 {
		return deny(DenyReasonOperatorMissing, ErrRoleAssignmentForbidden)
	}
	var operator model.User
	if err := tx.First(&operator, op.UserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return deny(DenyReasonOperatorMissing, ErrRoleAssignmentForbidden)
		}
		return fmt.Errorf("查詢操作者失敗: %w", err)
	}
	facts := authz.TokenFacts{SubjectKind: operator.Kind}
	opPrincipal, err := authz.ResolveUserOn(tx, op.UserID, facts)
	if err != nil {
		return err
	}
	opSuper := opPrincipal.IsSuperAdmin()

	direct := ch.Path == PathReplace || ch.Path == PathAdd || ch.Path == PathCreate ||
		ch.Path == PathPin || ch.Path == PathMapping
	oldIDs, newIDs := ch.OldRoleIDs, ch.NewRoleIDs
	if !direct {
		cur, err := authz.UserGroupRoleIDs(tx, ch.GroupID)
		if err != nil {
			return err
		}
		oldIDs = cur
		if ch.Path != PathGroupRoles {
			newIDs = cur
		}
	}

	// 1. 對象可寫
	var target model.User
	if direct && ch.TargetUserID != 0 {
		if err := tx.First(&target, ch.TargetUserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrUserNotFound
			}
			return fmt.Errorf("查詢目標帳號失敗: %w", err)
		}
		tp, err := authz.ResolveUserOn(tx, target.ID, authz.TokenFacts{SubjectKind: target.Kind})
		if err != nil {
			return err
		}
		if tp.IsSuperAdmin() && !opSuper {
			return deny(DenyReasonProtectedAccount, ErrProtectedAccountOperation)
		}
	}

	carried := unionIDs(oldIDs, newIDs)
	roles, err := loadRolesByID(tx, carried)
	if err != nil {
		return err
	}
	// 保護目標的判定範圍：讓任何帳號取得或失去保護角色的寫入才限超管。
	// 角色寫入路徑（直接指派、映射、群組角色指派）看被新增或移除的項目，
	// 保護角色在寫入前後都不變時，只增減其他角色不會讓任何人取得或失去保護身分；
	// 成員異動與刪除群組不改群組的角色集，看群組目前帶的全部指派，
	// 因為被加入或移出（或整群解散）的成員會因此取得或失去這些角色。
	protectedScope := symmetricDiff(oldIDs, newIDs)
	if ch.Path == PathGroupMember || ch.Path == PathGroupDelete {
		protectedScope = carried
	}

	// 2. 保護目標
	if !opSuper {
		for _, id := range protectedScope {
			r, ok := roles[id]
			if !ok {
				continue
			}
			protected, err := roleIsProtectedOn(tx, r)
			if err != nil {
				return err
			}
			if protected {
				return deny(DenyReasonProtectedRole, ErrProtectedRoleAssignment)
			}
		}
	}

	// 3. 指派能力：群組成員異動與刪除只在群組帶有角色指派時才需要
	needCap := direct || ch.Path == PathGroupRoles || len(carried) > 0
	if needCap && !opPrincipal.Has(authz.PermRoleAssign) {
		return deny(DenyReasonCapabilityMissing, ErrRoleAssignmentForbidden)
	}

	// 4. 範圍：入口是否接受 → 角色可否限定節點 → 節點集合非空（節點存在由 CheckNodesLive 判定）。
	// 不比對操作者自身的範圍。
	if ch.ScopeRequested {
		return deny(DenyReasonScopeUnsupported, ErrRoleBindingScopeUnsupported)
	}
	nodeRoleIDs := make([]uint, 0, len(ch.NodeScopes))
	for id := range ch.NodeScopes {
		nodeRoleIDs = append(nodeRoleIDs, id)
	}
	sort.Slice(nodeRoleIDs, func(i, j int) bool { return nodeRoleIDs[i] < nodeRoleIDs[j] })
	for _, id := range nodeRoleIDs {
		r, ok := roles[id]
		if !ok {
			continue
		}
		class, _, err := RoleNodeScopability(tx, r)
		if err != nil {
			return err
		}
		if class == authz.NodeScopabilityRejected {
			return deny(DenyReasonNotNodeScopable, errRoleNotNodeScopable())
		}
		if len(ch.NodeScopes[id]) == 0 {
			return deny(DenyReasonNodesEmpty, errRoleBindingNodesEmpty())
		}
	}

	// 5. agent
	agentInvolved, err := g.agentInvolved(tx, direct, target, ch)
	if err != nil {
		return err
	}
	if agentInvolved {
		// agent 不取得任何節點範圍指派：能力類別守衛攔不到只含基本類或空權限集的角色，
		// 所以帶節點範圍的新值不論三態一律拒絕
		if len(ch.NodeScopes) > 0 {
			return deny(DenyReasonAgentRole, ErrAgentRoleForbidden)
		}
		for _, id := range newIDs {
			r, ok := roles[id]
			if !ok {
				continue
			}
			forbidden, err := roleForbiddenForAgent(tx, r)
			if err != nil {
				return err
			}
			if forbidden {
				return deny(DenyReasonAgentRole, ErrAgentRoleForbidden)
			}
		}
	}

	// 6. 開放邊界：只看新增的項目，既有的不因目錄收斂而被擋
	for _, id := range subtractIDs(newIDs, oldIDs) {
		r, ok := roles[id]
		if !ok || !g.catalog.Allows(r) {
			return deny(DenyReasonRoleNotAssignable, ErrRoleNotFound)
		}
	}
	return nil
}

func (g *AssignmentGuard) agentInvolved(tx *gorm.DB, direct bool, target model.User, ch AssignmentChange) (bool, error) {
	if direct {
		if ch.Path == PathCreate {
			return ch.TargetKind == model.KindAgent, nil
		}
		return target.Kind == model.KindAgent, nil
	}
	var n int64
	q := tx.Table("users").Where("kind = ? AND deleted_at IS NULL", model.KindAgent)
	switch ch.Path {
	case PathGroupMember:
		if len(ch.AddedMemberIDs) == 0 {
			return false, nil
		}
		q = q.Where("id IN ?", ch.AddedMemberIDs)
	case PathGroupRoles:
		q = q.Where("id IN (SELECT user_id FROM user_group_members WHERE user_group_id = ?)", ch.GroupID)
	default:
		return false, nil
	}
	if err := q.Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢 agent 成員失敗: %w", err)
	}
	return n > 0, nil
}

// roleForbiddenForAgent 角色是否禁止給 agent：依能力類別，內建取程式定義、自訂取其權限集合。
func roleForbiddenForAgent(db *gorm.DB, r model.Role) (bool, error) {
	key := ""
	if r.BuiltinKey != nil {
		key = *r.BuiltinKey
	}
	if key != "" || r.DefinitionVersion < 1 {
		return authz.RoleForbiddenForAgent(key), nil
	}
	perms, err := customRolePermissions(db, r.ID)
	if err != nil {
		return false, err
	}
	return authz.CapabilityRestrictedForAgent(perms), nil
}

func loadRolesByID(tx *gorm.DB, ids []uint) (map[uint]model.Role, error) {
	out := map[uint]model.Role{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []model.Role
	if err := tx.Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢角色失敗: %w", err)
	}
	for _, r := range rows {
		out[r.ID] = r
	}
	return out, nil
}

func unionIDs(a, b []uint) []uint {
	seen := map[uint]bool{}
	var out []uint
	for _, s := range [][]uint{a, b} {
		for _, id := range s {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func subtractIDs(a, b []uint) []uint {
	in := map[uint]bool{}
	for _, id := range b {
		in[id] = true
	}
	var out []uint
	for _, id := range a {
		if !in[id] {
			out = append(out, id)
		}
	}
	return out
}

func symmetricDiff(a, b []uint) []uint {
	return unionIDs(subtractIDs(a, b), subtractIDs(b, a))
}
