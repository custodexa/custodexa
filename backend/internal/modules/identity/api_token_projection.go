package identity

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// API token 的清單投影：七種狀態、建立時授權的角色與其中目前有效的角色及範圍、建立資格。
//
// 某個授權角色「目前有效」＝所屬帳號當下至少有一筆該角色的有效指派（直接或經群組皆算）；節點範圍的
// 指派在範圍內節點全數消失時不生效。角色被刪除後仍列出並保留當時名稱，視為不生效。

// APITokenStatus 清單狀態。
type APITokenStatus string

const (
	APITokenStatusActive                   APITokenStatus = "active"
	APITokenStatusExpiringSoon             APITokenStatus = "expiring_soon"
	APITokenStatusExpired                  APITokenStatus = "expired"
	APITokenStatusRevoked                  APITokenStatus = "revoked"
	APITokenStatusInvalidatedByRestore     APITokenStatus = "invalidated_by_restore"
	APITokenStatusSuspendedAccountDisabled APITokenStatus = "suspended_account_disabled"
	APITokenStatusSuspendedRolesRevoked    APITokenStatus = "suspended_roles_revoked"
)

// APITokenRoleScope 角色目前的範圍：全域，或節點範圍（尚未刪除的節點識別，升冪）。
type APITokenRoleScope struct {
	Kind    string `json:"kind"` // model.ScopeKindGlobal／model.ScopeKindNodes
	NodeIDs []uint `json:"node_ids,omitempty"`
}

// APITokenRoleView 一個角色與它在所屬帳號上目前是否有效、範圍（不生效時為 nil）。
type APITokenRoleView struct {
	APITokenRoleRef
	Effective bool               `json:"effective"`
	Scope     *APITokenRoleScope `json:"scope"`
}

// APITokenActorRef 撤銷者。
type APITokenActorRef struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
}

// APITokenView 一把 token 的清單投影（不含明文或雜湊）。
type APITokenView struct {
	ID           uint               `json:"id"`
	UserID       uint               `json:"user_id"`
	Name         string             `json:"name"`
	Status       APITokenStatus     `json:"status"`
	GrantedRoles []APITokenRoleView `json:"granted_roles"`
	Privileged   bool               `json:"privileged"`
	CreatedAt    time.Time          `json:"created_at"`
	ExpiresAt    *time.Time         `json:"expires_at"`
	LastUsedAt   *time.Time         `json:"last_used_at"`
	LastUsedIP   string             `json:"last_used_ip"`
	RevokedAt    *time.Time         `json:"revoked_at"`
	RevokedBy    *APITokenActorRef  `json:"revoked_by"`
	RevokeNote   string             `json:"revoke_note"`
}

// APITokenEligibility 建立資格與可勾選的角色。
type APITokenEligibility struct {
	CanCreate bool
	// Reason 不能建立時為 APITokenIneligibleNoManagementRole 或 APITokenIneligibleNotHuman
	Reason string
	// GrantableRoles 本人當下持有的管理類角色（皆為有效）
	GrantableRoles []APITokenRoleView
	// NonGrantableRoles 本人當下持有、但不屬管理類而不能授權的角色
	NonGrantableRoles []APITokenRoleRef
	// AllowedCIDRs 帳號目前的允許來源網段（原樣字串，空字串表示不限制）
	AllowedCIDRs string

	username  string
	effective map[uint]APITokenRoleView
}

const (
	APITokenIneligibleNoManagementRole = "no_management_role"
	APITokenIneligibleNotHuman         = "not_human"
)

// apiTokenOwnerState 投影所需的所屬帳號狀態。
type apiTokenOwnerState struct {
	Active    bool
	Effective map[uint]APITokenRoleView // 帳號當下有效的角色（依角色識別）
}

// effectiveRolesTx 帳號當下每個有效角色的範圍與管理類判定。以授權變更分類器同一套指派摘要計算
// （帳號完整身分，不套用任何 token 的限定）。
func effectiveRolesTx(tx *gorm.DB, userID uint) (map[uint]APITokenRoleView, map[uint]bool, error) {
	sum, err := authz.SummarizeGrants(tx, userID)
	if err != nil {
		return nil, nil, err
	}
	views := map[uint]APITokenRoleView{}
	management := map[uint]bool{}
	nodes := map[uint]map[uint]bool{}
	for _, e := range sum.Entries {
		live := e.Scope == model.ScopeKindGlobal || (e.Scope == model.ScopeKindNodes && len(e.Nodes) > 0)
		if !live {
			continue
		}
		v, ok := views[e.RoleID]
		if !ok {
			v = APITokenRoleView{APITokenRoleRef: APITokenRoleRef{RoleID: e.RoleID, Name: e.RoleName, BuiltinKey: e.BuiltinKey}, Effective: true}
		}
		if e.Scope == model.ScopeKindGlobal {
			v.Scope = &APITokenRoleScope{Kind: model.ScopeKindGlobal}
		} else if v.Scope == nil || v.Scope.Kind != model.ScopeKindGlobal {
			if nodes[e.RoleID] == nil {
				nodes[e.RoleID] = map[uint]bool{}
			}
			for _, n := range e.Nodes {
				nodes[e.RoleID][n] = true
			}
			v.Scope = &APITokenRoleScope{Kind: model.ScopeKindNodes}
		}
		views[e.RoleID] = v
		if e.Management {
			management[e.RoleID] = true
		}
	}
	for id, v := range views {
		if v.Scope.Kind == model.ScopeKindNodes {
			for n := range nodes[id] {
				v.Scope.NodeIDs = append(v.Scope.NodeIDs, n)
			}
			sort.Slice(v.Scope.NodeIDs, func(i, j int) bool { return v.Scope.NodeIDs[i] < v.Scope.NodeIDs[j] })
			views[id] = v
		}
	}
	return views, management, nil
}

// apiTokenEligibilityTx 建立資格：人類帳號、啟用中、未刪除，且當下至少有一個有效的管理類角色。
// 在 tx 內呼叫即為交易內現值。
func apiTokenEligibilityTx(tx *gorm.DB, userID uint) (*APITokenEligibility, error) {
	var u model.User
	if err := tx.Select("id", "username", "kind", "active", "allowed_cidrs").First(&u, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &APITokenEligibility{Reason: APITokenIneligibleNoManagementRole}, nil
		}
		return nil, fmt.Errorf("讀取帳號失敗: %w", err)
	}
	out := &APITokenEligibility{username: u.Username, AllowedCIDRs: u.AllowedCIDRs, GrantableRoles: []APITokenRoleView{}, NonGrantableRoles: []APITokenRoleRef{}}
	if u.Kind != model.KindHuman {
		out.Reason = APITokenIneligibleNotHuman
		return out, nil
	}
	effective, management, err := effectiveRolesTx(tx, userID)
	if err != nil {
		return nil, err
	}
	out.effective = effective
	ids := make([]uint, 0, len(effective))
	for id := range effective {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if management[id] {
			out.GrantableRoles = append(out.GrantableRoles, effective[id])
		} else {
			out.NonGrantableRoles = append(out.NonGrantableRoles, effective[id].APITokenRoleRef)
		}
	}
	out.CanCreate = u.Active && len(out.GrantableRoles) > 0
	if !out.CanCreate {
		out.Reason = APITokenIneligibleNoManagementRole
	}
	return out, nil
}

// Eligibility 帳號目前的建立資格與可勾選的角色（清單端點用）。
func (s *APITokenService) Eligibility(userID uint) (*APITokenEligibility, error) {
	return apiTokenEligibilityTx(s.db, userID)
}

// ListForUser 帳號全部 token 的清單投影（依識別升冪）。帳號不存在（含已刪除）時仍回其 token，
// 狀態依各自的撤銷與到期判定。
func (s *APITokenService) ListForUser(userID uint) ([]APITokenView, error) {
	var tokens []model.APIToken
	if err := s.db.Where("user_id = ?", userID).Order("id").Find(&tokens).Error; err != nil {
		return nil, fmt.Errorf("讀取 API token 失敗: %w", err)
	}
	out := make([]APITokenView, 0, len(tokens))
	if len(tokens) == 0 {
		return out, nil
	}
	var owner model.User
	state := apiTokenOwnerState{}
	if err := s.db.Select("id", "active").First(&owner, userID).Error; err == nil {
		state.Active = owner.Active
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("讀取帳號失敗: %w", err)
	}
	effective, _, err := effectiveRolesTx(s.db, userID)
	if err != nil {
		return nil, err
	}
	state.Effective = effective
	gen, err := currentRestoreGeneration(s.restoreGen, s.db)
	if err != nil {
		return nil, err
	}
	granted, err := grantedRolesOf(s.db, tokens)
	if err != nil {
		return nil, err
	}
	revokers, err := revokerNamesOf(s.db, tokens)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	for _, t := range tokens {
		v := projectAPIToken(t, granted[t.ID], state, gen, now)
		if t.RevokedBy != nil {
			v.RevokedBy = &APITokenActorRef{UserID: *t.RevokedBy, Username: revokers[*t.RevokedBy]}
		}
		out = append(out, v)
	}
	return out, nil
}

// grantedRolesOf 每把 token 建立時授權的角色（含已刪除的角色，保留其名稱）。
func grantedRolesOf(db *gorm.DB, tokens []model.APIToken) (map[uint][]APITokenRoleView, error) {
	ids := make([]uint, 0, len(tokens))
	for _, t := range tokens {
		ids = append(ids, t.ID)
	}
	var links []model.APITokenRole
	if err := db.Where("api_token_id IN ?", ids).Order("api_token_id, role_id").Find(&links).Error; err != nil {
		return nil, fmt.Errorf("讀取 API token 授權角色失敗: %w", err)
	}
	roleIDs := []uint{}
	for _, l := range links {
		roleIDs = append(roleIDs, l.RoleID)
	}
	roles := map[uint]model.Role{}
	if len(roleIDs) > 0 {
		var rows []model.Role
		if err := db.Unscoped().Select("id", "name", "builtin_key", "deleted_at").Where("id IN ?", roleIDs).Find(&rows).Error; err != nil {
			return nil, fmt.Errorf("讀取角色失敗: %w", err)
		}
		for _, r := range rows {
			roles[r.ID] = r
		}
	}
	out := map[uint][]APITokenRoleView{}
	for _, l := range links {
		r := roles[l.RoleID]
		ref := APITokenRoleRef{RoleID: l.RoleID, Name: grantedRoleName(l.RoleID, r.Name, r.DeletedAt.Valid)}
		if r.BuiltinKey != nil {
			ref.BuiltinKey = *r.BuiltinKey
		}
		out[l.APITokenID] = append(out[l.APITokenID], APITokenRoleView{APITokenRoleRef: ref})
	}
	return out, nil
}

func revokerNamesOf(db *gorm.DB, tokens []model.APIToken) (map[uint]string, error) {
	ids := []uint{}
	for _, t := range tokens {
		if t.RevokedBy != nil {
			ids = append(ids, *t.RevokedBy)
		}
	}
	out := map[uint]string{}
	if len(ids) == 0 {
		return out, nil
	}
	var users []model.User
	if err := db.Unscoped().Select("id", "username").Where("id IN ?", ids).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("讀取撤銷者失敗: %w", err)
	}
	for _, u := range users {
		out[u.ID] = u.Username
	}
	return out, nil
}

// projectAPIToken 組出一把 token 的投影。granted 只需帶角色的識別、名稱與內建識別，有效與範圍依 state 填入。
func projectAPIToken(t model.APIToken, granted []APITokenRoleView, state apiTokenOwnerState, gen string, now time.Time) APITokenView {
	roles := make([]APITokenRoleView, 0, len(granted))
	anyEffective := false
	refs := make([]APITokenRoleRef, 0, len(granted))
	for _, g := range granted {
		v := APITokenRoleView{APITokenRoleRef: g.APITokenRoleRef}
		if cur, ok := state.Effective[g.RoleID]; ok && cur.Effective {
			v.Effective, v.Scope = true, cur.Scope
			anyEffective = true
		}
		roles = append(roles, v)
		refs = append(refs, g.APITokenRoleRef)
	}
	return APITokenView{ID: t.ID, UserID: t.UserID, Name: t.Name, GrantedRoles: roles, Privileged: len(privilegedKeys(refs)) > 0,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, LastUsedIP: t.LastUsedIP,
		RevokedAt: t.RevokedAt, RevokeNote: t.RevokeNote,
		Status: apiTokenStatusOf(t, state.Active, anyEffective, gen, now)}
}

// apiTokenStatusOf 狀態優先序（同時符合多項時取最前者）：已撤銷 → 已因還原失效 → 已到期 →
// 因帳號停用而暫停 → 因角色收回而暫停 → 即將到期 → 有效。
func apiTokenStatusOf(t model.APIToken, accountActive, anyRoleEffective bool, gen string, now time.Time) APITokenStatus {
	switch {
	case t.RevokedAt != nil:
		return APITokenStatusRevoked
	case t.RestoreGeneration != gen:
		return APITokenStatusInvalidatedByRestore
	case t.ExpiresAt != nil && !t.ExpiresAt.After(now):
		return APITokenStatusExpired
	case !accountActive:
		return APITokenStatusSuspendedAccountDisabled
	case !anyRoleEffective:
		return APITokenStatusSuspendedRolesRevoked
	case t.ExpiresAt != nil && !t.ExpiresAt.After(now.Add(APITokenExpiringSoonWindow)):
		return APITokenStatusExpiringSoon
	default:
		return APITokenStatusActive
	}
}

// APITokenAdminList 管理者查看某個帳號的 token：清單與附帶狀態。
type APITokenAdminList struct {
	Tokens []APITokenView
	// CanRevoke 操作者能否撤銷這個帳號的 token（受保護帳號只限超級管理者）
	CanRevoke bool
	// Protected 帳號當下持有超級管理者或系統安全管理員身分（任一來源）
	Protected bool
	// AccountActive 帳號是否啟用中
	AccountActive bool
}

// ListForAdmin 管理者查看某個帳號的 token。帳號不存在（含已刪除）回 ErrUserNotFound，與使用者詳情同一規則。
// 能否撤銷與撤銷時的受保護帳號判定同一界線：帳號持有受保護身分時只限超級管理者（操作者以請求主體判定）。
func (s *APITokenService) ListForAdmin(op Operator, ownerID uint) (*APITokenAdminList, error) {
	var owner model.User
	if err := s.db.Select("id", "active").First(&owner, ownerID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("讀取帳號失敗: %w", err)
	}
	tokens, err := s.ListForUser(ownerID)
	if err != nil {
		return nil, err
	}
	effective, _, err := effectiveRolesTx(s.db, ownerID)
	if err != nil {
		return nil, err
	}
	protected := false
	for _, v := range effective {
		if v.BuiltinKey == model.BuiltinSuperAdmin || v.BuiltinKey == model.BuiltinSecurityAdmin {
			protected = true
		}
	}
	operatorSuper := op.Principal != nil && op.Principal.UserID == op.UserID && op.Principal.IsSuperAdmin()
	return &APITokenAdminList{Tokens: tokens, CanRevoke: !protected || operatorSuper || op.UserID == ownerID,
		Protected: protected, AccountActive: owner.Active}, nil
}

// RestoreSummary 還原世代造成的失效：已因還原失效的 token 數與目前世代的還原時刻（沒有還原紀錄時為 nil）。
type APITokenRestoreSummary struct {
	InvalidatedCount int
	RestoredAt       *time.Time
}

// RestoreSummaryOf 由清單投影計算已因還原失效的數量；還原時刻取自注入的讀取函式（未注入時為 nil）。
func (s *APITokenService) RestoreSummaryOf(tokens []APITokenView) APITokenRestoreSummary {
	out := APITokenRestoreSummary{}
	for _, t := range tokens {
		if t.Status == APITokenStatusInvalidatedByRestore {
			out.InvalidatedCount++
		}
	}
	if s.restoredAt != nil {
		if at, err := s.restoredAt(s.db); err == nil && at != nil {
			v := at.UTC()
			out.RestoredAt = &v
		}
	}
	return out
}

// SetRestoredAtSource 注入目前還原世代的還原時刻讀取函式（組裝根注入）。
func (s *APITokenService) SetRestoredAtSource(src func(db *gorm.DB) (*time.Time, error)) {
	s.restoredAt = src
}

// deletedRoleNameSuffix 角色刪除時為釋出名稱（名稱唯一索引含已刪列）而接在名稱後的字尾。
func deletedRoleNameSuffix(roleID uint) string { return fmt.Sprintf("~del%d", roleID) }

// grantedRoleName 授權角色的顯示名稱：角色已刪除時去掉刪除字尾，回到刪除前的名稱。
func grantedRoleName(roleID uint, name string, deleted bool) string {
	if !deleted {
		return name
	}
	return strings.TrimSuffix(name, deletedRoleNameSuffix(roleID))
}
