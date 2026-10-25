package authz

import (
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 授權摘要：把一個主體「此刻有效的角色指派與群組授權規則」收斂成可比較的集合，
// 供授權變更分類器比對寫入前後的差異。只計角色、範圍、授權規則三項；
// 審核範圍不在內（維持一般審計）。

// GrantEntry 一筆有效指派。比較鍵為（來源、群組、角色），與角色名無關；
// 範圍不在鍵內，同鍵前後兩筆的範圍以涵蓋比較（見 widens）。
type GrantEntry struct {
	Via      string // ViaDirect／ViaGroup
	GroupID  uint   // Via == ViaGroup 時的群組編號
	RoleID   uint
	RoleName string
	// BuiltinKey 內建範本識別；自訂角色為空。不參與比較鍵。
	BuiltinKey string
	Scope      string // model.ScopeKindGlobal／model.ScopeKindNodes
	// Nodes 節點範圍時指派涵蓋且尚未刪除的節點（升冪）；全域為空。
	Nodes []uint
	// Cover 每個節點的涵蓋集合（節點自身加未刪除祖先）。缺項視為只含節點自身（偏向多報）。
	Cover map[uint][]uint
	// Management 角色屬管理類：有效權限集合含任一資產、授權規則、身分、設定組的管理類別權限點。
	Management bool
}

func (e GrantEntry) key() string {
	return fmt.Sprintf("%s/%d/%d", e.Via, e.GroupID, e.RoleID)
}

// GrantSummary 主體的授權摘要。
type GrantSummary struct {
	Entries []GrantEntry
	// RuleIDs 經所屬群組帶來的有效授權規則編號（未軟刪除者），升冪。
	RuleIDs []uint
}

// 管理類群組：稽核組內的管理類別權限點（例如稽核員範本的告警管理）不算管理類。
func isManagementGroup(g PermGroup) bool {
	return g == GroupAsset || g == GroupAuthzRule || g == GroupIdentity || g == GroupSettings
}

// assignmentIsManagement 單一指派的角色是否屬管理類（同一筆指派內判定，含範圍生效）。
func assignmentIsManagement(a Assignment) bool {
	p := NewPrincipal(0, TokenFacts{}, []Assignment{a})
	for _, k := range p.Capabilities() {
		if def, ok := LookupPermission(k); ok && def.Category == CategoryManage && isManagementGroup(def.Group) {
			return true
		}
	}
	return false
}

func entryOf(a Assignment) GrantEntry {
	return GrantEntry{Via: a.Via, GroupID: a.GroupID, RoleID: a.RoleID, RoleName: a.RoleName,
		BuiltinKey: a.BuiltinKey, Scope: a.Scope, Nodes: a.LiveNodeIDs, Management: assignmentIsManagement(a)}
}

// entryOfIn 同 entryOf，另在 tx 內讀出節點範圍各節點的涵蓋集合（分類器的涵蓋比較用）。
func entryOfIn(tx *gorm.DB, a Assignment) (GrantEntry, error) {
	e := entryOf(a)
	if a.Scope != model.ScopeKindNodes || len(a.LiveNodeIDs) == 0 {
		return e, nil
	}
	cover, err := grantCoverOf(tx, a.LiveNodeIDs)
	if err != nil {
		return GrantEntry{}, err
	}
	e.Cover = cover
	return e, nil
}

// SummarizeGrants 計算使用者此刻的授權摘要；在交易內呼叫即為交易內現值。
func SummarizeGrants(tx *gorm.DB, userID uint) (GrantSummary, error) {
	var kind string
	if err := tx.Model(&model.User{}).Where("id = ?", userID).Pluck("kind", &kind).Error; err != nil {
		return GrantSummary{}, fmt.Errorf("查詢主體種類失敗: %w", err)
	}
	p, err := ResolveUserOn(tx, userID, TokenFacts{SubjectKind: kind})
	if err != nil {
		return GrantSummary{}, err
	}
	out := GrantSummary{}
	for _, a := range p.Assignments {
		e, err := entryOfIn(tx, a)
		if err != nil {
			return GrantSummary{}, err
		}
		out.Entries = append(out.Entries, e)
	}
	var rules []uint
	if err := tx.Model(&model.AssetAuthorization{}).
		Where("user_group_id IN (SELECT user_group_id FROM user_group_members WHERE user_id = ?)", userID).
		Order("id").Pluck("id", &rules).Error; err != nil {
		return GrantSummary{}, fmt.Errorf("查詢群組授權規則失敗: %w", err)
	}
	out.RuleIDs = rules
	return out, nil
}

// GroupGrantEntries 群組目前帶的角色指派（含管理類判定）。
func GroupGrantEntries(tx *gorm.DB, groupID uint) ([]GrantEntry, error) {
	var rows []assignmentRow
	if err := tx.Raw(`SELECT roles.id AS role_id, roles.name AS role_name, roles.builtin_key AS builtin_key, roles.definition_version AS def_version,
 user_group_roles.scope_kind AS scope_kind, user_group_roles.user_group_id AS group_id
 FROM user_group_roles JOIN roles ON roles.id = user_group_roles.role_id AND roles.deleted_at IS NULL
 WHERE user_group_roles.user_group_id = ? ORDER BY roles.id`, groupID).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取群組角色指派失敗: %w", err)
	}
	custom, err := customPermissionsOf(tx, ProductCatalogue(), rows)
	if err != nil {
		return nil, err
	}
	out := make([]GrantEntry, 0, len(rows))
	for _, g := range rows {
		a := Assignment{RoleID: g.RoleID, RoleName: g.RoleName, Via: ViaGroup, GroupID: g.GroupID, Scope: g.ScopeKind}
		if g.BuiltinKey != nil {
			a.BuiltinKey = *g.BuiltinKey
		} else if g.DefVersion >= 1 {
			a.Custom, a.Permissions = true, custom[g.RoleID]
		}
		if g.ScopeKind == model.ScopeKindNodes {
			if a.LiveNodeIDs, err = liveNodesOf(tx, model.BindingSubjectUserGroup, g.GroupID, g.RoleID); err != nil {
				return nil, err
			}
		}
		e, err := entryOfIn(tx, a)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func entryKeys(es []GrantEntry) map[string]GrantEntry {
	m := make(map[string]GrantEntry, len(es))
	for _, e := range es {
		m[e.key()] = e
	}
	return m
}

func sortedEntries(m map[string]GrantEntry) []GrantEntry {
	out := make([]GrantEntry, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}
