package authz

import (
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 以指派集合為輸入的判定入口：供「模擬指派」預覽某組指派會給出的能力與範圍。
// 只換主體的來源（由輸入的指派集合組出），其後的展開、目錄、scopeGrants、有效節點、子樹與超管規則
// 全部與正式判定共用（principalFromAssignments → NewPrincipalOn → decideOn／scopeSetOn）。
// 只讀角色定義、拓撲與節點存活；不讀主體已存的指派、不寫任何表、不取鎖。

// AssignmentInput 指派集合中的一筆指派。
type AssignmentInput struct {
	BindingSubject string // model.BindingSubjectUser（直接）或 model.BindingSubjectUserGroup（經群組）
	GroupID        uint   // 經群組時必填；直接指派時須為 0
	RoleID         uint
	Scope          string // model.ScopeKindGlobal／model.ScopeKindNodes
	NodeIDs        []uint // Scope=nodes 時的原始節點（入口內以未刪除過濾）；全域指派須為空
}

// AssignmentSet 一個主體的指派集合。
type AssignmentSet struct {
	SubjectKind string            // model.KindHuman／model.KindAgent（與 TokenFacts.SubjectKind 同義，空值視為 human）
	Items       []AssignmentInput // 空＝零指派主體，適用相容規則
}

// ErrAssignmentRoleMissing 指派集合引用的角色不存在或已刪除（不冒充零指派）。
var ErrAssignmentRoleMissing = errors.New("authz: assignment set references a missing role")

// ErrAssignmentInvalid 指派集合的欄位不合法。
var ErrAssignmentInvalid = errors.New("authz: invalid assignment set")

// DecideForAssignments 以指派集合為主體判定權限點對目標是否放行；與 Decide 共用 decideOn。
func (e *ScopeEvaluator) DecideForAssignments(tx *gorm.DB, set AssignmentSet, perm Permission, target ScopeTarget) (ScopeResult, error) {
	p, err := e.assignmentPrincipal(tx, set)
	if err != nil {
		return ScopeResult{}, err
	}
	res, _, err := e.decideOn(tx, p, perm, target)
	return res, err
}

// ScopeSetForAssignments 以指派集合為主體的一般三態集合；與 ScopeSetFor 共用 scopeSetOn。
func (e *ScopeEvaluator) ScopeSetForAssignments(tx *gorm.DB, set AssignmentSet, perm Permission) (ScopeSet, error) {
	p, err := e.assignmentPrincipal(tx, set)
	if err != nil {
		return ScopeSet{}, err
	}
	return scopeSetOn(p, perm, sourcesAll), nil
}

// NodeScopeOnlySetForAssignments 以指派集合為主體的「只取節點範圍指派」變體；與 NodeScopeOnlySetFor 共用 scopeSetOn。
func (e *ScopeEvaluator) NodeScopeOnlySetForAssignments(tx *gorm.DB, set AssignmentSet, perm Permission) (ScopeSet, error) {
	p, err := e.assignmentPrincipal(tx, set)
	if err != nil {
		return ScopeSet{}, err
	}
	return scopeSetOn(p, perm, sourcesNodeOnly), nil
}

// ViewShortcutForAssignments 以指派集合為主體的檢視類全量視圖資格；即 Principal.ViewShortcut，
// 與正式主體共用同一舊主角色折疊與內建身分判定。
func (e *ScopeEvaluator) ViewShortcutForAssignments(tx *gorm.DB, set AssignmentSet) (bool, error) {
	p, err := e.assignmentPrincipal(tx, set)
	if err != nil {
		return false, err
	}
	return p.ViewShortcut(), nil
}

func (e *ScopeEvaluator) assignmentPrincipal(tx *gorm.DB, set AssignmentSet) (*Principal, error) {
	if tx == nil {
		return nil, errScopeNilTx
	}
	return principalFromAssignments(tx, e.cat, set)
}

// principalFromAssignments 由指派集合組出主體：讀未刪除角色的定義（內建識別、自訂集合，目錄過濾同正式解析），
// 以 filterLiveNodes 過濾範圍節點，再經 NewPrincipalOn 計算能力與來源。主體沒有使用者編號。
func principalFromAssignments(db *gorm.DB, cat Catalogue, set AssignmentSet) (*Principal, error) {
	if set.SubjectKind != "" && set.SubjectKind != model.KindHuman && set.SubjectKind != model.KindAgent {
		return nil, fmt.Errorf("%w: subject kind %q", ErrAssignmentInvalid, set.SubjectKind)
	}
	roleIDs := make([]uint, 0, len(set.Items))
	for i, it := range set.Items {
		if err := validateAssignmentInput(it); err != nil {
			return nil, fmt.Errorf("%w: item %d: %s", ErrAssignmentInvalid, i, err.Error())
		}
		roleIDs = append(roleIDs, it.RoleID)
	}
	roles := map[uint]assignmentRow{}
	if len(roleIDs) > 0 {
		var rows []assignmentRow
		if err := db.Raw(`SELECT roles.id AS role_id, roles.name AS role_name, roles.builtin_key AS builtin_key, roles.definition_version AS def_version
 FROM roles WHERE roles.id IN ? AND roles.deleted_at IS NULL`, roleIDs).Scan(&rows).Error; err != nil {
			return nil, fmt.Errorf("解析指派集合角色失敗: %w", err)
		}
		for _, r := range rows {
			roles[r.RoleID] = r
		}
	}
	items := make([]assignmentRow, len(set.Items))
	for i, it := range set.Items {
		r, ok := roles[it.RoleID]
		if !ok {
			return nil, fmt.Errorf("%w: role %d", ErrAssignmentRoleMissing, it.RoleID)
		}
		r.ScopeKind = it.Scope
		if it.BindingSubject == model.BindingSubjectUserGroup {
			r.GroupID = it.GroupID
		}
		items[i] = r
	}
	custom, err := customPermissionsOf(db, cat, items)
	if err != nil {
		return nil, err
	}
	assignments := make([]Assignment, 0, len(items))
	for i, r := range items {
		via := ViaDirect
		if set.Items[i].BindingSubject == model.BindingSubjectUserGroup {
			via = ViaGroup
		}
		a := assignmentFromRow(r, via, custom)
		if a.Scope == model.ScopeKindNodes {
			ids, err := filterLiveNodes(db, set.Items[i].NodeIDs)
			if err != nil {
				return nil, err
			}
			a.LiveNodeIDs = ids
		}
		assignments = append(assignments, a)
	}
	return NewPrincipalOn(cat, 0, TokenFacts{SubjectKind: set.SubjectKind}, assignments), nil
}

func validateAssignmentInput(it AssignmentInput) error {
	switch it.BindingSubject {
	case model.BindingSubjectUser:
		if it.GroupID != 0 {
			return errors.New("direct assignment with group id")
		}
	case model.BindingSubjectUserGroup:
		if it.GroupID == 0 {
			return errors.New("group assignment without group id")
		}
	default:
		return fmt.Errorf("binding subject %q", it.BindingSubject)
	}
	switch it.Scope {
	case model.ScopeKindGlobal:
		if len(it.NodeIDs) > 0 {
			return errors.New("global assignment with nodes")
		}
	case model.ScopeKindNodes:
	default:
		return fmt.Errorf("scope %q", it.Scope)
	}
	if it.RoleID == 0 {
		return errors.New("role id is zero")
	}
	return nil
}
