package authz

import (
	"errors"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 預覽的可管理資產台數（選用）。
//
// 數字只有台數，不帶資產名稱、位址或識別碼。總量走範圍判定器的指派集合入口
// （ManagementVisibleScopeForAssignments）與資產頁同一份管理可視規則；逐角色數字取自同一次解析中
// 被記為資產檢視節點範圍來源的指派，不由角色名稱、角色定義含不含該權限點或「範圍不生效」狀態推導。
// 本檔不寫任何資料、不改主體解析。

// ErrPreviewScopeMissing 要求台數但範圍判定器未注入（不回部分資料）。
var ErrPreviewScopeMissing = errors.New("預覽台數需要的範圍判定器未注入")

// ManagedAssetPair 變更前後的可管理資產台數。
type ManagedAssetPair struct {
	Before int `json:"before"`
	After  int `json:"after"`
}

// PreviewRoleAssets 一個以節點範圍持有的角色的台數。直接指派回 direct、from_groups_extra、total；
// 群組指派只回 total。
type PreviewRoleAssets struct {
	RoleID          uint `json:"role_id"`
	Direct          *int `json:"direct,omitempty"`
	FromGroupsExtra *int `json:"from_groups_extra,omitempty"`
	Total           int  `json:"total"`
}

// ManagedAssetCounts 預覽回應的台數欄位；只在要求台數時出現（嵌入為指標，未要求時整組不輸出）。
type ManagedAssetCounts struct {
	ManagedAssets *ManagedAssetPair   `json:"managed_assets,omitempty"`
	GroupAssets   *ManagedAssetPair   `json:"group_assets,omitempty"`
	RoleAssets    []PreviewRoleAssets `json:"role_assets"`
}

func assignmentSetOf(kind string, as []Assignment) AssignmentSet {
	items := make([]AssignmentInput, 0, len(as))
	for _, a := range as {
		items = append(items, assignmentInputOf(a))
	}
	return AssignmentSet{SubjectKind: kind, Items: items}
}

// previewManagedAssetCounts 直接指派與群組角色指派的台數；其他種類回 nil。
func previewManagedAssetCounts(tx *gorm.DB, req PreviewRequest) (*ManagedAssetCounts, error) {
	if req.Kind != PreviewDirectRoles && req.Kind != PreviewGroupRoles {
		return nil, nil
	}
	if req.Scope == nil {
		return nil, ErrPreviewScopeMissing
	}
	ev := req.Scope
	var kind string
	var before, after []Assignment
	if req.Kind == PreviewDirectRoles {
		kinds, err := userKinds(tx, []uint{req.UserID})
		if err != nil {
			return nil, err
		}
		k, ok := kinds[req.UserID]
		if !ok {
			return nil, ErrPreviewInvalid
		}
		kind = k
		p, err := ResolveUserOn(tx, req.UserID, TokenFacts{SubjectKind: kind})
		if err != nil {
			return nil, err
		}
		add, err := roleAssignmentsIn(tx, req.RoleIDs, ViaDirect, 0, req.RoleNodes)
		if err != nil {
			return nil, err
		}
		before, after = p.Assignments, manualDirectAfter(p.Assignments, add, req.RoleNodes)
	} else {
		roleIDs, err := UserGroupRoleIDs(tx, req.GroupID)
		if err != nil {
			return nil, err
		}
		if before, err = currentGroupAssignments(tx, roleIDs, req.GroupID); err != nil {
			return nil, err
		}
		ranges, err := groupRoleRanges(tx, req.GroupID, req.RoleNodes)
		if err != nil {
			return nil, err
		}
		if after, err = roleAssignmentsIn(tx, req.RoleIDs, ViaGroup, req.GroupID, ranges); err != nil {
			return nil, err
		}
	}
	beforeSet, afterSet := assignmentSetOf(kind, before), assignmentSetOf(kind, after)
	b, err := ev.managementVisibleCount(tx, beforeSet)
	if err != nil {
		return nil, err
	}
	a, err := ev.managementVisibleCount(tx, afterSet)
	if err != nil {
		return nil, err
	}
	rows, err := ev.roleAssetRows(tx, afterSet, req.Kind == PreviewDirectRoles)
	if err != nil {
		return nil, err
	}
	out := &ManagedAssetCounts{RoleAssets: rows}
	pair := &ManagedAssetPair{Before: b, After: a}
	if req.Kind == PreviewDirectRoles {
		out.ManagedAssets = pair
	} else {
		out.GroupAssets = pair
	}
	return out, nil
}

func (e *ScopeEvaluator) managementVisibleCount(tx *gorm.DB, set AssignmentSet) (int, error) {
	m, err := e.ManagementVisibleScopeForAssignments(tx, set)
	if err != nil {
		return 0, err
	}
	n, err := e.CountManagementVisible(tx, m)
	return int(n), err
}

// countSubtreeRoots 一組節點根的子樹內未刪除資產去重台數。
func (e *ScopeEvaluator) countSubtreeRoots(tx *gorm.DB, roots []uint) (int, error) {
	seen := map[uint]bool{}
	uniq := make([]uint, 0, len(roots))
	for _, r := range roots {
		if !seen[r] {
			seen[r] = true
			uniq = append(uniq, r)
		}
	}
	if len(uniq) == 0 {
		return 0, nil
	}
	n, err := e.CountManagementVisible(tx, ManagementVisibleScope{built: true, set: ScopeSet{state: ScopeSetConditional, roots: uniq}})
	return int(n), err
}

// roleAssetRows 每個以節點範圍持有的角色一列。來源取自同一次解析中資產檢視權限點的節點範圍來源；
// 某筆節點範圍指派沒有成為來源（角色不含該權限點，或解析時未啟用其範本）時，它對該列的貢獻為 0。
func (e *ScopeEvaluator) roleAssetRows(tx *gorm.DB, set AssignmentSet, direct bool) ([]PreviewRoleAssets, error) {
	p, err := e.assignmentPrincipal(tx, set)
	if err != nil {
		return nil, err
	}
	_, idx := p.sourceAssignments(PermAssetView)
	directRoots, allRoots := map[uint][]uint{}, map[uint][]uint{}
	for _, i := range idx {
		a := p.Assignments[i]
		allRoots[a.RoleID] = append(allRoots[a.RoleID], a.LiveNodeIDs...)
		if a.Via == ViaDirect {
			directRoots[a.RoleID] = append(directRoots[a.RoleID], a.LiveNodeIDs...)
		}
	}
	listed := map[uint]bool{}
	for _, a := range p.Assignments {
		if a.Scope == model.ScopeKindNodes {
			listed[a.RoleID] = true
		}
	}
	ids := make([]uint, 0, len(listed))
	for id := range listed {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]PreviewRoleAssets, 0, len(ids))
	for _, id := range ids {
		total, err := e.countSubtreeRoots(tx, allRoots[id])
		if err != nil {
			return nil, err
		}
		row := PreviewRoleAssets{RoleID: id, Total: total}
		if direct {
			d, err := e.countSubtreeRoots(tx, directRoots[id])
			if err != nil {
				return nil, err
			}
			extra := total - d
			row.Direct, row.FromGroupsExtra = &d, &extra
		}
		out = append(out, row)
	}
	return out, nil
}
