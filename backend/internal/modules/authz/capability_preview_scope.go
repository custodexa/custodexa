package authz

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 危險組合預覽的節點範圍面。
//
// 兩種組合以「範圍有交集」為條件，依實際交集計算：授權規則管理與資產或憑證管理，以及資產管理與可連線資產。
// 其餘三種與範圍無關，照舊。交集一律經範圍判定器的指派集合入口（ScopeSetForAssignments）與集合述詞
// （ApplyScopeSet）求得，預覽的假設指派不另組主體、不另寫子樹查詢。本檔不寫任何資料。

// checkPreviewRoleNodes role_nodes 的輸入檢查：只有直接指派與群組角色指派接受；鍵必須在 role_ids 內；
// 節點集合不可為空（改全域以 Global 表示）。
func checkPreviewRoleNodes(req PreviewRequest) error {
	if len(req.RoleNodes) == 0 {
		return nil
	}
	if req.Kind != PreviewDirectRoles && req.Kind != PreviewGroupRoles {
		return fmt.Errorf("%w: role_nodes 只接受直接指派與群組角色指派", ErrPreviewInvalid)
	}
	listed := make(map[uint]bool, len(req.RoleIDs))
	for _, id := range req.RoleIDs {
		listed[id] = true
	}
	for id, rg := range req.RoleNodes {
		if !listed[id] {
			return fmt.Errorf("%w: role_nodes 的角色不在 role_ids 內", ErrPreviewInvalid)
		}
		if !rg.Global && len(rg.NodeIDs) == 0 {
			return fmt.Errorf("%w: role_nodes 的節點集合不可為空", ErrPreviewInvalid)
		}
	}
	return nil
}

// groupRoleRanges 群組各角色指派變更後的範圍：現有節點範圍的指派保留其節點，請求的 role_nodes 覆蓋。
func groupRoleRanges(tx *gorm.DB, groupID uint, over map[uint]PreviewRoleRange) (map[uint]PreviewRoleRange, error) {
	scoped, err := UserGroupNodeScopedRoleIDs(tx, groupID)
	if err != nil {
		return nil, err
	}
	nodes, err := UserGroupRoleScopes(tx, groupID)
	if err != nil {
		return nil, err
	}
	out := make(map[uint]PreviewRoleRange, len(scoped)+len(over))
	for _, id := range scoped {
		out[id] = PreviewRoleRange{NodeIDs: nodes[id]}
	}
	for id, rg := range over {
		out[id] = rg
	}
	return out, nil
}

// currentGroupAssignments 群組目前帶給成員的指派（含各指派現有的節點範圍）。
func currentGroupAssignments(tx *gorm.DB, roleIDs []uint, groupID uint) ([]Assignment, error) {
	ranges, err := groupRoleRanges(tx, groupID, nil)
	if err != nil {
		return nil, err
	}
	return roleAssignmentsIn(tx, roleIDs, ViaGroup, groupID, ranges)
}

func hasNodeScopedAssignment(as []Assignment) bool {
	for _, a := range as {
		if a.Scope == model.ScopeKindNodes {
			return true
		}
	}
	return false
}

// assignmentRanges 一筆指派在三組權限點上的有效範圍（單筆指派各自求得，不跨指派拼接）。
type assignmentRanges struct {
	authz ScopeSet // 授權規則管理
	asset ScopeSet // 資產管理（不含憑證）
	cred  ScopeSet // 憑證管理
}

func assignmentInputOf(a Assignment) AssignmentInput {
	in := AssignmentInput{BindingSubject: model.BindingSubjectUser, RoleID: a.RoleID, Scope: model.ScopeKindGlobal}
	if a.Via == ViaGroup {
		in.BindingSubject, in.GroupID = model.BindingSubjectUserGroup, a.GroupID
	}
	if a.Scope == model.ScopeKindNodes {
		in.Scope, in.NodeIDs = model.ScopeKindNodes, a.LiveNodeIDs
	}
	return in
}

func isCredentialPermission(k Permission) bool { return strings.HasPrefix(string(k), "credential:") }

// unionScopeSets 多個範圍集合的聯集：任一不限即不限；否則取節點聯集；全空即空。
func unionScopeSets(sets []ScopeSet) ScopeSet {
	seen := map[uint]bool{}
	var roots []uint
	for _, s := range sets {
		switch s.state {
		case ScopeSetUnlimited:
			return unlimitedSet()
		case ScopeSetConditional:
			for _, n := range s.roots {
				if !seen[n] {
					seen[n] = true
					roots = append(roots, n)
				}
			}
		}
	}
	if len(roots) == 0 {
		return emptySet(ScopeReasonNoEffectiveBinding)
	}
	return ScopeSet{state: ScopeSetConditional, roots: roots}
}

func (e *ScopeEvaluator) rangesOfAssignment(tx *gorm.DB, kind string, a Assignment) (assignmentRanges, error) {
	set := AssignmentSet{SubjectKind: kind, Items: []AssignmentInput{assignmentInputOf(a)}}
	var authzSets, assetSets, credSets []ScopeSet
	seen := map[Permission]bool{}
	for _, k := range assignmentRolePermissions(a) {
		if seen[k] {
			continue
		}
		seen[k] = true
		def, ok := LookupPermission(k)
		if !ok {
			continue
		}
		var dst *[]ScopeSet
		switch {
		case k == PermAuthorizationManage:
			dst = &authzSets
		case def.Group == GroupAsset && def.Category == CategoryManage && isCredentialPermission(k):
			dst = &credSets
		case def.Group == GroupAsset && def.Category == CategoryManage:
			dst = &assetSets
		default:
			continue
		}
		s, err := e.ScopeSetForAssignments(tx, set, k)
		if err != nil {
			return assignmentRanges{}, err
		}
		*dst = append(*dst, s)
	}
	return assignmentRanges{authz: unionScopeSets(authzSets), asset: unionScopeSets(assetSets), cred: unionScopeSets(credSets)}, nil
}

// refineScopedCombos 有節點範圍指派的主體：授權規則管理與資產或憑證管理、資產管理與可連線資產兩個組合
// 改依實際交集；其餘三種沿用 base。拓撲未注入時退回 base（只多提示）。
func refineScopedCombos(tx *gorm.DB, ev *ScopeEvaluator, kind string, userID uint, st subjectState,
	connect bool, base []string) ([]string, error) {

	if ev.topo == nil {
		return base, nil
	}
	has := map[string]bool{}
	for _, c := range base {
		has[c] = true
	}
	needAuthz, needConnect := has[ComboAuthzRulesWithAssetOrCredential], has[ComboAssetManagementWithConnect]
	if !needAuthz && !needConnect {
		return base, nil
	}
	ranges := make([]assignmentRanges, 0, len(st.assignments))
	for _, a := range st.assignments {
		r, err := ev.rangesOfAssignment(tx, kind, a)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}
	if needAuthz {
		ok, err := ev.authzMeetsManagement(tx, ranges)
		if err != nil {
			return nil, err
		}
		has[ComboAuthzRulesWithAssetOrCredential] = ok
	}
	if needConnect {
		ok, err := ev.managementMeetsConnectable(tx, ranges, connect, userID, st.groupIDs)
		if err != nil {
			return nil, err
		}
		has[ComboAssetManagementWithConnect] = ok
	}
	out := make([]string, 0, len(base))
	for _, c := range DangerCombos() {
		if has[c] {
			out = append(out, c)
		}
	}
	return out, nil
}

// authzMeetsManagement 存在一筆含授權規則管理的指派與一筆含資產（或憑證）管理的指派，兩者範圍有交集。
func (e *ScopeEvaluator) authzMeetsManagement(tx *gorm.DB, ranges []assignmentRanges) (bool, error) {
	for _, a := range ranges {
		if a.authz.state != ScopeSetUnlimited && a.authz.state != ScopeSetConditional {
			continue
		}
		for _, b := range ranges {
			if ok, err := e.rangesIntersect(tx, a.authz, b.asset, false); err != nil || ok {
				return ok, err
			}
			if ok, err := e.rangesIntersect(tx, a.authz, b.cred, true); err != nil || ok {
				return ok, err
			}
		}
	}
	return false, nil
}

// rangesIntersect 兩個範圍集合是否有交集（聯集條件，只多提示、不少提示）：
// 任一不限且另一非空；節點子樹相交（一方的節點在另一方節點的子樹內）；有一台未刪除資產同時在兩方內；
// credential 為真時另看有沒有一份專用憑證的掛載資產同時在兩方內。
func (e *ScopeEvaluator) rangesIntersect(tx *gorm.DB, a, b ScopeSet, credential bool) (bool, error) {
	if a.state == ScopeSetEmpty || b.state == ScopeSetEmpty || a.state == 0 || b.state == 0 {
		return false, nil
	}
	if a.state == ScopeSetUnlimited || b.state == ScopeSetUnlimited {
		return true, nil
	}
	for _, kind := range []ScopeQueryKind{ScopeQueryNode, ScopeQueryAsset} {
		var base *gorm.DB
		if kind == ScopeQueryNode {
			base = tx.Model(&model.AssetGroup{})
		} else {
			base = tx.Model(&model.Asset{})
		}
		ok, err := e.existsInBoth(tx, base, a, b, kind)
		if err != nil || ok {
			return ok, err
		}
	}
	if credential {
		return e.credentialInBoth(tx, a, b)
	}
	return false, nil
}

func (e *ScopeEvaluator) existsInBoth(tx, base *gorm.DB, a, b ScopeSet, kind ScopeQueryKind) (bool, error) {
	q, err := e.ApplyScopeSet(tx, base, a, kind)
	if err != nil {
		return false, err
	}
	if q, err = e.ApplyScopeSet(tx, q, b, kind); err != nil {
		return false, err
	}
	var n int64
	if err := q.Limit(1).Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢範圍交集失敗: %w", err)
	}
	return n > 0, nil
}

// credentialInBoth 有一份專用憑證（以最早一筆未刪除掛載判定）的掛載資產同時在兩方範圍內。節點歸屬的共用憑證，
// 歸屬節點在兩方子樹內即兩方節點子樹相交，由 rangesIntersect 的節點步驟涵蓋（不需要憑證存在，只多提示）。
// 憑證與掛載的讀取經拓撲讀取器，本檔不直接讀憑證表。
func (e *ScopeEvaluator) credentialInBoth(tx *gorm.DB, a, b ScopeSet) (bool, error) {
	assets, err := e.ApplyScopeSet(tx, tx.Model(&model.Asset{}).Select("assets.id"), a, ScopeQueryAsset)
	if err != nil {
		return false, err
	}
	if assets, err = e.ApplyScopeSet(tx, assets, b, ScopeQueryAsset); err != nil {
		return false, err
	}
	var n int64
	if err := tx.Raw("SELECT count(*) FROM (?) AS mounted", e.topo.CredentialsFirstMountedOn(tx, assets)).Scan(&n).Error; err != nil {
		return false, fmt.Errorf("查詢憑證範圍交集失敗: %w", err)
	}
	return n > 0, nil
}

// managementMeetsConnectable 主體經授權規則可連線的資產中，至少一台落在其某筆資產管理指派的範圍內。
func (e *ScopeEvaluator) managementMeetsConnectable(tx *gorm.DB, ranges []assignmentRanges, connect bool,
	userID uint, groupIDs []uint) (bool, error) {

	sets := make([]ScopeSet, 0, 2*len(ranges))
	for _, r := range ranges {
		sets = append(sets, r.asset, r.cred)
	}
	mgmt := unionScopeSets(sets)
	switch mgmt.state {
	case ScopeSetUnlimited:
		return connect, nil
	case ScopeSetConditional:
	default:
		return false, nil
	}
	now := time.Now()
	q := tx.Model(&model.AssetAuthorization{}).Where("permission = ?", model.PermissionConnect).
		Where("(date_start IS NULL OR date_start <= ?) AND (date_expired IS NULL OR date_expired > ?)", now, now)
	if len(groupIDs) > 0 {
		q = q.Where("user_id = ? OR user_group_id IN ?", userID, groupIDs)
	} else {
		q = q.Where("user_id = ?", userID)
	}
	var rules []struct {
		AssetID      *uint
		AssetGroupID *uint
	}
	if err := q.Select("asset_id, asset_group_id").Scan(&rules).Error; err != nil {
		return false, fmt.Errorf("查詢連線授權規則失敗: %w", err)
	}
	var direct, nodes []uint
	for _, r := range rules {
		if r.AssetID != nil {
			direct = append(direct, *r.AssetID)
		}
		if r.AssetGroupID != nil {
			nodes = append(nodes, *r.AssetGroupID)
		}
	}
	if len(direct) == 0 && len(nodes) == 0 {
		return false, nil
	}
	assets, err := e.ApplyScopeSet(tx, tx.Model(&model.Asset{}), mgmt, ScopeQueryAsset)
	if err != nil {
		return false, err
	}
	switch {
	case len(direct) > 0 && len(nodes) > 0:
		assets = assets.Where("assets.id IN ? OR assets.id IN (?)", direct, e.topo.SubtreeAssetIDs(tx, nodes))
	case len(direct) > 0:
		assets = assets.Where("assets.id IN ?", direct)
	default:
		assets = assets.Where("assets.id IN (?)", e.topo.SubtreeAssetIDs(tx, nodes))
	}
	var n int64
	if err := assets.Limit(1).Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢可連線資產失敗: %w", err)
	}
	return n > 0, nil
}
