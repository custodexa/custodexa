package authz

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 危險組合預覽（唯讀）。
//
// 以「提議的變更」對每位受影響主體各算一次變更前、變更後的有效能力，找出變更後新命中的
// 危險組合、入口增減與將觸發的授權變更分類。組合依有效能力聯集計算（跨角色、跨群組），
// 單一角色定義看不到的組合也會被指出。本檔不寫任何資料、不推進版本、不產生審計。
// 警告只是提示；寫入路徑不要求預覽，仍依指派關卡裁決。

// 危險組合碼。
const (
	ComboAuthzRulesWithAssetOrCredential = "authz_rules_with_asset_or_credential"
	ComboSecurityWithAssetOrAuthz        = "security_with_asset_or_authz"
	ComboAssetManagementWithConnect      = "asset_management_with_connect"
	ComboIdentityWithSecurity            = "identity_with_security"
	ComboIdentityWithBusinessOrConnect   = "identity_with_business_or_connect"
)

// DangerCombos 五個組合碼（固定順序）。
func DangerCombos() []string {
	return []string{ComboAuthzRulesWithAssetOrCredential, ComboSecurityWithAssetOrAuthz,
		ComboAssetManagementWithConnect, ComboIdentityWithSecurity, ComboIdentityWithBusinessOrConnect}
}

// 預覽輸入種類。
const (
	PreviewDirectRoles     = "direct_roles"    // 使用者直接指派（整組替換後的角色集合）
	PreviewGroupRoles      = "group_roles"     // 群組角色指派（整組替換後的角色集合）
	PreviewGroupMembers    = "group_members"   // 群組成員（整組替換後的成員集合）
	PreviewRoleDefinition  = "role_definition" // 自訂角色權限集合修改
	PreviewMappingGrant    = "mapping_grant"   // 外部群組映射規則生效：命中帳號被加上角色（RoleID）或使用者群組成員身分（GroupID）
	PreviewDefaultListSize = 100               // 主體清單上限
)

var (
	// ErrPreviewInvalid 輸入種類不明、對象不存在或角色不存在。
	ErrPreviewInvalid = errors.New("預覽輸入無效")
	// ErrPreviewRoleNotCustom 角色定義預覽只接受自訂角色。
	ErrPreviewRoleNotCustom = errors.New("預覽的角色不是自訂角色")
)

// PreviewRequest 提議的變更。各種類只讀自己的欄位。
type PreviewRequest struct {
	Kind       string
	OperatorID uint
	// PreviewDirectRoles
	UserID uint
	// PreviewGroupRoles／PreviewGroupMembers
	GroupID uint
	// PreviewDirectRoles／PreviewGroupRoles：變更後的角色集合
	RoleIDs []uint
	// RoleNodes 與寫入同形的節點範圍輸入（角色編號 → 範圍值）：鍵不存在即保留現有範圍（新增的角色為全域），
	// Global 為改全域，否則為節點集合（不可為空）。鍵必須在 RoleIDs 內；只有 PreviewDirectRoles、
	// PreviewGroupRoles 接受。
	RoleNodes map[uint]PreviewRoleRange
	// Scope 範圍判定器（取拓撲）。有節點範圍指派的主體，兩種有交集條件的組合依實際交集計算；
	// 未注入時退回任何範圍都算（只多提示）。
	Scope *ScopeEvaluator
	// IncludeManagedAssetCounts 要求回可管理資產台數；只有直接指派與群組角色指派會回，其他種類忽略。
	IncludeManagedAssetCounts bool
	// PreviewGroupMembers：變更後的成員集合（舊語義：整組有效成員）
	MemberIDs []uint
	// PreviewGroupMembers：變更後的手動成員集合（與寫入同義，只改手動成分；與 MemberIDs 二擇一，
	// 非 nil 即視為已提供，空切片代表清空手動成員）。
	ManualMemberIDs *[]uint
	// PreviewMappingGrant：規則命中的帳號，加上 RoleID 的角色或 GroupID 的成員身分（二擇一）
	SubjectIDs []uint
	// PreviewRoleDefinition／PreviewMappingGrant
	RoleID      uint
	Permissions []string
	// Limit 主體清單上限；0 或超過預設值一律取預設值。
	Limit int
	// GroupMemberPlanner 手動成員輸入的求值（身分模組的資料與規則，由組裝端注入）。
	GroupMemberPlanner GroupMemberPlanner
	// MappingRuleCounter 角色定義種類計算整筆分類所需的映射規則計數（身分模組的資料，由組裝端注入）。
	MappingRuleCounter RoleMappingRuleCounter
	// MappingRule／MappingRulePlanner 映射規則變更種類的輸入與求值器（身分模組的資料與規則，由組裝端注入）。
	MappingRule        *MappingRuleChange
	MappingRulePlanner MappingRulePlanner
}

// PreviewRoleRange 預覽輸入中一個角色的範圍值。
type PreviewRoleRange struct {
	Global  bool
	NodeIDs []uint
}

// PreviewSubject 一位主體的預覽。
type PreviewSubject struct {
	UserID uint `json:"user_id"`
	// Self 該主體就是操作者本人。
	Self bool `json:"self"`
	// AssignCapable 變更後持有指派角色能力（身分管理員本人的標示依據）。
	AssignCapable bool     `json:"assign_capable"`
	EntriesGained []string `json:"entries_gained"`
	EntriesLost   []string `json:"entries_lost"`
	// Combos 變更後命中的全部組合；NewCombos 其中變更前未命中者。
	Combos    []string `json:"combos"`
	NewCombos []string `json:"new_combos"`
	// RoutesGained／RoutesLost 頁面入口增減，依導覽同一份規則求得（RouteEntryRules）；
	// 登入即可與依本人資格的入口不列入。
	RoutesGained []string `json:"routes_gained"`
	RoutesLost   []string `json:"routes_lost"`
	// 將觸發的分類（同 ClassifyGrantChange）。
	SelfDirection     GrantDirection `json:"self_direction"`
	ManagementGranted bool           `json:"management_granted"`
	Marks             []string       `json:"marks"`
}

// PreviewResult 預覽結果。
type PreviewResult struct {
	// Total 受影響主體總數。
	Total int `json:"total"`
	// Matched 符合列出條件（本人或變更後新命中組合）的主體數；Subjects 超過上限時截斷。
	Matched   int              `json:"matched"`
	Truncated bool             `json:"truncated"`
	Subjects  []PreviewSubject `json:"subjects"`
	// Operation 整筆修改的告警分類與入口增減，不受列出條件與上限影響；分類與寫入同一組函式求得。
	// 映射規則生效種類（內部種類）不回傳。
	Operation *PreviewOperation `json:"operation,omitempty"`
	// 台數欄位：只在要求且種類適用時出現（嵌入指標，未要求時不輸出任何鍵）。
	*ManagedAssetCounts
}

// PreviewOperation 整筆變更將觸發的告警分類與全體主體的入口增減聯集。
type PreviewOperation struct {
	// Marks 告警標記（self_authorization、management_grant）；沒有時為空陣列。
	Marks []string `json:"marks"`
	// SelfDirection 對操作者本人的方向（空、increase、decrease）。
	SelfDirection     GrantDirection `json:"self_direction"`
	ManagementGranted bool           `json:"management_granted"`
	// RoutesGained／RoutesLost 所有已求值主體的頁面入口增減聯集（導覽規則語義）。
	RoutesGained []string `json:"routes_gained"`
	RoutesLost   []string `json:"routes_lost"`
	// EntriesGained／EntriesLost 所有已求值主體的角色功能入口增減聯集（角色編輯描述表語義）。
	EntriesGained []string `json:"entries_gained"`
	EntriesLost   []string `json:"entries_lost"`
	// Evaluated 實際求值的主體數。
	Evaluated int `json:"evaluated"`
}

// GroupMemberPlan 手動成員輸入求值的結果（與群組成員寫入共用同一份求值）。
type GroupMemberPlan struct {
	// Effective 變更後的有效成員：手動集加上仍受映射支持或本就非手動的成員。
	Effective []uint
	// Added 寫入定義的加入名單：手動集中目前不是成員、或目前只是映射成員者；不含已被排除者。
	Added []uint
}

// GroupMemberPlanner 依群組現值與手動成員輸入求變更後成員。唯讀。
type GroupMemberPlanner func(tx *gorm.DB, groupID uint, manualIDs []uint) (GroupMemberPlan, error)

// ErrPreviewPlannerMissing 手動成員輸入需要的求值器未注入（缺了就會把映射成員錯報成移出）。
var ErrPreviewPlannerMissing = errors.New("手動成員求值器未注入")

// previewExtra 計畫階段順帶求得、整筆分類要用的事實。
type previewExtra struct {
	// groupAdded 群組角色指派新增的角色（寫入側的 entriesAdded 同義）。
	groupAdded []GrantEntry
	// groupHasEntries 群組目前帶的角色指派（成員加入路徑判管理類用）。
	groupEntries []GrantEntry
	// addedMembers 群組成員加入名單（含操作者本人，之後再排除）。
	addedMembers []uint
}

// subjectState 一位主體在某個時點的假設狀態。
type subjectState struct {
	assignments []Assignment
	groupIDs    []uint
}

// PreviewEffectiveCapabilities 計算預覽。tx 只做讀取。
func PreviewEffectiveCapabilities(tx *gorm.DB, req PreviewRequest) (PreviewResult, error) {
	limit := req.Limit
	if limit <= 0 || limit > PreviewDefaultListSize {
		limit = PreviewDefaultListSize
	}
	if req.Kind == PreviewMappingRuleChange {
		return previewMappingRuleChange(tx, req, limit)
	}
	ids, mutate, extra, err := previewPlan(tx, req)
	if err != nil {
		return PreviewResult{}, err
	}
	kinds, err := userKinds(tx, ids)
	if err != nil {
		return PreviewResult{}, err
	}
	live := make([]uint, 0, len(ids))
	for _, id := range ids {
		if _, ok := kinds[id]; ok {
			live = append(live, id)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i] < live[j] })

	res := PreviewResult{Total: len(live), Subjects: []PreviewSubject{}}
	var listed []PreviewSubject
	all := make([]PreviewSubject, 0, len(live))
	for _, id := range live {
		subj, err := previewSubject(tx, id, kinds[id], req.OperatorID, req.Scope, mutate)
		if err != nil {
			return PreviewResult{}, err
		}
		all = append(all, subj)
		if subj.Self || len(subj.NewCombos) > 0 {
			listed = append(listed, subj)
		}
	}
	// 本人排最前，其餘依使用者編號。
	sort.SliceStable(listed, func(i, j int) bool {
		if listed[i].Self != listed[j].Self {
			return listed[i].Self
		}
		return listed[i].UserID < listed[j].UserID
	})
	res.Matched = len(listed)
	if len(listed) > limit {
		listed, res.Truncated = listed[:limit], true
	}
	if listed != nil {
		res.Subjects = listed
	}
	if req.Kind != PreviewMappingGrant {
		op, err := previewOperation(req, extra, tx, all)
		if err != nil {
			return PreviewResult{}, err
		}
		res.Operation = &op
	}
	if req.IncludeManagedAssetCounts {
		counts, err := previewManagedAssetCounts(tx, req)
		if err != nil {
			return PreviewResult{}, err
		}
		res.ManagedAssetCounts = counts
	}
	return res, nil
}

// previewOperation 整筆變更的分類：與寫入共用同一組分類函式，不從逐人分類加總
// （對沒有組合的他人發放、空群組新增管理角色，逐人列表是空的，整筆仍要回報）。
func previewOperation(req PreviewRequest, extra previewExtra, tx *gorm.DB, all []PreviewSubject) (PreviewOperation, error) {
	var base PreviewOperation
	switch req.Kind {
	case PreviewRoleDefinition:
		op, err := roleDefinitionOperation(tx, req)
		if err != nil {
			return PreviewOperation{}, err
		}
		base = op
	case PreviewDirectRoles:
		for _, s := range all {
			if s.UserID == req.UserID {
				base.SelfDirection, base.ManagementGranted, base.Marks = s.SelfDirection, s.ManagementGranted, s.Marks
			}
		}
	case PreviewGroupRoles:
		base = operatorOperation(all)
		if mg := ClassifyGroupManagementGrant(extra.groupAdded); len(mg) > 0 {
			base.ManagementGranted = true
			base.Marks = append(base.Marks, GrantMarkManagementGrant)
		}
	case PreviewGroupMembers:
		base = operatorOperation(all)
		others := 0
		for _, id := range extra.addedMembers {
			if id != req.OperatorID {
				others++
			}
		}
		if others > 0 && len(ClassifyGroupManagementGrant(extra.groupEntries)) > 0 {
			base.ManagementGranted = true
			base.Marks = append(base.Marks, GrantMarkManagementGrant)
		}
	}
	return aggregateOperation(base, all), nil
}

// aggregateOperation 補上標記空陣列、求值數與全體已求值主體的入口增減聯集。
func aggregateOperation(base PreviewOperation, all []PreviewSubject) PreviewOperation {
	if base.Marks == nil {
		base.Marks = []string{}
	}
	base.Evaluated = len(all)
	rg, rl, eg, el := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range all {
		for _, v := range s.RoutesGained {
			rg[v] = true
		}
		for _, v := range s.RoutesLost {
			rl[v] = true
		}
		for _, v := range s.EntriesGained {
			eg[v] = true
		}
		for _, v := range s.EntriesLost {
			el[v] = true
		}
	}
	base.RoutesGained, base.RoutesLost = sortedKeys(rg), sortedKeys(rl)
	base.EntriesGained, base.EntriesLost = sortedKeys(eg), sortedKeys(el)
	return base
}

// operatorOperation 群組路徑的本人分類：操作者本人若在受影響者內，取他的前後摘要分類。
func operatorOperation(all []PreviewSubject) PreviewOperation {
	var op PreviewOperation
	for _, s := range all {
		if s.Self {
			op.SelfDirection = s.SelfDirection
			if s.SelfDirection != GrantNone {
				op.Marks = append(op.Marks, GrantMarkSelfAuthorization)
			}
		}
	}
	return op
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// roleDefinitionOperation 角色定義修改的整筆分類：集合差與持有／引用事實都取現值，
// 與寫入共用 ClassifyRoleContentChange、ClassifyRoleContentOperation。
func roleDefinitionOperation(tx *gorm.DB, req PreviewRequest) (PreviewOperation, error) {
	after, err := NormalizeRolePermissions(req.Permissions)
	if err != nil {
		return PreviewOperation{}, fmt.Errorf("%w: %v", ErrPreviewInvalid, err)
	}
	var keys []string
	if err := tx.Model(&model.RolePermission{}).Where("role_id = ?", req.RoleID).Pluck("permission_key", &keys).Error; err != nil {
		return PreviewOperation{}, fmt.Errorf("讀取角色權限集合失敗: %w", err)
	}
	before := make([]Permission, len(keys))
	for i, k := range keys {
		before[i] = Permission(k)
	}
	impact, err := LoadRoleContentImpact(tx, req.RoleID, req.MappingRuleCounter)
	if err != nil {
		return PreviewOperation{}, err
	}
	cl := ClassifyRoleContentOperation(ClassifyRoleContentChange(before, after), impact, req.OperatorID)
	marks := cl.Marks
	if marks == nil {
		marks = []string{}
	}
	return PreviewOperation{Marks: marks, SelfDirection: cl.SelfDirection, ManagementGranted: cl.ManagementGranted}, nil
}

type stateMutator func(tx *gorm.DB, userID uint, before subjectState) (subjectState, error)

// previewPlan 找出受影響使用者與「如何由變更前狀態得到變更後狀態」。
func previewPlan(tx *gorm.DB, req PreviewRequest) ([]uint, stateMutator, previewExtra, error) {
	var extra previewExtra
	switch req.Kind {
	case PreviewDirectRoles:
		if req.UserID == 0 {
			return nil, nil, extra, fmt.Errorf("%w: 缺少使用者", ErrPreviewInvalid)
		}
		if err := checkPreviewRoleNodes(req); err != nil {
			return nil, nil, extra, err
		}
		add, err := roleAssignmentsIn(tx, req.RoleIDs, ViaDirect, 0, req.RoleNodes)
		if err != nil {
			return nil, nil, extra, err
		}
		return []uint{req.UserID}, func(_ *gorm.DB, _ uint, b subjectState) (subjectState, error) {
			return subjectState{assignments: manualDirectAfter(b.assignments, add, req.RoleNodes), groupIDs: b.groupIDs}, nil
		}, extra, nil
	case PreviewGroupRoles:
		if err := requireGroup(tx, req.GroupID); err != nil {
			return nil, nil, extra, err
		}
		if err := checkPreviewRoleNodes(req); err != nil {
			return nil, nil, extra, err
		}
		ranges, err := groupRoleRanges(tx, req.GroupID, req.RoleNodes)
		if err != nil {
			return nil, nil, extra, err
		}
		add, err := roleAssignmentsIn(tx, req.RoleIDs, ViaGroup, req.GroupID, ranges)
		if err != nil {
			return nil, nil, extra, err
		}
		members, err := groupMemberIDs(tx, req.GroupID)
		if err != nil {
			return nil, nil, extra, err
		}
		groupBefore, err := GroupGrantEntries(tx, req.GroupID)
		if err != nil {
			return nil, nil, extra, err
		}
		afterEntries := make([]GrantEntry, 0, len(add))
		for _, a := range add {
			e, err := entryOfIn(tx, a)
			if err != nil {
				return nil, nil, extra, err
			}
			afterEntries = append(afterEntries, e)
		}
		extra.groupAdded = GrantEntriesAdded(groupBefore, afterEntries)
		gid := req.GroupID
		return members, func(_ *gorm.DB, _ uint, b subjectState) (subjectState, error) {
			kept := dropAssignments(b.assignments, func(a Assignment) bool { return a.Via == ViaGroup && a.GroupID == gid })
			return subjectState{assignments: append(kept, add...), groupIDs: b.groupIDs}, nil
		}, extra, nil
	case PreviewGroupMembers:
		if err := checkPreviewRoleNodes(req); err != nil {
			return nil, nil, extra, err
		}
		if err := requireGroup(tx, req.GroupID); err != nil {
			return nil, nil, extra, err
		}
		current, err := groupMemberIDs(tx, req.GroupID)
		if err != nil {
			return nil, nil, extra, err
		}
		cur := map[uint]bool{}
		for _, id := range current {
			cur[id] = true
		}
		nextIDs := req.MemberIDs
		if req.ManualMemberIDs != nil {
			if req.MemberIDs != nil {
				return nil, nil, extra, fmt.Errorf("%w: member_ids 與 manual_member_ids 只能擇一", ErrPreviewInvalid)
			}
			if req.GroupMemberPlanner == nil {
				return nil, nil, extra, ErrPreviewPlannerMissing
			}
			plan, err := req.GroupMemberPlanner(tx, req.GroupID, dedupeIDs(*req.ManualMemberIDs))
			if err != nil {
				return nil, nil, extra, err
			}
			nextIDs, extra.addedMembers = plan.Effective, plan.Added
		} else {
			for _, id := range nextIDs {
				if !cur[id] {
					extra.addedMembers = append(extra.addedMembers, id)
				}
			}
		}
		// 加入名單只算存在的帳號（寫入遇到不存在的帳號整筆拒絕，預覽不把它們算進通知）
		existing, err := userKinds(tx, extra.addedMembers)
		if err != nil {
			return nil, nil, extra, err
		}
		added := extra.addedMembers[:0:0]
		for _, id := range extra.addedMembers {
			if _, ok := existing[id]; ok {
				added = append(added, id)
			}
		}
		extra.addedMembers = added
		next := map[uint]bool{}
		for _, id := range nextIDs {
			next[id] = true
		}
		if extra.groupEntries, err = GroupGrantEntries(tx, req.GroupID); err != nil {
			return nil, nil, extra, err
		}
		var affected []uint
		for id := range next {
			if !cur[id] {
				affected = append(affected, id)
			}
		}
		for id := range cur {
			if !next[id] {
				affected = append(affected, id)
			}
		}
		groupRoleIDs, err := UserGroupRoleIDs(tx, req.GroupID)
		if err != nil {
			return nil, nil, extra, err
		}
		groupAssignments, err := currentGroupAssignments(tx, groupRoleIDs, req.GroupID)
		if err != nil {
			return nil, nil, extra, err
		}
		gid := req.GroupID
		return affected, func(_ *gorm.DB, uid uint, b subjectState) (subjectState, error) {
			kept := dropAssignments(b.assignments, func(a Assignment) bool { return a.Via == ViaGroup && a.GroupID == gid })
			groups := withoutID(b.groupIDs, gid)
			if next[uid] {
				kept = append(kept, groupAssignments...)
				groups = append(groups, gid)
			}
			return subjectState{assignments: kept, groupIDs: groups}, nil
		}, extra, nil
	case PreviewMappingGrant:
		if err := checkPreviewRoleNodes(req); err != nil {
			return nil, nil, extra, err
		}
		ids, mut, err := previewMappingGrantPlan(tx, req)
		return ids, mut, extra, err
	case PreviewRoleDefinition:
		if err := checkPreviewRoleNodes(req); err != nil {
			return nil, nil, extra, err
		}
		perms, err := NormalizeRolePermissions(req.Permissions)
		if err != nil {
			return nil, nil, extra, fmt.Errorf("%w: %v", ErrPreviewInvalid, err)
		}
		var role struct {
			ID         uint
			BuiltinKey *string
			DefVersion int64
		}
		if err := tx.Raw(`SELECT id, builtin_key, definition_version AS def_version FROM roles WHERE id = ? AND deleted_at IS NULL`, req.RoleID).Scan(&role).Error; err != nil {
			return nil, nil, extra, fmt.Errorf("讀取角色失敗: %w", err)
		}
		if role.ID == 0 {
			return nil, nil, extra, fmt.Errorf("%w: 角色不存在", ErrPreviewInvalid)
		}
		if role.BuiltinKey != nil || role.DefVersion < 1 {
			return nil, nil, extra, ErrPreviewRoleNotCustom
		}
		var ids []uint
		if err := tx.Raw(`SELECT user_id FROM user_roles WHERE role_id = ?
 UNION
 SELECT m.user_id FROM user_group_members m
 JOIN user_groups g ON g.id = m.user_group_id AND g.deleted_at IS NULL
 JOIN user_group_roles r ON r.user_group_id = m.user_group_id
 WHERE r.role_id = ?`, req.RoleID, req.RoleID).Scan(&ids).Error; err != nil {
			return nil, nil, extra, fmt.Errorf("讀取受影響使用者失敗: %w", err)
		}
		rid := req.RoleID
		return ids, func(_ *gorm.DB, _ uint, b subjectState) (subjectState, error) {
			out := make([]Assignment, len(b.assignments))
			copy(out, b.assignments)
			for i := range out {
				if out[i].RoleID == rid {
					out[i].Custom, out[i].Permissions = true, perms
				}
			}
			return subjectState{assignments: out, groupIDs: b.groupIDs}, nil
		}, extra, nil
	}
	return nil, nil, extra, fmt.Errorf("%w: 種類 %q", ErrPreviewInvalid, req.Kind)
}

func previewSubject(tx *gorm.DB, userID uint, kind string, operatorID uint, ev *ScopeEvaluator, mutate stateMutator) (PreviewSubject, error) {
	p, err := ResolveUserOn(tx, userID, TokenFacts{SubjectKind: kind})
	if err != nil {
		return PreviewSubject{}, err
	}
	groups, err := userGroupIDs(tx, userID)
	if err != nil {
		return PreviewSubject{}, err
	}
	before := subjectState{assignments: p.Assignments, groupIDs: groups}
	after, err := mutate(tx, userID, before)
	if err != nil {
		return PreviewSubject{}, err
	}
	bEval, err := evalState(tx, ev, userID, kind, before)
	if err != nil {
		return PreviewSubject{}, err
	}
	aEval, err := evalState(tx, ev, userID, kind, after)
	if err != nil {
		return PreviewSubject{}, err
	}
	bSum, err := summaryOf(tx, before)
	if err != nil {
		return PreviewSubject{}, err
	}
	aSum, err := summaryOf(tx, after)
	if err != nil {
		return PreviewSubject{}, err
	}
	self := userID == operatorID && operatorID != 0
	cl := ClassifyGrantChange(bSum, aSum, self)
	subj := PreviewSubject{
		UserID: userID, Self: self, AssignCapable: aEval.principal.Has(PermRoleAssign),
		EntriesGained: setDiff(aEval.entries, bEval.entries), EntriesLost: setDiff(bEval.entries, aEval.entries),
		Combos: aEval.combos, NewCombos: setDiff(aEval.combos, bEval.combos),
		RoutesGained: setDiff(aEval.routes, bEval.routes), RoutesLost: setDiff(bEval.routes, aEval.routes),
		SelfDirection: cl.SelfDirection, ManagementGranted: len(cl.ManagementGranted) > 0, Marks: cl.Marks,
	}
	return subj, nil
}

type stateEval struct {
	principal *Principal
	entries   []string
	routes    []string
	combos    []string
}

func evalState(tx *gorm.DB, ev *ScopeEvaluator, userID uint, kind string, st subjectState) (stateEval, error) {
	p := NewPrincipal(userID, TokenFacts{SubjectKind: kind}, st.assignments)
	connect := p.HasBuiltin(model.BuiltinSuperAdmin)
	if !connect {
		var err error
		if connect, err = hasConnectRule(tx, userID, st.groupIDs); err != nil {
			return stateEval{}, err
		}
	}
	combos := comboCodes(p, connect)
	if ev != nil && hasNodeScopedAssignment(st.assignments) {
		var err error
		if combos, err = refineScopedCombos(tx, ev, kind, userID, st, connect, combos); err != nil {
			return stateEval{}, err
		}
	}
	return stateEval{principal: p, entries: visibleEntries(p), routes: visibleRoutes(p), combos: combos}, nil
}

// visibleEntries 變更後可見的入口：任一非隱藏態的鍵全數在有效能力內。
func visibleEntries(p *Principal) []string {
	var out []string
	for _, e := range entryDescriptors() {
		for _, stt := range e.States[1:] {
			all := len(stt.Keys) > 0
			for _, k := range stt.Keys {
				if !p.Has(k) {
					all = false
					break
				}
			}
			if all {
				out = append(out, e.ID)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// securityKeys 安全能力：設定組內的告警去向與金鑰、安全政策管理點、刪除錄影。
func securityKeys() []Permission {
	return []Permission{PermNotificationChannel, PermSystemAlertManage, PermOffsiteManage, PermSyslogManage, PermKeyManage, PermSecurityPolicyManage, PermRecordingDelete}
}

func comboCodes(p *Principal, connect bool) []string {
	asset := false
	for _, k := range p.Capabilities() {
		if def, ok := LookupPermission(k); ok && def.Group == GroupAsset && def.Category == CategoryManage {
			asset = true
			break
		}
	}
	authzMgmt := p.Has(PermAuthorizationManage)
	security := false
	for _, k := range securityKeys() {
		if p.Has(k) {
			security = true
			break
		}
	}
	identity := p.Has(PermRoleAssign)
	var out []string
	if authzMgmt && asset {
		out = append(out, ComboAuthzRulesWithAssetOrCredential)
	}
	if security && (asset || authzMgmt) {
		out = append(out, ComboSecurityWithAssetOrAuthz)
	}
	if asset && connect {
		out = append(out, ComboAssetManagementWithConnect)
	}
	if identity && security {
		out = append(out, ComboIdentityWithSecurity)
	}
	if identity && (asset || authzMgmt || connect) {
		out = append(out, ComboIdentityWithBusinessOrConnect)
	}
	return out
}

// hasConnectRule 使用者或所屬群組是否有至少一條現時有效的 connect 授權規則。
func hasConnectRule(tx *gorm.DB, userID uint, groupIDs []uint) (bool, error) {
	now := time.Now()
	q := tx.Model(&model.AssetAuthorization{}).Where("permission = ?", model.PermissionConnect).
		Where("(date_start IS NULL OR date_start <= ?) AND (date_expired IS NULL OR date_expired > ?)", now, now)
	if len(groupIDs) > 0 {
		q = q.Where("user_id = ? OR user_group_id IN ?", userID, groupIDs)
	} else {
		q = q.Where("user_id = ?", userID)
	}
	var n int64
	if err := q.Limit(1).Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢連線授權規則失敗: %w", err)
	}
	return n > 0, nil
}

// summaryOf 假設狀態的授權摘要（與 SummarizeGrants 同義，但來源是假設狀態）。
func summaryOf(tx *gorm.DB, st subjectState) (GrantSummary, error) {
	out := GrantSummary{}
	for _, a := range st.assignments {
		e, err := entryOfIn(tx, a)
		if err != nil {
			return GrantSummary{}, err
		}
		out.Entries = append(out.Entries, e)
	}
	if len(st.groupIDs) > 0 {
		if err := tx.Model(&model.AssetAuthorization{}).Where("user_group_id IN ?", st.groupIDs).Order("id").Pluck("id", &out.RuleIDs).Error; err != nil {
			return GrantSummary{}, fmt.Errorf("查詢群組授權規則失敗: %w", err)
		}
	}
	return out, nil
}

// roleAssignments 把角色編號轉成全域指派（含自訂角色權限集合）。角色不存在即拒絕。
func roleAssignments(tx *gorm.DB, roleIDs []uint, via string, groupID uint) ([]Assignment, error) {
	return roleAssignmentsIn(tx, roleIDs, via, groupID, nil)
}

// roleAssignmentsIn 同 roleAssignments，另依 ranges 把指定角色帶成節點範圍（節點以未刪除過濾）；
// 沒有列在 ranges 的角色為全域。
func roleAssignmentsIn(tx *gorm.DB, roleIDs []uint, via string, groupID uint, ranges map[uint]PreviewRoleRange) ([]Assignment, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	var rows []assignmentRow
	if err := tx.Raw(`SELECT id AS role_id, name AS role_name, builtin_key AS builtin_key, definition_version AS def_version
 FROM roles WHERE id IN ? AND deleted_at IS NULL ORDER BY id`, roleIDs).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取角色失敗: %w", err)
	}
	want := map[uint]bool{}
	for _, id := range roleIDs {
		want[id] = true
	}
	if len(rows) != len(want) {
		return nil, fmt.Errorf("%w: 角色不存在", ErrPreviewInvalid)
	}
	custom, err := customPermissionsOf(tx, ProductCatalogue(), rows)
	if err != nil {
		return nil, err
	}
	out := make([]Assignment, 0, len(rows))
	for _, r := range rows {
		a := Assignment{RoleID: r.RoleID, RoleName: r.RoleName, Via: via, GroupID: groupID, Scope: model.ScopeKindGlobal}
		if r.BuiltinKey != nil {
			a.BuiltinKey = *r.BuiltinKey
		} else if r.DefVersion >= 1 {
			a.Custom, a.Permissions = true, custom[r.RoleID]
		}
		if rg, ok := ranges[r.RoleID]; ok && !rg.Global {
			live, err := filterLiveNodes(tx, rg.NodeIDs)
			if err != nil {
				return nil, err
			}
			a.Scope, a.LiveNodeIDs = model.ScopeKindNodes, live
		}
		out = append(out, a)
	}
	return out, nil
}

func requireGroup(tx *gorm.DB, groupID uint) error {
	var n int64
	if err := tx.Model(&model.UserGroup{}).Where("id = ?", groupID).Count(&n).Error; err != nil {
		return fmt.Errorf("讀取群組失敗: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: 群組不存在", ErrPreviewInvalid)
	}
	return nil
}

func groupMemberIDs(tx *gorm.DB, groupID uint) ([]uint, error) {
	var ids []uint
	if err := tx.Model(&model.UserGroupMember{}).Where("user_group_id = ?", groupID).Pluck("user_id", &ids).Error; err != nil {
		return nil, fmt.Errorf("讀取群組成員失敗: %w", err)
	}
	return ids, nil
}

func userGroupIDs(tx *gorm.DB, userID uint) ([]uint, error) {
	var ids []uint
	if err := tx.Raw(`SELECT m.user_group_id FROM user_group_members m
 JOIN user_groups g ON g.id = m.user_group_id AND g.deleted_at IS NULL WHERE m.user_id = ?`, userID).Scan(&ids).Error; err != nil {
		return nil, fmt.Errorf("讀取所屬群組失敗: %w", err)
	}
	return ids, nil
}

// userKinds 未刪除使用者的主體種類。
func userKinds(tx *gorm.DB, ids []uint) (map[uint]string, error) {
	out := map[uint]string{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct {
		ID   uint
		Kind string
	}
	if err := tx.Model(&model.User{}).Select("id, kind").Where("id IN ?", ids).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取使用者種類失敗: %w", err)
	}
	for _, r := range rows {
		out[r.ID] = r.Kind
	}
	return out, nil
}

// manualDirectAfter 直接指派寫入後的指派集：只替換手動成分，語義與正式寫入相同。
// 映射賦予的成分不受影響（只由映射賦予的列保留，請求中列出也不轉成手動）；
// 手動與並存的列在請求集合內保留，不在集合內則手動列移除、並存列降為映射（範圍改回全域、節點清空）。
// 請求集合內尚無指派列的角色以手動新增。
func manualDirectAfter(in []Assignment, want []Assignment, over map[uint]PreviewRoleRange) []Assignment {
	wanted := make(map[uint]bool, len(want))
	wantedBy := make(map[uint]Assignment, len(want))
	for _, w := range want {
		wanted[w.RoleID] = true
		wantedBy[w.RoleID] = w
	}
	out := make([]Assignment, 0, len(in)+len(want))
	held := map[uint]bool{}
	for _, a := range in {
		if a.Via != ViaDirect {
			out = append(out, a)
			continue
		}
		held[a.RoleID] = true
		switch a.RoleSource {
		case model.RoleSourceMapped:
			out = append(out, a)
		case model.RoleSourceBoth:
			if !wanted[a.RoleID] {
				// 降為僅映射時，管理者那份的節點範圍隨之失效：與正式寫入相同，改回全域並清節點
				a.RoleSource = model.RoleSourceMapped
				a.Scope, a.LiveNodeIDs = model.ScopeKindGlobal, nil
			} else {
				a = withRequestedRange(a, wantedBy[a.RoleID], over)
			}
			out = append(out, a)
		default:
			if wanted[a.RoleID] {
				out = append(out, withRequestedRange(a, wantedBy[a.RoleID], over))
			}
		}
	}
	for _, w := range want {
		if !held[w.RoleID] {
			w.RoleSource = model.RoleSourceManual
			out = append(out, w)
		}
	}
	return out
}

// withRequestedRange 請求的 role_nodes 帶了這個角色時，已持有的指派改成請求的範圍；沒帶則保留現有範圍。
func withRequestedRange(held, wanted Assignment, over map[uint]PreviewRoleRange) Assignment {
	if _, ok := over[held.RoleID]; ok {
		held.Scope, held.LiveNodeIDs = wanted.Scope, wanted.LiveNodeIDs
	}
	return held
}

func dropAssignments(in []Assignment, drop func(Assignment) bool) []Assignment {
	out := make([]Assignment, 0, len(in))
	for _, a := range in {
		if !drop(a) {
			out = append(out, a)
		}
	}
	return out
}

func withoutID(in []uint, id uint) []uint {
	out := make([]uint, 0, len(in))
	for _, v := range in {
		if v != id {
			out = append(out, v)
		}
	}
	return out
}

// setDiff a 中不在 b 的字串（保序）。
func setDiff(a, b []string) []string {
	in := map[string]bool{}
	for _, s := range b {
		in[s] = true
	}
	out := []string{}
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	return out
}

// previewMappingGrantPlan 映射規則生效的假設：命中帳號各自多出一個角色指派，或多一個使用者群組成員身分
// （連同群組的角色指派）。已經持有者不重複計入。
func previewMappingGrantPlan(tx *gorm.DB, req PreviewRequest) ([]uint, stateMutator, error) {
	if (req.RoleID == 0) == (req.GroupID == 0) {
		return nil, nil, fmt.Errorf("%w: 映射目標須為角色或使用者群組二擇一", ErrPreviewInvalid)
	}
	if req.RoleID != 0 {
		add, err := roleAssignments(tx, []uint{req.RoleID}, ViaDirect, 0)
		if err != nil {
			return nil, nil, err
		}
		if len(add) == 0 {
			return nil, nil, fmt.Errorf("%w: 角色不存在", ErrPreviewInvalid)
		}
		rid := req.RoleID
		return req.SubjectIDs, func(_ *gorm.DB, _ uint, b subjectState) (subjectState, error) {
			for _, a := range b.assignments {
				if a.RoleID == rid {
					return b, nil
				}
			}
			return subjectState{assignments: append(append([]Assignment{}, b.assignments...), add...), groupIDs: b.groupIDs}, nil
		}, nil
	}
	if err := requireGroup(tx, req.GroupID); err != nil {
		return nil, nil, err
	}
	groupRoleIDs, err := UserGroupRoleIDs(tx, req.GroupID)
	if err != nil {
		return nil, nil, err
	}
	groupAssignments, err := currentGroupAssignments(tx, groupRoleIDs, req.GroupID)
	if err != nil {
		return nil, nil, err
	}
	gid := req.GroupID
	return req.SubjectIDs, func(_ *gorm.DB, _ uint, b subjectState) (subjectState, error) {
		for _, g := range b.groupIDs {
			if g == gid {
				return b, nil
			}
		}
		return subjectState{
			assignments: append(append([]Assignment{}, b.assignments...), groupAssignments...),
			groupIDs:    append(append([]uint{}, b.groupIDs...), gid),
		}, nil
	}, nil
}

func dedupeIDs(in []uint) []uint {
	seen := make(map[uint]bool, len(in))
	out := make([]uint, 0, len(in))
	for _, id := range in {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
