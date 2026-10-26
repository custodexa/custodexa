package authz

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 單一使用者的權限一覽（解釋服務）。
//
// 管理面重用被檢視者的已解析主體（Resolver 同一路徑）與其逐權限點來源，不另算一套來源；
// 連線面重用有效權限主體視角的範圍化投影與連線授權判定，不另寫 SQL。
// 整個服務唯讀：不寫任何表、不推進權限版本、不產生事件或審計列。
// 服務放在 authz 內；映射規則與政策段位由組裝端注入的唯讀介面提供。

// OverviewMappingReader 映射規則的唯讀查詢（身分模組實作）。
type OverviewMappingReader interface {
	// RoleMappingRules 被檢視者各角色（鍵為角色編號）目前由哪些映射規則支持。
	RoleMappingRules(db *gorm.DB, userID uint) (map[uint][]OverviewRuleRef, error)
	// GroupMappingRules 被檢視者各使用者群組（鍵為群組編號）的成員資格目前由哪些映射規則支持。
	GroupMappingRules(db *gorm.DB, userID uint) (map[uint][]OverviewRuleRef, error)
}

// OverviewPolicyResolver 連線政策段位的批次解析（政策模組實作，全域預設鍵整批只讀一次）。
type OverviewPolicyResolver interface {
	ResolveSegments(assetPolicies []*string) []string
}

// assetManageWritePerms 「能管理這台主機」的口徑：資產與資產帳號的非檢視權限點中，
// 對單一資產目標判定的那幾個。只持有憑證或節點管理者不因此被標示為也能管理。
func assetManageWritePerms() []Permission {
	return []Permission{PermAssetUpdate, PermAssetDelete, PermAssetTest, PermAccountRotate}
}

// PermissionOverviewService 權限一覽服務。零值不可用；以 NewPermissionOverviewService 建立。
type PermissionOverviewService struct {
	db       *gorm.DB
	e        *ScopeEvaluator
	eff      *EffectiveAccessResolver
	acl      *AssetAuthorizationService
	mappings OverviewMappingReader
	policies OverviewPolicyResolver
	now      func() time.Time
}

// NewPermissionOverviewService 以讀取連線、範圍判定器（目錄與拓撲）、已注入判定器的有效權限解析器、
// 連線授權服務、映射唯讀查詢與政策段位解析建立。任一為 nil 時各讀取方法回 ErrPermissionOverviewUnwired。
func NewPermissionOverviewService(db *gorm.DB, e *ScopeEvaluator, eff *EffectiveAccessResolver,
	acl *AssetAuthorizationService, mappings OverviewMappingReader, policies OverviewPolicyResolver) *PermissionOverviewService {
	return &PermissionOverviewService{db: db, e: e, eff: eff, acl: acl, mappings: mappings, policies: policies, now: time.Now}
}

func (s *PermissionOverviewService) ready() bool {
	return s != nil && s.db != nil && s.e != nil && s.eff != nil && s.acl != nil && s.mappings != nil && s.policies != nil
}

// subjectOf 載入被檢視者並解析主體；使用者不存在或已刪除回 ErrEffectiveSubjectNotFound。
func (s *PermissionOverviewService) subjectOf(userID uint) (*model.User, *Principal, error) {
	var u model.User
	if err := s.db.First(&u, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrEffectiveSubjectNotFound
		}
		return nil, nil, err
	}
	p, err := ResolveUserOn(s.db, u.ID, TokenFacts{SubjectKind: u.Kind})
	if err != nil {
		return nil, nil, err
	}
	return &u, p, nil
}

// Overview 回傳被檢視者的權限一覽。檢視者取自 ctx 的主體（在讀取連線上重解）。
func (s *PermissionOverviewService) Overview(ctx context.Context, subjectUserID uint) (*PermissionOverview, error) {
	if !s.ready() {
		return nil, ErrPermissionOverviewUnwired
	}
	if PrincipalFromContext(ctx) == nil {
		return nil, ErrPermissionOverviewNoViewer
	}
	u, p, err := s.subjectOf(subjectUserID)
	if err != nil {
		return nil, err
	}
	mgmt, err := s.management(u, p)
	if err != nil {
		return nil, err
	}
	conn, err := s.connection(ctx, u, p)
	if err != nil {
		return nil, err
	}
	return &PermissionOverview{UserID: u.ID, Username: u.Username, Management: *mgmt, Connection: *conn}, nil
}

// ---- 管理面 ----

// srcSpec 一個來源在指派清單中的位置與種類（direct 與 mapped 可共用同一筆指派）。
type srcSpec struct {
	ref    string
	kind   string
	asgIdx int // 合成來源為 implicitGlobalSource
}

func (s *PermissionOverviewService) management(u *model.User, p *Principal) (*OverviewManagement, error) {
	out := &OverviewManagement{
		Identity: OverviewIdentity{
			SuperAdmin: p.IsSuperAdmin(), Auditor: p.IsAuditor(), Approver: p.IsApprover(),
			Agent:         u.Kind == model.KindAgent,
			CompatDefault: u.Kind != model.KindAgent && len(p.Assignments) == 0,
		},
		Sources: []OverviewSource{}, Bindings: []OverviewBinding{}, Permissions: []OverviewPermission{},
		IneffectiveSources: []OverviewIneffectiveSource{},
	}
	paths, err := asset.NodePathMap(s.db)
	if err != nil {
		return nil, err
	}
	roleRules, err := s.mappings.RoleMappingRules(s.db, u.ID)
	if err != nil {
		return nil, err
	}
	groupRules, err := s.mappings.GroupMappingRules(s.db, u.ID)
	if err != nil {
		return nil, err
	}
	rawDirect, err := SubjectBindingNodes(s.db, model.BindingSubjectUser, u.ID)
	if err != nil {
		return nil, err
	}
	groups, err := s.groupFacts(p, u.ID)
	if err != nil {
		return nil, err
	}

	// 逐權限點來源 → 逐指派的有效權限點
	effective := map[int][]Permission{}
	for perm, idxs := range p.srcs {
		seenIdx := map[int]bool{}
		for _, i := range idxs {
			if !seenIdx[i] {
				seenIdx[i] = true
				effective[i] = append(effective[i], perm)
			}
		}
	}
	sortPerms := func(ps []Permission) {
		sort.Slice(ps, func(a, b int) bool { return ps[a] < ps[b] })
	}

	seq := 0
	nextRef := func() string { seq++; return "src-" + strconv.Itoa(seq) }
	refsOfAsg := map[int][]string{}
	var specs []srcSpec
	isAgent := u.Kind == model.KindAgent
	for i, a := range p.Assignments {
		if isAgent { // agent 的能力固定，指派列不產生來源
			break
		}
		kinds := []string{OverviewSourceGroup}
		if a.Via == ViaDirect {
			kinds = nil
			if a.RoleSource != model.RoleSourceMapped {
				kinds = append(kinds, OverviewSourceDirect)
			}
			if a.RoleSource == model.RoleSourceMapped || a.RoleSource == model.RoleSourceBoth {
				kinds = append(kinds, OverviewSourceMapped)
			}
		}
		for _, k := range kinds {
			sp := srcSpec{ref: nextRef(), kind: k, asgIdx: i}
			specs = append(specs, sp)
			refsOfAsg[i] = append(refsOfAsg[i], sp.ref)
		}
	}
	implicitRef := ""
	if len(effective[implicitGlobalSource]) > 0 {
		implicitRef = nextRef()
	}

	rawGroup := map[uint]map[uint][]uint{} // 群組編號 → 角色編號 → 原始節點
	rawNodesOf := func(a Assignment) ([]uint, error) {
		if a.Via == ViaDirect {
			return rawDirect[a.RoleID], nil
		}
		m, ok := rawGroup[a.GroupID]
		if !ok {
			var err error
			if m, err = SubjectBindingNodes(s.db, model.BindingSubjectUserGroup, a.GroupID); err != nil {
				return nil, err
			}
			rawGroup[a.GroupID] = m
		}
		return m[a.RoleID], nil
	}
	scopeOf := func(a Assignment) (OverviewScope, error) {
		if a.Scope != model.ScopeKindNodes {
			return OverviewScope{Kind: OverviewScopeGlobal, Nodes: []OverviewNode{}}, nil
		}
		raw, err := rawNodesOf(a)
		if err != nil {
			return OverviewScope{}, err
		}
		sc := OverviewScope{Kind: OverviewScopeNodes, Nodes: nodesOf(a.LiveNodeIDs, paths)}
		if inactive := len(raw) - len(a.LiveNodeIDs); inactive > 0 {
			sc.InactiveNodeCount = inactive
		}
		return sc, nil
	}

	for _, sp := range specs {
		a := p.Assignments[sp.asgIdx]
		scope, err := scopeOf(a)
		if err != nil {
			return nil, err
		}
		role := &OverviewRole{ID: a.RoleID, Name: a.RoleName}
		if a.BuiltinKey != "" {
			k := a.BuiltinKey
			role.BuiltinKey = &k
		}
		src := OverviewSource{SourceRef: sp.ref, Kind: sp.kind, Role: role, Scope: scope,
			EffectivePermissions: []string{}, Ineffective: []OverviewIneffective{}}
		eff := append([]Permission(nil), effective[sp.asgIdx]...)
		sortPerms(eff)
		for _, k := range eff {
			src.EffectivePermissions = append(src.EffectivePermissions, string(k))
		}
		switch sp.kind {
		case OverviewSourceMapped:
			rules := append([]OverviewRuleRef{}, roleRules[a.RoleID]...)
			src.MappingRules = &rules
		case OverviewSourceGroup:
			gf := groups[a.GroupID]
			rules := append([]OverviewRuleRef{}, groupRules[a.GroupID]...)
			src.Group = &OverviewGroupInfo{ID: a.GroupID, Name: gf.name,
				MemberSource: memberSourceOf(gf.manual, len(rules) > 0), MappingRules: rules}
		}
		if a.Scope == model.ScopeKindNodes && len(a.LiveNodeIDs) == 0 {
			out.IneffectiveSources = append(out.IneffectiveSources, OverviewIneffectiveSource{OverviewSource: src, Reason: OverviewReasonNodesAllDeleted})
			continue
		}
		src.Ineffective = s.ineffectiveOf(p, a, effective[sp.asgIdx])
		out.Sources = append(out.Sources, src)
	}
	if implicitRef != "" {
		kind := OverviewSourceCompatDefault
		if isAgent {
			kind = OverviewSourceAgentFixed
		}
		src := OverviewSource{SourceRef: implicitRef, Kind: kind, Role: nil,
			Scope:                OverviewScope{Kind: OverviewScopeGlobal, Nodes: []OverviewNode{}},
			EffectivePermissions: []string{}, Ineffective: []OverviewIneffective{}}
		eff := append([]Permission(nil), effective[implicitGlobalSource]...)
		sortPerms(eff)
		for _, k := range eff {
			src.EffectivePermissions = append(src.EffectivePermissions, string(k))
		}
		out.Sources = append(out.Sources, src)
	}

	// 有效權限點：範圍與來源
	for _, perm := range p.Capabilities() {
		global, nodes := p.bindingOf(perm)
		sc := OverviewScope{Kind: OverviewScopeGlobal, Nodes: []OverviewNode{}}
		if !global {
			sc = OverviewScope{Kind: OverviewScopeNodes, Nodes: nodesOf(nodes, paths)}
		}
		var refs []string
		for _, i := range p.srcs[perm] {
			if i == implicitGlobalSource {
				refs = append(refs, implicitRef)
				continue
			}
			refs = append(refs, refsOfAsg[i]...)
		}
		out.Permissions = append(out.Permissions, OverviewPermission{Permission: string(perm), Scopes: sc, SourceRefs: uniqueStrings(refs)})
	}

	bindings, err := s.bindings(p, out.Sources, specs)
	if err != nil {
		return nil, err
	}
	out.Bindings = bindings
	return out, nil
}

// bindings 依角色合併來源成卡片；合成來源各自一張沒有角色的卡。
func (s *PermissionOverviewService) bindings(p *Principal, sources []OverviewSource, specs []srcSpec) ([]OverviewBinding, error) {
	asgOf := map[string]int{}
	for _, sp := range specs {
		asgOf[sp.ref] = sp.asgIdx
	}
	type card struct {
		role  *OverviewRole
		refs  []string
		keys  map[string]bool
		asg   map[int]bool
		order []int
		glob  bool
	}
	byRole := map[uint]*card{}
	var cards []*card
	for _, src := range sources {
		var c *card
		if src.Role == nil {
			c = &card{keys: map[string]bool{}, asg: map[int]bool{}, glob: true}
			cards = append(cards, c)
		} else if c = byRole[src.Role.ID]; c == nil {
			c = &card{role: src.Role, keys: map[string]bool{}, asg: map[int]bool{}}
			byRole[src.Role.ID] = c
			cards = append(cards, c)
		}
		c.refs = append(c.refs, src.SourceRef)
		for _, k := range src.EffectivePermissions {
			c.keys[k] = true
		}
		if src.Scope.Kind == OverviewScopeGlobal {
			c.glob = true
		}
		if i, ok := asgOf[src.SourceRef]; ok && !c.asg[i] {
			c.asg[i] = true
			c.order = append(c.order, i)
		}
	}
	out := make([]OverviewBinding, 0, len(cards))
	for _, c := range cards {
		keys := make([]Permission, 0, len(c.keys))
		for k := range c.keys {
			keys = append(keys, Permission(k))
		}
		sort.Slice(keys, func(a, b int) bool { return keys[a] < keys[b] })
		sum := SummarizeRole(keys)
		b := OverviewBinding{Role: c.role, SourceRefs: c.refs, Entries: OverviewEntries{
			Manage: nonNil(sum.Manage), Partial: nonNil(sum.Partial), Read: nonNil(sum.Read), Available: nonNil(sum.Available)}}
		if !c.glob {
			set := AssignmentSet{SubjectKind: p.Facts.SubjectKind}
			for _, i := range c.order {
				a := p.Assignments[i]
				in := AssignmentInput{BindingSubject: model.BindingSubjectUser, RoleID: a.RoleID, Scope: a.Scope, NodeIDs: a.LiveNodeIDs}
				if a.Via == ViaGroup {
					in.BindingSubject, in.GroupID = model.BindingSubjectUserGroup, a.GroupID
				}
				set.Items = append(set.Items, in)
			}
			vis, err := s.e.ManagementVisibleScopeForAssignments(s.db, set)
			if err != nil {
				return nil, err
			}
			n, err := s.e.CountManagementVisible(s.db, vis)
			if err != nil {
				return nil, err
			}
			b.ManageableAssetCount = &n
		}
		out = append(out, b)
	}
	return out, nil
}

// ineffectiveOf 一筆（仍有存活節點或全域的）指派中，角色內容有、卻不生效的權限點與原因。
func (s *PermissionOverviewService) ineffectiveOf(p *Principal, a Assignment, effective []Permission) []OverviewIneffective {
	have := map[Permission]bool{}
	for _, k := range effective {
		have[k] = true
	}
	out := []OverviewIneffective{}
	seen := map[Permission]bool{}
	for _, perm := range assignmentRolePermissions(a) {
		if have[perm] || seen[perm] {
			continue
		}
		seen[perm] = true
		def, ok := p.cat.Lookup(perm)
		if !ok || (a.Custom && !IsAssignable(perm)) {
			continue
		}
		reason := ""
		switch {
		case a.Scope != model.ScopeKindNodes:
			continue
		case def.Scope != ScopeEnforced:
			reason = OverviewReasonNotNodeScopable
		case !a.Custom && !IsLockedManagementTemplate(a.BuiltinKey):
			reason = OverviewReasonBuiltinRequiresGlobal
		default:
			continue
		}
		out = append(out, OverviewIneffective{Permission: string(perm), Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Permission < out[j].Permission })
	return out
}

type groupFact struct {
	name   string
	manual bool
}

// groupFacts 被檢視者所屬（有角色指派的）使用者群組的名稱與手動成員旗標。
func (s *PermissionOverviewService) groupFacts(p *Principal, userID uint) (map[uint]groupFact, error) {
	ids := map[uint]bool{}
	for _, a := range p.Assignments {
		if a.Via == ViaGroup {
			ids[a.GroupID] = true
		}
	}
	out := map[uint]groupFact{}
	if len(ids) == 0 {
		return out, nil
	}
	list := make([]uint, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	var rows []struct {
		ID     uint
		Name   string
		Manual bool
	}
	if err := s.db.Raw(`SELECT user_groups.id AS id, user_groups.name AS name, user_group_members.manual AS manual
 FROM user_groups JOIN user_group_members ON user_group_members.user_group_id = user_groups.id AND user_group_members.user_id = ?
 WHERE user_groups.id IN ? AND user_groups.deleted_at IS NULL`, userID, list).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = groupFact{name: r.Name, manual: r.Manual}
	}
	return out, nil
}

// memberSourceOf 成員來源：手動旗標與是否有映射支持。
func memberSourceOf(manual, mapped bool) string {
	switch {
	case manual && mapped:
		return "both"
	case manual:
		return "manual"
	}
	return "mapped"
}

func nodesOf(ids []uint, paths map[uint]string) []OverviewNode {
	out := make([]OverviewNode, 0, len(ids))
	for _, id := range ids {
		out = append(out, OverviewNode{ID: id, Path: paths[id]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
