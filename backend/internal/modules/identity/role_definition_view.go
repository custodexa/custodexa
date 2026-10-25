package identity

import (
	"context"

	"github.com/custodexa/backend/internal/modules/authz"
)

// 角色定義的唯讀對外形狀。
//
// 列表與單筆的 summary 都由 authz.SummarizeRole 對真實權限集合產生，前端不依角色名稱或權限鍵自行重建。

// RoleSummaryView 結構化的白話摘要（可翻譯 token，不含自由文字）；陣列恆為陣列，不回 null。
type RoleSummaryView struct {
	Manage              []string `json:"manage"`
	Read                []string `json:"read"`
	Available           []string `json:"available"`
	Partial             []string `json:"partial"`
	Hidden              []string `json:"hidden"`
	PermissionCount     int      `json:"permission_count"`
	CatalogCount        int      `json:"catalog_count"`
	ScopeGlobalOnly     bool     `json:"scope_global_only"`
	ConnectionSeparate  bool     `json:"connection_separate"`
	AssignmentTrustHint bool     `json:"assignment_trust_hint"`
	Unattributed        []string `json:"unattributed"`
	// ScopeNodeSelectable／ScopeMixedGlobalOnly 管理範圍的兩個 token；皆假時沿用 ScopeGlobalOnly。
	ScopeNodeSelectable  bool `json:"scope_node_selectable"`
	ScopeMixedGlobalOnly bool `json:"scope_mixed_global_only"`
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// NewRoleSummaryView 由權限鍵集合產生摘要（草稿與無內建識別的角色）。
func NewRoleSummaryView(keys []string) RoleSummaryView { return NewRoleSummaryViewFor("", keys) }

// NewRoleSummaryViewFor 由內建識別與權限鍵集合產生摘要；範圍 token 依 authz.ScopeSummaryTokens。
func NewRoleSummaryViewFor(builtinKey string, keys []string) RoleSummaryView {
	ps := make([]authz.Permission, len(keys))
	for i, k := range keys {
		ps[i] = authz.Permission(k)
	}
	s := authz.SummarizeRole(ps)
	nodeSel, mixed := authz.ScopeSummaryTokens(builtinKey, ps)
	un := make([]string, len(s.Unattributed))
	for i, k := range s.Unattributed {
		un[i] = string(k)
	}
	return RoleSummaryView{
		Manage: nonNil(s.Manage), Read: nonNil(s.Read), Available: nonNil(s.Available), Partial: nonNil(s.Partial), Hidden: nonNil(s.Hidden),
		PermissionCount: s.PermissionCount, CatalogCount: s.CatalogCount, ScopeGlobalOnly: s.ScopeGlobalOnly && !nodeSel && !mixed,
		ConnectionSeparate: s.ConnectionSeparate, AssignmentTrustHint: s.AssignmentTrustHint, Unattributed: un,
		ScopeNodeSelectable: nodeSel, ScopeMixedGlobalOnly: mixed,
	}
}

// RoleDefinitionRow 列表的一列：角色本身加上唯讀判定（欄位攤平在同一層）。
type RoleDefinitionRow struct {
	ID                uint            `json:"id"`
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	BuiltinKey        *string         `json:"builtin_key"`
	Locked            bool            `json:"locked"`
	DefinitionVersion int64           `json:"definition_version"`
	TemplateRoleID    *uint           `json:"template_role_id"`
	Summary           RoleSummaryView `json:"summary"`
	RoleProjection
}

// RoleDefinitionList 角色列表回應。
type RoleDefinitionList struct {
	Data      []RoleDefinitionRow `json:"data"`
	Total     int                 `json:"total"`
	CanDefine bool                `json:"can_define"`
}

// RoleDefinitionDetail 單筆回應：權限鍵、版本、範本來源、摘要與缺依賴。
type RoleDefinitionDetail struct {
	ID                  uint                      `json:"id"`
	Name                string                    `json:"name"`
	Description         string                    `json:"description"`
	BuiltinKey          *string                   `json:"builtin_key"`
	Locked              bool                      `json:"locked"`
	DefinitionVersion   int64                     `json:"definition_version"`
	TemplateRoleID      *uint                     `json:"template_role_id"`
	Permissions         []string                  `json:"permissions"`
	Summary             RoleSummaryView           `json:"summary"`
	MissingDependencies []authz.MissingDependency `json:"missing_dependencies"`
	BlockedScreens      []authz.BlockedScreen     `json:"blocked_screens"`
	// Scopable／NodeRangeNoEffect 與列表同源（角色的內建識別加集合）；NodeScopedBindingCount 為
	// 目前以節點範圍持有此角色的指派筆數（直接與群組合計）。
	Scopable               bool  `json:"scopable"`
	NodeRangeNoEffect      bool  `json:"node_range_no_effect"`
	NodeScopedBindingCount int64 `json:"node_scoped_binding_count"`
}

// RoleDraftSummary 草稿權限集合的摘要與缺依賴（不寫入）。
type RoleDraftSummary struct {
	Summary             RoleSummaryView           `json:"summary"`
	MissingDependencies []authz.MissingDependency `json:"missing_dependencies"`
	BlockedScreens      []authz.BlockedScreen     `json:"blocked_screens"`
	// 草稿以純集合判定（不套用內建識別）。
	Scopable          bool `json:"scopable"`
	NodeRangeNoEffect bool `json:"node_range_no_effect"`
}

// scopeFlags 三態判定轉兩個布林：rejected→假／假、effective→真／假、no_effect→真／真。
func scopeFlags(class authz.NodeScopability) (scopable, noEffect bool) {
	return class != authz.NodeScopabilityRejected, class == authz.NodeScopabilityNoEffect
}

// RoleDefinitionReader 角色定義的唯讀服務：真實定義（RoleDefinitionService）加唯讀投影。
type RoleDefinitionReader struct {
	defs *RoleDefinitionService
	proj *RoleProjector
}

// NewRoleDefinitionReader 建立唯讀服務。
func NewRoleDefinitionReader(defs *RoleDefinitionService, proj *RoleProjector) *RoleDefinitionReader {
	return &RoleDefinitionReader{defs: defs, proj: proj}
}

func builtinKeyPtr(d *RoleDefinition) *string {
	if d.BuiltinKey == "" {
		return nil
	}
	k := d.BuiltinKey
	return &k
}

func nonNilDeps(d []authz.MissingDependency) []authz.MissingDependency {
	if d == nil {
		return []authz.MissingDependency{}
	}
	return d
}

func nonNilScreens(b []authz.BlockedScreen) []authz.BlockedScreen {
	if b == nil {
		return []authz.BlockedScreen{}
	}
	return b
}

// List 全部角色（含鎖定範本與自訂角色）及對操作者的判定。
func (r *RoleDefinitionReader) List(ctx context.Context, operatorID uint) (*RoleDefinitionList, error) {
	defs, err := r.defs.ListDefinitions(ctx)
	if err != nil {
		return nil, err
	}
	set, err := r.proj.ProjectRoles(operatorID)
	if err != nil {
		return nil, err
	}
	out := &RoleDefinitionList{Data: make([]RoleDefinitionRow, 0, len(defs)), CanDefine: set.CanDefine}
	for i := range defs {
		d := &defs[i]
		pr, ok := set.ByRole[d.ID]
		if !ok {
			continue // 兩次讀取之間被刪除的角色
		}
		out.Data = append(out.Data, RoleDefinitionRow{
			ID: d.ID, Name: d.Name, Description: d.Description, BuiltinKey: builtinKeyPtr(d), Locked: d.Locked,
			DefinitionVersion: d.DefinitionVersion, TemplateRoleID: d.TemplateRoleID,
			Summary: NewRoleSummaryViewFor(d.BuiltinKey, d.Permissions), RoleProjection: pr,
		})
	}
	out.Total = len(out.Data)
	return out, nil
}

// Get 單一角色；查無回 ErrRoleDefinitionNotFound。
func (r *RoleDefinitionReader) Get(ctx context.Context, roleID uint) (*RoleDefinitionDetail, error) {
	d, err := r.defs.GetDefinition(ctx, roleID)
	if err != nil {
		return nil, err
	}
	return NewRoleDefinitionDetail(d), nil
}

// NewRoleDefinitionDetail 由服務層定義產生單筆回應形狀（單筆讀取與寫入成功回應共用）。
func NewRoleDefinitionDetail(d *RoleDefinition) *RoleDefinitionDetail {
	return &RoleDefinitionDetail{
		ID: d.ID, Name: d.Name, Description: d.Description, BuiltinKey: builtinKeyPtr(d), Locked: d.Locked,
		DefinitionVersion: d.DefinitionVersion, TemplateRoleID: d.TemplateRoleID,
		Permissions: nonNil(d.Permissions), Summary: NewRoleSummaryViewFor(d.BuiltinKey, d.Permissions),
		MissingDependencies: nonNilDeps(d.MissingDependencies), BlockedScreens: nonNilScreens(d.BlockedScreens),
		Scopable: d.Scopable, NodeRangeNoEffect: d.NodeRangeNoEffect, NodeScopedBindingCount: d.NodeScopedBindingCount,
	}
}

// DraftSummary 以草稿權限集合產生摘要與缺依賴。不合法的鍵整筆拒絕（*authz.ErrRolePermissionInvalid）。
func (r *RoleDefinitionReader) DraftSummary(keys []string) (*RoleDraftSummary, error) {
	perms, err := authz.NormalizeRolePermissions(keys)
	if err != nil {
		return nil, err
	}
	norm := permStrings(perms)
	class, _ := authz.ClassifyNodeScopability("", perms)
	scopable, noEffect := scopeFlags(class)
	return &RoleDraftSummary{
		Scopable: scopable, NodeRangeNoEffect: noEffect,
		Summary:             NewRoleSummaryView(norm),
		MissingDependencies: nonNilDeps(authz.MissingDependencies(perms)),
		BlockedScreens:      nonNilScreens(authz.BlockedScreens(perms)),
	}, nil
}
