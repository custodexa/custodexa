package authz

import (
	"context"
	"sort"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 查一台資產：被檢視者能否管理（附放行的角色與範圍）與能否連線（附命中的授權）。
//
//   - 資產界線：資產必須在檢視者本人的資產可視集合內（與資產列表同一判定：檢視捷徑主體為全部；
//     其他主體為連線可視，範圍化檢視者另加管理可視）。看不到與不存在回同一個錯誤。
//   - 連線界線：另需檢視者持 authorization:manage 且資產在其範圍內；否則連線標示不可用，不含任何授權項。

// ProbeAsset 回傳被檢視者對一台資產的管理與連線判定。
func (s *PermissionOverviewService) ProbeAsset(ctx context.Context, subjectUserID, assetID uint) (*OverviewAssetProbe, error) {
	if !s.ready() {
		return nil, ErrPermissionOverviewUnwired
	}
	viewerCtx := PrincipalFromContext(ctx)
	if viewerCtx == nil {
		return nil, ErrPermissionOverviewNoViewer
	}
	u, subject, err := s.subjectOf(subjectUserID)
	if err != nil {
		return nil, err
	}
	viewer, err := s.e.resolveInTx(s.db, viewerCtx)
	if err != nil {
		return nil, err
	}
	visible, err := s.assetVisibleTo(viewer, assetID)
	if err != nil {
		return nil, err
	}
	if !visible {
		return nil, ErrEffectiveAssetNotFound
	}
	out := &OverviewAssetProbe{UserID: u.ID, AssetID: assetID}
	if out.Manage, err = s.probeManage(subject, assetID); err != nil {
		return nil, err
	}
	if out.Connect, err = s.probeConnect(ctx, u, subject, viewer, assetID); err != nil {
		return nil, err
	}
	return out, nil
}

// assetVisibleTo 資產是否在檢視者的資產可視集合內（資產不存在或已刪除為否）。
func (s *PermissionOverviewService) assetVisibleTo(viewer *Principal, assetID uint) (bool, error) {
	var n int64
	if err := s.db.Model(&model.Asset{}).Where("id = ?", assetID).Count(&n).Error; err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if viewer.ViewShortcut() {
		return true, nil
	}
	ok, err := s.acl.CheckPermissionForPrincipal(viewer, viewer.UserID, assetID, model.PermissionView)
	if err != nil || ok {
		return ok, err
	}
	if !isAssetScopedViewer(viewer) {
		return false, nil
	}
	vis := managementVisibleOn(viewer)
	ids, err := s.e.managementVisibleIDs(s.db, vis)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		if id == assetID {
			return true, nil
		}
	}
	return false, nil
}

func (s *PermissionOverviewService) probeManage(subject *Principal, assetID uint) (OverviewProbeManage, error) {
	out := OverviewProbeManage{Grants: []OverviewManageGrant{}}
	for _, perm := range assetManageWritePerms() {
		res, _, err := s.e.decideOn(s.db, subject, perm, AssetTarget(assetID))
		if err != nil {
			return out, err
		}
		if res.Outcome == ScopeAllow {
			out.Allowed = true
			break
		}
	}
	if !out.Allowed {
		return out, nil
	}
	cover, exists, err := s.e.topo.AssetCoverNodes(s.db, assetID)
	if err != nil {
		return out, err
	}
	if !exists {
		cover = nil
	}
	coverSet := map[uint]bool{}
	for _, n := range cover {
		coverSet[n] = true
	}
	paths, err := asset.NodePathMap(s.db)
	if err != nil {
		return out, err
	}
	seen := map[int]bool{}
	for _, perm := range assetManageWritePerms() {
		for _, i := range subject.srcs[perm] {
			if i != implicitGlobalSource {
				seen[i] = true
			}
		}
	}
	order := make([]int, 0, len(seen))
	for i := range seen {
		order = append(order, i)
	}
	sort.Ints(order)
	for _, i := range order {
		a := subject.Assignments[i]
		role := &OverviewRole{ID: a.RoleID, Name: a.RoleName}
		if a.BuiltinKey != "" {
			k := a.BuiltinKey
			role.BuiltinKey = &k
		}
		g := OverviewManageGrant{Role: role}
		if globalEffective(a) {
			g.Scope = OverviewScope{Kind: OverviewScopeGlobal, Nodes: []OverviewNode{}}
		} else {
			var hit []uint
			for _, n := range a.LiveNodeIDs {
				if coverSet[n] {
					hit = append(hit, n)
				}
			}
			if len(hit) == 0 {
				continue
			}
			g.Scope = OverviewScope{Kind: OverviewScopeNodes, Nodes: nodesOf(hit, paths)}
		}
		out.Grants = append(out.Grants, g)
	}
	return out, nil
}

func (s *PermissionOverviewService) probeConnect(ctx context.Context, u *model.User, subject, viewer *Principal, assetID uint) (OverviewProbeConnect, error) {
	if !viewer.Has(PermAuthorizationManage) {
		return OverviewProbeConnect{Available: false}, nil
	}
	d, _, err := s.e.decideOn(s.db, viewer, PermAuthorizationManage, AuthorizationAssetObjectTarget(assetID))
	if err != nil {
		return OverviewProbeConnect{}, err
	}
	if d.Outcome != ScopeAllow {
		return OverviewProbeConnect{Available: false}, nil
	}
	allowed, err := s.acl.CheckPermissionForPrincipal(subject, u.ID, assetID, model.PermissionConnect)
	if err != nil {
		return OverviewProbeConnect{}, err
	}
	out := OverviewProbeConnect{Available: true, Allowed: &allowed, RoleOverride: roleOverrideOfPrincipal(subject)}
	projected, err := s.eff.ResolveEffectiveAssetsFor(ctx, u.ID, s.now())
	if err != nil {
		return OverviewProbeConnect{}, err
	}
	var mine []EffectiveAssetEntry
	for _, a := range projected.Assets {
		if a.AssetID == assetID {
			mine = append(mine, a)
		}
	}
	items, err := s.itemsOf(subject, mine)
	if err != nil {
		return OverviewProbeConnect{}, err
	}
	out.Items = &items
	return out, nil
}
