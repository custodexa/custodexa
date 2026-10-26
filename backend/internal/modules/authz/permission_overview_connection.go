package authz

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 權限一覽的連線面。
//
//   - 可視界線：檢視者 authorization:manage 的範圍集合內的資產（與有效權限主體視角同一判定）。
//   - 項目：依授權記錄分項；檢視者看不到的授權記錄只併成不具名項（等級與台數）。
//   - 範圍外資產台數：被檢視者可連線、但不在檢視者範圍內的資產數。可連線集合與執行期的
//     連線授權判定同義（內建超管短路者另以摘要呈現、不帶此欄），經揭露登錄產出。

// connection 組連線面。
func (s *PermissionOverviewService) connection(ctx context.Context, u *model.User, subject *Principal) (*OverviewConnection, error) {
	viewer, set, err := s.eff.viewer(ctx)
	if err != nil {
		return nil, err
	}
	if !viewer.Has(PermAuthorizationManage) {
		return &OverviewConnection{Available: false}, nil
	}
	out := &OverviewConnection{Available: true, RoleOverride: roleOverrideOfPrincipal(subject)}
	now := s.now()
	projected, err := s.eff.ResolveEffectiveAssetsFor(ctx, u.ID, now)
	if err != nil {
		return nil, err
	}
	items, err := s.itemsOf(subject, projected.Assets)
	if err != nil {
		return nil, err
	}
	out.Items = &items

	manageOnly := []OverviewManageOnly{}
	out.ManageOnly = &manageOnly
	if subject.IsSuperAdmin() { // 內建超管可連線所有主機：不帶台數，也沒有「能管不能連」
		return out, nil
	}
	connectable, err := s.connectableSet(u.ID, now)
	if err != nil {
		return nil, err
	}
	var v *ownScopeView
	if set.state != ScopeSetUnlimited {
		if v, err = s.eff.newScopeView(set); err != nil {
			return nil, err
		}
		ids := make([]uint, 0, len(connectable))
		for id := range connectable {
			ids = append(ids, id)
		}
		in, err := v.assetsInScope(ids)
		if err != nil {
			return nil, err
		}
		out.AssetCountField = &disclosure.AssetCountField{OutOfScopeAssetCount: disclosure.AssetCountValue{
			Value: disclosure.Count(disclosure.OutOfScopeAssetCount, len(ids)-len(in))}}
	}
	rows, err := s.manageOnlyOf(subject, v, connectable)
	if err != nil {
		return nil, err
	}
	manageOnly = rows
	out.ManageOnly = &manageOnly
	return out, nil
}

// roleOverrideOfPrincipal 由被檢視者已解析的主體判定角色隱含摘要（不看角色名稱、不讀直接角色列）。
func roleOverrideOfPrincipal(p *Principal) string {
	switch {
	case p.IsSuperAdmin():
		return model.RoleAdmin
	case p.IsAuditor():
		return model.RoleAuditor
	}
	return ""
}

// connectableSet 被檢視者可連線的資產（未投影解析中等級為 connect 者，以資產編號去重）。
// 內建超管短路另行處理，不經此集合。
func (s *PermissionOverviewService) connectableSet(userID uint, now time.Time) (map[uint]bool, error) {
	res, err := s.eff.ResolveEffectiveAssets(userID, now)
	if err != nil {
		return nil, err
	}
	out := map[uint]bool{}
	for _, a := range res.Assets {
		if a.Permission == model.PermissionConnect {
			out[a.AssetID] = true
		}
	}
	return out, nil
}

// managedAmong 候選資產中，被檢視者對其持有資產管理寫入權（任一口徑權限點，且範圍判定放行）者。
func (s *PermissionOverviewService) managedAmong(p *Principal, ids []uint) (map[uint]bool, error) {
	out := map[uint]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	for _, perm := range assetManageWritePerms() {
		set := scopeSetOn(p, perm, sourcesAll)
		switch set.state {
		case ScopeSetUnlimited:
			for _, id := range ids {
				out[id] = true
			}
			return out, nil
		case ScopeSetConditional:
			q, err := s.e.ApplyScopeSet(s.db, s.db.Model(&model.Asset{}).Where("assets.id IN ?", ids), set, ScopeQueryAsset)
			if err != nil {
				return nil, err
			}
			var hit []uint
			if err := q.Pluck("assets.id", &hit).Error; err != nil {
				return nil, err
			}
			for _, id := range hit {
				out[id] = true
			}
		}
	}
	return out, nil
}

// itemAcc 一個連線項的累積。
type itemAcc struct {
	item   OverviewConnectionItem
	assets map[uint]bool
	policy map[string]bool
}

// itemsOf 把（已依檢視者範圍投影與遮蔽的）資產溯因依授權記錄分項。
func (s *PermissionOverviewService) itemsOf(subject *Principal, assets []EffectiveAssetEntry) ([]OverviewConnectionItem, error) {
	ids := make([]uint, 0, len(assets))
	for _, a := range assets {
		ids = append(ids, a.AssetID)
	}
	managed, err := s.managedAmong(subject, ids)
	if err != nil {
		return nil, err
	}
	policyOf, err := s.policyOf(ids)
	if err != nil {
		return nil, err
	}
	accounts, err := s.accountScopes(assets)
	if err != nil {
		return nil, err
	}
	acc := map[string]*itemAcc{}
	var order []string
	add := func(key string, build func() OverviewConnectionItem, assetID uint, disclosed bool) {
		a, ok := acc[key]
		if !ok {
			a = &itemAcc{item: build(), assets: map[uint]bool{}, policy: map[string]bool{}}
			acc[key] = a
			order = append(order, key)
		}
		a.assets[assetID] = true
		if disclosed {
			a.policy[policyOf[assetID]] = true
		}
	}
	for _, e := range assets {
		for _, path := range e.Paths {
			path, e := path, e
			switch {
			case path.Kind == PathApproverScope:
				add("approver", func() OverviewConnectionItem {
					return OverviewConnectionItem{Kind: OverviewItemApproverScope, Permission: string(model.PermissionView)}
				}, e.AssetID, false)
			case path.AuthorizationID == nil:
				add("undisclosed:"+string(path.Permission), func() OverviewConnectionItem {
					return OverviewConnectionItem{Kind: OverviewItemUndisclosed, Permission: string(path.Permission)}
				}, e.AssetID, false)
			default:
				id := *path.AuthorizationID
				add("auth:"+strconv.FormatUint(uint64(id), 10), func() OverviewConnectionItem {
					d := &OverviewItemDetail{AuthorizationID: id, Via: OverviewVia{Type: "self"},
						AccountScope: accounts[id], Validity: OverviewValidity{DateStart: path.DateStart, DateExpired: path.DateExpired}}
					switch path.Kind {
					case PathAssetNode, PathUserGroupAssetNode:
						d.Target = OverviewTarget{Type: "node", Name: path.ViaNodePath}
					default:
						d.Target = OverviewTarget{Type: "asset", Name: e.AssetName}
					}
					if path.ViaGroupID != nil {
						d.Via = OverviewVia{Type: "group", GroupName: path.ViaGroupName}
					}
					return OverviewConnectionItem{Kind: OverviewItemAuthorization, Permission: string(path.Permission), OverviewItemDetail: d}
				}, e.AssetID, true)
			}
		}
	}
	out := make([]OverviewConnectionItem, 0, len(order))
	for _, key := range order {
		a := acc[key]
		a.item.VisibleAssetCount = len(a.assets)
		for id := range a.assets {
			if managed[id] {
				a.item.ManagedAssetCount++
			}
		}
		if a.item.OverviewItemDetail != nil {
			a.item.AccessPolicy = mergePolicies(a.policy)
		}
		out = append(out, a.item)
	}
	sort.SliceStable(out, func(i, j int) bool { return itemRank(out[i]) < itemRank(out[j]) })
	return out, nil
}

// itemRank 排序：授權記錄依編號，其次審核範圍，最後不具名項（連線在前）。
func itemRank(it OverviewConnectionItem) int64 {
	switch it.Kind {
	case OverviewItemAuthorization:
		return int64(it.AuthorizationID)
	case OverviewItemApproverScope:
		return 1 << 40
	}
	if it.Permission == string(model.PermissionConnect) {
		return 1<<41 + 0
	}
	return 1<<41 + 1
}

func mergePolicies(set map[string]bool) string {
	if len(set) == 1 {
		for v := range set {
			return v
		}
	}
	return OverviewPolicyMixed
}

// policyOf 資產編號 → 有效連線政策段位。
func (s *PermissionOverviewService) policyOf(ids []uint) (map[uint]string, error) {
	out := map[uint]string{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []model.Asset
	if err := s.db.Select("id", "access_policy").Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, err
	}
	raw := make([]*string, len(rows))
	for i := range rows {
		raw[i] = rows[i].AccessPolicy
	}
	segs := s.policies.ResolveSegments(raw)
	for i := range rows {
		out[rows[i].ID] = segs[i]
	}
	return out, nil
}

// accountScopes 授權記錄編號 → 帳號範圍（全部帳號為 nil）。只查出現在回應中（檢視者可視）的記錄。
func (s *PermissionOverviewService) accountScopes(assets []EffectiveAssetEntry) (map[uint][]string, error) {
	seen := map[uint]bool{}
	var ids []uint
	for _, a := range assets {
		for _, p := range a.Paths {
			if p.AuthorizationID != nil && !seen[*p.AuthorizationID] {
				seen[*p.AuthorizationID] = true
				ids = append(ids, *p.AuthorizationID)
			}
		}
	}
	out := map[uint][]string{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []model.AssetAuthorization
	if err := s.db.Select("id", "accounts").Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		if !r.Accounts.IsAll() {
			out[r.ID] = []string(r.Accounts)
		}
	}
	return out, nil
}

// manageOnlyOf 被檢視者每筆節點範圍管理指派的範圍節點中，能管理卻沒有連線授權的資產台數。
// 檢視者範圍化時，只列檢視者 authorization:manage 範圍內的節點與資產。
func (s *PermissionOverviewService) manageOnlyOf(subject *Principal, v *ownScopeView, connectable map[uint]bool) ([]OverviewManageOnly, error) {
	nodeSet := map[uint]bool{}
	for _, perm := range assetManageWritePerms() {
		_, idxs := subject.sourceAssignments(perm)
		for _, i := range idxs {
			for _, n := range subject.Assignments[i].LiveNodeIDs {
				nodeSet[n] = true
			}
		}
	}
	nodes := make([]uint, 0, len(nodeSet))
	for n := range nodeSet {
		if v == nil || v.selected[n] {
			nodes = append(nodes, n)
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i] < nodes[j] })
	out := []OverviewManageOnly{}
	if len(nodes) == 0 {
		return out, nil
	}
	paths, err := asset.NodePathMap(s.db)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		var ids []uint
		sub := s.e.topo.SubtreeAssetIDs(s.db, []uint{n})
		if err := s.db.Model(&model.Asset{}).Where("assets.id IN (?)", sub).Pluck("assets.id", &ids).Error; err != nil {
			return nil, err
		}
		managed, err := s.managedAmong(subject, ids)
		if err != nil {
			return nil, err
		}
		cand := make([]uint, 0, len(ids))
		for _, id := range ids {
			if managed[id] && !connectable[id] {
				cand = append(cand, id)
			}
		}
		if v != nil {
			in, err := v.assetsInScope(cand)
			if err != nil {
				return nil, err
			}
			kept := cand[:0]
			for _, id := range cand {
				if in[id] {
					kept = append(kept, id)
				}
			}
			cand = kept
		}
		if len(cand) > 0 {
			out = append(out, OverviewManageOnly{NodePath: paths[n], AssetCount: len(cand)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].NodePath < out[j].NodePath })
	return out, nil
}
