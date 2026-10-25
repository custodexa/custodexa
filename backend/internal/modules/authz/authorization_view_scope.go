package authz

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 授權規則管理範圍對讀取面的投影：授權列表與兩個有效權限視角。
//
//   - 列表：集合述詞套在規則的客體上（資產客體取子樹內資產，節點客體取子樹內節點），
//     於篩選、COUNT 與分頁之前生效；全域檢視者（不限集合）不加條件。
//   - 主體視角：資產與檢視者範圍取交集；交集外的資產不出現、不給計數。
//   - 客體視角：資產在範圍外與不存在同為 ErrEffectiveAssetNotFound。
//   - 溯因遮蔽（兩視角共用）：規則識別碼只在規則出現在檢視者的列表投影時保留；
//     節點識別碼與路徑只在節點屬檢視者可見節點（範圍子樹與其定位祖先）時保留；
//     範圍外歸屬節點數經 disclosure.Count 產出，單位為該資產在範圍外的歸屬節點數。
//
// 本檔不取鎖、不寫表；主體一律在讀取連線上重解。

var errAuthorizationViewUnwired = errors.New("authz: authorization view scope without evaluator or topology")

// AuthorizationListScope 授權列表的範圍條件：只能由 EffectiveAccessResolver.ListObjectScope 建立。
// 零值不可用（套用時回錯誤），呼叫方不得當作不限。
type AuthorizationListScope struct {
	e   *ScopeEvaluator
	p   *Principal
	set ScopeSet
}

// ApplyAuthorizationRuleScope 把集合加到授權規則查詢上（篩選、計數與分頁之前呼叫）：
// 不限回原查詢；空與拓撲未注入的條件加 1 = 0；條件加「客體在子樹內」。q 的主表須為 asset_authorizations。
func (e *ScopeEvaluator) ApplyAuthorizationRuleScope(tx *gorm.DB, q *gorm.DB, set ScopeSet) (*gorm.DB, error) {
	if q == nil {
		return nil, errScopeQueryNil
	}
	switch set.state {
	case ScopeSetUnlimited:
		return q, nil
	case ScopeSetEmpty:
		return q.Where("1 = 0"), nil
	case ScopeSetConditional:
	default:
		return nil, errScopeSetInvalid
	}
	if e == nil || e.topo == nil {
		return q.Where("1 = 0"), nil
	}
	if tx == nil {
		return nil, errScopeNilTx
	}
	return q.Where("(asset_authorizations.asset_id IN (?) OR asset_authorizations.asset_group_id IN (?))",
		e.topo.SubtreeAssetIDs(tx, set.roots), e.topo.SubtreeNodeIDs(tx, set.roots)), nil
}

// apply 把範圍條件加到授權列表查詢上。
func (s AuthorizationListScope) apply(db *gorm.DB, q *gorm.DB) (*gorm.DB, error) {
	if s.e == nil || s.p == nil || s.set.state == 0 {
		return nil, errAuthorizationViewUnwired
	}
	return s.e.ApplyAuthorizationRuleScope(db, q, s.set)
}

// nodeAllowed 節點是否在檢視者範圍內；不存在與範圍外同為否。
func (s AuthorizationListScope) nodeAllowed(db *gorm.DB, nodeID uint) (bool, error) {
	if s.set.state == ScopeSetUnlimited {
		return true, nil
	}
	res, _, err := s.e.decideOn(db, s.p, PermAuthorizationManage, AuthorizationNodeObjectTarget(nodeID))
	if err != nil {
		return false, err
	}
	return res.Outcome == ScopeAllow, nil
}

// WithScope 注入判定器（組裝時）；未注入時範圍化讀取方法回錯誤，不退回全量。
func (r *EffectiveAccessResolver) WithScope(e *ScopeEvaluator) *EffectiveAccessResolver {
	r.e = e
	return r
}

// viewer 在讀取連線上重解檢視者並取授權規則管理能力的集合；拓撲缺席且集合不是不限時回錯誤。
func (r *EffectiveAccessResolver) viewer(ctx context.Context) (*Principal, ScopeSet, error) {
	if r == nil || r.e == nil || r.db == nil {
		return nil, ScopeSet{}, errAuthorizationViewUnwired
	}
	p, err := r.e.resolveInTx(r.db, PrincipalFromContext(ctx))
	if err != nil {
		return nil, ScopeSet{}, err
	}
	set := scopeSetOn(p, PermAuthorizationManage, sourcesAll)
	if set.state == ScopeSetConditional && r.e.topo == nil {
		return nil, ScopeSet{}, errAuthorizationViewUnwired
	}
	return p, set, nil
}

// ListObjectScope 授權列表的範圍條件（呼叫端放進列表篩選的 object_scope 鍵）。
func (r *EffectiveAccessResolver) ListObjectScope(ctx context.Context) (AuthorizationListScope, error) {
	p, set, err := r.viewer(ctx)
	if err != nil {
		return AuthorizationListScope{}, err
	}
	return AuthorizationListScope{e: r.e, p: p, set: set}, nil
}

// ownScopeView 檢視者範圍下的遮蔽依據，一次查詢建立。
type ownScopeView struct {
	r        *EffectiveAccessResolver
	set      ScopeSet
	visible  map[uint]bool // 可見節點：範圍子樹加定位祖先
	selected map[uint]bool // 範圍子樹
}

func (r *EffectiveAccessResolver) newScopeView(set ScopeSet) (*ownScopeView, error) {
	proj, err := r.e.projectionOn(r.db, set)
	if err != nil {
		return nil, err
	}
	v := &ownScopeView{r: r, set: set, visible: map[uint]bool{}, selected: proj.Selectable}
	for id := range proj.Selectable {
		v.visible[id] = true
	}
	for id := range proj.Locators {
		v.visible[id] = true
	}
	return v, nil
}

// assetsInScope ids 中屬範圍內的資產。
func (v *ownScopeView) assetsInScope(ids []uint) (map[uint]bool, error) {
	out := map[uint]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	q, err := v.r.e.ApplyScopeSet(v.r.db, v.r.db.Model(&model.Asset{}).Where("assets.id IN ?", ids), v.set, ScopeQueryAsset)
	if err != nil {
		return nil, err
	}
	var in []uint
	if err := q.Pluck("assets.id", &in).Error; err != nil {
		return nil, err
	}
	for _, id := range in {
		out[id] = true
	}
	return out, nil
}

// rulesInProjection ids 中出現在檢視者列表投影的規則。
func (v *ownScopeView) rulesInProjection(ids []uint) (map[uint]bool, error) {
	out := map[uint]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	q, err := v.r.e.ApplyAuthorizationRuleScope(v.r.db,
		v.r.db.Model(&model.AssetAuthorization{}).Where("asset_authorizations.id IN ?", ids), v.set)
	if err != nil {
		return nil, err
	}
	var in []uint
	if err := q.Pluck("asset_authorizations.id", &in).Error; err != nil {
		return nil, err
	}
	for _, id := range in {
		out[id] = true
	}
	return out, nil
}

// outOfScopeNodeCounts 各資產在範圍外的歸屬節點數（掛載節點去重，祖先不另算）。
func (v *ownScopeView) outOfScopeNodeCounts(assetIDs []uint) (map[uint]int, error) {
	out := map[uint]int{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		AssetID uint
		NodeID  uint
	}
	if err := v.r.db.Table("asset_nodes AS an").
		Select("DISTINCT an.asset_id AS asset_id, an.node_id AS node_id").
		Joins("JOIN asset_groups g ON g.id = an.node_id AND g.deleted_at IS NULL").
		Where("an.asset_id IN ?", assetIDs).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, row := range rows {
		if !v.selected[row.NodeID] {
			out[row.AssetID]++
		}
	}
	return out, nil
}

// maskPaths 就地遮蔽溯因，回是否有任何一條的節點被遮蔽（只遮蔽規則識別碼不算：節點仍可見，不需計數）。
func (v *ownScopeView) maskPaths(paths []EffectivePath, ruleVisible map[uint]bool) bool {
	nodeMasked := false
	for i := range paths {
		p := &paths[i]
		if p.AuthorizationID != nil && !ruleVisible[*p.AuthorizationID] {
			p.AuthorizationID = nil
		}
		if p.ViaNodeID != nil && !v.visible[*p.ViaNodeID] {
			p.ViaNodeID = nil
			p.ViaNodePath = ""
			nodeMasked = true
		}
	}
	return nodeMasked
}

func nodeCountField(n int) *disclosure.NodeCountField {
	return &disclosure.NodeCountField{OutOfScopeNodeCount: disclosure.NodeCountValue{Value: disclosure.Count(disclosure.OutOfScopeNodeCount, n)}}
}

func authorizationIDsOf(paths []EffectivePath, into *[]uint) {
	for _, p := range paths {
		if p.AuthorizationID != nil {
			*into = append(*into, *p.AuthorizationID)
		}
	}
}

// ResolveEffectiveAssetsFor 主體視角（依檢視者範圍）：全域檢視者與未範圍化結果相同。
func (r *EffectiveAccessResolver) ResolveEffectiveAssetsFor(ctx context.Context, subjectUserID uint, now time.Time) (*EffectiveAssetsResult, error) {
	_, set, err := r.viewer(ctx)
	if err != nil {
		return nil, err
	}
	res, err := r.ResolveEffectiveAssets(subjectUserID, now)
	if err != nil || set.state == ScopeSetUnlimited {
		return res, err
	}
	v, err := r.newScopeView(set)
	if err != nil {
		return nil, err
	}
	ids := make([]uint, 0, len(res.Assets))
	for _, a := range res.Assets {
		ids = append(ids, a.AssetID)
	}
	in, err := v.assetsInScope(ids)
	if err != nil {
		return nil, err
	}
	kept := make([]EffectiveAssetEntry, 0, len(res.Assets))
	var keptIDs, ruleIDs []uint
	for _, a := range res.Assets {
		if !in[a.AssetID] {
			continue
		}
		kept = append(kept, a)
		keptIDs = append(keptIDs, a.AssetID)
		authorizationIDsOf(a.Paths, &ruleIDs)
	}
	ruleVisible, err := v.rulesInProjection(ruleIDs)
	if err != nil {
		return nil, err
	}
	counts, err := v.outOfScopeNodeCounts(keptIDs)
	if err != nil {
		return nil, err
	}
	for i := range kept {
		if v.maskPaths(kept[i].Paths, ruleVisible) {
			kept[i].NodeCountField = nodeCountField(counts[kept[i].AssetID])
		}
	}
	res.Assets = kept
	return res, nil
}

// ResolveEffectiveUsersFor 客體視角（依檢視者範圍）：資產在範圍外與不存在同為 ErrEffectiveAssetNotFound。
func (r *EffectiveAccessResolver) ResolveEffectiveUsersFor(ctx context.Context, assetID uint, now time.Time) (*EffectiveUsersResult, error) {
	p, set, err := r.viewer(ctx)
	if err != nil {
		return nil, err
	}
	if set.state == ScopeSetUnlimited {
		return r.ResolveEffectiveUsers(assetID, now)
	}
	d, _, err := r.e.decideOn(r.db, p, PermAuthorizationManage, AuthorizationAssetObjectTarget(assetID))
	if err != nil {
		return nil, err
	}
	if d.Outcome != ScopeAllow {
		return nil, ErrEffectiveAssetNotFound
	}
	res, err := r.ResolveEffectiveUsers(assetID, now)
	if err != nil {
		return nil, err
	}
	v, err := r.newScopeView(set)
	if err != nil {
		return nil, err
	}
	var ruleIDs []uint
	for _, u := range res.Users {
		authorizationIDsOf(u.Paths, &ruleIDs)
	}
	ruleVisible, err := v.rulesInProjection(ruleIDs)
	if err != nil {
		return nil, err
	}
	counts, err := v.outOfScopeNodeCounts([]uint{assetID})
	if err != nil {
		return nil, err
	}
	for i := range res.Users {
		if v.maskPaths(res.Users[i].Paths, ruleVisible) {
			res.Users[i].NodeCountField = nodeCountField(counts[assetID])
		}
	}
	return res, nil
}
