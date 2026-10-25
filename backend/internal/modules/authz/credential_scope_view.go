package authz

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 憑證庫的範圍判定與範圍化讀取投影。
//
//   - 目標解析：節點歸屬以歸屬節點自身加未刪除祖先為涵蓋節點；專用憑證以其最早建立的一筆未刪除掛載
//     所屬資產的涵蓋節點為涵蓋節點；全域歸屬沒有涵蓋節點（只有全域來源涵蓋，判定器對全域來源不解析目標）。
//     已刪除與不存在只回 Exists=false，與範圍外同一個拒絕。
//   - 集合述詞：節點歸屬落在子樹節點內，或專用憑證的掛載資產落在子樹資產內；與單筆解析同一口徑。
//   - 範圍化檢視者：經節點範圍指派持有任一資產、資產帳號或憑證權限點（不看節點是否仍有效）。
//     標記只決定回應帶不帶範圍化欄位，不授予任何能力。
//
// 本檔不取鎖、不寫表；主體一律在呼叫方給的連線上重解。

// ScopeTargetCredential 憑證目標（RefID 為憑證識別）。
const ScopeTargetCredential ScopeTargetKind = "credential"

// CredentialTarget 憑證目標。
func CredentialTarget(credentialID uint) ScopeTarget {
	return ScopeTarget{Kind: ScopeTargetCredential, RefID: credentialID}
}

var errCredentialScopeUnwired = errors.New("authz: credential scope without evaluator, topology or database")

// errCredentialManagementInconsistent 逐目標判定判為範圍外，判定器對同一目標卻未判出範圍拒絕值。
var errCredentialManagementInconsistent = errors.New("authz: credential management scope decision inconsistent")

// CredentialScopeResolver 憑證目標解析器的登記項（組裝判定器時傳入 NewScopeEvaluator）。
func CredentialScopeResolver() ScopeTargetResolverRegistration {
	return ScopeTargetResolverRegistration{Kind: ScopeTargetCredential, Resolve: resolveCredentialScopeTarget}
}

func resolveCredentialScopeTarget(tx *gorm.DB, topo ScopeTopology, t ScopeTarget) (ResolvedScopeTarget, error) {
	if topo == nil {
		return ResolvedScopeTarget{}, errScopeResolverNoTopology
	}
	if t.Kind != ScopeTargetCredential {
		return ResolvedScopeTarget{}, errScopeResolverKind
	}
	notFound := ResolvedScopeTarget{Layer: ScopeLayerTarget}
	if t.RefID == 0 {
		return notFound, nil
	}
	kind, ownerNodeID, ok, err := topo.CredentialOwnership(tx, t.RefID)
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	if !ok {
		return notFound, nil
	}
	found := ResolvedScopeTarget{Exists: true, Layer: ScopeLayerTarget}
	switch kind {
	case model.CredentialOwnerNode:
		if ownerNodeID == nil {
			return found, nil
		}
		nodes, exists, err := topo.NodeCoverNodes(tx, *ownerNodeID)
		if err != nil {
			return ResolvedScopeTarget{}, err
		}
		if exists {
			found.CoverNodes = nodes
		}
	case model.CredentialOwnerAsset:
		assetID, err := topo.CredentialFirstMountAsset(tx, t.RefID)
		if err != nil {
			return ResolvedScopeTarget{}, err
		}
		if assetID == 0 {
			return found, nil
		}
		nodes, exists, err := topo.AssetCoverNodes(tx, assetID)
		if err != nil {
			return ResolvedScopeTarget{}, err
		}
		if exists {
			found.CoverNodes = nodes
		}
	}
	return found, nil
}

// DecideCredentialManagement 一次管理請求的範圍交集（asset.CredentialManagementAuthorizer 的範圍面）：
// 每個能力對每筆憑證判定（歸屬口徑），每個明確指定的目標資產以同一能力判定資產範圍。
// 不限範圍的主體（超管、全域來源）不解析目標。回 missing（能力拒絕時的權限點）或 denied（範圍拒絕值）；
// 兩者皆空即放行。主體重解一次後共用。
func (e *ScopeEvaluator) DecideCredentialManagement(ctx context.Context, tx *gorm.DB, actorUserID uint, caps []string,
	credentialIDs, targetAssetIDs []uint) (missing string, denied *ErrScopeDenied, err error) {

	if e == nil || e.topo == nil {
		return "", nil, errCredentialScopeUnwired
	}
	if actorUserID == 0 {
		return "", nil, ErrScopeNilPrincipal
	}
	p, err := e.resolveInTx(tx, ownershipPrincipal(ctx, actorUserID))
	if err != nil {
		return "", nil, err
	}
	targets := make([]ScopeTarget, 0, len(credentialIDs)+len(targetAssetIDs))
	for _, id := range credentialIDs {
		targets = append(targets, CredentialTarget(id))
	}
	for _, id := range targetAssetIDs {
		targets = append(targets, AssetTarget(id))
	}
	return e.decideCredentialTargets(tx, p, caps, targets)
}

// DecideCredentialOnNodes 以節點為目標的憑證能力判定（新增資產時資產尚未存在，目標是送出的節點）：
// 每個能力對每個節點判定，全部涵蓋才放行，任一節點不涵蓋即回該節點的範圍拒絕；已刪除或不存在的節點
// 由節點解析視同不存在。回傳口徑同 DecideCredentialManagement。零節點由呼叫端處理（只認全域來源）。
func (e *ScopeEvaluator) DecideCredentialOnNodes(ctx context.Context, tx *gorm.DB, actorUserID uint, caps []string,
	nodeIDs []uint) (missing string, denied *ErrScopeDenied, err error) {

	if e == nil || e.topo == nil {
		return "", nil, errCredentialScopeUnwired
	}
	if actorUserID == 0 {
		return "", nil, ErrScopeNilPrincipal
	}
	p, err := e.resolveInTx(tx, ownershipPrincipal(ctx, actorUserID))
	if err != nil {
		return "", nil, err
	}
	targets := make([]ScopeTarget, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		targets = append(targets, NodeTarget(id))
	}
	return e.decideCredentialTargets(tx, p, caps, targets)
}

// decideCredentialTargets 每個能力對每個目標逐一判定（全部通過才放行）：能力拒絕回該權限點，
// 範圍拒絕回判定器對同一目標取出的拒絕值。
func (e *ScopeEvaluator) decideCredentialTargets(tx *gorm.DB, p *Principal, caps []string,
	targets []ScopeTarget) (string, *ErrScopeDenied, error) {

	for _, c := range caps {
		perm := Permission(c)
		for _, target := range targets {
			res, _, derr := e.decideOn(tx, p, perm, target)
			if derr != nil {
				return "", nil, derr
			}
			switch res.Outcome {
			case ScopeAllow:
			case ScopeDenyCapability:
				return c, nil, nil
			default:
				d, derr := e.credentialManagementDenial(tx, p, perm, target)
				return "", d, derr
			}
		}
	}
	return "", nil, nil
}

// credentialManagementDenial 逐目標判定判為範圍外時，由判定器對同一目標（同一交易、同一權限點）取出範圍拒絕值；
// 拒絕值的種類、層與原因只由判定器給出。兩個回傳值恰有一個非 nil：拒絕值，或讀取失敗／判定不一致。
func (e *ScopeEvaluator) credentialManagementDenial(tx *gorm.DB, p *Principal, perm Permission, target ScopeTarget) (*ErrScopeDenied, error) {
	_, denied, err := e.DecideWithDenial(tx, p, perm, target)
	if err != nil {
		return nil, err
	}
	if denied == nil {
		return nil, errCredentialManagementInconsistent
	}
	return denied, nil
}

// CredentialCapabilityMissing 不帶目標的憑證能力檢核：任一有效來源（含節點範圍）即算持有。
// 只供呼叫端其後自行收斂範圍的操作（列表以檢視集合投影、建立以歸屬判定）；回第一個缺少的權限點，皆有回空字串。
func (e *ScopeEvaluator) CredentialCapabilityMissing(ctx context.Context, tx *gorm.DB, actorUserID uint,
	caps []string) (string, error) {

	if e == nil || e.topo == nil {
		return "", errCredentialScopeUnwired
	}
	if actorUserID == 0 {
		return "", ErrScopeNilPrincipal
	}
	p, err := e.resolveInTx(tx, ownershipPrincipal(ctx, actorUserID))
	if err != nil {
		return "", err
	}
	for _, c := range caps {
		if !p.Has(Permission(c)) {
			return c, nil
		}
	}
	return "", nil
}

// credentialViewerPerms 構成憑證庫範圍化檢視者的權限點：資產頁的檢視者權限點（不含節點管理）加全部憑證權限點。
var credentialViewerPerms = []Permission{
	PermAssetView, PermAssetCreate, PermAssetUpdate, PermAssetDelete, PermAssetTest, PermAccountRotate,
	PermCredentialView, PermCredentialCreate, PermCredentialUpdate, PermCredentialSetSecret,
	PermCredentialRotate, PermCredentialConvertScope, PermCredentialDetach, PermCredentialDelete,
	PermCredentialBind,
}

// credentialOpPerms 列級旗標逐項判定的權限點。
var credentialOpPerms = []Permission{
	PermCredentialUpdate, PermCredentialSetSecret, PermCredentialRotate, PermCredentialBind,
	PermCredentialConvertScope, PermCredentialDetach, PermCredentialDelete,
}

// IsCredentialScopedViewer 請求脈絡上的主體是否為憑證庫的範圍化檢視者（脈絡未帶主體為否）。
// 只決定拒絕的回應形狀（範圍化檢視者的能力拒絕回單一 forbidden），不授予任何能力。
func IsCredentialScopedViewer(ctx context.Context) bool {
	return isCredentialScopedViewer(PrincipalFromContext(ctx))
}

// isCredentialScopedViewer 主體是否為憑證庫的範圍化檢視者（只看節點範圍指派的角色內容）。
func isCredentialScopedViewer(p *Principal) bool {
	if p == nil || p.Facts.SubjectKind == model.KindAgent {
		return false
	}
	for _, a := range p.Assignments {
		if a.Scope != model.ScopeKindNodes {
			continue
		}
		for _, perm := range assignmentRolePermissions(a) {
			for _, v := range credentialViewerPerms {
				if perm == v {
					return true
				}
			}
		}
	}
	return false
}

// CredentialScopeReader 憑證庫的範圍化讀取；由組裝根以判定器與讀取連線建立。
type CredentialScopeReader struct {
	e  *ScopeEvaluator
	db *gorm.DB
}

// NewCredentialScopeReader 以判定器（目錄、拓撲與憑證解析器）與讀取連線建立。
func NewCredentialScopeReader(e *ScopeEvaluator, db *gorm.DB) *CredentialScopeReader {
	return &CredentialScopeReader{e: e, db: db}
}

var _ asset.CredentialScopeSource = (*CredentialScopeReader)(nil)

// CredentialsInView 帳號列的憑證投影：範圍化檢視者回 ids 中落在其憑證檢視集合內者（scoped 為真，
// 與憑證庫列表同一個集合述詞）；非範圍化檢視者回 scoped 為假。
func (r *CredentialScopeReader) CredentialsInView(ctx context.Context, ids []uint) (map[uint]bool, bool, error) {
	v, err := r.CredentialScopeView(ctx)
	if err != nil || v == nil {
		return nil, false, err
	}
	out := make(map[uint]bool, len(ids))
	if len(ids) == 0 {
		return out, true, nil
	}
	q, err := v.ApplyVisible(r.e.topo.CredentialsByID(r.db, ids))
	if err != nil {
		return nil, false, err
	}
	var got []uint
	if err := q.Pluck("credentials.id", &got).Error; err != nil {
		return nil, false, err
	}
	for _, id := range got {
		out[id] = true
	}
	return out, true, nil
}

// AccountCredentialShape 帳號列表回應的形狀：精簡（不含憑證識別欄位）、完整（照現行）、範圍化（經憑證檢視集合投影）。
type AccountCredentialShape int

const (
	AccountCredentialSlim AccountCredentialShape = iota
	AccountCredentialFull
	AccountCredentialScoped
)

// AccountCredentialProjection 帳號列表的形狀與憑證可見集合：以讀取當下重新解析的同一份主體決定兩件事。
// 該主體對帳號列表識別欄位的欄位能力不成立回精簡；成立且非範圍化檢視者回完整；成立且是範圍化檢視者回
// 範圍化與 ids 中落在其憑證檢視集合內者。請求進入後才被撤銷指派的主體以重解後的狀態為準，不沿用請求快照。
func (r *CredentialScopeReader) AccountCredentialProjection(ctx context.Context, ids []uint) (AccountCredentialShape, map[uint]bool, error) {
	if r == nil || r.e == nil || r.e.topo == nil || r.db == nil {
		return AccountCredentialSlim, nil, errCredentialScopeUnwired
	}
	p, err := r.e.resolveInTx(r.db, PrincipalFromContext(ctx))
	if err != nil {
		return AccountCredentialSlim, nil, err
	}
	if !FieldCapability("GET", "/api/v1/assets/:id/accounts", "credential_identity_fields", p) {
		return AccountCredentialSlim, nil, nil
	}
	if !isCredentialScopedViewer(p) {
		return AccountCredentialFull, nil, nil
	}
	v := &credentialScopeView{e: r.e, db: r.db, view: scopeSetOn(p, PermCredentialView, sourcesAll)}
	inView := make(map[uint]bool, len(ids))
	if len(ids) == 0 {
		return AccountCredentialScoped, inView, nil
	}
	q, err := v.ApplyVisible(r.e.topo.CredentialsByID(r.db, ids))
	if err != nil {
		return AccountCredentialSlim, nil, err
	}
	var got []uint
	if err := q.Pluck("credentials.id", &got).Error; err != nil {
		return AccountCredentialSlim, nil, err
	}
	for _, id := range got {
		inView[id] = true
	}
	return AccountCredentialScoped, inView, nil
}

type credentialScopeView struct {
	e *ScopeEvaluator
	// db 讀取路徑（CredentialScopeView）的連線；交易內的影響判定不經投影留存交易句柄，改以參數傳入
	db   *gorm.DB
	view ScopeSet
	// viewNodes 檢視集合物化後的節點範圍（遮蔽掛載列的歸屬節點用）
	viewNodes nodeScope
	ops       map[Permission]nodeScope
	sets      map[Permission]ScopeSet
}

// CredentialScopeView 範圍化檢視者回投影；其餘主體回 nil（呼叫方走現行路徑）。
func (r *CredentialScopeReader) CredentialScopeView(ctx context.Context) (asset.CredentialScopeView, error) {
	if r == nil {
		return nil, errCredentialScopeUnwired
	}
	v, err := r.credentialProjection(ctx, r.db)
	if err != nil || v == nil {
		return nil, err
	}
	v.db = r.db
	return v, nil
}

// CredentialImpactScopeIn 在呼叫端交易內（持有憑證列鎖時）判定 ids 中落在該動作能力有效範圍內、與落在檢視集合內的資產；
// 主體重解與範圍查詢都走 tx，不另開連線，也不留存交易句柄。非範圍化檢視者回 scoped 為假。
func (r *CredentialScopeReader) CredentialImpactScopeIn(ctx context.Context, tx *gorm.DB, capability string,
	ids []uint) (inCapability, inView map[uint]bool, scoped bool, err error) {

	if r == nil || tx == nil {
		return nil, nil, false, errCredentialScopeUnwired
	}
	v, err := r.credentialProjection(ctx, tx)
	if err != nil || v == nil {
		return nil, nil, false, err
	}
	if inCapability, err = v.assetsInCapabilityOn(tx, capability, ids); err != nil {
		return nil, nil, false, err
	}
	if inView, err = v.assetsInSetOn(tx, v.view, ids); err != nil {
		return nil, nil, false, err
	}
	return inCapability, inView, true, nil
}

// credentialProjection 以 db 重解主體並物化檢視與各動作的範圍；非範圍化檢視者回 (nil, nil)。
// 回傳的投影不帶連線，由呼叫方決定之後的查詢走哪個連線。
func (r *CredentialScopeReader) credentialProjection(ctx context.Context, db *gorm.DB) (*credentialScopeView, error) {
	if r == nil || r.e == nil || r.e.topo == nil || db == nil {
		return nil, errCredentialScopeUnwired
	}
	p, err := r.e.resolveInTx(db, PrincipalFromContext(ctx))
	if err != nil {
		return nil, err
	}
	if !isCredentialScopedViewer(p) {
		return nil, nil
	}
	v := &credentialScopeView{e: r.e, view: scopeSetOn(p, PermCredentialView, sourcesAll),
		ops: map[Permission]nodeScope{}, sets: map[Permission]ScopeSet{}}
	if v.viewNodes, err = r.e.materialize(db, v.view); err != nil {
		return nil, err
	}
	for _, perm := range credentialOpPerms {
		set := scopeSetOn(p, perm, sourcesAll)
		ns, err := r.e.materialize(db, set)
		if err != nil {
			return nil, err
		}
		v.ops[perm], v.sets[perm] = ns, set
	}
	return v, nil
}

// ApplyVisible 把檢視集合（credential:view 的有效範圍）加到以 credentials 為主表的查詢上。
func (v *credentialScopeView) ApplyVisible(q *gorm.DB) (*gorm.DB, error) {
	if q == nil {
		return nil, errScopeQueryNil
	}
	switch v.view.state {
	case ScopeSetUnlimited:
		return q, nil
	case ScopeSetConditional:
	default:
		return q.Where("1 = 0"), nil
	}
	if v.e.topo == nil {
		return q.Where("1 = 0"), nil
	}
	// 專用憑證以最早一筆掛載判定，與單筆解析（CredentialFirstMountAsset）同一口徑
	mounted := v.e.topo.CredentialsFirstMountedOn(v.db, v.e.topo.SubtreeAssetIDs(v.db, v.view.roots))
	return q.Where("((credentials.owner_kind = ? AND credentials.owner_node_id IN (?)) OR "+
		"(credentials.owner_kind = ? AND credentials.id IN (?)))",
		model.CredentialOwnerNode, v.e.topo.SubtreeNodeIDs(v.db, v.view.roots),
		model.CredentialOwnerAsset, mounted), nil
}

// MaskNodes 依檢視範圍遮蔽資產歸屬：回範圍內節點（原順序）與範圍外筆數；與資產頁的遮蔽同一判定。
func (v *credentialScopeView) MaskNodes(nodeIDs []uint) ([]uint, int) {
	return v.viewNodes.split(nodeIDs)
}

// AssetsInView ids 中落在檢視集合內的資產。
func (v *credentialScopeView) AssetsInView(ids []uint) (map[uint]bool, error) {
	return v.assetsInSetOn(v.db, v.view, ids)
}

// AssetsInCapability ids 中落在該動作能力有效範圍內的資產；未列管的能力視為空集合。
func (v *credentialScopeView) AssetsInCapability(capability string, ids []uint) (map[uint]bool, error) {
	return v.assetsInCapabilityOn(v.db, capability, ids)
}

func (v *credentialScopeView) assetsInCapabilityOn(db *gorm.DB, capability string, ids []uint) (map[uint]bool, error) {
	set, ok := v.sets[Permission(capability)]
	if !ok {
		return map[uint]bool{}, nil
	}
	return v.assetsInSetOn(db, set, ids)
}

func (v *credentialScopeView) assetsInSetOn(db *gorm.DB, set ScopeSet, ids []uint) (map[uint]bool, error) {
	if db == nil {
		return nil, errCredentialScopeUnwired
	}
	out := make(map[uint]bool, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	if set.state == ScopeSetUnlimited {
		for _, id := range ids {
			out[id] = true
		}
		return out, nil
	}
	q, err := v.e.ApplyScopeSet(db, db.Model(&model.Asset{}).Where("assets.id IN ?", ids), set, ScopeQueryAsset)
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

// Allows 一個動作對一組涵蓋節點是否可操作；原因碼不含名稱。
func (v *credentialScopeView) Allows(capability string, nodeIDs []uint) (bool, string) {
	s, ok := v.ops[Permission(capability)]
	if !ok {
		return false, asset.CredentialActionNoCapability
	}
	switch s.state {
	case ScopeSetUnlimited:
		return true, ""
	case ScopeSetConditional:
		if in, _ := s.split(nodeIDs); len(in) > 0 {
			return true, ""
		}
		return false, asset.CredentialActionOutOfScope
	}
	return false, asset.CredentialActionNoCapability
}
