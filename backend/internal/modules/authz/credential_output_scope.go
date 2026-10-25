package authz

import (
	"context"

	"github.com/custodexa/backend/internal/modules/asset"
)

// credentialOutputFull 輸出判定的全量條件，只有兩條正面條件：
//  1. 憑證檢視能力不限範圍（超級管理者，或憑證檢視有全域來源）。
//  2. 完全不持、也未被指派憑證檢視能力，而相容的憑證管理能力有全域來源。
//
// 改密與輪替能力都不授予憑證識別的可見性：它們只決定可列出哪些資產目標。
// 其餘一切主體（含無指派、有效節點已空、只持改密入口）都是受限。
func credentialOutputFull(p *Principal) bool {
	if p == nil {
		return false
	}
	if scopeSetOn(p, PermCredentialView, sourcesAll).State() == ScopeSetUnlimited {
		return true
	}
	if p.Has(PermCredentialView) || p.assignsPermission(PermCredentialView) {
		return false
	}
	return scopeSetOn(p, PermCredentialManage, sourcesAll).State() == ScopeSetUnlimited
}

var _ asset.CredentialOutputScopeSource = (*CredentialScopeReader)(nil)

// outputScope 產生回應當下以重解主體算出的輸出判定。
type outputScope struct {
	full bool
	view *credentialScopeView
}

func (o *outputScope) Full() bool { return o.full }

// AssetsInView 受限時 ids 中落在憑證檢視集合內的資產。
func (o *outputScope) AssetsInView(ids []uint) (map[uint]bool, error) {
	if o.full {
		out := make(map[uint]bool, len(ids))
		for _, id := range ids {
			out[id] = true
		}
		return out, nil
	}
	return o.view.AssetsInView(ids)
}

// CredentialsInView 受限時 ids 中落在憑證檢視集合內的憑證。
func (o *outputScope) CredentialsInView(ids []uint) (map[uint]bool, error) {
	out := make(map[uint]bool, len(ids))
	if o.full {
		for _, id := range ids {
			out[id] = true
		}
		return out, nil
	}
	if len(ids) == 0 {
		return out, nil
	}
	q, err := o.view.ApplyVisible(o.view.e.topo.CredentialsByID(o.view.db, ids))
	if err != nil {
		return nil, err
	}
	var got []uint
	if err := q.Pluck("credentials.id", &got).Error; err != nil {
		return nil, err
	}
	for _, id := range got {
		out[id] = true
	}
	return out, nil
}

// CredentialOutputScope 以產生回應當下重新解析的主體回三態判定之一（全量或受限；失敗回錯誤）。
// 脈絡無主體、重解失敗一律回錯誤，不退回全量。
func (r *CredentialScopeReader) CredentialOutputScope(ctx context.Context) (asset.CredentialOutputScope, error) {
	if r == nil || r.e == nil || r.e.topo == nil || r.db == nil {
		return nil, errCredentialScopeUnwired
	}
	p, err := r.e.resolveInTx(r.db, PrincipalFromContext(ctx))
	if err != nil {
		return nil, err
	}
	if credentialOutputFull(p) {
		return &outputScope{full: true}, nil
	}
	return &outputScope{view: &credentialScopeView{e: r.e, db: r.db, view: scopeSetOn(p, PermCredentialView, sourcesAll)}}, nil
}
