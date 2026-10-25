package main

import (
	"context"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// credentialManagementAdapter 把 asset 的憑證管理授權 port 接到 authz 的能力檢核。
//
// 放在組裝根而非任一模組內：asset 不匯入 authz（避免出向邊），authz 也不認識 asset 的型別。
// 判定以資料庫現況重新解析主體，不讀 context 內的快取主體。
type credentialManagementAdapter struct {
	resolver *authz.Resolver
	// scope 範圍交集（憑證歸屬與目標資產）；未注入時只驗能力（全域口徑）
	scope   *authz.ScopeEvaluator
	scopeDB *gorm.DB
}

// withScope 啟用範圍交集：db 為 nil 的呼叫（關卡未帶交易）改用 scopeDB。
func (a *credentialManagementAdapter) withScope(e *authz.ScopeEvaluator, db *gorm.DB) *credentialManagementAdapter {
	a.scope, a.scopeDB = e, db
	return a
}

func newCredentialManagementAdapter(resolver *authz.Resolver) *credentialManagementAdapter {
	return &credentialManagementAdapter{resolver: resolver}
}

func (a *credentialManagementAdapter) AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
	actor asset.CredentialManagementActor, req asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {

	d, err := a.resolver.HasAllCapabilities(db, actor.UserID, req.Capabilities)
	if err != nil {
		return asset.CredentialManagementDecision{}, err
	}
	out := asset.CredentialManagementDecision{Allowed: d.Allowed, Missing: d.Missing, AuthzVersion: d.Version, Sources: d.Sources}
	if a.scope == nil || (!d.Allowed && d.Missing == capabilityMissingPrincipal) {
		return out, nil
	}
	sdb := db
	if sdb == nil {
		sdb = a.scopeDB
	}
	if req.NodeTarget {
		// 節點目標（新增資產）：零節點沒有目標可涵蓋，只認全域來源，不標記須收斂
		if len(req.NodeIDs) == 0 {
			return out, nil
		}
		missing, denied, err := a.scope.DecideCredentialOnNodes(ctx, sdb, actor.UserID, req.Capabilities, req.NodeIDs)
		if err != nil {
			return asset.CredentialManagementDecision{}, err
		}
		return a.targetedOutcome(ctx, out, missing, denied), nil
	}
	if len(req.CredentialIDs) == 0 && len(req.AssetIDs) == 0 {
		// 不帶目標：預設只認全域來源（不帶目標檢核的口徑）；呼叫端其後自行收斂範圍的操作改認任一有效來源
		if d.Allowed || !targetlessScopeNarrowed(req.Operation) {
			return out, nil
		}
		missing, err := a.scope.CredentialCapabilityMissing(ctx, sdb, actor.UserID, req.Capabilities)
		if err != nil {
			return asset.CredentialManagementDecision{}, err
		}
		// 只有節點範圍來源放行時標記：呼叫端缺投影或歸屬判定即拒絕，不以未收斂的全域口徑回應
		out.Allowed, out.Missing, out.ScopeNarrowingRequired = missing == "", missing, missing == ""
		return out, nil
	}
	// 帶目標：能力與範圍皆由判定器以憑證歸屬與明確目標資產判定（全部掛載不逐台驗），
	// 取代不帶目標檢核對節點範圍來源的保守拒絕；能力先於範圍
	missing, denied, err := a.scope.DecideCredentialManagement(ctx, sdb, actor.UserID, req.Capabilities,
		req.CredentialIDs, req.AssetIDs)
	if err != nil {
		return asset.CredentialManagementDecision{}, err
	}
	return a.targetedOutcome(ctx, out, missing, denied), nil
}

// targetedOutcome 帶目標判定的結果收斂成決定：範圍拒絕原樣帶回（接入層寫出與不存在同形的回應）、
// 能力拒絕記缺漏、皆無即放行。
func (a *credentialManagementAdapter) targetedOutcome(ctx context.Context, out asset.CredentialManagementDecision,
	missing string, denied *authz.ErrScopeDenied) asset.CredentialManagementDecision {

	switch {
	case denied != nil:
		out.Allowed, out.Missing, out.ScopeDenial = false, "", denied
	case missing != "":
		// 範圍化檢視者（以請求進入時的主體認定，交易內撤權後仍成立）的能力拒絕回單一 forbidden；
		// 其他主體沿現行與不存在同形的收斂回應
		out.Allowed, out.Missing = false, missing
		out.ScopedCapabilityDenial = authz.IsCredentialScopedViewer(ctx)
	default:
		out.Allowed, out.Missing = true, ""
	}
	return out
}

// capabilityMissingPrincipal 能力檢核對不存在、已刪除或停用主體回報的缺漏值。
const capabilityMissingPrincipal = "principal"

// targetlessScopeNarrowed 不帶目標、但呼叫端其後自行收斂範圍的操作：列表（檢視集合投影）與建立（歸屬判定）。
func targetlessScopeNarrowed(op asset.CredentialOperation) bool {
	switch op {
	case asset.CredOpView, asset.CredOpCreate:
		return true
	}
	return false
}

// RestoreGeneration 讀目前持久還原世代：背景工作的授權脈絡記下建立當下的世代，
// 派送前比對，還原前留下的意圖不在還原後送出。讀取失敗原樣回傳（呼叫端 fail-close）。
func (a *credentialManagementAdapter) RestoreGeneration(db *gorm.DB) (string, error) {
	return authz.RestoreGeneration(db)
}

var _ asset.RestoreGenerationReader = (*credentialManagementAdapter)(nil)
var _ asset.CredentialManagementAuthorizer = (*credentialManagementAdapter)(nil)
