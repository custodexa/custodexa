package authz

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// 授權規則寫入（建立、批次、調整帳號範圍、刪除）的交易內範圍判定。
//
// 呼叫方依序：主體 users 列鎖（升冪，lockUserRows）→ 拓撲序列化鎖（lockForAuthorizationWrite）→
// 同交易判定。判定時主體在交易內重解（傳入主體的指派一律忽略），目標與拓撲也在交易內重讀。
// 取得拓撲序列化鎖之後不再取新的使用者或群組鎖；防自我授權守衛內的列鎖是對已持有列的重入。
// 主體（使用者、群組、agent）不經範圍判定。

var (
	errAuthorizationScopeUnwired = errors.New("authz: authorization write scope without evaluator")
	// ErrAuthorizationScopeMissing 授權規則寫入的範圍判定未注入。
	ErrAuthorizationScopeMissing = errors.New("authz: authorization write scope not injected")
	// errAuthorizationScopeInconsistent 判定器回範圍拒絕卻未帶拒絕值。
	errAuthorizationScopeInconsistent = errors.New("authz: authorization scope decision inconsistent")
)

// AuthorizationWriteCapabilityError 交易內重解後主體不持授權規則管理能力。
type AuthorizationWriteCapabilityError struct{}

// Error 固定字串。
func (e *AuthorizationWriteCapabilityError) Error() string {
	return "authz: authorization write without capability"
}

// AuthorizationBatchUnavailableError 範圍化操作者的批次中有客體範圍外或不存在；Count 只算客體。
type AuthorizationBatchUnavailableError struct {
	Count int
}

// Error 固定字串，不含 ID 或名稱。
func (e *AuthorizationBatchUnavailableError) Error() string {
	return "authz: authorization batch contains unavailable objects"
}

// AuthorizationWriteScope 授權規則寫入的範圍判定；零值不可用，以 NewAuthorizationWriteScope 建立。
type AuthorizationWriteScope struct {
	e *ScopeEvaluator
}

// NewAuthorizationWriteScope 以判定器建立。判定器須已登記 AuthorizationScopeResolvers。
func NewAuthorizationWriteScope(e *ScopeEvaluator) *AuthorizationWriteScope {
	return &AuthorizationWriteScope{e: e}
}

// NewAuthorizationScopeEvaluator 組裝期用：產品目錄加拓撲讀取器，並登記產品所有後段目標種類（ProductScopeResolvers）。
func NewAuthorizationScopeEvaluator(cat Catalogue, topo ScopeTopology) *ScopeEvaluator {
	return NewScopeEvaluator(cat, topo, ProductScopeResolvers()...)
}

// lockForAuthorizationWrite 取主體 users 列鎖（升冪）後取拓撲序列化鎖。
// 兩步固定順序；subjectUserIDs 為空（刪除與群組主體）時只取拓撲鎖。
func lockForAuthorizationWrite(tx *gorm.DB, subjectUserIDs []uint) error {
	if err := lockUserRows(tx, subjectUserIDs); err != nil {
		return err
	}
	return LockScopeTopologyTx(tx)
}

// decide 對 target 判定授權規則管理能力：放行回 nil；能力拒絕回 *AuthorizationWriteCapabilityError；
// 範圍拒絕回 *ErrScopeDenied。讀取失敗原樣回，不當作不存在。
func (w *AuthorizationWriteScope) decide(ctx context.Context, tx *gorm.DB, target ScopeTarget) error {
	if w == nil || w.e == nil {
		return errAuthorizationScopeUnwired
	}
	res, denied, err := w.e.DecideWithDenial(tx, PrincipalFromContext(ctx), PermAuthorizationManage, target)
	if err != nil {
		return err
	}
	switch res.Outcome {
	case ScopeAllow:
		return nil
	case ScopeDenyCapability:
		return &AuthorizationWriteCapabilityError{}
	case ScopeDenyScope:
		if denied != nil {
			return denied
		}
	}
	return errAuthorizationScopeInconsistent
}

// DecideObject 判定建立授權的客體（資產或節點其一）。
func (w *AuthorizationWriteScope) DecideObject(ctx context.Context, tx *gorm.DB, assetID, nodeID uint) error {
	if nodeID != 0 {
		return w.decide(ctx, tx, AuthorizationNodeObjectTarget(nodeID))
	}
	return w.decide(ctx, tx, AuthorizationAssetObjectTarget(assetID))
}

// DecideRule 判定既有規則（以其客體為目標）。
func (w *AuthorizationWriteScope) DecideRule(ctx context.Context, tx *gorm.DB, ruleID uint) error {
	return w.decide(ctx, tx, AuthorizationRuleTarget(ruleID))
}

// CountUnavailableObjects 批次的客體判定：回無法操作（範圍外或不存在）的客體數。
// 能力拒絕即整批回能力錯誤；全域操作者與超級管理者恆放行，計數為 0。
func (w *AuthorizationWriteScope) CountUnavailableObjects(ctx context.Context, tx *gorm.DB, assetIDs, nodeIDs []uint) (int, error) {
	unavailable := 0
	check := func(target ScopeTarget) error {
		err := w.decide(ctx, tx, target)
		var denied *ErrScopeDenied
		switch {
		case err == nil:
			return nil
		case errors.As(err, &denied):
			unavailable++
			return nil
		}
		return err
	}
	for _, id := range assetIDs {
		if err := check(AuthorizationAssetObjectTarget(id)); err != nil {
			return 0, err
		}
	}
	for _, id := range nodeIDs {
		if err := check(AuthorizationNodeObjectTarget(id)); err != nil {
			return 0, err
		}
	}
	return unavailable, nil
}
