package authz

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// 審核範圍寫入與讀取的交易內範圍判定。
//
// 呼叫方在寫入交易內先取拓撲序列化鎖，再於同交易判定：資產型與節點型以資產、節點目標判定
// （審核範圍管理鍵）；申請人型建立與既有申請人型列另需全域的申請人型管理鍵。
// 判定在交易內重解主體（傳入主體的指派一律忽略）。

var (
	errApproverScopeUnwired      = errors.New("authz: approver scope write scope without evaluator")
	errApproverScopeInconsistent = errors.New("authz: approver scope decision inconsistent")
	// ErrApproverScopeWriteScopeMissing 審核範圍寫入的範圍判定未注入。
	ErrApproverScopeWriteScopeMissing = errors.New("authz: approver scope write scope not injected")
)

// ApproverScopeCapabilityError 交易內重解後主體不持所需的審核範圍管理能力；Required 為該操作要求的全部權限點。
type ApproverScopeCapabilityError struct {
	Required []Permission
}

// Error 固定字串。
func (e *ApproverScopeCapabilityError) Error() string {
	return "authz: approver scope write without capability"
}

// ApproverScopeWriteScope 審核範圍的範圍判定；以 NewApproverScopeWriteScope 建立。
type ApproverScopeWriteScope struct {
	e *ScopeEvaluator
}

// NewApproverScopeWriteScope 以判定器建立；判定器須已登記 ApproverScopeScopeResolvers。
func NewApproverScopeWriteScope(e *ScopeEvaluator) *ApproverScopeWriteScope {
	return &ApproverScopeWriteScope{e: e}
}

// decide 判定單一權限點：放行回 nil；能力拒絕回 *ApproverScopeCapabilityError（Required 為 required）；
// 範圍拒絕回 *ErrScopeDenied。
func (w *ApproverScopeWriteScope) decide(ctx context.Context, tx *gorm.DB, perm Permission, target ScopeTarget, required []Permission) error {
	if w == nil || w.e == nil {
		return errApproverScopeUnwired
	}
	res, denied, err := w.e.DecideWithDenial(tx, PrincipalFromContext(ctx), perm, target)
	if err != nil {
		return err
	}
	switch res.Outcome {
	case ScopeAllow:
		return nil
	case ScopeDenyCapability:
		return &ApproverScopeCapabilityError{Required: required}
	case ScopeDenyScope:
		if denied != nil {
			return denied
		}
	}
	return errApproverScopeInconsistent
}

// DecideCreate 建立前的判定。資產型與節點型回該客體的資產或節點拒絕（範圍外與不存在同形）；
// 申請人型要求審核範圍管理鍵與申請人型管理鍵皆放行，任一不放行一律回能力錯誤（不揭露差別）。
func (w *ApproverScopeWriteScope) DecideCreate(ctx context.Context, tx *gorm.DB, spec ApproverScopeSpec) error {
	k := []Permission{PermApproverScopeManage}
	switch {
	case spec.AssetID != nil:
		return w.decide(ctx, tx, PermApproverScopeManage, AssetTarget(*spec.AssetID), k)
	case spec.AssetGroupID != nil:
		return w.decide(ctx, tx, PermApproverScopeManage, NodeTarget(*spec.AssetGroupID), k)
	}
	both := []Permission{PermApproverScopeManage, PermApproverScopeApplicantManage}
	for _, perm := range both {
		err := w.decide(ctx, tx, perm, ApproverScopeApplicantCreateTarget(), both)
		var denied *ErrScopeDenied
		if errors.As(err, &denied) {
			return &ApproverScopeCapabilityError{Required: both}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// DecideRow 移除前對既有列的第一步判定（審核範圍管理鍵）。範圍外與不存在回審核範圍種類的拒絕。
func (w *ApproverScopeWriteScope) DecideRow(ctx context.Context, tx *gorm.DB, id uint) error {
	return w.decide(ctx, tx, PermApproverScopeManage, ApproverScopeRowTarget(id), []Permission{PermApproverScopeManage})
}

// DecideApplicantRow 申請人型列的第二步判定（申請人型管理鍵）。走到這一步的主體已經全域持有審核範圍管理鍵
// （節點範圍持有者在第一步即得範圍拒絕），對它而言不存在的列是 ErrScopeNotFound；不放行時回同一個值，
// 回應與審計都與該主體移除不存在的列相同，不是 403。拒絕值只由判定器產生，這裡不自行建構。
func (w *ApproverScopeWriteScope) DecideApplicantRow(ctx context.Context, tx *gorm.DB, id uint) error {
	err := w.decide(ctx, tx, PermApproverScopeApplicantManage, ApproverScopeRowTarget(id), []Permission{PermApproverScopeApplicantManage})
	var capErr *ApproverScopeCapabilityError
	var denied *ErrScopeDenied
	if errors.As(err, &capErr) || errors.As(err, &denied) {
		return ErrScopeNotFound
	}
	return err
}
