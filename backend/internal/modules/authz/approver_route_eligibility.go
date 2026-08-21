package authz

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 審核／撤銷端點守門的資格判準（SD-2 收斂 W7 7.1；**D-12 行為變更 W7b 8.1-8.2**）。
//
// **D-12 收斂（2026-08-09 拍板）**：`admin` 角色本身**不再構成有效審核資格**。
// 審核端點守門改由 `evaluateEffectiveApprover`（＝`IsEffectiveApprover` 的述詞）
// 判定，與入口／badge 判定成為單一真相；本檔只保留「回傳結構＋錯誤碼分流」這層
// 呼叫端適配，不再自帶第二份判準 SQL。
//
// **端點分離（design.md D-12 訂正）**：`POST /access-requests/:id/revoke` 屬**遏制
// 動作不是審核**，既有 spec 明定資格＝admin OR 原核准人；若一併收斂，admin 將無法
// 撤銷已核出的票證＝安全倒退。故撤銷端點改用 `EvaluateRevokeRouteEligibility`
// （＝收斂前的判準：admin OR 有效審核者），行為零變更。
//
// 等價比對見 `approver_eligibility_parity_test.go`（W7 7.3 建立，W7b 8.10 改為
// 斷言兩實作**逐例一致**，含 admin 兩類皆不放行）。

// ApproverRouteEligibility 審核端點守門的判定結果。
//
// **W7b 8.3**：`IsAdmin` 欄位已移除——admin 兜底語義隨 D-12 收斂消滅，
// handler 端範圍過濾一律依審核範圍。撤銷端點所需的 admin 旗標改由
// `RevokeRouteEligibility.IsAdmin` 提供。
type ApproverRouteEligibility struct {
	// Allowed 放行與否（approver 角色 OR 屬任一審核方群組；**不含 admin**）
	Allowed bool
	// RoleQueryFailed 角色查詢失敗（呼叫端須回 CodeInternalRoleQuery）
	RoleQueryFailed bool
	// ScopeQueryFailed 群組查詢失敗（呼叫端須回 CodeInternalApproverQuery）
	ScopeQueryFailed bool
}

// EvaluateApproverRouteEligibility 即時查 DB 判定審核端點資格（D-12 後不含 admin）。
// 兩個查詢的失敗以不同旗標回報，使呼叫端能維持既有的兩種錯誤碼分流。
func EvaluateApproverRouteEligibility(db *gorm.DB, userID uint) (ApproverRouteEligibility, error) {
	allowed, roleQueryFailed, err := evaluateEffectiveApprover(db, userID)
	if err != nil {
		return ApproverRouteEligibility{
			RoleQueryFailed:  roleQueryFailed,
			ScopeQueryFailed: !roleQueryFailed,
		}, err
	}
	return ApproverRouteEligibility{Allowed: allowed}, nil
}

// RevokeRouteEligibility 撤銷端點守門的判定結果。
type RevokeRouteEligibility struct {
	// IsAdmin 操作者具 admin 角色（呼叫端寫入 RevokeAdminKey，service 層據此走
	// 「admin 兜底」撤銷資格分支）
	IsAdmin bool
	// Allowed 放行與否（admin OR 有效審核者）
	Allowed bool
	// RoleQueryFailed 角色查詢失敗（呼叫端須回 CodeInternalRoleQuery）
	RoleQueryFailed bool
	// ScopeQueryFailed 群組查詢失敗（呼叫端須回 CodeInternalApproverQuery）
	ScopeQueryFailed bool
}

// EvaluateRevokeRouteEligibility 撤銷端點守門（D-12 端點分離）：admin OR 有效審核者。
//
// **判準與收斂前的 `RequireApproverRole` 相同**（admin OR approver 角色 OR 屬任一
// 審核方群組），故撤銷端點行為零變更；細緻資格（原核准人 vs 範圍命中）仍由
// service 的 `eligibleToRevoke` 裁決，本守衛只做粗篩與 admin 旗標傳遞。
func EvaluateRevokeRouteEligibility(db *gorm.DB, userID uint) (RevokeRouteEligibility, error) {
	var adminCount int64
	if err := db.Table("user_roles").
		Joins("JOIN roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ? AND roles.name = ? AND roles.deleted_at IS NULL",
			userID, model.RoleAdmin).
		Count(&adminCount).Error; err != nil {
		return RevokeRouteEligibility{RoleQueryFailed: true}, fmt.Errorf("查詢 admin 角色失敗: %w", err)
	}
	if adminCount > 0 {
		return RevokeRouteEligibility{IsAdmin: true, Allowed: true}, nil
	}

	allowed, roleQueryFailed, err := evaluateEffectiveApprover(db, userID)
	if err != nil {
		return RevokeRouteEligibility{
			RoleQueryFailed:  roleQueryFailed,
			ScopeQueryFailed: !roleQueryFailed,
		}, err
	}
	return RevokeRouteEligibility{Allowed: allowed}, nil
}
