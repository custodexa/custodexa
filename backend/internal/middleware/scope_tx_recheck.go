package middleware

import (
	"errors"

	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 寫入交易內的範圍重判。
//
// 登錄閘在 handler 之前以一般連線判定範圍；服務在自己的寫入交易內改動拓撲（例如資產掛載）後，
// 目標可能已不在主體範圍內。登錄閘放行時把本請求通過的判定（權限點與目標）留在請求脈絡，
// handler 經 TxScopeRecheck 取出交給服務，服務在交易內以同一判定器重判。
//
// 回傳值：
//   - 放行 → nil（介面值本身為 nil，不是帶型別的 nil）。
//   - 範圍拒絕 → *authz.ErrScopeDenied，種類與層由 DecideWithDenial 給出，本檔不建構拒絕值。
//     handler 以 errors.As 取出後交 RespondScopeDenied，回應與登錄閘的範圍拒絕相同。
//   - 能力拒絕 → *TxCapabilityDenied，handler 交 RespondAuthzDecision。
//   - 讀取失敗或判定結果不一致 → 一般錯誤（500，不放行）。

const txScopeRecheckKey = "authz_tx_scope_recheck"

// txScopeCheck 登錄閘對本請求通過的一條判定。
type txScopeCheck struct {
	perm   authz.Permission
	target authz.ScopeTarget
}

// txScopeRecheck 登錄閘放行時留下的判定依賴；建構後不可變。
type txScopeRecheck struct {
	eval      *authz.ScopeEvaluator
	principal *authz.Principal
	checks    []txScopeCheck
}

// TxCapabilityDenied 交易內重判為能力拒絕（主體的能力在登錄閘之後被收回）。
type TxCapabilityDenied struct {
	Result authz.ScopeResult
	Basis  CapabilityDenial
}

func (e *TxCapabilityDenied) Error() string { return "authz: capability denied in transaction" }

// errTxScopeInconsistent 判定結果與拒絕值的組合不合法（呼叫端錯誤），不放行。
var errTxScopeInconsistent = errors.New("authz: inconsistent scope decision in transaction")

// rememberTxScopeRecheck 登錄閘全部放行後呼叫；沒有任何判定時不留。
func rememberTxScopeRecheck(c *gin.Context, g *ScopeGate, p *authz.Principal, checks []txScopeCheck) {
	if len(checks) == 0 {
		return
	}
	c.Set(txScopeRecheckKey, &txScopeRecheck{eval: g.eval, principal: p, checks: append([]txScopeCheck(nil), checks...)})
}

// TxScopeRecheck 本請求在登錄閘通過的範圍判定，回傳在交易內重判的函式；
// 本請求沒有經過範圍判定時回 nil，服務據此略過重判（行為不變）。
func TxScopeRecheck(c *gin.Context) func(tx *gorm.DB) error {
	v, ok := c.Get(txScopeRecheckKey)
	if !ok {
		return nil
	}
	r, _ := v.(*txScopeRecheck)
	if r == nil {
		return nil
	}
	return r.recheck
}

// recheck 在呼叫方交易內逐條重判；能力拒絕先於範圍拒絕（與登錄閘同序）。
func (r *txScopeRecheck) recheck(tx *gorm.DB) error {
	var capDenied *TxCapabilityDenied
	var scopeDenied *authz.ErrScopeDenied
	for _, ck := range r.checks {
		res, denied, err := r.eval.DecideWithDenial(tx, r.principal, ck.perm, ck.target)
		if err != nil {
			return err
		}
		switch {
		case res.Outcome == authz.ScopeAllow && denied == nil:
		case res.Outcome == authz.ScopeDenyCapability && denied == nil:
			if capDenied == nil {
				capDenied = &TxCapabilityDenied{Result: res, Basis: AllOfCapabilityDenial(ck.perm)}
			}
		case res.Outcome == authz.ScopeDenyScope && denied != nil:
			if scopeDenied == nil {
				scopeDenied = denied
			}
		default:
			return errTxScopeInconsistent
		}
	}
	// 只在非 nil 時轉成 error：帶型別的 nil 指標放進 error 介面會變成非 nil 錯誤
	if capDenied != nil {
		return capDenied
	}
	if scopeDenied != nil {
		return scopeDenied
	}
	return nil
}
