package asset

import "errors"

// 能力拒絕的錯誤值帶出拒絕依據。
//
// 憑證管理關卡與欄位級能力判定被拒時，回傳的錯誤包著原本的拒絕哨兵（errors.Is 照舊命中），
// 另附拒絕依據的權限點鍵：主體缺的那一項；無從得知缺哪一項的分支（空主體、主體不存在或停用）
// 改附該操作層級要求的全部權限點。HTTP 層把它存進請求脈絡供審計取用，回應本身不帶任何鍵。
// 本模組不依賴 authz，鍵以字串傳遞。

// CapabilityDeniedError 能力拒絕的錯誤值：Sentinel 為 ErrCredentialBindForbidden 或
// ErrFieldCapabilityDenied；Required 為拒絕依據的權限點鍵，空＝呼叫端無從得知（由 HTTP 層退回路由要求）。
type CapabilityDeniedError struct {
	Sentinel error
	Required []string
	// Forbidden 為真＝範圍化檢視者經範圍判定器判出的能力拒絕：接入層回單一 forbidden，不收斂成不存在
	Forbidden bool
}

func (e *CapabilityDeniedError) Error() string { return e.Sentinel.Error() }

// Unwrap 回原哨兵，使 errors.Is(err, ErrCredentialBindForbidden) 等判定不變。
func (e *CapabilityDeniedError) Unwrap() error { return e.Sentinel }

// capabilityDenied 以哨兵與依據鍵建立錯誤值；空鍵略過。
func capabilityDenied(sentinel error, keys ...string) error {
	req := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != "" {
			req = append(req, k)
		}
	}
	return &CapabilityDeniedError{Sentinel: sentinel, Required: req}
}

// DeniedCapabilities 取錯誤鏈上能力拒絕所附的權限點鍵（複本）；未附或不是能力拒絕回 nil。
func DeniedCapabilities(err error) []string {
	var d *CapabilityDeniedError
	if !errors.As(err, &d) || len(d.Required) == 0 {
		return nil
	}
	return append([]string(nil), d.Required...)
}

// IsForbiddenCapabilityDenial 錯誤鏈上是否為須回單一 forbidden 的能力拒絕（見 Forbidden）。
func IsForbiddenCapabilityDenial(err error) bool {
	var d *CapabilityDeniedError
	return errors.As(err, &d) && d.Forbidden
}
