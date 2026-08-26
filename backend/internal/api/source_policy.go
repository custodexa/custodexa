package api

import (
	"errors"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/sourceip"
)

// 允許來源網段清單的對外錯誤對映。
// 驗證本體在 sourceip 單一實作；此處只把 typed error 換成機器碼。

// sourcePolicyValidationCode 把清單驗證錯誤對映為 VALIDATION_* 碼。
// 非清單類錯誤回 ("", false)，由呼叫端沿既有分流處理。
func sourcePolicyValidationCode(err error) (apierror.ErrCode, bool) {
	switch {
	case errors.Is(err, sourceip.ErrPrefixInvalid):
		return apierror.CodeValidationSourcePrefixInvalid, true
	case errors.Is(err, sourceip.ErrTooManyPrefixes):
		return apierror.CodeValidationSourcePrefixLimit, true
	}
	return "", false
}
