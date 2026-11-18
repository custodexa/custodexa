package api

import (
	"errors"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/identity"
)

// userCreateConflictCode 建立使用者時的衝突對應的機器碼：使用者名稱已被使用為名稱衝突碼，
// 電子郵件已被使用為與修改路徑相同的電子郵件衝突碼。不是衝突時 ok 為 false。
func userCreateConflictCode(err error) (code apierror.ErrCode, ok bool) {
	switch {
	case errors.Is(err, identity.ErrUsernameExists):
		return apierror.CodeUsernameExists, true
	case errors.Is(err, identity.ErrEmailConflict):
		return apierror.CodeEmailConflict, true
	}
	return "", false
}
