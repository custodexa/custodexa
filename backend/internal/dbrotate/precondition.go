package dbrotate

import (
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
)

// MaxNewSecretLen 新密碼長度上限（SQL Server 登入密碼上限 128 字元，三方言取同一值）。
const MaxNewSecretLen = 128

// CheckPreconditions 第 1 步本地前置檢查（不碰遠端）。回空字串＝通過，否則回原因碼。
//
//   - 帳號名：不得為空、不得含控制字元。
//   - 新密碼：非空、可列印 ASCII、不含 ' " \、長度不超過 128。產生器的字元集本來就
//     排除這三個字元，擋下的是不該出現的輸入，不是常態。
//   - 舊密碼：不得含 NUL；PostgreSQL 的舊密碼限 ASCII（回滾時以用戶端算的 verifier
//     改回，本套件不做 SASLprep，非 ASCII 的舊密碼回滾後可能登不進去）。
func CheckPreconditions(p dbconsole.Protocol, username string, oldSecret, newSecret []byte) string {
	if username == "" || hasControl([]byte(username)) {
		return model.ChangeSecretReasonInvalidAccountName
	}
	if !validNewSecret(newSecret) {
		return model.ChangeSecretReasonInvalidNewSecret
	}
	for _, b := range oldSecret {
		if b == 0 {
			return model.ChangeSecretReasonInvalidOldSecret
		}
		if p == dbconsole.ProtocolPostgres && b >= 0x80 {
			return model.ChangeSecretReasonInvalidOldSecret
		}
	}
	return ""
}

func validNewSecret(s []byte) bool {
	if len(s) == 0 || len(s) > MaxNewSecretLen {
		return false
	}
	for _, b := range s {
		if b < 0x20 || b > 0x7e || b == '\'' || b == '"' || b == '\\' {
			return false
		}
	}
	return true
}

func hasControl(s []byte) bool {
	for _, b := range s {
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}
