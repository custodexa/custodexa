package api

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/modules/identity"
)

// auditableLoginUsername 把登入失敗列要記的帳號字串轉成可落庫的形態。
//
// 含控制字元或非法 UTF-8 的帳號在認證服務即以憑證錯誤拒絕，但那一筆失敗仍要
// 留痕；原樣寫入時資料庫會拒收含 NUL 的文字欄，審計列就此消失。故以 U+FFFD
// 取代無法落庫的字元：留下「有人送了這種帳號」的事實，而不是讓它悄悄不見。
// 合法輸入原樣返回。
func auditableLoginUsername(username string) string {
	if identity.LoginUsernameAcceptable(username) {
		return username
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return utf8.RuneError
		}
		return r
	}, strings.ToValidUTF8(username, string(utf8.RuneError)))
}
