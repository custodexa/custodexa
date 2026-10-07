package identity

import (
	"unicode"
	"unicode/utf8"
)

// LoginUsernameAcceptable 回報登入帳號字串能否送進帳號查詢：合法 UTF-8 且不含
// 控制字元（C0、DEL、C1，含 NUL、換行與定位字元）。
//
// 不合格的字串不可能是任何帳號的名稱。交給資料庫只會換來驅動層錯誤（含 NUL 的
// 文字參數會被拒收，回應變成 500 並帶出資料層的錯誤路徑）；交給目錄則等於把它
// 拼進查詢。登入於查詢前即以憑證錯誤拒絕，回應與「查無帳號」相同；判定只看輸入
// 本身、不涉及任何帳號狀態，故不構成帳號枚舉。
//
// 只做字元層判定，不限制長度或字元集：帳號名稱的規則由建立帳號的路徑決定，
// 這裡只擋「任何帳號都不可能叫這個名字」的輸入。
func LoginUsernameAcceptable(username string) bool {
	if !utf8.ValidString(username) {
		return false
	}
	for _, r := range username {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
