package identity

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
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

// directoryLoginName 目錄登入名稱的保存形：先做 Unicode 相容正規化（NFKC），
// 再去前後空白並把內部連續空白壓成一個，大小寫保留。目錄端判定同名時不計較
// 這些差異，帳號名稱存成這個形式，才與目錄端認得的名稱一致。
func directoryLoginName(username string) string {
	return strings.Join(strings.Fields(norm.NFKC.String(username)), " ")
}

// directoryLoginNameKey 目錄登入名稱的比對鍵：在保存形之上再做大小寫摺疊。
// 兩個名稱的比對鍵相同，目錄端就視為同一人；目錄登入對應帳號一律以此鍵判定，
// 不只看 ASCII 大小寫。
func directoryLoginNameKey(username string) string {
	folded := norm.NFKC.String(cases.Fold().String(directoryLoginName(username)))
	return strings.Join(strings.Fields(folded), " ")
}

// asciiEqualFold 兩字串完全相同，或只差 ASCII 英文字母大小寫。
// 不做 Unicode 摺疊：非 ASCII 的大小寫或相容形差異不算同名。
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x == y {
			continue
		}
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
