package api

// isSHA256Hex 是否為 64 字元的十六進位（SHA256 的字面形狀）。
//
// 用於瀏覽器綁定值的形狀驗證：只驗非空會讓任意字串成為合法綁定
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
