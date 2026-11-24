package api

import (
	"strings"
	"testing"
)

func TestIsSHA256Hex(t *testing.T) {
	// 瀏覽器綁定值的形狀驗證：只驗非空會讓任意字串成為合法綁定
	valid := strings.Repeat("a1B2", 16) // 64 字元
	if !isSHA256Hex(valid) {
		t.Errorf("%q 應為合法 SHA256 十六進位", valid)
	}
	invalid := []string{
		"", "   ", "short", strings.Repeat("a", 63), strings.Repeat("a", 65),
		strings.Repeat("g", 64), // 非十六進位字元
		strings.Repeat("a", 63) + " ",
	}
	for _, s := range invalid {
		if isSHA256Hex(s) {
			t.Errorf("%q 不應通過形狀驗證", s)
		}
	}
}
