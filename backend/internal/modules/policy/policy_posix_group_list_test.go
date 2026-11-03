package policy

import (
	"strings"
	"testing"
)

func TestPosixGroupListPolicy(t *testing.T) {
	def := findDef(PolicyHostPrivilegedGroupsPOSIX)
	if def == nil {
		t.Fatal("政策鍵未定義")
	}
	if def.Default != "root,sudo,wheel,admin" || def.MaxLength != 8192 || def.ListFormat != PolicyListPOSIXGroups {
		t.Fatalf("定義不符：%+v", def)
	}
	ok := []struct{ name, in, want string }{
		{"出廠值", "root,sudo,wheel,admin", "root,sudo,wheel,admin"},
		{"首尾空白", "  wheel ,  sudo  ", "wheel,sudo"},
		{"重複保留先後", "wheel,sudo,wheel,root,sudo", "wheel,sudo,root"},
		{"空項略過", "wheel,,  ,sudo,", "wheel,sudo"},
		{"項內空白合法", "wheel, domain admins ", "wheel,domain admins"},
		{"錢號合法", "svc$grp", "svc$grp"},
		{"空值合法", "", ""},
		{"只有空白與逗號", " , , ", ""},
		{"恰 256 位元組", strings.Repeat("g", 256), strings.Repeat("g", 256)},
		{"恰 32 項", groupsN(32), groupsN(32)},
	}
	for _, c := range ok {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizePolicyValue(def, c.in)
			if err != nil {
				t.Fatalf("不應拒絕：%v", err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
	bad := []struct{ name, in string }{
		{"含冒號", "wheel,bad:name"},
		{"含 TAB", "wheel,ba\td"},
		{"含換行", "wheel,\nsudo"},
		{"含 C1 控制字元", "wheel,a\u0085b"},
		{"含 NUL", "wheel,a\x00b"},
		{"257 位元組", strings.Repeat("g", 257)},
		{"33 項", groupsN(33)},
		{"非 UTF-8", "wheel,\xff"},
	}
	for _, c := range bad {
		t.Run("拒絕/"+c.name, func(t *testing.T) {
			if _, err := normalizePolicyValue(def, c.in); err == nil {
				t.Fatalf("%q 應被拒絕", c.in)
			}
		})
	}
	t.Run("ListFormat 只能用於 text", func(t *testing.T) {
		bogus := []PolicyDef{{Key: "x_int", Type: PolicyTypeInt, Default: "1", ListFormat: PolicyListPOSIXGroups, Label: "x"}}
		if err := validateDefList(bogus); err == nil {
			t.Fatal("int 型設 ListFormat 應被定義自檢擋下")
		}
	})
}

func groupsN(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "g" + strings.Repeat("x", i+1)
	}
	return strings.Join(parts, ",")
}
