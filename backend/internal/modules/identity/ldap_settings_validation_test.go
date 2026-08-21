package identity

import (
	"errors"
	"strings"
	"testing"
)

// TestLDAPUserFilterRejectsUnsafe user_filter 兩層驗證的負向格。
//
// 最關鍵者為 OR 繞過（`(|(uid=%s)(uid=svc-admin))`）：三條語法規則全過，
// 但 OR 的另一分支可在搜尋結果不含登入帳號時命中——僅做語法檢查會放行
func TestLDAPUserFilterRejectsUnsafe(t *testing.T) {
	cases := []struct {
		name   string
		filter string
		reason string
	}{
		{"OR 繞過", "(|(uid=%s)(uid=svc-admin))", LDAPFilterReasonPlaceholderScope},
		{"OR 巢狀於 AND 之下", "(&(objectClass=user)(|(uid=%s)(uid=svc-admin)))", LDAPFilterReasonPlaceholderScope},
		{"NOT 包住 placeholder", "(!(uid=%s))", LDAPFilterReasonPlaceholderScope},
		{"NOT 於祖先鏈深處", "(&(objectClass=user)(!(&(uid=%s))))", LDAPFilterReasonPlaceholderScope},
		{"無 placeholder", "(objectClass=person)", LDAPFilterReasonPlaceholderMissing},
		{"兩個 placeholder", "(&(uid=%s)(cn=%s))", LDAPFilterReasonPlaceholderMultiple},
		{"其他格式化動詞", "(&(uid=%s)(uidNumber=%d))", LDAPFilterReasonFormatVerb},
		{"單獨的 %d", "(uid=%d)", LDAPFilterReasonFormatVerb},
		{"跳脫百分號", "(uid=%%s)", LDAPFilterReasonFormatVerb},
		{"尾端孤立百分號", "(uid=%s", LDAPFilterReasonParenUnbalanced},
		{"括號不配對（缺右）", "(&(uid=%s)", LDAPFilterReasonParenUnbalanced},
		{"括號不配對（多右）", "(uid=%s))", LDAPFilterReasonParenUnbalanced},
		{"未以括號開頭", "uid=%s", LDAPFilterReasonSyntax},
		{"尾隨垃圾", "(uid=%s)junk", LDAPFilterReasonSyntax},
		{"非法跳脫", "(uid=\\zz%s)", LDAPFilterReasonSyntax},
		{"placeholder 位於屬性名", "(%s=alice)", LDAPFilterReasonPlaceholderPosition},
		{"空字串", "", LDAPFilterReasonEmpty},
		{"超長", "(uid=%s" + strings.Repeat("x", ldapUserFilterMaxLen) + ")", LDAPFilterReasonTooLong},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateLDAPUserFilter(tc.filter)
			if err == nil {
				t.Fatalf("ValidateLDAPUserFilter(%q) 應被拒", tc.filter)
			}
			if !errors.Is(err, ErrLDAPFilterInvalid) {
				t.Fatalf("錯誤未歸入 ErrLDAPFilterInvalid: %v", err)
			}
			var filterErr *LDAPFilterError
			if !errors.As(err, &filterErr) {
				t.Fatalf("錯誤型別非 *LDAPFilterError: %v", err)
			}
			if filterErr.Reason != tc.reason {
				t.Errorf("Reason = %q, want %q", filterErr.Reason, tc.reason)
			}
		})
	}
}

// TestLDAPUserFilterAcceptsNecessaryPlaceholder 正向：placeholder 為必要條件的形態。
// 結構規則不得誤傷正當的 AD 複合 AND filter
func TestLDAPUserFilterAcceptsNecessaryPlaceholder(t *testing.T) {
	cases := []string{
		"(uid=%s)",
		"(&(objectClass=user)(sAMAccountName=%s))",
		"(&(objectClass=person)(&(uid=%s)(accountStatus=active)))",
		"(&(objectClass=user)(!(userAccountControl=2))(sAMAccountName=%s))",
		"(userPrincipalName=%s)",
		"(&(objectClass=user)(cn=*%s*))",
	}

	for _, filter := range cases {
		t.Run(filter, func(t *testing.T) {
			if err := ValidateLDAPUserFilter(filter); err != nil {
				t.Fatalf("ValidateLDAPUserFilter(%q) 應通過，得 %v", filter, err)
			}
		})
	}
}

// TestLDAPDirectoryValidationEnabledCompleteness 啟用態完整性：缺任一必填即拒
func TestLDAPDirectoryValidationEnabledCompleteness(t *testing.T) {
	complete := func() LDAPDirectoryInput {
		return LDAPDirectoryInput{
			Name:            "corp",
			URL:             "ldaps://dir.example",
			BindDN:          "cn=admin,dc=example,dc=org",
			BaseDN:          "ou=users,dc=example,dc=org",
			UserFilter:      "(uid=%s)",
			AttrEmail:       "mail",
			AttrFullName:    "cn",
			Enabled:         true,
			HasBindPassword: true,
		}
	}

	if _, err := ValidateLDAPDirectoryInput(complete()); err != nil {
		t.Fatalf("完整輸入應通過，得 %v", err)
	}

	cases := []struct {
		field  string
		mutate func(*LDAPDirectoryInput)
	}{
		{"url", func(in *LDAPDirectoryInput) { in.URL = "" }},
		{"bind_dn", func(in *LDAPDirectoryInput) { in.BindDN = "" }},
		{"base_dn", func(in *LDAPDirectoryInput) { in.BaseDN = "" }},
		{"user_filter", func(in *LDAPDirectoryInput) { in.UserFilter = "" }},
		{"attr_email", func(in *LDAPDirectoryInput) { in.AttrEmail = "" }},
		{"attr_fullname", func(in *LDAPDirectoryInput) { in.AttrFullName = "" }},
		{"bind_password", func(in *LDAPDirectoryInput) { in.HasBindPassword = false }},
	}

	for _, tc := range cases {
		t.Run("缺"+tc.field, func(t *testing.T) {
			in := complete()
			tc.mutate(&in)
			_, err := ValidateLDAPDirectoryInput(in)
			if !errors.Is(err, ErrLDAPSettingsIncomplete) {
				t.Fatalf("應回 ErrLDAPSettingsIncomplete，得 %v", err)
			}
			var fieldErr *LDAPFieldError
			if !errors.As(err, &fieldErr) || fieldErr.Field != tc.field {
				t.Fatalf("錯誤未指名欄位 %s: %v", tc.field, err)
			}
			if fieldErr.Reason != LDAPFieldReasonRequired {
				t.Errorf("Reason = %q, want %q", fieldErr.Reason, LDAPFieldReasonRequired)
			}
		})
	}

	// 空白字串等同未填（Normalized 先 trim，避免以空白繞過必填）
	in := complete()
	in.BaseDN = "   "
	if _, err := ValidateLDAPDirectoryInput(in); !errors.Is(err, ErrLDAPSettingsIncomplete) {
		t.Errorf("純空白欄位應視為未填，得 %v", err)
	}
}

// TestLDAPDirectoryValidationDraftLenient 草稿（enabled=false）僅驗有值欄位格式
func TestLDAPDirectoryValidationDraftLenient(t *testing.T) {
	// spec 場景：enabled=false 且僅填 url → 通過
	result, err := ValidateLDAPDirectoryInput(LDAPDirectoryInput{URL: "ldap://dir.example"})
	if err != nil {
		t.Fatalf("草稿應通過，得 %v", err)
	}
	if result.ParsedURL.CanonicalOrigin() != "ldap://dir.example:389" {
		t.Errorf("草稿亦應回解析後端點，得 %+v", result.ParsedURL)
	}

	// 全空草稿亦通過
	if _, err := ValidateLDAPDirectoryInput(LDAPDirectoryInput{}); err != nil {
		t.Fatalf("全空草稿應通過，得 %v", err)
	}

	// 但有值欄位的格式仍驗：壞 filter 不因「還是草稿」而放行，
	// 否則存檔驗證會被「先存草稿再翻啟用」繞過
	if _, err := ValidateLDAPDirectoryInput(LDAPDirectoryInput{UserFilter: "(|(uid=%s)(uid=svc-admin))"}); !errors.Is(err, ErrLDAPFilterInvalid) {
		t.Errorf("草稿的 OR 繞過 filter 應被拒，得 %v", err)
	}
	if _, err := ValidateLDAPDirectoryInput(LDAPDirectoryInput{URL: "ldap://u:p@dir.example"}); !errors.Is(err, ErrLDAPURLInvalid) {
		t.Errorf("草稿的非法 URL 應被拒，得 %v", err)
	}
}

// TestLDAPDirectoryValidationFieldFormat 欄位格式（長度、屬性名字元集）
func TestLDAPDirectoryValidationFieldFormat(t *testing.T) {
	cases := []struct {
		name   string
		in     LDAPDirectoryInput
		field  string
		reason string
	}{
		{"name 超長", LDAPDirectoryInput{Name: strings.Repeat("n", ldapNameMaxLen+1)}, "name", LDAPFieldReasonTooLong},
		{"bind_dn 超長", LDAPDirectoryInput{BindDN: strings.Repeat("d", ldapDNMaxLen+1)}, "bind_dn", LDAPFieldReasonTooLong},
		{"base_dn 超長", LDAPDirectoryInput{BaseDN: strings.Repeat("d", ldapDNMaxLen+1)}, "base_dn", LDAPFieldReasonTooLong},
		{"attr_email 超長", LDAPDirectoryInput{AttrEmail: strings.Repeat("a", ldapAttrNameMaxLen+1)}, "attr_email", LDAPFieldReasonTooLong},
		{"attr_email 挾帶括號", LDAPDirectoryInput{AttrEmail: "mail)(uid=*"}, "attr_email", LDAPFieldReasonFormat},
		{"attr_fullname 含空白", LDAPDirectoryInput{AttrFullName: "common name"}, "attr_fullname", LDAPFieldReasonFormat},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateLDAPDirectoryInput(tc.in)
			if !errors.Is(err, ErrLDAPFieldInvalid) {
				t.Fatalf("應回 ErrLDAPFieldInvalid，得 %v", err)
			}
			var fieldErr *LDAPFieldError
			if !errors.As(err, &fieldErr) {
				t.Fatalf("錯誤型別非 *LDAPFieldError: %v", err)
			}
			if fieldErr.Field != tc.field || fieldErr.Reason != tc.reason {
				t.Errorf("得 (%s, %s), want (%s, %s)", fieldErr.Field, fieldErr.Reason, tc.field, tc.reason)
			}
		})
	}

	// 正當屬性名（含 OID 形式）不得誤傷
	for _, attr := range []string{"mail", "cn", "displayName", "sAMAccountName", "0.9.2342.19200300.100.1.3"} {
		if _, err := ValidateLDAPDirectoryInput(LDAPDirectoryInput{AttrEmail: attr}); err != nil {
			t.Errorf("屬性名 %q 應通過，得 %v", attr, err)
		}
	}
}

// TestLDAPDirectoryValidationNormalizes 驗過的值即是應存檔的值（前後空白已去除）
func TestLDAPDirectoryValidationNormalizes(t *testing.T) {
	result, err := ValidateLDAPDirectoryInput(LDAPDirectoryInput{
		Name:            " corp ",
		URL:             " ldaps://Dir.Example ",
		BindDN:          " cn=admin ",
		BaseDN:          " ou=users ",
		UserFilter:      " (uid=%s) ",
		AttrEmail:       " mail ",
		AttrFullName:    " cn ",
		Enabled:         true,
		HasBindPassword: true,
	})
	if err != nil {
		t.Fatalf("非預期錯誤: %v", err)
	}
	if result.Input.Name != "corp" || result.Input.URL != "ldaps://Dir.Example" ||
		result.Input.BindDN != "cn=admin" || result.Input.BaseDN != "ou=users" ||
		result.Input.UserFilter != "(uid=%s)" || result.Input.AttrEmail != "mail" ||
		result.Input.AttrFullName != "cn" {
		t.Fatalf("正規化結果不符: %+v", result.Input)
	}
	if result.ParsedURL.CanonicalOrigin() != "ldaps://dir.example:636" {
		t.Errorf("ParsedURL = %+v", result.ParsedURL)
	}
}
