package identity

import (
	"errors"
	"strings"
	"testing"
)

// TestLDAPURLParseRejectsNonOriginShapes URL 文法收斂：origin 形狀以外一律拒。
// 每格對應「拒絕 userinfo／path／query／fragment／空 host／超界 port」的一項
func TestLDAPURLParseRejectsNonOriginShapes(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		reason string
	}{
		{"userinfo 挾帶憑證", "ldap://user:secret@dir.example", LDAPURLReasonUserinfo},
		{"spec 場景的完整非法形狀", "ldap://user:secret@dir.example/ou=x?scope", LDAPURLReasonUserinfo},
		{"path", "ldap://dir.example/ou=users", LDAPURLReasonPath},
		{"空 path 的尾斜線", "ldap://dir.example/", LDAPURLReasonPath},
		{"query", "ldap://dir.example?scope=sub", LDAPURLReasonQuery},
		{"fragment", "ldap://dir.example#frag", LDAPURLReasonFragment},
		{"空 host", "ldap://", LDAPURLReasonHost},
		{"埠超界", "ldap://dir.example:70000", LDAPURLReasonPort},
		{"埠為零", "ldap://dir.example:0", LDAPURLReasonPort},
		{"尾隨冒號", "ldap://dir.example:", LDAPURLReasonPort},
		{"非 ldap scheme", "http://dir.example", LDAPURLReasonScheme},
		{"ldapi scheme", "ldapi://dir.example", LDAPURLReasonScheme},
		{"無 scheme", "dir.example:389", LDAPURLReasonScheme},
		{"空字串", "   ", LDAPURLReasonEmpty},
		{"超長", "ldap://" + strings.Repeat("a", ldapURLMaxLen) + ".example", LDAPURLReasonTooLong},
		{"主機含空白", "ldap://dir example", LDAPURLReasonMalformed},
		{"非 ASCII 主機", "ldap://dır.example", LDAPURLReasonHost},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, err := ParseLDAPURL(tc.raw)
			if err == nil {
				t.Fatalf("ParseLDAPURL(%q) 應被拒，卻回 %+v", tc.raw, endpoint)
			}
			if !errors.Is(err, ErrLDAPURLInvalid) {
				t.Fatalf("錯誤未歸入 ErrLDAPURLInvalid: %v", err)
			}
			var urlErr *LDAPURLError
			if !errors.As(err, &urlErr) {
				t.Fatalf("錯誤型別非 *LDAPURLError: %v", err)
			}
			if urlErr.Reason != tc.reason {
				t.Errorf("Reason = %q, want %q", urlErr.Reason, tc.reason)
			}
			// 拒絕原因恆為靜態字串，不得回填使用者輸入（否則 userinfo 憑證會
			// 隨錯誤訊息進入回應與日誌）
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("錯誤訊息洩漏輸入內容: %v", err)
			}
			if !endpoint.IsZero() {
				t.Errorf("被拒時應回零值端點，得 %+v", endpoint)
			}
		})
	}
}

// TestLDAPURLParseAcceptsOriginShapes 正向形狀與解析結果
func TestLDAPURLParseAcceptsOriginShapes(t *testing.T) {
	cases := []struct {
		raw       string
		scheme    string
		host      string
		port      int
		canonical string
	}{
		{"ldap://dir.example", "ldap", "dir.example", 389, "ldap://dir.example:389"},
		{"ldaps://dir.example", "ldaps", "dir.example", 636, "ldaps://dir.example:636"},
		{"ldap://dir.example:1389", "ldap", "dir.example", 1389, "ldap://dir.example:1389"},
		{"LDAP://DIR.Example", "ldap", "dir.example", 389, "ldap://dir.example:389"},
		{"  ldap://dir.example  ", "ldap", "dir.example", 389, "ldap://dir.example:389"},
		{"ldap://192.168.10.5:389", "ldap", "192.168.10.5", 389, "ldap://192.168.10.5:389"},
		{"ldaps://[2001:db8::1]:636", "ldaps", "2001:db8::1", 636, "ldaps://[2001:db8::1]:636"},
		{"ldap://ldap-test:1389", "ldap", "ldap-test", 1389, "ldap://ldap-test:1389"},
		{"ldap://dc_01.corp.example", "ldap", "dc_01.corp.example", 389, "ldap://dc_01.corp.example:389"},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			endpoint, err := ParseLDAPURL(tc.raw)
			if err != nil {
				t.Fatalf("ParseLDAPURL(%q) 非預期錯誤: %v", tc.raw, err)
			}
			if endpoint.Scheme != tc.scheme || endpoint.Host != tc.host || endpoint.Port != tc.port {
				t.Fatalf("解析 = %+v, want scheme=%s host=%s port=%d", endpoint, tc.scheme, tc.host, tc.port)
			}
			if got := endpoint.CanonicalOrigin(); got != tc.canonical {
				t.Errorf("CanonicalOrigin = %q, want %q", got, tc.canonical)
			}
		})
	}
}

// TestLDAPCanonicalOriginEndpointIdentity 端點身分以 canonical origin 判定——
// 字面比較會把 `ldap://h` 與 `ldap://h:389` 誤判為不同端點而誤擋正常存檔
func TestLDAPCanonicalOriginEndpointIdentity(t *testing.T) {
	cases := []struct {
		name string
		a    string
		b    string
		same bool
	}{
		{"預設埠與顯式 389 相等", "ldap://H", "ldap://h:389", true},
		{"ldaps 預設埠與顯式 636 相等", "ldaps://h", "ldaps://h:636", true},
		{"大小寫不影響", "LDAP://Dir.Example:389", "ldap://dir.example", true},
		{"FQDN 尾點不影響", "ldap://dir.example.", "ldap://dir.example", true},
		{"不同埠即不同端點", "ldap://h:389", "ldap://h:1389", false},
		{"不同 scheme 即不同端點", "ldap://h", "ldaps://h", false},
		{"不同主機即不同端點", "ldap://h", "ldap://h2", false},
		{"ldap:636 與 ldaps:636 不同", "ldap://h:636", "ldaps://h", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := ParseLDAPURL(tc.a)
			if err != nil {
				t.Fatalf("解析 %q 失敗: %v", tc.a, err)
			}
			b, err := ParseLDAPURL(tc.b)
			if err != nil {
				t.Fatalf("解析 %q 失敗: %v", tc.b, err)
			}
			if got := SameLDAPEndpoint(a, b); got != tc.same {
				t.Errorf("SameLDAPEndpoint(%q, %q) = %v, want %v（canonical: %q vs %q）",
					tc.a, tc.b, got, tc.same, a.CanonicalOrigin(), b.CanonicalOrigin())
			}
		})
	}
}

// TestLDAPEndpointHelpers 撥號／清單比對用的衍生值
func TestLDAPEndpointHelpers(t *testing.T) {
	endpoint, err := ParseLDAPURL("ldaps://[2001:db8::1]")
	if err != nil {
		t.Fatalf("非預期錯誤: %v", err)
	}
	if got := endpoint.HostPort(); got != "[2001:db8::1]:636" {
		t.Errorf("HostPort = %q, want [2001:db8::1]:636", got)
	}
	if !endpoint.UsesTLS() {
		t.Error("ldaps 應回 UsesTLS()=true")
	}
	if endpoint.PortExplicit {
		t.Error("未指定埠時 PortExplicit 應為 false")
	}

	plain, err := ParseLDAPURL("ldap://dir.example:1389")
	if err != nil {
		t.Fatalf("非預期錯誤: %v", err)
	}
	if plain.UsesTLS() || !plain.PortExplicit || plain.HostPort() != "dir.example:1389" {
		t.Errorf("解析結果不符: %+v", plain)
	}

	// 零值端點不與任何端點相等（避免「未解析」被當成匹配）
	if SameLDAPEndpoint(LDAPEndpoint{}, plain) || SameLDAPEndpoint(plain, LDAPEndpoint{}) {
		t.Error("零值端點不應與任何端點相等")
	}
	if got := (LDAPEndpoint{}).CanonicalOrigin(); got != "" {
		t.Errorf("零值 CanonicalOrigin = %q, want 空字串", got)
	}

	origin, err := LDAPCanonicalOrigin("LDAP://Dir.Example")
	if err != nil || origin != "ldap://dir.example:389" {
		t.Errorf("LDAPCanonicalOrigin = (%q, %v)", origin, err)
	}
	if _, err := LDAPCanonicalOrigin("ldap://u:p@h"); !errors.Is(err, ErrLDAPURLInvalid) {
		t.Errorf("非法輸入應回 ErrLDAPURLInvalid，得 %v", err)
	}
}
