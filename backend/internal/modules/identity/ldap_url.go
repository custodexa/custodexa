package identity

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// LDAP 目錄位址（URL）的單一嚴格文法 parser（ldap-settings-migration D3）。
//
// # 為什麼把文法收斂到 origin 形狀
//
// v1 僅接受 `ldap[s]://host[:port]`——拒絕 userinfo、path、query、fragment、
// 空 host 與超界 port，並設長度上限。兩個理由：
//
//   - `ldap://user:secret@host/...` 形態會把憑證帶進 UI 顯示、錯誤訊息與審計的
//     「目標 URL」欄位。目錄位址是 admin 可寫、且會被回顯與留痕的欄位，容許
//     userinfo 等於開一條「憑證寫進日誌」的常設管道。
//   - path/query/fragment 對 LDAP 撥號毫無意義（go-ldap 只取 host:port），
//     卻讓不同層各自 parse 時的行為差異有處可藏，擴大 parser 差異繞過面。
//
// # 唯一解析點
//
// **存檔驗證、端點身分比較與 egress 輸入三者共用本函式的同一份解析結果**；
// 不同路徑各自 parse 會出現「檢查對象與撥號對象不同」的繞過。撥號層無法字面
// 共用本結構（`ldap.DialURL` 內部自行 parse 字串），故撥號層的保證改由
// `LDAPEgressPolicy` 的 `net.Dialer.Control` 提供——檢查發生在名稱解析之後、
// 實際 connect 之前，對象是即將連線的實際位址，不依賴「傳進去的是同一個 struct」。
// 兩者合起來涵蓋 parser 差異與 DNS 變動兩種繞過。
//
// # 端點身分一律比 canonical origin，不比字面
//
// scheme 與 host 小寫、port 空缺補協定預設（389/636）、去除 FQDN 尾點。
// 字面（byte-equal）比較會把 `ldap://h` 與 `ldap://h:389` 誤判為兩個端點，
// 使「URL 變更即強制重供 bind 密碼」的規則對根本沒換位址的存檔誤擋。

const (
	// ldapURLMaxLen URL 長度上限。DB 欄位為 size:500，此處取更嚴的 255——
	// origin 形狀不含 path/query，正常值遠短於此；上限的用途是讓 parser 與
	// 後續回顯／審計欄位有明確界線，而非貼齊儲存極限
	ldapURLMaxLen = 255

	// ldapSchemeDefaultPort／ldapsSchemeDefaultPort 協定預設埠（RFC 4516）
	ldapSchemeDefaultPort  = 389
	ldapsSchemeDefaultPort = 636

	// ldapHostMaxLen 主機名總長上限（RFC 1035）
	ldapHostMaxLen = 253
	// ldapHostLabelMaxLen 單一標籤長上限
	ldapHostLabelMaxLen = 63
)

// ErrLDAPURLInvalid LDAP 目錄位址文法不合法的哨兵錯誤；
// 呼叫端以 errors.Is 判定，細分原因取 LDAPURLError.Reason
var ErrLDAPURLInvalid = errors.New("LDAP 目錄位址格式不合法")

// LDAP URL 拒絕原因（供 API 層對應機器碼；**恆為靜態字串**，
// 不得回填使用者輸入——輸入本身可能含 userinfo 憑證）
const (
	LDAPURLReasonEmpty     = "empty"
	LDAPURLReasonTooLong   = "too_long"
	LDAPURLReasonMalformed = "malformed"
	LDAPURLReasonScheme    = "scheme"
	LDAPURLReasonUserinfo  = "userinfo"
	LDAPURLReasonPath      = "path"
	LDAPURLReasonQuery     = "query"
	LDAPURLReasonFragment  = "fragment"
	LDAPURLReasonHost      = "host"
	LDAPURLReasonPort      = "port"
)

// LDAPURLError 帶拒絕原因的 URL 文法錯誤
type LDAPURLError struct {
	Reason string
}

func (e *LDAPURLError) Error() string {
	return fmt.Sprintf("%v（%s）", ErrLDAPURLInvalid, e.Reason)
}

// Unwrap 使 errors.Is(err, ErrLDAPURLInvalid) 成立
func (e *LDAPURLError) Unwrap() error { return ErrLDAPURLInvalid }

func newLDAPURLError(reason string) error { return &LDAPURLError{Reason: reason} }

// LDAPEndpoint 解析後的目錄端點。零值代表「未解析」（IsZero 為真）
type LDAPEndpoint struct {
	// Scheme 恆為小寫的 ldap 或 ldaps
	Scheme string
	// Host 小寫主機名或 IP 字面值（IPv6 不含方括號），已去 FQDN 尾點
	Host string
	// Port 實際埠；輸入未指定時為協定預設（389／636）
	Port int
	// PortExplicit 輸入是否顯式帶埠。僅供回顯／診斷，**不參與端點身分比較**
	PortExplicit bool
}

// IsZero 是否為未解析的零值
func (e LDAPEndpoint) IsZero() bool { return e.Scheme == "" }

// hostLiteral IPv6 需方括號才能與埠併寫
func (e LDAPEndpoint) hostLiteral() string {
	if strings.Contains(e.Host, ":") {
		return "[" + e.Host + "]"
	}
	return e.Host
}

// CanonicalOrigin 端點身分的唯一判準：scheme 小寫＋host 小寫＋埠恆顯式。
// 兩個 URL 指向同一端點 ⟺ CanonicalOrigin 相等
func (e LDAPEndpoint) CanonicalOrigin() string {
	if e.IsZero() {
		return ""
	}
	return fmt.Sprintf("%s://%s:%d", e.Scheme, e.hostLiteral(), e.Port)
}

// HostPort 撥號／loopback 允許清單比對用的 host:port
func (e LDAPEndpoint) HostPort() string {
	if e.IsZero() {
		return ""
	}
	return net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

// UsesTLS 是否為 ldaps（隱式 TLS）
func (e LDAPEndpoint) UsesTLS() bool { return e.Scheme == "ldaps" }

// ldapHostPattern ASCII 主機名標籤。**刻意不接受非 ASCII**：
// 未經 punycode 正規化的國際化網域會使 canonical origin 比較出現同形異碼
// （homograph）縫隙，而目錄伺服器位址不需要這項能力
var ldapHostPattern = regexp.MustCompile(`^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$`)

// ParseLDAPURL 解析並驗證目錄位址，回傳結構化端點。
//
// 僅接受 origin 形狀 `ldap[s]://host[:port]`；任何 userinfo／path／query／
// fragment／空 host／超界 port 一律拒絕（見檔頭理由）
func ParseLDAPURL(raw string) (LDAPEndpoint, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonEmpty)
	}
	if len(trimmed) > ldapURLMaxLen {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonTooLong)
	}
	// 內含空白／控制字元者不進 url.Parse——不同 parser 對其容忍度不一，
	// 正是文法收斂要消除的差異面
	if strings.ContainsAny(trimmed, " \t\r\n\v\f") {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonMalformed)
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonMalformed)
	}
	// scheme 先判：`dir.example:389`（缺 scheme 的常見誤填）會被 net/url 解為
	// scheme=dir.example＋opaque=389，先判 scheme 才能回出對使用者有意義的原因
	scheme := strings.ToLower(u.Scheme)
	if scheme != "ldap" && scheme != "ldaps" {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonScheme)
	}
	// opaque（`ldap:host` 這類缺 `//` 的形態）非 origin 形狀
	if u.Opaque != "" {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonMalformed)
	}
	// userinfo 先於其他成分判定：其存在本身即是憑證外洩管道
	if u.User != nil {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonUserinfo)
	}
	// 連單一 "/" 的空 path 也拒——origin 形狀不含 path 成分，
	// 允許「無資訊的 path」等於讓每層各自決定要不要 strip
	if u.Path != "" || u.RawPath != "" {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonPath)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonQuery)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonFragment)
	}

	// 尾隨冒號（`ldap://host:`）：net/url 視為合法的空埠，但語義曖昧，一律拒
	if strings.HasSuffix(u.Host, ":") {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonPort)
	}

	host := strings.ToLower(u.Hostname())
	// FQDN 尾點去除：`h.` 與 `h` 解析到同一目標，保留尾點會使端點比較誤判為不同
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonHost)
	}
	if strings.HasPrefix(u.Host, "[") {
		// 方括號形式只接受合法 IP 字面值
		if ip := net.ParseIP(host); ip == nil {
			return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonHost)
		}
	} else if !isValidLDAPHostname(host) {
		return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonHost)
	}

	port := ldapSchemeDefaultPort
	if scheme == "ldaps" {
		port = ldapsSchemeDefaultPort
	}
	explicit := false
	if raw := u.Port(); raw != "" {
		n, convErr := strconv.Atoi(raw)
		if convErr != nil || n < 1 || n > 65535 {
			return LDAPEndpoint{}, newLDAPURLError(LDAPURLReasonPort)
		}
		port = n
		explicit = true
	}

	return LDAPEndpoint{Scheme: scheme, Host: host, Port: port, PortExplicit: explicit}, nil
}

// isValidLDAPHostname ASCII 主機名／IPv4 字面值檢查（長度＋字元集）
func isValidLDAPHostname(host string) bool {
	if len(host) > ldapHostMaxLen {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) > ldapHostLabelMaxLen {
			return false
		}
	}
	return ldapHostPattern.MatchString(host)
}

// LDAPCanonicalOrigin 解析後直接取 canonical origin 的便利函式
func LDAPCanonicalOrigin(raw string) (string, error) {
	endpoint, err := ParseLDAPURL(raw)
	if err != nil {
		return "", err
	}
	return endpoint.CanonicalOrigin(), nil
}

// SameLDAPEndpoint 端點身分比較的唯一判準（canonical origin 相等）。
// 兩者皆須為已解析端點；任一為零值即視為不同端點
func SameLDAPEndpoint(a, b LDAPEndpoint) bool {
	if a.IsZero() || b.IsZero() {
		return false
	}
	return a.CanonicalOrigin() == b.CanonicalOrigin()
}
