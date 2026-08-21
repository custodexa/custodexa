package identity

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrLDAPEgressBlocked 撥號目標落在不允許的位址範圍。
// 對外一律收斂為單一「無法連線」語義（不細分原因），詳見 DialURL 註解
var ErrLDAPEgressBlocked = errors.New("LDAP 目錄位址不在允許範圍")

// LDAPEgressPolicy LDAP 撥號的出站位址政策（ldap-settings-migration D5）。
//
// LDAP URL 自本 change 起成為 admin 可寫的執行期外連位址，**登入與連線測試
// 兩條撥號路徑皆須過本政策**。
//
// # 與 OIDC 政策的差異化（刻意，非疏漏）
//
// OIDC 的常態目標是公網 SaaS IdP，故 default-deny 私有網段；LDAP/AD 的常態
// 位置就是內網（RFC1918／IPv6 ULA），照搬 default-deny 會使每個典型部署都要
// 逐一 env 放行，等於把設定面遷回部署層、與本 change 的目的自相矛盾。
// 故本政策**私有網段預設放行**，仍封鎖 loopback／link-local（含雲端 metadata）／
// unspecified／multicast；雲端 metadata 位於 CGNAT 段者（阿里雲 100.100.100.200）
// 亦封鎖——allowPrivate 只放寬 RFC1918 與 IPv6 ULA，不放寬電信共用位址空間。
//
// loopback 例外一律走 LDAP_ALLOWED_LOOPBACK_ENDPOINTS 顯式放行，
// **不提供關閉檢查的開關**；且該清單只能解除 loopback 的封鎖，
// 對 link-local／metadata／multicast 無效（見 checkDialAddress 的判定順序）。
//
// # 實作接縫：net.Dialer.Control（唯一正解）
//
// go-ldap v3.4.13 的 DialOpt 只有 DialWithDialer 與 DialWithTLSConfig，
// 沒有 OIDC 那種 http.Transport.DialContext 式的自訂撥號函式接縫。照字面移植
// 只會退化成兩種被明文否定的形態：
//
//   - 撥號前先 LookupIP 檢查一次再 DialURL：檢查與連線之間的 DNS 變動即繞過
//     （rebinding 窗口原樣復活）。
//   - 把 URL 的 host 改寫為已驗證的 IP：ldaps 的憑證主機名驗證因此失敗，
//     逼管理員勾 skip_tls_verify——用一個安全機制逼出另一個安全降級。
//
// net.Dialer.Control 在**名稱解析之後、實際 connect 之前**被呼叫，並帶入
// 即將連線的實際位址（net/sock_posix.go 的 ctrlAddr 即已解析的 IP:port），
// 故「檢查對象即撥號對象」，無 TOCTOU 窗口；多 A／AAAA 候選天然涵蓋——
// 每個候選 connect 前都會各過一次 Control。
//
// 兩條路徑共用同一個 *net.Dialer 是已實碼實證的事實（go-ldap conn.go:186 明文、
// :191 的 ldaps 經 tls.DialWithDialer；crypto/tls/tls.go 走 netDialer.DialContext），
// 且 SNI 仍取原 hostname，故 ldaps 憑證驗證不因位址檢查而弱化。
// 此事實由 ldap_egress_seam_test.go 的整合測試釘住（防依賴升版後行為變動）。
type LDAPEgressPolicy struct {
	// AllowedLoopbackEndpoints loopback 例外清單，元素為 host:port 精確比對值
	//（不支援萬用字元、不支援單獨 host）。來源為 LDAP_ALLOWED_LOOPBACK_ENDPOINTS
	AllowedLoopbackEndpoints []string

	// observe 測試觀測接縫：**生產路徑恆為 nil**。唯一設值者是 _test.go，
	// 用以斷言「Control 確實被呼叫、且收到的是已解析的 IP:port 而非主機名」
	observe func(network, address string)
}

// NewLDAPEgressPolicyFromEnv 自環境變數建立政策。
//
// 讀取採字面 key 直接 os.Getenv：env 漂移守衛只認第 0 參數的字串字面值
func NewLDAPEgressPolicyFromEnv() *LDAPEgressPolicy {
	return &LDAPEgressPolicy{
		AllowedLoopbackEndpoints: parseLDAPAllowedLoopbackEndpoints(os.Getenv("LDAP_ALLOWED_LOOPBACK_ENDPOINTS")),
	}
}

// parseLDAPAllowedLoopbackEndpoints 逗號分隔解析；空白項略過
func parseLDAPAllowedLoopbackEndpoints(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// DialURL 以受出站政策約束的 dialer 建立 LDAP 連線（登入與連線測試共用的唯一撥號入口）。
//
// correlationID 為失敗事件的關聯識別碼（連線測試傳 diagnostic_id，登入路徑可傳空）。
// **失敗的粗分類原因（DNS／逾時／拒絕／TLS／出站政策）只寫入伺服端 operational log**，
// 不得進入 API 回應或 admin 可見的審計欄位——回應面收斂為單一「無法連線」碼的部分
// 由連線測試端點（tasks 2.6）接手，本函式只負責保證分類資訊的落點在 log。
func (p *LDAPEgressPolicy) DialURL(rawURL string, skipTLSVerify bool, correlationID string) (*ldap.Conn, error) {
	// 主機名只用於 loopback 允許清單的名稱形式比對；解析失敗不影響位址判定
	//（判定對象恆為 Control 收到的實際位址），故此處不做 URL 文法驗證——
	// 嚴格文法驗證是存檔／測試入口的職責（tasks 2.2）
	requestedHost := ""
	if u, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		requestedHost = u.Hostname()
	}

	opts := []ldap.DialOpt{
		ldap.DialWithDialer(p.dialer(requestedHost, ldapDialTimeout)),
	}
	if skipTLSVerify {
		// 僅供測試環境自簽憑證；風險由傳輸安全政策（清冊／存檔閘／登入閘）治理
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}

	conn, err := ldap.DialURL(rawURL, opts...)
	if err != nil {
		logLDAPDialFailure(correlationID, requestedHost, err)
		return nil, err
	}
	conn.SetTimeout(ldapDialTimeout)
	return conn, nil
}

// dialer 產生帶位址檢查的 dialer。
//
// 檢查放在 Control 而非撥號前的名稱解析——這是「檢查對象即撥號對象」的實作點
func (p *LDAPEgressPolicy) dialer(requestedHost string, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			if p.observe != nil {
				p.observe(network, address)
			}
			return p.checkDialAddress(requestedHost, address)
		},
	}
}

// checkDialAddress 判定即將連線的實際位址是否放行。
//
// 判定順序刻意如此——multicast 先於 loopback 允許清單，確保清單只能解除
// loopback 的封鎖，不會成為其他禁區的萬用鑰匙
func (p *LDAPEgressPolicy) checkDialAddress(requestedHost, address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// 位址形狀不可判定時一律拒絕（fail-secure）
		return fmt.Errorf("%w: 位址無法判定 (%s)", ErrLDAPEgressBlocked, address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Control 收到的必為已解析位址；非 IP 代表接縫語義已變（依賴升版），
		// 此時寧可全面拒絕也不放行未經檢查的目標
		return fmt.Errorf("%w: %s 非已解析位址", ErrLDAPEgressBlocked, address)
	}

	// multicast（含 IPv6 ff00::/8 與 IPv4 224.0.0.0/4）：目錄服務不可能在此，
	// 且允許清單不得放行。註：僅 link-local multicast 由 isBlockedEgressIP 涵蓋，
	// 一般 multicast 的封鎖是 LDAP 側的額外約束，刻意不塞進共用函式以免動到 OIDC 行為
	if ip.IsMulticast() {
		return fmt.Errorf("%w: %s", ErrLDAPEgressBlocked, address)
	}
	if ip.IsLoopback() {
		if p.isAllowedLoopback(requestedHost, ip, port) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrLDAPEgressBlocked, address)
	}
	// allowPrivate=true：私有網段放行，其餘禁區（link-local 含 169.254.169.254、
	// unspecified、0.0.0.0/8、CGNAT 含阿里雲 metadata、受限廣播、已廢止 site-local）照擋
	if isBlockedEgressIP(ip, true) {
		return fmt.Errorf("%w: %s", ErrLDAPEgressBlocked, address)
	}
	return nil
}

// isAllowedLoopback loopback 例外比對：host:port 精確相等，無萬用字元。
//
// 兩種可接受的寫法：已解析位址形式（127.0.0.1:389、[::1]:389）與 URL 主機名形式
// （localhost:389）。後者仍受「實際位址必須是 loopback」約束——放行的是這一組
// host:port，不是該主機名日後可能解析到的任何位址
func (p *LDAPEgressPolicy) isAllowedLoopback(requestedHost string, ip net.IP, port string) bool {
	candidates := []string{net.JoinHostPort(ip.String(), port)}
	if h := strings.ToLower(strings.TrimSpace(requestedHost)); h != "" {
		candidates = append(candidates, net.JoinHostPort(h, port))
	}
	for _, entry := range p.AllowedLoopbackEndpoints {
		norm := normalizeLoopbackEndpoint(entry)
		if norm == "" {
			continue
		}
		for _, c := range candidates {
			if norm == c {
				return true
			}
		}
	}
	return false
}

// normalizeLoopbackEndpoint 正規化清單項；缺 port 或形狀不合法者回空字串（略過而非放行）
func normalizeLoopbackEndpoint(entry string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(entry))
	if err != nil || host == "" || port == "" {
		return ""
	}
	host = strings.ToLower(host)
	// IPv6 的書寫變體（::1 與 0:0:0:0:0:0:0:1）須正規化為同一形式
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return net.JoinHostPort(host, port)
}

// ldapDialFailureClass 撥號失敗的粗分類。
//
// **僅供伺服端 operational log**：階梯式測試回應本身就是內網探測 oracle，
// 再細分撥號失敗原因會提高其解析度。此型別不得出現在 API 回應或 admin 可見審計欄位
type ldapDialFailureClass string

const (
	ldapDialFailureEgress  ldapDialFailureClass = "egress_blocked"
	ldapDialFailureDNS     ldapDialFailureClass = "dns"
	ldapDialFailureTimeout ldapDialFailureClass = "timeout"
	ldapDialFailureRefused ldapDialFailureClass = "refused"
	ldapDialFailureTLS     ldapDialFailureClass = "tls"
	ldapDialFailureOther   ldapDialFailureClass = "other"
)

// classifyLDAPDialError 粗分類撥號錯誤。
//
// 判定順序：出站政策 → DNS → 逾時 → 連線被拒 → TLS → 其他。
// 出站政策必須排最前——它經 net.OpError 包裝後同時可能滿足其他判定
func classifyLDAPDialError(err error) ldapDialFailureClass {
	if err == nil {
		return ldapDialFailureOther
	}
	if errors.Is(err, ErrLDAPEgressBlocked) {
		return ldapDialFailureEgress
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ldapDialFailureDNS
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ldapDialFailureTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ldapDialFailureRefused
	}
	var certErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	if errors.As(err, &certErr) || errors.As(err, &recordErr) ||
		strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:") {
		return ldapDialFailureTLS
	}
	return ldapDialFailureOther
}

// logLDAPDialFailure 將粗分類原因寫入伺服端 operational log 並回傳分類。
//
// correlationID 空字串（登入路徑）以 "-" 記；host 為 URL 主機名，不記憑證與 socket 細節
func logLDAPDialFailure(correlationID, host string, err error) ldapDialFailureClass {
	class := classifyLDAPDialError(err)
	if correlationID == "" {
		correlationID = "-"
	}
	log.Printf("[LDAPEgress] 撥號失敗 correlation_id=%s host=%s class=%s err=%v",
		correlationID, host, class, err)
	return class
}
