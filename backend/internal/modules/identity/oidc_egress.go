package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrOIDCIssuerScheme issuer 或對外基準網址未使用 https
	ErrOIDCIssuerScheme = errors.New("issuer 必須使用 https")
	// ErrOIDCIssuerShape issuer 形狀不合法（帶 userinfo／query／fragment）
	ErrOIDCIssuerShape = errors.New("issuer 不得包含使用者資訊、查詢字串或片段")
	// ErrOIDCEgressBlocked 出站目標解析至不允許的位址
	ErrOIDCEgressBlocked = errors.New("身分提供者位址不在允許範圍（內部網段需經明確允許清單放行）")
)

// oidcEgressTimeout 對 IdP 的出站逾時：discovery/JWKS/token 皆屬登入路徑，
// 目錄無回應時不可拖垮登入端點（比照 LDAP 的 5 秒設計）
const oidcEgressTimeout = 10 * time.Second

// OIDCEgressPolicy 對身分提供者的出站信任邊界。
//
// **不做「endpoint 必須與 issuer 同源」的限制**——該限制曾出現在設計草案中，
// 經實查證實會直接阻斷 Google：其 issuer 為 accounts.google.com，但 token endpoint
// 在 oauth2.googleapis.com、JWKS 在 www.googleapis.com、userinfo 在
// openidconnect.googleapis.com，四個不同 host。同源既阻斷必要目標，也擋不住
// 管理者把 issuer 指向內網。
//
// 改以**出站位址政策**防 SSRF：解析後的 IP 不得落在 loopback／link-local
// （含 169.254.169.254 雲端 metadata）／私有網段，且**每次連線時重新檢查**——
// 只在設定時檢查一次擋不住 DNS rebinding（先解析為公網位址、隨後改指內部位址）。
type OIDCEgressPolicy struct {
	// AllowedInternalHosts 明確放行的內部主機名（部署層設定）。
	// 內網 IdP 場景以此顯式放行，而非提供「關閉檢查」的布林開關
	AllowedInternalHosts []string
	// AllowInsecureHosts 非 release 模式的 dev 靶機主機名（允許 http）。
	// release 模式一律為空——無任何例外
	AllowInsecureHosts []string

	// resolver 名稱解析接縫。**生產路徑恆為 nil**（走 net.DefaultResolver）；
	// 唯一的設值者是 _test.go——「同一名稱兩次解析回不同位址」（DNS rebinding）
	// 無法用真實 DNS 在測試中重現，而「解析只發生一次」正是本政策的核心不變式
	resolver func(ctx context.Context, host string) ([]net.IPAddr, error)
	// dial 連線接縫。**生產路徑恆為 nil**（走 net.Dialer）；測試以此觀測
	// 「實際送進 dial 的位址是已驗過的 IP，而非會被再解析一次的主機名」
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ValidateIssuerURL 驗證 issuer 形狀與 scheme（設定階段）。
//
// release 模式下 issuer SHALL 為 https；唯一例外是非 release 模式且列於
// AllowInsecureHosts 的 dev 靶機主機名
func (p *OIDCEgressPolicy) ValidateIssuerURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("issuer 格式不正確: %w", err)
	}
	if u.Host == "" {
		return ErrOIDCIssuerShape
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrOIDCIssuerShape
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && p.isInsecureAllowed(u.Hostname()) {
		return nil
	}
	return ErrOIDCIssuerScheme
}

func (p *OIDCEgressPolicy) isInsecureAllowed(host string) bool {
	for _, h := range p.AllowInsecureHosts {
		if strings.EqualFold(strings.TrimSpace(h), host) {
			return true
		}
	}
	return false
}

func (p *OIDCEgressPolicy) isInternalAllowed(host string) bool {
	for _, h := range p.AllowedInternalHosts {
		if strings.EqualFold(strings.TrimSpace(h), host) {
			return true
		}
	}
	// dev 靶機同時視為已放行的內部主機（其位址必為 loopback）
	return p.isInsecureAllowed(host)
}

// HTTPClient 產生受出站政策約束的 HTTP client。
//
// 位址檢查放在 DialContext——**這是「每次連線重新檢查」的實作點**：若改在請求
// 前用 net.LookupHost 檢查，攻擊者可在檢查與連線之間改變 DNS 回應而繞過。
//
// **名稱只解析一次，連線用的就是驗過的那個 IP**：dial 傳主機名等於再解析一次，
// 兩次查詢之間的 DNS 變動（第一次回公網、第二次回 169.254.169.254）即是 DNS
// rebinding 的窗口。TLS 的 SNI 與憑證驗證仍以 URL 的主機名進行（http.Transport
// 不看 DialContext 實際連到哪個位址），故以 IP 連線不會弱化憑證驗證。
func (p *OIDCEgressPolicy) HTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: oidcEgressTimeout}
	resolve := p.resolver
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return net.DefaultResolver.LookupIPAddr(ctx, host)
		}
	}
	dial := p.dial
	if dial == nil {
		dial = dialer.DialContext
	}
	return &http.Client{
		Timeout: oidcEgressTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				allowed := p.isInternalAllowed(host)
				ips, err := resolve(ctx, host)
				if err != nil {
					return nil, err
				}
				if len(ips) == 0 {
					return nil, fmt.Errorf("%w: %s 無可用位址", ErrOIDCEgressBlocked, host)
				}
				for _, ip := range ips {
					// allowPrivate=false：OIDC 的常態目標是公網 SaaS IdP，私有網段
					// 一律 default-deny（內網 IdP 走 AllowedInternalHosts 顯式放行）。
					// 參數化是為了讓 LDAP 側共用同一份禁區判定，**OIDC 側行為零變更**
					if !allowed && isBlockedEgressIP(ip.IP, false) {
						return nil, fmt.Errorf("%w: %s → %s", ErrOIDCEgressBlocked, host, ip.IP)
					}
				}
				// **以驗過的位址直接連線，不把主機名再交給 dialer 解析一次**：
				// 傳主機名等於做第二次名稱解析，攻擊者控制的 DNS 只要在兩次查詢間
				// 改變回應（第一次公網、第二次 169.254.169.254）即繞過整個檢查。
				// 代價是失去 dialer 的 Happy Eyeballs：改為依序嘗試已驗證的位址，
				// 全部失敗才回最後一個錯誤
				var lastErr error
				for _, ip := range ips {
					conn, derr := dial(ctx, network, net.JoinHostPort(ip.String(), port))
					if derr == nil {
						return conn, nil
					}
					lastErr = derr
				}
				return nil, lastErr
			},
			// 出站 TLS 一律走系統信任庫驗證；**不提供 skip-verify 開關**
			//（一旦提供 skip-verify 開關，它就會在「先讓它連上」的壓力下被打開並留在生產）。
			// 內網自簽 IdP 由部署層加 CA 解決
			TLSHandshakeTimeout: oidcEgressTimeout,
		},
	}
}

// isBlockedEgressIP 判定位址是否落在禁止的網段（OIDC 與 LDAP 兩政策共用）。
//
// 涵蓋 loopback、link-local（含 169.254.169.254 雲端 metadata 端點——這是
// SSRF 最典型的目標，可取得執行個體的憑證）、私有網段與未指定位址，
// 外加 Go 的 IsPrivate **不涵蓋**但同樣不可能是正當 IdP 的幾段。
//
// allowPrivate 放寬「私有網段」一項且**僅此一項**（RFC1918 與 IPv6 ULA fc00::/7）：
// LDAP/AD 的常態位置就是內網故傳 true，OIDC 的常態是公網 SaaS IdP 故傳 false。
// 刻意不放寬 CGNAT 100.64.0.0/10——該段是電信與
// 雲端業者的共用位址空間而非企業內網，阿里雲的 metadata 端點即在其中；
// 亦不放寬已廢止的 IPv6 site-local（fec0::/10，「已廢止」不等於「連不到」）。
func isBlockedEgressIP(ip net.IP, allowPrivate bool) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	if !allowPrivate && ip.IsPrivate() {
		return true
	}
	// IPv4（含 v4-in-v6 表示）：判完即回，不落入下方的 IPv6 位元判定
	if v4 := ip.To4(); v4 != nil {
		switch {
		// 0.0.0.0/8「本網路」：IsUnspecified 只擋 0.0.0.0 本身，但多數協定堆疊
		// 把整段當成「本機」，0.1.2.3 一樣連得到自己
		case v4[0] == 0:
			return true
		// 100.64.0.0/10 CGNAT（RFC 6598）：電信與雲端業者的共用位址空間，
		// 語義同私網；阿里雲的 metadata 端點即在此段
		case v4[0] == 100 && v4[1]&0xC0 == 64:
			return true
		// 255.255.255.255 受限廣播
		case v4.Equal(net.IPv4bcast):
			return true
		}
		return false
	}
	if len(ip) != net.IPv6len {
		return false
	}
	// IPv6 unique local（fc00::/7）：Go 的 IsPrivate 已涵蓋，此處明示以防日後行為變動。
	// 與 IsPrivate 同屬「私有網段」語義，故同受 allowPrivate 支配
	if ip[0]&0xfe == 0xfc {
		return !allowPrivate
	}
	// fec0::/10 已廢止的 site-local（RFC 3879）：位址已不該出現，但舊堆疊仍會
	// 把它路由到內網——「已廢止」不等於「連不到」
	if ip[0] == 0xfe && ip[1]&0xc0 == 0xc0 {
		return true
	}
	return false
}
