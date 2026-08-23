package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 出站信任邊界的完整格點。
//
// 既有覆蓋只有 oidc_verify_test.go 的 TestDiscoveryBlockedByEgressPolicy 一格
//（未放行 loopback 時 discovery 被擋）與 oidc_provider_service_test.go 的
// TestOIDCProviderReleaseModeRejectsHTTPIssuer（release 拒 http issuer），
// 兩者都只斷言「有錯誤」，**沒有任何一格證明拒絕發生在 socket 建立之前**。
//
// 那個差別是本檔存在的理由：SSRF 的傷害在「連上去」那一刻就已造成
//（雲端 metadata 端點只要一個 GET 就吐出執行個體憑證；內網服務只要收到 TCP
// 連線就可能有副作用）。「連上去、拿到回應、然後在應用層丟棄」與「根本沒連」
// 在錯誤訊息上完全一樣，只有連線計數分得出來。故本檔一律以**可觀測的
// fake listener**（countingListener 計 Accept、handler 計請求）斷言零連線。
//
// 突變自檢（任一即應轉紅）：
//   - 把 oidc_egress.go 的位址檢查自 DialContext 移到請求前的 LookupHost：
//     TestEgressBlocksDNSNameResolvingToPrivateIP 的語義基礎消失（該測試仍綠，
//     但 rebinding 窗口回歸——故另以 isBlockedEgressIP 表格與零連線斷言鎖住）。
//   - 把 `if !allowed && isBlockedEgressIP(...)` 改成 `if !allowed` 之外的任何放寬
//     （例如漏掉 IsPrivate 或 IsLinkLocalUnicast）→ 對應格點轉紅。
//   - 讓 HTTPClient 帶上 CheckRedirect 的放行、或 TLS skip-verify → 對應格點轉紅。
//   - 把 dial 目標改回主機名（＝連線時再解析一次）→ oidc_egress_rebinding_test.go
//     的 TestEgressResolvesOnceAndDialsVerifiedAddress 轉紅（本檔的格點抓不到它，
//     因為真實 DNS 造不出「兩次查詢不同答案」）。

// --- 可觀測的 fake listener ---

// countingListener 計 Accept 次數：**「拒絕發生在 socket 建立前」的唯一可觀測證據**。
// 錯誤型別只能證明應用層拒絕了，證明不了底下沒有 TCP 連線
type countingListener struct {
	net.Listener
	accepts atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return c, err
}

func (l *countingListener) count() int64 { return l.accepts.Load() }

// egressProbe 一台綁在指定位址的觀測伺服器：連線數與請求數各自可讀
type egressProbe struct {
	srv      *httptest.Server
	listener *countingListener
	hits     atomic.Int64
}

// newEgressProbe 於 host 上啟一台計數伺服器（tls=true 時走自簽憑證）。
// handler 為 nil 時回 200 與固定內容
func newEgressProbe(t *testing.T, host string, tls bool, handler http.HandlerFunc) *egressProbe {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("在 %s 上開啟監聽失敗: %v", host, err)
	}
	probe := &egressProbe{listener: &countingListener{Listener: ln}}
	probe.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probe.hits.Add(1)
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	probe.srv.Listener = probe.listener
	if tls {
		probe.srv.StartTLS()
	} else {
		probe.srv.Start()
	}
	t.Cleanup(probe.srv.Close)
	return probe
}

func (p *egressProbe) url() string     { return p.srv.URL }
func (p *egressProbe) accepts() int64  { return p.listener.count() }
func (p *egressProbe) requests() int64 { return p.hits.Load() }
func (p *egressProbe) hostPort() string {
	return strings.TrimPrefix(strings.TrimPrefix(p.srv.URL, "https://"), "http://")
}

// port 取回本探針監聽的埠（供以主機名重新定址同一個 socket）
func (p *egressProbe) port() string {
	_, port, err := net.SplitHostPort(p.hostPort())
	if err != nil {
		return ""
	}
	return port
}

// assertNoContact 斷言該探針從未被連上（零 TCP 連線、零 HTTP 請求）
func (p *egressProbe) assertNoContact(t *testing.T, why string) {
	t.Helper()
	if n := p.accepts(); n != 0 {
		t.Errorf("%s：目標接受了 %d 個 TCP 連線，拒絕未發生在 socket 建立前", why, n)
	}
	if n := p.requests(); n != 0 {
		t.Errorf("%s：目標收到 %d 個 HTTP 請求", why, n)
	}
}

// privateIPv4 取本機非 loopback 的私有 IPv4（容器內為 eth0 的 172.x）。
// 找不到時回空字串——測試以 t.Fatal 中止而非跳過，避免「環境沒有私網位址」
// 靜默變成假綠
func privateIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("列舉網路介面失敗: %v", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil || ip.IsLoopback() || !ip.IsPrivate() {
			continue
		}
		return ip.String()
	}
	t.Fatal("本機找不到私有 IPv4 位址：測試須在 docker compose 內執行（容器 eth0 為 172.16/12 網段）")
	return ""
}

// --- 4.13 格點 ---

// TestEgressBlocksLoopbackBeforeSocket 4.13：loopback 目標於 socket 建立前即拒
func TestEgressBlocksLoopbackBeforeSocket(t *testing.T) {
	probe := newEgressProbe(t, "127.0.0.1", false, nil)
	policy := &OIDCEgressPolicy{} // release 組態：無任何放行

	_, err := policy.HTTPClient().Get(probe.url())
	if !errors.Is(err, ErrOIDCEgressBlocked) {
		t.Fatalf("loopback 目標應被出站政策擋下，實得 %v", err)
	}
	probe.assertNoContact(t, "未放行的 loopback")
}

// TestEgressBlocksPrivateAddressBeforeSocket 4.13：私有網段目標於 socket 建立前即拒。
//
// 與 loopback 分開一格是必要的：兩者由 isBlockedEgressIP 的不同判定式攔下
// （IsLoopback vs IsPrivate），只測 loopback 時「漏掉 IsPrivate」的突變不會轉紅，
// 而內網 IdP 網段正是 SSRF 最想到達的地方
func TestEgressBlocksPrivateAddressBeforeSocket(t *testing.T) {
	probe := newEgressProbe(t, privateIPv4(t), false, nil)
	policy := &OIDCEgressPolicy{}

	_, err := policy.HTTPClient().Get(probe.url())
	if !errors.Is(err, ErrOIDCEgressBlocked) {
		t.Fatalf("私有網段目標應被擋下，實得 %v", err)
	}
	probe.assertNoContact(t, "未放行的私有網段")
}

// TestEgressBlockedAddressMatrix 4.13：位址判定的封閉格點。
//
// 169.254.169.254（雲端 metadata）是最重要的一格——取得執行個體憑證只需一個 GET
func TestEgressBlockedAddressMatrix(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1", // loopback
		"169.254.169.254", "169.254.1.1", "fe80::1", // link-local（含雲端 metadata）
		"10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1", // 私有網段
		"0.0.0.0", "::", // 未指定
		"fc00::1", "fd12:3456::1", // IPv6 unique local
		// 這幾格：Go 的 IsPrivate 不涵蓋這幾段，但它們同樣
		// 不可能是正當的 IdP，且都能到達內部資源
		"100.64.0.1", "100.100.100.200", "100.127.255.254", // CGNAT（RFC 6598；阿里雲 metadata 亦在此段）
		"0.1.2.3", "0.255.255.255", // 0.0.0.0/8「本網路」：多數堆疊視同本機
		"255.255.255.255",         // 受限廣播
		"fec0::1", "feff:ffff::1", // 已廢止的 IPv6 site-local（RFC 3879）
	}
	for _, s := range blocked {
		if !isBlockedEgressIP(net.ParseIP(s), false) {
			t.Errorf("%s 應被判定為禁止出站目標", s)
		}
	}
	// 公網位址不得被誤擋——否則政策等於停用 OIDC 本身。
	// 100.63.x 與 100.128.x 是 CGNAT 段的上下緊鄰，鎖住 /10 的遮罩不得寫成 /8
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "142.250.1.1", "2001:4860:4860::8888",
		"100.63.255.255", "100.128.0.1", "1.0.0.1", "254.255.255.255", "fe00::1"} {
		if isBlockedEgressIP(net.ParseIP(s), false) {
			t.Errorf("%s 為公網位址，不應被擋", s)
		}
	}
	// nil（解析不出位址）一律視為禁止：fail-secure
	if !isBlockedEgressIP(nil, false) {
		t.Error("無法解析的位址應 fail-secure 判定為禁止")
	}
}

// TestOIDCEgressUnaffectedByAllowPrivateParameterization
// 守衛：isBlockedEgressIP 因 LDAP 而參數化（allowPrivate），**OIDC 側行為必須零變更**。
//
// 本測試的存在理由是「共用安全函式被第二個呼叫端改動」這個具體風險：LDAP 需要放行
// 私網，若參數預設值搞反、或 OIDC 呼叫端被順手改成 true，OIDC 的 default-deny-private
// 就會靜默消失而所有既有 OIDC 測試仍全綠（它們斷言的是「私網被擋」，而擋的來源可能
// 被誤判為 AllowedInternalHosts）。故此處直接對呼叫端傳入的參數值本身做斷言：
// **allowPrivate=false（OIDC 用值）下，私有網段一格都不許放行**。
func TestOIDCEgressUnaffectedByAllowPrivateParameterization(t *testing.T) {
	// OIDC 用值：私網全數封鎖（參數化前後行為必須逐格相同）
	for _, s := range []string{
		"10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254",
		"192.168.0.1", "192.168.255.254", "fc00::1", "fd12:3456::1",
	} {
		if !isBlockedEgressIP(net.ParseIP(s), false) {
			t.Errorf("OIDC 呼叫端（allowPrivate=false）下 %s 必須被擋——default-deny-private 已失效", s)
		}
	}
	// LDAP 用值：僅「私有網段」一項放寬，其餘禁區照擋（放寬範圍不得外溢）
	for _, s := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "fc00::1", "fd12:3456::1"} {
		if isBlockedEgressIP(net.ParseIP(s), true) {
			t.Errorf("LDAP 呼叫端（allowPrivate=true）下 %s 應放行（目錄常態位置為內網）", s)
		}
	}
	for _, s := range []string{
		"127.0.0.1", "::1", // loopback（LDAP 側另由允許清單處理，共用函式仍須判為禁止）
		"169.254.169.254", "fe80::1", // link-local 含雲端 metadata
		"0.0.0.0", "::", "0.1.2.3", // unspecified 與 0.0.0.0/8
		"100.64.0.1", "100.100.100.200", // CGNAT（阿里雲 metadata）：非企業內網，不隨 allowPrivate 放寬
		"255.255.255.255", "fec0::1", // 受限廣播與已廢止 site-local
	} {
		if !isBlockedEgressIP(net.ParseIP(s), true) {
			t.Errorf("allowPrivate=true 只放寬私有網段，%s 仍必須被擋", s)
		}
	}
	if !isBlockedEgressIP(nil, true) {
		t.Error("allowPrivate=true 下 nil 仍須 fail-secure 判定為禁止")
	}
}

// TestOIDCPolicyStillDeniesPrivateHostEndToEnd 守衛（端到端形態）：OIDC 政策對私網
// 目標仍在 socket 建立前拒絕。與上一格的差別是它走完整的 HTTPClient 路徑——
// 即使有人把 oidc_egress.go 的呼叫端參數改成 true，這一格也會轉紅
func TestOIDCPolicyStillDeniesPrivateHostEndToEnd(t *testing.T) {
	probe := newEgressProbe(t, privateIPv4(t), false, nil)
	policy := &OIDCEgressPolicy{}

	//nolint:bodyclose // 政策拒絕時無回應本體
	_, err := policy.HTTPClient().Get(probe.url())
	if !errors.Is(err, ErrOIDCEgressBlocked) {
		t.Fatalf("OIDC 對私網目標必須維持 default-deny，實得 %v", err)
	}
	probe.assertNoContact(t, "參數化後的 OIDC 私網目標")
}

// TestEgressBlocksCloudMetadataEndpoint 4.13：對 169.254.169.254 的請求在 dial 內即拒。
//
// 該位址無法在測試中架設監聽，故以錯誤型別斷言——ErrOIDCEgressBlocked 只可能
// 由 DialContext 在 dialer.DialContext 之前回傳，其存在本身即證明未建立 socket
func TestEgressBlocksCloudMetadataEndpoint(t *testing.T) {
	policy := &OIDCEgressPolicy{}
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://[fd00:ec2::254]/latest/meta-data/",
	} {
		_, err := policy.HTTPClient().Get(target)
		if !errors.Is(err, ErrOIDCEgressBlocked) {
			t.Errorf("%s 應被出站政策擋下，實得 %v", target, err)
		}
	}
}

// TestEgressBlocksDNSNameResolvingToPrivateIP 4.13：公網型 DNS 名稱解析至私網位址
// （DNS rebinding）於 socket 建立前即拒。
//
// **這是整份政策最關鍵的一格**：設定階段看到的是一個主機名，位址由 DNS 決定，
// 攻擊者只要讓該名稱在連線當下解析到內網位址即可。檢查放在 DialContext 內
// （名稱解析與連線同一次 dial）就沒有 TOCTOU 窗口。
// 容器內以自身 hostname 取得「名稱 → 私有 IP」的真實 DNS 事實，不需外部網路
func TestEgressBlocksDNSNameResolvingToPrivateIP(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("取得主機名失敗: %v", err)
	}
	ips, err := net.LookupIP(hostname)
	if err != nil {
		t.Fatalf("主機名 %q 無法解析（測試須在 docker compose 內執行）: %v", hostname, err)
	}
	var private string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && v4.IsPrivate() {
			private = v4.String()
			break
		}
	}
	if private == "" {
		t.Fatalf("主機名 %q 未解析到私有 IPv4（實得 %v）：本格點的前提不成立", hostname, ips)
	}

	// 目標實際綁在該私有位址上；請求則以**主機名**定址，走完整的名稱解析路徑
	probe := newEgressProbe(t, private, false, nil)
	policy := &OIDCEgressPolicy{}

	target := fmt.Sprintf("http://%s/discovery", net.JoinHostPort(hostname, probe.port()))
	_, err = policy.HTTPClient().Get(target)
	if !errors.Is(err, ErrOIDCEgressBlocked) {
		t.Fatalf("解析至私網的主機名應被擋下，實得 %v", err)
	}
	if !strings.Contains(fmt.Sprint(err), private) {
		t.Errorf("錯誤訊息應指出實際解析到的位址 %s（供管理者診斷），實得 %v", private, err)
	}
	probe.assertNoContact(t, "DNS 解析至私網的目標")
}

// TestEgressRedirectToPrivateHostIsBlocked 4.13：redirect 至私網於 socket 建立前即拒。
//
// 第一跳是合法且已放行的公網 IdP，它回一個 302 指向內網——若政策只在第一次
// 請求前檢查，後續每一跳都不受管。Go 的 http.Client 自動跟隨 redirect，每一跳
// 都走同一個 Transport，故檢查落在 DialContext 才會逐跳生效
func TestEgressRedirectToPrivateHostIsBlocked(t *testing.T) {
	internal := newEgressProbe(t, privateIPv4(t), false, nil)
	hop := newEgressProbe(t, "127.0.0.1", false, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.url()+"/latest/meta-data", http.StatusFound)
	})

	// 第一跳顯式放行、redirect 目標未放行：證明放行是**逐主機**而非全域開關
	policy := &OIDCEgressPolicy{AllowedInternalHosts: []string{"127.0.0.1"}}

	_, err := policy.HTTPClient().Get(hop.url() + "/.well-known/openid-configuration")
	if !errors.Is(err, ErrOIDCEgressBlocked) {
		t.Fatalf("redirect 至私網應被擋下，實得 %v", err)
	}
	if hop.requests() == 0 {
		t.Fatal("第一跳應確實被請求（前提不成立則本測試沒有驗到 redirect 這一段）")
	}
	internal.assertNoContact(t, "redirect 指向的私網目標")
}

// TestEgressAllowlistHitPermitsExactHostOnly 4.13：allowlist 命中與否兩側。
//
// 命中側必須真的通得過——否則內網 IdP 場景無解，部署層就會去找「關閉檢查」的
// 開關（那正是設計要避免的）。未命中側必須擋住，且放行不得外溢到其他內部位址
func TestEgressAllowlistHitPermitsExactHostOnly(t *testing.T) {
	allowed := newEgressProbe(t, "127.0.0.1", false, nil)
	other := newEgressProbe(t, privateIPv4(t), false, nil)

	policy := &OIDCEgressPolicy{AllowedInternalHosts: []string{"127.0.0.1"}}

	resp, err := policy.HTTPClient().Get(allowed.url())
	if err != nil {
		t.Fatalf("已放行的內部主機應可連線: %v", err)
	}
	_ = resp.Body.Close()
	if allowed.accepts() == 0 || allowed.requests() == 0 {
		t.Errorf("放行主機的連線數/請求數 = %d/%d, 皆應 > 0", allowed.accepts(), allowed.requests())
	}

	// 同一份政策下的另一個內部位址不得沾光
	if _, err := policy.HTTPClient().Get(other.url()); !errors.Is(err, ErrOIDCEgressBlocked) {
		t.Fatalf("未列於清單的內部位址應仍被擋，實得 %v", err)
	}
	other.assertNoContact(t, "未列於允許清單的內部位址")

	// 未放行時同一個目標必被擋（命中與否的對照組；缺此對照時「政策形同虛設」不會轉紅）
	empty := &OIDCEgressPolicy{}
	if _, err := empty.HTTPClient().Get(allowed.url()); !errors.Is(err, ErrOIDCEgressBlocked) {
		t.Fatalf("未放行時同一目標應被擋，實得 %v", err)
	}

	// dev 靶機清單（AllowInsecureHosts）同時視為已放行的內部主機
	dev := &OIDCEgressPolicy{AllowInsecureHosts: []string{"127.0.0.1"}}
	resp2, err := dev.HTTPClient().Get(allowed.url())
	if err != nil {
		t.Fatalf("dev 靶機主機應可連線: %v", err)
	}
	_ = resp2.Body.Close()
}

// TestEgressRejectsSelfSignedTLS 4.13：自簽 TLS 被拒（不提供 skip-verify 開關）。
//
// TLS 握手在 TCP 之後，故本格點的斷言不是「零連線」而是「零 HTTP 請求」——
// 憑證驗證失敗必須發生在任何應用層資料往返之前
func TestEgressRejectsSelfSignedTLS(t *testing.T) {
	probe := newEgressProbe(t, "127.0.0.1", true, nil)
	policy := &OIDCEgressPolicy{AllowedInternalHosts: []string{"127.0.0.1"}}

	_, err := policy.HTTPClient().Get(probe.url())
	if err == nil {
		t.Fatal("自簽憑證的 IdP 應被系統信任庫拒絕")
	}
	msg := fmt.Sprint(err)
	if !strings.Contains(msg, "x509") && !strings.Contains(msg, "certificate") {
		t.Errorf("錯誤應源自憑證驗證，實得 %v", err)
	}
	if n := probe.requests(); n != 0 {
		t.Errorf("憑證驗證失敗後不得有任何 HTTP 請求送達，實得 %d", n)
	}
}

// TestReleaseModeHTTPIssuerRejectedWithoutAnyDial 4.13：release 模式 http issuer 被拒，
// 且**設定階段完全不出站**。
//
// 既有的 TestOIDCProviderReleaseModeRejectsHTTPIssuer 已驗錯誤型別，此處補的是
// 零連線：驗證若在拒絕之前先去 fetch discovery，管理者輸入的任意 http URL 就成了
// 一個未經驗證的出站觸發器（連 issuer scheme 都還沒過關）
func TestReleaseModeHTTPIssuerRejectedWithoutAnyDial(t *testing.T) {
	probe := newEgressProbe(t, "127.0.0.1", false, nil)
	release := &OIDCEgressPolicy{}

	httpIssuer := "http://" + probe.hostPort() + "/dex"
	if err := release.ValidateIssuerURL(httpIssuer); !errors.Is(err, ErrOIDCIssuerScheme) {
		t.Fatalf("release 模式的 http issuer → %v, want ErrOIDCIssuerScheme", err)
	}
	probe.assertNoContact(t, "release 模式拒絕 http issuer")

	// 形狀不合法者亦於設定階段即拒，同樣零出站
	for label, raw := range map[string]string{
		"帶 userinfo": "https://user:pw@" + probe.hostPort(),
		"帶 query":    "https://" + probe.hostPort() + "?tenant=a",
		"帶 fragment": "https://" + probe.hostPort() + "#f",
		"無主機":        "https:///path",
	} {
		if err := release.ValidateIssuerURL(raw); !errors.Is(err, ErrOIDCIssuerShape) {
			t.Errorf("%s → %v, want ErrOIDCIssuerShape", label, err)
		}
	}
	probe.assertNoContact(t, "形狀不合法的 issuer")

	// 合法的 https issuer 於驗證階段一樣不出站（驗證純屬語法判定）
	if err := release.ValidateIssuerURL("https://" + probe.hostPort()); err != nil {
		t.Fatalf("https issuer 應通過形狀與 scheme 驗證: %v", err)
	}
	probe.assertNoContact(t, "合法 https issuer 的設定階段驗證")

	// 非 release 且列於 dev 靶機清單者為唯一 http 例外——同樣不出站
	dev := &OIDCEgressPolicy{AllowInsecureHosts: []string{"127.0.0.1"}}
	if err := dev.ValidateIssuerURL(httpIssuer); err != nil {
		t.Fatalf("dev 靶機的 http issuer 應被接受: %v", err)
	}
	probe.assertNoContact(t, "dev 靶機 http issuer 的設定階段驗證")
}

// TestDiscoveryEgressBlockNeverContactsTarget 4.13：走完整 discovery 路徑時，
// 出站政策的拒絕同樣發生在 socket 建立前。
//
// 前面的格點都直接驅動 OIDCEgressPolicy；此格點證明 OIDCDiscoveryService 確實
// 使用該 client（而非另建一個沒有政策的 http.Client）——既有的
// TestDiscoveryBlockedByEgressPolicy 只斷言錯誤型別，接不到「有連上去但丟棄回應」
func TestDiscoveryEgressBlockNeverContactsTarget(t *testing.T) {
	probe := newEgressProbe(t, "127.0.0.1", false, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	svc := NewOIDCDiscoveryService(&OIDCEgressPolicy{})
	p := &model.OIDCProvider{Issuer: probe.url(), ClientID: "cid", Enabled: true}
	p.ID = 4013

	_, err := svc.OAuth2Config(context.Background(), p, "secret", "https://bastion.example.com/cb")
	if !errors.Is(err, ErrOIDCDiscoveryFailed) {
		t.Fatalf("discovery 應失敗於出站政策，實得 %v", err)
	}
	if !strings.Contains(fmt.Sprint(err), ErrOIDCEgressBlocked.Error()) {
		t.Fatalf("錯誤應源自出站位址政策，實得 %v", err)
	}
	probe.assertNoContact(t, "discovery 的出站目標")
}
