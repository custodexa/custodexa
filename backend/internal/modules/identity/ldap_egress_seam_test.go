package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/custodexa/backend/config"
)

// ldapTestConfig 最小可用的認證器設定（本檔只走到撥號階段，DN/filter 不影響結果）
func ldapTestConfig(url string) config.LDAPConfig {
	return config.LDAPConfig{
		Enabled:      true,
		URL:          url,
		BindDN:       "cn=admin,dc=example,dc=org",
		BindPassword: "irrelevant-for-dial-stage",
		BaseDN:       "ou=users,dc=example,dc=org",
		UserFilter:   "(uid=%s)",
		AttrEmail:    "mail",
		AttrFullName: "cn",
	}
}

// 出站政策的**實作接縫**釘子（ldap-settings-migration tasks 2.5 / D5）。
//
// 判定邏輯正確但接縫沒接上，等於政策不存在。本檔以真實 listener 證明：
//
//  1. 明文 ldap:// 與 ldaps:// **兩條路徑**的 net.Dialer.Control 都會被呼叫
//     （ldaps 經 tls.DialWithDialer，是最容易在依賴升版後悄悄失效的一條）。
//  2. Control 收到的是**已解析的 IP:port**，不是主機名——若哪天收到主機名，
//     「檢查對象即撥號對象」的前提就已破裂（連線時會發生第二次名稱解析）。
//  3. 拒絕發生在 **socket 建立之前**：以 countingListener 的 Accept 計數為證，
//     錯誤型別只能證明應用層拒絕了，證明不了底下沒有 TCP 連線。
//  4. ldaps 的憑證驗證仍以 **URL 主機名**進行，未因位址檢查而改以 IP 驗證或跳過。
//
// 這是防依賴升版行為變動的釘子：go-ldap 若改為自建 dialer、或 crypto/tls 改為
// 不走 netDialer.DialContext，本檔的格點會轉紅而不是靜默失去保護

// ldapSeamListener 一台計數用的 TCP 靶機；tlsCfg 非 nil 時提供 TLS
type ldapSeamListener struct {
	ln *countingListener
	wg sync.WaitGroup
}

// newLDAPSeamListener 於 127.0.0.1 上啟一台靶機並持續 accept。
// 回傳監聽埠；連線僅被握手／保留，不實作 LDAP 協定——本檔要證明的是
// 「連線是否建立」，與 LDAP 協定往返無關
func newLDAPSeamListener(t *testing.T, tlsCfg *tls.Config) (*ldapSeamListener, string) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("開啟 127.0.0.1 監聽失敗: %v", err)
	}
	l := &ldapSeamListener{ln: &countingListener{Listener: raw}}
	var accept net.Listener = l.ln
	if tlsCfg != nil {
		// tls.NewListener 包在計數器之外：Accept 計數仍反映 TCP 層的連線數
		accept = tls.NewListener(l.ln, tlsCfg)
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		for {
			conn, err := accept.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				// 保留連線直到對端關閉：go-ldap 建線後會啟動 reader
				buf := make([]byte, 1)
				_, _ = conn.Read(buf)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = raw.Close()
		l.wg.Wait()
	})
	_, port, err := net.SplitHostPort(raw.Addr().String())
	if err != nil {
		t.Fatalf("取監聽埠失敗: %v", err)
	}
	return l, port
}

func (l *ldapSeamListener) accepts() int64 { return l.ln.count() }

// assertAccepted 斷言靶機恰好接受 want 個連線。
//
// 撥號端返回時伺服端的 accept 可能尚未記到，故先輪詢等待再斷言精確值——
// 定值 sleep 會讓這格在忙碌機器上偶發轉紅（假紅同樣是壞測試）
func (l *ldapSeamListener) assertAccepted(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && l.accepts() < want {
		time.Sleep(10 * time.Millisecond)
	}
	if n := l.accepts(); n != want {
		t.Fatalf("靶機 accept 次數 = %d, want %d", n, want)
	}
}

// seamObserver 記錄 Control 實際收到的位址
type seamObserver struct {
	mu   sync.Mutex
	seen []string
}

func (o *seamObserver) record(_ string, addr string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, addr)
}

func (o *seamObserver) addresses() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]string, len(o.seen))
	copy(out, o.seen)
	return out
}

// assertAllResolvedIPs 斷言每一筆觀測到的位址都是 IP:port（而非主機名:port）
func (o *seamObserver) assertAllResolvedIPs(t *testing.T, why string) {
	t.Helper()
	addrs := o.addresses()
	if len(addrs) == 0 {
		t.Fatalf("%s：Control 從未被呼叫——出站政策根本沒有生效於此路徑", why)
	}
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			t.Fatalf("%s：Control 收到的 %q 不是 host:port", why, a)
		}
		if net.ParseIP(host) == nil {
			t.Fatalf("%s：Control 收到的是主機名 %q——連線時會再解析一次，"+
				"檢查與撥號不是同一個位址（TOCTOU 窗口復活）", why, a)
		}
	}
}

// TestLDAPEgressControlSeamBlocksPlainAndTLSBeforeSocket 兩條協定路徑的核心格點。
//
// 明文與 ldaps 各起一台 loopback 靶機（未列於允許清單），斷言：撥號被出站政策擋下、
// 靶機零 TCP 連線、Control 收到的是已解析 IP:port
func TestLDAPEgressControlSeamBlocksPlainAndTLSBeforeSocket(t *testing.T) {
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedLocalhostCert(t)}}

	cases := []struct {
		name   string
		scheme string
		tlsCfg *tls.Config
	}{
		{"明文 ldap（dialer.Dial 路徑）", "ldap", nil},
		{"ldaps（tls.DialWithDialer 路徑）", "ldaps", tlsCfg},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target, port := newLDAPSeamListener(t, c.tlsCfg)
			obs := &seamObserver{}
			// 允許清單刻意留空：loopback 預設全擋
			p := &LDAPEgressPolicy{observe: obs.record}

			conn, err := p.DialURL(fmt.Sprintf("%s://127.0.0.1:%s", c.scheme, port), false, "seam-test")
			if err == nil {
				conn.Close()
				t.Fatal("未放行的 loopback 目標竟撥號成功——出站政策未生效於此路徑")
			}
			if !errors.Is(err, ErrLDAPEgressBlocked) {
				t.Fatalf("錯誤應可辨識為出站政策拒絕，實得 %v", err)
			}
			obs.assertAllResolvedIPs(t, c.name)
			// 給落後的 accept 一點時間，避免「零連線」是因為還沒被記到
			time.Sleep(50 * time.Millisecond)
			if n := target.accepts(); n != 0 {
				t.Fatalf("靶機接受了 %d 個 TCP 連線：拒絕未發生在 socket 建立前", n)
			}
		})
	}
}

// TestLDAPEgressAllowlistedLoopbackConnects 允許清單放行後連線確實建立。
//
// 反向格點：若政策把所有 loopback 一律擋死（或 Control 恆回錯），本格轉紅——
// 「擋得住」與「擋過頭」都是失敗
func TestLDAPEgressAllowlistedLoopbackConnects(t *testing.T) {
	target, port := newLDAPSeamListener(t, nil)
	obs := &seamObserver{}
	p := &LDAPEgressPolicy{
		AllowedLoopbackEndpoints: []string{net.JoinHostPort("127.0.0.1", port)},
		observe:                  obs.record,
	}

	conn, err := p.DialURL(fmt.Sprintf("ldap://127.0.0.1:%s", port), false, "")
	if err != nil {
		t.Fatalf("已放行的 loopback 端點應可連線，實得 %v", err)
	}
	defer conn.Close()
	obs.assertAllResolvedIPs(t, "已放行的 loopback")
	target.assertAccepted(t, 1)
}

// TestLDAPEgressChecksEveryResolvedCandidate 多候選逐一過 Control。
//
// localhost 在容器內解析為 127.0.0.1 與 ::1 兩個位址；只放行前者時，
// 未放行的候選被拒、放行的候選連線成功——證明判定套用於**每一個候選**而非
// 「解析結果的第一個」。這正是「解析後改變的位址仍被攔截」得以成立的機制
func TestLDAPEgressChecksEveryResolvedCandidate(t *testing.T) {
	ips, err := net.LookupIP("localhost")
	if err != nil {
		t.Fatalf("解析 localhost 失敗: %v", err)
	}
	var hasV4, hasV6 bool
	for _, ip := range ips {
		if ip.To4() != nil {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	if !hasV4 || !hasV6 {
		t.Fatalf("本測試前提為 localhost 同時解析出 IPv4 與 IPv6（容器 /etc/hosts），實得 %v", ips)
	}

	target, port := newLDAPSeamListener(t, nil)
	obs := &seamObserver{}
	// 只放行 IPv4 候選：::1 候選必須被拒，且不得因此使整體撥號失敗
	p := &LDAPEgressPolicy{
		AllowedLoopbackEndpoints: []string{net.JoinHostPort("127.0.0.1", port)},
		observe:                  obs.record,
	}

	conn, err := p.DialURL(fmt.Sprintf("ldap://localhost:%s", port), false, "")
	if err != nil {
		t.Fatalf("放行的候選應可連線，實得 %v", err)
	}
	defer conn.Close()
	obs.assertAllResolvedIPs(t, "多候選")
	// 恰好 1：未放行的候選被 Control 擋在 socket 之前，不會多出一條連線
	target.assertAccepted(t, 1)
}

// TestLDAPSCertificateVerificationUsesURLHost ldaps 憑證驗證不因位址政策而弱化。
//
// 靶機憑證只簽給 localhost（無 IP SAN）。以 ldaps://127.0.0.1:port 撥號時，
// TLS 必須以 **URL 的主機名 127.0.0.1** 驗證而失敗——若實作把 host 改寫為 IP
// 或改用其他名稱驗證，錯誤型別就不會是主機名不符；若跳過驗證，則根本不會有錯。
// 同時 accept 次數為 1：TCP 已建立（Control 放行），失敗確實發生在 TLS 層
func TestLDAPSCertificateVerificationUsesURLHost(t *testing.T) {
	cert := selfSignedLocalhostCert(t)
	target, port := newLDAPSeamListener(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	p := &LDAPEgressPolicy{AllowedLoopbackEndpoints: []string{
		net.JoinHostPort("127.0.0.1", port),
		net.JoinHostPort("localhost", port),
	}}

	conn, err := p.DialURL(fmt.Sprintf("ldaps://127.0.0.1:%s", port), false, "")
	if err == nil {
		conn.Close()
		t.Fatal("憑證未簽給 127.0.0.1，驗證應失敗——出現成功代表憑證驗證已被弱化")
	}
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Fatalf("應為主機名不符錯誤（證明以 URL 主機名驗證），實得 %T: %v", err, err)
	}
	if hostErr.Host != "127.0.0.1" {
		t.Fatalf("驗證所用主機名 = %q, want 127.0.0.1（URL 的主機名）", hostErr.Host)
	}
	// TCP 應已建立（Control 放行）後才於 TLS 層失敗
	target.assertAccepted(t, 1)

	// 以主機名撥號時驗證對象為 localhost：憑證主機名相符，改因自簽 CA 不受信任而失敗
	conn2, err2 := p.DialURL(fmt.Sprintf("ldaps://localhost:%s", port), false, "")
	if err2 == nil {
		conn2.Close()
		t.Fatal("自簽 CA 不在系統信任庫，驗證應失敗")
	}
	if errors.As(err2, &hostErr) {
		t.Fatalf("以 localhost 撥號時不應為主機名不符（憑證即簽給 localhost），實得 %v", err2)
	}
	if !strings.Contains(err2.Error(), "x509") {
		t.Fatalf("應為憑證鏈驗證失敗，實得 %v", err2)
	}
}

// TestLDAPSSkipTLSVerifyStillPassesEgress skip_tls_verify 只影響憑證驗證，
// **不影響出站位址政策**——兩者是各自獨立的閘
func TestLDAPSSkipTLSVerifyStillPassesEgress(t *testing.T) {
	cert := selfSignedLocalhostCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	// 未放行：即使勾了 skip_tls_verify 仍被出站政策擋在 socket 之前
	blocked, blockedPort := newLDAPSeamListener(t, tlsCfg)
	deny := &LDAPEgressPolicy{}
	if conn, err := deny.DialURL(fmt.Sprintf("ldaps://127.0.0.1:%s", blockedPort), true, ""); err == nil {
		conn.Close()
		t.Fatal("skip_tls_verify 不得成為出站位址政策的旁路")
	} else if !errors.Is(err, ErrLDAPEgressBlocked) {
		t.Fatalf("應為出站政策拒絕，實得 %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := blocked.accepts(); n != 0 {
		t.Fatalf("靶機接受了 %d 個 TCP 連線，拒絕未發生在 socket 建立前", n)
	}

	// 已放行：skip_tls_verify 下自簽憑證握手成功，ldaps 路徑端到端可用
	target, port := newLDAPSeamListener(t, tlsCfg)
	allow := &LDAPEgressPolicy{AllowedLoopbackEndpoints: []string{net.JoinHostPort("127.0.0.1", port)}}
	conn, err := allow.DialURL(fmt.Sprintf("ldaps://127.0.0.1:%s", port), true, "")
	if err != nil {
		t.Fatalf("已放行且 skip_tls_verify 的 ldaps 應可連線，實得 %v", err)
	}
	defer conn.Close()
	target.assertAccepted(t, 1)
}

// TestLDAPAuthenticatorDialGoesThroughEgressPolicy 登入路徑確實走同一撥號入口。
//
// 政策只掛在連線測試而登入路徑自建 dialer，是本設計最容易發生的實作退化
// （登入才是攻擊者真正能反覆觸發的路徑）。本格以 loopback URL 直接驗證
func TestLDAPAuthenticatorDialGoesThroughEgressPolicy(t *testing.T) {
	t.Setenv("LDAP_ALLOWED_LOOPBACK_ENDPOINTS", "")
	target, port := newLDAPSeamListener(t, nil)

	auth := NewLDAPAuthenticator(ldapTestConfig(fmt.Sprintf("ldap://127.0.0.1:%s", port)))
	_, err := auth.Authenticate("someone", "some-password")
	if err == nil {
		t.Fatal("撥號應被出站政策擋下")
	}
	if !errors.Is(err, ErrLDAPEgressBlocked) {
		t.Fatalf("登入路徑的撥號錯誤應可辨識為出站政策拒絕，實得 %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := target.accepts(); n != 0 {
		t.Fatalf("登入路徑仍連上了靶機 %d 次：撥號未經出站政策", n)
	}
}

// TestLDAPControlSeamStillAppliesToRawDialURL 依賴行為釘子：直接以 go-ldap 的
// DialWithDialer 驗證 Control 於兩條路徑皆被呼叫。
//
// 與上面的格點差別在於它**不經本專案的政策程式碼**——若 go-ldap 改為忽略傳入的
// dialer（或 ldaps 改走自建 dialer），本格會轉紅，明確指出根因在依賴而非本專案
func TestLDAPControlSeamStillAppliesToRawDialURL(t *testing.T) {
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedLocalhostCert(t)}}
	for _, c := range []struct {
		name   string
		scheme string
		tlsCfg *tls.Config
	}{
		{"ldap", "ldap", nil},
		{"ldaps", "ldaps", tlsCfg},
	} {
		t.Run(c.name, func(t *testing.T) {
			target, port := newLDAPSeamListener(t, c.tlsCfg)
			sentinel := errors.New("control 攔截")
			var mu sync.Mutex
			var seen []string
			d := &net.Dialer{
				Timeout: 2 * time.Second,
				Control: func(_, address string, _ syscall.RawConn) error {
					mu.Lock()
					seen = append(seen, address)
					mu.Unlock()
					return sentinel
				},
			}
			opts := []ldap.DialOpt{ldap.DialWithDialer(d)}
			if c.tlsCfg != nil {
				opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
			}
			conn, err := ldap.DialURL(fmt.Sprintf("%s://127.0.0.1:%s", c.scheme, port), opts...)
			if err == nil {
				conn.Close()
				t.Fatal("Control 回錯時撥號不應成功——go-ldap 未使用傳入的 dialer")
			}
			if !errors.Is(err, sentinel) {
				t.Fatalf("錯誤應源自 Control，實得 %v", err)
			}
			if len(seen) == 0 {
				t.Fatal("Control 未被呼叫：go-ldap 此路徑不再使用傳入的 dialer")
			}
			for _, a := range seen {
				host, _, splitErr := net.SplitHostPort(a)
				if splitErr != nil || net.ParseIP(host) == nil {
					t.Fatalf("Control 收到的 %q 不是已解析的 IP:port", a)
				}
			}
			time.Sleep(50 * time.Millisecond)
			if n := target.accepts(); n != 0 {
				t.Fatalf("Control 回錯後仍建立了 %d 個連線", n)
			}
		})
	}
}

// selfSignedLocalhostCert 產生只簽給 localhost（無 IP SAN）的自簽憑證
func selfSignedLocalhostCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("產生金鑰失敗: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("簽發憑證失敗: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
