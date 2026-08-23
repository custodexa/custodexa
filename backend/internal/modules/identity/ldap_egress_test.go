package identity

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// LDAP 出站位址政策的判定格點。
//
// 與 OIDC 的差異化是本檔的主軸：**私有網段預設放行**（目錄常態位置為內網），
// 但 loopback／link-local（含雲端 metadata）／unspecified／multicast 照擋，
// 且 loopback 例外只能經 LDAP_ALLOWED_LOOPBACK_ENDPOINTS 精確放行。
//
// 突變自檢（任一即應轉紅）：
//   - 把 isBlockedEgressIP 的第二參數自 true 改 false → 私網格點轉紅（等於 LDAP 不可用）
//   - 把允許清單改成前綴／萬用字元比對 → 「不支援萬用字元」格點轉紅
//   - 把允許清單的判定移到 multicast／link-local 之前 → 「清單不得放行其他禁區」格點轉紅
//   - 讓 ParseIP 失敗的位址落入放行 → fail-secure 格點轉紅
//
// 撥號接縫本身（Control 是否真的被呼叫、兩條協定路徑是否都生效）由
// ldap_egress_seam_test.go 以真實 listener 釘住——判定正確但接縫沒接上等於沒有政策

// checkAddr 以政策判定一個「已解析位址」，回傳是否放行
func checkAddr(t *testing.T, p *LDAPEgressPolicy, requestedHost, address string) error {
	t.Helper()
	return p.checkDialAddress(requestedHost, address)
}

// TestLDAPEgressAllowsPrivateNetworks 私網放行——與 OIDC 的核心差異化。
//
// 這一格若轉紅，代表典型部署（AD/OpenLDAP 在 RFC1918 或 docker 網段）全數不可用
func TestLDAPEgressAllowsPrivateNetworks(t *testing.T) {
	p := &LDAPEgressPolicy{}
	for _, addr := range []string{
		"10.0.0.5:389", "10.255.255.254:636",
		"172.16.0.1:389", "172.31.255.254:389",
		"192.168.1.10:389", "192.168.255.254:636",
		"[fc00::1]:389", "[fd12:3456::1]:636", // IPv6 ULA
	} {
		if err := checkAddr(t, p, "dc.corp.example", addr); err != nil {
			t.Errorf("私網目標 %s 應放行（目錄服務常態位置為內網），實得 %v", addr, err)
		}
	}
	// 公網位址亦放行：政策封鎖的是內部要害位址，不是「非私網」
	for _, addr := range []string{"203.0.113.10:636", "[2001:db8::1]:636"} {
		if err := checkAddr(t, p, "ldap.example.com", addr); err != nil {
			t.Errorf("公網目標 %s 應放行，實得 %v", addr, err)
		}
	}
}

// TestLDAPEgressBlocksLoopbackWithoutAllowlist 未列於允許清單的 loopback 一律拒絕
func TestLDAPEgressBlocksLoopbackWithoutAllowlist(t *testing.T) {
	p := &LDAPEgressPolicy{}
	for _, addr := range []string{"127.0.0.1:389", "127.0.0.1:5432", "127.1.2.3:389", "[::1]:389"} {
		err := checkAddr(t, p, "localhost", addr)
		if !errors.Is(err, ErrLDAPEgressBlocked) {
			t.Errorf("loopback 目標 %s 應被出站政策擋下，實得 %v", addr, err)
		}
	}
}

// TestLDAPEgressBlocksInternalHazards 內部要害位址一律拒絕，且**不受允許清單影響**。
//
// 允許清單的名稱是 LOOPBACK_ENDPOINTS 而非 INTERNAL_HOSTS 正是為了這件事：
// 它只能解除 loopback 的封鎖，不得成為 metadata／multicast 的萬用鑰匙
func TestLDAPEgressBlocksInternalHazards(t *testing.T) {
	hazards := []string{
		"169.254.169.254:80", "169.254.1.1:389", "[fe80::1]:389", // link-local 含雲端 metadata
		"0.0.0.0:389", "[::]:389", "0.1.2.3:389", // unspecified 與 0.0.0.0/8
		"100.64.0.1:389", "100.100.100.200:80", // CGNAT（阿里雲 metadata 在此段）
		"255.255.255.255:389",            // 受限廣播
		"[fec0::1]:389",                  // 已廢止的 IPv6 site-local
		"224.0.0.1:389", "239.1.2.3:389", // IPv4 multicast
		"[ff02::1]:389", "[ff05::2]:389", // IPv6 multicast
	}
	// 連「把每一個要害位址都寫進允許清單」都不得放行
	var allowAll []string
	for _, h := range hazards {
		allowAll = append(allowAll, h)
	}
	for _, p := range []*LDAPEgressPolicy{{}, {AllowedLoopbackEndpoints: allowAll}} {
		for _, addr := range hazards {
			err := checkAddr(t, p, "evil.example.com", addr)
			if !errors.Is(err, ErrLDAPEgressBlocked) {
				t.Errorf("要害位址 %s 應被擋（清單長度 %d），實得 %v",
					addr, len(p.AllowedLoopbackEndpoints), err)
			}
		}
	}
}

// TestLDAPEgressLoopbackAllowlistExactMatch 允許清單：host:port 精確比對、無萬用字元
func TestLDAPEgressLoopbackAllowlistExactMatch(t *testing.T) {
	p := &LDAPEgressPolicy{AllowedLoopbackEndpoints: []string{
		"127.0.0.1:389",
		"localhost:1389",
		"[::1]:636",
	}}

	// 位址形式命中
	if err := checkAddr(t, p, "localhost", "127.0.0.1:389"); err != nil {
		t.Errorf("已放行的 127.0.0.1:389 應通過，實得 %v", err)
	}
	// 主機名形式命中（實際位址仍須為 loopback）
	if err := checkAddr(t, p, "localhost", "127.0.0.1:1389"); err != nil {
		t.Errorf("以主機名形式放行的 localhost:1389 應通過，實得 %v", err)
	}
	// IPv6 書寫變體正規化後仍命中
	if err := checkAddr(t, p, "localhost", "[0:0:0:0:0:0:0:1]:636"); err != nil {
		t.Errorf("::1 的書寫變體應正規化後命中，實得 %v", err)
	}

	// 埠不同即不命中——放行的是端點而非主機
	if err := checkAddr(t, p, "localhost", "127.0.0.1:5432"); !errors.Is(err, ErrLDAPEgressBlocked) {
		t.Errorf("埠不同的 127.0.0.1:5432 不得因 127.0.0.1:389 已放行而通過，實得 %v", err)
	}
	// 不同 loopback 位址不命中
	if err := checkAddr(t, p, "localhost", "127.0.0.2:389"); !errors.Is(err, ErrLDAPEgressBlocked) {
		t.Errorf("127.0.0.2:389 未列於清單，不得通過，實得 %v", err)
	}
	// 主機名不同不命中（不做後綴／子網域比對）
	if err := checkAddr(t, p, "evil-localhost", "127.0.0.1:1389"); !errors.Is(err, ErrLDAPEgressBlocked) {
		t.Errorf("主機名 evil-localhost 未列於清單，不得通過，實得 %v", err)
	}
}

// TestLDAPEgressAllowlistRejectsWildcards 萬用字元不被支援，且不得誤放行
func TestLDAPEgressAllowlistRejectsWildcards(t *testing.T) {
	for _, entry := range []string{"*", "*:*", "127.0.0.1:*", "*:389", "127.0.0.1", "localhost"} {
		p := &LDAPEgressPolicy{AllowedLoopbackEndpoints: []string{entry}}
		err := checkAddr(t, p, "localhost", "127.0.0.1:389")
		if !errors.Is(err, ErrLDAPEgressBlocked) {
			t.Errorf("清單項 %q 不得放行 127.0.0.1:389（不支援萬用字元、不支援單獨 host），實得 %v", entry, err)
		}
	}
}

// TestLDAPEgressFailsSecureOnUnresolvableAddress Control 收到非 IP 形狀時一律拒絕。
//
// 生產路徑不會發生（Control 的 ctrlAddr 恆為已解析位址）；本格是接縫語義若因
// 依賴升版而改變時的保險——寧可全面拒絕也不放行未經檢查的目標
func TestLDAPEgressFailsSecureOnUnresolvableAddress(t *testing.T) {
	p := &LDAPEgressPolicy{AllowedLoopbackEndpoints: []string{"ldap.example.com:389"}}
	for _, addr := range []string{"ldap.example.com:389", "not-an-ip:389", "389", "", "127.0.0.1"} {
		if err := checkAddr(t, p, "ldap.example.com", addr); !errors.Is(err, ErrLDAPEgressBlocked) {
			t.Errorf("非已解析位址 %q 應 fail-secure 拒絕，實得 %v", addr, err)
		}
	}
}

// TestParseLDAPAllowedLoopbackEndpoints env 解析：逗號分隔、去空白、略過空項
func TestParseLDAPAllowedLoopbackEndpoints(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"127.0.0.1:389", []string{"127.0.0.1:389"}},
		{" 127.0.0.1:389 , localhost:1389 ", []string{"127.0.0.1:389", "localhost:1389"}},
		{"127.0.0.1:389,,[::1]:636,", []string{"127.0.0.1:389", "[::1]:636"}},
	}
	for _, c := range cases {
		if got := parseLDAPAllowedLoopbackEndpoints(c.raw); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parse(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// TestNewLDAPEgressPolicyFromEnv 政策自 env 取得清單（字面 key，受漂移守衛覆蓋）
func TestNewLDAPEgressPolicyFromEnv(t *testing.T) {
	t.Setenv("LDAP_ALLOWED_LOOPBACK_ENDPOINTS", "127.0.0.1:1389")
	p := NewLDAPEgressPolicyFromEnv()
	if err := p.checkDialAddress("localhost", "127.0.0.1:1389"); err != nil {
		t.Errorf("env 放行的端點應通過，實得 %v", err)
	}
	if err := p.checkDialAddress("localhost", "127.0.0.1:389"); !errors.Is(err, ErrLDAPEgressBlocked) {
		t.Errorf("未放行的 loopback 端點仍應被擋，實得 %v", err)
	}
}

// TestNewLDAPEgressPolicyFromEnvDefaultDeniesLoopback 未設 env 時無任何 loopback 例外——
// 「不提供關閉檢查的開關」的另一面：預設就是全擋
func TestNewLDAPEgressPolicyFromEnvDefaultDeniesLoopback(t *testing.T) {
	t.Setenv("LDAP_ALLOWED_LOOPBACK_ENDPOINTS", "")
	p := NewLDAPEgressPolicyFromEnv()
	if len(p.AllowedLoopbackEndpoints) != 0 {
		t.Fatalf("未設定時清單應為空，實得 %v", p.AllowedLoopbackEndpoints)
	}
	if err := p.checkDialAddress("localhost", "127.0.0.1:389"); !errors.Is(err, ErrLDAPEgressBlocked) {
		t.Errorf("預設應拒絕 loopback，實得 %v", err)
	}
}

// TestClassifyLDAPDialError 粗分類：只供伺服端 log，不得外洩至回應。
//
// 出站政策必須排在最前——它經 net.OpError 包裝後同時可能滿足其他判定式
func TestClassifyLDAPDialError(t *testing.T) {
	egressWrapped := &net.OpError{
		Op: "dial", Net: "tcp",
		Err: fmt.Errorf("%w: 127.0.0.1:389", ErrLDAPEgressBlocked),
	}
	cases := []struct {
		name string
		err  error
		want ldapDialFailureClass
	}{
		{"出站政策（經 OpError 包裝）", egressWrapped, ldapDialFailureEgress},
		{"DNS 失敗", &net.DNSError{Err: "no such host", Name: "ldap.invalid", IsNotFound: true}, ldapDialFailureDNS},
		{"逾時", &net.OpError{Op: "dial", Err: &timeoutStubError{}}, ldapDialFailureTimeout},
		{"連線被拒", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, ldapDialFailureRefused},
		{"TLS 憑證", errors.New("x509: certificate signed by unknown authority"), ldapDialFailureTLS},
		{"其他", errors.New("something else"), ldapDialFailureOther},
	}
	for _, c := range cases {
		if got := classifyLDAPDialError(c.err); got != c.want {
			t.Errorf("%s: classify = %q, want %q", c.name, got, c.want)
		}
	}
}

// timeoutStubError 逾時錯誤替身（net.Error 介面）
type timeoutStubError struct{}

func (e *timeoutStubError) Error() string { return "i/o timeout" }
func (e *timeoutStubError) Timeout() bool { return true }
func (e *timeoutStubError) Temporary() bool {
	return true
}

// TestLDAPDialFailureClassNotLeakedToError 粗分類字串不得混入回傳給呼叫端的錯誤。
//
// 回應面收斂由連線測試端點接手，但「分類只存在於 log」這條界線在本層就要成立：
// 若哪天有人把 class 併進 error 訊息，端點再怎麼收斂都會把它帶出去
func TestLDAPDialFailureClassNotLeakedToError(t *testing.T) {
	p := &LDAPEgressPolicy{}
	err := p.checkDialAddress("localhost", "127.0.0.1:389")
	if err == nil {
		t.Fatal("loopback 應被拒")
	}
	for _, class := range []ldapDialFailureClass{
		ldapDialFailureDNS, ldapDialFailureTimeout, ldapDialFailureRefused, ldapDialFailureTLS,
	} {
		if strings.Contains(err.Error(), string(class)) {
			t.Errorf("撥號錯誤訊息不得帶粗分類字串 %q，實得 %q", class, err.Error())
		}
	}
}
