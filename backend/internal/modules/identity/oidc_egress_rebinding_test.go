package identity

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

// DNS rebinding：名稱只解析一次（批 14 對抗審查 M1 / spec oidc-auth L33）。
//
// 既有格點（TestEgressBlocksDNSNameResolvingToPrivateIP）證明的是「解析到私網
// 就擋」，它用的是**穩定**的 DNS 事實，因此對「檢查一次、連線時再解析一次」
// 的實作照樣全綠。真正的 rebinding 需要同一名稱在兩次查詢間改變回應——真實
// DNS 在測試中造不出來，故以 policy 的解析接縫注入。
//
// 斷言有兩層：
//  1. 解析次數為 1（結構面）；
//  2. 送進 dial 的位址是**已驗過的 IP 字面值**而非主機名（後果面）——傳主機名
//     時第二次解析由 net.Dialer 在測試看不見的地方發生，只有這一句擋得住。
func TestEgressResolvesOnceAndDialsVerifiedAddress(t *testing.T) {
	var lookups atomic.Int64
	var dialedAddr atomic.Value

	policy := &OIDCEgressPolicy{
		resolver: func(_ context.Context, host string) ([]net.IPAddr, error) {
			// 第一次回公網（通過檢查）；此後回雲端 metadata 位址——
			// 攻擊者控制的權威 DNS 正是這樣運作（TTL=0，逐次改答案）
			if lookups.Add(1) == 1 {
				return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
			}
			return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
		},
		dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialedAddr.Store(addr)
			return nil, errors.New("stub dial: 不建立真實連線")
		},
	}

	//nolint:bodyclose // stub dial 恆失敗，不會有回應本體
	_, _ = policy.HTTPClient().Get("http://idp.example.com/.well-known/openid-configuration")

	raw, ok := dialedAddr.Load().(string)
	if !ok {
		t.Fatal("dial 未被呼叫：本測試的前提（請求會走到 DialContext）不成立")
	}
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		t.Fatalf("dial 目標 %q 不是 host:port: %v", raw, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("dial 目標 %q 仍是主機名——連線時會發生第二次名稱解析，"+
			"DNS rebinding 窗口仍在（第二次解析回 169.254.169.254 即打到雲端 metadata）", raw)
	}
	if isBlockedEgressIP(ip, false) {
		t.Fatalf("dial 目標 %s 是禁止出站的位址：檢查與連線用的不是同一個位址", ip)
	}
	if n := lookups.Load(); n != 1 {
		t.Errorf("名稱解析次數 = %d, want 1（每多一次就多一個 rebinding 窗口）", n)
	}
}

// TestEgressDialsEveryResolvedAddressUntilSuccess 單次解析的必要副作用：
// 多位址主機不得因「只試第一個」而失去可用性（政策不該把正常 IdP 弄掛）
func TestEgressDialsEveryResolvedAddressUntilSuccess(t *testing.T) {
	var tried []string
	policy := &OIDCEgressPolicy{
		resolver: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("203.0.113.10")},
				{IP: net.ParseIP("198.51.100.7")},
			}, nil
		},
		dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			tried = append(tried, addr)
			return nil, errors.New("stub dial")
		},
	}
	//nolint:bodyclose // stub dial 恆失敗
	_, _ = policy.HTTPClient().Get("http://idp.example.com/x")

	if len(tried) != 2 {
		t.Fatalf("嘗試過的位址 = %v, want 兩個都試過", tried)
	}
	for i, want := range []string{"203.0.113.10:80", "198.51.100.7:80"} {
		if tried[i] != want {
			t.Errorf("第 %d 個 dial 目標 = %q, want %q", i+1, tried[i], want)
		}
	}
}
