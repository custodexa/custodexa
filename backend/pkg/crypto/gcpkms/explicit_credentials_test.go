package gcpkms

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// 顯式憑證取代環境自動發現的守衛（任務 3.4）。
//
// 部署形態是地端機房以開放名單連往外部雲端金鑰服務：環境中不存在應當被採用的
// 工作負載身分，「恰好撿到一組 ADC」代表撿到的是別人的憑證。故憑證缺席時
// **拒絕建構**，而不是回落環境自動發現。
//
// 目的地閘與 TLS 閘仍在憑證**之後**：換憑證來源不得鬆動它們。

// TestGCPCredentialsRequiredForClient 缺服務帳號金鑰檔內容即拒絕建構。
func TestGCPCredentialsRequiredForClient(t *testing.T) {
	scope, err := ResolveProjectScope(fixtureKey)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	c, err := NewClient(context.Background(), Settings{KeyID: fixtureKey, Scope: scope})
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("缺憑證應回 ErrAuthentication，得 %v", err)
	}
	if c != nil {
		t.Fatal("拒絕建構時不得回傳可用 client")
	}
}

// TestResolveTransportRequiresExplicitCredentials 傳輸建構同樣缺憑證即拒。
//
// 這是「不回落環境自動發現」的結構點：`resolveExplicit` 在材料為空時**不呼叫**
// 任何會觸發自動發現的建構入口，直接回錯。
func TestResolveTransportRequiresExplicitCredentials(t *testing.T) {
	base := secureTransport()
	defer base.CloseIdleConnections()

	rt, err := resolveExplicit(nil)(context.Background(), destinationGuard{next: base})
	if !errors.Is(err, ErrAuthentication) || rt != nil {
		t.Fatalf("空材料應回 ErrAuthentication 且無傳輸，得 rt=%v err=%v", rt, err)
	}
	rt2, err2 := resolveExplicit([]byte{})(context.Background(), destinationGuard{next: base})
	if !errors.Is(err2, ErrAuthentication) || rt2 != nil {
		t.Fatalf("零長度材料應回 ErrAuthentication，得 rt=%v err=%v", rt2, err2)
	}
}

// TestEndpointGateStaysAfterCredentials 目的地閘在憑證之後仍然生效。
//
// 換憑證來源不得鬆動目的地檢查：任何非 `https://cloudkms.googleapis.com` 的請求
// 在送出前即被拒——**含明文 DEK 的請求**不得被導向別處。
func TestEndpointGateStaysAfterCredentials(t *testing.T) {
	guard := destinationGuard{next: explicitCredsRT(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("request reached the network")
	})}
	for _, raw := range []string{
		"http://cloudkms.googleapis.com/v1/x",  // 明文
		"https://kms.attacker.example/v1/x",    // 換主機
		"https://cloudkms.googleapis.com:8443", // 換埠（URL.Host 含埠，與允許值不等）
	} {
		req, err := http.NewRequest(http.MethodPost, raw, nil)
		if err != nil {
			t.Fatalf("fixture %q: %v", raw, err)
		}
		if _, err := guard.RoundTrip(req); !errors.Is(err, ErrEndpoint) {
			t.Errorf("目的地 %q 應在送出前被拒，得 %v", raw, err)
		}
	}
	// 正向控制：合法目的地會走到下一層（否則「一律拒絕」也會讓上面全綠）。
	ok, _ := http.NewRequest(http.MethodPost, "https://cloudkms.googleapis.com/v1/x", nil)
	if _, err := guard.RoundTrip(ok); errors.Is(err, ErrEndpoint) {
		t.Fatal("合法目的地被誤擋——本案將無法分辨閘有沒有在判斷")
	}
}

type explicitCredsRT func(*http.Request) (*http.Response, error)

func (f explicitCredsRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
