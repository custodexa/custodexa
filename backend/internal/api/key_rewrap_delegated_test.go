package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
)

// 委託重包目標的 wire 面（kek-provider-modularization tasks 3.3）。
//
// 三類失敗各有專屬機器碼與狀態碼，因為處置完全不同：
// 「本部署做不到」（501）／「這次沒通」（502）／「判別子打錯」（400）。

const apiFakeKMSARN = "arn:aws:kms:ap-northeast-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

// apiFakeDelegatedProvider 委託 provider 替身（AES 實作 ＋ kms 身分面）
type apiFakeDelegatedProvider struct {
	aes *crypto.AESCrypto
}

func newAPIFakeDelegatedProvider(t *testing.T) *apiFakeDelegatedProvider {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x33
	}
	a, err := crypto.NewAESCrypto(key)
	if err != nil {
		t.Fatalf("AES: %v", err)
	}
	return &apiFakeDelegatedProvider{aes: a}
}

func (p *apiFakeDelegatedProvider) Wrap(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errors.New("委託 provider 不接受空 AAD")
	}
	return p.aes.EncryptBytesAAD(plaintext, aad)
}

func (p *apiFakeDelegatedProvider) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errors.New("委託 provider 不接受空 AAD")
	}
	return p.aes.DecryptBytesAAD(wrapped, aad)
}

func (p *apiFakeDelegatedProvider) KeyRef() crypto.KeyRef {
	return crypto.KeyRef{Provider: crypto.KeyRefProviderKMS, KeyID: apiFakeKMSARN}
}
func (p *apiFakeDelegatedProvider) Mode() string      { return crypto.KEKModeKMS }
func (p *apiFakeDelegatedProvider) FormatTag() string { return crypto.WrappedFormatKMS }
func (p *apiFakeDelegatedProvider) ReEncrypt(ctx context.Context, wrapped, aad []byte, from crypto.KEKProvider) ([]byte, error) {
	return crypto.DefaultReEncrypt(ctx, p, wrapped, aad, from)
}

// TestRewrapDelegatedTargetSucceedsAndCarriesNoPlaintext 委託分支的正向案例：
// 200＋恰三鍵回應，且**明文欄在任何分支都不存在**（不是「以空字串靜默退化」）
func TestRewrapDelegatedTargetSucceedsAndCarriesNoPlaintext(t *testing.T) {
	h := newKeyMgmtTestHandler(t)
	provider := newAPIFakeDelegatedProvider(t)
	h.SetDelegatedProviderFactory(func(context.Context, string, string) (crypto.KEKProvider, error) {
		return provider, nil
	})

	before := countKeyRows(t, h)
	w, _ := doRewrap(t, h, `{"mode":"kms","key_ref":"`+apiFakeKMSARN+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("委託目標的合法請求應成功，得 %d body=%s", w.Code, w.Body.String())
	}
	if after := countKeyRows(t, h); after <= before {
		t.Fatalf("委託重包應寫出 pending clone 列：%d → %d", before, after)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非 JSON: %v", err)
	}
	want := map[string]bool{"target_mode": true, "new_kek_id": true, "rewrapped_keys": true}
	if len(body) != len(want) {
		t.Fatalf("回應鍵集應恰為契約三鍵，得 %v", body)
	}
	for k := range body {
		if !want[k] {
			t.Fatalf("回應含契約外欄位 %q（委託分支尤其不得出現明文欄）：%v", k, body)
		}
	}
	if body["target_mode"] != "kms" {
		t.Fatalf("判別子應為 kms，得 %v", body["target_mode"])
	}
	if body["new_kek_id"] != apiFakeKMSARN {
		t.Fatalf("new_kek_id 應為正規 ARN，得 %v", body["new_kek_id"])
	}
	// 明文欄的名稱在任何分支都不得出現（含空字串靜默退化的形態）
	for _, forbidden := range []string{"new_kek", "material", "plaintext"} {
		if _, exists := body[forbidden]; exists {
			t.Fatalf("回應不得含明文欄 %q：%v", forbidden, body)
		}
	}
}

// TestRewrapDelegatedPreflightFailureIsDistinct 預檢失敗（不可達／無權限）
// 與「尚未提供」分流：502＋專屬機器碼，且不得回吐外部錯誤細節
func TestRewrapDelegatedPreflightFailureIsDistinct(t *testing.T) {
	h := newKeyMgmtTestHandler(t)
	h.SetDelegatedProviderFactory(func(context.Context, string, string) (crypto.KEKProvider, error) {
		return nil, errors.New("AccessDeniedException: arn:aws:kms:secret-account:key/xyz")
	})

	before := countKeyRows(t, h)
	w, _ := doRewrap(t, h, `{"mode":"kms","key_ref":"`+apiFakeKMSARN+`"}`)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("預檢失敗應回 502，得 %d body=%s", w.Code, w.Body.String())
	}
	if code := responseCode(t, w); code != "INTERNAL_KEY_REWRAP_TARGET_UNAVAILABLE" {
		t.Fatalf("機器碼 = %q", code)
	}
	if after := countKeyRows(t, h); after != before {
		t.Fatalf("拒絕路徑不得寫入 data_keys：%d → %d", before, after)
	}
	// 外部系統的錯誤細節屬伺服端日誌範疇，不得經 API 外洩
	if body := w.Body.String(); contains(body, "secret-account") || contains(body, "AccessDenied") {
		t.Fatalf("回應洩漏外部系統細節: %s", body)
	}
}

// TestRewrapDelegatedUnsupportedWhenNoFactory 未注入 factory（或該模式未交付）
// 仍為 501「尚未提供」，SHALL NOT 靜默退化為本地目標
func TestRewrapDelegatedUnsupportedWhenNoFactory(t *testing.T) {
	h := newKeyMgmtTestHandler(t) // 不注入 factory
	w, _ := doRewrap(t, h, `{"mode":"hsm","key_ref":"token:label"}`)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("未交付模式應回 501，得 %d", w.Code)
	}
	if code := responseCode(t, w); code != "VALIDATION_KEY_REWRAP_TARGET_UNSUPPORTED" {
		t.Fatalf("機器碼 = %q", code)
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

var _ crypto.KEKProvider = (*apiFakeDelegatedProvider)(nil)
var _ keyvault.DelegatedProviderFactory = func(context.Context, string, string) (crypto.KEKProvider, error) {
	return nil, nil
}
