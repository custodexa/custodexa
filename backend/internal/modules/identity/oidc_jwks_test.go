package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// JWKS 輪替四情境。
//
// 輪替是 IdP 的常態運維，本系統若不能跟上，全體使用者會在 IdP 換鑰當下集體
// 登入失敗；反之若快取無上限，已自 JWKS 移除的金鑰會永久有效——後者才是安全
// 問題，故有 oidcJWKSMaxStale 這個強制重建的上限。

func issueForRotation(t *testing.T, idp *fakeIdP) string {
	t.Helper()
	return idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
	})
}

// elapseThrottleWindow 把節流計時撥回，模擬最小重取間隔已過。
// 不用真的 sleep 60 秒——測試要驗的是「窗口過了就能重取」，不是計時器本身
func elapseThrottleWindow(t *testing.T, svc *OIDCDiscoveryService, providerID uint) {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	c := svc.cache[providerID]
	if c == nil || c.throttle == nil {
		t.Fatal("快取與節流層應已建立")
	}
	c.throttle.mu.Lock()
	c.throttle.last = time.Now().Add(-oidcJWKSMinRefetch - time.Second)
	c.throttle.mu.Unlock()
}

func TestJWKSRotationNewKeyIDAccepted(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// 先建立快取（模擬系統已在服務中）
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err != nil {
		t.Fatalf("輪替前應可驗證: %v", err)
	}

	// IdP 新增一把金鑰並改用它簽發，舊金鑰仍在 JWKS（標準的重疊期輪替）
	old := idp.signing
	next := newFakeKey(t, "test-key-2")
	idp.publishKeys(old, next)
	idp.signWith(next)

	// 節流窗口內：新 kid 尚無法被接受。這是節流的既定代價（spec 明訂），
	// 不是缺陷——不斷言它，日後有人把節流拿掉也不會有測試變紅
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err == nil {
		t.Fatal("最小重取間隔內不應重取 JWKS（否則偽造 kid 可放大攻擊 IdP）")
	}

	elapseThrottleWindow(t, svc, p.ID)
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err != nil {
		t.Fatalf("節流窗口過後，新 kid 應觸發 JWKS 重取並通過: %v", err)
	}
	// 重疊期內舊金鑰簽的 token 仍應可用（否則輪替瞬間會踢掉在途登入）
	idp.signWith(old)
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err != nil {
		t.Fatalf("重疊期內舊 kid 應仍可用: %v", err)
	}
}

func TestJWKSRotationSameKeyIDNewKeyAccepted(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err != nil {
		t.Fatalf("輪替前應可驗證: %v", err)
	}

	// 同一個 kid 換掉底層金鑰：快取按 kid 命中卻驗不過，須能重取而非直接失敗
	replaced := newFakeKey(t, idp.signing.kid)
	idp.publishKeys(replaced)
	idp.signWith(replaced)

	elapseThrottleWindow(t, svc, p.ID)
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err != nil {
		t.Fatalf("同 kid 換金鑰應重取 JWKS 後通過: %v", err)
	}
}

func TestJWKSUnknownKidFailsClosedWhenIdPUnreachable(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err != nil {
		t.Fatalf("關閉前應可驗證: %v", err)
	}

	// spec 明文情境：**快取仍新鮮**但出現未知 kid，而此時 JWKS 端點不可達。
	// 與 TestJWKSIdPUnreachableFailsClosed 不同——那格測的是快取已逾陳舊上限。
	// 兩條路徑各自獨立，只測其一會漏掉「新鮮快取＋未知 kid」這條
	unknown := newFakeKey(t, "kid-never-published")
	idp.signWith(unknown)
	raw := issueForRotation(t, idp)
	idp.server.Close()
	elapseThrottleWindow(t, svc, p.ID) // 排除「被節流擋下」這個替代解釋

	if _, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce); err == nil {
		t.Fatal("未知 kid 且 JWKS 不可達時必須 fail-close")
	}
}

func TestJWKSRemovedKeyRejectedAfterMaxStale(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err != nil {
		t.Fatalf("移除前應可驗證: %v", err)
	}

	// IdP 移除舊金鑰（例如該金鑰已洩漏）。快取仍持有它，故短期內仍會通過——
	// 這正是 oidcJWKSMaxStale 存在的理由：無上限則已撤銷的金鑰永久有效
	next := newFakeKey(t, "test-key-2")
	idp.publishKeys(next)

	stale := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
	})

	// 把快取時間撥回超過上限，模擬 24 小時後：verifier 強制重建、金鑰重取
	svc.mu.Lock()
	c := svc.cache[p.ID]
	if c == nil {
		svc.mu.Unlock()
		t.Fatal("快取應已建立（前提不成立則本測試無意義）")
	}
	c.fetchedAt = time.Now().Add(-oidcJWKSMaxStale - time.Minute)
	svc.mu.Unlock()

	if _, err := svc.VerifyIDToken(context.Background(), p, stale, testNonce); err == nil {
		t.Fatal("已自 JWKS 移除的金鑰所簽 token，最遲於陳舊上限後必須被拒")
	}
}

func TestJWKSMaxStaleBoundIsFinite(t *testing.T) {
	// 上限本體的守衛：改成 0 或極大值都會使前一個測試失去意義，
	// 故把「有限且不長於一日」寫成可驗收的斷言
	if oidcJWKSMaxStale <= 0 || oidcJWKSMaxStale > 24*time.Hour {
		t.Fatalf("JWKS 陳舊上限 = %v，應為正值且不長於 24 小時", oidcJWKSMaxStale)
	}
}

func TestJWKSIdPUnreachableFailsClosed(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := issueForRotation(t, idp)
	if _, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce); err != nil {
		t.Fatalf("關閉前應可驗證: %v", err)
	}

	// IdP 不可達且快取已過陳舊上限：不得沿用舊金鑰放行
	idp.server.Close()
	svc.mu.Lock()
	svc.cache[p.ID].fetchedAt = time.Now().Add(-oidcJWKSMaxStale - time.Minute)
	svc.mu.Unlock()

	_, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce)
	if err == nil {
		t.Fatal("IdP 不可達且快取已逾期時必須拒絕（不得以舊金鑰放行）")
	}
	if !errors.Is(err, ErrOIDCDiscoveryFailed) {
		t.Errorf("錯誤類別 = %v, want ErrOIDCDiscoveryFailed", err)
	}
}

func TestJWKSCacheInvalidatedOnIssuerChange(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err != nil {
		t.Fatalf("初次驗證失敗: %v", err)
	}

	// provider 列被刪除後以同 id 重建成另一個身分域（issuer/client_id 不同）：
	// 快取按 provider id 索引，若不比對 issuer/client_id，新設定會沿用舊 IdP 的金鑰
	other := newFakeIdP(t)
	p2 := &model.OIDCProvider{Issuer: other.issuer, ClientID: "other-client", Enabled: true}
	p2.ID = p.ID

	// 舊 IdP 簽的 token 對新設定必須無效（iss 與 aud 皆不符）
	if _, err := svc.VerifyIDToken(context.Background(), p2, issueForRotation(t, idp), testNonce); err == nil {
		t.Fatal("設定已換身分域，舊 IdP 的 token 不得通過（快取須依 issuer/client_id 失效）")
	}
	// 新 IdP 簽的 token 應通過
	fresh := other.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "other-client", nonce: testNonce,
	})
	if _, err := svc.VerifyIDToken(context.Background(), p2, fresh, testNonce); err != nil {
		t.Fatalf("新身分域的 token 應通過: %v", err)
	}
}

func TestDiscoveryInvalidateForcesRefetch(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err != nil {
		t.Fatalf("初次驗證失敗: %v", err)
	}
	svc.mu.Lock()
	_, cached := svc.cache[p.ID]
	svc.mu.Unlock()
	if !cached {
		t.Fatal("驗證後應留下快取")
	}

	// 設定變更／停用時的顯式失效路徑
	svc.Invalidate(p.ID)
	svc.mu.Lock()
	_, stillCached := svc.cache[p.ID]
	svc.mu.Unlock()
	if stillCached {
		t.Fatal("Invalidate 應移除該 provider 的快取")
	}
}
