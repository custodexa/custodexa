package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/custodexa/backend/internal/model"
)

// id_token 驗證失敗矩陣。
//
// 這些情境在真實 IdP 上無法製造，故以 fakeIdP 逐格覆蓋。**其中時間判定與
// 演算法白名單是本設計最脆弱的兩點**：verifier 已開 SkipExpiryCheck，
// verifyTimeClaims 一旦被移除即等於完全不驗過期，而該退化不會使任何
// 正向測試變紅——只有這裡的過期案例會抓到。

// testEgress dev 靶機式出站政策：httptest 伺服器位於 loopback，
// 預設政策會擋（正是 SSRF 防線生效的證明），測試以顯式放行取得可測性
func testEgress() *OIDCEgressPolicy {
	return &OIDCEgressPolicy{AllowInsecureHosts: []string{"127.0.0.1"}}
}

// newVerifyFixture 一組 fakeIdP＋discovery 服務＋對應的 provider 設定
func newVerifyFixture(t *testing.T) (*fakeIdP, *OIDCDiscoveryService, *model.OIDCProvider) {
	t.Helper()
	idp := newFakeIdP(t)
	svc := NewOIDCDiscoveryService(testEgress())
	p := &model.OIDCProvider{Issuer: idp.issuer, ClientID: "test-client", Enabled: true}
	p.ID = 1
	return idp, svc, p
}

const testNonce = "nonce-value-1"

func TestVerifyIDTokenAcceptsValidToken(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		extra: map[string]any{
			"preferred_username": "alice",
			"email":              "alice@example.com",
			"email_verified":     true,
			"name":               "Alice",
		},
	})

	claims, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce)
	if err != nil {
		t.Fatalf("有效 token 應通過驗證: %v", err)
	}
	if claims.Subject != "sub-1" {
		t.Errorf("Subject = %q, want sub-1", claims.Subject)
	}
	if claims.PreferredUsername != "alice" || claims.Email != "alice@example.com" {
		t.Errorf("claims 取出不正確: %+v", claims)
	}
	if !claims.EmailVerified {
		t.Error("email_verified 應為 true")
	}
	if claims.Raw["preferred_username"] != "alice" {
		t.Error("Raw 應保留原始 claims 供 admission 求值")
	}
}

// verifyRejects 共用斷言：驗證必須失敗，且錯誤歸類為 token 驗證失敗
func verifyRejects(t *testing.T, svc *OIDCDiscoveryService, p *model.OIDCProvider, raw, nonce, why string) {
	t.Helper()
	_, err := svc.VerifyIDToken(context.Background(), p, raw, nonce)
	if err == nil {
		t.Fatalf("%s：應拒絕但通過了驗證", why)
	}
	if !errors.Is(err, ErrOIDCTokenVerification) {
		t.Errorf("%s：錯誤類別 = %v, want ErrOIDCTokenVerification", why, err)
	}
}

func TestVerifyIDTokenRejectsForgedSignature(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		signWithOtherKey: true,
	})
	verifyRejects(t, svc, p, raw, testNonce, "他方金鑰簽章")
}

func TestVerifyIDTokenRejectsSymmetricAlgorithm(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// HS256 以 client_secret 當驗章金鑰＝任何知道 secret 的一方都能偽造 ID token；
	// 三大 IdP 亦不簽發對稱演算法的 ID token。白名單為封閉集合，對稱演算法一律拒絕
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		alg: jwt.SigningMethodHS256,
	})
	verifyRejects(t, svc, p, raw, testNonce, "HS256 不在演算法白名單")
}

func TestSignatureAlgAllowlistIsClosed(t *testing.T) {
	// 白名單本體的守衛：擴充時必須是明示決定，不可因「支援更多 IdP」被悄悄放寬
	want := map[string]bool{oidc.RS256: true, oidc.ES256: true}
	if len(oidcSignatureAlgs) != len(want) {
		t.Fatalf("演算法白名單 = %v，預期恰為 RS256 與 ES256", oidcSignatureAlgs)
	}
	for _, a := range oidcSignatureAlgs {
		if !want[a] {
			t.Errorf("白名單含非預期演算法 %q", a)
		}
		if strings.HasPrefix(a, "HS") || a == "none" {
			t.Errorf("白名單不得含對稱演算法或 none，實得 %q", a)
		}
	}
}

func TestVerifyIDTokenRejectsWrongIssuer(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		issuer: "https://evil.example.com",
	})
	verifyRejects(t, svc, p, raw, testNonce, "iss 與 provider 設定不符")
}

func TestVerifyIDTokenRejectsWrongAudience(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "another-client", nonce: testNonce,
	})
	verifyRejects(t, svc, p, raw, testNonce, "aud 不含本方 client_id")
}

func TestVerifyIDTokenRejectsMultiAudienceWithMismatchedAZP(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// 缺此檢查時，實際授權給 other-client 的 token 會被本系統接受，形成跨 client 冒名
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: []string{"test-client", "other-client"},
		azp: "other-client", nonce: testNonce,
	})
	verifyRejects(t, svc, p, raw, testNonce, "多 audience 但 azp 指向他方 client")
}

func TestVerifyIDTokenAcceptsMultiAudienceWithMatchingAZP(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: []string{"test-client", "other-client"},
		azp: "test-client", nonce: testNonce,
	})
	if _, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce); err != nil {
		t.Fatalf("多 audience 且 azp 相符應通過: %v", err)
	}
}

func TestVerifyIDTokenRejectsExpiredBeyondSkew(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// **本檔最關鍵的一格**：verifier 開了 SkipExpiryCheck，此案例僅靠
	// verifyTimeClaims 攔下。若該函式被移除，只有這裡會變紅
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		issuedAt: time.Now().Add(-30 * time.Minute), expiresIn: 5 * time.Minute,
	})
	verifyRejects(t, svc, p, raw, testNonce, "token 已過期逾容忍窗")
}

func TestVerifyIDTokenAcceptsExpiredWithinSkew(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// 剛過期 10 秒：落在 ±60s 時鐘偏移容忍內，應通過。
	// 缺此容忍時，容器與 IdP 差幾秒即出現隨機性登入失敗且極難診斷
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		issuedAt: time.Now().Add(-5 * time.Minute), expiresIn: 5*time.Minute - 10*time.Second,
	})
	if _, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce); err != nil {
		t.Fatalf("過期 10 秒應在 ±60s 容忍窗內通過: %v", err)
	}
}

func TestVerifyIDTokenRejectsFutureIssuedAt(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		issuedAt: time.Now().Add(10 * time.Minute),
	})
	verifyRejects(t, svc, p, raw, testNonce, "iat 位於未來逾容忍窗")
}

func TestVerifyIDTokenAcceptsFutureIssuedAtWithinSkew(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		issuedAt: time.Now().Add(20 * time.Second),
	})
	if _, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce); err != nil {
		t.Fatalf("iat 早 20 秒應在容忍窗內通過: %v", err)
	}
}

func TestVerifyIDTokenRejectsMissingExpiry(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// **SkipExpiryCheck 之下最危險的一格**：go-oidc 不管過期，
	// 若我方只在「有值時」檢查，缺 exp 的 token 就是一張永不到期的憑證
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		omitExpiry: true,
	})
	verifyRejects(t, svc, p, raw, testNonce, "token 缺少 exp")
}

func TestVerifyIDTokenRejectsMissingIssuedAt(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		omitIssuedAt: true,
	})
	verifyRejects(t, svc, p, raw, testNonce, "token 缺少 iat")
}

func TestVerifyIDTokenRejectsNotYetValid(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// nbf 逾容忍窗：iat 可以是現在而 nbf 在未來，兩者是不同的宣告
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		extra: map[string]any{"nbf": time.Now().Add(10 * time.Minute).Unix()},
	})
	verifyRejects(t, svc, p, raw, testNonce, "nbf 位於未來逾容忍窗")
}

func TestVerifyIDTokenAcceptsNotBeforeWithinSkew(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		extra: map[string]any{"nbf": time.Now().Add(20 * time.Second).Unix()},
	})
	if _, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce); err != nil {
		t.Fatalf("nbf 早 20 秒應在 ±60s 容忍窗內通過: %v", err)
	}
}

func TestVerifyIDTokenAcceptsPastNotBefore(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		extra: map[string]any{"nbf": time.Now().Add(-time.Minute).Unix()},
	})
	if _, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce); err != nil {
		t.Fatalf("已生效的 nbf 應通過: %v", err)
	}
}

func TestVerifyIDTokenRejectsNonNumericNotBefore(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// 型別不符不做寬鬆轉型：外部可控值不得以「解析不出來就當沒有」放行
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		extra: map[string]any{"nbf": "not-a-number"},
	})
	verifyRejects(t, svc, p, raw, testNonce, "nbf 型別不符")
}

func TestVerifyIDTokenRejectsNonceMismatch(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: "other-nonce",
	})
	verifyRejects(t, svc, p, raw, testNonce, "nonce 與本次流程不符（重放他次流程的 token）")
}

func TestVerifyIDTokenRejectsMissingNonce(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{subject: "sub-1", audience: "test-client"})
	verifyRejects(t, svc, p, raw, testNonce, "token 完全不帶 nonce")
}

func TestVerifyIDTokenRejectsEmptySubject(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// 空 subject 會使第一個異常 token 吸附該 provider 後續全部異常 token
	// （所有人共用同一個外部身分列）
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "  ", audience: "test-client", nonce: testNonce,
	})
	verifyRejects(t, svc, p, raw, testNonce, "subject 為空白")
}

func TestVerifyIDTokenRejectsOverlongSubject(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: strings.Repeat("s", 256), audience: "test-client", nonce: testNonce,
	})
	verifyRejects(t, svc, p, raw, testNonce, "subject 超過 255 字元上限")
}

func TestVerifyIDTokenSubjectIsCaseSensitive(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "Sub-Mixed-Case", audience: "test-client", nonce: testNonce,
	})
	claims, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce)
	if err != nil {
		t.Fatalf("驗證失敗: %v", err)
	}
	// 不做任何正規化：大小寫折疊會把 IdP 眼中的兩個不同主體併為一個身分
	if claims.Subject != "Sub-Mixed-Case" {
		t.Errorf("Subject 被正規化為 %q，應原值保留", claims.Subject)
	}
}

func TestVerifyIDTokenUnverifiedEmailNotMarkedVerified(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		extra: map[string]any{"email": "spoof@corp.example", "email_verified": false},
	})
	claims, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce)
	if err != nil {
		t.Fatalf("驗證失敗: %v", err)
	}
	if claims.EmailVerified {
		t.Fatal("email_verified=false 不得被視為已驗證（否則可據以映射本地身分）")
	}
}

func TestVerifyIDTokenEmailVerifiedWrongTypeTreatedFalse(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// 部分 IdP 以字串 "true" 送出。型別不符一律視為未驗證（fail-secure），
	// 不做寬鬆解析——寬鬆解析等於接受外部可控值決定「已驗證」
	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
		extra: map[string]any{"email": "x@corp.example", "email_verified": "true"},
	})
	claims, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce)
	if err != nil {
		t.Fatalf("驗證失敗: %v", err)
	}
	if claims.EmailVerified {
		t.Fatal("email_verified 型別不符應視為未驗證")
	}
}

func TestDiscoveryBlockedByEgressPolicy(t *testing.T) {
	// 出站位址政策的正向證明：不放行 loopback 時，指向 httptest 伺服器的
	// discovery 必須被擋下（SSRF 防線；169.254.169.254 類雲端 metadata 同理）
	idp := newFakeIdP(t)
	svc := NewOIDCDiscoveryService(&OIDCEgressPolicy{})
	p := &model.OIDCProvider{Issuer: idp.issuer, ClientID: "test-client", Enabled: true}
	p.ID = 99

	_, err := svc.VerifyIDToken(context.Background(), p, "irrelevant", testNonce)
	if err == nil {
		t.Fatal("未放行的 loopback 目標應被出站政策擋下")
	}
	if !errors.Is(err, ErrOIDCDiscoveryFailed) {
		t.Errorf("錯誤類別 = %v, want ErrOIDCDiscoveryFailed", err)
	}
	if !strings.Contains(err.Error(), ErrOIDCEgressBlocked.Error()) {
		t.Errorf("錯誤應源自出站位址政策，實得: %v", err)
	}
}
