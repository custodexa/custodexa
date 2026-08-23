package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/custodexa/backend/internal/model"
)

// discovery 宣告的兩項政策（spec 第 29 行與第 324 行）：
// 本地演算法集合與 discovery 宣告取交集、未知 kid 重取受最小間隔節流。

func TestIntersectSigningAlgs(t *testing.T) {
	cases := []struct {
		name           string
		local, declare []string
		want           []string
	}{
		{"僅 RS256 的 IdP（Google 實況）", oidcSignatureAlgs, []string{"RS256"}, []string{"RS256"}},
		{"兩者皆宣告", oidcSignatureAlgs, []string{"RS256", "ES256", "PS256"}, []string{"RS256", "ES256"}},
		{"只宣告我方不接受者", oidcSignatureAlgs, []string{"HS256", "PS512"}, []string{}},
		{"未宣告該欄位 → 沿用本地", oidcSignatureAlgs, nil, oidcSignatureAlgs},
	}
	for _, c := range cases {
		got := intersectSigningAlgs(c.local, c.declare)
		if len(got) != len(c.want) {
			t.Errorf("%s: 交集 = %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: 交集 = %v, want %v", c.name, got, c.want)
				break
			}
		}
	}
}

func TestProviderUnusableWhenNoCommonSigningAlg(t *testing.T) {
	// IdP 只宣告我方不接受的演算法：該 provider SHALL 不可用。
	// 缺此判定時，症狀會表現為「每次登入都驗簽失敗」——錯誤指向簽章而非設定，
	// 管理者幾乎不可能據以定位到「演算法談不攏」
	idp := newFakeIdPWithAlgs(t, []string{"HS256", "PS512"})
	svc := NewOIDCDiscoveryService(testEgress())
	p := &model.OIDCProvider{Issuer: idp.issuer, ClientID: "test-client", Enabled: true}
	p.ID = 1

	_, err := svc.VerifyIDToken(context.Background(), p, "irrelevant", testNonce)
	if !errors.Is(err, ErrOIDCNoCommonSigningAlg) {
		t.Fatalf("交集為空應使 provider 不可用，實得 %v", err)
	}
}

func TestProviderUsableWhenDeclaredAlgsOverlap(t *testing.T) {
	idp := newFakeIdPWithAlgs(t, []string{"PS256", "RS256"})
	svc := NewOIDCDiscoveryService(testEgress())
	p := &model.OIDCProvider{Issuer: idp.issuer, ClientID: "test-client", Enabled: true}
	p.ID = 1

	raw := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: testNonce,
	})
	if _, err := svc.VerifyIDToken(context.Background(), p, raw, testNonce); err != nil {
		t.Fatalf("交集含 RS256 應可用: %v", err)
	}
}

func TestJWKSRefetchThrottled(t *testing.T) {
	idp, svc, p := newVerifyFixture(t)
	// 建立快取並完成第一次 JWKS 取得
	if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err != nil {
		t.Fatalf("初次驗證失敗: %v", err)
	}
	before := idp.jwksRequests()
	if before == 0 {
		t.Fatal("初次驗證應已取過 JWKS（前提不成立則本測試無意義）")
	}

	// 以未知 kid 洪水灌入：go-oidc 遇未知 kid 會重取，若無節流，
	// 每一發偽造請求都會被放大成一次對 IdP 的 JWKS 請求
	unknown := newFakeKey(t, "kid-does-not-exist")
	idp.signWith(unknown)
	for i := 0; i < 20; i++ {
		if _, err := svc.VerifyIDToken(context.Background(), p, issueForRotation(t, idp), testNonce); err == nil {
			t.Fatal("未知 kid 的 token 不應通過驗證")
		}
	}

	if after := idp.jwksRequests(); after != before {
		t.Fatalf("60 秒內的重取應被節流：JWKS 請求數 %d → %d（20 次偽造 kid 全部放大）",
			before, after)
	}
}

func TestJWKSMinRefetchBoundIsMeaningful(t *testing.T) {
	// 節流間隔本體的守衛：設為 0 會使前一格失去意義，設得過長則真實輪替
	// 遲遲不生效。設計上訂為 60 秒
	if oidcJWKSMinRefetch <= 0 || oidcJWKSMinRefetch > oidcJWKSMaxStale {
		t.Fatalf("最小重取間隔 = %v，應為正值且短於最大陳舊時間 %v",
			oidcJWKSMinRefetch, oidcJWKSMaxStale)
	}
}

func TestSigningAlgAllowlistUsesOIDCConstants(t *testing.T) {
	// 白名單以函式庫常數而非字面字串定義，避免拼錯造成「白名單裡沒有任何
	// 演算法會匹配」而全部拒絕（或反之）
	for _, a := range oidcSignatureAlgs {
		if a != oidc.RS256 && a != oidc.ES256 {
			t.Errorf("白名單含非預期值 %q", a)
		}
	}
}
