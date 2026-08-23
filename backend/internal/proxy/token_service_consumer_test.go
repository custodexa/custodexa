package proxy_test

// TokenService 的**消費側**測試
//
// 「消費側」＝以 `gatewayapi.TokenService` 這個**介面型別**為依賴的測試。
// `redeemOnce` 只認得介面，對 `proxy.ConnectTokenManager` 一無所知；同一組斷言
// 同時跑手寫替身與真實實作，證明「只經介面就能完成簽發→兌換即焚這件職責」。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// issueThenRedeemTwice 純介面消費端：簽一張票、兌換兩次。
// 回傳（首次兌換的 grant, 首次是否成功, 二次是否成功）。
func issueThenRedeemTwice(ctx context.Context, ts gatewayapi.TokenService,
	g gatewayapi.ConnectGrant) (gatewayapi.ConnectGrant, bool, bool, error) {
	token, err := ts.IssueConnectToken(ctx, g)
	if err != nil {
		return gatewayapi.ConnectGrant{}, false, false, err
	}
	first, ok1 := ts.RedeemConnectToken(ctx, token)
	_, ok2 := ts.RedeemConnectToken(ctx, token)
	return first, ok1, ok2, nil
}

// ── 手寫替身：只依介面契約而生，完全不使用 proxy ──────────────────────

type stubTokens struct {
	grants map[string]gatewayapi.ConnectGrant
	seq    int
}

var _ gatewayapi.TokenService = (*stubTokens)(nil)

func (s *stubTokens) IssueConnectToken(_ context.Context, g gatewayapi.ConnectGrant) (string, error) {
	if s.grants == nil {
		s.grants = map[string]gatewayapi.ConnectGrant{}
	}
	s.seq++
	tok := string(rune('a' + s.seq))
	g.ExpiresAt = time.Now().Add(time.Minute)
	s.grants[tok] = g
	return tok, nil
}

func (s *stubTokens) RedeemConnectToken(_ context.Context, token string) (gatewayapi.ConnectGrant, bool) {
	g, ok := s.grants[token]
	delete(s.grants, token)
	if !ok || time.Now().After(g.ExpiresAt) {
		return gatewayapi.ConnectGrant{}, false
	}
	return g, true
}

// TestTokenServiceConsumerBurnsOnRead 兌換即焚是契約語義：第二次兌換必須失敗。
// 兩個實作跑同一組斷言。
func TestTokenServiceConsumerBurnsOnRead(t *testing.T) {
	want := gatewayapi.ConnectGrant{
		UserID: 9, AssetID: 4, AccountID: 2,
		AuthMethod: "oidc", ProviderID: 3, AuthEpoch: 1, CredEpoch: 5,
	}

	cases := map[string]gatewayapi.TokenService{
		"手寫替身":                      &stubTokens{},
		"proxy.ConnectTokenManager": proxy.NewConnectTokenManager(),
	}
	for name, ts := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok1, ok2, err := issueThenRedeemTwice(context.Background(), ts, want)
			if err != nil {
				t.Fatalf("簽發失敗: %v", err)
			}
			if !ok1 {
				t.Fatal("首次兌換應成功")
			}
			if ok2 {
				t.Fatal("二次兌換必須失敗（即焚語義）")
			}
			// 客體選擇器與認證脈絡必須原樣穿過介面——認證脈絡是兌換側複查
			// provider 啟用與世代相符的唯一依據
			if got.UserID != want.UserID || got.AssetID != want.AssetID || got.AccountID != want.AccountID {
				t.Fatalf("客體選擇器未原樣穿過介面: %+v", got)
			}
			if got.AuthMethod != want.AuthMethod || got.ProviderID != want.ProviderID ||
				got.AuthEpoch != want.AuthEpoch || got.CredEpoch != want.CredEpoch {
				t.Fatalf("認證脈絡未原樣穿過介面: %+v", got)
			}
			// 到期時刻由實作填寫，契約只保證它被設定
			if got.ExpiresAt.IsZero() {
				t.Fatal("ExpiresAt 未由簽發側填寫")
			}
		})
	}
}

// TestTokenServiceConsumerRejectsUnknownToken 未知票一律回 false，不得回一張零值 grant 而稱成功
func TestTokenServiceConsumerRejectsUnknownToken(t *testing.T) {
	var ts gatewayapi.TokenService = proxy.NewConnectTokenManager()
	if _, ok := ts.RedeemConnectToken(context.Background(), "no-such-token"); ok {
		t.Fatal("未知票不得兌換成功")
	}
}

// TestTokenServiceConsumerSurfacesCapacityError 容量拒發須以 error 穿過介面，
// 呼叫端據此分流為 503 而非 500（連線熱路徑的可用性訊號）
func TestTokenServiceConsumerSurfacesCapacityError(t *testing.T) {
	var ts gatewayapi.TokenService = proxy.NewConnectTokenManager()
	ctx := context.Background()
	var lastErr error
	for i := 0; i < 64; i++ {
		if _, err := ts.IssueConnectToken(ctx, gatewayapi.ConnectGrant{UserID: 1, AssetID: 1}); err != nil {
			lastErr = err
			break
		}
	}
	if lastErr == nil {
		t.Fatal("單一使用者連續簽發應在上限處被拒")
	}
	if !errors.Is(lastErr, proxy.ErrConnectTokenCapacity) {
		t.Fatalf("容量拒發的 sentinel 未穿過介面: %v", lastErr)
	}
}
