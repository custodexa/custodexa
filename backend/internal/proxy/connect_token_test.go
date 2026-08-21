package proxy

import (
	"context"
	"testing"
	"time"
)

func TestConnectTokenIssueResolve(t *testing.T) {
	m := NewConnectTokenManager()
	token, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 7, AccountID: 0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(token) != 32 {
		t.Errorf("token length = %d", len(token))
	}

	grant, ok := m.RedeemConnectToken(context.Background(), token)
	if !ok {
		t.Fatal("Resolve should succeed")
	}
	if grant.UserID != 1 || grant.AssetID != 7 || grant.AccountID != 0 {
		t.Errorf("grant = %+v", grant)
	}
}

// TestConnectTokenCarriesAccount 帳號選擇器隨 grant 保存（asset-multi-account D3）：
// 兌換點據此取憑證，故 Issue 帶入什麼、Resolve 就必須原樣拿到什麼
func TestConnectTokenCarriesAccount(t *testing.T) {
	m := NewConnectTokenManager()
	token, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 7, AccountID: 42})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	grant, ok := m.RedeemConnectToken(context.Background(), token)
	if !ok {
		t.Fatal("Resolve should succeed")
	}
	if grant.AccountID != 42 {
		t.Errorf("grant.AccountID = %d, want 42", grant.AccountID)
	}
}

func TestConnectTokenSingleUse(t *testing.T) {
	m := NewConnectTokenManager()
	token, _ := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 7, AccountID: 0})

	if _, ok := m.RedeemConnectToken(context.Background(), token); !ok {
		t.Fatal("first resolve should succeed")
	}
	if _, ok := m.RedeemConnectToken(context.Background(), token); ok {
		t.Error("second resolve must fail (single use)")
	}
}

func TestConnectTokenExpiry(t *testing.T) {
	m := NewConnectTokenManager()
	token, _ := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 7, AccountID: 0})

	// 直接竄改過期時間模擬逾時
	m.mu.Lock()
	g := m.grants[token]
	g.ExpiresAt = time.Now().Add(-time.Second)
	m.grants[token] = g
	m.mu.Unlock()

	if _, ok := m.RedeemConnectToken(context.Background(), token); ok {
		t.Error("expired token must fail")
	}
}

func TestConnectTokenUnknown(t *testing.T) {
	m := NewConnectTokenManager()
	if _, ok := m.RedeemConnectToken(context.Background(), "deadbeef"); ok {
		t.Error("unknown token must fail")
	}
}
