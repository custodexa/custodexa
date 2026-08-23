package identity

// SessionVerifier 的**消費側**測試
//
// 「消費側」＝以 `gatewayapi.SessionVerifier` 這個**介面型別**為依賴的測試。
// `authenticateWS` 只認得介面，對 `AuthService` 一無所知——它同時被手寫替身與
// 真實 `*AuthService` 驅動，證明「只經介面就能完成 WS 端點的身分認證這件職責」。

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// authenticateWS 純介面消費端：WS 端點的 query token 認證。
// 回傳 (userID, 角色快照, 是否通過)。
func authenticateWS(ctx context.Context, v gatewayapi.SessionVerifier,
	rawJWT string) (uint, string, bool) {
	p, err := v.VerifySession(ctx, rawJWT)
	if err != nil {
		return 0, "", false
	}
	return p.UserID, p.Role, true
}

// ── 手寫替身：只依介面契約而生 ────────────────────────────────────────

type stubVerifier struct {
	principal gatewayapi.Principal
	err       error
	sawJWT    string
}

var _ gatewayapi.SessionVerifier = (*stubVerifier)(nil)

func (s *stubVerifier) VerifySession(_ context.Context, rawJWT string) (gatewayapi.Principal, error) {
	s.sawJWT = rawJWT
	return s.principal, s.err
}

// TestSessionVerifierConsumerAcceptsPrincipal 通過時，消費端只憑介面就取得身分快照
func TestSessionVerifierConsumerAcceptsPrincipal(t *testing.T) {
	stub := &stubVerifier{principal: gatewayapi.Principal{UserID: 11, Username: "alice", Role: "admin"}}
	userID, role, ok := authenticateWS(context.Background(), stub, "raw.jwt.value")
	if !ok || userID != 11 || role != "admin" {
		t.Fatalf("身分快照未穿過介面: id=%d role=%q ok=%v", userID, role, ok)
	}
	if stub.sawJWT != "raw.jwt.value" {
		t.Fatalf("原始 JWT 未原樣穿過介面: %q", stub.sawJWT)
	}
}

// TestSessionVerifierConsumerRejectsScopedToken 真實實作：scoped token（MFA pending／
// 強制改密／MFA 註冊）一律 deny-by-default——這是 WS 旁路曾被繞過一次的那道閘，
// 且它在任何 DB 存取**之前**判定，故本格不需資料庫夾具。
func TestSessionVerifierConsumerRejectsScopedToken(t *testing.T) {
	svc := NewAuthService("secret", 15*time.Minute)
	var v gatewayapi.SessionVerifier = svc

	scoped, err := svc.jwtManager.GenerateScopedToken(1, "bob", "bob@example.com", "user",
		crypto.ScopeMFAPending, 5*time.Minute, crypto.AuthContext{})
	if err != nil {
		t.Fatalf("產生 scoped token 失敗: %v", err)
	}
	if _, _, ok := authenticateWS(context.Background(), v, scoped); ok {
		t.Fatal("scoped token 不得通過 WS 認證面（deny-by-default）")
	}
	if _, _, ok := authenticateWS(context.Background(), v, "not-a-jwt"); ok {
		t.Fatal("非法 token 不得通過")
	}
}

// TestSessionVerifierConsumerMapsClaimsToPrincipal 真實實作的快樂路徑：
// 逐欄比對 claims → Principal 的對映，證明本方法**只做對映、不新增判定**。
// 兩次 DB 讀（可連線複查、憑證世代）以 sqlmock 供應。
func TestSessionVerifierConsumerMapsClaimsToPrincipal(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := NewAuthService("secret", 15*time.Minute)
	var v gatewayapi.SessionVerifier = svc

	authCtx := crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: 3, AuthEpoch: 2, CredEpoch: 7,
	}
	token, err := svc.jwtManager.GenerateToken(42, "carol", "carol@example.com", "auditor", authCtx)
	if err != nil {
		t.Fatalf("產生 token 失敗: %v", err)
	}

	// (1) CheckUserConnectable：active 且未鎖定
	mock.ExpectQuery(`SELECT .+ FROM "users"`).
		WillReturnRows(sqlmock.NewRows([]string{"active", "locked_until"}).AddRow(true, nil))
	// (2) VerifyCredentialGenerationByUserID：使用者憑證世代與 token 相符
	mock.ExpectQuery(`SELECT .+ FROM "users"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "credential_epoch"}).AddRow(42, 7))
	// (3) provider 啟用與 auth_epoch 相符（OIDC 脈絡才有這一趟）
	mock.ExpectQuery(`SELECT .+ FROM "oidc_providers"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "auth_epoch", "enabled"}).AddRow(3, 2, true))

	p, err := v.VerifySession(context.Background(), token)
	if err != nil {
		t.Fatalf("有效 session token 應通過: %v", err)
	}
	if p.UserID != 42 || p.Username != "carol" || p.Role != "auditor" || p.Scope != "" {
		t.Fatalf("身分欄位對映不符: %+v", p)
	}
	if p.AuthMethod != crypto.AuthMethodOIDC || p.ProviderID != 3 ||
		p.AuthEpoch != 2 || p.CredEpoch != 7 {
		t.Fatalf("認證脈絡對映不符: %+v", p)
	}
}
