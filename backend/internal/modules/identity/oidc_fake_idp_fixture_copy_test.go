package identity_test

// identity 測試夾具的複本：假 IdP。理由見 identity_fixtures_test.go 檔頭。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIdP 測試用的 OIDC 身分提供者。
//
// 提供 discovery、JWKS 與可控的 id_token 簽發，使驗證失敗矩陣（簽章、演算法、
// iss、aud/azp、exp/iat、nonce、空 sub）與 JWKS 輪替四情境得以逐格覆蓋——
// 這些情境在真實 IdP 上無法製造。
type fakeIdP struct {
	server *httptest.Server
	// issuer 對外宣告的 issuer；刻意可與實際位址不同，用於製造 iss 不符的情境
	issuer string

	mu sync.Mutex
	// published JWKS 目前發佈的金鑰（可輪替、可移除）
	published []fakeKey
	// signing 目前用來簽發的金鑰；可指向已自 JWKS 移除者
	signing fakeKey

	// stagedCodes 預先登錄的授權碼 → id_token；未登錄者於 /token 回 400
	stagedCodes map[string]string
	// lastCodeVerifier 最近一次 token 請求帶的 PKCE verifier，供測試斷言
	// 「PKCE 確實有送出」——它是恆啟用而非可關閉選項
	lastCodeVerifier string
	// expectedChallenge 若非空，/token 會驗證 S256(code_verifier) == challenge。
	// 只斷言「verifier 非空」不足以證明 PKCE 有效——送一個固定字串也會非空
	expectedChallenge string
	// pkceMismatch 記錄配對失敗，供測試斷言
	pkceMismatch bool
	// tokenRequests /token 被呼叫的次數（授權碼一次性的佐證）
	tokenRequests int
	// jwksReqs /keys 被取用的次數，供「未知 kid 重取受節流」斷言。
	// 沒有這個計數就無法區分「節流生效」與「根本沒重取」
	jwksReqs int
	// declaredAlgs discovery 宣告的 id_token 簽章演算法集合
	declaredAlgs []string
}

type fakeKey struct {
	kid string
	key *rsa.PrivateKey
}

func newFakeKey(t *testing.T, kid string) fakeKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成測試金鑰失敗: %v", err)
	}
	return fakeKey{kid: kid, key: key}
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	k := newFakeKey(t, "test-key-1")
	f := &fakeIdP{published: []fakeKey{k}, signing: k, stagedCodes: map[string]string{},
		declaredAlgs: []string{"RS256"}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.issuer,
			"authorization_endpoint":                f.server.URL + "/auth",
			"token_endpoint":                        f.server.URL + "/token",
			"jwks_uri":                              f.server.URL + "/keys",
			"userinfo_endpoint":                     f.server.URL + "/userinfo",
			"id_token_signing_alg_values_supported": f.declaredAlgs,
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.jwksReqs++
		keys := make([]map[string]any, 0, len(f.published))
		for _, k := range f.published {
			keys = append(keys, map[string]any{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.kid,
				"n": base64.RawURLEncoding.EncodeToString(k.key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.key.E)).Bytes()),
			})
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	// /token 授權碼交換端點：只認預先登錄的 code，且一次性
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		verifier := r.PostFormValue("code_verifier")
		f.mu.Lock()
		f.tokenRequests++
		f.lastCodeVerifier = verifier
		// PKCE 實際配對：S256(verifier) 須等於授權請求送出的 challenge。
		// 這是 IdP 端本該做的事，fake IdP 不做就等於全鏈路測試對 PKCE 無感
		if f.expectedChallenge != "" {
			sum := sha256.Sum256([]byte(verifier))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != f.expectedChallenge {
				f.pkceMismatch = true
			}
		}
		idToken, ok := f.stagedCodes[r.PostFormValue("code")]
		delete(f.stagedCodes, r.PostFormValue("code")) // 授權碼一次性
		mismatch := f.pkceMismatch
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if mismatch {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token", "token_type": "Bearer",
			"expires_in": 3600, "id_token": idToken,
		})
	})
	// /auth 授權端點：本測試不走瀏覽器，僅供 discovery 宣告完整
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	f.server = httptest.NewServer(mux)
	f.issuer = f.server.URL
	t.Cleanup(f.server.Close)
	return f
}

// jwksRequests JWKS 端點被取用的次數
func (f *fakeIdP) jwksRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jwksReqs
}

// newFakeIdPWithAlgs discovery 宣告指定演算法集合的 fake IdP
func newFakeIdPWithAlgs(t *testing.T, algs []string) *fakeIdP {
	t.Helper()
	f := newFakeIdP(t)
	f.mu.Lock()
	f.declaredAlgs = algs
	f.mu.Unlock()
	return f
}

// stageCode 登錄一組授權碼與其對應的 id_token（模擬使用者已在 IdP 完成認證）
func (f *fakeIdP) stageCode(code, idToken string) {
	f.mu.Lock()
	f.stagedCodes[code] = idToken
	f.mu.Unlock()
}

// expectChallenge 要求 /token 驗證 S256(code_verifier) 與此 challenge 相符
func (f *fakeIdP) expectChallenge(challenge string) {
	f.mu.Lock()
	f.expectedChallenge = challenge
	f.mu.Unlock()
}

func (f *fakeIdP) stats() (requests int, verifier string, pkceMismatch bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenRequests, f.lastCodeVerifier, f.pkceMismatch
}

// publishKeys 覆寫 JWKS 內容（模擬 IdP 輪替：新增 kid、同 kid 換 key、移除舊 key）
func (f *fakeIdP) publishKeys(keys ...fakeKey) {
	f.mu.Lock()
	f.published = keys
	f.mu.Unlock()
}

// signWith 指定後續簽發所用金鑰
func (f *fakeIdP) signWith(k fakeKey) {
	f.mu.Lock()
	f.signing = k
	f.mu.Unlock()
}

// idTokenOpts 控制簽發內容，用於製造各種驗證失敗情境
type idTokenOpts struct {
	subject   string
	audience  any // string 或 []string
	azp       string
	nonce     string
	issuer    string // 空＝用 f.issuer
	expiresIn time.Duration
	issuedAt  time.Time
	extra     map[string]any
	// signWithOtherKey 以一把從未發佈的金鑰簽（製造簽章驗證失敗）
	signWithOtherKey bool
	// alg 覆寫簽章演算法（製造演算法不在白名單的情境）
	alg jwt.SigningMethod
	// omitExpiry／omitIssuedAt 完全省略該時間宣告。
	// OIDC Core 要求兩者必填，但 SkipExpiryCheck 之下我方若不自行強制，
	// 缺 exp 的 token 就會永久有效——故必須能製造出「欄位不存在」而非「值為零」
	omitExpiry   bool
	omitIssuedAt bool
}

func (f *fakeIdP) issueIDToken(t *testing.T, o idTokenOpts) string {
	t.Helper()
	now := time.Now()
	if o.issuedAt.IsZero() {
		o.issuedAt = now
	}
	if o.expiresIn == 0 {
		o.expiresIn = 5 * time.Minute
	}
	iss := o.issuer
	if iss == "" {
		iss = f.issuer
	}
	if o.audience == nil {
		// 忘記帶 audience 會產生 "aud": null，於是驗證因 aud 不符而失敗——
		// 任何「應被拒絕」的斷言都會因錯誤的理由變綠。給預設值消除這個陷阱
		o.audience = "test-client"
	}
	claims := jwt.MapClaims{
		"iss": iss,
		"sub": o.subject,
		"aud": o.audience,
	}
	if !o.omitExpiry {
		claims["exp"] = o.issuedAt.Add(o.expiresIn).Unix()
	}
	if !o.omitIssuedAt {
		claims["iat"] = o.issuedAt.Unix()
	}
	if o.nonce != "" {
		claims["nonce"] = o.nonce
	}
	if o.azp != "" {
		claims["azp"] = o.azp
	}
	for k, v := range o.extra {
		claims[k] = v
	}

	method := o.alg
	if method == nil {
		method = jwt.SigningMethodRS256
	}
	tok := jwt.NewWithClaims(method, claims)

	f.mu.Lock()
	signKey := f.signing
	f.mu.Unlock()
	if o.signWithOtherKey {
		signKey = newFakeKey(t, signKey.kid) // 同 kid 但金鑰不同：純簽章偽造
	}
	tok.Header["kid"] = signKey.kid

	// HS256 等對稱演算法需要 []byte 金鑰
	if method == jwt.SigningMethodHS256 {
		s, err := tok.SignedString([]byte("symmetric-secret"))
		if err != nil {
			t.Fatalf("簽發對稱 token 失敗: %v", err)
		}
		return s
	}
	s, err := tok.SignedString(signKey.key)
	if err != nil {
		t.Fatalf("簽發 token 失敗: %v", err)
	}
	return s
}
