package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/custodexa/backend/internal/model"
	"golang.org/x/oauth2"
)

var (
	// ErrOIDCDiscoveryFailed discovery 取得或解析失敗
	ErrOIDCDiscoveryFailed = errors.New("無法取得身分提供者的 discovery 設定")
	// ErrOIDCTokenVerification id_token 驗證失敗
	ErrOIDCTokenVerification = errors.New("id_token 驗證失敗")
)

// oidcSignatureAlgs 簽章演算法封閉白名單（idp-oidc-integration D11）。
//
// 「非對稱」是類別不是清單——`等`字使實際集合無法驗收。明確列出二者：
// 三大 IdP 皆支援 RS256（Google 的 discovery 實查僅宣告 RS256）。
// 對稱演算法與 none 一律拒絕：HS256 以 client_secret 當驗章金鑰，等同把「誰能簽發」
// 降級成「誰知道 secret」；三大 IdP 亦不簽發對稱演算法的 ID token
var oidcSignatureAlgs = []string{oidc.RS256, oidc.ES256}

// oidcClockSkew 時鐘偏移容忍（D11）。
//
// 容器與 IdP 差幾秒即會出現隨機性登入失敗，症狀極難診斷。
// go-oidc 的 Config **沒有 leeway 欄位**，且單一 Now 偏移無法同時放寬 exp 與 iat
// 兩端（往回撥可容忍 exp 剛過，卻使 iat/nbf 檢查更嚴）。故採 SkipExpiryCheck
// 並自行實作時間判定——**這是本方案唯一的致命失誤模式**：開了 skip 卻忘記自檢
// 等於完全不驗過期，故必須有守衛測試涵蓋容忍窗內外兩側。
const oidcClockSkew = 60 * time.Second

// oidcJWKSMaxStale JWKS 最大陳舊時間（D17）：超過即強制重建 verifier。
// 已自 JWKS 移除的金鑰最遲於此時間內失效
const oidcJWKSMaxStale = 24 * time.Hour

// oidcJWKSMinRefetch 未知 kid 觸發重取的最小間隔（D17）。
//
// go-oidc 的 RemoteKeySet 遇未知 kid 會自動重取，但**未提供節流**——
// 攻擊者以偽造 kid 灌本系統，即可把流量放大轉嫁到 IdP 的 JWKS 端點。
// 節流的代價是「真實輪替後最多延遲一分鐘才接受新 kid」，遠小於放大攻擊的風險
const oidcJWKSMinRefetch = 60 * time.Second

// ErrOIDCJWKSThrottled JWKS 重取受節流（未知 kid 於最小間隔內再次觸發）
var ErrOIDCJWKSThrottled = errors.New("JWKS 重取受最小間隔節流")

// ErrOIDCNoCommonSigningAlg 本地允許集合與 discovery 宣告集合交集為空
var ErrOIDCNoCommonSigningAlg = errors.New("身分提供者宣告的簽章演算法與本系統允許集合無交集")

// jwksThrottleTransport 只對該 provider 的 jwks_uri 施加最小重取間隔。
//
// **刻意不對所有 URL 節流**：token 端點在正常登入尖峰會被密集呼叫，
// 一併節流即等於自我阻斷。target 於 discovery 完成後才得知，故可變
type jwksThrottleTransport struct {
	base http.RoundTripper

	mu     sync.Mutex
	target string
	last   time.Time
}

func (t *jwksThrottleTransport) setTarget(u string) {
	t.mu.Lock()
	t.target = u
	t.mu.Unlock()
}

func (t *jwksThrottleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	throttled := t.target != "" && r.URL.String() == t.target &&
		!t.last.IsZero() && time.Since(t.last) < oidcJWKSMinRefetch
	if throttled {
		t.mu.Unlock()
		return nil, ErrOIDCJWKSThrottled
	}
	if t.target != "" && r.URL.String() == t.target {
		t.last = time.Now()
	}
	t.mu.Unlock()
	return t.base.RoundTrip(r)
}

// intersectSigningAlgs 本地封閉集合與 discovery 宣告集合取交集（spec 第 29 行）。
//
// 交集為空即該 provider 不可用——這比「照本地集合硬試」誠實：IdP 若只簽
// 我方不接受的演算法，每次登入都會在驗簽階段失敗，錯誤訊息卻指向簽章而非設定
func intersectSigningAlgs(local, declared []string) []string {
	if len(declared) == 0 {
		// discovery 未宣告該欄位：無從取交集，沿用本地集合（仍是最終約束）
		return local
	}
	set := make(map[string]bool, len(declared))
	for _, a := range declared {
		set[a] = true
	}
	out := make([]string, 0, len(local))
	for _, a := range local {
		if set[a] {
			out = append(out, a)
		}
	}
	return out
}

// oidcProviderCache 快取項：**僅存非授權狀態**（discovery 文件、JWKS、verifier）。
//
// 授權關鍵欄位（enabled／auth_epoch／admission_*／force_shared）**不在此快取**，
// 一律現查 DB——epoch 驗證與 admission 每次求值的價值就在於讀到最新狀態，
// 落入行程快取會使多副本下的停用與規則收緊形同虛設
type oidcProviderCache struct {
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	fetchedAt time.Time
	// issuer/clientID 一併記錄，用於偵測設定變更（雖然兩者建後不可變，
	// 但 provider 列可能被刪除後以同 tuple 重建）
	issuer   string
	clientID string
	// httpClient 該 provider 專屬的出站 client（含 JWKS 節流層）。
	// verifier 內的 RemoteKeySet 已捕獲它，驗證時須沿用同一個才維持節流狀態
	httpClient *http.Client
	// throttle 該 client 的 JWKS 節流層（保留參照供狀態觀察與測試推進時間）
	throttle *jwksThrottleTransport
}

// OIDCDiscoveryService discovery 與 id_token 驗證（idp-oidc-integration D3/D11/D17）
type OIDCDiscoveryService struct {
	egress *OIDCEgressPolicy

	mu    sync.Mutex
	cache map[uint]*oidcProviderCache
}

// NewOIDCDiscoveryService 建立 discovery 服務
func NewOIDCDiscoveryService(egress *OIDCEgressPolicy) *OIDCDiscoveryService {
	return &OIDCDiscoveryService{egress: egress, cache: make(map[uint]*oidcProviderCache)}
}

// Invalidate 使指定 provider 的快取失效（設定變更/停用時呼叫）
func (s *OIDCDiscoveryService) Invalidate(providerID uint) {
	s.mu.Lock()
	delete(s.cache, providerID)
	s.mu.Unlock()
}

// resolve 取得（或建立）該 provider 的 discovery 與 verifier。
//
// go-oidc 的 NewProvider 會強制 discovery 文件的 issuer 與輸入完整字串一致——
// 這比只比對 netloc 的弱驗證嚴謹，也是 Azure 多租戶端點在本設計下不可用的原因
// （其 issuer 字面為 https://login.microsoftonline.com/{tenantid}/v2.0，帶 placeholder）
func (s *OIDCDiscoveryService) resolve(ctx context.Context, p *model.OIDCProvider) (*oidcProviderCache, error) {
	s.mu.Lock()
	c, ok := s.cache[p.ID]
	s.mu.Unlock()

	fresh := ok && c.issuer == p.Issuer && c.clientID == p.ClientID &&
		time.Since(c.fetchedAt) < oidcJWKSMaxStale
	if fresh {
		return c, nil
	}

	// 出站受位址政策約束（防 SSRF；檢查在 DialContext 內，故無 DNS rebinding 窗口）。
	// 另包一層 JWKS 節流：go-oidc 的 RemoteKeySet 會在此 client 上自行重取，
	// 節流必須放在它底下才攔得到
	httpClient := s.egress.HTTPClient()
	throttle := &jwksThrottleTransport{base: httpClient.Transport}
	httpClient.Transport = throttle
	ctx = oidc.ClientContext(ctx, httpClient)

	prov, err := oidc.NewProvider(ctx, strings.TrimRight(p.Issuer, "/"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCDiscoveryFailed, err)
	}

	// discovery 的宣告值：jwks_uri 供節流鎖定目標，演算法集合供取交集
	var meta struct {
		JWKSURI     string   `json:"jwks_uri"`
		SigningAlgs []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := prov.Claims(&meta); err != nil {
		return nil, fmt.Errorf("%w: 無法解析 discovery 宣告: %v", ErrOIDCDiscoveryFailed, err)
	}
	throttle.setTarget(meta.JWKSURI)

	algs := intersectSigningAlgs(oidcSignatureAlgs, meta.SigningAlgs)
	if len(algs) == 0 {
		return nil, fmt.Errorf("%w: %v", ErrOIDCNoCommonSigningAlg, meta.SigningAlgs)
	}

	verifier := prov.Verifier(&oidc.Config{
		ClientID:             p.ClientID,
		SupportedSigningAlgs: algs,
		// 自行實作時間判定以獲得雙向的偏移容忍（見 oidcClockSkew 的說明）。
		// **verifyTimeClaims 是這個 skip 的配套，不可缺**
		SkipExpiryCheck: true,
	})

	c = &oidcProviderCache{
		provider: prov, verifier: verifier, fetchedAt: time.Now(),
		issuer: p.Issuer, clientID: p.ClientID, httpClient: httpClient, throttle: throttle,
	}
	s.mu.Lock()
	s.cache[p.ID] = c
	s.mu.Unlock()
	return c, nil
}

// OAuth2Config 組出該 provider 的 oauth2 設定
func (s *OIDCDiscoveryService) OAuth2Config(ctx context.Context, p *model.OIDCProvider,
	secret, redirectURI string) (*oauth2.Config, error) {
	c, err := s.resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: secret,
		Endpoint:     c.provider.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       strings.Fields(p.Scopes),
	}, nil
}

// VerifiedClaims id_token 驗證通過後的 claims
type VerifiedClaims struct {
	Subject           string
	PreferredUsername string
	Email             string
	EmailVerified     bool
	Name              string
	// Raw 全部 claims，供 admission 規則求值
	Raw map[string]any
}

// VerifyIDToken 驗證 id_token 並取出 claims（D11 的驗證清單執行點）。
//
// go-oidc 負責：簽章（限白名單演算法）、iss 完整字串比對、aud 含 client_id、nonce。
// 本函式另外負責：**時間判定（exp/iat/nbf ±60s，因 SkipExpiryCheck 已開）**、
// 多 audience 時的 azp 比對、sub 的非空與長度檢查。
func (s *OIDCDiscoveryService) VerifyIDToken(ctx context.Context, p *model.OIDCProvider,
	rawIDToken, expectedNonce string) (*VerifiedClaims, error) {
	c, err := s.resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	ctx = oidc.ClientContext(ctx, c.httpClient)

	tok, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCTokenVerification, err)
	}
	if tok.Nonce != expectedNonce {
		return nil, fmt.Errorf("%w: nonce 不符", ErrOIDCTokenVerification)
	}
	if err := verifyTimeClaims(tok); err != nil {
		return nil, err
	}
	if err := verifyAudience(tok, p.ClientID); err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := tok.Claims(&raw); err != nil {
		return nil, fmt.Errorf("%w: claims 解析失敗", ErrOIDCTokenVerification)
	}

	sub := strings.TrimSpace(tok.Subject)
	if sub == "" || len(sub) > 255 {
		// 空 subject 會使第一個異常 token 吸附該 provider 後續全部異常 token
		return nil, fmt.Errorf("%w: subject 為空或過長", ErrOIDCTokenVerification)
	}

	vc := &VerifiedClaims{Subject: sub, Raw: raw}
	if v, ok := raw["preferred_username"].(string); ok {
		vc.PreferredUsername = strings.TrimSpace(v)
	}
	if v, ok := raw["email"].(string); ok {
		vc.Email = strings.TrimSpace(v)
	}
	if v, ok := raw["email_verified"].(bool); ok {
		vc.EmailVerified = v
	}
	if v, ok := raw["name"].(string); ok {
		vc.Name = strings.TrimSpace(v)
	}
	return vc, nil
}

// verifyTimeClaims 時間判定（SkipExpiryCheck 的配套，D11）。
//
// **此函式是安全關鍵**：verifier 已開 SkipExpiryCheck，若這裡漏檢即等於完全
// 不驗過期。容忍 ±60 秒的時鐘偏移，兩端各自放寬
func verifyTimeClaims(tok *oidc.IDToken) error {
	now := time.Now()

	// exp／iat 於 OIDC Core 為必填，此處**強制存在**。
	// 「有值才檢查」在 SkipExpiryCheck 之下是致命的：缺 exp 的 token 會永遠通過，
	// 等同一張不會到期的憑證，而 go-oidc 因 skip 也不會替我們把關
	if tok.Expiry.IsZero() {
		return fmt.Errorf("%w: 缺少 exp", ErrOIDCTokenVerification)
	}
	if tok.IssuedAt.IsZero() {
		return fmt.Errorf("%w: 缺少 iat", ErrOIDCTokenVerification)
	}
	if now.After(tok.Expiry.Add(oidcClockSkew)) {
		return fmt.Errorf("%w: token 已過期", ErrOIDCTokenVerification)
	}
	if tok.IssuedAt.After(now.Add(oidcClockSkew)) {
		return fmt.Errorf("%w: token 簽發時間位於未來", ErrOIDCTokenVerification)
	}

	// nbf 為選填；有值即須生效。go-oidc 的 IDToken 未暴露此欄，故自 claims 取。
	// 型別以 float64 收（JSON 數值一律解為浮點），非數值型別即拒——外部可控值
	// 不做寬鬆轉型
	var c struct {
		NotBefore *float64 `json:"nbf"`
	}
	if err := tok.Claims(&c); err != nil {
		return fmt.Errorf("%w: 無法解析 nbf", ErrOIDCTokenVerification)
	}
	if c.NotBefore != nil {
		nbf := time.Unix(int64(*c.NotBefore), 0)
		if now.Add(oidcClockSkew).Before(nbf) {
			return fmt.Errorf("%w: token 尚未生效", ErrOIDCTokenVerification)
		}
	}
	return nil
}

// verifyAudience 多 audience 時強制 azp 等於 client_id（D11）。
//
// 缺此檢查時，若 IdP 簽出多 aud 的 id_token，本系統會接受**實際授權給另一個
// client** 的 token，形成跨 client 冒名
func verifyAudience(tok *oidc.IDToken, clientID string) error {
	if len(tok.Audience) <= 1 {
		return nil
	}
	var claims struct {
		AZP string `json:"azp"`
	}
	if err := tok.Claims(&claims); err != nil {
		return fmt.Errorf("%w: 無法解析 azp", ErrOIDCTokenVerification)
	}
	if claims.AZP != clientID {
		return fmt.Errorf("%w: 多 audience 但 azp 不符", ErrOIDCTokenVerification)
	}
	return nil
}
