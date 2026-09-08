package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 探索預覽：管理端唯讀，輸入 issuer 回端點清單與支援的宣告。
//
// # 為什麼沿用既有的出站信任邊界而不另建撥號路徑
//
// 另建即等於開出一支管理員可指向任意內網位址的探測器。本函式一律走
// OIDCEgressPolicy 的 issuer 形狀驗證與位址政策 client：形狀不合即在撥號前拒絕，
// 解析到內部網段即在 DialContext 上被擋（每次連線重新檢查，故無 DNS rebinding 窗口）。
//
// # 不落庫
//
// 預覽不建立、不更新任何 provider 列。它是「填表之前先看看那個 issuer 是什麼」，
// 把它做成順手寫回設定會讓一次探索變成一次未經確認的設定變更。
//
// # 呼叫留痕
//
// 這是一支能讓管理員對外發起連線的端點，「誰在什麼時候要系統去連哪裡」本身
// 就是課責內容。成功與失敗都寫一列（失敗只記靜態成因分類，不記對端回應內容）。

// OIDCDiscoveryPreview 探索預覽的回應形狀（欄名逐字沿 OpenID discovery 文件）
type OIDCDiscoveryPreview struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	ClaimsSupported       []string `json:"claims_supported"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// 探索預覽的審計事件碼（Details.event）
const (
	OIDCAuditEventDiscoveryPreview = "oidc_discovery_preview"
)

// oidcDiscoveryPreviewTimeout 預覽的整體時限。
// 沿出站政策的逾時量級：管理端等待一支撥號請求的耐受度與登入路徑相同
const oidcDiscoveryPreviewTimeout = oidcEgressTimeout

// PreviewDiscovery 取回 issuer 的探索文件（不落庫）。
//
// 回傳的 error 恆為 ErrOIDCDiscoveryFailed 或 issuer 形狀／出站政策的既有錯誤，
// 對端的原始回應內容不外傳——逐因回報等於把管理端變成一支可讀出內網探測結果的工具。
func (s *IdentitySourceService) PreviewDiscovery(ctx context.Context, egress *OIDCEgressPolicy,
	issuer string, actor GroupRoleMappingActor) (*OIDCDiscoveryPreview, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	if egress == nil {
		return nil, ErrOIDCDiscoveryFailed
	}
	raw := strings.TrimRight(strings.TrimSpace(issuer), "/")
	if err := egress.ValidateIssuerURL(raw); err != nil {
		// 形狀或 scheme 不合：在撥號**之前**拒絕，且一樣留痕
		s.auditDiscoveryPreview(actor, raw, false, "issuer_rejected")
		return nil, err
	}

	out, ferr := fetchDiscoveryPreview(ctx, egress.HTTPClient(), raw)
	if ferr != nil {
		// 失敗成因只落伺服端 log（含對端位址與錯誤），對外收斂成一支碼
		log.Printf("[OIDC] 探索預覽失敗 issuer=%s: %v", raw, ferr)
		s.auditDiscoveryPreview(actor, raw, false, "fetch_failed")
		return nil, ErrOIDCDiscoveryFailed
	}
	s.auditDiscoveryPreview(actor, raw, true, "")
	return out, nil
}

// fetchDiscoveryPreview 取 well-known 文件並解析。
//
// **自行組 well-known 路徑而不借用 go-oidc 的 NewProvider**：後者會一併建立
// verifier 與 RemoteKeySet（多一次 JWKS 取得），而預覽只需要文件本身；
// 且 NewProvider 對 issuer 一致性的強制比對會讓「文件裡的 issuer 與輸入不同」
// 表現為連線失敗，而那正是預覽該顯示給管理者看的內容。
func fetchDiscoveryPreview(ctx context.Context, client *http.Client,
	issuer string) (*OIDCDiscoveryPreview, error) {
	ctx, cancel := context.WithTimeout(ctx, oidcDiscoveryPreviewTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("探索文件回應狀態 %d", resp.StatusCode)
	}
	var doc OIDCDiscoveryPreview
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("解析探索文件失敗: %w", err)
	}
	if doc.Issuer == "" {
		return nil, fmt.Errorf("探索文件未宣告 issuer")
	}
	return &doc, nil
}

// auditDiscoveryPreview 呼叫留痕。
//
// **不是 fail-close**：預覽不改變任何狀態，留痕失敗時讓查詢照樣回答比讓
// 管理者卡在一支唯讀端點上合理；寫入失敗落伺服端 log。
func (s *IdentitySourceService) auditDiscoveryPreview(actor GroupRoleMappingActor,
	issuer string, ok bool, failure string) {
	details := map[string]any{
		"event":   OIDCAuditEventDiscoveryPreview,
		"issuer":  issuer,
		"outcome": discoveryPreviewOutcome(ok),
	}
	if failure != "" {
		details["failure"] = failure
	}
	payload, err := json.Marshal(details)
	if err != nil {
		log.Printf("[OIDC] 探索預覽審計序列化失敗: %v", err)
		return
	}
	status := model.StatusSuccess
	if !ok {
		status = model.StatusFailure
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
			Action:   string(model.ActionExecute),
			Resource: string(model.ResourceOIDCProvider),
			Status:   string(status),
			Actor:    gatewayapi.Actor{UserID: actor.ID, Username: actor.Name},
			Request:  gatewayapi.RequestMeta{ClientIP: actor.IP},
			Details:  string(payload),
		})
	}); err != nil {
		log.Printf("[OIDC] 探索預覽審計寫入失敗: %v", err)
	}
}

func discoveryPreviewOutcome(ok bool) string {
	if ok {
		return "success"
	}
	return "failed"
}

// CachedReachable 探索文件是否已被本系統成功取得（**只讀快取，不撥號**）。
//
// true＝快取內有這個 provider 的新鮮項目，那是「曾經真的連上並解析成功」的證據；
// 沒有項目即 nil（尚無資料），**不回 false**——沒試過與試過失敗是兩件事，
// 而燈號把 false 畫成黃色（有問題）。
func (s *OIDCDiscoveryService) CachedReachable(p *model.OIDCProvider) *bool {
	if s == nil || p == nil {
		return nil
	}
	s.mu.Lock()
	c, ok := s.cache[p.ID]
	s.mu.Unlock()
	if !ok || c.issuer != p.Issuer || c.clientID != p.ClientID ||
		time.Since(c.fetchedAt) >= oidcJWKSMaxStale {
		return nil
	}
	reachable := true
	return &reachable
}
