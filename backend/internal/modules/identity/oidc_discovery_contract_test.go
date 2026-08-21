package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 真實 IdP discovery 文件的契約測試（idp-oidc-integration tasks 0.3a）。
//
// **本檔的存在理由是防止「信任門檻收緊」誤傷真實目標**：設計草案中的「endpoint
// 必須與 issuer 同源」即屬此類——它讀起來像是合理的縱深防禦，卻會當場阻斷 Google
// （四個 endpoint 分佈於四個 host）。fakeIdP 的 discovery 恰好全部同源，故那類回歸
// **不會使既有任何一格變紅**；唯有把真實文件餵進同一條解析路徑才抓得到。
//
// fixture 為 2026-08-04 匿名實抓（來源與更新守則見 testdata/discovery/README.md），
// 以本地 httptest 重播，測試不觸網。

const discoveryFixtureDir = "testdata/discovery"

// loadDiscoveryFixture 讀入 fixture 原文（不做任何欄位改寫）
func loadDiscoveryFixture(t *testing.T, file string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(discoveryFixtureDir, file))
	if err != nil {
		t.Fatalf("讀取 fixture %s 失敗: %v", file, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("fixture %s 非合法 JSON: %v", file, err)
	}
	if doc["issuer"] == nil {
		t.Fatalf("fixture %s 缺 issuer，前提不成立", file)
	}
	return doc
}

// replayDiscovery 以本地伺服器重播 fixture，回傳可當作 provider.Issuer 使用的位址。
//
// issuerOverride 非空時取代文件中的 issuer 欄位（其餘欄位**逐字保留**，
// 包括那些指向真實 IdP host 的 endpoint——跨 host 正是本檔要斷言的性質）。
// 傳入 sentinel replayVerbatim 則完全不改寫，用於斷言 issuer 逐字比對會擋下不符者；
// replaySelfTrailingSlash 宣告「自身位址＋尾斜線」，用於斷言比對不做正規化。
const (
	replayVerbatim          = "\x00verbatim"
	replaySelfTrailingSlash = "\x00self-trailing-slash"
)

func replayDiscovery(t *testing.T, doc map[string]any, issuerOverride string) string {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		out := make(map[string]any, len(doc))
		for k, v := range doc {
			out[k] = v
		}
		switch issuerOverride {
		case replayVerbatim:
			// 保留原始 issuer
		case replaySelfTrailingSlash:
			out["issuer"] = srv.URL + "/"
		case "":
			out["issuer"] = srv.URL
		default:
			out["issuer"] = issuerOverride
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func fixtureString(t *testing.T, doc map[string]any, key string) string {
	t.Helper()
	v, ok := doc[key].(string)
	if !ok {
		t.Fatalf("fixture 的 %s 不是字串（實得 %T）", key, doc[key])
	}
	return v
}

func fixtureStrings(t *testing.T, doc map[string]any, key string) []string {
	t.Helper()
	raw, ok := doc[key].([]any)
	if !ok {
		t.Fatalf("fixture 的 %s 不是陣列（實得 %T）", key, doc[key])
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("fixture 的 %s 含非字串元素 %T", key, v)
		}
		out = append(out, s)
	}
	return out
}

// realIdPFixtures 三家可用形狀（Entra 取 tenant-specific——common 因 issuer 帶
// placeholder 而恆不可用，另於 TestDiscoveryContractEntraCommonIssuerPlaceholder 斷言）
var realIdPFixtures = []struct {
	name string
	file string
}{
	{"Google", "google.json"},
	{"Entra（tenant-specific）", "entra-tenant-specific.json"},
	{"Okta", "okta.json"},
}

func TestDiscoveryContractRealIdPDocumentsResolve(t *testing.T) {
	for _, f := range realIdPFixtures {
		t.Run(f.name, func(t *testing.T) {
			doc := loadDiscoveryFixture(t, f.file)
			issuer := replayDiscovery(t, doc, "")

			svc := NewOIDCDiscoveryService(testEgress())
			p := &model.OIDCProvider{Issuer: issuer, ClientID: "test-client", Enabled: true}
			p.ID = 1

			c, err := svc.resolve(context.Background(), p)
			if err != nil {
				t.Fatalf("真實 IdP 的 discovery 文件應被我方接受，實得: %v", err)
			}

			// endpoint 逐字沿用文件宣告值——**不得被改寫成 issuer 同源的推導值**
			if got, want := c.provider.Endpoint().AuthURL, fixtureString(t, doc, "authorization_endpoint"); got != want {
				t.Errorf("authorization_endpoint = %q, want %q", got, want)
			}
			if got, want := c.provider.Endpoint().TokenURL, fixtureString(t, doc, "token_endpoint"); got != want {
				t.Errorf("token_endpoint = %q, want %q", got, want)
			}
			// JWKS 節流層鎖定的目標即文件宣告的 jwks_uri（Google 的該值在第三個 host）
			if got, want := c.throttle.target, fixtureString(t, doc, "jwks_uri"); got != want {
				t.Errorf("節流目標 = %q, want %q（jwks_uri 未被正確鎖定）", got, want)
			}
		})
	}
}

func TestDiscoveryContractGoogleEndpointsSpanFourHosts(t *testing.T) {
	// design 已裁決不可要求 endpoint 與 issuer 同源。此格是該裁決的機械保證：
	// 任何同源限制都會使下面的 resolve 失敗，或使四 host 的前提斷言失效
	doc := loadDiscoveryFixture(t, "google.json")

	endpoints := map[string]string{
		"issuer":                 fixtureString(t, doc, "issuer"),
		"authorization_endpoint": fixtureString(t, doc, "authorization_endpoint"),
		"token_endpoint":         fixtureString(t, doc, "token_endpoint"),
		"jwks_uri":               fixtureString(t, doc, "jwks_uri"),
		"userinfo_endpoint":      fixtureString(t, doc, "userinfo_endpoint"),
	}

	hosts := map[string]bool{}
	policy := testEgress()
	for name, raw := range endpoints {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s 解析失敗: %v", name, err)
		}
		hosts[u.Host] = true
		// 形狀門檻（https／無 userinfo／無 query／無 fragment）須接受真實 endpoint。
		// 正式碼目前只把此閘套用於 issuer；此處對全部 endpoint 掃一遍，是為了讓
		// 「日後把形狀限制擴及 endpoint」這類收緊在此當場現形，而非上線後才誤傷
		if err := policy.ValidateIssuerURL(raw); err != nil {
			t.Errorf("形狀門檻拒絕了 Google 的 %s (%s): %v", name, raw, err)
		}
	}
	// issuer＋三個 endpoint 分佈於四個不同 host（authorization_endpoint 與 issuer 同 host）
	if len(hosts) != 4 {
		t.Fatalf("Google 的 endpoint 應橫跨 4 個 host，實得 %d 個: %v（fixture 可能已過期）",
			len(hosts), hosts)
	}

	// 跨 host 的文件必須真的走得完我方 resolve
	issuer := replayDiscovery(t, doc, "")
	svc := NewOIDCDiscoveryService(testEgress())
	p := &model.OIDCProvider{Issuer: issuer, ClientID: "test-client", Enabled: true}
	p.ID = 1
	c, err := svc.resolve(context.Background(), p)
	if err != nil {
		t.Fatalf("跨 host 的 Google discovery 應被接受（同源限制會在此當場失敗）: %v", err)
	}
	issuerHost, err := url.Parse(issuer)
	if err != nil {
		t.Fatalf("重播位址解析失敗: %v", err)
	}
	tokenHost, err := url.Parse(c.provider.Endpoint().TokenURL)
	if err != nil {
		t.Fatalf("token_endpoint 解析失敗: %v", err)
	}
	if tokenHost.Host == issuerHost.Host {
		t.Fatal("前提不成立：token_endpoint 與 issuer 竟同 host，本測試失去防同源回歸的意義")
	}
}

func TestDiscoveryContractSigningAlgIntersectionNonEmpty(t *testing.T) {
	// 演算法白名單一旦收緊到與真實 IdP 無交集，該 provider 即完全不可用。
	// 四份 fixture（含 Entra common）全數納入
	files := []string{"google.json", "entra-common.json", "entra-tenant-specific.json", "okta.json"}
	for _, f := range files {
		doc := loadDiscoveryFixture(t, f)
		declared := fixtureStrings(t, doc, "id_token_signing_alg_values_supported")
		got := intersectSigningAlgs(oidcSignatureAlgs, declared)
		if len(got) == 0 {
			t.Errorf("%s: 本地白名單 %v 與宣告集合 %v 交集為空——該 IdP 將完全不可用",
				f, oidcSignatureAlgs, declared)
			continue
		}
		// 三家實查皆宣告 RS256；本地集合若移除 RS256 即三家全滅
		hasRS256 := false
		for _, a := range got {
			if a == "RS256" {
				hasRS256 = true
			}
		}
		if !hasRS256 {
			t.Errorf("%s: 交集 %v 不含 RS256（三大 IdP 皆以 RS256 簽發）", f, got)
		}
	}
}

func TestDiscoveryContractIssuerComparedLiterally(t *testing.T) {
	// issuer 為逐字比對而非 host 比對或正規化比對——這既是 Entra common
	// 不可用的成因，也是「把 issuer 指到別處就換一個 IdP」的防線
	doc := loadDiscoveryFixture(t, "google.json")

	t.Run("文件 issuer 與取得位址不符即拒", func(t *testing.T) {
		issuer := replayDiscovery(t, doc, replayVerbatim)
		svc := NewOIDCDiscoveryService(testEgress())
		p := &model.OIDCProvider{Issuer: issuer, ClientID: "test-client", Enabled: true}
		p.ID = 1
		_, err := svc.resolve(context.Background(), p)
		if !errors.Is(err, ErrOIDCDiscoveryFailed) {
			t.Fatalf("issuer 不符應歸類為 discovery 失敗，實得 %v", err)
		}
	})

	t.Run("僅差一個尾斜線亦拒", func(t *testing.T) {
		svc := NewOIDCDiscoveryService(testEgress())
		// 文件宣告「自身位址＋尾斜線」。resolve 會 TrimRight 掉設定值的尾斜線，
		// 故此處的差異純粹來自文件端，正是逐字比對才擋得住的形狀
		issuer := replayDiscovery(t, doc, replaySelfTrailingSlash)
		p := &model.OIDCProvider{Issuer: issuer, ClientID: "test-client", Enabled: true}
		p.ID = 1
		if _, err := svc.resolve(context.Background(), p); !errors.Is(err, ErrOIDCDiscoveryFailed) {
			t.Fatalf("尾斜線差異應使逐字比對失敗，實得 %v", err)
		}
	})
}

func TestDiscoveryContractEntraCommonIssuerPlaceholder(t *testing.T) {
	// tasks 0.3 的實查結論文件化：Entra 多租戶 common 端點的 issuer 字面帶
	// placeholder，逐字比對之下恆不可用，管理者必須改用 tenant-specific 端點
	common := loadDiscoveryFixture(t, "entra-common.json")
	iss := fixtureString(t, common, "issuer")
	if !strings.Contains(iss, "{tenantid}") {
		t.Fatalf("Entra common 的 issuer 應含 {tenantid} placeholder，實得 %q（fixture 可能已過期）", iss)
	}

	// 逐字重播：無論自哪個位址取得，帶 placeholder 的 issuer 都不可能相符
	svc := NewOIDCDiscoveryService(testEgress())
	p := &model.OIDCProvider{
		Issuer:   replayDiscovery(t, common, replayVerbatim),
		ClientID: "test-client", Enabled: true,
	}
	p.ID = 1
	if _, err := svc.resolve(context.Background(), p); !errors.Is(err, ErrOIDCDiscoveryFailed) {
		t.Fatalf("帶 placeholder 的 issuer 應使 discovery 失敗，實得 %v", err)
	}

	// 對照組：同一家 IdP 的 tenant-specific 形狀無 placeholder 且可用——
	// 證明「不可用」源自 common 端點的 issuer 形狀，而非我方擋掉了 Entra
	tenant := loadDiscoveryFixture(t, "entra-tenant-specific.json")
	tenantIss := fixtureString(t, tenant, "issuer")
	if strings.ContainsAny(tenantIss, "{}") {
		t.Fatalf("tenant-specific issuer 不應含 placeholder，實得 %q", tenantIss)
	}
	svc2 := NewOIDCDiscoveryService(testEgress())
	p2 := &model.OIDCProvider{
		Issuer:   replayDiscovery(t, tenant, ""),
		ClientID: "test-client", Enabled: true,
	}
	p2.ID = 1
	if _, err := svc2.resolve(context.Background(), p2); err != nil {
		t.Fatalf("tenant-specific 的 Entra discovery 應可用: %v", err)
	}
}
