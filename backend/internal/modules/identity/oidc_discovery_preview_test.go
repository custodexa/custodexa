package identity_test

import (
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"net/http"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 探索預覽的測試。
//
// 「拒絕內部位址」那一條的斷言是**對端一次都沒被碰到**：只斷言回了錯誤的話，
// 一個「先撥號、再檢查」的實作也會過——而那正是 SSRF 的形狀。

// discoveryDoc dex 形態的探索文件（欄名逐字沿 OpenID discovery）
const discoveryDoc = `{
  "issuer": "%ISSUER%",
  "authorization_endpoint": "%ISSUER%/auth",
  "token_endpoint": "%ISSUER%/token",
  "jwks_uri": "%ISSUER%/keys",
  "userinfo_endpoint": "%ISSUER%/userinfo",
  "claims_supported": ["sub","email","name","groups"],
  "scopes_supported": ["openid","profile","email","groups"]
}`

// newDiscoveryServer well-known 端點的替身，回傳伺服器與被打次數
func newDiscoveryServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.ReplaceAll(discoveryDoc, "%ISSUER%", srv.URL)))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestDiscoveryPreviewReturnsEndpoints 取回端點清單與支援的宣告，並留一列成功的痕跡。
func TestDiscoveryPreviewReturnsEndpoints(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())
	srv, hits := newDiscoveryServer(t)

	out, err := svc.PreviewDiscovery(t.Context(), testEgress(), srv.URL, mappingTestActor)
	if err != nil {
		t.Fatalf("探索預覽: %v", err)
	}
	if out.Issuer != srv.URL {
		t.Fatalf("issuer = %q，want %q", out.Issuer, srv.URL)
	}
	if out.AuthorizationEndpoint != srv.URL+"/auth" || out.TokenEndpoint != srv.URL+"/token" ||
		out.JWKSURI != srv.URL+"/keys" || out.UserinfoEndpoint != srv.URL+"/userinfo" {
		t.Fatalf("端點清單不完整: %+v", out)
	}
	if len(out.ClaimsSupported) != 4 || len(out.ScopesSupported) != 4 {
		t.Fatalf("宣告／範圍清單 = %v／%v", out.ClaimsSupported, out.ScopesSupported)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("對端被打 %d 次，want 1", got)
	}
	if got := countAuditEvent(t, db, identity.OIDCAuditEventDiscoveryPreview); got != 1 {
		t.Fatalf("呼叫留痕列數 = %d，want 1", got)
	}
}

// TestDiscoveryPreviewRejectsInternalHost 內部位址在撥號之前即被拒，且留下一列痕跡。
//
// 斷言的重點是**對端一次都沒被碰到**：只驗「回了錯誤」的話，一個先撥號再檢查的
// 實作也會通過，而那正是要防的形狀。
func TestDiscoveryPreviewRejectsInternalHost(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())
	srv, hits := newDiscoveryServer(t)

	// 未列入放行清單的出站政策：httptest 伺服器位於 loopback，正是禁區
	strict := &identity.OIDCEgressPolicy{}
	if _, err := svc.PreviewDiscovery(t.Context(), strict, srv.URL, mappingTestActor); err == nil {
		t.Fatal("指向內部位址應被拒")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("被拒的預覽仍碰了對端 %d 次，want 0", got)
	}
	if got := countAuditEvent(t, db, identity.OIDCAuditEventDiscoveryPreview); got != 1 {
		t.Fatalf("拒絕也要留痕：列數 = %d，want 1", got)
	}

	// https 但解析到內部位址者於連線階段被擋（形狀檢查放行、位址政策攔下）
	_, err := svc.PreviewDiscovery(t.Context(), strict, "https://localhost:1/", mappingTestActor)
	if err == nil {
		t.Fatal("解析至 loopback 的位址應被拒")
	}
	if !errors.Is(err, identity.ErrOIDCDiscoveryFailed) {
		t.Fatalf("err = %v，want ErrOIDCDiscoveryFailed（成因只落伺服端 log）", err)
	}
}

// TestDiscoveryPreviewDoesNotPersist 預覽不建立、不更新任何 provider 列。
func TestDiscoveryPreviewDoesNotPersist(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())
	before := seedMappingProvider(t, db, "", "openid")
	srv, _ := newDiscoveryServer(t)

	var countBefore int64
	if err := db.Model(&model.OIDCProvider{}).Count(&countBefore).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if _, err := svc.PreviewDiscovery(t.Context(), testEgress(), srv.URL, mappingTestActor); err != nil {
		t.Fatalf("探索預覽: %v", err)
	}
	var countAfter int64
	if err := db.Model(&model.OIDCProvider{}).Count(&countAfter).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if countBefore != countAfter {
		t.Fatalf("provider 列數 %d → %d，預覽不得落庫", countBefore, countAfter)
	}
	var after model.OIDCProvider
	if err := db.First(&after, before.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.Issuer != before.Issuer || after.GroupsClaim != before.GroupsClaim ||
		after.Scopes != before.Scopes || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("既有 provider 被預覽改動：%+v → %+v", before, after)
	}
}
