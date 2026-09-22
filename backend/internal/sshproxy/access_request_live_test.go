package sshproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

// Run by e2e_smoke.sh in dev compose. Only identity/request fixtures are isolated;
// issuance, redemption, encrypted credentials, SSH and physical termination are real.
func TestAccessRequestAgentLive(t *testing.T) {
	if os.Getenv("TEST_AGENT_TASK_SSH") != "1" {
		t.Skip("dev compose SSH target required")
	}
	h, db := setupGenerationTest(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.AccessRequestItem{}, &model.AccessRequestApproval{}, &model.ApproverScope{}, &model.AgentToken{}, &model.SessionCommand{}, &model.AlertRule{}, &model.CommandAlert{}))
	require.NoError(t, db.Model(&model.User{}).Where("id=1").Updates(map[string]any{"kind": model.KindAgent, "owner_user_id": 2}).Error)
	require.NoError(t, db.Model(&model.User{}).Where("id=2").Update("kind", model.KindHuman).Error)
	require.NoError(t, db.Model(&model.Asset{}).Where("id=1").Updates(map[string]any{"host": "ssh-test", "port": 2222, "access_policy": model.AccessPolicyApproval}).Error)
	segment := model.AccessPolicyApproval
	second := model.Asset{Name: "task-second", Protocol: model.ProtocolSSH, Host: "ssh-test", Port: 2222, CreatedBy: 2, AccessPolicy: &segment}
	require.NoError(t, db.Create(&second).Error)
	ids := []uint{1, second.ID}
	accounts := make(map[uint]map[string]uint)
	enc, err := aesColumnCodec(t, make([]byte, 32)).EncryptFor(context.Background(), crypto.CipherRef{Table: "credential_secret_versions", Column: "password_enc"}, "testpass123")
	require.NoError(t, err)
	for _, aid := range ids {
		accounts[aid] = map[string]uint{}
		for _, name := range []string{"testuser", "root"} {
			cred := model.Credential{Scope: model.CredentialScopeDedicated, Username: name, SecretType: model.ChangeSecretTypePassword, AuthMethod: "password", ProtocolFamily: model.ProtocolFamilySSH}
			require.NoError(t, db.Create(&cred).Error)
			ver := model.CredentialSecretVersion{CredentialID: cred.ID, VersionNo: 1, SecretType: model.ChangeSecretTypePassword, PasswordEnc: enc, CreatedReason: model.CredentialVersionReasonManual}
			require.NoError(t, db.Create(&ver).Error)
			acct := model.AssetAccount{AssetID: aid, Username: name, IsDefault: name == "testuser", CredentialID: cred.ID, EffectiveVersionID: &ver.ID}
			require.NoError(t, db.Create(&acct).Error)
			accounts[aid][name] = acct.ID
		}
		user := uint(1)
		if aid != 1 {
			require.NoError(t, db.Create(&model.AssetAuthorization{UserID: &user, AssetID: &aid, Permission: model.PermissionView, GrantedBy: 2}).Error)
		}
		approver := uint(2)
		require.NoError(t, db.Create(&model.ApproverScope{ApproverID: &approver, AssetID: &aid, GrantedBy: 2}).Error)
	}
	matcher := audit.InitAlertMatcher(db, nil)
	require.NoError(t, matcher.LoadRules())
	t.Cleanup(func() { audit.InitAlertMatcher(nil, nil) })
	h.Registry = proxy.NewConnectionRegistry()
	h.SessionService = session.NewSessionService(h.Registry)
	h.HostKeys = asset.NewHostKeyService(db)
	h.AuditService = audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	t.Cleanup(func() { h.AuditService.Shutdown(context.Background()) })
	policies := policy.NewSecurityPolicyService(db)
	requests := authz.NewAccessRequestService(db, policies, h.AccessPolicy, h.AuditService, nil)
	requests.SetAccountPresenceSource(asset.RequestAccountPresent)
	requests.SetSessionService(h.SessionService)
	handler := api.NewAccessRequestHandler(requests, nil, db)
	tokens := identity.NewAgentTokenService(db, audit.NewTxSink())
	issued, err := tokens.Create(1, identity.CreateAgentTokenRequest{Name: "e2e", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: 2})
	require.NoError(t, err)
	h.AuthService.SetEpochGateDB(db)
	// Authenticate the actual bearer before constructing the in-process subject.
	router := gin.New()
	router.Use(middleware.AgentRouteAllowlist(h.AuthService))
	router.POST("/api/v1/access-requests", middleware.AuthMiddleware(h.AuthService), handler.Create)
	for _, surface := range []struct{ method, path string }{{"POST", "/api/v1/connect-tokens"}, {"GET", "/api/v1/ssh"}, {"GET", "/api/v1/db-console"}, {"GET", "/api/v1/connect"}} {
		router.Handle(surface.method, surface.path, func(c *gin.Context) { t.Error("HTTP forbidden surface reached") })
		r := httptest.NewRequest(surface.method, surface.path, nil)
		r.Header.Set("Authorization", "Bearer "+issued.Token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		require.Equal(t, 403, w.Code)
		require.Contains(t, w.Body.String(), "AUTH_AGENT_FORBIDDEN_ROUTE")
		t.Logf("PASS HTTP %s %s => 403 (bearer redacted)", surface.method, surface.path)
	}
	body := fmt.Sprintf(`{"items":[{"asset_id":1,"accounts":["testuser"]},{"asset_id":%d,"accounts":["testuser","root"]}],"reason":"agent live smoke","duration_minutes":60}`, second.ID)
	r := httptest.NewRequest("POST", "/api/v1/access-requests", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+issued.Token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	require.Equal(t, 201, w.Code, w.Body.String())
	var response struct {
		ID    uint `json:"id"`
		Items []struct {
			ID uint `json:"id"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.Len(t, response.Items, 2)
	t.Logf("PASS step 1 agent created request=%d two assets; HTTP 201", response.ID)
	_, err = requests.Approve(2, false, response.ID, authz.DecideInput{ItemID: response.Items[0].ID})
	require.NoError(t, err)
	narrow := []string{"testuser"}
	duration := 15
	_, err = requests.Approve(2, false, response.ID, authz.DecideInput{ItemID: response.Items[1].ID, Accounts: &narrow, DurationMinutes: &duration})
	require.NoError(t, err)
	t.Log("PASS step 2 reviewer approved first and narrowed second accounts/duration")
	// Same authenticated context accepted by the HTTP authentication layer; no JWT impersonation.
	var subject gatewayapi.ConnectSubject
	authRouter := gin.New()
	authRouter.GET("/context", middleware.AuthMiddleware(h.AuthService), func(c *gin.Context) {
		auth := middleware.GetAuthContext(c)
		uid, _ := middleware.GetCurrentUserID(c)
		subject = gatewayapi.ConnectSubject{UserID: uid, AuthMethod: auth.EffectiveMethod(), CredEpoch: auth.CredEpoch, ClientIP: "127.0.0.1"}
	})
	q := httptest.NewRequest("GET", "/context", nil)
	q.RemoteAddr = "127.0.0.1:1234"
	q.Header.Set("Authorization", "Bearer "+issued.Token)
	authW := httptest.NewRecorder()
	authRouter.ServeHTTP(authW, q)
	require.Equal(t, 200, authW.Code)
	require.Equal(t, uint(1), subject.UserID)
	issue := func(aid, account uint) (gatewayapi.ConnectGrant, *gatewayapi.Denial) {
		c := gateTestContext("POST", "/in-process", nil)
		return h.IssueConnectGrant(c, subject, &ConnectTokenRequest{AssetID: aid, AccountID: account, AccessRequestID: response.ID})
	}
	grantA, out := issue(1, accounts[1]["testuser"])
	require.Nil(t, out)
	grantB, out := issue(second.ID, accounts[second.ID]["testuser"])
	require.Nil(t, out)
	_, out = issue(second.ID, accounts[second.ID]["root"])
	require.NotNil(t, out)
	require.Equal(t, 403, out.Status)
	require.Equal(t, "AUTH_REQUEST_ITEM_MISMATCH", out.Decision.Code)
	t.Log("PASS step 3 in-process issuance: in-scope grants succeed; root => 403 AUTH_REQUEST_ITEM_MISMATCH")
	// The harness exposes only the pre-existing redemption handler, not an application agent route.
	redemption := gin.New()
	redemption.GET("/ssh", h.HandleSSH)
	srv := httptest.NewServer(redemption)
	defer srv.Close()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for h.Registry.Count() > 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
	})
	dial := func(grant gatewayapi.ConnectGrant) *websocket.Conn {
		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), grant)
		require.NoError(t, err)
		ws, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ssh?cols=80&rows=24&connect_token="+url.QueryEscape(token), nil)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			t.Fatalf("redemption status=%d; token redacted", status)
		}
		t.Cleanup(func() { ws.Close() })
		return ws
	}
	wsA, wsB := dial(grantA), dial(grantB)
	echo := func(ws *websocket.Conn, marker string) {
		require.NoError(t, ws.WriteJSON(map[string]string{"type": "data", "data": "echo " + marker + "-$((40+2))\r"}))
		require.NoError(t, ws.SetReadDeadline(time.Now().Add(8*time.Second)))
		var all strings.Builder
		for {
			_, raw, e := ws.ReadMessage()
			require.NoError(t, e)
			var msg struct{ Type, Data string }
			require.NoError(t, json.Unmarshal(raw, &msg))
			if msg.Type == "data" {
				all.WriteString(msg.Data)
			}
			if strings.Contains(all.String(), marker+"-42") {
				break
			}
		}
	}
	echo(wsA, "first")
	echo(wsB, "second")
	var sessions []model.Session
	require.NoError(t, db.Where("access_request_id=?", response.ID).Order("id").Find(&sessions).Error)
	require.Len(t, sessions, 2)
	t.Logf("PASS step 4 real ssh-test commands on sessions %d,%d, request_id persisted", sessions[0].ID, sessions[1].ID)
	// Start on the soon-to-be-revoked connection; nohup and redirected stdio
	// leave the target process independent of that SSH session.
	readMarker := func(ws *websocket.Conn, pattern *regexp.Regexp) []string {
		t.Helper()
		require.NoError(t, ws.SetReadDeadline(time.Now().Add(8*time.Second)))
		var output strings.Builder
		for {
			var msg struct{ Type, Data string }
			require.NoError(t, ws.ReadJSON(&msg))
			if msg.Type == "data" {
				output.WriteString(msg.Data)
			}
			if match := pattern.FindStringSubmatch(output.String()); match != nil {
				return match
			}
		}
	}
	require.NoError(t, wsA.WriteJSON(map[string]string{"type": "data", "data": "nohup sleep 120 </dev/null >/dev/null 2>&1 & bg=$!; printf 'V2_BG_%s\\n' \"$bg\"\r"}))
	backgroundPID := readMarker(wsA, regexp.MustCompile(`V2_BG_([0-9]+)`))[1]
	t.Cleanup(func() {
		_ = wsB.WriteJSON(map[string]string{"type": "data", "data": "kill " + backgroundPID + " 2>/dev/null\r"})
	})
	// Preserve a pre-revocation grant and verify redemption rechecks the item.
	stale, out := issue(1, accounts[1]["testuser"])
	require.Nil(t, out)
	_, err = requests.RevokeItem(2, false, "reviewer", response.ID, response.Items[0].ID, "e2e revoke")
	require.NoError(t, err)
	t.Log("PASS step 5 revoke first item with default access_revoke_disconnect=false")
	require.NoError(t, wsA.SetReadDeadline(time.Now().Add(3*time.Second)))
	closed := false
	for {
		_, _, e := wsA.ReadMessage()
		if e != nil {
			if ne, ok := e.(interface{ Timeout() bool }); ok && ne.Timeout() {
				t.Fatal("revoked socket remained open")
			}
			closed = true
			break
		}
	}
	require.True(t, closed)
	echo(wsB, "survives")
	require.NoError(t, wsB.WriteJSON(map[string]string{"type": "data", "data": "if kill -0 " + backgroundPID + "; then printf 'V2_%s\\n' BG_ALIVE; else printf 'V2_%s\\n' BG_DEAD; fi; kill " + backgroundPID + " 2>/dev/null\r"}))
	backgroundState := readMarker(wsB, regexp.MustCompile(`V2_BG_(ALIVE|DEAD)`))[1]
	require.Equal(t, "ALIVE", backgroundState, "revocation must not kill the detached target process")
	t.Log("PASS detached nohup process survived revocation, confirmed over the other SSH connection")
	require.NoError(t, db.Where("id=?", sessions[0].ID).First(&sessions[0]).Error)
	require.Equal(t, model.EndReasonRevoked, sessions[0].EndReason)
	require.NoError(t, db.Where("id=?", sessions[1].ID).First(&sessions[1]).Error)
	require.Equal(t, model.SessionStatusActive, sessions[1].Status)
	token, err := h.ConnectTokens.IssueConnectToken(context.Background(), stale)
	require.NoError(t, err)
	code, denied := gateRedeemSSH(h, token, "80", "24")
	require.Equal(t, 403, code)
	require.Equal(t, "RULE_ACCESS_APPROVAL_REQUIRED", denied["code"])
	t.Log("PASS step 6 revoked socket closed; other socket still executes; pre-revocation grant redemption => 403")
	wsB.Close()
	wsA.Close()
	deadline := time.Now().Add(5 * time.Second)
	for h.Registry.Count() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	require.Zero(t, h.Registry.Count())
	time.Sleep(100 * time.Millisecond)
}
