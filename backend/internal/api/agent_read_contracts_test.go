package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type agentReadEnv struct {
	db                  *gorm.DB
	router              *gin.Engine
	owner, agent, other *model.User
	jwt                 map[string]string
	token               string
	policies            *policy.SecurityPolicyService
}

func newAgentReadEnv(t *testing.T) *agentReadEnv {
	t.Helper()
	db, users, owner, agent := principalAPIEnv(t)
	require.NoError(t, db.AutoMigrate(&model.SecurityPolicy{}, &model.AgentToken{}, &model.AgentProbeEvent{}, &model.AgentToolCall{}, &model.AgentTaskReport{}, &model.Session{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.AccessRequestApproval{}, &model.Asset{}, &model.AssetAuthorization{}, &model.UserGroup{}, &model.AssetGroup{}, &model.AssetNode{}, &model.AssetAccount{}, &model.Credential{}, &model.AgentVisibilityExposure{}))
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	other := &model.User{Username: "other", Password: "!", Kind: model.KindHuman, Active: true}
	require.NoError(t, db.Create(other).Error)
	e := &agentReadEnv{db: db, owner: owner, agent: agent, other: other, jwt: map[string]string{}}
	e.policies = policy.NewSecurityPolicyService(db)
	auth := identity.NewAuthService("agent-read-test-key", time.Hour)
	auth.SetEpochGateDB(db)
	for _, role := range []string{model.RoleAdmin, model.RoleAuditor, model.RoleUser} {
		token, err := crypto.NewJWTManager("agent-read-test-key", time.Hour).GenerateToken(owner.ID, owner.Username, "", role, crypto.AuthContext{})
		require.NoError(t, err)
		e.jwt[role] = token
	}
	e.jwt["other"], _ = crypto.NewJWTManager("agent-read-test-key", time.Hour).GenerateToken(other.ID, other.Username, "", model.RoleUser, crypto.AuthContext{})
	tok, err := identity.NewAgentTokenService(db, audit.NewTxSink()).Create(agent.ID, identity.CreateAgentTokenRequest{Name: "initial-name", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
	require.NoError(t, err)
	e.token = tok.Token
	log := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})
	e.router = gin.New()
	e.router.Use(middleware.AuditLogMiddleware(log), middleware.AgentRouteAllowlist(auth))
	root := e.router.Group("/api/v1")
	users.RegisterRoutes(root, auth)
	NewAuditIntegrityHandler(db, nil).RegisterRoutes(root, auth)
	requests := authz.NewAccessRequestService(db, e.policies, policy.NewAccessPolicyService(db, e.policies, authz.NewAssetAuthorizationService(db)), nil, nil)
	requests.SetAccountPresenceSource(func(tx *gorm.DB, id uint, name string) (bool, error) {
		var count int64
		err := tx.Model(&model.AssetAccount{}).Where("asset_id = ? AND username = ?", id, name).Count(&count).Error
		return count > 0, err
	})
	NewAccessRequestHandler(requests, nil, db).RegisterRoutes(root, auth)
	NewAuditTimelineHandler(audit.NewTimelineService(db)).RegisterRoutes(root, auth)
	NewSessionHandler(session.NewSessionService(nil)).RegisterRoutes(root, auth)
	return e
}
func (e *agentReadEnv) get(path, token string) *httptest.ResponseRecorder {
	q := httptest.NewRequest("GET", "/api/v1"+path, nil)
	if token != "" {
		q.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, q)
	return w
}
func (e *agentReadEnv) request(t *testing.T, asset uint) *model.AccessRequest {
	t.Helper()
	r := &model.AccessRequest{RequesterID: e.owner.ID, ExecutorUserID: &e.agent.ID, AssetID: asset, Reason: "fixture", RequestedDurationMinutes: 30, Status: model.AccessRequestPending, PendingExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, e.db.Create(r).Error)
	return r
}
func agentReadJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	return out
}
func TestAgentReadAuthenticationAndIDOR(t *testing.T) {
	e := newAgentReadEnv(t)
	// Real registered middleware, not hand-written role stubs.
	paths := []string{"/agent-tasks?subject=2&owner=999", "/agent-tool-calls?user_id=2&session_id=999", fmt.Sprintf("/users/%d/agent-breaker/events", e.agent.ID), "/users?kind=agent", "/sessions?actor_kind=agent&user_id=999", "/sessions/999", "/audit/subjects?type=user&q=agent", "/access-requests/pending", "/access-requests/reviews/pending", "/access-requests/history"}
	// Include a real task so removing audit:view exposes data (200), not merely a 404.
	request := e.request(t, 1)
	paths = append(paths, fmt.Sprintf("/agent-tasks/%d", request.ID))
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			require.Equal(t, 401, e.get(path, "").Code)
			require.Equal(t, 403, e.get(path, e.token).Code)
			w := e.get(path, e.jwt["other"])
			require.Equal(t, 403, w.Code, w.Body.String())
		})
	}
	// A successful owner request does not grant another human the same subject.
	require.Equal(t, 200, e.get(fmt.Sprintf("/users/%d/agent-breaker/events", e.agent.ID), e.jwt[model.RoleUser]).Code)
	for _, token := range []string{"", e.token} {
		w := e.get("/my/agents?owner_user_id=999", token)
		want := 401
		if token != "" {
			want = 403
		}
		require.Equal(t, want, w.Code)
	}
}
func TestAgentTasksListContract(t *testing.T) {
	e := newAgentReadEnv(t)
	require.Empty(t, agentReadJSON(t, e.get("/agent-tasks", e.jwt[model.RoleAuditor]))["data"])
	a := e.request(t, 1)
	b := e.request(t, 2)
	at := time.Now().UTC()
	require.NoError(t, e.db.Model(b).Update("closed_at", at).Error)
	require.NoError(t, e.db.Create(&model.AgentTaskReport{AccessRequestID: a.ID, UserID: e.agent.ID, Version: 1, Body: "self report", SubmittedAt: at}).Error)
	w := e.get(fmt.Sprintf("/agent-tasks?subject=%d&report_status=missing&limit=1", e.agent.ID), e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	body := agentReadJSON(t, w)
	require.EqualValues(t, 1, body["total"])
	require.EqualValues(t, b.ID, body["data"].([]any)[0].(map[string]any)["id"])
	require.Empty(t, agentReadJSON(t, e.get("/agent-tasks?owner=999", e.jwt[model.RoleAdmin]))["data"])
	for _, query := range []string{"subject=bad", "report_status=wrong", "limit=-1", "from=2026-09-23T00:00:00Z&to=2026-09-22T00:00:00Z"} {
		require.Equal(t, 400, e.get("/agent-tasks?"+query, e.jwt[model.RoleAuditor]).Code)
	}
	// Service bound enforced even if a caller bypasses the handler's clamp.
	for i := 0; i < 103; i++ {
		e.request(t, uint(i+3))
	}
	body = agentReadJSON(t, e.get("/agent-tasks?limit=99999", e.jwt[model.RoleAdmin]))
	require.Len(t, body["data"], 100)
	require.EqualValues(t, 105, body["total"])
}
func TestSessionLedgerContract(t *testing.T) {
	e := newAgentReadEnv(t)
	s1, s2 := uint(1), uint(2)
	for i, id := range []*uint{&s1, &s2, nil} {
		row := model.AgentToolCall{Seq: uint(i + 1), UserID: e.agent.ID, AgentTokenID: 1, OwnerUserID: e.owner.ID, Tool: "list_assets", ArgsRedacted: "{}", Decision: model.ToolCallPending, SessionID: id}
		require.NoError(t, e.db.Session(&gorm.Session{SkipHooks: true}).Create(&row).Error)
	}
	w := e.get("/agent-tool-calls?session_id=1", e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	body := agentReadJSON(t, w)
	require.EqualValues(t, 1, body["total"])
	require.Len(t, body["data"], 1)
	require.Empty(t, agentReadJSON(t, e.get("/agent-tool-calls?session_id=999", e.jwt[model.RoleAuditor]))["data"])
	require.Equal(t, 400, e.get("/agent-tool-calls?session_id=0", e.jwt[model.RoleAdmin]).Code)
	var logs []model.AuditLog
	require.NoError(t, e.db.Where("resource = ?", model.ResourceAgentToolCall).Find(&logs).Error)
	require.NotEmpty(t, logs)
	require.Contains(t, logs[0].Details, "session_id")
}
func TestBreakerEventsContract(t *testing.T) {
	e := newAgentReadEnv(t)
	path := fmt.Sprintf("/users/%d/agent-breaker/events", e.agent.ID)
	require.Empty(t, agentReadJSON(t, e.get(path, e.jwt[model.RoleUser]))["data"])
	at := time.Now().UTC()
	require.NoError(t, e.db.Model(e.agent).Update("breaker_pending_at", at).Error)
	for i := 0; i < 103; i++ {
		require.NoError(t, e.db.Create(&model.AgentProbeEvent{UserID: e.agent.ID, AgentTokenID: 1, AssetRef: uint(i + 1), Endpoint: "GET /assets/:id", Class: model.ProbeNeverVisible, CreatedAt: at}).Error)
	}
	require.NoError(t, e.db.Create(&model.AgentProbeEvent{UserID: 999, AgentTokenID: 1, AssetRef: 1000, Endpoint: "GET /assets/:id", Class: model.ProbeRetired, CreatedAt: at}).Error)
	w := e.get(path+"?limit=99999", e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	body := agentReadJSON(t, w)
	require.EqualValues(t, 103, body["total"])
	require.Len(t, body["data"], 100)
	require.NotNil(t, body["breaker_pending_at"])
	var logs []model.AuditLog
	require.NoError(t, e.db.Where("resource = ?", model.ResourceAuditIntegrity).Find(&logs).Error)
	require.NotEmpty(t, logs)
	require.Contains(t, logs[len(logs)-1].Details, "limit")
	require.Equal(t, 403, e.get("/users/999/agent-breaker/events", e.jwt[model.RoleUser]).Code)
}
func TestUserKindContract(t *testing.T) {
	e := newAgentReadEnv(t)
	for _, kind := range []string{"human", "agent"} {
		w := e.get("/users?kind="+kind+"&include_agents=true&page_size=1", e.jwt[model.RoleAdmin])
		require.Equal(t, 200, w.Code, w.Body.String())
		rows := agentReadJSON(t, w)["data"].([]any)
		require.Len(t, rows, 1)
		require.Equal(t, kind, rows[0].(map[string]any)["kind"])
	}
	require.Empty(t, agentReadJSON(t, e.get("/users?kind=agent&search=no-such-user", e.jwt[model.RoleAdmin]))["data"])
	require.Equal(t, 400, e.get("/users?kind=robot", e.jwt[model.RoleAdmin]).Code)
}
func TestSelfCreateContract(t *testing.T) {
	e := newAgentReadEnv(t)
	w := e.get("/my/agents", e.jwt[model.RoleUser])
	require.Equal(t, 403, w.Code)
	status := agentReadJSON(t, w)["self_create"].(map[string]any)
	require.Equal(t, false, status["enabled"])
	require.EqualValues(t, 1, status["current"])
	_, err := e.policies.Update(policy.PolicyAgentSelfCreateEnabled, "true", "test")
	require.NoError(t, err)
	w = e.get(fmt.Sprintf("/my/agents?owner_user_id=%d", e.owner.ID), e.jwt["other"])
	require.Equal(t, 200, w.Code, w.Body.String())
	body := agentReadJSON(t, w)
	require.Empty(t, body["data"])
	require.EqualValues(t, 0, body["self_create"].(map[string]any)["current"])
	w = e.get("/my/agents", e.jwt[model.RoleUser])
	require.Equal(t, 200, w.Code)
	require.EqualValues(t, 1, agentReadJSON(t, w)["self_create"].(map[string]any)["current"])
}
func TestQuotaDetailsContract(t *testing.T) {
	for _, dimension := range []string{"hour", "pending"} {
		r := gin.New()
		r.GET("/error", func(c *gin.Context) {
			respondAccessRequestError(c, "", &authz.AgentRequestRateError{Count: 5, Limit: 5, Dimension: dimension})
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/error", nil))
		require.Equal(t, 429, w.Code)
		body := agentReadJSON(t, w)
		require.Equal(t, "RULE_AGENT_REQUEST_RATE", body["code"])
		details := body["details"].(map[string]any)
		require.EqualValues(t, 5, details["used"])
		require.EqualValues(t, 5, details["limit"])
		seconds := 0
		if dimension == "hour" {
			seconds = 3600
		}
		require.EqualValues(t, seconds, details["window_seconds"])
	}
}
func TestAccountDetailsContract(t *testing.T) {
	r := gin.New()
	r.GET("/error", func(c *gin.Context) {
		respondAccessRequestError(c, "", &authz.AccountNotOnAssetError{ItemIndex: 1, AssetID: 8})
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/error", nil))
	require.Equal(t, 400, w.Code)
	body := agentReadJSON(t, w)
	require.Equal(t, "VALIDATION_ACCOUNT_NOT_ON_ASSET", body["code"])
	require.Equal(t, map[string]any{"item_index": float64(1), "asset_id": float64(8)}, body["details"])
}
func TestExecutorAndBoundsContract(t *testing.T) {
	e := newAgentReadEnv(t)
	r := e.request(t, 1)
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, e.db.Model(r).Update("requested_date_start", future).Error)
	require.NoError(t, e.db.Create(&model.AccessRequestItem{RequestID: r.ID, RequesterID: e.owner.ID, AssetID: 1, Status: model.AccessRequestPending, Accounts: model.AccountScope{"app"}}).Error)
	w := e.get("/access-requests/mine", e.jwt[model.RoleUser])
	require.Equal(t, 200, w.Code, w.Body.String())
	body := agentReadJSON(t, w)
	row := body["data"].([]any)[0].(map[string]any)
	executor := row["executor"].(map[string]any)
	require.EqualValues(t, e.agent.ID, executor["id"])
	require.Equal(t, "agent", executor["kind"])
	require.Equal(t, e.owner.Username, executor["owner_username"])
	require.NotContains(t, executor, "password")
	bounds := row["items"].([]any)[0].(map[string]any)["decision_bounds"].(map[string]any)
	require.EqualValues(t, 30, bounds["max_duration"])
	require.Equal(t, []any{"app"}, bounds["accounts"])
	require.Equal(t, future.Format(time.RFC3339), bounds["earliest_start"])
	require.Empty(t, agentReadJSON(t, e.get(fmt.Sprintf("/access-requests/mine?requester_id=%d", e.owner.ID), e.jwt["other"]))["data"])
	require.Equal(t, 401, e.get("/access-requests/mine", "").Code)
}
func TestSessionKindContract(t *testing.T) {
	e := newAgentReadEnv(t)
	for i, kind := range []string{"agent", "human", ""} {
		row := model.Session{SessionID: fmt.Sprint(i), UserID: e.agent.ID, StartTime: time.Now(), Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH}
		if kind != "" {
			row.ActorKind = &kind
		}
		require.NoError(t, e.db.Create(&row).Error)
	}
	for _, kind := range []string{"human", "agent"} {
		w := e.get("/sessions?actor_kind="+kind, e.jwt[model.RoleAuditor])
		require.Equal(t, 200, w.Code, w.Body.String())
		body := agentReadJSON(t, w)
		want := 1
		if kind == "human" {
			want = 2
		}
		require.EqualValues(t, want, body["total"])
		for _, raw := range body["data"].([]any) {
			value := raw.(map[string]any)["actor_kind"]
			if value != nil {
				require.Equal(t, kind, value)
			}
		}
	}
	require.Empty(t, agentReadJSON(t, e.get("/sessions?actor_kind=agent&user_id=999", e.jwt[model.RoleAdmin]))["data"])
	require.Equal(t, 400, e.get("/sessions?actor_kind=robot", e.jwt[model.RoleAuditor]).Code)
}
func TestTokenNameSnapshotContract(t *testing.T) {
	e := newAgentReadEnv(t)
	var token model.AgentToken
	require.NoError(t, e.db.First(&token).Error)
	row := model.Session{SessionID: "snapshot", UserID: e.agent.ID, AgentTokenID: &token.ID, StartTime: time.Now(), Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH}
	require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
		if err := identity.BindAgentSessionPrincipal(tx, &row); err != nil {
			return err
		}
		return tx.Create(&row).Error
	}))
	require.NotNil(t, row.AgentTokenName)
	require.Equal(t, "initial-name", *row.AgentTokenName)
	// Direct SQL simulates a later name change; read response must remain the snapshot.
	require.NoError(t, e.db.Exec("UPDATE agent_tokens SET name = ? WHERE id = ?", "later-name", token.ID).Error)
	w := e.get(fmt.Sprintf("/sessions/%d", row.ID), e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "initial-name")
	require.NotContains(t, w.Body.String(), "later-name")
	legacy := model.Session{SessionID: "legacy", UserID: e.owner.ID, StartTime: time.Now(), Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH}
	require.NoError(t, e.db.Create(&legacy).Error)
	require.Contains(t, e.get(fmt.Sprintf("/sessions/%d", legacy.ID), e.jwt[model.RoleAdmin]).Body.String(), `"agent_token_name":null`)
}
func TestSubjectKindContract(t *testing.T) {
	e := newAgentReadEnv(t)
	w := e.get("/audit/subjects?type=user&q=agent", e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"kind":"agent"`)
	require.Contains(t, w.Body.String(), fmt.Sprintf(`"owner_user_id":%d`, e.owner.ID))
	require.NotContains(t, w.Body.String(), "password")
	require.NotContains(t, w.Body.String(), "email")
	require.Empty(t, agentReadJSON(t, e.get("/audit/subjects?type=user&q=nobody", e.jwt[model.RoleAuditor]))["data"])
	require.True(t, strings.Contains(e.get("/audit/subjects?type=user&q=human", e.jwt[model.RoleAuditor]).Body.String(), `"kind":"human"`))
}

func TestExistingAgentRequestContract(t *testing.T) {
	e := newAgentReadEnv(t)
	for _, token := range []string{"", e.jwt[model.RoleAdmin], e.jwt[model.RoleAuditor]} {
		q := httptest.NewRequest("POST", "/api/v1/access-requests", strings.NewReader(`{"asset_id":1,"accounts":["app"],"reason":"test","duration_minutes":30}`))
		q.Header.Set("Content-Type", "application/json")
		if token != "" {
			q.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		e.router.ServeHTTP(w, q)
		want := 403
		if token == "" {
			want = 401
		}
		require.Equal(t, want, w.Code, w.Body.String())
	}
	approval := model.AccessPolicyApproval
	for i := 1; i <= 2; i++ {
		asset := model.Asset{Name: fmt.Sprintf("a%d", i), Host: fmt.Sprintf("192.0.2.%d", i), Protocol: model.ProtocolSSH, AccessPolicy: &approval}
		require.NoError(t, e.db.Create(&asset).Error)
		require.NoError(t, e.db.Create(&model.AssetAuthorization{UserID: &e.agent.ID, AssetID: &asset.ID, Permission: model.PermissionView, GrantedBy: e.owner.ID}).Error)
		credential := model.Credential{Username: "app", Scope: model.CredentialScopeDedicated, SecretType: "password", ProtocolFamily: model.ProtocolFamilySSH}
		require.NoError(t, e.db.Create(&credential).Error)
		require.NoError(t, e.db.Create(&model.AssetAccount{AssetID: asset.ID, CredentialID: credential.ID, Username: "app"}).Error)
	}
	post := func(body string) *httptest.ResponseRecorder {
		q := httptest.NewRequest("POST", "/api/v1/access-requests", strings.NewReader(body))
		q.Header.Set("Content-Type", "application/json")
		q.Header.Set("Authorization", "Bearer "+e.token)
		w := httptest.NewRecorder()
		e.router.ServeHTTP(w, q)
		return w
	}
	w := post(`{"items":[{"asset_id":1,"accounts":["app"]},{"asset_id":2,"accounts":["missing"]}],"reason":"test","duration_minutes":30}`)
	require.Equal(t, 400, w.Code, w.Body.String())
	require.Equal(t, map[string]any{"item_index": float64(1), "asset_id": float64(2)}, agentReadJSON(t, w)["details"])
	_, err := e.policies.Update(policy.PolicyAgentRequestRatePerHour, "1", "test")
	require.NoError(t, err)
	w = post(`{"asset_id":1,"accounts":["app"],"reason":"test","duration_minutes":30}`)
	require.Equal(t, 201, w.Code, w.Body.String())
	w = post(`{"asset_id":2,"accounts":["app"],"reason":"test","duration_minutes":30}`)
	require.Equal(t, 429, w.Code, w.Body.String())
	require.Equal(t, map[string]any{"used": float64(1), "limit": float64(1), "window_seconds": float64(3600), "dimension": "hour"}, agentReadJSON(t, w)["details"])
	e.request(t, 99) // A human's assisted request is not an agent-owned request.
	w = e.get(fmt.Sprintf("/access-requests/mine?requester_id=%d", e.owner.ID), e.token)
	require.Equal(t, 200, w.Code, w.Body.String())
	rows := agentReadJSON(t, w)["data"].([]any)
	require.Len(t, rows, 1)
	require.EqualValues(t, e.agent.ID, rows[0].(map[string]any)["requester_id"])
	require.Contains(t, w.Body.String(), `"executor"`)
	require.Contains(t, w.Body.String(), `"decision_bounds"`)
}
