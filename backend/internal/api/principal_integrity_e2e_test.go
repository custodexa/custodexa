package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestPrincipalIntegrityEndToEnd(t *testing.T)              { runPrincipalIntegrityHTTP(t) }
func TestCheckpointVerifyEndpointPrincipalStates(t *testing.T) { runPrincipalIntegrityHTTP(t) }
func runPrincipalIntegrityHTTP(t *testing.T) {
	var db *gorm.DB
	var err error
	dsn := os.Getenv("W1R_PG_DSN")
	if dsn != "" {
		schema := fmt.Sprintf("w1r_%d", time.Now().UnixNano())
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatal(err)
		}
		sqlDB, _ := db.DB()
		sqlDB.SetMaxOpenConns(1)
		if err := db.Exec("CREATE SCHEMA " + schema).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Exec("SET search_path TO " + schema).Error; err != nil {
			t.Fatal(err)
		}
		t.Log("PostgreSQL evidence schema:", schema)
		t.Cleanup(func() { sqlDB.Close() })
	} else {
		db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatal(err)
		}
		sqlDB, _ := db.DB()
		sqlDB.SetMaxOpenConns(1)
		t.Cleanup(func() { sqlDB.Close() })
	}
	if err := db.AutoMigrate(&model.AgentToolCall{}, &model.User{}, &model.Role{}, &model.UserRole{}, &model.AgentToken{}, &model.AuditLog{}, &model.AuditCheckpoint{}, &model.AuditCheckpointTrim{}, &model.IntegrityBaseline{}, &model.AuditFailureEvent{}, &model.SecurityPolicy{}, &model.NotificationChannel{}, &model.UserGroup{}, &model.ApproverScope{}, &model.Asset{}, &model.AssetAuthorization{}, &model.RefreshToken{}, &model.PasswordHistory{}); err != nil {
		t.Fatal(err)
	}
	if dsn != "" {
		if err := db.Exec(`CREATE UNIQUE INDEX principal_open_test ON audit_failure_events ((cause_params::jsonb->>'table')) WHERE ended_at IS NULL AND mechanism='principal_state_integrity'`).Error; err != nil {
			t.Fatal(err)
		}
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	audit.SetPrincipalSource(identity.SnapshotPrincipalStates)
	audit.SetAgentTokenSource(identity.SnapshotAgentTokenStates)
	t.Cleanup(resetPrincipalTestSources)
	owner := model.User{Username: "integrity-owner", Password: "!", Active: true}
	human := model.User{Username: "integrity-human", Password: "!", Active: true}
	for _, u := range []*model.User{&owner, &human} {
		if err := db.Create(u).Error; err != nil {
			t.Fatal(err)
		}
	}
	agent := model.User{Username: "integrity-agent", Password: "!", Active: true, Kind: model.KindAgent, OwnerUserID: &owner.ID}
	if err := db.Create(&agent).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.IntegrityBaseline{ID: 1, BaselineAt: time.Now().Add(-time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.SecurityPolicy{Key: policy.PolicyFailureAlertEnabled, Value: "true"}).Error; err != nil {
		t.Fatal(err)
	}
	notifications := make(chan string, 16)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		notifications <- string(b)
		w.WriteHeader(200)
	}))
	t.Cleanup(receiver.Close)
	if err := db.Create(&model.NotificationChannel{Name: "integrity-e2e", Type: model.NotificationChannelTypeWebhook, URL: receiver.URL, Enabled: true, Language: model.NotificationChannelLanguageEnUS}).Error; err != nil {
		t.Fatal(err)
	}
	notifier := audit.InitAlertNotifier(db, nil)
	if err := notifier.LoadChannels(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.StopAlertNotifierForRelease(notifier) })
	failures := audit.InitAuditFailure(db, policy.NewSecurityPolicyService(db))
	t.Cleanup(audit.ResetAuditFailureSingleton)
	rec := audit.NewRoleStateReconciler(db, failures)
	signer := newFakeCheckpointSigner(t)
	seal := audit.NewCheckpointService(db, signer, nil, nil)
	seal.SetRoleStateReconciler(rec)
	if err := seal.EnsureGenesis(); err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewCheckpointVerifier(db, seal, audit.NewCheckpointPurger(db, signer), nil, nil)
	verifier.SetRoleStateReconciler(rec)
	h := &AuditCheckpointHandler{verifier: verifier, signing: signer}
	users := identity.NewUserService(db, authz.NewAssetAuthorizationService(db))
	h.SetRoleStateNames(users, failures)
	tokens := identity.NewAgentTokenService(db, audit.NewTxSink())
	tokens.SetIntegrityProbe(rec)
	userHandler := NewUserHandler(users)
	userHandler.SetAgentTokenService(tokens)
	auth := identity.NewAuthService("integrity-e2e-jwt", time.Hour)
	auth.SetEpochGateDB(db)
	jwt, err := crypto.NewJWTManager("integrity-e2e-jwt", time.Hour).GenerateToken(owner.ID, owner.Username, "", model.RoleAdmin, crypto.AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/verify", middleware.AuthMiddleware(auth), h.Verify)
	userHandler.RegisterRoutes(router.Group("/api/v1"), auth)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		q.Header.Set("Authorization", "Bearer "+jwt)
		q.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, q)
		return w
	}
	verify := func(wantPrincipal, wantToken string) {
		w := call("GET", "/verify", "")
		if w.Code != 200 {
			t.Fatalf("verify status %d", w.Code)
		}
		var body struct {
			Data struct {
				Chain map[string]json.RawMessage `json:"chain"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{"role_state": "match", "principal_state": wantPrincipal, "agent_token_state": wantToken} {
			var state principalStateView
			if err := json.Unmarshal(body.Data.Chain[key], &state); err != nil {
				t.Fatal(err)
			}
			if state.State != want {
				t.Fatalf("%s state=%s want=%s", key, state.State, want)
			}
			if want == "mismatch" && (state.LastEvent == nil || (len(state.Missing) == 0 && len(state.Extra) == 0)) {
				t.Fatal("mismatch lacks difference/event", key)
			}
			t.Logf("HTTP verify: %s=%s since=%d missing=%v extra=%v event=%v", key, state.State, state.SinceSeq, state.Missing, state.Extra, state.LastEvent != nil)
		}
	}
	verify("match", "match")
	if err := db.Exec("UPDATE users SET kind='agent',owner_user_id=? WHERE id=?", owner.ID, human.ID).Error; err != nil {
		t.Fatal(err)
	}
	t.Log("SQL direct kind change id", human.ID)
	verify("mismatch", "match")
	if err := db.Exec("INSERT INTO agent_tokens(id,user_id,name,token_hash,created_by,expires_at) VALUES(99,?,?,?,?,?)", agent.ID, "direct-insert", strings.Repeat("b", 64), owner.ID, time.Now().Add(time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	t.Log("SQL direct credential insert id 99")
	verify("mismatch", "mismatch")
	for i := 0; i < 2; i++ {
		select {
		case body := <-notifications:
			if !strings.Contains(body, model.CausePrincipalStateMismatch) {
				t.Fatal("wrong webhook payload")
			}
			t.Log("webhook delivered principal_state_mismatch")
		case <-time.After(5 * time.Second):
			t.Fatal("notification not delivered")
		}
	}
	var open int64
	if err := db.Model(&model.AuditFailureEvent{}).Where("mechanism=? AND ended_at IS NULL", model.MechanismPrincipalStateIntegrity).Count(&open).Error; err != nil || open != 2 {
		t.Fatalf("open=%d err=%v", open, err)
	}
	// Resolve the unauthorized human->agent conversion by deleting that principal
	// through the application, and invalidate the inserted credential via the API.
	w := call("DELETE", fmt.Sprintf("/api/v1/users/%d", human.ID), "")
	if w.Code != 200 && w.Code != 204 {
		t.Fatalf("delete principal: %d %s", w.Code, w.Body)
	}
	w = call("DELETE", fmt.Sprintf("/api/v1/users/%d/agent-tokens/99", agent.ID), `{"note":"integrity e2e revoke"}`)
	if w.Code != 204 {
		t.Fatalf("revoke credential: %d %s", w.Code, w.Body)
	}
	verify("match", "match")
	cp, err := seal.SealNow()
	if err != nil || cp.RoleStateReconciled == nil || !*cp.RoleStateReconciled {
		t.Fatal("legitimate changes did not reconcile at seal", err)
	}
	t.Log("application delete+revoke; sealed all-match", cp.Seq)
}
