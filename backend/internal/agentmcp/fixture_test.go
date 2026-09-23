package agentmcp

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type fixture struct {
	h                                 *Handler
	db                                *gorm.DB
	token                             string
	agent, asset, account, task, item uint
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old; sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.AgentToken{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{}, &model.AssetAccount{}, &model.AssetHostKey{}, &model.Credential{}, &model.CredentialSecretVersion{}, &model.AssetAuthorization{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.AccessRequestApproval{}, &model.SecurityPolicy{}, &model.TransmissionConsent{}, &model.AuditLog{}, &model.AuditFailureEvent{}, &model.Session{}, &model.SessionCommand{}, &model.AlertRule{}, &model.CommandAlert{}, &model.OIDCProvider{}, &model.AgentToolCall{}, &model.AgentTaskReport{}, &model.AgentVisibilityExposure{}, &model.AgentProbeEvent{}, &model.ApproverScope{}, &model.DataKey{}, &model.IntegrityBaseline{}, &model.RefreshToken{}))
	kek, err := crypto.NewEnvKEKProvider(make([]byte, 32))
	require.NoError(t, err)
	km, err := keyvault.InitKeyManager(db, kek)
	require.NoError(t, err)
	_, err = audit.InitAuditIntegrityVersioned(db, km)
	require.NoError(t, err)
	t.Cleanup(func() { audit.ResetAuditIntegritySingleton(); model.SetAgentToolCallStampHook(nil) })
	owner := model.User{Username: "mcp-owner", Password: "!", Kind: model.KindHuman, Active: true}
	require.NoError(t, db.Create(&owner).Error)
	agent := model.User{Username: "mcp-agent", Password: "!", Kind: model.KindAgent, OwnerUserID: &owner.ID, Active: true}
	require.NoError(t, db.Create(&agent).Error)
	open := model.AccessPolicyOpen
	target := model.Asset{Name: "mcp-target", Protocol: model.ProtocolSSH, Host: "ssh-test", Port: 2222, Active: true, AccessPolicy: &open, CreatedBy: owner.ID}
	require.NoError(t, db.Create(&target).Error)
	codec := aesColumnCodec(t, make([]byte, 32))
	sshPassword := "testpass123"
	if fromEnv := os.Getenv("LEDGER_E2E_SSH_PASSWORD"); fromEnv != "" {
		sshPassword = fromEnv
	}
	enc, err := codec.EncryptFor(context.Background(), crypto.CipherRef{Table: "credential_secret_versions", Column: "password_enc"}, sshPassword)
	require.NoError(t, err)
	cred := model.Credential{Scope: model.CredentialScopeDedicated, Username: "testuser", SecretType: model.ChangeSecretTypePassword, AuthMethod: "password", ProtocolFamily: model.ProtocolFamilySSH}
	require.NoError(t, db.Create(&cred).Error)
	version := model.CredentialSecretVersion{CredentialID: cred.ID, VersionNo: 1, SecretType: model.ChangeSecretTypePassword, PasswordEnc: enc, CreatedReason: model.CredentialVersionReasonManual}
	require.NoError(t, db.Create(&version).Error)
	account := model.AssetAccount{AssetID: target.ID, Username: "testuser", IsDefault: true, CredentialID: cred.ID, EffectiveVersionID: &version.ID}
	require.NoError(t, db.Create(&account).Error)
	now := time.Now().Add(-time.Minute)
	end := now.Add(time.Hour)
	ticket := model.AssetAuthorization{UserID: &agent.ID, AssetID: &target.ID, Permission: model.PermissionConnect, GrantedBy: owner.ID, Source: model.AuthorizationSourceTicket, Accounts: model.AccountScope{"testuser"}, DateStart: &now, DateExpired: &end}
	require.NoError(t, db.Create(&ticket).Error)
	task := model.AccessRequest{RequesterID: agent.ID, AssetID: target.ID, Accounts: model.AccountScope{"testuser"}, Reason: "MCP integration", RequestedDurationMinutes: 60, Status: model.AccessRequestPending, PendingExpiresAt: end}
	require.NoError(t, db.Create(&task).Error)
	item := model.AccessRequestItem{RequestID: task.ID, RequesterID: agent.ID, AssetID: target.ID, Accounts: model.AccountScope{"testuser"}, Status: model.AccessRequestPending}
	require.NoError(t, db.Create(&item).Error)
	require.NoError(t, db.Model(&item).Updates(map[string]any{"status": model.AccessRequestApproved, "approved_duration_minutes": 60, "approved_date_start": now, "decided_at": now, "authorization_id": ticket.ID}).Error)
	require.NoError(t, db.Model(&task).Update("status", model.AccessRequestApproved).Error)
	assets, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	auth := identity.NewAuthService("mcp-test-secret", time.Hour)
	auth.SetEpochGateDB(db)
	registry := proxy.NewConnectionRegistry()
	audits := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	t.Cleanup(func() { require.NoError(t, audits.Shutdown(context.Background())) })
	authzService := authz.NewAssetAuthorizationService(db)
	ssh := sshproxy.NewHandler(assets, auth, authzService, session.NewSessionService(registry), registry, t.TempDir(), audits)
	ssh.SessionService.SetAuditSink(audit.NewTxSink())
	ssh.SessionService.SetAgentActorSource(func(tx *gorm.DB, sess *model.Session) error {
		if err := identity.BindAgentSessionPrincipal(tx, sess); err != nil {
			return err
		}
		return authz.BindAgentSessionTask(tx, sess)
	})
	ssh.AlertSink = audit.NewAlertRecorder(db)
	ssh.HostKeys = asset.NewHostKeyService(db)
	ssh.DB = db
	policies := policy.NewSecurityPolicyService(db)
	ssh.AccessPolicy = policy.NewAccessPolicyService(db, policies, authzService)
	audit.InitAuditFailure(db, policies)
	matcher := audit.InitAlertMatcher(db, nil)
	require.NoError(t, matcher.LoadRules())
	t.Cleanup(func() { audit.InitAlertMatcher(nil, nil) })
	issued, err := identity.NewAgentTokenService(db, audit.NewTxSink()).Create(agent.ID, identity.CreateAgentTokenRequest{Name: "mcp-test", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
	require.NoError(t, err)
	f := &fixture{h: NewHandler(ssh).WithLedgerCodec(km), db: db, token: issued.Token, agent: agent.ID, asset: target.ID, account: account.ID, task: task.ID, item: item.ID}
	return f
}
func (f *fixture) input() OpenSessionInput {
	return OpenSessionInput{AssetID: f.asset, AccountID: f.account, RequestID: f.task}
}
func (f *fixture) authenticated(t *testing.T, ip string, fn func(*gin.Context)) {
	t.Helper()
	r := gin.New()
	r.POST("/api/v1/mcp", middleware.AuthMiddleware(f.h.ssh.AuthService), fn)
	q := httptest.NewRequest("POST", "/api/v1/mcp", nil)
	q.RemoteAddr = ip + ":4567"
	q.Header.Set("Authorization", "Bearer "+f.token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, q)
	require.Equal(t, 200, w.Code, w.Body.String())
}
