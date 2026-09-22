package sshproxy

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	sessionmodule "github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func agentSessionFixture(t *testing.T) (*gorm.DB, *sessionmodule.SessionService, model.User, model.AgentToken, model.AccessRequest) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sql, _ := db.DB()
	sql.SetMaxOpenConns(1)
	t.Cleanup(func() { sql.Close() })
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	if err := db.AutoMigrate(&model.User{}, &model.AgentToken{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.Session{}, &model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	owner := model.User{ID: 1, Username: "owner", Kind: model.KindHuman, Active: true}
	agent := model.User{ID: 2, Username: "agent", Kind: model.KindAgent, OwnerUserID: &owner.ID, Active: true}
	for _, u := range []*model.User{&owner, &agent} {
		if err := db.Create(u).Error; err != nil {
			t.Fatal(err)
		}
	}
	token := model.AgentToken{UserID: agent.ID, Name: "fixture", TokenHash: "hash", ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Create(&token).Error; err != nil {
		t.Fatal(err)
	}
	task := model.AccessRequest{RequesterID: owner.ID, ExecutorUserID: &agent.ID, AssetID: 1, Reason: "task", RequestedDurationMinutes: 30, Status: model.AccessRequestPending, PendingExpiresAt: time.Now()}
	if err := db.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	service := sessionmodule.NewSessionService(nil)
	service.SetAuditSink(audit.NewTxSink())
	service.SetAgentActorSource(func(tx *gorm.DB, sess *model.Session) error {
		if err := identity.BindAgentSessionPrincipal(tx, sess); err != nil {
			return err
		}
		return authz.BindAgentSessionTask(tx, sess)
	})
	return db, service, agent, token, task
}
func TestSessionActorSnapshot(t *testing.T) {
	db, service, agent, token, task := agentSessionFixture(t)
	h := &Handler{SessionService: service}
	sess := h.createSession(agent.ID, 1, model.ProtocolSSH, "192.0.2.1", nil, accountSnapshot{}, authProvenance{AgentTokenID: token.ID, AccessRequestID: task.ID}, false)
	if sess == nil || sess.ActorKind == nil || *sess.ActorKind != model.KindAgent || *sess.OwnerUserID != 1 || *sess.OnBehalfOfUserID != 1 || *sess.AgentTokenID != token.ID || *sess.AccessRequestID != task.ID {
		t.Fatal(sess)
	}
	if err := db.Create(&model.User{ID: 99, Username: "new-owner", Kind: model.KindHuman, Active: true}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.User{}).Where("id=?", agent.ID).Update("owner_user_id", 99).Error; err != nil {
		t.Fatal(err)
	}
	var saved model.Session
	if err := db.First(&saved, sess.ID).Error; err != nil || *saved.OwnerUserID != 1 || *saved.OnBehalfOfUserID != 1 {
		t.Fatal(saved, err)
	}
}
func TestSessionAuthorizationSource(t *testing.T) {
	_, service, agent, token, _ := agentSessionFixture(t)
	sess := &model.Session{UserID: agent.ID, AgentTokenID: &token.ID}
	if err := service.CreateWithGenerationGuard(crypto.AuthContext{}, sess); err == nil {
		t.Fatal("agent missing request accepted")
	}
}
func TestSessionActorHumanCompatibility(t *testing.T) {
	_, service, _, _, _ := agentSessionFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	legacy := &model.Session{CreatedAt: now, UpdatedAt: now, UserID: 1, SessionID: "legacy", StartTime: now}
	live := &model.Session{CreatedAt: now, UpdatedAt: now, UserID: 1, SessionID: "live", StartTime: now}
	if err := service.Create(legacy); err != nil {
		t.Fatal(err)
	}
	if err := service.CreateWithGenerationGuard(crypto.AuthContext{}, live); err != nil {
		t.Fatal(err)
	}
	var left, right map[string]any
	b, _ := json.Marshal(legacy)
	json.Unmarshal(b, &left)
	b, _ = json.Marshal(live)
	json.Unmarshal(b, &right)
	for _, m := range []map[string]any{left, right} {
		delete(m, "id")
		delete(m, "session_id")
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatal("human JSON changed", left, right)
	}
	for _, key := range []string{"actor_kind", "owner_user_id", "on_behalf_of_user_id", "revoked_during_session_at"} {
		if _, ok := right[key]; ok {
			t.Fatal("new human field", key)
		}
	}
}
func TestRevokeDuringSession(t *testing.T) {
	db, service, agent, token, task := agentSessionFixture(t)
	sess := &model.Session{UserID: agent.ID, AgentTokenID: &token.ID, AccessRequestID: &task.ID}
	if err := service.Create(sess); err != nil {
		t.Fatal(err)
	}
	if _, err := service.TerminateByAgentToken(token.ID, model.EndReasonAdminTerminate); err != nil {
		t.Fatal(err)
	}
	var saved model.Session
	if err := db.First(&saved, sess.ID).Error; err != nil || saved.RevokedDuringSessionAt == nil || saved.Status != model.SessionStatusDisconnected {
		t.Fatal(saved, err)
	}
	var rows []model.AuditLog
	if err := db.Where("resource=? AND resource_id=?", model.ResourceSession, sess.ID).Find(&rows).Error; err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(rows[0].Details), &details); err != nil || details["event"] != "revoked_during_session" {
		t.Fatal(details, err)
	}
	if _, err := service.TerminateByAgentToken(token.ID, model.EndReasonAdminTerminate); err != nil {
		t.Fatal(err)
	}
	var count int64
	db.Model(&model.AuditLog{}).Where("resource=? AND resource_id=?", model.ResourceSession, sess.ID).Count(&count)
	if count != 1 {
		t.Fatal("duplicate revoke audit", count)
	}
}
