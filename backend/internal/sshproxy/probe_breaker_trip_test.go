package sshproxy

import (
	"context"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"testing"
	"time"
)

func TestProbeBreakerTrip(t *testing.T) {
	db, sessions, agent, token, task := agentSessionFixture(t)
	if err := db.AutoMigrate(&model.AgentProbeEvent{}, &model.CommandAlert{}, &model.Asset{}, &model.AgentVisibilityExposure{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Session(&gorm.Session{SkipHooks: true}).Create(&model.Asset{ID: 77, Name: "unexposed"}).Error; err != nil {
		t.Fatal(err)
	}
	other := model.AgentToken{UserID: agent.ID, Name: "other", TokenHash: "otherhash", ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	sess := &model.Session{UserID: agent.ID, AgentTokenID: &token.ID, AccessRequestID: &task.ID}
	if err := sessions.Create(sess); err != nil {
		t.Fatal(err)
	}
	survivor := &model.Session{UserID: agent.ID, AgentTokenID: &other.ID, AccessRequestID: &task.ID}
	if err := sessions.Create(survivor); err != nil {
		t.Fatal(err)
	}
	tokens := identity.NewAgentTokenService(db, audit.NewTxSink())
	tokens.SetSessionTerminator(sessions)
	grants := proxy.NewConnectTokenManager()
	a, err := grants.IssueConnectToken(context.Background(), gatewayapi.ConnectGrant{UserID: agent.ID, AgentTokenID: token.ID})
	if err != nil {
		t.Fatal(err)
	}
	b, err := grants.IssueConnectToken(context.Background(), gatewayapi.ConnectGrant{UserID: agent.ID, AgentTokenID: other.ID})
	if err != nil {
		t.Fatal(err)
	}
	breaker := audit.NewProbeBreaker(db, audit.NewTxSink(), audit.NewAlertRecorder(db), audit.ProbeBreakerDependencies{LockPrincipal: identity.LockProbePrincipal, Classify: authz.ClassifyAgentProbe, Trip: tokens.TripProbeBreakerInTx, Finish: func(id uint) { grants.InvalidateByAgentToken(id); tokens.FinishProbeBreaker(id) }, Limits: func() (int, int) { return 1, 300 }, Notify: func(uint, notifycat.Event, map[string]string) {}})
	if r, err := breaker.RecordDenied(context.Background(), agent.ID, token.ID, 77, "GET /assets/:id"); err != nil || !r.Tripped {
		t.Fatal(r, err)
	}
	if _, ok := grants.RedeemConnectToken(context.Background(), a); ok {
		t.Fatal("tripped grant survived")
	}
	if _, ok := grants.RedeemConnectToken(context.Background(), b); !ok {
		t.Fatal("unrelated grant lost")
	}
	var saved, untouched model.Session
	db.First(&saved, sess.ID)
	db.First(&untouched, survivor.ID)
	if saved.Status != model.SessionStatusDisconnected || saved.RevokedDuringSessionAt == nil || untouched.Status != model.SessionStatusActive {
		t.Fatal(saved, untouched)
	}
	var user model.User
	db.First(&user, agent.ID)
	var frozen model.AgentToken
	db.First(&frozen, token.ID)
	if user.BreakerPendingAt == nil || frozen.SuspendedAt == nil {
		t.Fatal(user, frozen)
	}
	late := &model.Session{UserID: agent.ID, AgentTokenID: &token.ID, AccessRequestID: &task.ID}
	if err := sessions.Create(late); err == nil {
		t.Fatal("already redeemed grant established late session")
	}
}
