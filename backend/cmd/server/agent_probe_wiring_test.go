package main

import (
	"context"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"testing"
	"time"
)

type probeWiringTerminator struct{ ids []uint }

func (s *probeWiringTerminator) TerminateByAgentToken(id uint, reason string) (identity.AgentSessionTermination, error) {
	s.ids = append(s.ids, id)
	return identity.AgentSessionTermination{}, nil
}

func TestProbeBreakerTripProductionWiring(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sql, _ := db.DB()
	sql.SetMaxOpenConns(1)
	t.Cleanup(func() { sql.Close() })
	if err := db.AutoMigrate(&model.User{}, &model.AgentToken{}, &model.Asset{}, &model.AgentVisibilityExposure{}, &model.AgentProbeEvent{}, &model.AuditLog{}, &model.CommandAlert{}); err != nil {
		t.Fatal(err)
	}
	owner := uint(1)
	for _, u := range []model.User{{ID: owner, Username: "owner", Kind: model.KindHuman, Active: true}, {ID: 2, Username: "agent", Kind: model.KindAgent, OwnerUserID: &owner, Active: true}} {
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
	}
	token := model.AgentToken{UserID: 2, Name: "token", TokenHash: "hash", ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Create(&token).Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint{10, 11} {
		if err := db.Session(&gorm.Session{SkipHooks: true}).Create(&model.Asset{ID: id, Name: "target"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	authorization := authz.NewAssetAuthorizationService(db)
	if err := authorization.RecordAgentVisibilityExposures(context.Background(), 2, []uint{10}); err != nil {
		t.Fatal(err)
	}
	tokens := identity.NewAgentTokenService(db, audit.NewTxSink())
	termination := &probeWiringTerminator{}
	tokens.SetSessionTerminator(termination)
	grants := proxy.NewConnectTokenManager()
	grant, err := grants.IssueConnectToken(context.Background(), gatewayapi.ConnectGrant{UserID: 2, AgentTokenID: token.ID})
	if err != nil {
		t.Fatal(err)
	}
	notified := 0
	wireAgentProbeBreaker(db, audit.NewTxSink(), audit.NewAlertRecorder(db), authorization, tokens, grants, func() (int, int) { return 1, 300 }, func(id uint, event notifycat.Event, params map[string]string) {
		notified++
		if id != owner || event != notifycat.EventAgentBreakerTripped || params["owner_id"] != "1" {
			t.Error(id, event, params)
		}
		// Notification runs only after the same transaction has committed its alert and token state.
		var n int64
		db.Model(&model.CommandAlert{}).Where("kind=?", model.AlertKindAgentBreaker).Count(&n)
		var saved model.AgentToken
		db.First(&saved, token.ID)
		if n != 1 || saved.SuspendedAt == nil {
			t.Error(n, saved)
		}
	})
	for _, id := range []uint{10, 999, 11} {
		if err := authorization.RecordDeniedAgentProbe(context.Background(), 2, token.ID, id, "GET /assets/:id"); err != nil {
			t.Fatal(err)
		}
	}
	if len(termination.ids) != 1 || termination.ids[0] != token.ID {
		t.Fatal("termination wiring", termination.ids)
	}
	if notified != 1 {
		t.Fatal("notifications", notified)
	}
	if _, ok := grants.RedeemConnectToken(context.Background(), grant); ok {
		t.Fatal("issued grant survived")
	}
	var user model.User
	db.First(&user, 2)
	if user.BreakerPendingAt == nil {
		t.Fatal("principal not pending")
	}
	var events []model.AgentProbeEvent
	db.Order("id").Find(&events)
	if len(events) != 3 || events[0].Class != model.ProbeRevoked || events[1].Class != model.ProbeRetired || events[2].Class != model.ProbeNeverVisible {
		t.Fatal(events)
	}
}
