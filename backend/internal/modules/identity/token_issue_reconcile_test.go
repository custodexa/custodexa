package identity

import (
	"bytes"
	"context"
	"errors"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTokenIssueReconcile(t *testing.T) {
	for _, mode := range []string{"match", "mismatch", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			tokens, db, owner, agent := agentTokenEnv(t)
			if err := db.AutoMigrate(&model.AuditCheckpoint{}, &model.AuditFailureEvent{}); err != nil {
				t.Fatal(err)
			}
			other := model.User{Username: "other-owner", Password: "!", Active: true}
			if err := db.Create(&other).Error; err != nil {
				t.Fatal(err)
			}
			body, _, err := audit.SnapshotStateTables(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Create(&model.AuditCheckpoint{Seq: 1, AggScheme: model.LatestCheckpointScheme, RoleStateSnapshot: &body}).Error; err != nil {
				t.Fatal(err)
			}
			failures := audit.InitAuditFailure(db, policy.NewSecurityPolicyService(db))
			t.Cleanup(audit.ResetAuditFailureSingleton)
			rec := audit.NewRoleStateReconciler(db, failures)
			tokens.SetIntegrityProbe(rec)
			if mode == "mismatch" {
				if err := db.Exec("UPDATE users SET owner_user_id=? WHERE id=?", other.ID, agent.ID).Error; err != nil {
					t.Fatal(err)
				}
			}
			var logbuf bytes.Buffer
			old := log.Writer()
			log.SetOutput(&logbuf)
			t.Cleanup(func() { log.SetOutput(old) })
			if mode == "unknown" {
				fired := 0
				err := db.Callback().Query().Before("gorm:query").Register("probe-failure", func(tx *gorm.DB) {
					if tx.Statement.Table == "audit_checkpoints" {
						fired++
						tx.AddError(errors.New("probe-unavailable"))
					}
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					db.Callback().Query().Remove("probe-failure")
					if fired == 0 {
						t.Error("probe fault not reached")
					}
				})
			}
			before, err := audit.SnapshotPrincipals(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			result, err := tokens.Create(agent.ID, CreateAgentTokenRequest{Name: "probe", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
			if err != nil || result == nil {
				t.Fatal("probe blocked issuance", err)
			}
			after, err := audit.SnapshotPrincipals(context.Background(), db)
			if err != nil || before.Hash != after.Hash {
				t.Fatal("probe mutated principals", err)
			}
			var events int64
			db.Model(&model.AuditFailureEvent{}).Where("mechanism=?", model.MechanismPrincipalStateIntegrity).Count(&events)
			want := int64(0)
			if mode == "mismatch" {
				want = 1
			}
			if events != want {
				t.Fatalf("events %d want %d", events, want)
			}
			if mode == "unknown" {
				if !strings.Contains(logbuf.String(), "reconciliation unknown") {
					t.Fatal("failure not logged")
				}
				for _, report := range rec.ReconcileTables(context.Background()) {
					if report.State == audit.RoleStateMatch {
						t.Fatal("failed probe reported match")
					}
				}
			}
		})
	}
	t.Run("kind", func(t *testing.T) {
		tokens, db, owner, _ := agentTokenEnv(t)
		if err := db.AutoMigrate(&model.AuditCheckpoint{}, &model.AuditFailureEvent{}, &model.NotificationChannel{}); err != nil {
			t.Fatal(err)
		}
		human := model.User{Username: "kind-human", Password: "!", Kind: model.KindHuman, Active: true}
		if err := db.Create(&human).Error; err != nil {
			t.Fatal(err)
		}
		body, _, err := audit.SnapshotStateTables(context.Background(), db)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.AuditCheckpoint{Seq: 1, AggScheme: model.LatestCheckpointScheme, RoleStateSnapshot: &body}).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.SecurityPolicy{Key: policy.PolicyFailureAlertEnabled, Value: "true"}).Error; err != nil {
			t.Fatal(err)
		}
		notifications := make(chan struct{}, 1)
		receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case notifications <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(receiver.Close)
		if err := db.Create(&model.NotificationChannel{Name: "kind-integrity", Type: model.NotificationChannelTypeWebhook, URL: receiver.URL, Enabled: true, Language: model.NotificationChannelLanguageEnUS}).Error; err != nil {
			t.Fatal(err)
		}
		notifier := audit.InitAlertNotifier(db, nil)
		t.Cleanup(func() { audit.StopAlertNotifierForRelease(notifier) })
		if err := notifier.LoadChannels(); err != nil {
			t.Fatal(err)
		}
		failures := audit.InitAuditFailure(db, policy.NewSecurityPolicyService(db))
		t.Cleanup(audit.ResetAuditFailureSingleton)
		tokens.SetIntegrityProbe(audit.NewRoleStateReconciler(db, failures))
		if err := db.Exec("UPDATE users SET kind=?, owner_user_id=? WHERE id=?", model.KindAgent, owner.ID, human.ID).Error; err != nil {
			t.Fatal(err)
		}
		result, err := tokens.Create(human.ID, CreateAgentTokenRequest{Name: "kind-probe", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
		if err != nil || result == nil {
			t.Fatal("kind probe blocked issuance", err)
		}
		var events int64
		if err := db.Model(&model.AuditFailureEvent{}).Where("mechanism=?", model.MechanismPrincipalStateIntegrity).Count(&events).Error; err != nil {
			t.Fatal(err)
		}
		if events != 1 {
			t.Fatalf("events %d want 1", events)
		}
		select {
		case <-notifications:
		case <-time.After(5 * time.Second):
			t.Fatal("kind integrity notification not sent")
		}
	})
}
