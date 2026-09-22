package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

func init() {
	audit.SetPrincipalSource(SnapshotPrincipalStates)
	audit.SetAgentTokenSource(SnapshotAgentTokenStates)
}
func failProjectionAudit(t *testing.T, db *gorm.DB, resource model.AuditResource) {
	t.Helper()
	if err := db.Callback().Create().Before("gorm:create").Register("projection-failure", func(tx *gorm.DB) {
		if row, ok := tx.Statement.Dest.(*model.AuditLog); ok && row.Resource == resource {
			tx.AddError(errors.New("injected projection audit failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Callback().Create().Remove("projection-failure") })
}
func projectionTableForTest(t *testing.T, name string) audit.StateTable {
	t.Helper()
	for _, st := range audit.StateTableRegistry() {
		if st.Name == name {
			return st
		}
	}
	t.Fatal("missing registry", name)
	return audit.StateTable{}
}
func TestPrincipalAuditTransactionalReplay(t *testing.T) {
	for _, fail := range []bool{false, true} {
		for _, op := range []string{"create", "owner", "delete"} {
			t.Run(op+map[bool]string{false: "/success", true: "/rollback"}[fail], func(t *testing.T) {
				users, _, db, owner, agent := principalEnv(t)
				if err := db.AutoMigrate(&model.AgentToken{}, &model.UserGroup{}, &model.ApproverScope{}); err != nil {
					t.Fatal(err)
				}
				before, err := audit.SnapshotPrincipals(context.Background(), db)
				if err != nil {
					t.Fatal(err)
				}
				if fail {
					failProjectionAudit(t, db, model.ResourceUser)
				}
				var writeErr error
				switch op {
				case "create":
					_, writeErr = users.Create(&CreateUserRequest{Username: "integrity-agent", Kind: model.KindAgent, OwnerUserID: &owner.ID})
				case "owner":
					other := model.User{Username: "new-owner", Password: "!", Active: true}
					if err := db.Create(&other).Error; err != nil {
						t.Fatal(err)
					}
					before, err = audit.SnapshotPrincipals(context.Background(), db)
					if err != nil {
						t.Fatal(err)
					}
					_, _, writeErr = users.Update(agent.ID, &UpdateUserRequest{OwnerUserID: &other.ID})
				case "delete":
					writeErr = users.Delete(agent.ID)
				}
				after, err := audit.SnapshotPrincipals(context.Background(), db)
				if err != nil {
					t.Fatal(err)
				}
				if fail {
					if writeErr == nil || before.Hash != after.Hash {
						t.Fatalf("failure did not roll back: %v", writeErr)
					}
					return
				}
				if writeErr != nil {
					t.Fatal(writeErr)
				}
				var rows []model.AuditLog
				if err := db.Where("resource = ?", model.ResourceUser).Order("id").Find(&rows).Error; err != nil {
					t.Fatal(err)
				}
				if len(rows) != 1 {
					t.Fatalf("want one projection event: %d", len(rows))
				}
				st := projectionTableForTest(t, audit.StateTablePrincipals)
				set, err := st.Decode(before.Body)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := st.Apply(set, rows)
				if err != nil || expected.Hash != after.Hash {
					t.Fatalf("legal write cannot replay: %v %s != %s", err, expected.Body, after.Body)
				}
			})
		}
	}
}
func TestAgentTokenAuditTransactionalReplay(t *testing.T) {
	for _, op := range []string{"create", "revoke", "suspend"} {
		for _, fail := range []bool{false, true} {
			t.Run(op+map[bool]string{false: "/success", true: "/rollback"}[fail], func(t *testing.T) {
				svc, db, owner, agent := agentTokenEnv(t)
				var token *CreatedAgentToken
				if op != "create" {
					token = createAgentTestToken(t, svc, owner, agent)
				}
				before, err := audit.SnapshotAgentTokens(context.Background(), db)
				if err != nil {
					t.Fatal(err)
				}
				var maxID uint
				db.Model(&model.AuditLog{}).Select("COALESCE(MAX(id),0)").Scan(&maxID)
				if fail {
					failProjectionAudit(t, db, model.ResourceAgentToken)
				}
				var writeErr error
				switch op {
				case "create":
					token, writeErr = svc.Create(agent.ID, CreateAgentTokenRequest{Name: "audit-token", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
				case "revoke":
					writeErr = svc.Revoke(agent.ID, token.ID, "private-note", gatewayapi.Actor{UserID: owner.ID})
				case "suspend":
					writeErr = svc.Suspend(agent.ID, token.ID, "private-reason", gatewayapi.Actor{UserID: owner.ID})
				}
				after, err := audit.SnapshotAgentTokens(context.Background(), db)
				if err != nil {
					t.Fatal(err)
				}
				if fail {
					if writeErr == nil || before.Hash != after.Hash {
						t.Fatalf("failure did not roll back: %v", writeErr)
					}
					return
				}
				if writeErr != nil {
					t.Fatal(writeErr)
				}
				var rows []model.AuditLog
				if err := db.Where("resource = ? AND id > ?", model.ResourceAgentToken, maxID).Order("id").Find(&rows).Error; err != nil {
					t.Fatal(err)
				}
				if len(rows) == 0 {
					t.Fatal("missing audit")
				}
				for _, row := range rows {
					for _, secret := range []string{"cxa_", token.TokenHash, token.Token, "private-note", "private-reason"} {
						if strings.Contains(row.Details, secret) {
							t.Fatal("audit secret leaked")
						}
					}
				}
				st := projectionTableForTest(t, audit.StateTableAgentTokens)
				set, err := st.Decode(before.Body)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := st.Apply(set, rows)
				if err != nil || expected.Hash != after.Hash {
					t.Fatalf("token replay: %v %s != %s", err, expected.Body, after.Body)
				}
			})
		}
	}
}
