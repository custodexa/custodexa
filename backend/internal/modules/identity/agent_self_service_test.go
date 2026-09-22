package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"strings"
	"sync"
	"testing"
	"time"
)

func selfPolicy(t *testing.T, db *gorm.DB, key, value string) {
	t.Helper()
	if err := db.AutoMigrate(&model.SecurityPolicy{}); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.NewSecurityPolicyService(db).Update(key, value, "test"); err != nil {
		t.Fatal(err)
	}
}
func TestAgentSelfCreate(t *testing.T) {
	for _, tc := range []string{"disabled", "agent caller", "inactive", "no name", "no purpose", "valid"} {
		t.Run(tc, func(t *testing.T) {
			users, _, db, owner, agent := principalEnv(t)
			selfPolicy(t, db, policy.PolicyAgentSelfCreateEnabled, "true")
			actor := gatewayapi.Actor{UserID: owner.ID}
			req := CreateMyAgentRequest{Username: "self-worker", Purpose: "nightly backup"}
			switch tc {
			case "disabled":
				selfPolicy(t, db, policy.PolicyAgentSelfCreateEnabled, "false")
			case "agent caller":
				actor.UserID = agent.ID
			case "inactive":
				if err := db.Model(owner).Update("active", false).Error; err != nil {
					t.Fatal(err)
				}
			case "no name":
				req.Username = " "
			case "no purpose":
				req.Purpose = " "
			}
			before := principalCount(t, db, &model.User{})
			auditBefore := principalCount(t, db, &model.AuditLog{})
			u, err := users.CreateMyAgent(actor, req)
			if tc != "valid" {
				if err == nil {
					t.Fatal("accepted invalid request")
				}
				if tc == "disabled" && !errors.Is(err, ErrAgentSelfCreateDisabled) {
					t.Fatal(err)
				}
				if principalCount(t, db, &model.User{}) != before || principalCount(t, db, &model.AuditLog{}) != auditBefore {
					t.Fatal("rejected request wrote rows")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if u.Kind != model.KindAgent || *u.OwnerUserID != owner.ID || u.Password != "!" || u.MustChangePassword || u.FullName != "" || u.LocalDisplayName != nil {
				t.Fatalf("invalid agent: %+v", u)
			}
			list, err := users.List(&ListUsersRequest{Page: 1, PageSize: 100})
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range list.Data {
				if row.ID == u.ID {
					t.Fatal("agent in default admin list")
				}
			}
		})
	}
}
func TestAgentSelfCreateLimit(t *testing.T) {
	users, _, db, owner, agent := principalEnv(t)
	selfPolicy(t, db, policy.PolicyAgentSelfCreateEnabled, "true")
	selfPolicy(t, db, policy.PolicyAgentSelfCreateMaxPerOwner, "1")
	actor := gatewayapi.Actor{UserID: owner.ID}
	req := CreateMyAgentRequest{Username: "self-limited", Purpose: "test"}
	if _, err := users.CreateMyAgent(actor, req); !errors.Is(err, ErrAgentSelfCreateLimit) {
		t.Fatal(err)
	}
	if err := db.Delete(agent).Error; err != nil {
		t.Fatal(err)
	}
	u, err := users.CreateMyAgent(actor, req)
	if err != nil {
		t.Fatal(err)
	}
	// Administrator path remains exempt, even with the policy disabled.
	selfPolicy(t, db, policy.PolicyAgentSelfCreateEnabled, "false")
	if _, err := users.Create(&CreateUserRequest{Username: "admin-exempt", Kind: model.KindAgent, OwnerUserID: &owner.ID}); err != nil {
		t.Fatal(err)
	}
	selfPolicy(t, db, policy.PolicyAgentSelfCreateEnabled, "true")
	selfPolicy(t, db, policy.PolicyAgentSelfCreateMaxPerOwner, "3")
	if _, err := users.CreateMyAgent(actor, CreateMyAgentRequest{Username: "before-lowering", Purpose: "test"}); err != nil {
		t.Fatal(err)
	}
	selfPolicy(t, db, policy.PolicyAgentSelfCreateMaxPerOwner, "1")
	before := principalCount(t, db, &model.User{})
	logs := principalCount(t, db, &model.AuditLog{})
	if _, err := users.CreateMyAgent(actor, CreateMyAgentRequest{Username: "after-lowering", Purpose: "test"}); !errors.Is(err, ErrAgentSelfCreateLimit) {
		t.Fatal(err)
	}
	var saved model.User
	if err := db.First(&saved, u.ID).Error; err != nil || !saved.Active {
		t.Fatal("existing agent changed", err)
	}
	if principalCount(t, db, &model.User{}) != before || principalCount(t, db, &model.AuditLog{}) != logs {
		t.Fatal("limit failure wrote rows")
	}
}
func TestAgentSelfCreateLimitConcurrentPG(t *testing.T) {
	dsn := pgLockTestDSN(t)
	admin := openPGLockDB(t, dsn)
	schema := fmt.Sprintf("self_agent_%d", time.Now().UnixNano())
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error; err != nil {
			t.Error(err)
		}
	})
	db := openPGLockDB(t, dsn+" search_path="+schema)
	other := openPGLockDB(t, dsn+" search_path="+schema)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}, &model.AuditLog{}, &model.SecurityPolicy{}); err != nil {
		t.Fatal(err)
	}
	owner := model.User{Username: "pg-owner", Password: "!", Kind: model.KindHuman, Active: true}
	if err := db.Create(&owner).Error; err != nil {
		t.Fatal(err)
	}
	selfPolicy(t, db, policy.PolicyAgentSelfCreateEnabled, "true")
	selfPolicy(t, db, policy.PolicyAgentSelfCreateMaxPerOwner, "1")
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i, conn := range []*gorm.DB{db, other} {
		wg.Add(1)
		go func(i int, conn *gorm.DB) {
			defer wg.Done()
			<-start
			_, err := NewUserService(conn, nil).CreateMyAgent(gatewayapi.Actor{UserID: owner.ID}, CreateMyAgentRequest{Username: fmt.Sprintf("racer-%d", i), Purpose: "concurrent test"})
			errs <- err
		}(i, conn)
	}
	close(start)
	wg.Wait()
	close(errs)
	success, limited := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrAgentSelfCreateLimit) {
			limited++
		} else {
			t.Fatal(err)
		}
	}
	var n int64
	db.Model(&model.User{}).Where("owner_user_id = ?", owner.ID).Count(&n)
	if success != 1 || limited != 1 || n != 1 {
		t.Fatal(success, limited, n)
	}
}
func TestAgentSelfCreateAudit(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			users, _, db, owner, _ := principalEnv(t)
			selfPolicy(t, db, policy.PolicyAgentSelfCreateEnabled, "true")
			if fail {
				if err := db.Callback().Create().Before("gorm:create").Register("self-audit-fail", func(tx *gorm.DB) {
					if row, ok := tx.Statement.Dest.(*model.AuditLog); ok && strings.Contains(row.Details, `"self_service":true`) {
						tx.AddError(errors.New("audit unavailable"))
					}
				}); err != nil {
					t.Fatal(err)
				}
			}
			before := principalCount(t, db, &model.User{})
			logs := principalCount(t, db, &model.AuditLog{})
			user, err := users.CreateMyAgent(gatewayapi.Actor{UserID: owner.ID}, CreateMyAgentRequest{Username: "audited-self", Purpose: "scheduled report"})
			if fail {
				if err == nil || principalCount(t, db, &model.User{}) != before || principalCount(t, db, &model.AuditLog{}) != logs {
					t.Fatal("audit failure did not roll back")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var rows []model.AuditLog
			if err := db.Where("resource_id = ?", user.ID).Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range rows {
				var details map[string]any
				if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
					t.Fatal(err)
				}
				if details["self_service"] == true {
					found = true
					if details["purpose"] != "scheduled report" || details["agent_self_create_enabled"] != true || row.Username != owner.Username {
						t.Fatal(details)
					}
				}
				for _, key := range []string{"password", "token", "token_hash", "secret"} {
					if _, ok := details[key]; ok {
						t.Fatal("credential field", key)
					}
				}
			}
			if !found {
				t.Fatal("missing self audit")
			}
			adminAgent, err := users.Create(&CreateUserRequest{Username: "audited-admin", Kind: model.KindAgent, OwnerUserID: &owner.ID})
			if err != nil {
				t.Fatal(err)
			}
			rows = nil
			db.Where("resource_id = ?", adminAgent.ID).Find(&rows)
			for _, row := range rows {
				if strings.Contains(row.Details, "self_service") || strings.Contains(row.Details, "purpose") {
					t.Fatal("admin has self marker")
				}
			}
		})
	}
}
