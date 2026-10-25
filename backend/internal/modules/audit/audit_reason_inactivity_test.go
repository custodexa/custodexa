package audit_test

import (
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestInactivityDisableRecordsDays 擋：閒置停用的原因說不出「逾幾天」。
// 以真的停用流程產生審計列，再交給分類器，寫入端與分類器的鍵名不一致時即紅
func TestInactivityDisableRecordsDays(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{},
		&model.PasswordHistory{}, &model.RefreshToken{}, &model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.AuditLog{}, &model.UserRole{}); err != nil {
		t.Fatal(err)
	}
	seedAuthzState(t, db)
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policies := policy.NewSecurityPolicyService(db)
	if _, err := policies.Update(policy.PolicyInactiveDisableDays, "90", "admin"); err != nil {
		t.Fatal(err)
	}
	users := identity.NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.SetSecurityPolicies(policies)
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	svc := identity.NewInactivityService(db, policies, users, auditSvc)

	stale := time.Now().AddDate(0, 0, -120)
	email := "stale@x"
	u := &model.User{Username: "stale", Email: &email, Password: "x", Active: true, LastLoginAt: &stale}
	if err := db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	// 另放一位 active admin，避免停用撞上最後一位管理員的守衛
	adminEmail := "keeper@x"
	recent := time.Now()
	keeper := &model.User{Username: "keeper", Email: &adminEmail, Password: "x", Active: true, LastLoginAt: &recent}
	if err := db.Create(keeper).Error; err != nil {
		t.Fatal(err)
	}

	n, err := svc.DisableInactive()
	if err != nil || n != 1 {
		t.Fatalf("DisableInactive = %d, %v; want 1", n, err)
	}
	var row model.AuditLog
	if err := db.Where("error_msg = ? AND user_id = ?", "auto_disabled_inactive_account", u.ID).First(&row).Error; err != nil {
		t.Fatalf("找不到閒置停用列: %v", err)
	}
	if row.Details != `{"inactive_days":90}` {
		t.Errorf("Details = %q, want {\"inactive_days\":90}", row.Details)
	}
	code, params := audit.ClassifyAuditReason(audit.AuditReasonInput{Action: string(row.Action), Resource: string(row.Resource),
		Status: string(row.Status), ErrorMsg: row.ErrorMsg, Details: row.Details, Path: row.Path})
	if code != "auto_disabled_inactive_account" || params["days"] != "90" {
		t.Errorf("新列分類 = %q %#v, want auto_disabled_inactive_account days=90", code, params)
	}
	// 升級前的舊列沒有 Details：改用不帶天數的句型
	code, params = audit.ClassifyAuditReason(audit.AuditReasonInput{Action: string(row.Action), Resource: string(row.Resource),
		Status: string(row.Status), ErrorMsg: row.ErrorMsg})
	if code != "auto_disabled_inactive_account_nodays" || len(params) != 0 {
		t.Errorf("舊列分類 = %q %#v, want auto_disabled_inactive_account_nodays", code, params)
	}
}
