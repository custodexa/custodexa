package audit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func projectionDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	if err := db.AutoMigrate(&model.User{}, &model.AgentToken{}); err != nil {
		t.Fatal(err)
	}
	audit.SetPrincipalSource(identity.SnapshotPrincipalStates)
	audit.SetAgentTokenSource(identity.SnapshotAgentTokenStates)
	t.Cleanup(func() {
		audit.SetPrincipalSource(func(context.Context, *gorm.DB) ([]audit.PrincipalState, error) { return nil, nil })
		audit.SetAgentTokenSource(func(context.Context, *gorm.DB) ([]audit.AgentTokenState, error) { return nil, nil })
	})
	return db
}
func TestPrincipalSnapshotStability(t *testing.T) {
	for _, column := range []string{"last_login_at", "full_name", "password"} {
		t.Run(column, func(t *testing.T) {
			db := projectionDB(t)
			u := model.User{Username: "private-principal-name", Email: projectionString("private@example.test"), Password: "private-password", Active: true}
			if err := db.Create(&u).Error; err != nil {
				t.Fatal(err)
			}
			before, err := audit.SnapshotPrincipals(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			value := any("changed")
			if column == "last_login_at" {
				value = time.Now()
			}
			if err := db.Model(&u).Update(column, value).Error; err != nil {
				t.Fatal(err)
			}
			after, err := audit.SnapshotPrincipals(context.Background(), db)
			if err != nil || before.Hash != after.Hash {
				t.Fatal("irrelevant change altered projection", err)
			}
			for _, secret := range []string{u.Username, *u.Email, u.Password} {
				if strings.Contains(string(before.Body), secret) {
					t.Fatal("private text in snapshot")
				}
			}
			if err := db.Delete(&u).Error; err != nil {
				t.Fatal(err)
			}
			deleted, err := audit.SnapshotPrincipals(context.Background(), db)
			if err != nil || deleted.Count != 0 {
				t.Fatal("soft-deleted principal included", err)
			}
		})
	}
}
func projectionString(s string) *string { return &s }
func TestSnapshotAgentTokenStorageChanges(t *testing.T) {
	for _, column := range []string{"last_used_at", "token_hash", "expires_at"} {
		t.Run(column, func(t *testing.T) {
			db := projectionDB(t)
			row := model.AgentToken{UserID: 1, Name: "private-token-name", TokenHash: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour), RevokeNote: "private-revoke-note", SuspendedReason: "private-reason"}
			if err := db.Create(&row).Error; err != nil {
				t.Fatal(err)
			}
			before, err := audit.SnapshotAgentTokens(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			var value any = time.Now().Add(2 * time.Hour)
			if column == "token_hash" {
				value = strings.Repeat("b", 64)
			}
			if err := db.Model(&row).Update(column, value).Error; err != nil {
				t.Fatal(err)
			}
			after, err := audit.SnapshotAgentTokens(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			if (before.Hash == after.Hash) != (column == "last_used_at") {
				t.Fatal("incorrect storage change sensitivity", column)
			}
			for _, secret := range []string{"cxa_", strings.Repeat("a", 64), row.Name, row.RevokeNote, row.SuspendedReason} {
				if strings.Contains(string(before.Body), secret) {
					t.Fatal("secret in snapshot")
				}
			}
		})
	}
}
