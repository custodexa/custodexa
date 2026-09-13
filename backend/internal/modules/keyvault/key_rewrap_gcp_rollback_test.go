package keyvault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func gcpRollbackDB(t *testing.T, dialect string) *gorm.DB {
	t.Helper()
	var db *gorm.DB
	if dialect == "sqlite" {
		db = newKeyManagerDB(t)
	} else {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		var err error
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatal("PostgreSQL fixture connection failed")
		}
		sqlDB, err := db.DB()
		if err != nil {
			t.Fatal(err)
		}
		sqlDB.SetMaxOpenConns(1)
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			t.Fatal(err)
		}
		schema := "gcp_rewrap_" + hex.EncodeToString(suffix[:])
		if err := db.Exec("CREATE SCHEMA " + schema).Error; err != nil {
			t.Fatal("cannot create isolated PostgreSQL schema")
		}
		t.Cleanup(func() {
			if err := db.Exec("DROP SCHEMA " + schema + " CASCADE").Error; err != nil {
				t.Error("cannot remove owned PostgreSQL schema")
			}
			_ = sqlDB.Close()
		})
		if err := db.Exec("SET search_path TO " + schema).Error; err != nil {
			t.Fatal("cannot select isolated schema")
		}
		if err := db.AutoMigrate(&model.DataKey{}); err != nil {
			t.Fatal("cannot migrate isolated fixture")
		}
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if dialect == "sqlite" {
		t.Cleanup(func() { _ = sqlDB.Close() })
		if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, statement := range []string{"CREATE TABLE gcp_commit_parent (id INTEGER PRIMARY KEY)", "CREATE TABLE gcp_commit_child (parent_id INTEGER REFERENCES gcp_commit_parent(id) DEFERRABLE INITIALLY DEFERRED)"} {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatal("cannot build deferred commit constraint")
		}
	}
	return db
}
func TestGCPRewrapRollback(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			if dialect == "postgres" && os.Getenv("TEST_PG_DSN") == "" {
				_ = testgate.Value(t, testgate.EnvPGDSN)
			}
			for _, failure := range []string{"first-step", "second-step", "second-row", "create", "commit", "cancel"} {
				t.Run(failure, func(t *testing.T) {
					db := gcpRollbackDB(t, dialect)
					s, target, f := gcpServiceFixture(t, db)
					before := gcpRows(t, db)
					memory := snapshotGCPMemory(s)
					pool := installGCPTxPool(t, db)
					pool.fault = failure
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					encrypts := 0
					f.hook = func(call context.Context, method string, _ []byte) error {
						if !pool.active {
							t.Fatal("KMS call outside transaction")
						}
						if dialect == "postgres" && !pool.lockSeen {
							t.Fatal("KMS call before advisory lock")
						}
						if dialect == "sqlite" && kekProcessMu.TryLock() {
							kekProcessMu.Unlock()
							t.Fatal("KMS call outside key lock")
						}
						pool.events = append(pool.events, method)
						if method == "encrypt" {
							encrypts++
						}
						if failure == "first-step" && method == "decrypt" || failure == "second-step" && method == "encrypt" || failure == "second-row" && method == "encrypt" && encrypts == 2 {
							return errGCPInjected
						}
						return call.Err()
					}
					if failure == "cancel" {
						if err := db.Callback().Create().After("gorm:create").Register("gcp_cancel_after_last_create", func(tx *gorm.DB) {
							if pool.creates == 2 {
								cancel()
							}
						}); err != nil {
							t.Fatal(err)
						}
					}
					result, err := s.RewrapKEK(ctx, gcpTarget(t, target))
					if err == nil || result != nil {
						t.Fatal("failed transaction returned success")
					}
					if !pool.rolledBack || pool.active {
						t.Fatal("transaction did not rollback")
					}
					if failure == "first-step" && encrypts != 0 {
						t.Fatal("first-step failure reached encrypt")
					}
					if failure == "commit" && (!pool.commitFailed || (!strings.Contains(strings.ToUpper(err.Error()), "FOREIGN KEY") && !strings.Contains(err.Error(), "23503"))) {
						t.Fatal("COMMIT did not fail on a real deferred constraint")
					}
					expectedCreates := map[string]int{"first-step": 0, "second-step": 0, "second-row": 1, "create": 2, "commit": 2, "cancel": 2}[failure]
					if pool.creates != expectedCreates {
						t.Fatal("fault was not reached after the expected partial progress")
					}
					assertGCPRollback(t, s, before, memory)
					t.Log("real database rollback: zero added pending, live rows unchanged, memory unchanged, no success response")
				})
			}
		})
	}
}
