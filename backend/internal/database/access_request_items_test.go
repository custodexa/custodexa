package database

import (
	"fmt"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
	"strings"
	"testing"
	"time"
)

func TestAccessRequestItemsMigrationPostgres(t *testing.T) {
	for _, failCount := range []bool{false, true} {
		t.Run(fmt.Sprintf("count_fault_%v", failCount), func(t *testing.T) {
			db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), fmt.Sprintf("w21_items_%d", time.Now().UnixNano()))
			for _, m := range migrations {
				if m.Version == "20260921_access_request_items" {
					break
				}
				if err := m.Up(db); err != nil {
					t.Fatal(err)
				}
			}
			for _, q := range []string{
				`INSERT INTO users(id,username,password,active) VALUES(991,'fixture-requester','!',true),(992,'fixture-decider','!',true)`,
				`INSERT INTO assets(id,name,protocol,host,port,created_by) VALUES(991,'fixture-asset','ssh','fixture.invalid',22,991)`,
				`INSERT INTO access_requests(id,requester_id,asset_id,reason,requested_duration_minutes,status,pending_expires_at,kind,accounts,approved_duration_minutes,approved_date_start,approver_id,decided_at,revoked_at,revoked_by) VALUES
   (991,991,991,'pending',60,'pending',now()+interval '1 day','normal','["app"]',NULL,NULL,NULL,NULL,NULL,NULL),
   (992,991,991,'approved',90,'approved',now()+interval '1 day','normal','["app","ops"]',45,'2026-09-20T00:00:00Z',992,'2026-09-19T00:00:00Z',NULL,NULL),
   (993,991,991,'revoked',60,'approved',now()+interval '1 day','normal','["@ALL"]',30,'2026-09-18T00:00:00Z',992,'2026-09-17T00:00:00Z','2026-09-19T00:00:00Z',992)`,
			} {
				if err := db.Exec(q).Error; err != nil {
					t.Fatal(err)
				}
			}
			if failCount {
				if err := db.Callback().Raw().After("gorm:raw").Register("w21_count_fault", func(tx *gorm.DB) {
					if strings.Contains(tx.Statement.SQL.String(), "INSERT INTO access_request_items") {
						tx.RowsAffected = 0
					}
				}); err != nil {
					t.Fatal(err)
				}
			}
			err := applyAccessRequestItems(db)
			if failCount {
				if err == nil || !strings.Contains(err.Error(), "backfill mismatch") {
					t.Fatal("count discrepancy accepted", err)
				}
				if db.Migrator().HasTable("access_request_items") {
					t.Fatal("partial migration retained")
				}
				t.Log("count mismatch rejected; whole migration rolled back")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var differences int64
			err = db.Raw(`SELECT count(*) FROM ((SELECT request_id,requester_id,asset_id,accounts,status,approved_duration_minutes,approved_date_start,decided_by,decided_at,revoked_at,revoked_by FROM access_request_items)
  EXCEPT (SELECT id,requester_id,asset_id,accounts,CASE WHEN revoked_at IS NOT NULL THEN 'revoked' ELSE status END,approved_duration_minutes,approved_date_start,approver_id,decided_at,revoked_at,revoked_by FROM access_requests)) d`).Scan(&differences).Error
			if err != nil || differences != 0 {
				t.Fatal("backfill field drift", differences, err)
			}
			var rows int64
			db.Table("access_request_items").Count(&rows)
			if rows != 3 {
				t.Fatal(rows)
			}
			err = db.Exec(`INSERT INTO access_request_items(request_id,requester_id,asset_id,status) VALUES(992,991,991,'pending')`).Error
			if err == nil || !strings.Contains(err.Error(), "23505") {
				t.Fatal("pending duplicate accepted", err)
			}
			if rollbackAccessRequestItems(db) == nil {
				t.Fatal("destructive rollback offered")
			}
			db.Table("access_request_items").Count(&rows)
			if rows != 3 {
				t.Fatal("rollback removed evidence")
			}
			t.Log("3 legacy rows → 3 items; all scope/decision/revocation columns preserved; duplicate pending SQLSTATE 23505; Down retains data")
		})
	}
}
