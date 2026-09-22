package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

func TestAccessRequestItemDecisionsMigrationPostgres(t *testing.T) {
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), fmt.Sprintf("w22_items_%d", time.Now().UnixNano()))
	for _, m := range migrations {
		if m.Version == "20260921_access_request_item_decisions" {
			break
		}
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}
	queries := []string{
		`INSERT INTO users(id,username,password,active) VALUES(901,'r','!',true),(902,'a','!',true)`,
		`INSERT INTO assets(id,name,protocol,host,port,created_by) VALUES(901,'a','ssh','fixture.invalid',22,901)`,
		`INSERT INTO asset_authorizations(id,user_id,asset_id,permission,granted_by,source,accounts) VALUES(901,901,901,'connect',902,'ticket','["app"]')`,
		`INSERT INTO access_requests(id,requester_id,asset_id,reason,requested_duration_minutes,status,pending_expires_at,kind,authorization_id,revoke_note) VALUES(901,901,901,'r',60,'approved',now()+interval '1 day','normal',901,'old-note')`,
		`INSERT INTO access_request_items(id,request_id,requester_id,asset_id,status) VALUES(901,901,901,901,'approved')`,
		`INSERT INTO access_request_approvals(request_id,approver_id,note) VALUES(901,902,'legacy vote')`,
	}
	for _, q := range queries {
		if err := db.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO assets(id,name,protocol,host,port,created_by) VALUES(902,'second','ssh','fixture.invalid',22,901)`,
		`INSERT INTO asset_authorizations(id,user_id,asset_id,permission,granted_by,source,accounts,date_start,date_expired) VALUES(902,901,902,'connect',901,'ticket','["app"]','2026-09-21T00:00:00Z','2026-09-21T01:00:00Z')`,
		`INSERT INTO access_request_items(id,request_id,requester_id,asset_id,status,approved_date_start,approved_duration_minutes) VALUES(903,901,901,902,'approved','2026-09-21T00:00:00Z',60)`,
	} {
		if err := db.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := applyAccessRequestItemDecisions(db); err != nil {
		t.Fatal(err)
	}
	var ok bool
	if err := db.Raw(`SELECT i.authorization_id=901 AND i.revoke_note='old-note' AND a.item_id=i.id FROM access_request_items i JOIN access_request_approvals a ON a.request_id=i.request_id WHERE i.id=901`).Scan(&ok).Error; err != nil || !ok {
		t.Fatal("link backfill", ok, err)
	}
	if err := db.Raw(`SELECT authorization_id=902 FROM access_request_items WHERE id=903`).Scan(&ok).Error; err != nil || !ok {
		t.Fatal("later automatic item ticket missing", ok, err)
	}
	if err := db.Exec(`INSERT INTO access_request_items(id,request_id,requester_id,asset_id,status) VALUES(902,901,901,901,'rejected')`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO access_request_approvals(request_id,approver_id,item_id) VALUES(901,902,902)`).Error; err != nil {
		t.Fatal("different item vote rejected", err)
	}
	if err := db.Exec(`INSERT INTO access_request_approvals(request_id,approver_id,item_id) VALUES(901,902,902)`).Error; err == nil {
		t.Fatal("duplicate item vote accepted")
	}
	t.Log("legacy ticket/revoke note/vote linked; one actor may vote once per item; repeat vote denied")
}
