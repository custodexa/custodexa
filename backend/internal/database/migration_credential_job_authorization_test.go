package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

// TestCredentialJobAuthorizationMigration 憑證背景工作授權增量：
// 升級前已啟用的排程計畫回填發起者（只有完全查不到可歸屬者才暫停）、舊秘密不動、
// 資料步驟與 RunMigrations 重跑結果相同、授權表為證據不提供回滾。
func TestCredentialJobAuthorizationMigration(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, fmt.Sprintf("job_auth_%d", time.Now().UnixNano()))

	idx := -1
	for i, m := range migrations {
		if m.Version == "20261022_credential_job_authorization" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("找不到本增量")
	}
	for _, m := range migrations[:idx] {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}

	// 使用者：1 啟用一般使用者、2 已停用、3 agent。
	for _, u := range []string{
		`INSERT INTO users(id,username,password,kind,active,created_at,updated_at) VALUES(1,'alice','x','human',true,now(),now())`,
		`INSERT INTO users(id,username,password,kind,active,created_at,updated_at) VALUES(2,'bob','x','human',false,now(),now())`,
		`INSERT INTO users(id,username,password,kind,owner_user_id,active,created_at,updated_at) VALUES(3,'bot','x','agent',1,true,now(),now())`,
	} {
		if err := db.Exec(u).Error; err != nil {
			t.Fatal(err)
		}
	}
	plan := func(id int, name string, enabled bool, cron string) {
		t.Helper()
		if err := db.Exec(`INSERT INTO change_secret_plans(id,name,asset_ids,cron,enabled,created_at,updated_at) VALUES(?,?,?,?,?,now(),now())`,
			id, name, "[1]", cron, enabled).Error; err != nil {
			t.Fatal(err)
		}
	}
	auditRow := func(method, path string, resourceID any, userID int, body string) {
		t.Helper()
		if err := db.Exec(`INSERT INTO audit_logs(action,resource,resource_id,status,user_id,username,method,path,request_body,created_at,updated_at)
			VALUES('update','change_secret_plan',?,'success',?,'u',?,?,?,now(),now())`,
			resourceID, userID, method, path, body).Error; err != nil {
			t.Fatal(err)
		}
	}
	plan(1, "有修改者", true, "0 3 * * *") // 最後修改者 alice
	auditRow("PUT", "/api/v1/change-secret-plans/1", 1, 1, "{}")
	plan(2, "只有建立者", true, "0 4 * * *") // POST 以計畫名比對
	auditRow("POST", "/api/v1/change-secret-plans", nil, 1, `{"name":"只有建立者"}`)
	plan(3, "查不到", true, "0 5 * * *") // 無任何審計
	plan(4, "修改者已停用", true, "0 6 * * *")
	auditRow("PUT", "/api/v1/change-secret-plans/4", 4, 2, "{}")
	plan(5, "修改者是代理", true, "0 7 * * *")
	auditRow("PUT", "/api/v1/change-secret-plans/5", 5, 3, "{}")
	plan(6, "已停用計畫", false, "0 8 * * *")
	plan(7, "僅手動", true, "")
	before := dumpTables(t, db, "credentials", "credential_secret_versions")
	// 升級前已還原過的部署：回填列記升級當下的還原世代，既有排程不因世代為空而全部停擺
	res := db.Exec(`UPDATE authz_state SET restore_generation = 'gen-restored'`)
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	if res.RowsAffected == 0 {
		t.Fatal("authz_state 應已有一列")
	}

	if err := migrations[idx].Up(db); err != nil {
		t.Fatal(err)
	}

	type planState struct {
		AuthorizationID    *uint
		AuthorizationState string
		Cron               string
		Enabled            bool
		Revision           int
	}
	state := func(id int) planState {
		t.Helper()
		var s planState
		if err := db.Raw(`SELECT authorization_id, authorization_state, cron, enabled, revision FROM change_secret_plans WHERE id = ?`, id).Scan(&s).Error; err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, id := range []int{1, 2} {
		s := state(id)
		if s.AuthorizationID == nil || s.AuthorizationState != "" {
			t.Fatalf("計畫 %d 應回填發起者: %+v", id, s)
		}
		var actor struct {
			ActorID    uint
			AuthSource string
			SourceKind string
		}
		if err := db.Raw(`SELECT actor_id, auth_source, source_kind FROM credential_job_authorizations WHERE id = ?`, *s.AuthorizationID).Scan(&actor).Error; err != nil {
			t.Fatal(err)
		}
		if actor.ActorID != 1 || actor.AuthSource != "audit_backfill" || actor.SourceKind != "plan" {
			t.Fatalf("計畫 %d 回填內容不符: %+v", id, actor)
		}
		var gen string
		if err := db.Raw(`SELECT restore_generation FROM credential_job_authorizations WHERE id = ?`, *s.AuthorizationID).Scan(&gen).Error; err != nil {
			t.Fatal(err)
		}
		if gen != "gen-restored" {
			t.Fatalf("計畫 %d 回填列應記升級當下的還原世代，實得 %q", id, gen)
		}
	}
	for _, id := range []int{3, 4, 5} {
		s := state(id)
		if s.AuthorizationID != nil || s.AuthorizationState != "needs_reauthorization" {
			t.Fatalf("計畫 %d 查不到可歸屬者應暫停: %+v", id, s)
		}
		if !s.Enabled || s.Cron == "" {
			t.Fatalf("計畫 %d 暫停不得改動 cron 與 enabled: %+v", id, s)
		}
	}
	for _, id := range []int{6, 7} {
		if s := state(id); s.AuthorizationID != nil || s.AuthorizationState != "" {
			t.Fatalf("計畫 %d 未啟用排程，不應被處理: %+v", id, s)
		}
	}
	if after := dumpTables(t, db, "credentials", "credential_secret_versions"); after != before {
		t.Fatal("升級改動了候選或憑證秘密")
	}

	// 資料步驟重跑結果相同。
	first := dumpTables(t, db, "change_secret_plans", "credential_job_authorizations")
	if err := BackfillPlanInitiators(db); err != nil {
		t.Fatal(err)
	}
	if second := dumpTables(t, db, "change_secret_plans", "credential_job_authorizations"); second != first {
		t.Fatal("資料步驟重跑改動了內容")
	}

	// 授權表來源種類值域；證據不提供回滾。
	if db.Exec(`INSERT INTO credential_job_authorizations(source_kind,source_id,actor_id,auth_source,confirmed_at) VALUES('other',1,1,'request',now())`).Error == nil {
		t.Fatal("來源種類值域外被接受")
	}
	if err := rollbackCredentialJobAuthorization(db); err == nil {
		t.Fatal("授權脈絡屬證據，不應提供回滾")
	}

	// RunMigrations 第二次不改內容。
	run := freshSchema(t, dsn, fmt.Sprintf("job_auth_run_%d", time.Now().UnixNano()))
	prev := DB
	DB = run
	t.Cleanup(func() { DB = prev })
	if err := RunMigrations(); err != nil {
		t.Fatalf("第一次 RunMigrations: %v", err)
	}
	tables := []string{"schema_migrations", "change_secret_plans", "credential_job_authorizations"}
	a := dumpTables(t, run, tables...)
	if err := RunMigrations(); err != nil {
		t.Fatalf("第二次 RunMigrations: %v", err)
	}
	if b := dumpTables(t, run, tables...); b != a {
		t.Fatal("第二次 RunMigrations 改動了內容")
	}
}
