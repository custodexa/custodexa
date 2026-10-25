package database

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// TestPermissionMigrationReentry 擋：升級後權限資料被改動、重跑 migration 或還原完成後再遷移
// 讓內容漂移、零本地超管或懸空列被悄悄修補而放行。
//
// 本 change 不為存量憑證設歸屬（那是後續階段的事；此樹的憑證表沒有歸屬欄），所以
// 「既有憑證歸屬不重設」以憑證表內容不變來表達，不另造欄位。
// 放行與否由還原完整性關卡（authz.CheckRestoreIntegrity）決定；這裡只證明遷移報告如實呈現
// 零本地超管與懸空列、重跑不修補它們。

const reentryTables = "roles,user_roles,users,authz_state"

func reentrySnapshot(t *testing.T, db *gorm.DB) string {
	t.Helper()
	return dumpTables(t, db, strings.Split(reentryTables, ",")...)
}

// pairs 以「使用者名稱/角色名稱/來源」描述全部指派（含已刪除角色與懸空列的原始 role_id）。
func rolePairs(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var rows []struct {
		Username string
		Role     string
		Source   string
	}
	if err := db.Raw(`SELECT u.username AS username, COALESCE(r.name, 'role#' || ur.role_id) AS role, ur.source AS source
 FROM user_roles ur JOIN users u ON u.id = ur.user_id LEFT JOIN roles r ON r.id = ur.role_id
 ORDER BY u.username, role, ur.source`).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.Username+"/"+r.Role+"/"+r.Source)
	}
	return out
}

// simulateRestoreDone 把一次完成的還原留在 authz_state（世代、操作 ID、輸入摘要、完成狀態）。
func simulateRestoreDone(t *testing.T, db *gorm.DB) {
	t.Helper()
	gen := strings.Repeat("ab", 32)
	if err := db.Exec(`UPDATE authz_state SET restore_generation = ?, restore_op_id = ?, restore_input_digest = ?,
 restore_status = 'done', restored_at = ?, version = version + 1 WHERE id = 1`,
		gen, "op-reentry", strings.Repeat("cd", 32), time.Now().UTC()).Error; err != nil {
		t.Fatalf("模擬完成的還原: %v", err)
	}
}

func TestPermissionMigrationReentry(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		t.Run("1.17 升級後角色與來源保留，純 approver 與零角色不補權", func(t *testing.T) {
			db := newAuthzSQLite(t)
			seed117(t, db, true)
			zero := model.User{Username: "zero-role", Password: "hash", Active: true, ProvisioningOrigin: model.AuthSourceLocal}
			if err := db.Create(&zero).Error; err != nil {
				t.Fatal(err)
			}
			before := rolePairs(t, db)
			if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
				t.Fatalf("資料步驟: %v", err)
			}
			after := rolePairs(t, db)
			if fmt.Sprint(before) != fmt.Sprint(after) {
				t.Fatalf("角色與來源在升級前後不同:\nbefore=%v\nafter=%v", before, after)
			}
			var apv, zeroN int64
			db.Raw(`SELECT COUNT(*) FROM user_roles ur JOIN users u ON u.id = ur.user_id WHERE u.username = 'apv'`).Scan(&apv)
			db.Raw(`SELECT COUNT(*) FROM user_roles WHERE user_id = ?`, zero.ID).Scan(&zeroN)
			if apv != 1 {
				t.Errorf("純 approver 的指派 %d 筆, want 1（不得補任何權）", apv)
			}
			if zeroN != 0 {
				t.Errorf("零角色使用者被補了 %d 筆指派", zeroN)
			}
			var nonGlobal int64
			db.Model(&model.UserRole{}).Where("scope_kind <> ?", "global").Count(&nonGlobal)
			if nonGlobal != 0 {
				t.Errorf("存量指派有 %d 列非 global", nonGlobal)
			}
		})

		t.Run("資料步驟重跑、還原完成後再重跑，內容世代報告皆不變", func(t *testing.T) {
			db := newAuthzSQLite(t)
			seed117(t, db, true)
			if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
				t.Fatal(err)
			}
			if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
				t.Fatalf("第二次: %v", err)
			}
			second := reentrySnapshot(t, db)
			repBefore, err := ReadAuthzMigrationReport(db)
			if err != nil {
				t.Fatal(err)
			}
			jsBefore, _ := repBefore.comparable()

			simulateRestoreDone(t, db)
			restored := reentrySnapshot(t, db)
			if restored == second {
				t.Fatal("模擬的還原沒有留下世代，測試前提不成立")
			}
			if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
				t.Fatalf("還原完成後再遷移: %v", err)
			}
			if again := reentrySnapshot(t, db); again != restored {
				t.Errorf("還原完成後重跑改變了狀態:\nbefore=%s\nafter=%s", restored, again)
			}
			var st model.AuthzState
			if err := db.First(&st).Error; err != nil {
				t.Fatal(err)
			}
			if st.RestoreGeneration != strings.Repeat("ab", 32) || st.RestoreOpID != "op-reentry" || st.RestoreStatus != "done" {
				t.Errorf("還原世代被重跑改動: %+v", st)
			}
			repAfter, err := ReadAuthzMigrationReport(db)
			if err != nil {
				t.Fatal(err)
			}
			if jsAfter, _ := repAfter.comparable(); jsAfter != jsBefore {
				t.Errorf("遷移報告在還原完成後的重跑中改變:\n%s\n%s", jsBefore, jsAfter)
			}
		})

		t.Run("零本地超管與懸空列重跑後仍如實呈現，不被修補", func(t *testing.T) {
			db := newAuthzSQLite(t)
			seed117(t, db, true)
			// 把兩位本地超管都停用：此後的資料沒有可用的本地超管
			if err := db.Exec(`UPDATE users SET active = ? WHERE username IN ('root', 'root2')`, false).Error; err != nil {
				t.Fatal(err)
			}
			pairsBefore := rolePairs(t, db)
			for i := 0; i < 2; i++ {
				if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
					t.Fatalf("第 %d 次: %v", i+1, err)
				}
			}
			rep, err := ReadAuthzMigrationReport(db)
			if err != nil {
				t.Fatal(err)
			}
			if rep.LocalSuperAdmins != 0 {
				t.Errorf("本地超管數 %d, want 0（不得因重跑而憑空出現）", rep.LocalSuperAdmins)
			}
			if rep.DanglingAssignments != 2 {
				t.Errorf("懸空指派 %d, want 2（不得被刪除或補齊）", rep.DanglingAssignments)
			}
			if pairsAfter := rolePairs(t, db); fmt.Sprint(pairsAfter) != fmt.Sprint(pairsBefore) {
				t.Errorf("重跑改動了指派:\nbefore=%v\nafter=%v", pairsBefore, pairsAfter)
			}
			var active int64
			db.Raw(`SELECT COUNT(*) FROM users WHERE username IN ('root', 'root2') AND active = ?`, true).Scan(&active)
			if active != 0 {
				t.Errorf("遷移把停用的超管重新啟用 %d 位", active)
			}
		})
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		_ = dsn

		t.Run("升級後 RunMigrations 與還原完成後的再遷移內容相同", func(t *testing.T) {
			db := newAuthzPrePG(t, fmt.Sprintf("perm_reentry_%d", time.Now().UnixNano()))
			withGlobalDB(t, db)
			seed117(t, db, false)
			pairsBefore := rolePairs(t, db)
			if err := RunMigrations(); err != nil {
				t.Fatalf("RunMigrations: %v", err)
			}
			if pairsAfter := rolePairs(t, db); fmt.Sprint(pairsAfter) != fmt.Sprint(pairsBefore) {
				t.Fatalf("升級改動了角色與來源:\nbefore=%v\nafter=%v", pairsBefore, pairsAfter)
			}
			tables := []string{"roles", "user_roles", "users", "authz_state", "schema_migrations", "permission_state_events", "credentials"}
			first := dumpTables(t, db, tables...)
			if err := RunMigrations(); err != nil {
				t.Fatalf("第二次 RunMigrations: %v", err)
			}
			if second := dumpTables(t, db, tables...); second != first {
				t.Fatalf("第二次 RunMigrations 改變了內容:\n%s\n%s", first, second)
			}
			repBefore, err := ReadAuthzMigrationReport(db)
			if err != nil {
				t.Fatal(err)
			}
			jsBefore, _ := repBefore.comparable()

			simulateRestoreDone(t, db)
			restored := dumpTables(t, db, tables...)
			if err := RunMigrations(); err != nil {
				t.Fatalf("還原完成後再遷移: %v", err)
			}
			if again := dumpTables(t, db, tables...); again != restored {
				t.Errorf("還原完成後再遷移改變了內容（角色、來源、世代、遷移版本或憑證）:\n%s\n%s", restored, again)
			}
			repAfter, err := ReadAuthzMigrationReport(db)
			if err != nil {
				t.Fatal(err)
			}
			if jsAfter, _ := repAfter.comparable(); jsAfter != jsBefore {
				t.Errorf("遷移報告改變:\n%s\n%s", jsBefore, jsAfter)
			}
		})
	})

	// 同一個 DB 上把整條升級鏈（正式遷移＋啟動時的保留下限對帳）連跑兩次：後段 migration 或對帳
	// 重跑時不得改到前段寫下的任何資料。只在 PostgreSQL 上跑——版本化 migration 只支援 PostgreSQL。
	t.Run("p2_chain_rerun", func(t *testing.T) {
		_ = testgate.Value(t, testgate.EnvPGDSN)
		db := newAuthzPrePG(t, fmt.Sprintf("perm_chain_%d", time.Now().UnixNano()))
		withGlobalDB(t, db)
		seed117(t, db, false)
		// 升級前低於下限的保留值，讓對帳在第一次就留下抬升紀錄
		for k, v := range map[string]string{
			policy.PolicyRetentionAuditLogDays: "3", policy.PolicyRetentionSessionCommandDays: "6",
			policy.PolicyRetentionAlertDays: "5", policy.PolicyRetentionRecordingDays: "6",
			policy.PolicyRetentionCheckpointDays: "6",
		} {
			if err := db.Save(&model.SecurityPolicy{Key: k, Value: v, UpdatedBy: "legacy"}).Error; err != nil {
				t.Fatal(err)
			}
		}

		// 對帳本體用正式函式；審計落地面以直寫 audit_logs 的實作代替組裝根的那一個
		sink := reentryAuditSink{}
		auditor := func(tx *gorm.DB, r policy.FloorRaise) error {
			return port.WriteInTx(sink, tx, port.AuditEvent{
				Actor:    gatewayapi.Actor{UserID: 0, Username: "system"},
				Action:   string(model.ActionRetentionFloorRaised),
				Resource: string(model.ResourceSecurityPolicy),
				Status:   string(model.StatusSuccess),
				Details:  fmt.Sprintf(`{"key":%q,"old_value":%d,"new_value":%d}`, r.Key, r.OldValue, r.NewValue),
			})
		}
		chain := func(round int) {
			t.Helper()
			if err := RunMigrations(); err != nil {
				t.Fatalf("第 %d 次 RunMigrations: %v", round, err)
			}
			if _, err := policy.NewSecurityPolicyService(db).ReconcileRetentionFloor(auditor, "chain-test"); err != nil {
				t.Fatalf("第 %d 次保留下限對帳: %v", round, err)
			}
		}

		// 觀測集合：各段新增或加欄的表、權限版本與事件、系統告警與投遞佇列、審計、
		// 對帳標記、migration marker，以及升級前的存量表
		tables := []string{
			"roles", "user_roles", "users", "authz_state", "role_binding_nodes", "user_group_roles",
			"permission_state_events", "agent_tokens", "asset_authorizations", "audit_checkpoints",
			"audit_checkpoint_trims", "refresh_tokens", "role_permissions",
			"command_alerts", "system_alert_details", "system_alert_outbox", "system_alert_severity_overrides",
			"asset_host_keys", "asset_host_key_mismatches", "user_channel_observations",
			"change_secret_plans", "change_secret_batches", "change_secret_candidates",
			"credential_rotations", "credential_rotation_members", "credential_job_authorizations",
			"credential_host_identity_confirmations", "user_release_guidance", "credential_impact_confirmations",
			"security_policies", "security_policy_floor_raises", "audit_logs",
			"schema_migrations", "credentials",
		}
		chain(1)
		var raises int64
		db.Table("security_policy_floor_raises").Count(&raises)
		if raises == 0 {
			t.Fatal("第一次對帳沒有留下抬升紀錄，測試前提不成立")
		}
		first := dumpTables(t, db, tables...)
		chain(2)
		if second := dumpTables(t, db, tables...); second != first {
			t.Fatalf("同一 DB 第二次跑升級鏈改變了內容:\n%s\n%s", first, second)
		}
	})
}

// reentryAuditSink 交易內審計落地面的測試實作：直接寫 audit_logs。
type reentryAuditSink struct{}

func (reentryAuditSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	return tx.Create(&model.AuditLog{
		UserID: ev.Actor.UserID, Username: ev.Actor.Username,
		Action: model.AuditAction(ev.Action), Resource: model.AuditResource(ev.Resource),
		Status: model.AuditStatus(ev.Status), Details: ev.Details,
	}).Error
}
