package identity

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 每日簽核的高危計數不含例行系統記帳：保留期限清除、外部登入時沒有角色增減的映射
// 重算。角色真的增減、管理員刪規則引發的撤權、閒置停用、管理員改帳號照計。
//
// 角色映射的兩列由真登入流程產生（不手寫 JSON）：寫入端改了細節欄的鍵名，
// 有增減的那一列就會被誤排除，本測試即紅。其餘列以直寫 SQL 植入，等同升級前
// 已在庫裡的舊列——排除條件只看既有欄位，舊列與新列同一口徑。

const routineOuterGroup = "cn=outer,ou=groups,dc=example,dc=org"

// generatedMappingRows 以真登入流程產生兩筆「角色映射已套用」：第一次登入取得角色
// （roles_added 非空），第二次多一條規則支撐同一個角色（只有映射依據變動）
func generatedMappingRows(t *testing.T) (changed, basisOnly model.AuditLog) {
	t.Helper()
	authService, _, db := setupRoleMappingEnv(t)
	roleMappingUser(t, db, "testldap")
	roleMappingRule(t, db, 1, roleMappingInnerGroup, model.RoleAuditor)
	authService.SetLDAPResolver(mappingResolver(1, "memberOf", ldapInfoWithGroups("testldap", roleMappingInnerGroup)))
	if _, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"}); err != nil {
		t.Fatalf("第一次登入: %v", err)
	}
	roleMappingRule(t, db, 1, routineOuterGroup, model.RoleAuditor)
	authService.SetLDAPResolver(mappingResolver(1, "memberOf",
		ldapInfoWithGroups("testldap", roleMappingInnerGroup, routineOuterGroup)))
	if _, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"}); err != nil {
		t.Fatalf("第二次登入: %v", err)
	}
	rows := roleMappingAuditRows(t, db, RoleMappingEventApplied)
	if len(rows) != 2 {
		t.Fatalf("角色映射已套用 %d 筆, want 2（前提不成立）", len(rows))
	}
	var first, second struct {
		Added    []string `json:"roles_added"`
		Supports bool     `json:"supports_changed"`
	}
	_ = json.Unmarshal([]byte(rows[0].Details), &first)
	_ = json.Unmarshal([]byte(rows[1].Details), &second)
	if len(first.Added) == 0 || len(second.Added) != 0 || !second.Supports {
		t.Fatalf("前提不成立：第一筆應有角色增加、第二筆只有依據變動（%s／%s）", rows[0].Details, rows[1].Details)
	}
	return rows[0], rows[1]
}

// routineTargetDB 每日簽核需要的表（sqlite 或 PostgreSQL 的隔離 schema）
func routineTargetDB(t *testing.T, kind string) *gorm.DB {
	t.Helper()
	cfg := &gorm.Config{Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true}
	var db *gorm.DB
	var err error
	if kind == "postgres" {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		schema := fmt.Sprintf("daily_review_routine_%d", time.Now().UnixNano())
		admin, err := gorm.Open(postgres.Open(dsn), cfg)
		if err != nil {
			t.Fatalf("postgres 連線失敗: %v", err)
		}
		if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
			if s, err := admin.DB(); err == nil {
				_ = s.Close()
			}
		})
		if db, err = gorm.Open(postgres.Open(dsn+" search_path="+schema), cfg); err != nil {
			t.Fatal(err)
		}
	} else if db, err = gorm.Open(sqlite.Open(":memory:"), cfg); err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{}, &model.SecurityPolicyHistory{},
		&model.DailyReviewLog{}, &model.AuditRetentionWatermark{}); err != nil {
		t.Fatal(err)
	}
	// sqlite 驅動讀不回生產的 timestamptz 欄，告警表手建等價表（同 audit 模組的每日簽核測試）
	if kind == "postgres" {
		if err := db.AutoMigrate(&model.CommandAlert{}); err != nil {
			t.Fatal(err)
		}
	} else if err := db.Exec(`CREATE TABLE command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL DEFAULT 'r',
		session_id INTEGER NOT NULL DEFAULT 0, user_id INTEGER NOT NULL DEFAULT 3, asset_id INTEGER,
		command TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'high', triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error; err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, h := range []model.SecurityPolicyHistory{
		{PolicyKey: policy.PolicyDailyReviewTimezone, NewValue: "UTC", ChangedAt: since.Add(-time.Hour), ChangedBy: "admin", Source: model.PolicyHistorySourceMigrationUpgrade},
		{PolicyKey: policy.PolicyDailyReviewEnabled, OldValue: "false", NewValue: "true", ChangedAt: since, ChangedBy: "admin", Source: model.PolicyHistorySourcePolicyUpdate},
	} {
		h := h
		if err := db.Create(&h).Error; err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range map[string]string{policy.PolicyDailyReviewTimezone: "UTC", policy.PolicyDailyReviewEnabled: "true"} {
		if err := db.Create(&model.SecurityPolicy{Key: k, Value: v, UpdatedBy: "admin", UpdatedAt: since}).Error; err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// insertRow 以直寫 SQL 植入一列（不經任何寫入端，形同既有的舊列）；回傳編號
func insertRow(t *testing.T, db *gorm.DB, at time.Time, r model.AuditLog) uint {
	t.Helper()
	if err := db.Exec(`INSERT INTO audit_logs (created_at, action, resource, resource_id, status, user_id, username,
		path, client_ip, status_code, error_msg, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		at.UTC(), r.Action, r.Resource, r.ResourceID, r.Status, r.UserID, r.Username,
		r.Path, r.ClientIP, r.StatusCode, r.ErrorMsg, r.Details).Error; err != nil {
		t.Fatalf("植入審計列: %v", err)
	}
	var id uint
	if err := db.Raw("SELECT MAX(id) FROM audit_logs").Scan(&id).Error; err != nil {
		t.Fatal(err)
	}
	return id
}

func countOf(p *int64) int64 {
	if p == nil {
		return -1
	}
	return *p
}

// TestDailyReviewHighRiskExcludesRoutineSystemRows 擋：例行系統記帳灌大高危數
func TestDailyReviewHighRiskExcludesRoutineSystemRows(t *testing.T) {
	changed, basisOnly := generatedMappingRows(t)
	for _, kind := range []string{"sqlite", "postgres"} {
		t.Run(kind, func(t *testing.T) {
			db := routineTargetDB(t, kind)
			base := time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC)
			n := 0
			put := func(r model.AuditLog) uint {
				n++
				return insertRow(t, db, base.Add(time.Duration(n)*time.Minute), r)
			}
			target := uint(42)
			recompute := func(code string) model.AuditLog {
				return model.AuditLog{Action: model.ActionUpdate, Resource: model.ResourceUser, ResourceID: &target,
					Status: model.StatusSuccess, UserID: target, Username: "testldap", ClientIP: "system",
					StatusCode: 200, ErrorMsg: code, Details: `{"channel":"directory:1"}`}
			}
			copyOf := func(r model.AuditLog) model.AuditLog {
				return model.AuditLog{Action: r.Action, Resource: r.Resource, ResourceID: r.ResourceID, Status: r.Status,
					UserID: r.UserID, Username: r.Username, ClientIP: r.ClientIP, StatusCode: r.StatusCode,
					ErrorMsg: r.ErrorMsg, Details: r.Details, Path: r.Path}
			}
			// 不計入：保留清除成功與失敗、三種一律排除的重算碼、只有依據變動的重算
			put(model.AuditLog{Action: model.ActionDelete, Resource: model.ResourceRetention, Status: model.StatusSuccess,
				Username: "system", Details: `{"target":"audit_logs","days":365,"deleted":0,"partial":false}`})
			put(model.AuditLog{Action: model.ActionDelete, Resource: model.ResourceRetention, Status: model.StatusFailure,
				Username: "system", ErrorMsg: "statement timeout", Details: `{"target":"command_alerts","days":180,"deleted":3,"partial":true,"error":"statement timeout"}`})
			put(recompute(UserGroupMappingEventApplied))
			put(recompute(RoleMappingSkipSourceAttrUnset))
			put(recompute(RoleMappingSkipGroupsUnknown))
			put(copyOf(basisOnly))
			// 計入：角色實際增減、管理員刪規則引發的撤權、閒置停用、管理員帶路徑的修改
			want := map[uint]string{
				put(copyOf(changed)):                    "角色實際增減",
				put(recompute(MappingRuleRevokedEvent)): "刪規則撤權",
				put(model.AuditLog{Action: model.ActionUpdate, Resource: model.ResourceUser, ResourceID: &target,
					Status: model.StatusSuccess, UserID: target, Username: "idle", ClientIP: "system", StatusCode: 200,
					ErrorMsg: "auto_disabled_inactive_account"}): "閒置停用",
				put(model.AuditLog{Action: model.ActionUpdate, Resource: model.ResourceUser, ResourceID: &target,
					Status: model.StatusSuccess, UserID: 1, Username: "admin", Path: "/api/v1/users/42", StatusCode: 200}): "管理員修改",
			}

			svc := audit.NewDailyReviewService(db, policy.NewSecurityPolicyService(db), nil)
			svc.SetClock(func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) })
			snap, err := svc.Snapshot("2026-10-10", base.Add(-3*time.Hour), base.Add(21*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if got := countOf(snap.HighRiskOps); got != int64(len(want)) {
				t.Errorf("快照高危數 = %d, want %d", got, len(want))
			}
			detail, err := svc.Day("2026-10-10")
			if err != nil {
				t.Fatal(err)
			}
			if detail.Counts == nil || countOf(detail.Counts.HighRiskOps) != int64(len(want)) {
				t.Errorf("明細的計數不是 %d", len(want))
			}
			if detail.HighRiskOps.Total != int64(len(want)) {
				t.Errorf("明細總數 = %d, want %d", detail.HighRiskOps.Total, len(want))
			}
			for _, it := range detail.HighRiskOps.Items {
				if _, ok := want[it.ID]; !ok {
					t.Errorf("明細列出不該計入的列 %d（%s %s error_msg=%q）", it.ID, it.Action, it.Resource, it.ErrorMsg)
				}
				delete(want, it.ID)
			}
			for id, what := range want {
				t.Errorf("明細缺少 %s（列 %d）", what, id)
			}
		})
	}
}
