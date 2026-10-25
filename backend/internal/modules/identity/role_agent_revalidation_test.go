package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 角色內容修改與 agent 持有者的重驗：修改前拒絕（拒絕明細隨錯誤回傳）、提交後兩側偵測與告警、指派入口不誤報。
// 夾具依 TEST_PG_DSN 選方言；非空時整組跑在 PostgreSQL 的獨立 schema。

// detectedAlertFailSink 只讓提交後偵測（以使用者為目標、路徑為偵測值）的告警寫入失敗。
type detectedAlertFailSink struct{ inner port.SystemAlertSink }

func (s detectedAlertFailSink) RaiseInTx(tx *gorm.DB, ev port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	if p := ev.Params["path"]; ev.Target.Kind == port.SystemAlertTargetUser &&
		(p == agentRevalidationDetectedPathRole || p == agentRevalidationDetectedPathAssign) {
		return port.SystemAlertReceipt{}, errors.New("injected alert failure")
	}
	return s.inner.RaiseInTx(tx, ev)
}

type revalEnv struct {
	*roleDefEnv
	grader *GrantGrader
	users  *UserService
	groups *UserGroupService
	pgDSN  string // PostgreSQL 時的連線字串（含 search_path），供第二條連線
}

// revalDB 依 TEST_PG_DSN 選方言；PostgreSQL 時回傳含獨立 schema 的連線字串。
func revalDB(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	dsn := os.Getenv("TEST_PG_DSN")
	if dsn == "" {
		return nil, ""
	}
	schema := fmt.Sprintf("rar_%d", time.Now().UnixNano())
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if sd, e := admin.DB(); e == nil {
			_ = sd.Close()
		}
	})
	full := dsn + " search_path=" + schema
	db, err := gorm.Open(postgres.Open(full), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sd, e := db.DB(); e == nil {
			_ = sd.Close()
		}
	})
	require.Equal(t, "postgres", db.Dialector.Name(), "TEST_PG_DSN 非空時不得回退 SQLite")
	t.Logf("EVIDENCE dialect=%s", db.Dialector.Name())
	return db, full
}

// newRevalEnv 建夾具；audit 與 alerts 為 nil 時用真的 writer。
func newRevalEnv(t *testing.T, auditSink port.TxSink, alerts port.SystemAlertSink) *revalEnv {
	t.Helper()
	var base *roleDefEnv
	db, dsn := revalDB(t)
	if db == nil {
		base = newRoleDefEnv(t)
	} else {
		base = newRoleDefEnvOn(t, db)
	}
	require.NoError(t, base.db.AutoMigrate(&model.PasswordHistory{}, &model.RefreshToken{}, &model.UserRoleMappingRuleSupport{},
		&model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.UserRoleMapping{}))
	if auditSink == nil {
		auditSink = audit.NewTxSink()
	}
	if alerts == nil {
		alerts = audit.NewSystemAlertSink(nil)
	}
	g := NewGrantGrader(audit.NewTxSink(), alerts)
	base.svc = NewRoleDefinitionService(base.db, auditSink, base.events, g)
	us := NewUserService(base.db, nil)
	us.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	us.SetGrantGrader(g)
	us.SetPinAuditSink(audit.NewTxSink())
	gs := NewUserGroupService(base.db, audit.NewTxSink(), noopRevoker{})
	gs.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	gs.SetGrantGrader(g)
	return &revalEnv{roleDefEnv: base, grader: g, users: us, groups: gs, pgDSN: dsn}
}

func (e *revalEnv) op() Operator {
	return Operator{UserID: e.admin, Username: "root", ClientIP: "127.0.0.1"}
}

func (e *revalEnv) mkAgent(t *testing.T, name string) uint {
	t.Helper()
	owner := e.admin
	u := model.User{Username: name, Kind: model.KindAgent, OwnerUserID: &owner, Active: true}
	require.NoError(t, e.db.Create(&u).Error)
	return u.ID
}

// roleState 角色的權限集合與定義版本。
func (e *revalEnv) roleState(t *testing.T, roleID uint) ([]string, int64) {
	t.Helper()
	var r model.Role
	require.NoError(t, e.db.First(&r, roleID).Error)
	var perms []string
	require.NoError(t, e.db.Model(&model.RolePermission{}).Where("role_id = ?", roleID).Order("permission_key").Pluck("permission_key", &perms).Error)
	return perms, r.DefinitionVersion
}

func (e *revalEnv) holdings(t *testing.T) (direct, group int64) {
	t.Helper()
	require.NoError(t, e.db.Model(&model.UserRole{}).Count(&direct).Error)
	require.NoError(t, e.db.Model(&model.UserGroupRole{}).Count(&group).Error)
	return direct, group
}

func (e *revalEnv) auditCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.AuditLog{}).Count(&n).Error)
	return n
}

func (e *revalEnv) deniedRows(t *testing.T, roleID uint) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, e.db.Where("status = ? AND resource_id = ?", model.StatusDenied, roleID).Order("id").Find(&rows).Error)
	return rows
}

// detections 偵測事件的審計列（details 已解析）。
func (e *revalEnv) detections(t *testing.T) []map[string]any {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, e.db.Where("details LIKE ?", "%"+RoleUpdateAgentRestrictedEvent+"%").Order("id").Find(&rows).Error)
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.Details), &d))
		require.Equal(t, RoleUpdateAgentRestrictedEvent, d["event"])
		out = append(out, d)
	}
	return out
}

// agentAlerts 提交後偵測建立的告警：以使用者為目標的管理類發放、路徑為偵測值。
// （指派側案例以同交易注入模擬並發，指派本身的交易內分級也會看到受限內容而另發一筆路徑為指派入口的告警，不計入。）
func (e *revalEnv) agentAlerts(t *testing.T) []model.SystemAlertDetail {
	t.Helper()
	var rows []model.SystemAlertDetail
	require.NoError(t, e.db.Where("alert_type = ? AND target_kind = ?", authz.AlertKeyManagementGranted, string(port.SystemAlertTargetUser)).
		Order("alert_id").Find(&rows).Error)
	out := []model.SystemAlertDetail{}
	for _, r := range rows {
		var params map[string]string
		require.NoError(t, json.Unmarshal([]byte(r.Params), &params))
		if p := params["path"]; p == agentRevalidationDetectedPathRole || p == agentRevalidationDetectedPathAssign {
			out = append(out, r)
		}
	}
	return out
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func jsonIDs(v any) []uint {
	arr, _ := v.([]any)
	out := make([]uint, 0, len(arr))
	for _, x := range arr {
		f, _ := x.(float64)
		out = append(out, uint(f))
	}
	return out
}

func jsonStrs(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// injectPermsOnUserRoleInsert 在下一次寫入 user_roles 之後、同一交易內把受限鍵加入角色，
// 模擬「指派通過關卡之後、提交之前，角色內容已被另一筆修改改成受限」。
func injectPermsOnUserRoleInsert(t *testing.T, db *gorm.DB, roleID uint, key string) {
	t.Helper()
	fired := false
	require.NoError(t, db.Callback().Raw().After("gorm:raw").Register("test:inject_role_perm", func(tx *gorm.DB) {
		if fired || tx.Error != nil || !strings.HasPrefix(tx.Statement.SQL.String(), "INSERT INTO user_roles") {
			return
		}
		fired = true
		if err := tx.Session(&gorm.Session{NewDB: true}).Exec("INSERT INTO role_permissions (role_id, permission_key) VALUES (?, ?)", roleID, key).Error; err != nil {
			_ = tx.AddError(err)
		}
	}))
	t.Cleanup(func() { _ = db.Callback().Raw().Remove("test:inject_role_perm") })
	t.Cleanup(func() { require.True(t, fired, "注入點必須被走到") })
}

func TestRoleUpdateAgentRevalidation(t *testing.T) {
	ctx := context.Background()
	restricted := string(authz.PermAlertRuleManage)

	t.Run("直接持有與只經群組持有的 agent：加入受限鍵的修改被拒，碼同指派拒絕，集合、版本與指派不變，拒絕錯誤帶 agent 數與受限權限點、服務不寫審計", func(t *testing.T) {
		e := newRevalEnv(t, nil, nil)
		// 指派 agent 受限角色時的拒絕（參照碼）
		ref := e.create(t, "ref-restricted", "asset:view", restricted)
		refErr := e.users.AddRoleBy(e.op(), e.mkAgent(t, "ref-agent"), ref.Name)
		require.ErrorIs(t, refErr, ErrAgentRoleForbidden)

		for _, src := range []string{"direct", "group"} {
			d := e.create(t, "held-"+src, "asset:view")
			ag := e.mkAgent(t, "ag-"+src)
			if src == "direct" {
				e.holdDirect(t, ag, d.ID, model.RoleSourceManual)
			} else {
				e.holdViaGroup(t, "g-"+src, d.ID, ag)
			}
			perms0, ver0 := e.roleState(t, d.ID)
			dh0, gh0 := e.holdings(t)
			a0 := e.auditCount(t)

			_, err := e.svc.Update(ctx, e.admin, d.ID, ver0, RoleInput{Name: d.Name, Permissions: []string{"asset:view", restricted}})
			require.Error(t, err, src)
			assert.ErrorIs(t, err, ErrAgentRoleForbidden, src)
			assert.Equal(t, AssignmentDenyReason(refErr), AssignmentDenyReason(err), src)
			var pe, refPE *PrincipalError
			require.True(t, errors.As(err, &pe), src)
			require.True(t, errors.As(refErr, &refPE))
			assert.Equal(t, refPE.Code, pe.Code, src)
			assert.Equal(t, refPE.Status, pe.Status, src)

			perms1, ver1 := e.roleState(t, d.ID)
			assert.Equal(t, perms0, perms1, src)
			assert.Equal(t, ver0, ver1, src)
			dh1, gh1 := e.holdings(t)
			assert.Equal(t, dh0, dh1, src)
			assert.Equal(t, gh0, gh1, src)

			// 拒絕明細隨錯誤回給呼叫端（HTTP 層併入該次請求的審計列）；服務本身不寫審計
			count, keys, ok := AgentRoleUpdateRejectionFacts(err)
			require.True(t, ok, src)
			assert.Equal(t, 1, count, src)
			assert.Equal(t, []string{restricted}, keys, src)
			assert.Equal(t, a0, e.auditCount(t), src)
			assert.Empty(t, e.deniedRows(t, d.ID), src)
			assert.Empty(t, e.detections(t), src)
		}
	})

	t.Run("只由人類持有：同一修改成功、版本推進一次、沒有拒絕列", func(t *testing.T) {
		e := newRevalEnv(t, nil, nil)
		d := e.create(t, "human-only", "asset:view")
		e.holdDirect(t, e.mkUser(t, "human"), d.ID, model.RoleSourceManual)
		_, ver0 := e.roleState(t, d.ID)
		up, err := e.svc.Update(ctx, e.admin, d.ID, ver0, RoleInput{Name: d.Name, Permissions: []string{"asset:view", restricted}})
		require.NoError(t, err)
		assert.Equal(t, ver0+1, up.DefinitionVersion)
		perms, ver := e.roleState(t, d.ID)
		assert.Equal(t, ver0+1, ver)
		assert.Contains(t, perms, restricted)
		assert.Empty(t, e.deniedRows(t, d.ID))
		assert.Empty(t, e.detections(t))
	})

	t.Run("修改不含受限鍵：有 agent 持有也成功", func(t *testing.T) {
		e := newRevalEnv(t, nil, nil)
		d := e.create(t, "agent-plain", "asset:view")
		e.holdDirect(t, e.mkAgent(t, "ag-plain"), d.ID, model.RoleSourceManual)
		_, ver0 := e.roleState(t, d.ID)
		up, err := e.svc.Update(ctx, e.admin, d.ID, ver0, RoleInput{Name: d.Name + "-renamed", Description: "x", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		assert.Equal(t, ver0+1, up.DefinitionVersion)
		assert.Empty(t, e.deniedRows(t, d.ID))
		assert.Empty(t, e.detections(t))
		assert.Empty(t, e.agentAlerts(t))
	})

	t.Run("交易失敗：集合與版本不變、沒有拒絕列與偵測列", func(t *testing.T) {
		e := newRevalEnv(t, nil, nil)
		d := e.create(t, "tx-fail", "asset:view")
		e.holdDirect(t, e.mkAgent(t, "ag-tx"), d.ID, model.RoleSourceManual)
		perms0, ver0 := e.roleState(t, d.ID)
		e.events.fail = errors.New("injected event failure")
		_, err := e.svc.Update(ctx, e.admin, d.ID, ver0, RoleInput{Name: d.Name + "-renamed", Description: "x", Permissions: []string{"asset:view"}})
		require.Error(t, err)
		e.events.fail = nil
		perms1, ver1 := e.roleState(t, d.ID)
		assert.Equal(t, perms0, perms1)
		assert.Equal(t, ver0, ver1)
		assert.Empty(t, e.deniedRows(t, d.ID))
		assert.Empty(t, e.detections(t))
	})

	t.Run("角色側：提交後才出現的 agent 持有者被重查命中，恰一筆告警與一列偵測審計，關聯編號相同", func(t *testing.T) {
		e := newRevalEnv(t, nil, nil)
		d := e.create(t, "role-side", "asset:view")
		ag := e.mkAgent(t, "ag-late")
		before, ver0 := e.roleState(t, d.ID)
		e.svc.afterCommitHook = func() { e.holdDirect(t, ag, d.ID, model.RoleSourceManual) }
		_, err := e.svc.Update(ctx, e.admin, d.ID, ver0, RoleInput{Name: d.Name, Permissions: []string{"asset:view", restricted}})
		require.NoError(t, err)
		after, _ := e.roleState(t, d.ID)

		dets := e.detections(t)
		require.Len(t, dets, 1)
		det := dets[0]
		assert.Equal(t, DetectedByRoleUpdate, det["detected_by"])
		assert.EqualValues(t, d.ID, det["role_id"])
		assert.Equal(t, []uint{ag}, jsonIDs(det["agent_ids"]))
		assert.Equal(t, before, jsonStrs(det["permissions_before"]))
		assert.Equal(t, after, jsonStrs(det["permissions_after"]))
		assert.Equal(t, []string{restricted}, jsonStrs(det["restricted_permissions"]))

		alerts := e.agentAlerts(t)
		require.Len(t, alerts, 1)
		assert.Equal(t, fmt.Sprint(ag), alerts[0].TargetID)
		assert.Equal(t, det["correlation_id"], alerts[0].CorrelationID)
		var params map[string]string
		require.NoError(t, json.Unmarshal([]byte(alerts[0].Params), &params))
		assert.Equal(t, agentRevalidationDetectedPathRole, params["path"])
	})

	t.Run("指派側：指派通過關卡後角色才變成受限，提交後恰一筆告警與一列偵測審計，指派已提交", func(t *testing.T) {
		e := newRevalEnv(t, nil, nil)
		d := e.create(t, "assign-side", "asset:view")
		ag := e.mkAgent(t, "ag-assign")
		injectPermsOnUserRoleInsert(t, e.db, d.ID, restricted)
		require.NoError(t, e.users.AddRoleBy(e.op(), ag, d.Name))
		var held int64
		require.NoError(t, e.db.Model(&model.UserRole{}).Where("user_id = ? AND role_id = ?", ag, d.ID).Count(&held).Error)
		assert.EqualValues(t, 1, held, "指派仍為已提交")

		dets := e.detections(t)
		require.Len(t, dets, 1)
		det := dets[0]
		assert.Equal(t, DetectedByAssignment, det["detected_by"])
		assert.EqualValues(t, d.ID, det["role_id"])
		assert.Equal(t, []uint{ag}, jsonIDs(det["agent_ids"]))
		assert.ElementsMatch(t, []string{"asset:view", restricted}, jsonStrs(det["permissions"]))
		assert.Equal(t, []string{restricted}, jsonStrs(det["restricted_permissions"]))
		alerts := e.agentAlerts(t)
		require.Len(t, alerts, 1)
		assert.Equal(t, fmt.Sprint(ag), alerts[0].TargetID)
		assert.Equal(t, det["correlation_id"], alerts[0].CorrelationID)
	})

	t.Run("告警寫入失敗：修改與指派仍為已提交，留錯誤日誌", func(t *testing.T) {
		e := newRevalEnv(t, nil, detectedAlertFailSink{inner: audit.NewSystemAlertSink(nil)})
		buf := captureLog(t)

		d := e.create(t, "alert-fail-role", "asset:view")
		ag := e.mkAgent(t, "ag-alert-role")
		_, ver0 := e.roleState(t, d.ID)
		e.svc.afterCommitHook = func() { e.holdDirect(t, ag, d.ID, model.RoleSourceManual) }
		_, err := e.svc.Update(ctx, e.admin, d.ID, ver0, RoleInput{Name: d.Name, Permissions: []string{"asset:view", restricted}})
		require.NoError(t, err)
		perms, ver := e.roleState(t, d.ID)
		assert.Equal(t, ver0+1, ver, "修改仍為已提交")
		assert.Contains(t, perms, restricted)
		e.svc.afterCommitHook = nil

		d2 := e.create(t, "alert-fail-assign", "asset:view")
		ag2 := e.mkAgent(t, "ag-alert-assign")
		injectPermsOnUserRoleInsert(t, e.db, d2.ID, restricted)
		require.NoError(t, e.users.AddRoleBy(e.op(), ag2, d2.Name))
		var held int64
		require.NoError(t, e.db.Model(&model.UserRole{}).Where("user_id = ? AND role_id = ?", ag2, d2.ID).Count(&held).Error)
		assert.EqualValues(t, 1, held, "指派仍為已提交")

		assert.Equal(t, 2, strings.Count(buf.String(), "[AgentRoleRevalidation] 提交後偵測失敗"))
		assert.Empty(t, e.agentAlerts(t))
		assert.Empty(t, e.detections(t), "偵測交易整筆回滾")
	})

	t.Run("指派側入口各一次無並發正常指派：偵測命中 0、不新增告警", func(t *testing.T) {
		e := newRevalEnv(t, nil, nil)
		userRole := e.roles["user"]
		owner := e.admin
		holds := func(uid uint) bool {
			var n int64
			require.NoError(t, e.db.Model(&model.UserRole{}).Where("user_id = ? AND role_id = ?", uid, userRole).Count(&n).Error)
			if n > 0 {
				return true
			}
			require.NoError(t, e.db.Table("user_group_members").
				Joins("JOIN user_group_roles ON user_group_roles.user_group_id = user_group_members.user_group_id").
				Where("user_group_members.user_id = ? AND user_group_roles.role_id = ?", uid, userRole).Count(&n).Error)
			return n > 0
		}
		auth := NewAuthService("reval-test-secret", time.Hour)
		auth.SetRoleMappingAuditSink(audit.NewTxSink())
		auth.SetGrantGrader(e.grader)

		entries := []struct {
			name string
			run  func(t *testing.T) uint
		}{
			{"建帳號帶角色", func(t *testing.T) uint {
				u, err := e.users.CreateBy(e.op(), &CreateUserRequest{Kind: model.KindAgent, OwnerUserID: &owner, Username: "ag-create", Roles: []string{"user"}})
				require.NoError(t, err)
				return u.ID
			}},
			{"單一角色加入", func(t *testing.T) uint {
				ag := e.mkAgent(t, "ag-add")
				require.NoError(t, e.users.AddRoleBy(e.op(), ag, "user"))
				return ag
			}},
			{"角色整組指派", func(t *testing.T) uint {
				ag := e.mkAgent(t, "ag-assign-all")
				_, err := e.users.AssignRolesBy(e.op(), ag, []string{"user"})
				require.NoError(t, err)
				return ag
			}},
			{"釘住映射角色", func(t *testing.T) uint {
				ag := e.mkAgent(t, "ag-pin")
				e.holdDirect(t, ag, userRole, model.RoleSourceMapped)
				_, err := e.users.PinMappedRoleBy(e.op(), ag, "user")
				require.NoError(t, err)
				return ag
			}},
			{"群組角色指派", func(t *testing.T) uint {
				ag := e.mkAgent(t, "ag-group-role")
				g := model.UserGroup{Name: "grp-role"}
				require.NoError(t, e.db.Create(&g).Error)
				require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: ag, Manual: true}).Error)
				_, err := e.groups.ReplaceRoleBindings(e.op(), g.ID, GroupRoleBindingsRequest{RoleIDs: []uint{userRole}})
				require.NoError(t, err)
				return ag
			}},
			{"群組成員加入", func(t *testing.T) uint {
				ag := e.mkAgent(t, "ag-group-member")
				g := model.UserGroup{Name: "grp-member"}
				require.NoError(t, e.db.Create(&g).Error)
				require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: userRole, ScopeKind: model.ScopeKindGlobal}).Error)
				_, err := e.groups.ReplaceMembersBy(e.op(), g.ID, ids(ag), nil)
				require.NoError(t, err)
				return ag
			}},
			{"目錄群組映射重算", func(t *testing.T) uint {
				prev := database.DB
				database.DB = e.db
				t.Cleanup(func() { database.DB = prev })
				owner := e.admin
				u := model.User{Username: "ag-ldap", Kind: model.KindAgent, OwnerUserID: &owner, Active: true, ExternalCredential: true}
				require.NoError(t, e.db.Create(&u).Error)
				dir := uint(41)
				// 來源列：PostgreSQL 一律要求來源存在且啟用
				require.NoError(t, e.db.AutoMigrate(&model.LDAPDirectory{}))
				ld := model.LDAPDirectory{Singleton: 1, Name: "directory", URL: "ldaps://ldap.example.test:636", BaseDN: "dc=example,dc=test",
					UserFilter: "(uid=%s)", AttrGroup: "memberOf", BindPasswordEnc: "enc", Enabled: true}
				ld.ID = dir
				require.NoError(t, e.db.Create(&ld).Error)
				eg := model.ExternalGroup{LDAPDirectoryID: &dir, MatchValue: "cn=ops"}
				require.NoError(t, e.db.Create(&eg).Error)
				require.NoError(t, e.db.Create(&model.GroupRoleMapping{LDAPDirectoryID: &dir, MatchValue: "cn=ops", RoleID: userRole, Enabled: true, CreatedBy: e.admin, ExternalGroupID: eg.ID}).Error)
				require.NoError(t, auth.recomputeLDAPRoleMapping(&u, &LDAPUserInfo{Groups: []string{"cn=ops"}, GroupsKnown: true},
					LDAPLoginResolution{DirectoryID: dir, GroupAttr: "memberOf"}))
				return u.ID
			}},
			{"身分提供者群組映射重算", func(t *testing.T) uint {
				owner := e.admin
				u := model.User{Username: "ag-oidc", Kind: model.KindAgent, OwnerUserID: &owner, Active: true, ExternalCredential: true}
				require.NoError(t, e.db.Create(&u).Error)
				require.NoError(t, e.db.AutoMigrate(&model.OIDCProvider{}))
				p := &model.OIDCProvider{Name: "reval", Issuer: "https://id.example.test/reval", ClientID: "client", Scopes: "openid groups",
					GroupsClaim: "groups", Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, AdmissionRules: "{}"}
				p.ID = 42
				require.NoError(t, e.db.Create(p).Error)
				pid := p.ID
				eg := model.ExternalGroup{OIDCProviderID: &pid, MatchValue: "ops"}
				require.NoError(t, e.db.Create(&eg).Error)
				require.NoError(t, e.db.Create(&model.GroupRoleMapping{OIDCProviderID: &pid, MatchValue: "ops", RoleID: userRole, Enabled: true, CreatedBy: e.admin, ExternalGroupID: eg.ID}).Error)
				login := &OIDCLoginService{db: e.db, auth: auth, mappingAudit: audit.NewTxSink()}
				require.NoError(t, login.recomputeMappedRoles(p, &u, &VerifiedClaims{Raw: map[string]any{"groups": []any{"ops"}}}))
				return u.ID
			}},
		}
		for _, en := range entries {
			t.Run(en.name, func(t *testing.T) {
				d0, al0 := len(e.detections(t)), e.alertRows(t)
				ag := en.run(t)
				assert.True(t, holds(ag), "入口寫入後 agent 持有該角色")
				assert.Equal(t, d0, len(e.detections(t)), "偵測命中 0")
				assert.Equal(t, al0, e.alertRows(t), "不新增告警")
			})
		}
	})

	t.Run("pg_assign_before_role_recheck", func(t *testing.T) {
		if os.Getenv("TEST_PG_DSN") == "" {
			t.Skip("需要 PostgreSQL（TEST_PG_DSN）：兩條連線的並發排程")
		}
		e := newRevalEnv(t, nil, nil)
		r := newPGRace(t, e, "pg-before")
		hookGate := newGate(t)
		e.svc.afterCommitHook = func() { hookGate.block(t, "角色側重查前的暫停") }

		uDone := r.startUpdate(ctx, restricted)
		r.uPaused.wait(t, "修改寫入新集合後暫停")
		sDone := r.startAssign()
		r.proveAssignWaitsOnUpdate(t)
		r.uRelease.open() // 修改提交，停在角色側重查之前
		errS := waitErr(t, sDone, "指派完成")
		require.NoError(t, errS)
		hookGate.open() // 指派已提交，角色側重查才開始
		errU := waitErr(t, uDone, "修改完成")
		require.NoError(t, errU)
		r.assertNoDeadlock(t, errU, errS)
		r.assertCommitted(t, restricted)

		byRole, byAssign := r.splitDetections(t)
		t.Logf("EVIDENCE schedule=a detected_by role_update=%d assignment=%d", len(byRole), len(byAssign))
		require.Len(t, byRole, 1, "角色側恰一列偵測審計")
		det := byRole[0]
		assert.EqualValues(t, r.role.ID, det["role_id"])
		assert.Equal(t, []uint{r.agent}, jsonIDs(det["agent_ids"]))
		assert.Equal(t, []string{"asset:view"}, jsonStrs(det["permissions_before"]))
		assert.ElementsMatch(t, []string{"asset:view", restricted}, jsonStrs(det["permissions_after"]))
		roleAlerts := r.alertsByPath(t, agentRevalidationDetectedPathRole)
		require.Len(t, roleAlerts, 1, "角色側恰一筆告警")
		assert.Equal(t, fmt.Sprint(r.agent), roleAlerts[0].TargetID)
		assert.Equal(t, det["correlation_id"], roleAlerts[0].CorrelationID)
		r.assertAlertsCorrelated(t)
	})

	t.Run("pg_assign_after_role_recheck", func(t *testing.T) {
		if os.Getenv("TEST_PG_DSN") == "" {
			t.Skip("需要 PostgreSQL（TEST_PG_DSN）：兩條連線的並發排程")
		}
		e := newRevalEnv(t, nil, nil)
		r := newPGRace(t, e, "pg-after")
		r.pauseAssignAfterInsert(t)

		uDone := r.startUpdate(ctx, restricted)
		r.uPaused.wait(t, "修改寫入新集合後暫停")
		sDone := r.startAssign()
		r.proveAssignWaitsOnUpdate(t)
		r.uRelease.open() // 修改提交，角色側重查立即執行
		errU := waitErr(t, uDone, "修改完成（含角色側重查）")
		require.NoError(t, errU)
		r.sPaused.wait(t, "指派寫入後、提交前暫停")
		byRole, _ := r.splitDetections(t)
		assert.Empty(t, byRole, "角色側重查時指派尚未提交：命中 0")
		assert.Empty(t, r.alertsByPath(t, agentRevalidationDetectedPathRole))
		r.sRelease.open()
		errS := waitErr(t, sDone, "指派完成")
		require.NoError(t, errS)
		r.assertNoDeadlock(t, errU, errS)
		r.assertCommitted(t, restricted)

		byRole, byAssign := r.splitDetections(t)
		t.Logf("EVIDENCE schedule=b detected_by role_update=%d assignment=%d", len(byRole), len(byAssign))
		assert.Empty(t, byRole)
		require.Len(t, byAssign, 1, "指派側恰一列偵測審計")
		det := byAssign[0]
		assert.EqualValues(t, r.role.ID, det["role_id"])
		assert.Equal(t, []uint{r.agent}, jsonIDs(det["agent_ids"]))
		assert.ElementsMatch(t, []string{"asset:view", restricted}, jsonStrs(det["permissions"]))
		assert.Equal(t, []string{restricted}, jsonStrs(det["restricted_permissions"]))
		assignAlerts := r.alertsByPath(t, agentRevalidationDetectedPathAssign)
		require.Len(t, assignAlerts, 1, "指派側恰一筆告警")
		assert.Equal(t, fmt.Sprint(r.agent), assignAlerts[0].TargetID)
		assert.Equal(t, det["correlation_id"], assignAlerts[0].CorrelationID)
		r.assertAlertsCorrelated(t)
	})
}
