package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

type atomEnv struct {
	*acctEnv
	groups *UserGroupService
}

// newAtomEnv 分級器用的落地面可替換：audit 或 alerts 任一注入失敗。
func newAtomEnv(t *testing.T, auditTx port.TxSink, alerts port.SystemAlertSink) *atomEnv {
	t.Helper()
	e := newAcctEnv(t, nil)
	if auditTx == nil {
		auditTx = audit.NewTxSink()
	}
	if alerts == nil {
		alerts = audit.NewSystemAlertSink(nil)
	}
	grader := NewGrantGrader(auditTx, alerts)
	e.users.SetGrantGrader(grader)
	g := NewUserGroupService(e.db, audit.NewTxSink(), noopRevoker{})
	g.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	g.SetGrantGrader(grader)
	return &atomEnv{acctEnv: e, groups: g}
}

// state 寫入點會動到的全部資料與版本、世代的指紋。
func (e *atomEnv) state(t *testing.T) string {
	t.Helper()
	var users, userRoles, members, groupRoles, groups int64
	require.NoError(t, e.db.Model(&model.User{}).Count(&users).Error)
	require.NoError(t, e.db.Table("user_roles").Count(&userRoles).Error)
	require.NoError(t, e.db.Table("user_group_members").Count(&members).Error)
	require.NoError(t, e.db.Table("user_group_roles").Count(&groupRoles).Error)
	require.NoError(t, e.db.Model(&model.UserGroup{}).Count(&groups).Error)
	var epochs int64
	require.NoError(t, e.db.Model(&model.User{}).Select("COALESCE(SUM(credential_epoch),0)").Scan(&epochs).Error)
	return fmt.Sprintf("u%d/ur%d/m%d/gr%d/g%d/v%d/e%d", users, userRoles, members, groupRoles, groups, e.version(t), epochs)
}

func (e *atomEnv) graded(t *testing.T) (alerts int64, marked []model.AuditLog) {
	t.Helper()
	require.NoError(t, e.db.Model(&model.SystemAlertDetail{}).Count(&alerts).Error)
	require.NoError(t, e.db.Where("details LIKE ?", "%grant_change_graded%").Find(&marked).Error)
	return alerts, marked
}

type atomCase struct {
	name  string
	setup func(t *testing.T, e *atomEnv) func() error // 回傳實際寫入的動作
	mark  string
	alert string
}

func atomCases() []atomCase {
	return []atomCase{
		{name: "替換", mark: "management_grant", alert: "management_role_granted", setup: func(t *testing.T, e *atomEnv) func() error {
			target := e.mkUser(t, "t1")
			return func() error {
				_, err := e.users.AssignRolesBy(e.op(e.admin), target, []string{"identity_admin"})
				return err
			}
		}},
		{name: "追加", mark: "management_grant", alert: "management_role_granted", setup: func(t *testing.T, e *atomEnv) func() error {
			target := e.mkUser(t, "t2")
			return func() error { return e.users.AddRoleBy(e.op(e.admin), target, "security_admin") }
		}},
		{name: "建帳號帶角色", mark: "management_grant", alert: "management_role_granted", setup: func(t *testing.T, e *atomEnv) func() error {
			return func() error {
				_, err := e.users.CreateBy(e.op(e.admin), &CreateUserRequest{Username: "n1", Password: "Passw0rd!xyz", Roles: []string{"identity_admin"}})
				return err
			}
		}},
		{name: "群組角色指派", mark: "management_grant", alert: "management_role_granted", setup: func(t *testing.T, e *atomEnv) func() error {
			gid := (&groupBindEnv{guardEnv: e.guardEnv, svc: e.groups}).group(t, "g1")
			return func() error {
				_, err := e.groups.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["identity_admin"]}})
				return err
			}
		}},
		{name: "成員加入", mark: "management_grant", alert: "management_role_granted", setup: func(t *testing.T, e *atomEnv) func() error {
			gb := &groupBindEnv{guardEnv: e.guardEnv, svc: e.groups}
			gid := gb.group(t, "g2")
			gb.giveRole(t, gid, "identity_admin")
			m := e.mkUser(t, "m")
			return func() error { _, err := e.groups.ReplaceMembersBy(e.op(e.admin), gid, ids(m), nil); return err }
		}},
		{name: "成員移除", mark: "self_authorization", alert: "self_privilege_decreased", setup: func(t *testing.T, e *atomEnv) func() error {
			gb := &groupBindEnv{guardEnv: e.guardEnv, svc: e.groups}
			gid := gb.group(t, "g3", e.admin)
			gb.giveRole(t, gid, "auditor")
			return func() error { _, err := e.groups.ReplaceMembersBy(e.op(e.admin), gid, ids(), nil); return err }
		}},
		{name: "群組刪除", mark: "self_authorization", alert: "self_privilege_decreased", setup: func(t *testing.T, e *atomEnv) func() error {
			gb := &groupBindEnv{guardEnv: e.guardEnv, svc: e.groups}
			gid := gb.group(t, "g4", e.admin)
			gb.giveRole(t, gid, "auditor")
			return func() error { _, err := e.groups.DeleteBy(e.op(e.admin), gid); return err }
		}},
	}
}

// TestGrantAuditAtomicity 擋：七個寫入點在告警事件或審計寫入失敗時，資料、權限版本、憑證世代全回滾；
// 成功時事件與帶標記的審計同交易可見且共用關聯編號。
func TestGrantAuditAtomicity(t *testing.T) {
	for _, tc := range atomCases() {
		t.Run(tc.name+"：成功時事件與標記審計同交易可見", func(t *testing.T) {
			e := newAtomEnv(t, nil, nil)
			do := tc.setup(t, e)
			before := e.state(t)
			require.NoError(t, do())
			assert.NotEqual(t, before, e.state(t), "寫入應生效")
			alerts, marked := e.graded(t)
			assert.EqualValues(t, 1, alerts)
			require.Len(t, marked, 1)
			var d struct {
				Marks []string `json:"grant_marks"`
				Corr  string   `json:"correlation_id"`
			}
			require.NoError(t, json.Unmarshal([]byte(marked[0].Details), &d))
			assert.Equal(t, []string{tc.mark}, d.Marks)
			var det model.SystemAlertDetail
			require.NoError(t, e.db.First(&det).Error)
			assert.Equal(t, tc.alert, det.AlertType)
			assert.Equal(t, d.Corr, det.CorrelationID, "事件與審計共用關聯編號")
		})
		t.Run(tc.name+"：告警事件寫入失敗全回滾", func(t *testing.T) {
			e := newAtomEnv(t, nil, failingAlerts{})
			do := tc.setup(t, e)
			before := e.state(t)
			require.Error(t, do())
			assert.Equal(t, before, e.state(t))
			alerts, marked := e.graded(t)
			assert.Zero(t, alerts)
			assert.Empty(t, marked)
		})
		t.Run(tc.name+"：審計寫入失敗全回滾", func(t *testing.T) {
			e := newAtomEnv(t, failingSink{err: errors.New("audit down")}, nil)
			do := tc.setup(t, e)
			before := e.state(t)
			require.Error(t, do())
			assert.Equal(t, before, e.state(t))
			alerts, _ := e.graded(t)
			assert.Zero(t, alerts)
		})
	}

	t.Run("分級鍵等於系統告警目錄登錄的類型鍵", func(t *testing.T) {
		assert.Equal(t, string(port.SystemAlertSelfPrivilegeIncreased), authz.AlertKeySelfIncreased)
		assert.Equal(t, string(port.SystemAlertSelfPrivilegeDecreased), authz.AlertKeySelfDecreased)
		assert.Equal(t, string(port.SystemAlertManagementRoleGranted), authz.AlertKeyManagementGranted)
	})

	t.Run("被拒的寫入沒有成功事件", func(t *testing.T) {
		e := newAtomEnv(t, nil, nil)
		ida := e.mkUser(t, "ida", "identity_admin")
		victim := e.mkUser(t, "victim")
		before := e.state(t)
		_, err := e.users.AssignRolesBy(e.op(ida), victim, []string{"admin"})
		require.Error(t, err)
		assert.Equal(t, before, e.state(t))
		alerts, marked := e.graded(t)
		assert.Zero(t, alerts)
		assert.Empty(t, marked)
	})

	t.Run("對自己所屬群組新增管理類指派：一筆寫入同時產生自我授權與以群組為目標的管理類發放", func(t *testing.T) {
		e := newAtomEnv(t, nil, nil)
		gb := &groupBindEnv{guardEnv: e.guardEnv, svc: e.groups}
		other := e.mkUser(t, "other")
		gid := gb.group(t, "mine", e.admin, other)
		_, err := e.groups.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["identity_admin"]}})
		require.NoError(t, err)
		var dets []model.SystemAlertDetail
		require.NoError(t, e.db.Find(&dets).Error)
		require.Len(t, dets, 2, "一筆寫入兩個事件，不逐成員展開")
		byType := map[string]model.SystemAlertDetail{}
		for _, d := range dets {
			byType[d.AlertType] = d
		}
		require.Contains(t, byType, "self_privilege_increased")
		require.Contains(t, byType, "management_role_granted")
		assert.NotEqual(t, byType["self_privilege_increased"].CorrelationID, byType["management_role_granted"].CorrelationID)
		_, marked := e.graded(t)
		assert.Len(t, marked, 2, "兩個事件各有一列帶標記的審計")
	})

	t.Run("對一般角色不告警、不多寫審計", func(t *testing.T) {
		e := newAtomEnv(t, nil, nil)
		target := e.mkUser(t, "plain")
		_, err := e.users.AssignRolesBy(e.op(e.admin), target, []string{"auditor"})
		require.NoError(t, err)
		alerts, marked := e.graded(t)
		assert.Zero(t, alerts)
		assert.Empty(t, marked)
	})
}

var _ = gorm.ErrRecordNotFound
