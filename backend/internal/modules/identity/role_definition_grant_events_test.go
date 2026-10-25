package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 角色內容修改的授權變更分級：以真實的修改前後集合與同交易的告警落地面斷言事件列與審計列，
// 分類結果不 mock。

type errAlerts struct{ err error }

func (f errAlerts) RaiseInTx(*gorm.DB, port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, f.err
}

type gradeEvent struct {
	Type, TargetKind, TargetID, Corr string
	// Severity 告警父列（command_alerts，以 alert_id 對應）實際落地的等級。
	Severity string
	Params   map[string]string
}

func (e *roleDefEnv) alertEvents(t *testing.T) []gradeEvent {
	t.Helper()
	var rows []model.SystemAlertDetail
	require.NoError(t, e.db.Order("alert_id").Find(&rows).Error)
	out := make([]gradeEvent, 0, len(rows))
	for _, r := range rows {
		ev := gradeEvent{Type: r.AlertType, TargetKind: r.TargetKind, TargetID: r.TargetID, Corr: r.CorrelationID}
		var sev []string
		require.NoError(t, e.db.Model(&model.CommandAlert{}).Where("id = ?", r.AlertID).Pluck("severity", &sev).Error)
		require.Len(t, sev, 1, "alert_id %d 必須恰有一列告警父列", r.AlertID)
		ev.Severity = sev[0]
		_ = json.Unmarshal([]byte(r.Params), &ev.Params)
		out = append(out, ev)
	}
	return out
}

// updateAudit 角色最後一筆修改審計的 details。
func (e *roleDefEnv) updateAudit(t *testing.T, roleID uint) map[string]any {
	t.Helper()
	var row model.AuditLog
	require.NoError(t, e.db.Where("action = ? AND resource_id = ?", model.ActionRoleDefinitionUpdate, roleID).Order("id DESC").First(&row).Error)
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(row.Details), &d))
	return d
}

func (e *roleDefEnv) holdDirect(t *testing.T, uid, roleID uint, source string) {
	t.Helper()
	require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: roleID, Source: source, ScopeKind: model.ScopeKindGlobal}).Error)
}

func (e *roleDefEnv) holdViaGroup(t *testing.T, name string, roleID uint, members ...uint) {
	t.Helper()
	g := model.UserGroup{Name: name}
	require.NoError(t, e.db.Create(&g).Error)
	for _, m := range members {
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: m}).Error)
	}
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: roleID, ScopeKind: model.ScopeKindGlobal}).Error)
}

func (e *roleDefEnv) update(t *testing.T, d *RoleDefinition, name string, perms ...string) (*RoleDefinition, error) {
	t.Helper()
	cur, err := e.svc.GetDefinition(context.Background(), d.ID)
	require.NoError(t, err)
	return e.svc.Update(context.Background(), e.admin, d.ID, cur.DefinitionVersion, RoleInput{Name: name, Description: cur.Description, Permissions: perms})
}

// updateWithDescription 同 update，但說明改成給定值。
func (e *roleDefEnv) updateWithDescription(t *testing.T, d *RoleDefinition, name, desc string, perms ...string) (*RoleDefinition, error) {
	t.Helper()
	cur, err := e.svc.GetDefinition(context.Background(), d.ID)
	require.NoError(t, err)
	return e.svc.Update(context.Background(), e.admin, d.ID, cur.DefinitionVersion, RoleInput{Name: name, Description: desc, Permissions: perms})
}

func (e *roleDefEnv) alertRows(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.SystemAlertDetail{}).Count(&n).Error)
	return n
}

func TestRoleDefinitionGrantEvents(t *testing.T) {
	t.Run("三位他人直接持有的非管理角色加入管理能力：一筆中分級管理類發放，以角色為目標", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "peer", "asset:view")
		for _, n := range []string{"p1", "p2", "p3"} {
			e.holdDirect(t, e.mkUser(t, n), d.ID, model.RoleSourceManual)
		}
		_, err := e.update(t, d, "peer", "asset:view", "asset:update")
		require.NoError(t, err)
		evs := e.alertEvents(t)
		require.Len(t, evs, 1)
		assert.Equal(t, authz.AlertKeyManagementGranted, evs[0].Type)
		assert.Equal(t, model.AlertSeverityMedium, evs[0].Severity, "管理類發放落地為中分級")
		assert.Equal(t, "role", evs[0].TargetKind)
		assert.Equal(t, sprintID(d.ID), evs[0].TargetID, "目標 ID 是角色")
		assert.Equal(t, "role_definition", evs[0].Params["path"])
		det := e.updateAudit(t, d.ID)
		assert.Equal(t, []any{"management_grant"}, det["grant_marks"])
		assert.EqualValues(t, 3, det["holder_count"])
		assert.Equal(t, evs[0].Corr, det["correlation_id"], "審計與事件共用關聯編號")
		assert.NotEmpty(t, evs[0].Corr)
	})

	t.Run("超管經群組持有：加入能力為高分級，只移除為低分級，有增有減為高分級", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "mine", "asset:view")
		e.holdViaGroup(t, "g-self", d.ID, e.admin)
		steps := []struct {
			perms []string
			want  string
			sev   string
		}{
			{[]string{"asset:view", "session:view"}, authz.AlertKeySelfIncreased, model.AlertSeverityHigh},
			{[]string{"asset:view"}, authz.AlertKeySelfDecreased, model.AlertSeverityLow},
			{[]string{"session:view"}, authz.AlertKeySelfIncreased, model.AlertSeverityHigh},
		}
		for i, st := range steps {
			_, err := e.update(t, d, "mine", st.perms...)
			require.NoError(t, err, i)
			evs := e.alertEvents(t)
			require.Len(t, evs, i+1, "每次修改恰一筆")
			last := evs[i]
			assert.Equal(t, st.want, last.Type, i)
			assert.Equal(t, st.sev, last.Severity, "第 %d 步告警父列的等級", i)
			assert.Equal(t, "user", last.TargetKind)
			assert.Equal(t, sprintID(e.admin), last.TargetID)
			assert.Equal(t, "role_definition", last.Params["path"])
			assert.Equal(t, []any{"self_authorization"}, e.updateAudit(t, d.ID)["grant_marks"])
			assert.Equal(t, last.Corr, e.updateAudit(t, d.ID)["correlation_id"])
		}
	})

	t.Run("超管同時經直接與映射持有：只一筆自我授權事件", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "both", "asset:view")
		e.holdDirect(t, e.admin, d.ID, model.RoleSourceBoth)
		e.holdViaGroup(t, "g-both", d.ID, e.admin)
		_, err := e.update(t, d, "both", "asset:view", "session:view")
		require.NoError(t, err)
		evs := e.alertEvents(t)
		require.Len(t, evs, 1)
		assert.Equal(t, authz.AlertKeySelfIncreased, evs[0].Type)
		assert.Equal(t, model.AlertSeverityHigh, evs[0].Severity)
		assert.EqualValues(t, 1, e.updateAudit(t, d.ID)["holder_count"], "同一帳號多來源只計一人")
	})

	t.Run("只改名稱與說明：沒有事件，審計沒有 grant_marks", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "plain", "asset:view")
		e.holdDirect(t, e.mkUser(t, "h1"), d.ID, model.RoleSourceManual)
		e.holdDirect(t, e.admin, d.ID, model.RoleSourceManual)
		_, err := e.update(t, d, "plain-renamed", "asset:view")
		require.NoError(t, err)
		assert.Empty(t, e.alertEvents(t))
		det := e.updateAudit(t, d.ID)
		assert.NotContains(t, det, "grant_marks")
		assert.NotContains(t, det, "correlation_id")
		// 真正改動說明（名稱與權限集合不變）同樣零事件、審計無標記
		got, err := e.updateWithDescription(t, d, "plain-renamed", "只改說明的新文字", "asset:view")
		require.NoError(t, err)
		assert.Equal(t, "只改說明的新文字", got.Description, "說明確實被改動")
		assert.Empty(t, e.alertEvents(t))
		det = e.updateAudit(t, d.ID)
		assert.NotContains(t, det, "grant_marks")
		assert.NotContains(t, det, "correlation_id")
	})

	t.Run("無持有者、只被停用映射規則指向：加入管理能力仍一筆發放；完全無引用：零事件", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "mapped-only", "asset:view")
		require.NoError(t, e.db.Create(&model.GroupRoleMapping{MatchValue: "cn=x", ExternalGroupID: 1, RoleID: d.ID, Enabled: false, CreatedBy: e.admin}).Error)
		_, err := e.update(t, d, "mapped-only", "asset:view", "ldap:manage")
		require.NoError(t, err)
		evs := e.alertEvents(t)
		require.Len(t, evs, 1)
		assert.Equal(t, authz.AlertKeyManagementGranted, evs[0].Type)
		assert.Equal(t, model.AlertSeverityMedium, evs[0].Severity)
		assert.EqualValues(t, 1, e.updateAudit(t, d.ID)["mapping_rule_count"])

		free := e.create(t, "free", "asset:view")
		_, err = e.update(t, free, "free", "asset:view", "asset:update")
		require.NoError(t, err)
		assert.Len(t, e.alertEvents(t), 1, "無持有者也無引用：沒有新增事件")
	})

	t.Run("事件或審計寫入失敗：角色內容、定義版本、權限版本、審計列、事件列全部維持修改前", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			break_ func(e *roleDefEnv, boom error)
		}{
			{"事件失敗", func(e *roleDefEnv, boom error) {
				e.svc.grader = NewGrantGrader(audit.NewTxSink(), errAlerts{err: boom})
			}},
			{"審計失敗", func(e *roleDefEnv, boom error) { e.svc.audit = failingSink{err: boom} }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := newRoleDefEnv(t)
				d := e.create(t, "rb", "asset:view")
				e.holdDirect(t, e.mkUser(t, "h"), d.ID, model.RoleSourceManual)
				_, p0, v0, a0 := e.snapshot(t)
				ev0 := e.alertRows(t)
				boom := errors.New("sink down")
				tc.break_(e, boom)
				_, err := e.update(t, d, "rb", "asset:view", "asset:update")
				assert.ErrorIs(t, err, boom)
				_, p1, v1, a1 := e.snapshot(t)
				assert.Equal(t, []int64{p0, v0, a0, ev0}, []int64{p1, v1, a1, e.alertRows(t)})
				got, gerr := e.svc.GetDefinition(context.Background(), d.ID)
				require.NoError(t, gerr)
				assert.Equal(t, int64(1), got.DefinitionVersion)
				assert.Equal(t, []string{"asset:view"}, got.Permissions)
			})
		}
	})

	t.Run("分級器未注入：修改有持有者的角色回錯且全部不變；無持有者無引用照常成功", func(t *testing.T) {
		e := newRoleDefEnv(t)
		held := e.create(t, "held", "asset:view")
		e.holdDirect(t, e.mkUser(t, "h"), held.ID, model.RoleSourceManual)
		free := e.create(t, "free", "asset:view")
		e.svc.grader = nil
		_, p0, v0, a0 := e.snapshot(t)
		_, err := e.update(t, held, "held", "asset:view", "asset:update")
		assert.ErrorIs(t, err, ErrRoleGraderMissing)
		_, err = e.update(t, held, "held-renamed", "asset:view")
		assert.ErrorIs(t, err, ErrRoleGraderMissing, "只改名稱也不放行")
		_, p1, v1, a1 := e.snapshot(t)
		assert.Equal(t, []int64{p0, v0, a0, 0}, []int64{p1, v1, a1, e.alertRows(t)})
		_, err = e.update(t, free, "free", "asset:view", "asset:update")
		require.NoError(t, err)
	})

	t.Run("預覽的 operation 與實際修改的事件種類、目標種類與筆數相同", func(t *testing.T) {
		type fixture struct {
			name   string
			setup  func(e *roleDefEnv, d *RoleDefinition)
			perms  []string
			marks  []string
			events []string // 預期事件類型與目標種類
		}
		for _, f := range []fixture{
			{"他人持有加管理能力", func(e *roleDefEnv, d *RoleDefinition) {
				e.holdDirect(t, e.mkUser(t, "o1"), d.ID, model.RoleSourceManual)
			},
				[]string{"asset:view", "asset:update"}, []string{authz.GrantMarkManagementGrant},
				[]string{authz.AlertKeyManagementGranted + "/role"}},
			{"本人持有並有他人持有加管理能力", func(e *roleDefEnv, d *RoleDefinition) {
				e.holdDirect(t, e.admin, d.ID, model.RoleSourceManual)
				e.holdDirect(t, e.mkUser(t, "o2"), d.ID, model.RoleSourceManual)
			}, []string{"asset:view", "asset:update"}, []string{authz.GrantMarkSelfAuthorization, authz.GrantMarkManagementGrant},
				[]string{authz.AlertKeySelfIncreased + "/user", authz.AlertKeyManagementGranted + "/role"}},
			{"本人持有只移除", func(e *roleDefEnv, d *RoleDefinition) { e.holdDirect(t, e.admin, d.ID, model.RoleSourceManual) },
				[]string{}, []string{authz.GrantMarkSelfAuthorization}, []string{authz.AlertKeySelfDecreased + "/user"}},
			{"只改名稱的集合相同", func(e *roleDefEnv, d *RoleDefinition) {
				e.holdDirect(t, e.mkUser(t, "o3"), d.ID, model.RoleSourceManual)
			},
				[]string{"asset:view"}, []string{}, []string{}},
		} {
			t.Run(f.name, func(t *testing.T) {
				e := newRoleDefEnv(t)
				d := e.create(t, "pv", "asset:view")
				f.setup(e, d)
				res, err := authz.PreviewEffectiveCapabilities(e.db, authz.PreviewRequest{
					Kind: authz.PreviewRoleDefinition, OperatorID: e.admin, RoleID: d.ID, Permissions: f.perms,
					MappingRuleCounter: RoleMappingRuleCount})
				require.NoError(t, err)
				require.NotNil(t, res.Operation)
				assert.Equal(t, f.marks, res.Operation.Marks)
				_, err = e.update(t, d, "pv-new", f.perms...)
				require.NoError(t, err)
				var got []string
				for _, ev := range e.alertEvents(t) {
					got = append(got, ev.Type+"/"+ev.TargetKind)
				}
				assert.ElementsMatch(t, append([]string{}, f.events...), append([]string{}, got...))
				// 標記與事件筆數一一對應：自我授權標記對一筆自我事件，管理類標記對一筆管理類事件
				assert.Len(t, got, len(res.Operation.Marks))
			})
		}
	})
}

func sprintID(id uint) string {
	b, _ := json.Marshal(id)
	return string(b)
}
