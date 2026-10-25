package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 範圍改變的版本、憑證世代與審計：縮小才推進世代，擴大與相同範圍不推進；
// 審計或告警事件寫入失敗時範圍、版本、世代整筆回滾。

type atomicEnv struct {
	*scopedEnv
	a, b uint
}

func newAtomicEnv(t *testing.T) *atomicEnv {
	t.Helper()
	e := &atomicEnv{scopedEnv: newScopedEnv(t)}
	e.idAdmin = e.mkUser(t, "ida", "identity_admin")
	e.create(t, "assetmgr", permStrings(authz.ScopedTemplateAssetAdminPermissions())...)
	e.users.assignmentGuard().SetNodeCoverageReader(asset.NewScopeTopologyReader())
	e.a, e.b = e.node(t, "甲"), e.node(t, "乙")
	return e
}

// revokedAll 該使用者的 refresh 憑證是否全部已撤銷（至少有一張）。
func (e *atomicEnv) revokedAll(t *testing.T, uid uint) bool {
	t.Helper()
	var total, open int64
	require.NoError(t, e.db.Model(&model.RefreshToken{}).Where("user_id = ?", uid).Count(&total).Error)
	require.NoError(t, e.db.Model(&model.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", uid).Count(&open).Error)
	return total > 0 && open == 0
}

// fingerprint 範圍列、權限版本與全體世代的指紋。
func (e *atomicEnv) fingerprint(t *testing.T) string {
	t.Helper()
	var rows []model.RoleBindingNode
	require.NoError(t, e.db.Order("subject_kind, subject_id, role_id, node_id").Find(&rows).Error)
	var kinds []string
	require.NoError(t, e.db.Table("user_roles").Order("user_id, role_id").
		Select("user_id || '/' || role_id || '/' || scope_kind").Scan(&kinds).Error)
	var gkinds []string
	require.NoError(t, e.db.Table("user_group_roles").Order("user_group_id, role_id").
		Select("user_group_id || '/' || role_id || '/' || scope_kind").Scan(&gkinds).Error)
	var sum int64
	require.NoError(t, e.db.Model(&model.User{}).Select("COALESCE(SUM(credential_epoch),0)").Scan(&sum).Error)
	return fmt.Sprintf("%v|%v|%v|v%d|e%d", rows, kinds, gkinds, e.version(t), sum)
}

func (e *atomicEnv) rangeAudits(t *testing.T, resource model.AuditResource) []map[string]any {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, e.db.Where("resource = ? AND action = ?", resource, model.ActionUpdate).
		Where("details LIKE ?", "%role_binding_range_changed%").Order("id").Find(&rows).Error)
	var out []map[string]any
	for _, r := range rows {
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.Details), &d))
		out = append(out, d)
	}
	return out
}

func (e *atomicEnv) groupWith(t *testing.T, name string, role string, nodes []uint, members ...uint) uint {
	t.Helper()
	gid := e.group(t, name, members...)
	rid := e.rid(t, role)
	_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{rid},
		RoleNodes: map[uint]RoleNodesValue{rid: nodesOf(nodes...)}})
	require.NoError(t, err)
	return gid
}

func TestScopedBindingAtomicity(t *testing.T) {
	t.Run("直接：擴大不推進世代、縮小推進世代並撤銷更新憑證、相同範圍不推進", func(t *testing.T) {
		e := newAtomicEnv(t)
		u := e.mkUser(t, "u1")
		_, err := e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.a)})
		require.NoError(t, err)
		e.refresh(t, u)
		v0, ep0 := e.version(t), e.epoch(t, u)
		_, err = e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.a, e.b)})
		require.NoError(t, err)
		assert.Equal(t, v0+1, e.version(t), "範圍改變推進一版")
		assert.Equal(t, ep0, e.epoch(t, u), "純擴大不推進世代")
		assert.False(t, e.revokedAll(t, u))
		_, err = e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.b, e.a)})
		require.NoError(t, err)
		assert.Equal(t, v0+1, e.version(t), "相同範圍重送版本不變")
		_, err = e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.a)})
		require.NoError(t, err)
		assert.Equal(t, v0+2, e.version(t))
		assert.Equal(t, ep0+1, e.epoch(t, u), "失去涵蓋推進世代")
		assert.True(t, e.revokedAll(t, u), "撤銷更新憑證")

		// 另有群組指派涵蓋乙：縮小不使本人失去涵蓋，世代不變
		u2 := e.mkUser(t, "u2")
		e.groupWith(t, "g-b", "assetmgr", []uint{e.b}, u2)
		_, err = e.assign(u2, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.a, e.b)})
		require.NoError(t, err)
		e.refresh(t, u2)
		ep2 := e.epoch(t, u2)
		_, err = e.assign(u2, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.a)})
		require.NoError(t, err)
		assert.Equal(t, ep2, e.epoch(t, u2), "另有指派涵蓋乙者世代不變")
		assert.False(t, e.revokedAll(t, u2))

		// 全域改節點也是縮小
		u3 := e.mkUser(t, "u3")
		_, err = e.assign(u3, []string{"assetmgr"}, nil)
		require.NoError(t, err)
		ep3 := e.epoch(t, u3)
		_, err = e.assign(u3, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.a)})
		require.NoError(t, err)
		assert.Equal(t, ep3+1, e.epoch(t, u3))
	})

	t.Run("群組：成員逐人判定縮小，擴大與相同範圍不推進", func(t *testing.T) {
		e := newAtomicEnv(t)
		m1, m2 := e.mkUser(t, "m1"), e.mkUser(t, "m2")
		gid := e.groupWith(t, "g", "assetmgr", []uint{e.a, e.b}, m1, m2)
		// m2 另有直接指派涵蓋乙
		_, err := e.assign(m2, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.b)})
		require.NoError(t, err)
		e.refresh(t, m1)
		e.refresh(t, m2)
		rid := e.rid(t, "assetmgr")
		put := func(nodes ...uint) {
			_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{rid},
				RoleNodes: map[uint]RoleNodesValue{rid: nodesOf(nodes...)}})
			require.NoError(t, err)
		}
		v0, e1, e2 := e.version(t), e.epoch(t, m1), e.epoch(t, m2)
		put(e.a, e.b)
		assert.Equal(t, v0, e.version(t), "相同範圍重送版本不變")
		put(e.a)
		assert.Equal(t, v0+1, e.version(t))
		assert.Equal(t, e1+1, e.epoch(t, m1), "無其他指派涵蓋乙的成員世代推進")
		assert.True(t, e.revokedAll(t, m1))
		assert.Equal(t, e2, e.epoch(t, m2), "另有指派涵蓋乙的成員世代不變")
		assert.False(t, e.revokedAll(t, m2))
		put(e.a, e.b)
		assert.Equal(t, v0+2, e.version(t))
		assert.Equal(t, e1+1, e.epoch(t, m1), "純擴大不推進世代")
	})

	t.Run("只改範圍的審計列：動作 update，帶前後範圍；角色增減列不受影響", func(t *testing.T) {
		e := newAtomicEnv(t)
		u := e.mkUser(t, "u1")
		_, err := e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.a, e.b)})
		require.NoError(t, err)
		assert.Empty(t, e.rangeAudits(t, model.ResourceUserRole), "新指派走 assign，不另寫範圍列")
		_, err = e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.a)})
		require.NoError(t, err)
		got := e.rangeAudits(t, model.ResourceUserRole)
		require.Len(t, got, 1)
		assert.Equal(t, "role_binding_range_changed", got[0]["event"])
		assert.Equal(t, []any{float64(e.a), float64(e.b)}, got[0]["range_before"])
		assert.Equal(t, []any{float64(e.a)}, got[0]["range_after"])
		assert.EqualValues(t, 2, got[0]["range_before_count"])
		assert.EqualValues(t, e.rid(t, "assetmgr"), got[0]["role_id"])
		_, err = e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": {Global: true}})
		require.NoError(t, err)
		got = e.rangeAudits(t, model.ResourceUserRole)
		require.Len(t, got, 2)
		assert.Equal(t, "global", got[1]["range_after"])

		m := e.mkUser(t, "m")
		gid := e.groupWith(t, "g", "assetmgr", []uint{e.a, e.b}, m)
		rid := e.rid(t, "assetmgr")
		_, err = e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{rid},
			RoleNodes: map[uint]RoleNodesValue{rid: nodesOf(e.b)}})
		require.NoError(t, err)
		gg := e.rangeAudits(t, model.ResourceUserGroupRole)
		require.Len(t, gg, 1)
		assert.Equal(t, "role_binding_range_changed", gg[0]["event"])
		assert.Equal(t, []any{float64(e.a), float64(e.b)}, gg[0]["range_before"])
		assert.Equal(t, []any{float64(e.b)}, gg[0]["range_after"])
		assert.EqualValues(t, gid, gg[0]["user_group_id"])
	})

	t.Run("審計或告警事件寫入失敗：範圍、版本、世代整筆回滾（直接與群組各兩案）", func(t *testing.T) {
		boom := errors.New("注入的寫入失敗")
		// 同一請求既縮小範圍（會推進世代），又新增一個管理類角色（會產生告警事件）
		type path struct {
			name string
			// setup 建好前置狀態，回傳實際寫入的動作
			setup func(t *testing.T, e *atomicEnv) func() error
		}
		paths := []path{
			{"直接", func(t *testing.T, e *atomicEnv) func() error {
				u := e.mkUser(t, "t1")
				_, err := e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(e.a, e.b)})
				require.NoError(t, err)
				e.refresh(t, u)
				return func() error {
					_, err := e.users.AssignRolesBy(e.op(e.admin), u, []string{"assetmgr", "identity_admin"},
						DirectAssignOptions{RoleNodes: map[string]RoleNodesValue{"assetmgr": nodesOf(e.a)}})
					return err
				}
			}},
			{"群組", func(t *testing.T, e *atomicEnv) func() error {
				m := e.mkUser(t, "t2")
				gid := e.groupWith(t, "g", "assetmgr", []uint{e.a, e.b}, m)
				e.refresh(t, m)
				rid := e.rid(t, "assetmgr")
				return func() error {
					_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{
						RoleIDs:   []uint{rid, e.rid(t, "identity_admin")},
						RoleNodes: map[uint]RoleNodesValue{rid: nodesOf(e.a)}})
					return err
				}
			}},
		}
		for _, p := range paths {
			for _, kind := range []string{"審計", "告警"} {
				t.Run(p.name+"："+kind+"失敗", func(t *testing.T) {
					e := newAtomicEnv(t)
					do := p.setup(t, e)
					var alerts port.SystemAlertSink = audit.NewSystemAlertSink(nil)
					if kind == "告警" {
						alerts = errAlerts{err: boom}
					}
					grader := NewGrantGrader(audit.NewTxSink(), alerts)
					e.users.SetGrantGrader(grader)
					e.svc.SetGrantGrader(grader)
					if kind == "審計" {
						if p.name == "直接" {
							const cb = "test:fail_range_audit"
							require.NoError(t, e.db.Callback().Create().Before("gorm:create").Register(cb, func(tx *gorm.DB) {
								if row, ok := tx.Statement.Dest.(*model.AuditLog); ok && strings.Contains(row.Details, "role_binding_range_changed") {
									_ = tx.AddError(boom)
								}
							}))
							t.Cleanup(func() { _ = e.db.Callback().Create().Remove(cb) })
						} else {
							e.svc = NewUserGroupService(e.db, failingRangeSink{}, noopRevoker{})
							e.svc.SetAssignmentGuard(e.users.assignmentGuard())
							e.svc.SetGrantGrader(grader)
						}
					}
					before := e.fingerprint(t)
					err := do()
					require.Error(t, err)
					assert.ErrorContains(t, err, "失敗")
					assert.Equal(t, before, e.fingerprint(t), "範圍、版本、世代全回滾")
				})
			}
		}
	})
}

// failingRangeSink 只讓「只改範圍」的審計寫入失敗，其餘照常落地。
type failingRangeSink struct{}

func (failingRangeSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	if strings.Contains(ev.Details, "role_binding_range_changed") {
		return errors.New("注入的審計寫入失敗")
	}
	return audit.NewTxSink().WriteInTx(tx, ev)
}
