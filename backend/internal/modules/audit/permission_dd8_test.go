package audit_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 記錄失效事件通道呼叫的假接收端（不碰 DB，避免 sqlite 單連線在交易內死鎖）。
// fakeFailureSink 模擬持久通道的去重語意：同項同識別（since_seq、actual_hash）且未結案時不重開，
// 結案只在有未結案單時計一次（與 AuditFailureService 相同）。
type fakeFailureSink struct {
	reports  []map[string]string
	resolved []string
	open     map[string]map[string]string
}

func (f *fakeFailureSink) ReportStateMismatch(table string, params map[string]string) error {
	if f.open == nil {
		f.open = map[string]map[string]string{}
	}
	if cur, ok := f.open[table]; ok && cur["since_seq"] == params["since_seq"] && cur["actual_hash"] == params["actual_hash"] {
		return nil
	}
	p := map[string]string{"_table": table}
	for k, v := range params {
		p[k] = v
	}
	f.reports = append(f.reports, p)
	f.open[table] = p
	return nil
}
func (f *fakeFailureSink) ResolveStateMismatch(table string) error {
	if _, ok := f.open[table]; !ok {
		return nil
	}
	delete(f.open, table)
	f.resolved = append(f.resolved, table)
	return nil
}

// 只看權限維度的呼叫（其餘基礎項的對帳也會經過同一個接收端）。
func (f *fakeFailureSink) permReports() (out []map[string]string) {
	for _, r := range f.reports {
		if r["_table"] == audit.StateTablePermission {
			out = append(out, r)
		}
	}
	return
}
func (f *fakeFailureSink) permResolved() (n int) {
	for _, r := range f.resolved {
		if r == audit.StateTablePermission {
			n++
		}
	}
	return
}

func eventDelta(t *testing.T, e model.PermissionStateEvent) audit.PermissionDelta {
	var d struct {
		audit.PermissionDelta
	}
	require.NoError(t, json.Unmarshal([]byte(e.Delta), &d))
	return d.PermissionDelta
}

// 情境一：兩次合法事件之間的直寫不得併進下一筆合法事件的差集。
func TestPermissionUntracedDriftSeparated(t *testing.T) {
	e := newPermEnv(t)
	seedPerm(t, e.db, false)
	require.NoError(t, e.svc.EnsureGenesis())
	sink := &fakeFailureSink{}
	rec := audit.NewRoleStateReconciler(e.db, nil)
	rec.SetStateFailureSink(sink)
	rec.SetPermissionAttestSigner(e.signer)

	// 繞過應用層直接改庫（新增一筆直接指派），不產生事件、不推進版本。
	require.NoError(t, e.db.Exec(`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (2, 1, 'manual', 'global')`).Error)

	// 隨後的合法變更（群組指派替換）。
	require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error { return authz.SetUserGroupRoles(tx, 1, []uint{1}, 1) }))

	var events []model.PermissionStateEvent
	require.NoError(t, e.db.Order("seq").Find(&events).Error)
	require.Len(t, events, 3, "activate、untraced、change")
	require.Equal(t, model.PermEventActivate, events[0].Kind)
	require.Equal(t, model.PermEventUntraced, events[1].Kind)
	require.Equal(t, model.PermEventChange, events[2].Kind)

	untraced, legit := eventDelta(t, events[1]), eventDelta(t, events[2])
	require.NotEmpty(t, untraced.Add["user_roles"], "直寫被記在獨立的無來源事件")
	require.Empty(t, legit.Add["user_roles"], "合法事件差集不含那筆直寫")
	require.Empty(t, legit.Del["user_roles"])
	require.NotEmpty(t, legit.Add[audit.PermSetGroupRoles], "合法事件仍記下自己的變更")

	// 鏈完整可重放，但因含無來源事件，對帳如實回不符並走既有失效事件通道告警。
	rep := rec.ReconcilePermission(context.Background())
	require.Equal(t, "mismatch", rep.State, rep.Error)
	require.NotEmpty(t, rep.Extra)
	require.Len(t, sink.permReports(), 1)
	require.NotEmpty(t, sink.permReports()[0]["extra"])

	// 沒有直寫時不產生無來源事件。
	e2 := newPermEnv(t)
	seedPerm(t, e2.db, false)
	require.NoError(t, e2.svc.EnsureGenesis())
	require.NoError(t, e2.db.Transaction(func(tx *gorm.DB) error { return authz.SetUserGroupRoles(tx, 1, []uint{1}, 1) }))
	var n int64
	require.NoError(t, e2.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventUntraced).Count(&n).Error)
	require.EqualValues(t, 0, n)
	require.Equal(t, "match", e2.reconcile().State)
}

// 情境二：附證啟用前讀取失敗不擋封章，但要留痕告警；恢復後結案並完成啟用。
func TestPermissionReadFailureNotSilent(t *testing.T) {
	e := newPermEnv(t)
	seedPerm(t, e.db, false)
	sink := &fakeFailureSink{}
	rec := audit.NewRoleStateReconciler(e.db, nil)
	rec.SetStateFailureSink(sink)
	rec.SetPermissionAttestSigner(e.signer)
	e.svc.SetRoleStateReconciler(rec)

	// 讓權限狀態讀取失敗：拿掉一張來源表。
	require.NoError(t, e.db.Migrator().RenameTable("group_role_mappings", "group_role_mappings_gone"))
	require.NoError(t, e.svc.EnsureGenesis(), "讀取失敗不擋封章")
	var cp model.AuditCheckpoint
	require.NoError(t, e.db.First(&cp, "seq = 1").Error)
	require.Nil(t, cp.PermStateSnapshot, "失敗期間沒有附證")
	require.Len(t, sink.permReports(), 1, "失敗期間有告警")
	require.Equal(t, "read_failed", sink.permReports()[0]["actual_hash"])
	require.Zero(t, sink.permResolved())

	// 再失敗一次：仍只有一張單（呼叫端去重由通道負責；此處確認參數穩定不變）。
	_, err := e.svc.SealNow()
	require.NoError(t, err)
	pr := sink.permReports()
	require.Equal(t, pr[0]["actual_hash"], pr[len(pr)-1]["actual_hash"])
	require.Equal(t, pr[0]["since_seq"], pr[len(pr)-1]["since_seq"])

	// 恢復：下一次成功讀取完成啟用並結案。
	require.NoError(t, e.db.Migrator().RenameTable("group_role_mappings_gone", "group_role_mappings"))
	cp2, err := e.svc.SealNow()
	require.NoError(t, err)
	require.NotNil(t, cp2.PermStateSnapshot, "恢復後補上附證")
	require.Equal(t, 1, sink.permResolved(), "恢復後結案")
	var act int64
	require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventActivate).Count(&act).Error)
	require.EqualValues(t, 1, act, "啟用事件即對帳補記的基準")
	require.Equal(t, "match", e.reconcile().State)
}
