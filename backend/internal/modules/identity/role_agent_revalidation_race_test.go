package identity

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
)

// 角色修改與指派在 PostgreSQL 上以兩條連線並發的排程夾具（只在 TEST_PG_DSN 非空時使用）。
// 修改交易在寫入新集合之後暫停（已鎖角色列、未提交），指派在另一條連線送出；
// 以第三條連線查 pg_stat_activity／pg_blocking_pids／pg_locks 正向證明指派正在等修改交易的鎖，
// 兩筆交易確實重疊，之後才依排程放行。

const raceWait = 60 * time.Second

// gate 一次性的開關：open 可重複呼叫；測試結束時一律打開，避免失敗路徑留下卡住的 goroutine。
type gate struct {
	ch   chan struct{}
	once sync.Once
}

func newGate(t *testing.T) *gate {
	g := &gate{ch: make(chan struct{})}
	t.Cleanup(g.open)
	return g
}

func (g *gate) open() { g.once.Do(func() { close(g.ch) }) }

// wait 只在測試 goroutine 呼叫：逾時即終止測試。
func (g *gate) wait(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.ch:
	case <-time.After(raceWait):
		t.Fatalf("等待逾時：%s", what)
	}
}

// block 在非測試 goroutine（交易內掛點）呼叫：逾時記錯誤後放行。
func (g *gate) block(t *testing.T, what string) {
	select {
	case <-g.ch:
	case <-time.After(raceWait):
		t.Errorf("掛點等待逾時：%s", what)
	}
}

func waitErr(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(raceWait):
		t.Fatalf("等待逾時：%s", what)
		return nil
	}
}

type pgRace struct {
	e       *revalEnv
	role    *RoleDefinition
	ver0    int64
	agent   uint
	appName string
	dbB     *gorm.DB // 指派用連線
	dbC     *gorm.DB // 觀察用連線
	usersB  *UserService
	pidU    int64 // 修改交易的 backend（在 uPaused 打開前寫入）
	uPaused *gate
	uRelease,
	sPaused, sRelease *gate
}

func openPG(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sd, e := db.DB(); e == nil {
			_ = sd.Close()
		}
	})
	return db
}

func newPGRace(t *testing.T, e *revalEnv, name string) *pgRace {
	t.Helper()
	require.NotEmpty(t, e.pgDSN)
	r := &pgRace{e: e, appName: "reval_assign_" + strings.ReplaceAll(name, "-", "_")}
	r.role = e.create(t, name, "asset:view")
	_, r.ver0 = e.roleState(t, r.role.ID)
	r.agent = e.mkAgent(t, "ag-"+name)
	r.dbB = openPG(t, e.pgDSN+" application_name="+r.appName)
	r.dbC = openPG(t, e.pgDSN)
	r.usersB = NewUserService(r.dbB, nil)
	r.usersB.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	r.usersB.SetGrantGrader(e.grader)
	r.uPaused, r.uRelease, r.sPaused, r.sRelease = newGate(t), newGate(t), newGate(t), newGate(t)

	// 修改側暫停點：寫入新集合的第一列之後（角色列已鎖、新集合已寫、未提交）
	fired := false
	require.NoError(t, e.db.Callback().Create().After("gorm:create").Register("test:pause_after_role_perms", func(tx *gorm.DB) {
		if fired || tx.Error != nil || tx.Statement.Table != "role_permissions" {
			return
		}
		fired = true
		var pid int64
		if err := tx.Session(&gorm.Session{NewDB: true}).Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
			t.Errorf("讀取修改交易 backend 失敗: %v", err)
		}
		r.pidU = pid
		r.uPaused.open()
		r.uRelease.block(t, "修改交易暫停")
	}))
	t.Cleanup(func() { _ = e.db.Callback().Create().Remove("test:pause_after_role_perms") })
	t.Cleanup(func() { assert.True(t, fired, "修改側暫停點必須被走到") })
	return r
}

// pauseAssignAfterInsert 指派側暫停點：寫入 user_roles 之後、提交之前。
func (r *pgRace) pauseAssignAfterInsert(t *testing.T) {
	t.Helper()
	fired := false
	require.NoError(t, r.dbB.Callback().Raw().After("gorm:raw").Register("test:pause_after_user_role", func(tx *gorm.DB) {
		if fired || tx.Error != nil || !strings.HasPrefix(tx.Statement.SQL.String(), "INSERT INTO user_roles") {
			return
		}
		fired = true
		r.sPaused.open()
		r.sRelease.block(t, "指派交易暫停")
	}))
	t.Cleanup(func() { assert.True(t, fired, "指派側暫停點必須被走到") })
}

func (r *pgRace) startUpdate(ctx context.Context, restricted string) <-chan error {
	ch := make(chan error, 1)
	go func() {
		_, err := r.e.svc.Update(ctx, r.e.admin, r.role.ID, r.ver0, RoleInput{Name: r.role.Name, Permissions: []string{"asset:view", restricted}})
		ch <- err
	}()
	return ch
}

func (r *pgRace) startAssign() <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- r.usersB.AddRoleBy(r.e.op(), r.agent, r.role.Name) }()
	return ch
}

type pgActivity struct {
	Pid           int64
	State         string
	WaitEventType string
	WaitEvent     string
	Blocking      string
	Query         string
}

type pgLockRow struct {
	Locktype string
	Relation string
	Mode     string
	Granted  bool
}

// proveAssignWaitsOnUpdate 正向證明：指派連線的 backend 在等鎖，且擋住它的正是尚未提交的修改交易。
// 這同時證明兩筆交易重疊（指派在修改提交前已送出語句）。
func (r *pgRace) proveAssignWaitsOnUpdate(t *testing.T) {
	t.Helper()
	require.NotZero(t, r.pidU)
	deadline := time.Now().Add(raceWait)
	var last []pgActivity
	for time.Now().Before(deadline) {
		last = nil
		require.NoError(t, r.dbC.Raw(`SELECT pid, COALESCE(state, '') AS state, COALESCE(wait_event_type, '') AS wait_event_type,
			COALESCE(wait_event, '') AS wait_event, pg_blocking_pids(pid)::text AS blocking, left(query, 160) AS query
			FROM pg_stat_activity WHERE application_name = ?`, r.appName).Scan(&last).Error)
		for _, a := range last {
			var blockedByU bool
			require.NoError(t, r.dbC.Raw("SELECT ? = ANY(pg_blocking_pids(?::int))", r.pidU, a.Pid).Scan(&blockedByU).Error)
			if a.WaitEventType != "Lock" || !blockedByU {
				continue
			}
			var u pgActivity
			require.NoError(t, r.dbC.Raw(`SELECT pid, COALESCE(state, '') AS state, '' AS wait_event_type, '' AS wait_event, '' AS blocking,
				left(query, 160) AS query FROM pg_stat_activity WHERE pid = ?`, r.pidU).Scan(&u).Error)
			var locks []pgLockRow
			require.NoError(t, r.dbC.Raw(`SELECT locktype, COALESCE(relation::regclass::text, '') AS relation, mode, granted
				FROM pg_locks WHERE pid = ? AND NOT granted`, a.Pid).Scan(&locks).Error)
			t.Logf("EVIDENCE lock_wait assign_pid=%d state=%q wait=%s/%s blocking_pids=%s query=%q", a.Pid, a.State, a.WaitEventType, a.WaitEvent, a.Blocking, a.Query)
			t.Logf("EVIDENCE lock_holder update_pid=%d state=%q last_query=%q", u.Pid, u.State, u.Query)
			for _, l := range locks {
				t.Logf("EVIDENCE lock_ungranted assign_pid=%d locktype=%s relation=%q mode=%s granted=%v", a.Pid, l.Locktype, l.Relation, l.Mode, l.Granted)
			}
			require.NotEmpty(t, locks, "等鎖的 backend 應有未取得的鎖")
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("指派連線未被修改交易擋住（不計為重疊）：最後觀察 %+v", last)
}

func (r *pgRace) assertNoDeadlock(t *testing.T, errs ...error) {
	t.Helper()
	for _, err := range errs {
		if err != nil {
			assert.NotContains(t, err.Error(), "40P01")
		}
	}
}

// assertCommitted 兩筆都已提交：角色含受限鍵且版本推進一次，agent 持有該角色。
func (r *pgRace) assertCommitted(t *testing.T, restricted string) {
	t.Helper()
	perms, ver := r.e.roleState(t, r.role.ID)
	assert.Contains(t, perms, restricted)
	assert.Equal(t, r.ver0+1, ver)
	var held int64
	require.NoError(t, r.e.db.Model(&model.UserRole{}).Where("user_id = ? AND role_id = ?", r.agent, r.role.ID).Count(&held).Error)
	assert.EqualValues(t, 1, held, "指派為已提交")
}

func (r *pgRace) splitDetections(t *testing.T) (byRole, byAssign []map[string]any) {
	t.Helper()
	for _, d := range r.e.detections(t) {
		switch d["detected_by"] {
		case DetectedByRoleUpdate:
			byRole = append(byRole, d)
		case DetectedByAssignment:
			byAssign = append(byAssign, d)
		}
	}
	return byRole, byAssign
}

func (r *pgRace) alertsByPath(t *testing.T, path string) []model.SystemAlertDetail {
	t.Helper()
	out := []model.SystemAlertDetail{}
	for _, a := range r.e.agentAlerts(t) {
		var params map[string]string
		require.NoError(t, json.Unmarshal([]byte(a.Params), &params))
		if params["path"] == path {
			out = append(out, a)
		}
	}
	return out
}

// assertAlertsCorrelated 告警總數至少 1，每筆告警的關聯編號都對得到一列偵測審計。
func (r *pgRace) assertAlertsCorrelated(t *testing.T) {
	t.Helper()
	alerts := r.e.agentAlerts(t)
	require.GreaterOrEqual(t, len(alerts), 1)
	corr := map[any]bool{}
	for _, d := range r.e.detections(t) {
		corr[d["correlation_id"]] = true
	}
	for _, a := range alerts {
		assert.True(t, corr[a.CorrelationID], "告警 %d 的關聯編號對不到偵測審計", a.AlertID)
	}
}
