package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 審核範圍建立與節點搬移的兩種先後（PostgreSQL）：兩條連線、真交易，先行者以拓撲鎖取得後的掛點停住，
// 後行者在拓撲序列化鎖上等待；等待以限定 database、key、pid 的 pg_locks 與 pg_blocking_pids 證明。
// 兩個交易的 pid 由掛點在各自交易取拓撲鎖的語句之前以 pg_backend_pid() 取得（依取鎖嘗試的先後記錄）。

type apsRaceProbe struct {
	mu      sync.Mutex
	pids    []int64
	writes  []string // 觀測窗內完成的寫入語句
	record  atomic.Bool
	first   atomic.Bool
	paused  chan struct{}
	release chan struct{}
}

func (p *apsRaceProbe) pid(t *testing.T, i int) int64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		if len(p.pids) > i {
			v := p.pids[i]
			p.mu.Unlock()
			return v
		}
		p.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("第 %d 個交易未在 5 秒內嘗試取拓撲鎖", i+1)
	return 0
}

func (e *apsEnv) installRaceProbe(t *testing.T) *apsRaceProbe {
	t.Helper()
	p := &apsRaceProbe{paused: make(chan struct{}), release: make(chan struct{})}
	cb := e.db.Callback()
	require.NoError(t, cb.Raw().Before("gorm:raw").Register("aps:pid", func(d *gorm.DB) {
		if !strings.Contains(d.Statement.SQL.String(), "pg_advisory_xact_lock") {
			return
		}
		var pid int64
		if err := d.Statement.ConnPool.QueryRowContext(d.Statement.Context, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			_ = d.AddError(err)
			return
		}
		p.mu.Lock()
		p.pids = append(p.pids, pid)
		p.mu.Unlock()
	}))
	rec := func(d *gorm.DB) {
		if p.record.Load() {
			p.mu.Lock()
			p.writes = append(p.writes, d.Statement.SQL.String())
			p.mu.Unlock()
		}
	}
	require.NoError(t, cb.Create().After("gorm:create").Register("aps:rec-c", rec))
	require.NoError(t, cb.Update().After("gorm:update").Register("aps:rec-u", rec))
	require.NoError(t, cb.Delete().After("gorm:delete").Register("aps:rec-d", rec))
	restore := authz.SetTopologyLockAcquiredHookForTest(func(*gorm.DB) {
		if p.first.CompareAndSwap(false, true) {
			close(p.paused)
			<-p.release
		}
	})
	t.Cleanup(restore)
	return p
}

// proveWaiting 證明 waiter 正在等 holder 持有的拓撲序列化鎖（上限 5 秒）。
func (e *apsEnv) proveWaiting(t *testing.T, waiter, holder int64) {
	t.Helper()
	const q = `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'
		AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		AND classid::bigint = ? AND objid::bigint = 1 AND objsubid = 2 AND pid = ? AND %s`
	deadline := time.Now().Add(5 * time.Second)
	var waiting int64
	for time.Now().Before(deadline) {
		require.NoError(t, e.obs.Raw(fmt.Sprintf(q, "NOT granted"), int64(authz.TopologySerializationLockClass), waiter).Scan(&waiting).Error)
		if waiting == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.EqualValues(t, 1, waiting, "後行交易 pid=%d 未在 5 秒內出現在拓撲鎖的等待列", waiter)
	var blocked bool
	require.NoError(t, e.obs.Raw("SELECT ?::int = ANY(pg_blocking_pids(?::int))", holder, waiter).Scan(&blocked).Error)
	require.True(t, blocked, "後行交易 pid=%d 須被先行交易 pid=%d 擋住", waiter, holder)
	var held int64
	require.NoError(t, e.obs.Raw(fmt.Sprintf(q, "granted"), int64(authz.TopologySerializationLockClass), holder).Scan(&held).Error)
	require.EqualValues(t, 1, held, "先行交易 pid=%d 須恰持有一列拓撲鎖", holder)
	fmt.Printf("APS-RACE waiter_pid=%d holder_pid=%d waiting=%d blocked=%v held=%d\n", waiter, holder, waiting, blocked, held)
}

// moveAudit 最新一筆搬移審計的 topology_coverage。
func (e *apsEnv) moveAudit(t *testing.T) (model.AuditLog, map[string]any) {
	t.Helper()
	var row model.AuditLog
	require.NoError(t, e.db.Where("details LIKE ?", "%topology_coverage%").Order("id desc").First(&row).Error)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(row.Details), &m), row.Details)
	cov, _ := m["topology_coverage"].(map[string]any)
	require.NotNil(t, cov, row.Details)
	return row, cov
}

func coverageHasApprover(cov map[string]any, side string, id uint) bool {
	ap, _ := cov["approvers"].(map[string]any)
	lst, _ := ap[side].(map[string]any)
	items, _ := lst["items"].([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		if v, ok := m["id"].(float64); ok && uint(v) == id && m["kind"] == "user" {
			return true
		}
	}
	return false
}

func runAPSRace(t *testing.T, moveFirst bool) {
	name := "aps_race_create_first"
	if moveFirst {
		name = "aps_race_move_first"
	}
	e := apsEnvFor(t, name)
	require.NotNil(t, e.obs, "競態子案例只在 PostgreSQL 跑")
	ap := e.approver("aps-race-ap")
	op := e.user("aps-race-op")
	e.grantNodes(op, e.role(authz.PermApproverScopeManage), "prod")
	e.hostAsset("aps-race-asset", "10.66.9.9", "prod/db/a")
	superP, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, e.super, authz.TokenFacts{})
	require.NoError(t, err)
	moverCtx := authz.ContextWithPrincipal(context.Background(), superP)
	sitID := e.id("sit")
	moveNode := e.id("prod/db/a")
	target := e.id("prod/db")
	if moveFirst {
		target = moveNode // 搬移後目標落在範圍外
	}
	probe := e.installRaceProbe(t)
	var seq atomic.Int64
	var createDone, moveDone int64
	var resp apsResp
	var moveErr error
	var wg sync.WaitGroup
	wg.Add(2)
	doCreate := func() {
		defer wg.Done()
		resp = e.do(op, http.MethodPost, "/api/v1/approver-scopes", map[string]any{"approver_id": ap, "asset_group_id": target})
		createDone = seq.Add(1)
	}
	doMove := func() {
		defer wg.Done()
		_, moveErr = e.svc2Move(moverCtx, moveNode, &sitID)
		moveDone = seq.Add(1)
	}
	before := e.scopeCount()
	if moveFirst {
		go doMove()
	} else {
		go doCreate()
	}
	select {
	case <-probe.paused:
	case <-time.After(10 * time.Second):
		t.Fatal("先行交易未在 10 秒內取得拓撲鎖")
	}
	holder := probe.pid(t, 0)
	probe.record.Store(true)
	if moveFirst {
		go doCreate()
	} else {
		go doMove()
	}
	waiter := probe.pid(t, 1)
	e.proveWaiting(t, waiter, holder)
	probe.mu.Lock()
	writes := append([]string(nil), probe.writes...)
	probe.mu.Unlock()
	require.Empty(t, writes, "後行交易在拓撲鎖上等待時不得已完成任何寫入")
	if !moveFirst {
		var parent *uint
		require.NoError(t, e.obs.Raw("SELECT parent_id FROM asset_groups WHERE id = ?", moveNode).Scan(&parent).Error)
		require.NotNil(t, parent)
		require.Equal(t, e.id("prod/db"), *parent, "等待期間節點尚未搬移")
	}
	probe.record.Store(false)
	close(probe.release)
	wg.Wait()
	require.NoError(t, moveErr)
	moveRow, cov := e.moveAudit(t)
	createAudit := model.AuditLog{}
	require.NoError(t, e.db.Where("resource = ?", "approver_scope").Order("id desc").First(&createAudit).Error)
	fmt.Printf("EVIDENCE dialect=%s subcase=%s holder_pid=%d waiter_pid=%d\n", e.db.Dialector.Name(), name, holder, waiter)
	if moveFirst {
		assert.Less(t, moveDone, createDone, "搬移先提交")
		assert.Equal(t, http.StatusNotFound, resp.code, resp.raw)
		assert.Equal(t, before, e.scopeCount(), "範圍拒絕不寫入")
		assert.Equal(t, model.StatusDenied, createAudit.Status)
		assert.Less(t, moveRow.ID, createAudit.ID, "搬移審計先於建立的拒絕審計")
		missing := e.do(op, http.MethodPost, "/api/v1/approver-scopes", map[string]any{"approver_id": ap, "asset_group_id": apsMissing})
		assert.Equal(t, missing, resp, "搬移後的範圍外與不存在同形")
		return
	}
	assert.Less(t, createDone, moveDone, "建立先完成")
	require.Equal(t, http.StatusCreated, resp.code, resp.raw)
	assert.Equal(t, before+1, e.scopeCount())
	assert.Equal(t, model.StatusSuccess, createAudit.Status)
	var created model.ApproverScope
	require.NoError(t, e.db.Where("asset_group_id = ? AND approver_id = ?", target, ap).First(&created).Error)
	assert.False(t, moveRow.CreatedAt.Before(created.CreatedAt), "搬移提交晚於建立")
	assert.True(t, coverageHasApprover(cov, "lost", ap), "搬移的拓撲審計須涵蓋新建的審核範圍：%v", cov)
}

// svc2Move 以節點樹服務搬移節點（超級管理者脈絡）。
func (e *apsEnv) svc2Move(ctx context.Context, id uint, parent *uint) (*model.AssetGroup, error) {
	return e.nodeScopeEnv.svc.Move(ctx, id, parent, e.super, "super", "127.0.0.1")
}
