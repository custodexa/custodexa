package asset_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 序列化鎖先於列鎖（PostgreSQL）：另一條連線持拓撲序列化鎖時，四種寫入各自啟動；
// 觀測連線先正向確認寫入方交易正在等這把鎖、擋住它的正是持鎖連線，再由第三條連線以
// FOR UPDATE NOWAIT 探測該寫入會碰的列皆未被鎖住。寫入方的 backend pid 在交易開始時
// （連線池的 BeginTx）以 pg_backend_pid() 取得。

const swWaitDeadline = 5 * time.Second

// swPidPool 包住 *sql.DB：每開一筆交易即在該交易上取 backend pid。
type swPidPool struct {
	*sql.DB
	mu   sync.Mutex
	pids []int64
}

func (p *swPidPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	tx, err := p.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	var pid int64
	if err := tx.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	p.mu.Lock()
	p.pids = append(p.pids, pid)
	p.mu.Unlock()
	return tx, nil
}

func (p *swPidPool) GetDBConn() (*sql.DB, error) { return p.DB, nil }

func (p *swPidPool) reset() {
	p.mu.Lock()
	p.pids = nil
	p.mu.Unlock()
}

func (p *swPidPool) began() []int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int64(nil), p.pids...)
}

func swOpenSQL(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	db := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// swHolder 一條釘住的連線：開交易並持拓撲序列化鎖。
type swHolder struct {
	conn *sql.Conn
	pid  int64
}

func swHoldTopologyLock(t *testing.T, db *sql.DB) *swHolder {
	t.Helper()
	ctx := context.Background()
	c, err := db.Conn(ctx)
	require.NoError(t, err)
	_, err = c.ExecContext(ctx, "BEGIN")
	require.NoError(t, err)
	h := &swHolder{conn: c}
	require.NoError(t, c.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&h.pid))
	_, err = c.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1, 1)", authz.TopologySerializationLockClass)
	require.NoError(t, err)
	return h
}

func (h *swHolder) release(t *testing.T) {
	t.Helper()
	_, err := h.conn.ExecContext(context.Background(), "ROLLBACK")
	require.NoError(t, err)
	_ = h.conn.Close()
}

const swWaitingSQL = `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'
 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
 AND classid::bigint = $1 AND objid = 1 AND objsubid = 2 AND pid = $2 AND NOT granted`

const swHeldSQL = `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'
 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
 AND classid::bigint = $1 AND objid = 1 AND objsubid = 2 AND pid = $2 AND granted`

// swProveWaiting 輪詢（上限 5 秒）寫入方交易 pid 出現且正在等拓撲序列化鎖，並確認擋住它的是持鎖連線。
func swProveWaiting(t *testing.T, obs *sql.DB, pool *swPidPool, holder *swHolder) int64 {
	t.Helper()
	ctx := context.Background()
	class := int64(authz.TopologySerializationLockClass)
	deadline := time.Now().Add(swWaitDeadline)
	for time.Now().Before(deadline) {
		for _, pid := range pool.began() {
			var n int64
			require.NoError(t, obs.QueryRowContext(ctx, swWaitingSQL, class, pid).Scan(&n))
			if n != 1 {
				continue
			}
			var blocked bool
			require.NoError(t, obs.QueryRowContext(ctx, "SELECT $1::int = ANY(pg_blocking_pids($2::int))",
				holder.pid, pid).Scan(&blocked))
			require.True(t, blocked, "擋住寫入方的須是持鎖連線")
			var held int64
			require.NoError(t, obs.QueryRowContext(ctx, swHeldSQL, class, holder.pid).Scan(&held))
			require.Equal(t, int64(1), held, "持鎖連線在同一 database 與 key 上恰持有一列")
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("5 秒內未確認寫入方交易正在等拓撲序列化鎖")
	return 0
}

// swProbe 第三條連線以 FOR UPDATE NOWAIT 探測列；被鎖時 NOWAIT 立刻回錯。
func swProbe(t *testing.T, db *sql.DB, what, query string, args ...any) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, query, args...)
	require.NoError(t, err, "%s：寫入方等序列化鎖時不得已持有此列的鎖", what)
	n := 0
	for rows.Next() {
		n++
	}
	require.NoError(t, rows.Err(), what)
	_ = rows.Close()
	require.Positive(t, n, "%s：探測須真的碰到列", what)
}

func runLockBeforeRowLocks(t *testing.T) {
	e := newSwEnv(t)
	require.Equal(t, "postgres", e.db.Dialector.Name(), "設了 PG 連線字串時不得回退 SQLite")
	cred, err := e.creds.Create(asset.WithSystemCaller(e.ctx(e.super)), &asset.CreateCredentialRequest{
		Name: "sw-shared-c", Username: "shared", Password: "pw", ProtocolFamily: model.ProtocolFamilySSH})
	require.NoError(t, err)
	bound := func(name string) uint {
		a, err := e.svc.Create(asset.WithSystemCaller(e.ctx(e.super)), &asset.CreateAssetRequest{
			Name: name, Protocol: model.ProtocolSSH, Host: "10.67.0.1", Port: 22, CreatedBy: e.super,
			NodeIDs: e.ids("sw-a"), CredentialID: cred.ID})
		require.NoError(t, err)
		return a.ID
	}
	moving, disabling, deleting := bound("sw-lock-move"), bound("sw-lock-off"), e.asset("sw-lock-del", "sw-a", "sw-c")

	pool := &swPidPool{DB: swOpenSQL(t, e.dsn)}
	pool.DB.SetMaxOpenConns(6)
	writerDB, err := gorm.Open(postgres.New(postgres.Config{Conn: pool}), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	database.DB = writerDB // 寫入方走 pid 連線池；newSwEnv 的 Cleanup 還原
	side := swOpenSQL(t, e.dsn)
	side.SetMaxOpenConns(4)

	credRow := `SELECT id FROM credentials WHERE id = $1 FOR UPDATE NOWAIT`
	assetRow := `SELECT id FROM assets WHERE id = $1 FOR UPDATE NOWAIT`
	cases := []struct {
		name   string
		run    func() error
		probes func(t *testing.T)
	}{
		{"create_with_shared_credential", func() error {
			_, err := e.svc.Create(e.ctx(e.super), &asset.CreateAssetRequest{Name: "sw-lock-new", Protocol: model.ProtocolSSH,
				Host: "10.67.0.2", Port: 22, CreatedBy: e.super, NodeIDs: e.ids("sw-a"), CredentialID: cred.ID})
			return err
		}, func(t *testing.T) {
			swProbe(t, side, "建立：共用憑證列", credRow, cred.ID)
		}},
		{"node_ids_update", e.setNodes(e.super, moving, "sw-a", "sw-b"), func(t *testing.T) {
			swProbe(t, side, "掛載更新：資產列", assetRow, moving)
			swProbe(t, side, "掛載更新：共用憑證列", credRow, cred.ID)
		}},
		{"pure_disable", e.disable(e.super, disabling), func(t *testing.T) {
			swProbe(t, side, "純停用：資產列", assetRow, disabling)
			swProbe(t, side, "純停用：共用憑證列", credRow, cred.ID)
		}},
		{"delete", e.del(e.super, deleting), func(t *testing.T) {
			swProbe(t, side, "刪除：資產列", assetRow, deleting)
			swProbe(t, side, "刪除：asset_nodes 列", `SELECT asset_id FROM asset_nodes WHERE asset_id = $1 FOR UPDATE NOWAIT`, deleting)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			holder := swHoldTopologyLock(t, side)
			pool.reset()
			done := make(chan error, 1)
			go func() { done <- c.run() }()
			released := false
			defer func() {
				if !released {
					holder.release(t)
					<-done
				}
			}()
			pid := swProveWaiting(t, side, pool, holder)
			t.Logf("writer pid=%d waiting on topology lock held by pid=%d", pid, holder.pid)
			c.probes(t)
			holder.release(t)
			released = true
			select {
			case err := <-done:
				require.NoError(t, err, "放行後寫入完成")
			case <-time.After(30 * time.Second):
				t.Fatal("放行後寫入未完成")
			}
		})
	}
	assert.Equal(t, fmt.Sprint([]string{"sw-a", "sw-b"}), fmt.Sprint(e.mounted(moving)))
}
