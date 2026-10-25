package asset

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

// 背景派送的判定短交易：判定（輪替成員另含派送領取）與拓撲寫入經同一把拓撲序列化鎖排成單一序列。
//
// 兩種提交順序：
//   - 移出先提交：該步的判定看到新範圍，不領取、不送出（記撤權碼），同批其他目標照常；
//   - 判定（領取）先提交：該步依當下範圍送出恰一次，移出在其後完成，同一工作的下一步看到新範圍而不送出。
//
// SQLite 跑法在交易外的同步點注入移出；PostgreSQL 跑法另以 pg_locks 正向證明移出交易確實在
// 拓撲鎖上等待、擋住它的正是判定交易（pg_move_first、pg_claim_first）。

// stBeforeRotateExecutor 遠端替身：Rotate 之前呼叫 before（交易外、判定已提交之後的同步點）。
type stBeforeRotateExecutor struct {
	*secretRecorder
	before func(host string)
}

func (h stBeforeRotateExecutor) Rotate(ctx context.Context, t rotationTarget, old, next []byte) error {
	if h.before != nil {
		h.before(t.asset.Host)
	}
	return h.secretRecorder.Rotate(ctx, t, old, next)
}

// stMover 把資產移到指定節點的拓撲寫入；SQLite 直接改列，PostgreSQL 開交易、第一個動作取拓撲鎖。
type stMover func(t *testing.T, node uint, assetIDs ...uint)

func (g *rtFixture) sqliteMover() stMover {
	return func(t *testing.T, node uint, assetIDs ...uint) {
		t.Helper()
		for _, id := range assetIDs {
			g.place(t, id, node)
		}
	}
}

// stMemberSetup 由批次發起的拆分（資產上界）：兩台放在 in，範圍化主體持帳號改密、憑證改密與脫離。
func stMemberSetup(t *testing.T, g *rtFixture, h1, h2 string, initiator uint) (*model.ChangeSecretBatch, []uint, map[uint]string) {
	t.Helper()
	grantRtSplit(g)
	_, assets, _ := g.sharedInNode(t, h1, h2, g.in)
	batch, assetIDs, err := g.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), initiator, "rt-init")
	require.NoError(t, err)
	require.Len(t, assetIDs, 2)
	return batch, assetIDs, map[uint]string{assets[0]: h1, assets[1]: h2}
}

// memberAsset 成員所在資產；tx 非 nil（交易內的同步點）時必須經 tx 讀，單連線的測試庫另開語句會互等。
func (g *rtFixture) memberAsset(t *testing.T, memberID uint, tx ...*gorm.DB) uint {
	t.Helper()
	q := g.db
	if len(tx) > 0 && tx[0] != nil {
		q = tx[0]
	}
	var m model.CredentialRotationMember
	require.NoError(t, q.First(&m, memberID).Error)
	return m.AssetID
}

func (g *rtFixture) memberOnAsset(t *testing.T, assetID uint) model.CredentialRotationMember {
	t.Helper()
	var m model.CredentialRotationMember
	require.NoError(t, g.db.Where("asset_id = ?", assetID).Order("id desc").First(&m).Error)
	return m
}

func otherKey(m map[uint]string, k uint) uint {
	for id := range m {
		if id != k {
			return id
		}
	}
	return 0
}

// stMemberMoveFirst 第一個成員的判定短交易開始之前，其資產移出範圍並提交：該成員不領取、遠端 0，另一台照常。
func stMemberMoveFirst(t *testing.T, g *rtFixture, move stMover, h1, h2 string) {
	batch, assetIDs, hosts := stMemberSetup(t, g, h1, h2, rtScopedUser)
	var first uint
	g.rotations.claimHook = func(stage string, _ *gorm.DB, memberID uint) {
		if stage == claimStageBeforeTx && first == 0 {
			first = g.memberAsset(t, memberID)
			move(t, g.out, first)
		}
	}
	g.runner.RunBatch(batch, assetIDs)
	require.NotZero(t, first, "走到成員判定短交易之前的同步點")
	other := otherKey(hosts, first)
	assert.Equal(t, 0, g.rotateCalls(hosts[first]), "移出先提交：該步遠端呼叫 0")
	assert.Equal(t, 1, g.rotateCalls(hosts[other]), "同批另一台照常送出")
	m := g.memberOnAsset(t, first)
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, m.LastError)
	assert.Nil(t, m.DispatchClaimedAt, "不領取：dispatch claim 未寫入")
	assert.Equal(t, model.CredentialMemberApplied, g.memberOnAsset(t, other).State)
}

// stMemberClaimFirst 第一個成員的判定＋領取先提交，其後兩台都移出範圍：該步照領取當下的範圍送出恰一次，
// 下一個成員重驗看到新範圍而不領取。wait 非 nil 時（PostgreSQL）由它負責移出並在交易外等移出完成。
func stMemberClaimFirst(t *testing.T, g *rtFixture, move stMover, h1, h2 string,
	inTx func(tx *gorm.DB, memberID uint), afterCommit func()) {

	batch, assetIDs, hosts := stMemberSetup(t, g, h1, h2, rtScopedUser)
	var first uint
	g.rotations.claimHook = func(stage string, tx *gorm.DB, memberID uint) {
		switch {
		case stage == claimStageClaimed && first == 0:
			first = g.memberAsset(t, memberID, tx)
			if inTx != nil {
				inTx(tx, memberID)
			}
		case stage == claimStageCommitted && first != 0 && g.memberAsset(t, memberID) == first:
			if afterCommit != nil {
				afterCommit()
				return
			}
			move(t, g.out, assetIDs...)
		}
	}
	g.runner.RunBatch(batch, assetIDs)
	require.NotZero(t, first, "走到領取寫入點")
	other := otherKey(hosts, first)
	assert.Equal(t, 1, g.rotateCalls(hosts[first]), "領取先提交：該步依領取當下的範圍送出恰一次")
	assert.Equal(t, 0, g.rotateCalls(hosts[other]), "下一個成員重驗看到新範圍：遠端呼叫 0")
	fm := g.memberOnAsset(t, first)
	assert.NotNil(t, fm.DispatchClaimedAt, "第一步的領取已提交")
	om := g.memberOnAsset(t, other)
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, om.LastError)
	assert.Nil(t, om.DispatchClaimedAt, "下一步不領取")
}

// stRunnerSetup 一般逐帳號批次：兩台放在 in，範圍化主體持帳號改密。
func stRunnerSetup(t *testing.T, g *rtFixture, h1, h2 string, initiator uint) (*model.ChangeSecretBatch, []uint, map[uint]string) {
	t.Helper()
	g.az.grant(CredCapAccountRotate, g.in)
	hosts := map[uint]string{}
	var accounts []uint
	for i, h := range []string{h1, h2} {
		assetID, accountID := g.addHost(t, fmt.Sprintf("st-%s-%d", h, i), h, "ops")
		g.place(t, assetID, g.in)
		hosts[accountID] = h
		accounts = append(accounts, accountID)
	}
	batch, assetIDs, err := g.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, accounts...),
		initiator, "rt-init")
	require.NoError(t, err)
	require.Len(t, assetIDs, 2)
	return batch, assetIDs, hosts
}

func (g *rtFixture) accountAsset(t *testing.T, accountID uint) uint {
	t.Helper()
	return g.bindingOf(t, accountID).AssetID
}

func recordOf(records []model.ChangeSecretRecord, accountID uint) *model.ChangeSecretRecord {
	for i := range records {
		if records[i].AccountID == accountID {
			return &records[i]
		}
	}
	return nil
}

// stRunnerMoveFirst 候選落庫後、最後一次判定之前，第一台的資產移出並提交：該台不送出，另一台照常。
func stRunnerMoveFirst(t *testing.T, g *rtFixture, move stMover, h1, h2 string, initiator uint) (uint, []model.ChangeSecretRecord, map[uint]string) {
	batch, assetIDs, hosts := stRunnerSetup(t, g, h1, h2, initiator)
	var first uint
	g.runner.dispatchHook = func(stage string, acc uint) {
		if stage == dispatchStageCandidate && first == 0 {
			first = acc
			move(t, g.out, g.accountAsset(t, acc))
		}
	}
	records := g.runner.RunBatch(batch, assetIDs)
	require.NotZero(t, first, "走到候選落庫後的判定點")
	return first, records, hosts
}

// stRunnerJudgeFirst 第一台最後一次判定先提交，送出之前兩台都移出：該台送出恰一次，下一台不送出。
func stRunnerJudgeFirst(t *testing.T, g *rtFixture, move stMover, h1, h2 string,
	inTx func(tx *gorm.DB), beforeRotate func()) {

	batch, assetIDs, hosts := stRunnerSetup(t, g, h1, h2, rtScopedUser)
	var first uint
	armed := false
	g.runner.dispatchHook = func(stage string, acc uint) {
		if stage == dispatchStageCandidate && first == 0 {
			first, armed = acc, true
		}
	}
	g.runner.judgeTxHook = func(tx *gorm.DB, accs []uint) {
		if armed && len(accs) == 1 && accs[0] == first {
			armed = false
			if inTx != nil {
				inTx(tx)
			}
		}
	}
	moved := false
	exec := stBeforeRotateExecutor{secretRecorder: g.rec, before: func(host string) {
		if first == 0 || moved || host != hosts[first] {
			return
		}
		moved = true
		if beforeRotate != nil {
			beforeRotate()
			return
		}
		var ids []uint
		for acc := range hosts {
			ids = append(ids, g.accountAsset(t, acc))
		}
		move(t, g.out, ids...)
	}}
	g.runner.executors = func(string) rotationExecutor { return exec }
	records := g.runner.RunBatch(batch, assetIDs)
	require.NotZero(t, first)
	require.True(t, moved, "送出前的同步點走到")
	var other uint
	for acc := range hosts {
		if acc != first {
			other = acc
		}
	}
	assert.Equal(t, 1, g.rotateCalls(hosts[first]), "判定先提交：該台依判定當下的範圍送出恰一次")
	assert.Equal(t, 0, g.rotateCalls(hosts[other]), "下一台重驗看到新範圍：遠端呼叫 0")
	if rec := recordOf(records, other); assert.NotNil(t, rec) {
		assert.Equal(t, model.ChangeSecretSkipped, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, rec.Error)
	}
}

func testDispatchShortTxSQLite(t *testing.T) {
	t.Run("member_move_first", func(t *testing.T) {
		g := newRtFixture(t)
		stMemberMoveFirst(t, g, g.sqliteMover(), "10.3.30.1", "10.3.30.2")
	})
	t.Run("member_claim_first", func(t *testing.T) {
		g := newRtFixture(t)
		stMemberClaimFirst(t, g, g.sqliteMover(), "10.3.31.1", "10.3.31.2", nil, nil)
	})
	t.Run("runner_move_first", func(t *testing.T) {
		g := newRtFixture(t)
		first, records, hosts := stRunnerMoveFirst(t, g, g.sqliteMover(), "10.3.32.1", "10.3.32.2", rtScopedUser)
		for acc, h := range hosts {
			rec := recordOf(records, acc)
			require.NotNil(t, rec)
			if acc == first {
				assert.Equal(t, 0, g.rotateCalls(h), "移出先提交：該台遠端呼叫 0")
				assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, rec.Error)
				continue
			}
			assert.Equal(t, 1, g.rotateCalls(h), "同批另一台照常")
			assert.Equal(t, model.ChangeSecretSuccess, rec.Status, rec.Error)
		}
	})
	t.Run("runner_judge_first", func(t *testing.T) {
		g := newRtFixture(t)
		stRunnerJudgeFirst(t, g, g.sqliteMover(), "10.3.33.1", "10.3.33.2", nil, nil)
	})
	t.Run("credential_reassigned_next_member_not_sent", func(t *testing.T) {
		g := newRtFixture(t)
		g.az.grant(CredCapRotate, g.in)
		credID, assets, _ := g.sharedInNode(t, "10.3.34.1", "10.3.34.2", g.in)
		hosts := map[uint]string{assets[0]: "10.3.34.1", assets[1]: "10.3.34.2"}
		rot, err := g.rotations.Start(userCtx(rtScopedUser, "rt-scoped"), credID, StartRotationRequest{})
		require.NoError(t, err)
		var first uint
		g.rotations.claimHook = func(stage string, _ *gorm.DB, memberID uint) {
			if stage == claimStageCommitted && first == 0 {
				first = g.memberAsset(t, memberID)
				require.NoError(t, g.db.Model(&model.Credential{}).Where("id = ?", credID).
					Update("owner_node_id", g.out).Error)
			}
		}
		require.NoError(t, g.rotations.Run(context.Background(), rot.ID))
		require.NotZero(t, first)
		other := otherKey(hosts, first)
		assert.Equal(t, 1, g.rotateCalls(hosts[first]), "改歸前已領取的一步照常送出")
		assert.Equal(t, 0, g.rotateCalls(hosts[other]), "憑證改歸範圍外：整組輪替下一個成員不送出")
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, g.memberOnAsset(t, other).LastError)
	})
	t.Run("retry_after_move_only_verifies", func(t *testing.T) {
		// 可能已送出的候選：發起者範圍不再涵蓋該資產時只做同一候選驗證（有限收斂），不再下達新變更
		g := newRtFixture(t)
		g.retry.WithManagementAuthorizer(g.az)
		g.az.grant(CredCapAccountRotate, g.in)
		assetID, accountID := g.addHost(t, "st-retry", "10.3.35.1", "ops")
		g.place(t, assetID, g.in)
		g.rec.mu.Lock()
		g.rec.verifyErr["10.3.35.1"] = fmt.Errorf("verify transport lost")
		g.rec.mu.Unlock()
		batch, ids, err := g.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, accountID),
			rtScopedUser, "rt-scoped")
		require.NoError(t, err)
		recs := g.runner.RunBatch(batch, ids)
		require.Len(t, recs, 1)
		require.Equal(t, model.ChangeSecretUnverified, recs[0].Status, recs[0].Error)
		var cand model.ChangeSecretCandidate
		require.NoError(t, g.db.Where("account_id = ?", accountID).First(&cand).Error)
		g.rec.mu.Lock()
		delete(g.rec.verifyErr, "10.3.35.1")
		g.rec.mu.Unlock()
		g.place(t, assetID, g.out)
		_, rcBefore, vcBefore := g.rec.snapshotCalls()
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, g.retry.revalidateCandidate(context.Background(), &cand),
			"判定短交易看到新範圍")
		g.retry.RetryOne(&cand)
		_, rcAfter, vcAfter := g.rec.snapshotCalls()
		assert.Equal(t, rcBefore["10.3.35.1"], rcAfter["10.3.35.1"], "不再下達新變更")
		assert.Equal(t, vcBefore["10.3.35.1"]+1, vcAfter["10.3.35.1"], "只做同一候選驗證")
	})
	t.Run("global_initiator_unaffected", func(t *testing.T) {
		g := newRtFixture(t)
		_, records, hosts := stRunnerMoveFirst(t, g, g.sqliteMover(), "10.3.36.1", "10.3.36.2", 1)
		for acc, h := range hosts {
			assert.Equal(t, 1, g.rotateCalls(h), "全域發起者在同樣拓撲變動下照常")
			if rec := recordOf(records, acc); assert.NotNil(t, rec) {
				assert.Equal(t, model.ChangeSecretSuccess, rec.Status, rec.Error)
			}
		}
		m := newRtFixture(t)
		batch, assetIDs, mh := stMemberSetup(t, m, "10.3.37.1", "10.3.37.2", 1)
		m.rotations.claimHook = func(stage string, _ *gorm.DB, memberID uint) {
			if stage == claimStageBeforeTx {
				m.place(t, m.memberAsset(t, memberID), m.out)
			}
		}
		m.runner.RunBatch(batch, assetIDs)
		for _, h := range mh {
			assert.Equal(t, 1, m.rotateCalls(h), "全域發起者的拆分成員照常")
		}
	})
	t.Run("requeuer_loses_scope", TestBackgroundRevalidatesRequeuerAfterOwnershipLeavesScope)
}

// --- PostgreSQL ---

// newPGRtFixture 與 newRtFixture 同構，資料庫為 PG 的獨立 schema，資產服務接上取真拓撲鎖的 port。
func newPGRtFixture(t *testing.T, dsn string) (*rtFixture, *pgBatchEnv) {
	t.Helper()
	e := newPGBatchEnv(t, dsn)
	require.Equal(t, "postgres", e.f.db.Dialector.Name(), "PG 跑法不得回退 SQLite")
	f := e.f
	f.assets.SetTopologyPermissionPort(&pgTopologyPort{})
	g := &rtFixture{batchFixture: f, az: newNodeScopedAuthorizer(f.authz, rtScopedUser), rec: newSecretRecorder()}
	for name, p := range map[string]*uint{"rt-in": &g.in, "rt-out": &g.out} {
		n := model.AssetGroup{Name: name}
		require.NoError(t, f.db.Create(&n).Error)
		*p = n.ID
	}
	f.batches.WithManagementAuthorizer(g.az)
	f.runner.WithManagementAuthorizer(g.az)
	f.retry.WithManagementAuthorizer(g.az)
	f.rotations.mgmt = credentialManagementGate{authorizer: g.az}
	f.useExecutor(g.rec)
	f.rotations.executors = func(string) rotationExecutor { return g.rec }
	return g, e
}

const stLockKey = `locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
   AND classid::bigint = ? AND objid::bigint = 1 AND objsubid = 2 AND pid = ?`

// pgMoveTx 移出範圍的拓撲寫入：交易開始即回報 pid，第一個動作取拓撲序列化鎖。
func pgMoveTx(db *gorm.DB, pidc chan<- int, node uint, assetIDs ...uint) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var pid int
		if err := tx.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
			return err
		}
		if pidc != nil {
			pidc <- pid
		}
		if err := (&pgTopologyPort{}).LockTopology(tx); err != nil {
			return err
		}
		for _, id := range assetIDs {
			if err := tx.Where("asset_id = ?", id).Delete(&model.AssetNode{}).Error; err != nil {
				return err
			}
			if err := tx.Create(&model.AssetNode{AssetID: id, NodeID: node}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func pgMover(e *pgBatchEnv) stMover {
	return func(t *testing.T, node uint, assetIDs ...uint) {
		t.Helper()
		require.NoError(t, pgMoveTx(e.db2, nil, node, assetIDs...))
	}
}

// pgBlockingProbe 判定交易持鎖停在交易內時：另起移出交易、以 pg_locks 正向證明它在拓撲鎖上等待、
// 擋住它的正是判定交易，然後放行判定交易。done 在移出交易完成時關閉。
type pgBlockingProbe struct {
	t        *testing.T
	e        *pgBatchEnv
	node     uint
	assetIDs func() []uint
	done     chan struct{}
	moveErr  error
	evidence string
	once     sync.Once
}

func (p *pgBlockingProbe) inTx(tx *gorm.DB) {
	p.once.Do(func() {
		t := p.t
		var holder int
		require.NoError(t, tx.Raw("SELECT pg_backend_pid()").Scan(&holder).Error)
		pidc := make(chan int, 1)
		ids := p.assetIDs()
		go func() {
			defer close(p.done)
			p.moveErr = pgMoveTx(p.e.db2, pidc, p.node, ids...)
		}()
		var mover int
		select {
		case mover = <-pidc:
		case <-time.After(5 * time.Second):
			t.Error("移出交易開始掛點未觸發")
			return
		}
		class := int64(pgTopologyClassForTest)
		waiting := false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			var n int64
			require.NoError(t, p.e.db2.Raw("SELECT count(*) FROM pg_locks WHERE NOT granted AND "+stLockKey, class, mover).
				Scan(&n).Error)
			if n == 1 {
				waiting = true
				break
			}
		}
		if !assert.True(t, waiting, "移出交易須在拓撲序列化鎖上等待（限定 database、class、key、pid，5 秒內）") {
			return
		}
		var blocked bool
		require.NoError(t, p.e.db2.Raw("SELECT ?::int = ANY(pg_blocking_pids(?::int))", holder, mover).Scan(&blocked).Error)
		assert.True(t, blocked, "擋住移出交易的正是判定交易")
		var held int64
		require.NoError(t, p.e.db2.Raw("SELECT count(*) FROM pg_locks WHERE granted AND "+stLockKey, class, holder).
			Scan(&held).Error)
		assert.Equal(t, int64(1), held, "同一 database 與 key 上判定交易 granted 恰 1 列")
		p.evidence = fmt.Sprintf("EVIDENCE holder_pid=%d mover_pid=%d class=%d objid=1 objsubid=2 waiting=true blocked_by_holder=%v holder_granted=%d",
			holder, mover, class, blocked, held)
		fmt.Println(p.evidence)
	})
}

// waitMoved 交易外的同步點：等移出交易完成（判定交易已提交，鎖已釋放）。
func (p *pgBlockingProbe) waitMoved() {
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		p.t.Error("判定交易提交後移出交易未在 10 秒內完成")
	}
	assert.NoError(p.t, p.moveErr)
}

func testDispatchShortTxPGMoveFirst(t *testing.T) {
	dsn := os.Getenv(testgate.EnvPGDSN)
	if dsn == "" {
		t.Skip("未設定 TEST_PG_DSN：PostgreSQL 的提交順序子案例只在 PG 跑法計入（SQLite 的同語義案例見 sqlite_orders）")
	}
	t.Run("member_claim", func(t *testing.T) {
		g, e := newPGRtFixture(t, dsn)
		stMemberMoveFirst(t, g, pgMover(e), "10.3.40.1", "10.3.40.2")
	})
	t.Run("runner_judge", func(t *testing.T) {
		g, e := newPGRtFixture(t, dsn)
		first, records, hosts := stRunnerMoveFirst(t, g, pgMover(e), "10.3.41.1", "10.3.41.2", rtScopedUser)
		for acc, h := range hosts {
			if acc == first {
				assert.Equal(t, 0, g.rotateCalls(h), "移出先提交：該台遠端呼叫 0")
				if rec := recordOf(records, acc); assert.NotNil(t, rec) {
					assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, rec.Error)
				}
				continue
			}
			assert.Equal(t, 1, g.rotateCalls(h), "同批另一台照常")
		}
	})
	fmt.Println("EVIDENCE dialect=postgres")
}

func testDispatchShortTxPGClaimFirst(t *testing.T) {
	dsn := os.Getenv(testgate.EnvPGDSN)
	if dsn == "" {
		t.Skip("未設定 TEST_PG_DSN：PostgreSQL 的提交順序子案例只在 PG 跑法計入（SQLite 的同語義案例見 sqlite_orders）")
	}
	t.Run("member_claim", func(t *testing.T) {
		g, e := newPGRtFixture(t, dsn)
		var assetIDs []uint
		p := &pgBlockingProbe{t: t, e: e, node: g.out, done: make(chan struct{}),
			assetIDs: func() []uint { return assetIDs }}
		// 兩台都移出：資產清單在領取寫入點由成員表取得
		inTx := func(tx *gorm.DB, _ uint) {
			var ms []model.CredentialRotationMember
			require.NoError(t, tx.Find(&ms).Error)
			for _, m := range ms {
				assetIDs = append(assetIDs, m.AssetID)
			}
			p.inTx(tx)
		}
		stMemberClaimFirst(t, g, nil, "10.3.42.1", "10.3.42.2", inTx, p.waitMoved)
		require.NotEmpty(t, p.evidence, "pg_locks 正向證據")
	})
	t.Run("runner_judge", func(t *testing.T) {
		g, e := newPGRtFixture(t, dsn)
		var assetIDs []uint
		p := &pgBlockingProbe{t: t, e: e, node: g.out, done: make(chan struct{}),
			assetIDs: func() []uint { return assetIDs }}
		inTx := func(tx *gorm.DB) {
			var accs []model.AssetAccount
			require.NoError(t, tx.Where("username = ?", "ops").Find(&accs).Error)
			for _, a := range accs {
				assetIDs = append(assetIDs, a.AssetID)
			}
			p.inTx(tx)
		}
		stRunnerJudgeFirst(t, g, nil, "10.3.43.1", "10.3.43.2", inTx, p.waitMoved)
		require.NotEmpty(t, p.evidence, "pg_locks 正向證據")
	})
	fmt.Println("EVIDENCE dialect=postgres")
}
