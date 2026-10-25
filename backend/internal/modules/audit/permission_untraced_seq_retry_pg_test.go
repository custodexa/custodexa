package audit_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 附證啟用後，兩筆並發的合法寫入同時看見同一個鏈頭並各自補寫無來源變動事件時的事件序號撞號。
// 需要真 PostgreSQL（TEST_PG_DSN；REQUIRE_INTEGRATION=1 時缺 DSN 轉為失敗）。

const seqUniqueIndex = "uq_permission_state_events_seq"

var errInjected = errors.New("注入的失敗")

func waitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("等待逾時: %s", what)
	}
}

type legalRes struct {
	pid int
	err error
}

func waitResult(t *testing.T, ch <-chan legalRes, what string) legalRes {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(40 * time.Second):
		t.Fatalf("等待逾時: %s", what)
		return legalRes{}
	}
}

type seqFx struct {
	t     *testing.T
	e     *permEnv
	admin *gorm.DB
	app   string        // 本案例連線池的 application_name；觀測查詢只看這個名稱的後端
	abort chan struct{} // 測試結束（含提前失敗）時關閉，放行所有掛點
	head  model.PermissionStateEvent
	v0    int64
}

// hold 在掛點上等待放行；測試提前失敗（abort 關閉）或逾時也會放行，不讓工作 goroutine 卡到整包逾時。
func (f *seqFx) hold(ch <-chan struct{}) {
	select {
	case <-ch:
	case <-f.abort:
	case <-time.After(60 * time.Second):
	}
}

// newSeqFx 建環境並斷言共通前置：來源已接、已啟用、鏈頭有完整性章、seq 唯一索引存在。
func newSeqFx(t *testing.T) *seqFx {
	t.Helper()
	e, schema, admin, _ := newPermEnvPG(t)
	seedPerm(t, e.db, false)
	for _, n := range []string{"g-t1", "g-t2", "g-t3"} {
		require.NoError(t, e.db.Create(&model.UserGroup{Name: n}).Error)
	}
	require.NoError(t, e.svc.EnsureGenesis())
	require.True(t, audit.PermissionSourcesWired())
	f := &seqFx{t: t, e: e, admin: admin, app: "seq_" + schema, abort: make(chan struct{})}
	var abortOnce sync.Once
	t.Cleanup(func() { abortOnce.Do(func() { close(f.abort) }) })
	require.NoError(t, e.db.Order("seq DESC").First(&f.head).Error)
	require.NotEmpty(t, f.head.IntegrityHMAC)
	var idxDef string
	require.NoError(t, e.db.Raw(`SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname = ?`, seqUniqueIndex).Scan(&idxDef).Error)
	require.Contains(t, idxDef, "UNIQUE INDEX")
	require.Contains(t, idxDef, "(seq)")
	f.v0 = f.version()
	return f
}

// driftErr 以資料庫直寫製造漂移（不經應用層），錯誤回傳給呼叫端；可在掛點內使用（不終止工作 goroutine）。
func (f *seqFx) driftErr(userID, roleID uint) error {
	return f.e.db.Exec(`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (?, ?, 'manual', 'global')`, userID, roleID).Error
}

// drift 供主測試 goroutine 使用：失敗即終止測試。
func (f *seqFx) drift(userID, roleID uint) {
	f.t.Helper()
	require.NoError(f.t, f.driftErr(userID, roleID))
}

func (f *seqFx) assertDrifted() {
	f.t.Helper()
	var head model.PermissionStateEvent
	require.NoError(f.t, f.e.db.Order("seq DESC").First(&head).Error)
	before, err := audit.DecodePermissionState([]byte(head.AfterBody))
	require.NoError(f.t, err)
	now, err := audit.ReadPermissionState(context.Background(), f.e.db)
	require.NoError(f.t, err)
	bd, err := before.Digest()
	require.NoError(f.t, err)
	nd, err := now.Digest()
	require.NoError(f.t, err)
	require.NotEqual(f.t, bd, nd, "漂移存在")
}

func (f *seqFx) version() int64 {
	v, err := authz.CurrentVersion(f.e.db)
	require.NoError(f.t, err)
	return v
}

func (f *seqFx) events() []model.PermissionStateEvent { return chainOK(f.t, f.e.db) }

// chainOK 鏈 seq 連續、prev_digest 串接、每筆 HMAC 驗證通過。
func chainOK(t *testing.T, db *gorm.DB) []model.PermissionStateEvent {
	t.Helper()
	evs := pgEventSeqsContiguous(t, db)
	for i := range evs {
		if i > 0 {
			require.Equal(t, evs[i-1].Digest, evs[i].PrevDigest, "seq=%d 串接", evs[i].Seq)
		}
		require.True(t, audit.GetAuditIntegrity().VerifyPermissionEvent(&evs[i]), "seq=%d HMAC", evs[i].Seq)
	}
	return evs
}

func countKind(evs []model.PermissionStateEvent, kind string) (n int) {
	for _, e := range evs {
		if e.Kind == kind {
			n++
		}
	}
	return
}

func (f *seqFx) groupRows(group string) (n int64) {
	require.NoError(f.t, f.e.db.Raw(`SELECT count(*) FROM user_group_roles ugr JOIN user_groups g ON g.id = ugr.user_group_id WHERE g.name = ?`, group).Scan(&n).Error)
	return
}

func (f *seqFx) auditRows(userID uint) (n int64) {
	require.NoError(f.t, f.e.db.Model(&model.AuditLog{}).Where("user_id = ?", userID).Count(&n).Error)
	return
}

func (f *seqFx) gone(group string, userID uint) {
	f.t.Helper()
	require.EqualValues(f.t, 0, f.groupRows(group), "業務列不存在")
	require.EqualValues(f.t, 0, f.auditRows(userID), "審計列不存在")
}

type legalOpt struct {
	userID uint
	level  *sql.TxOptions
	prefix func(tx *gorm.DB) error // Begin 之前同交易的寫入
	suffix func(tx *gorm.DB) error // 全部合法寫入之後
	notify bool                    // 結束後以交易擁有者的方式發提交後通知
}

// legal 以正式的群組角色寫入函式做一筆合法寫入（含審計列），在交易內第一句取 pid。
func (f *seqFx) legal(group string, o legalOpt) legalRes {
	var res legalRes
	fn := func(tx *gorm.DB) error {
		if err := tx.Raw(`SELECT pg_backend_pid()`).Scan(&res.pid).Error; err != nil {
			return err
		}
		if o.prefix != nil {
			if err := o.prefix(tx); err != nil {
				return err
			}
		}
		var gid uint
		if err := tx.Raw(`SELECT id FROM user_groups WHERE name = ?`, group).Scan(&gid).Error; err != nil {
			return err
		}
		if err := authz.SetUserGroupRoles(tx, gid, []uint{1}, 1); err != nil {
			return err
		}
		if err := tx.Create(&model.AuditLog{Action: model.ActionUpdate, Resource: model.ResourceUser, Status: "success", UserID: o.userID}).Error; err != nil {
			return err
		}
		if o.suffix != nil {
			return o.suffix(tx)
		}
		return nil
	}
	if o.level != nil {
		res.err = f.e.db.Transaction(fn, o.level)
	} else {
		res.err = f.e.db.Transaction(fn)
	}
	if o.notify {
		authz.NotifyVersionCommittedAfter(f.e.db, res.err)
	}
	return res
}

func (f *seqFx) goLegal(group string, o legalOpt) <-chan legalRes {
	ch := make(chan legalRes, 1)
	go func() { ch <- f.legal(group, o) }()
	return ch
}

// waitBlocked 等到有一個 permission_state_events 的 INSERT 在等鎖，且 pg_blocking_pids 指出阻擋者。
func (f *seqFx) waitBlocked() (waiter, blocker int) {
	f.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var pids []int
		require.NoError(f.t, f.admin.Raw(`SELECT pid FROM pg_stat_activity WHERE application_name = ? AND wait_event_type = 'Lock' AND query LIKE 'INSERT INTO "permission_state_events"%'`, f.app).Scan(&pids).Error)
		if len(pids) == 1 {
			var by []int64
			require.NoError(f.t, f.admin.Raw(`SELECT unnest(pg_blocking_pids(?))`, pids[0]).Scan(&by).Error)
			if len(by) == 1 {
				return pids[0], int(by[0])
			}
		}
		if !time.Now().Before(deadline) {
			var act []string
			f.admin.Raw(`SELECT pid::text || ' ' || coalesce(wait_event_type,'') || ' ' || coalesce(state,'') || ' ' || left(query,90) FROM pg_stat_activity WHERE application_name = ?`, f.app).Scan(&act)
			f.t.Fatalf("未觀測到 INSERT 在等鎖: %v", act)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func pgErrOf(err error) (code, constraint string) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code, pgErr.ConstraintName
	}
	return "", ""
}

func (f *seqFx) evidence(sub string, attempts int, err error, extra string) {
	code, cons := pgErrOf(err)
	f.t.Logf("EVIDENCE dialect=postgres subcase=%s attempts=%d sqlstate=%s constraint=%s %s", sub, attempts, code, cons, extra)
}

// hookCount 計數掛點：撞號次數、重試成功次數、最大嘗試序。
type hookCount struct {
	conflicts, retrySuccess, maxAttempt, inserts, savepoints atomic.Int32
}

func (c *hookCount) hooks(afterInsert func(attempt int)) audit.UntracedSeqHooks {
	return audit.UntracedSeqHooks{
		AfterCompare: func(attempt int, _ int64) {
			for {
				cur := c.maxAttempt.Load()
				if int32(attempt) <= cur || c.maxAttempt.CompareAndSwap(cur, int32(attempt)) {
					break
				}
			}
		},
		AfterInsert: func(attempt int) {
			c.inserts.Add(1)
			if attempt >= 2 {
				c.retrySuccess.Add(1)
			}
			if afterInsert != nil {
				afterInsert(attempt)
			}
		},
		AfterConflict: func(int) { c.conflicts.Add(1) },
		SavepointStep: func(step string) error {
			if step == "savepoint" {
				c.savepoints.Add(1)
			}
			return nil
		},
	}
}

// firstInsertGate 讓第一個成功插入 untraced 的交易停在插入之後，直到放行。
type firstInsertGate struct {
	f        *seqFx
	once     sync.Once
	inserted chan struct{}
	release  chan struct{}
}

func newFirstInsertGate(f *seqFx) *firstInsertGate {
	return &firstInsertGate{f: f, inserted: make(chan struct{}), release: make(chan struct{})}
}

func (g *firstInsertGate) afterInsert(int) {
	g.once.Do(func() {
		close(g.inserted)
		g.f.hold(g.release)
	})
}

// ---- 兩筆並發寫入撞同一鏈頭的標準交錯 ----

type conflictOpt struct {
	t2           legalOpt
	onConflict1  func() error        // T2 第一次撞號後（回滾前）；錯誤由主測試檢查
	onCompare2   func(headSeq int64) // T2 第二次嘗試比較後、插入前
	savepointErr func(step string) error
}

type conflictOut struct {
	conflict1Err    error // onConflict1 掛點回傳的錯誤（掛點內不呼叫 require）
	r1, r2          legalRes
	h1, h2          int64
	waiter, blocker int
	conflicts       int
	retrySuccess    int
	savepoints      int
	maxAttempt      int
	compare2Head    int64
}

// t2Attempts T2 的嘗試次數：每次嘗試以一個 savepoint 開頭，扣掉 T1（一次）與其他交易各一次。
func (o conflictOut) t2Attempts(others int) int { return o.savepoints - 1 - others }

// t2Inserts T2 的 untraced INSERT 次數（撞號次數加上重試成功的一次）。
func (o conflictOut) t2Inserts() int { return o.conflicts + o.retrySuccess }

func (f *seqFx) conflict(o conflictOpt) conflictOut {
	t := f.t
	var out conflictOut
	var mu sync.Mutex
	compareCalls, insertCalls := 0, 0
	heads := map[int]int64{}
	arrived := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	release := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	inserted, releaseInsert := make(chan struct{}), make(chan struct{})
	restore := audit.SetUntracedSeqHooksForTest(audit.UntracedSeqHooks{
		AfterCompare: func(attempt int, headSeq int64) {
			if attempt >= 2 {
				mu.Lock()
				out.maxAttempt, out.compare2Head = attempt, headSeq
				mu.Unlock()
				if o.onCompare2 != nil {
					o.onCompare2(headSeq)
				}
				return
			}
			mu.Lock()
			idx := compareCalls
			compareCalls++
			if idx < 2 {
				heads[idx] = headSeq
			}
			mu.Unlock()
			if idx < 2 {
				close(arrived[idx])
				f.hold(release[idx])
			}
		},
		AfterInsert: func(attempt int) {
			mu.Lock()
			first := insertCalls == 0
			insertCalls++
			if attempt >= 2 {
				out.retrySuccess++
			}
			mu.Unlock()
			if attempt == 1 && first {
				close(inserted)
				f.hold(releaseInsert)
			}
		},
		AfterConflict: func(attempt int) {
			mu.Lock()
			out.conflicts++
			mu.Unlock()
			if attempt == 1 && o.onConflict1 != nil {
				if err := o.onConflict1(); err != nil {
					mu.Lock()
					out.conflict1Err = err
					mu.Unlock()
				}
			}
		},
		SavepointStep: func(step string) error {
			if step == "savepoint" {
				mu.Lock()
				out.savepoints++
				mu.Unlock()
			}
			if o.savepointErr != nil {
				return o.savepointErr(step)
			}
			return nil
		},
	})
	defer restore()

	t2 := o.t2
	t2.userID = 9002
	c1 := f.goLegal("g-t1", legalOpt{userID: 9001})
	waitSignal(t, arrived[0], "T1 到達比較點")
	c2 := f.goLegal("g-t2", t2)
	waitSignal(t, arrived[1], "T2 到達比較點")
	mu.Lock()
	out.h1, out.h2 = heads[0], heads[1]
	mu.Unlock()
	require.Equal(t, f.head.Seq, out.h1)
	require.Equal(t, out.h1, out.h2, "兩者在比較點記下的 headSeq 相同")

	close(release[0])
	waitSignal(t, inserted, "T1 插入 untraced 完成")
	close(release[1])
	out.waiter, out.blocker = f.waitBlocked()
	close(releaseInsert)
	out.r1 = waitResult(t, c1, "T1")
	out.r2 = waitResult(t, c2, "T2")
	mu.Lock()
	conflict1Err := out.conflict1Err
	mu.Unlock()
	require.NoError(t, conflict1Err, "撞號後掛點內的直寫")
	require.NoError(t, out.r1.err, "T1 提交")
	require.Equal(t, out.blocker, out.r1.pid, "被觀測到的阻擋者即 T1")
	require.Equal(t, out.waiter, out.r2.pid, "被觀測到的等待者即 T2")
	mu.Lock()
	defer mu.Unlock()
	return out
}

func (f *seqFx) driftUser1() error { return f.driftErr(1, 2) }

func TestPermissionUntracedSeqRetryPG(t *testing.T) {
	t.Run("untraced_seq_conflict_pg", func(t *testing.T) {
		f := newSeqFx(t)
		f.drift(2, 1)
		f.assertDrifted()
		out := f.conflict(conflictOpt{})
		require.NoError(t, out.r2.err, "T2 應在重試後提交")
		require.Equal(t, 2, out.t2Attempts(0))
		require.Equal(t, 1, out.conflicts)
		evs := f.events()
		require.Equal(t, 1, countKind(evs, model.PermEventUntraced))
		require.EqualValues(t, 2, f.version()-f.v0, "兩筆合法寫入各推進一次")
		f.evidence("untraced_seq_conflict_pg", out.t2Attempts(0), out.r2.err,
			fmt.Sprintf("headSeq_t1=%d headSeq_t2=%d blocked_pid=%d blocker_pid=%d chain_len=%d", out.h1, out.h2, out.waiter, out.blocker, len(evs)))
	})

	t.Run("retry_rebase_no_remaining_drift", func(t *testing.T) {
		f := newSeqFx(t)
		f.drift(2, 1)
		out := f.conflict(conflictOpt{})
		require.NoError(t, out.r2.err)
		evs := f.events()
		require.Equal(t, 1, countKind(evs, model.PermEventUntraced), "全鏈 untraced 恰 1 筆")
		n := int(f.head.Seq)
		require.Equal(t, model.PermEventUntraced, evs[n].Kind, "先插入的 T1 寫出 untraced")
		require.Equal(t, model.PermEventChange, evs[n+1].Kind)
		require.Equal(t, model.PermEventChange, evs[n+2].Kind)
		ud := eventDelta(t, evs[n])
		require.Len(t, ud.Add[audit.PermSetUserRoles], 1, "untraced 差集是那筆直寫")
		var g2 uint
		require.NoError(t, f.e.db.Raw(`SELECT id FROM user_groups WHERE name='g-t2'`).Scan(&g2).Error)
		for _, c := range evs[n+1:] {
			d := eventDelta(t, c)
			require.Empty(t, d.Add[audit.PermSetUserRoles], "change 差集不含那筆直寫")
			require.Empty(t, d.Del[audit.PermSetUserRoles])
		}
		d2 := eventDelta(t, evs[n+2])
		require.Len(t, d2.Add[audit.PermSetGroupRoles], 1, "T2 的 change 差集只含 T2 的群組變更")
		require.Contains(t, d2.Add[audit.PermSetGroupRoles][0], fmt.Sprintf("[%d,", g2))
		require.Empty(t, d2.Del)
		rec := audit.NewRoleStateReconciler(f.e.db, nil)
		rec.SetStateFailureSink(&fakeFailureSink{})
		rec.SetPermissionAttestSigner(f.e.signer)
		rep := rec.ReconcilePermission(context.Background())
		require.Equal(t, "mismatch", rep.State, rep.Error)
		require.Len(t, rep.Extra, 1)
		require.Contains(t, rep.Extra[0], "user_roles")
		f.evidence("retry_rebase_no_remaining_drift", out.t2Attempts(0), out.r2.err, fmt.Sprintf("untraced=1 extra=%v", rep.Extra))
	})

	t.Run("retry_rebase_new_drift", func(t *testing.T) {
		f := newSeqFx(t)
		f.drift(2, 1)
		out := f.conflict(conflictOpt{onConflict1: f.driftUser1})
		require.NoError(t, out.r2.err)
		require.Equal(t, 2, out.t2Attempts(0))
		evs := f.events()
		require.Equal(t, 2, countKind(evs, model.PermEventUntraced), "T1 一筆、T2 重試時的新直寫一筆")
		var second *model.PermissionStateEvent
		for i := range evs {
			if evs[i].Kind == model.PermEventUntraced && evs[i].Seq > out.compare2Head {
				second = &evs[i]
			}
		}
		require.NotNil(t, second)
		require.Equal(t, out.compare2Head+1, second.Seq, "seq 等於重試時鏈頭加一")
		require.Equal(t, evs[out.compare2Head-1].Digest, second.PrevDigest)
		d := eventDelta(t, *second)
		require.Len(t, d.Add[audit.PermSetUserRoles], 1, "差集只含第二筆直寫")
		f.evidence("retry_rebase_new_drift", out.t2Attempts(0), out.r2.err, fmt.Sprintf("second_untraced_seq=%d", second.Seq))
	})

	t.Run("retry_budget_exhausted", func(t *testing.T) {
		f := newSeqFx(t)
		f.drift(2, 1)
		var step3 audit.PermissionDelta
		var t3 legalRes
		var step3Err error // 掛點內不呼叫 require（會終止工作 goroutine），改記錄錯誤由主測試檢查
		out := f.conflict(conflictOpt{
			onConflict1: f.driftUser1,
			onCompare2: func(headSeq int64) {
				var h model.PermissionStateEvent
				if err := f.e.db.Raw(`SELECT * FROM permission_state_events WHERE seq = ?`, headSeq).Scan(&h).Error; err != nil {
					step3Err = err
					return
				}
				before, err := audit.DecodePermissionState([]byte(h.AfterBody))
				if err != nil {
					step3Err = err
					return
				}
				now, err := audit.ReadPermissionState(context.Background(), f.e.db)
				if err != nil {
					step3Err = err
					return
				}
				step3 = audit.DiffPermissionState(before, now)
				t3 = f.legal("g-t3", legalOpt{userID: 9003})
			},
		})
		require.NoError(t, step3Err, "步驟 3 的掛點內讀取")
		require.Len(t, step3.Add, 1, "步驟 3：差集非空且只含設定使用者角色的權限")
		require.Len(t, step3.Add[audit.PermSetUserRoles], 1)
		require.Empty(t, step3.Del)
		require.NoError(t, t3.err, "T3 提交")
		require.Error(t, out.r2.err)
		require.True(t, errors.Is(out.r2.err, audit.ErrPermissionEventContention))
		code, cons := pgErrOf(out.r2.err)
		require.Equal(t, "23505", code)
		require.Equal(t, seqUniqueIndex, cons)
		require.Equal(t, 2, out.t2Attempts(1))
		require.Equal(t, 2, out.t2Inserts(), "T2 的 untraced INSERT 恰兩次")
		f.gone("g-t2", 9002)
		require.EqualValues(t, 1, f.groupRows("g-t3"))
		require.EqualValues(t, 2, f.version()-f.v0, "只有 T1 與 T3 推進")
		evs := f.events()
		require.Equal(t, 2, countKind(evs, model.PermEventUntraced))
		f.evidence("retry_budget_exhausted", out.t2Attempts(1), out.r2.err, fmt.Sprintf("t2_untraced_inserts=%d t3_pid=%d", out.t2Inserts(), t3.pid))
	})

	t.Run("savepoint_preserves_outer_prefix", func(t *testing.T) {
		f := newSeqFx(t)
		f.drift(2, 1)
		out := f.conflict(conflictOpt{t2: legalOpt{prefix: func(tx *gorm.DB) error {
			return tx.Create(&model.AuditLog{Action: model.ActionUpdate, Resource: model.ResourceUser, Status: "success", UserID: 9900}).Error
		}}})
		require.NoError(t, out.r2.err)
		require.Equal(t, 2, out.t2Attempts(0))
		require.EqualValues(t, 1, f.auditRows(9900), "Begin 前的標記列在提交後存在")
		evs := f.events()
		require.Equal(t, 1, countKind(evs, model.PermEventUntraced), "第一次失敗的嘗試沒有殘留事件")
		f.evidence("savepoint_preserves_outer_prefix", out.t2Attempts(0), out.r2.err, "")
	})

	t.Run("outer_failure_after_retry", func(t *testing.T) {
		f := newSeqFx(t)
		f.drift(2, 1)
		var notified atomic.Int32
		unreg := authz.RegisterVersionCommitListener(func() { notified.Add(1) })
		defer unreg()
		out := f.conflict(conflictOpt{onConflict1: f.driftUser1, t2: legalOpt{notify: true, suffix: func(*gorm.DB) error { return errInjected }}})
		require.True(t, errors.Is(out.r2.err, errInjected))
		require.Equal(t, 2, out.t2Attempts(0), "重試曾成功")
		require.Equal(t, 1, out.retrySuccess)
		f.gone("g-t2", 9002)
		require.EqualValues(t, 1, f.version()-f.v0, "只有 T1 推進")
		evs := f.events()
		require.Equal(t, 1, countKind(evs, model.PermEventUntraced), "T2 重試寫的事件隨外層回滾")
		require.Len(t, evs, int(f.head.Seq)+2, "僅 T1 的 untraced 與 change")
		require.EqualValues(t, 0, notified.Load(), "回滾不發提交後通知")
		f.evidence("outer_failure_after_retry", out.t2Attempts(0), out.r2.err, fmt.Sprintf("notified=%d", notified.Load()))
	})

	t.Run("constraint_whitelist", func(t *testing.T) {
		cases := []struct {
			name, ddl, code string
		}{
			{"other_unique", `CREATE UNIQUE INDEX uq_test_other ON permission_state_events (version)`, "23505"},
			{"check", `ALTER TABLE permission_state_events ADD CONSTRAINT ck_test_other CHECK (kind <> 'untraced')`, "23514"},
		}
		for _, c := range cases {
			f := newSeqFx(t)
			f.drift(2, 1)
			require.NoError(t, f.e.db.Exec(c.ddl).Error)
			cnt := &hookCount{}
			restore := audit.SetUntracedSeqHooksForTest(cnt.hooks(nil))
			res := f.legal("g-t2", legalOpt{userID: 9002})
			restore()
			require.Error(t, res.err)
			code, cons := pgErrOf(res.err)
			require.Equal(t, c.code, code, c.name)
			require.NotEqual(t, seqUniqueIndex, cons)
			require.False(t, errors.Is(res.err, audit.ErrPermissionEventContention))
			require.EqualValues(t, 1, cnt.savepoints.Load(), "只有一次嘗試")
			require.EqualValues(t, 1, cnt.conflicts.Load())
			f.gone("g-t2", 9002)
			f.evidence("constraint_whitelist/"+c.name, int(cnt.savepoints.Load()), res.err, "")
		}
	})

	t.Run("savepoint_failure", func(t *testing.T) {
		for _, step := range []string{"savepoint", "rollback_to", "release"} {
			step := step
			t.Run(step, func(t *testing.T) {
				f := newSeqFx(t)
				f.drift(2, 1)
				inject := func(s string) error {
					if s == step {
						return errInjected
					}
					return nil
				}
				if step == "rollback_to" {
					out := f.conflict(conflictOpt{savepointErr: inject})
					require.True(t, errors.Is(out.r2.err, errInjected))
					f.gone("g-t2", 9002)
					require.EqualValues(t, 1, f.version()-f.v0, "只有 T1 推進")
					f.events()
					f.evidence("savepoint_failure/"+step, out.t2Attempts(0), out.r2.err, "")
					return
				}
				restore := audit.SetUntracedSeqHooksForTest(audit.UntracedSeqHooks{SavepointStep: inject})
				res := f.legal("g-t2", legalOpt{userID: 9002})
				restore()
				require.True(t, errors.Is(res.err, errInjected))
				f.gone("g-t2", 9002)
				require.EqualValues(t, 0, f.version()-f.v0)
				evs := f.events()
				require.Len(t, evs, int(f.head.Seq), "沒有任何事件留下")
				f.evidence("savepoint_failure/"+step, 1, res.err, "")
			})
		}
	})

	t.Run("rr_does_not_spin", func(t *testing.T) {
		f := newSeqFx(t)
		f.drift(2, 1)
		n := f.head.Seq
		cnt := &hookCount{}
		restore := audit.SetUntracedSeqHooksForTest(cnt.hooks(nil))
		defer restore()
		frozen, go2 := make(chan struct{}), make(chan struct{})
		c2 := make(chan legalRes, 1)
		go func() {
			var res legalRes
			res.err = f.e.db.Transaction(func(tx *gorm.DB) error {
				var c int64
				if err := tx.Raw(`SELECT count(*) FROM permission_state_events`).Scan(&c).Error; err != nil {
					return err
				}
				close(frozen)
				f.hold(go2)
				return authz.SetUserGroupRoles(tx, 2, []uint{1}, 1) // 群組 g-t2
			}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			c2 <- res
		}()
		waitSignal(t, frozen, "T2 凍結快照")
		r1 := f.legal("g-t1", legalOpt{userID: 9001})
		require.NoError(t, r1.err)
		var headSeq int64
		require.NoError(t, f.e.db.Raw(`SELECT max(seq) FROM permission_state_events`).Scan(&headSeq).Error)
		require.Equal(t, n+2, headSeq, "T1 提交後鏈頭為 untraced(n+1) 加 change(n+2)")
		var kinds []string
		require.NoError(t, f.e.db.Raw(`SELECT kind FROM permission_state_events WHERE seq > ? ORDER BY seq`, n).Scan(&kinds).Error)
		require.Equal(t, []string{model.PermEventUntraced, model.PermEventChange}, kinds)
		before := cnt.inserts.Load()
		close(go2)
		r2 := waitResult(t, c2, "T2")
		require.Error(t, r2.err)
		code, _ := pgErrOf(r2.err)
		require.True(t, errors.Is(r2.err, audit.ErrPermissionEventContention) || code == "40001", "回 contention 或 40001：%v", r2.err)
		require.Equal(t, int32(1), cnt.conflicts.Load(), "T2 的 untraced INSERT 恰 1 次")
		require.Equal(t, before, cnt.inserts.Load(), "T2 沒有成功的插入")
		require.EqualValues(t, 3, cnt.savepoints.Load(), "T1 一次、T2 開了第二次嘗試的 savepoint 但重讀鏈頭未前進即停止")
		require.EqualValues(t, 0, f.groupRows("g-t2"))
		f.events()
		f.evidence("rr_does_not_spin", int(cnt.conflicts.Load()), r2.err, fmt.Sprintf("t2_untraced_inserts=%d head_after_t1=%d", cnt.conflicts.Load(), headSeq))
	})

	t.Run("untraced_vs_change_deadlock", func(t *testing.T) {
		f := newSeqFx(t)
		cnt := &hookCount{}
		gate := newFirstInsertGate(f)
		restore := audit.SetUntracedSeqHooksForTest(cnt.hooks(gate.afterInsert))
		defer restore()
		begun, goOn := make(chan struct{}), make(chan struct{})
		c2 := make(chan legalRes, 1)
		go func() {
			var res legalRes
			res.err = f.e.db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Raw(`SELECT pg_backend_pid()`).Scan(&res.pid).Error; err != nil {
					return err
				}
				if err := authz.BeginPermissionChange(tx); err != nil { // 尚無漂移：不寫 untraced
					return err
				}
				close(begun)
				f.hold(goOn)
				if err := tx.Exec(`INSERT INTO user_group_roles (user_group_id, role_id, scope_kind, created_at) SELECT id, 1, 'global', now() FROM user_groups WHERE name = 'g-t2'`).Error; err != nil {
					return err
				}
				if err := authz.AdvanceVersion(tx); err != nil {
					return err
				}
				return tx.Create(&model.AuditLog{Action: model.ActionUpdate, Resource: model.ResourceUser, Status: "success", UserID: 9002}).Error
			})
			c2 <- res
		}()
		waitSignal(t, begun, "T2 通過 Begin")
		f.drift(2, 1)
		c1 := f.goLegal("g-t1", legalOpt{userID: 9001})
		waitSignal(t, gate.inserted, "T1 插入 untraced")
		close(goOn)
		waiter, blocker := f.waitBlocked()
		close(gate.release)
		r1, r2 := waitResult(t, c1, "T1"), waitResult(t, c2, "T2")
		require.Equal(t, blocker, r1.pid)
		require.Equal(t, waiter, r2.pid)
		code1, _ := pgErrOf(r1.err)
		code2, _ := pgErrOf(r2.err)
		deadlocks := 0
		for _, c := range []string{code1, code2} {
			if c == "40P01" {
				deadlocks++
			}
		}
		require.Equal(t, 1, deadlocks, "恰一方 40P01：T1=%v T2=%v", r1.err, r2.err)
		require.True(t, (r1.err == nil) != (r2.err == nil), "另一方提交")
		if r1.err != nil {
			f.gone("g-t1", 9001)
		} else {
			f.gone("g-t2", 9002)
		}
		require.EqualValues(t, 1, f.version()-f.v0, "只有提交的一方推進")
		require.EqualValues(t, 0, cnt.conflicts.Load())
		require.EqualValues(t, 2, cnt.savepoints.Load(), "T1 與 T2 各一次 Begin 嘗試，未因 40P01 增加")
		require.EqualValues(t, 1, cnt.maxAttempt.Load())
		evs := f.events()
		f.evidence("untraced_vs_change_deadlock", int(cnt.maxAttempt.Load()), firstErr(r1.err, r2.err), fmt.Sprintf("victim_t1=%t chain_len=%d", r1.err != nil, len(evs)))
	})

	for _, kind := range []string{"settle", "record"} {
		kind := kind
		t.Run("other_inserters_residual/"+kind, func(t *testing.T) {
			f := newSeqFx(t)
			cnt := &hookCount{}
			gate := newFirstInsertGate(f)
			restore := audit.SetUntracedSeqHooksForTest(cnt.hooks(gate.afterInsert))
			defer restore()
			begun, goOn := make(chan struct{}), make(chan struct{})
			c2 := make(chan legalRes, 1)
			go func() {
				var res legalRes
				res.err = f.e.db.Transaction(func(tx *gorm.DB) error {
					if err := tx.Raw(`SELECT pg_backend_pid()`).Scan(&res.pid).Error; err != nil {
						return err
					}
					if err := authz.BeginPermissionChange(tx); err != nil {
						return err
					}
					if err := tx.Exec(`INSERT INTO user_group_roles (user_group_id, role_id, scope_kind, created_at) SELECT id, 1, 'global', now() FROM user_groups WHERE name = 'g-t2'`).Error; err != nil {
						return err
					}
					close(begun)
					f.hold(goOn)
					if kind == "settle" {
						return authz.SettlePermissionChange(tx)
					}
					return authz.AdvanceVersion(tx)
				})
				c2 <- res
			}()
			waitSignal(t, begun, "T2 通過 Begin 並完成寫入")
			f.drift(2, 1)
			c1 := make(chan legalRes, 1)
			go func() {
				var res legalRes
				res.err = f.e.db.Transaction(func(tx *gorm.DB) error {
					if err := tx.Raw(`SELECT pg_backend_pid()`).Scan(&res.pid).Error; err != nil {
						return err
					}
					return authz.BeginPermissionChange(tx)
				})
				c1 <- res
			}()
			waitSignal(t, gate.inserted, "T1 插入 untraced")
			close(goOn)
			waiter, blocker := f.waitBlocked()
			close(gate.release)
			r1, r2 := waitResult(t, c1, "T1"), waitResult(t, c2, "T2")
			require.NoError(t, r1.err)
			require.Equal(t, blocker, r1.pid)
			require.Equal(t, waiter, r2.pid)
			require.Error(t, r2.err)
			code, cons := pgErrOf(r2.err)
			require.Equal(t, "23505", code)
			require.Equal(t, seqUniqueIndex, cons)
			require.EqualValues(t, 0, f.groupRows("g-t2"), "整筆回滾")
			evs := f.events()
			require.Equal(t, 1, countKind(evs, model.PermEventUntraced))
			f.evidence("other_inserters_residual/"+kind, 1, r2.err, fmt.Sprintf("chain_len=%d", len(evs)))
		})
	}
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
