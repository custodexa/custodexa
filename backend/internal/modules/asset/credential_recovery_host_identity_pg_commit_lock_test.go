package asset

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 本檔是 TestCredentialRecoveryHostIdentityPG 的 commit_check_in_tx（M-6B-a3）。
//
// 位置主張（design 決策 4 (c)）：四個提交交易各自在交易內、取得 assets 列鎖之後、任何憑證列之前做主機身分比對；
// 比對取得的主機金鑰鎖是交易級鎖，一路持有到提交，所以比對通過到寫入之間，重置或採用插不進來。
//
// 驗法：驗證成功之後才武裝攔截點，實例一的提交交易停在第一個憑證列鎖定語句（比對之後、寫入之前）。此刻：
//
//	(i)  以 pg_locks 正向證明 T1 持有該資產的主機金鑰鎖（granted）與 assets 列鎖。
//	(ii) 由實例二發出重置（T2），證明 T2 排在同一把主機金鑰鎖上、擋住它的是 T1，且 T1 放行前 T2 不會完成。
//	(iii) 放行後兩者都成功：提交先成立，重置在其後才生效（世代加一、重置待記錄）。
//
// 既有的提交注入都在驗證之後、提交函式被呼叫之前打重置；比對若被搬到交易前，那些注入仍擋得下。
// 本葉的停點在交易內，比對若不在同一交易（或不取鎖），停點上 T1 不持主機金鑰鎖、T2 不會被擋，於是轉紅。

// citCase 一條提交路徑：setup 在測試 goroutine 內布好夾具與執行器，arm 由執行器在驗證成功後呼叫；
// 回傳的 start 在獨立 goroutine 執行整條流程（不得呼叫 t 的 FailNow 類方法），committed 在放行後斷言已提交。
type citCase struct {
	db1     *gorm.DB
	lo      *pgBatchEnv // 只用其 db2 做 pg_locks 探測
	svc2    *HostKeyService
	assetID uint
	setup   func(t *testing.T, arm func()) (start func() error, committed func(t *testing.T))
}

// citWait 輪詢到成立或逾時；逾時只記錯不中止，讓呼叫端照樣放行 T1、收回 goroutine。
func citWait(t *testing.T, what string, limit time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return true
		}
		select {
		case <-deadline.C:
			t.Errorf("逾時（%s）：%s", limit, what)
			return false
		case <-tick.C:
		}
	}
}

func runCommitCheckInTx(t *testing.T, c citCase) {
	h := &loHooks{t1Reached: make(chan int, 1), t1Release: make(chan struct{})}
	t.Cleanup(h.release)
	h.installT1(t, c.db1)
	h.installT2T3(t, c.lo.db2)
	start, committed := c.setup(t, func() { h.t1Armed.Store(true) })

	flowDone := make(chan error, 1)
	go func() { flowDone <- start() }()

	var t1 int
	select {
	case t1 = <-h.t1Reached:
	case err := <-flowDone:
		t.Fatalf("流程沒有走到提交交易的憑證列鎖定語句就結束（攔截點未觸發，否則為假綠）: %v", err)
	case <-time.After(30 * time.Second):
		h.release()
		<-flowDone
		t.Fatal("攔截點 30 秒內未觸發：提交交易沒有走到憑證列鎖定語句")
	}

	// 自身列在首次派送的綁定時才建立（輪替路徑），所以停點上才讀；純讀不受諮詢鎖影響
	var before model.AssetHostKey
	if err := c.lo.db2.Where("asset_id = ?", c.assetID).First(&before).Error; err != nil {
		h.release()
		<-flowDone
		t.Fatalf("停點上讀不到自身列: %v", err)
	}
	assert.False(t, before.ResetPending)

	yes, no := true, false
	// (i) 停點在比對之後、寫入之前：T1 在交易連線上，已持主機金鑰鎖與 assets 列鎖
	assert.Greater(t, t1, 0, "停點必須在交易連線上（提交交易內）")
	assert.Equal(t, 1, c.lo.loAdvisory(t, c.assetID, t1, &yes),
		"停點（第一個憑證列鎖定語句）上 T1 已持該資產的主機金鑰鎖：比對在同一交易內、取鎖後執行")
	assert.Zero(t, c.lo.loAdvisory(t, c.assetID, t1, &no), "T1 沒有在等主機金鑰鎖")
	assert.True(t, c.lo.loRowLockHeld(t, "assets", c.assetID), "T1 已持 assets 列鎖")

	// (ii) 實例二重置：排在 T1 持有的主機金鑰鎖上
	type resetOut struct {
		existed bool
		err     error
	}
	resetDone := make(chan resetOut, 1)
	h.armed.Store(2)
	go func() {
		existed, err := c.svc2.Reset(c.assetID, pgIdentityActor)
		resetDone <- resetOut{existed, err}
	}()
	var t2 int
	if citWait(t, "重置交易 pid 取得", 5*time.Second, func() bool { t2, _ = h.pids(); return t2 > 0 }) &&
		citWait(t, "重置排在主機金鑰鎖上等待（限定 database、key、pid）", 5*time.Second,
			func() bool { return c.lo.loAdvisory(t, c.assetID, t2, &no) == 1 }) {
		assert.True(t, c.lo.loBlockedBy(t, t1, t2), "擋住重置的是 T1")
		select {
		case <-resetDone:
			t.Error("T1 放行前重置不得完成")
		default:
		}
	}

	// (iii) 放行：提交先成立，重置在其後才生效
	h.release()
	var flowErr error
	select {
	case flowErr = <-flowDone:
	case <-time.After(60 * time.Second):
		t.Fatal("放行 T1 後提交流程未在 60 秒內完成")
	}
	var r resetOut
	select {
	case r = <-resetDone:
	case <-time.After(30 * time.Second):
		t.Fatal("放行 T1 後重置未在 30 秒內完成")
	}
	assert.False(t, h.t1Timeout.Load(), "T1 barrier 本身逾時")
	require.NoError(t, flowErr, "提交流程必須成功（比對當下身分未變）")
	require.NoError(t, r.err)
	assert.True(t, r.existed, "重置生效")
	committed(t)

	var after model.AssetHostKey
	require.NoError(t, c.lo.db2.Where("asset_id = ?", c.assetID).First(&after).Error)
	assert.Equal(t, before.ID, after.ID)
	assert.Equal(t, before.TrustGeneration+1, after.TrustGeneration, "重置在提交之後才生效：世代加一")
	assert.True(t, after.ResetPending)
}

// 一般候選 Promote：已綁定、已下達的候選重試，驗證成功之後武裝。
func citPromote(t *testing.T, e *pgIdentityEnv) citCase {
	return citCase{db1: e.f.db, lo: &pgBatchEnv{db2: e.db2}, svc2: e.svc2, assetID: e.f.assetID,
		setup: func(t *testing.T, arm func()) (func() error, func(t *testing.T)) {
			s := newPGRetryScenario(t, e)
			orig := s.f.retry.executors
			s.f.retry.executors = func(ch string) rotationExecutor {
				return verifyAfterExecutor{orig(ch), arm}
			}
			cand := candidateOfAccount(t, s.f)
			start := func() error {
				if !s.f.retry.RetryOneAs(context.Background(), &cand) {
					return errors.New("RetryOneAs 未轉正")
				}
				return nil
			}
			return start, func(t *testing.T) {
				assert.Zero(t, s.f.candidateCount(t), "候選已消耗")
				assert.NotEqual(t, "oldpass123", s.f.storedPassword(t), "正式憑證已換成候選值")
			}
		}}
}

// 帶目標憑證候選 promoteToCredential：同輪 h2 先驗證失敗留下候選，重試時驗證成功之後武裝。
func citPromoteToCredential(t *testing.T, e *pgBatchEnv) citCase {
	f := e.f
	f.runner.WithAuditSink(audit.NewTxSink())
	f.retry.WithAuditSink(audit.NewTxSink())
	_, _ = f.addHost(t, "cit-h1", "10.38.12.1", "ops")
	a2, acc2 := f.addHost(t, "cit-h2", "10.38.12.2", "ops")
	return citCase{db1: f.db, lo: e, svc2: e.svc2, assetID: a2,
		setup: func(t *testing.T, arm func()) (func() error, func(t *testing.T)) {
			rec := newSecretRecorder()
			rec.verifyErr["10.38.12.2"] = errors.New("verify timeout")
			f.useExecutor(rec)
			batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "提交交易內比對"), 1, "admin")
			require.NoError(t, err)
			records := f.runner.RunBatch(batch, assetIDs)
			require.Equal(t, model.ChangeSecretUnverified, recordByAsset(records, a2).Status)
			var cand model.ChangeSecretCandidate
			require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
			require.NotZero(t, cand.CredentialID, "帶目標憑證的候選")
			require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding)
			credBefore := f.bindingOf(t, acc2).CredentialID
			rec.mu.Lock()
			delete(rec.verifyErr, "10.38.12.2")
			rec.afterVerify = func(h string) {
				if h == "10.38.12.2" {
					arm()
				}
			}
			rec.mu.Unlock()
			start := func() error {
				if !f.retry.RetryOneAs(context.Background(), &cand) {
					return errors.New("RetryOneAs 未轉正")
				}
				return nil
			}
			return start, func(t *testing.T) {
				assert.Zero(t, f.candidateCountFor(t, acc2), "候選已消耗")
				assert.Equal(t, cand.CredentialID, f.bindingOf(t, acc2).CredentialID, "已改綁到候選所帶的憑證")
				assert.NotEqual(t, credBefore, f.bindingOf(t, acc2).CredentialID)
			}
		}}
}

// 輪替成員 commitGroupApplied／commitSplitApplied：單一成員，驗證成功之後武裝。
func citMember(t *testing.T, e *pgBatchEnv, split bool) citCase {
	f := e.f
	host := "10.38.13.1"
	if split {
		host = "10.38.14.1"
	}
	credID, accounts := f.sharedOn(t, "提交交易內比對", "ops", "old-shared", host)
	assetID := f.bindingOf(t, accounts[0]).AssetID
	return citCase{db1: f.db, lo: e, svc2: e.svc2, assetID: assetID,
		setup: func(t *testing.T, arm func()) (func() error, func(t *testing.T)) {
			rec := newSecretRecorder()
			rec.afterVerify = func(h string) {
				if h == host {
					arm()
				}
			}
			f.useRotationExecutor(rec)
			var rot *model.CredentialRotation
			var err error
			if split {
				rot, err = f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
			} else {
				rot, err = f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
			}
			require.NoError(t, err)
			start := func() error { return f.rotations.Run(adminCtx(), rot.ID) }
			return start, func(t *testing.T) {
				m := f.memberOf(t, rot.ID, accounts[0])
				assert.Equal(t, model.CredentialMemberApplied, m.State, "成員已就位")
				assert.Equal(t, model.HostKeyBindingBound, m.HostKeyBinding)
				assert.Zero(t, f.candidateCountFor(t, accounts[0]), "候選已消耗")
				if split {
					assert.NotEqual(t, credID, f.bindingOf(t, accounts[0]).CredentialID, "拆分已改綁到專用憑證")
				}
			}
		}}
}

// runCommitCheckInTxSuite 由 TestCredentialRecoveryHostIdentityPG 呼叫；四個提交交易各一葉。
func runCommitCheckInTxSuite(t *testing.T, dsn string, pgEvidence func(*testing.T, *gorm.DB)) {
	leaves := []struct {
		name string
		run  func(t *testing.T) *gorm.DB
	}{
		{"Promote", func(t *testing.T) *gorm.DB {
			e := newPGIdentityEnv(t, dsn)
			runCommitCheckInTx(t, citPromote(t, e))
			return e.f.db
		}},
		{"promoteToCredential", func(t *testing.T) *gorm.DB {
			e := newPGBatchEnv(t, dsn)
			runCommitCheckInTx(t, citPromoteToCredential(t, e))
			return e.f.db
		}},
		{"commitGroupApplied", func(t *testing.T) *gorm.DB {
			e := newPGBatchEnv(t, dsn)
			runCommitCheckInTx(t, citMember(t, e, false))
			return e.f.db
		}},
		{"commitSplitApplied", func(t *testing.T) *gorm.DB {
			e := newPGBatchEnv(t, dsn)
			runCommitCheckInTx(t, citMember(t, e, true))
			return e.f.db
		}},
	}
	for _, l := range leaves {
		t.Run(l.name, func(t *testing.T) {
			db := l.run(t)
			pgEvidence(t, db)
		})
	}
}
