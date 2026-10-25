package asset

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/testgate"
)

// TestCredentialRecoveryHostIdentityPG（task 6.1）：主機身分保護靠交易與鎖的次序，
// SQLite 測不出這些交錯。這裡以真的 PostgreSQL、兩條獨立連線池（一條池＝一個後端實例）加 barrier
// 強制提交順序，不用 sleep 做同步。各單以 t.Run 子測試逐次追加，子測試名照驗句原名。
//
// 本檔現有子測試：pin_vs_reset、precheck_vs_adopt_before_handshake、handshake_vs_reset_no_write、
// reset_relearn_same_key（M-6A-a）；reset_relearn_vs_adopt、app_generation_concurrent、
// duplicate_workers_and_audit_failure（M-6A-b，實作在 *_pg_gen_test.go）。其餘五個由後續單追加。
// commit_check_in_tx（M-6B-a3，實作在 *_pg_commit_lock_test.go）：四個提交交易的 (c) 在同一交易內、取鎖後。
func TestCredentialRecoveryHostIdentityPG(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	// 方言斷言在每個葉子；EVIDENCE 每個子測試只印一次（父層全部葉子通過才印）
	pgEvidence := func(t *testing.T, db *gorm.DB) {
		t.Helper()
		require.Equal(t, "postgres", db.Dialector.Name(), "本測試不得回退 SQLite")
	}
	emit := func(t *testing.T) {
		t.Helper()
		if !t.Failed() {
			fmt.Println("EVIDENCE dialect=postgres")
			t.Log("EVIDENCE dialect=postgres")
		}
	}

	t.Run("pin_vs_reset", func(t *testing.T) {
		defer emit(t)
		t.Run("重置先提交", func(t *testing.T) {
			e := newPGIdentityEnv(t, dsn)
			runPinVsResetResetFirst(t, e)
			pgEvidence(t, e.f.db)
		})
		t.Run("綁定先提交", func(t *testing.T) {
			e := newPGIdentityEnv(t, dsn)
			runPinVsResetPinFirst(t, e)
			pgEvidence(t, e.f.db)
		})
	})

	t.Run("precheck_vs_adopt_before_handshake", func(t *testing.T) {
		defer emit(t)
		t.Run("立即Verify", func(t *testing.T) {
			e := newPGIdentityEnv(t, dsn)
			runPrecheckAdoptImmediate(t, e)
			pgEvidence(t, e.f.db)
		})
		t.Run("排程retry", func(t *testing.T) {
			e := newPGIdentityEnv(t, dsn)
			runPrecheckAdoptRetry(t, e)
			pgEvidence(t, e.f.db)
		})
	})

	t.Run("handshake_vs_reset_no_write", func(t *testing.T) {
		defer emit(t)
		for _, variant := range []string{"重置", "刪列"} {
			t.Run(variant, func(t *testing.T) {
				e := newPGIdentityEnv(t, dsn)
				runHandshakeVsResetNoWrite(t, e, variant == "刪列")
				pgEvidence(t, e.f.db)
			})
		}
	})

	t.Run("reset_relearn_same_key", func(t *testing.T) {
		e := newPGIdentityEnv(t, dsn)
		runResetRelearnSameKey(t, e)
		pgEvidence(t, e.f.db)
		emit(t)
	})

	t.Run("reset_relearn_vs_adopt", func(t *testing.T) {
		e := newPGIdentityEnv(t, dsn)
		runResetRelearnVsAdopt(t, e)
		pgEvidence(t, e.f.db)
		emit(t)
	})

	t.Run("app_generation_concurrent", func(t *testing.T) {
		defer emit(t)
		for i, o := range appGenerationOrders {
			t.Run(o.name, func(t *testing.T) {
				e := newPGIdentityEnv(t, dsn)
				runAppGenerationConcurrent(t, e, i)
				pgEvidence(t, e.f.db)
			})
		}
	})

	t.Run("duplicate_workers_and_audit_failure", func(t *testing.T) {
		defer emit(t)
		for _, c := range []struct {
			name string
			run  func(*testing.T, *pgIdentityEnv)
		}{
			{"兩個worker同時遇異動", runDuplicateWorkers},
			{"審計失敗去重鍵不前進", runStopAuditFailure},
			{"採用交易失敗整筆回滾", runAdoptTxRollback},
		} {
			t.Run(c.name, func(t *testing.T) {
				e := newPGIdentityEnv(t, dsn)
				c.run(t, e)
				pgEvidence(t, e.f.db)
			})
		}
	})

	t.Run("verify_vs_local_commit", func(t *testing.T) {
		defer emit(t)
		for _, form := range barrierForms() {
			t.Run(form.name, func(t *testing.T) {
				t.Run("Promote", func(t *testing.T) {
					e := newPGIdentityEnv(t, dsn)
					runVerifyVsCommitPromote(t, e, form)
					pgEvidence(t, e.f.db)
				})
				t.Run("promoteToCredential", func(t *testing.T) {
					e := newPGBatchEnv(t, dsn)
					runVerifyVsCommitPromoteToCredential(t, e, form)
					pgEvidence(t, e.f.db)
				})
				t.Run("commitGroupApplied", func(t *testing.T) {
					e := newPGBatchEnv(t, dsn)
					runVerifyVsCommitMember(t, e, form, false)
					pgEvidence(t, e.f.db)
				})
				t.Run("commitSplitApplied", func(t *testing.T) {
					e := newPGBatchEnv(t, dsn)
					runVerifyVsCommitMember(t, e, form, true)
					pgEvidence(t, e.f.db)
				})
			})
		}
	})

	t.Run("manual_confirm_vs_adopt", func(t *testing.T) {
		defer emit(t)
		for _, c := range []struct {
			name string
			run  func(*testing.T, *pgIdentityEnv)
		}{
			{"確認資料取得後採用_舊確認409", runConfirmAfterAdopt},
			{"兩個並行確認恰一列生效", runConcurrentConfirm},
			{"跨實例同revision被唯一索引擋下", runConfirmRevisionUnique},
		} {
			t.Run(c.name, func(t *testing.T) {
				e := newPGIdentityEnv(t, dsn)
				c.run(t, e)
				pgEvidence(t, e.f.db)
			})
		}
	})

	t.Run("confirm_crash_barrier", func(t *testing.T) {
		defer emit(t)
		for _, c := range []struct{ name, point string }{
			{"(i)建立交易提交前", "create"},
			{"(ii)紀錄與審計提交後_Verify前", "record"},
			{"(iii)Verify成功後_本地提交前", "verify"},
		} {
			t.Run(c.name, func(t *testing.T) {
				e := newPGIdentityEnv(t, dsn)
				runConfirmCrashBarrier(t, e, c.point)
				pgEvidence(t, e.f.db)
			})
		}
	})

	t.Run("confirm_db_layer_only", func(t *testing.T) {
		defer emit(t)
		t.Run("行程內互斥分開_資料庫層單獨擋下雙重承接", func(t *testing.T) {
			e := newPGIdentityEnv(t, dsn)
			runConcurrentConfirmDBOnly(t, e)
			pgEvidence(t, e.f.db)
		})
	})

	t.Run("member_pin_concurrent", func(t *testing.T) {
		defer emit(t)
		t.Run("兩交易補記_第二個條件式更新不命中不覆寫", func(t *testing.T) {
			e := newPGIdentityEnv(t, dsn)
			runMemberPinTwoTx(t, e)
			pgEvidence(t, e.f.db)
		})
		t.Run("兩個確認並行_恰一個補記並建紀錄", func(t *testing.T) {
			e := newPGIdentityEnv(t, dsn)
			runMemberPinConcurrentConfirm(t, e)
			pgEvidence(t, e.f.db)
		})
	})

	t.Run("commit_phase_evidence", func(t *testing.T) {
		defer emit(t)
		t.Run("rotatePassword", func(t *testing.T) {
			e := newPGIdentityEnv(t, dsn)
			runCommitPhaseEvidenceRotate(t, e)
			pgEvidence(t, e.f.db)
		})
		t.Run("重試Promote", func(t *testing.T) {
			e := newPGIdentityEnv(t, dsn)
			runCommitPhaseEvidenceRetry(t, e)
			pgEvidence(t, e.f.db)
		})
	})

	t.Run("lock_order_with_dispatch", func(t *testing.T) {
		e := newPGBatchEnv(t, dsn)
		runLockOrderWithDispatch(t, e)
		pgEvidence(t, e.f.db)
		emit(t)
	})

	t.Run("commit_check_in_tx", func(t *testing.T) {
		defer emit(t)
		runCommitCheckInTxSuite(t, dsn, pgEvidence)
	})
}

// pgIdentityEnv 一個 PG schema 內的兩個後端實例：f.db 是實例一的連線池（跑流程的 runner、retry、
// 綁定回呼都在它上面），db2／svc2 是實例二的獨立連線池（重置、採用、重錄從這裡來）。
type pgIdentityEnv struct {
	f       *csFixture
	db2     *gorm.DB
	svc2    *HostKeyService
	appName string
}

var pgIdentityActor = HostKeyActor{UserID: 1, Username: "super"}

// openPGIdentityPool 開一條帶 application_name 的獨立連線池，application_name 用來把 pg_locks 的觀察
// 限定在本測試自己的連線（同叢集其他測試的等待不得計入）。
func openPGIdentityPool(t *testing.T, dsn, schema, appName string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema+" application_name="+appName), &gorm.Config{
		Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// newPGIdentityEnv 與 setupChangeSecretFixture 同構（真 SSH 靶機、真服務），但資料庫是 PG 的獨立 schema。
func newPGIdentityEnv(t *testing.T, dsn string) *pgIdentityEnv {
	t.Helper()
	schema := fmt.Sprintf("hid_pg_%d", time.Now().UnixNano())
	appName := "p2m6aa_" + schema
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { // 先註冊、後執行：兩條池關閉之後才丟 schema
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	db := openPGIdentityPool(t, dsn, schema, appName)
	db2 := openPGIdentityPool(t, dsn, schema, appName)
	require.Equal(t, "postgres", db.Dialector.Name())
	require.NoError(t, db.AutoMigrate(
		&model.Asset{}, &model.AssetAccount{}, &model.Credential{}, &model.CredentialSecretVersion{}, &model.AuditLog{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetHostKey{}, &model.AssetHostKeyMismatch{},
		&model.ChangeSecretPlan{}, &model.CredentialJobAuthorization{}, &model.ChangeSecretRecord{}, &model.ChangeSecretCandidate{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	const username, password = "root", "oldpass123"
	srv := newTestSSHServer(t, username, password)
	host, portStr, err := net.SplitHostPort(srv.addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	codec := aesColumnCodec(t, make([]byte, 32))
	assets, err := NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	assets.SetTopologyPermissionPort(noopTopologyPort{})
	asset, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: "target", Protocol: model.ProtocolSSH, Host: host, Port: port,
		Username: username, Password: password, CreatedBy: 1,
	})
	require.NoError(t, err)
	var acct model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&acct).Error)
	candidates, err := NewChangeSecretCandidateService(db, codec, assets, audit.NewTxSink())
	require.NoError(t, err)

	hostKeys := NewHostKeyService(db)
	hostKeys.SetAuditTxSink(audit.NewTxSink())
	hostKeys.SetSystemAlertSink(newFakeAlertSink())
	runner := NewChangeSecretRunner(db, assets, candidates, hostKeys, nil).WithOwnershipScope(globalOwnershipScopeForTest{}).WithManagementAuthorizer(newAllowAllAuthorizer())
	retry := NewChangeSecretRetryRunner(db, candidates, assets, hostKeys, nil).WithManagementAuthorizer(newAllowAllAuthorizer())
	f := &csFixture{
		db: db, assets: assets, candidates: candidates, runner: runner, retry: retry,
		hostKeys: hostKeys, server: srv, assetID: asset.ID, accountID: acct.ID, username: username,
	}
	svc2 := NewHostKeyService(db2)
	svc2.SetAuditTxSink(audit.NewTxSink())
	svc2.SetSystemAlertSink(newFakeAlertSink())
	return &pgIdentityEnv{f: f, db2: db2, svc2: svc2, appName: appName}
}

// pollUntil 以 ticker 輪詢條件直到成立或逾時（逾時上限，不是同步手段）。
func pollUntil(t *testing.T, what string, limit time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("逾時（%s）：%s", limit, what)
		case <-tick.C:
		}
	}
}

// hostKeyLockWaiters 本測試自己的連線中，正在等該資產主機金鑰信任鎖（advisory，objsubid=2）的後端數。
// 限定 database、命名空間、資產 id 與 application_name：同叢集其他測試的等待不計入。
func (e *pgIdentityEnv) hostKeyLockWaiters(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, e.db2.Raw(`SELECT count(*) FROM pg_locks l WHERE l.locktype='advisory' AND l.granted = false
		AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
		AND l.classid::bigint = ? AND l.objid::bigint = ? AND l.objsubid = 2
		AND l.pid IN (SELECT pid FROM pg_stat_activity WHERE application_name = ?)`,
		hostKeyLockNamespace, int64(e.f.assetID), e.appName).Scan(&n).Error)
	return n
}

// holdHostKeyLock 由實例二的一條連線持有該資產的主機金鑰信任鎖，回傳釋放函式。
func (e *pgIdentityEnv) holdHostKeyLock(t *testing.T) (release func()) {
	t.Helper()
	tx := e.db2.Begin()
	require.NoError(t, tx.Error)
	require.NoError(t, lockAssetHostKey(tx, e.f.assetID))
	var once sync.Once
	release = func() { once.Do(func() { _ = tx.Rollback().Error }) }
	t.Cleanup(release)
	return release
}

func (e *pgIdentityEnv) serverHostPort(t *testing.T) (string, int) { return serverAddr(t, e.f) }

// seedOwnRecord 以正式 TOFU 路徑讓靶機當下的金鑰成為該資產的自身記錄（世代 1）。
func (e *pgIdentityEnv) seedOwnRecord(t *testing.T) model.AssetHostKey {
	t.Helper()
	host, port := e.serverHostPort(t)
	_, err := e.f.hostKeys.Evaluate(e.f.assetID, host, port, e.f.server.currentHostKey().PublicKey())
	require.NoError(t, err)
	return e.ownRecord(t)
}

func (e *pgIdentityEnv) ownRecord(t *testing.T) model.AssetHostKey {
	t.Helper()
	var own model.AssetHostKey
	require.NoError(t, e.db2.Where("asset_id = ?", e.f.assetID).First(&own).Error)
	return own
}

func (e *pgIdentityEnv) dialContext() HostKeyDialContext {
	return HostKeyDialContext{AssetID: e.f.assetID, Path: HostKeyPathCredentialChange, UserID: 1, Username: "super"}
}

// pendingCandidate 新版建立、尚未完成任何金鑰交換的一般候選（具綁定資格）。
func (e *pgIdentityEnv) pendingCandidate(t *testing.T) model.ChangeSecretCandidate {
	t.Helper()
	c := model.ChangeSecretCandidate{
		AccountID: e.f.accountID, AssetID: e.f.assetID, SecretType: model.ChangeSecretTypePassword,
		HostKeyBinding: model.HostKeyBindingPending,
	}
	require.NoError(t, e.f.db.Create(&c).Error)
	return c
}

func (e *pgIdentityEnv) reloadCandidate(t *testing.T, id uint) model.ChangeSecretCandidate {
	t.Helper()
	var c model.ChangeSecretCandidate
	require.NoError(t, e.db2.First(&c, id).Error)
	return c
}

// dialResult 一次真 SSH 撥號的結果。
type dialResult struct {
	err error
}

// dialWithCallback 在 goroutine 裡以指定的主機金鑰回呼撥真 SSH 靶機（密碼認證）。
func (e *pgIdentityEnv) dialWithCallback(cb ssh.HostKeyCallback) <-chan dialResult {
	out := make(chan dialResult, 1)
	go func() {
		cfg := &ssh.ClientConfig{
			User: e.f.username, Auth: []ssh.AuthMethod{ssh.Password("oldpass123")},
			HostKeyCallback: cb, Timeout: 20 * time.Second,
		}
		c, err := ssh.Dial("tcp", e.f.server.addr(), cfg)
		if c != nil {
			_ = c.Close()
		}
		out <- dialResult{err: err}
	}()
	return out
}

func awaitDial(t *testing.T, ch <-chan dialResult) dialResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(30 * time.Second):
		t.Fatal("撥號逾時（30 秒上限）")
		return dialResult{}
	}
}

func (e *pgIdentityEnv) asset(t *testing.T) model.Asset {
	t.Helper()
	var a model.Asset
	require.NoError(t, e.db2.First(&a, e.f.assetID).Error)
	return a
}

// --- pin_vs_reset ---

// 重置先提交：綁定回呼的 Evaluate 之後、綁定交易取得信任鎖之前，重置已提交。
// 以實例二持有信任鎖排隊的方式確定提交次序（以 pg_locks 的等待者數確認排隊，不用 sleep）：
// 重置先排、綁定後排，放鎖後 PG 依排隊序授與。
func runPinVsResetResetFirst(t *testing.T, e *pgIdentityEnv) {
	own := e.seedOwnRecord(t)
	cand := e.pendingCandidate(t)
	svc := NewHostKeyService(e.f.db)
	cb, _ := svc.CallbackForBinding(e.dialContext(), HostKeyBindTarget{CandidateID: cand.ID})

	release := e.holdHostKeyLock(t)
	type resetOut struct {
		res HostKeyResetResult
		err error
	}
	resetCh := make(chan resetOut, 1)
	go func() {
		r, err := e.svc2.MarkResetWithGeneration(e.f.assetID, pgIdentityActor)
		resetCh <- resetOut{r, err}
	}()
	pollUntil(t, "重置交易排進信任鎖佇列", 10*time.Second, func() bool { return e.hostKeyLockWaiters(t) == 1 })

	base := e.f.server.authAttempts.Load()
	dialCh := e.dialWithCallback(cb)
	pollUntil(t, "綁定交易排進信任鎖佇列（在重置之後）", 10*time.Second, func() bool { return e.hostKeyLockWaiters(t) == 2 })

	release()
	ro := <-resetCh
	require.NoError(t, ro.err)
	require.True(t, ro.res.Reset, "重置必須生效")
	dr := awaitDial(t, dialCh)
	require.Error(t, dr.err, "重置先提交：綁定失敗，握手被拒")
	assert.Contains(t, dr.err.Error(), ErrHostKeyCheckFailed.Error())
	assert.Equal(t, base, e.f.server.authAttempts.Load(), "authAttempts 0：沒有送出任何認證")

	got := e.reloadCandidate(t, cand.ID)
	assert.Equal(t, model.HostKeyBindingPending, got.HostKeyBinding, "綁定未寫入：工作列仍是 pending")
	assert.Empty(t, got.HostKeyFingerprint)
	after := e.ownRecord(t)
	assert.True(t, after.ResetPending)
	assert.Equal(t, own.TrustGeneration+1, after.TrustGeneration)
}

// 綁定先提交：barrier 設在綁定回呼的 pin 交易提交之後、回 nil（也就是送出認證）之前。
// 此時第二條連線必須讀到 bound 快照，並能取得同一資產的信任鎖，證明綁定短交易已提交、沒有交易持鎖等網路。
// 然後讓重置提交，再放行握手：快照屬舊世代，後續驗證被 (a) 擋下。
func runPinVsResetPinFirst(t *testing.T, e *pgIdentityEnv) {
	own := e.seedOwnRecord(t)
	cand := e.pendingCandidate(t)
	svc := NewHostKeyService(e.f.db)
	inner, _ := svc.CallbackForBinding(e.dialContext(), HostKeyBindTarget{CandidateID: cand.ID})

	afterPin := make(chan struct{})
	release := make(chan struct{})
	var fired int
	wrapped := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := inner(hostname, remote, key); err != nil {
			return err
		}
		fired++
		close(afterPin) // pin 交易已提交；尚未回 nil，認證尚未送出
		<-release
		return nil
	}
	base := e.f.server.authAttempts.Load()
	dialCh := e.dialWithCallback(wrapped)
	select {
	case <-afterPin:
	case r := <-dialCh:
		t.Fatalf("撥號在 barrier 之前結束: %v", r.err)
	case <-time.After(30 * time.Second):
		t.Fatal("barrier 未觸發（30 秒上限）")
	}
	require.Equal(t, 1, fired, "barrier 必須真的觸發")
	require.Equal(t, base, e.f.server.authAttempts.Load(), "barrier 時尚未送出認證")

	// 正面證據一：第二條連線讀到 bound 快照
	snap := e.reloadCandidate(t, cand.ID)
	require.Equal(t, model.HostKeyBindingBound, snap.HostKeyBinding, "pin 交易已提交")
	require.Equal(t, own.ID, snap.HostKeyRecordID)
	require.Equal(t, own.TrustGeneration, snap.HostKeyGeneration)
	require.Equal(t, own.Fingerprint, snap.HostKeyFingerprint)
	// 正面證據二：第二條連線能在短時限內取得同一資產的信任鎖（綁定交易沒有持鎖等網路）
	require.NoError(t, e.db2.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL lock_timeout = '3s'").Error; err != nil {
			return err
		}
		return lockAssetHostKey(tx, e.f.assetID)
	}), "barrier 時信任鎖必須是空的")

	// 兩條實例的重置在 barrier 期間提交
	res, err := e.svc2.MarkResetWithGeneration(e.f.assetID, pgIdentityActor)
	require.NoError(t, err)
	require.True(t, res.Reset)

	close(release)
	dr := awaitDial(t, dialCh)
	require.NoError(t, dr.err, "綁定先提交：握手放行，認證已送出")
	assert.Equal(t, base+1, e.f.server.authAttempts.Load(), "綁定先提交的次序下認證恰送出一次")

	// 快照屬舊世代：後續驗證（撥號前查庫與提交前比對）被 (a) 擋下
	stale := e.reloadCandidate(t, cand.ID)
	asset := e.asset(t)
	assert.Equal(t, own.TrustGeneration, stale.HostKeyGeneration, "工作列快照仍是舊世代")
	assert.Equal(t, hostIdentityResetPending, hostIdentityVerdict(e.db2, hostIdentityJobOfCandidate(&stale), &asset))
	txErr := e.db2.Transaction(func(tx *gorm.DB) error {
		return assertHostIdentityUnchangedTx(tx, hostIdentityJobOfCandidate(&stale), nil)
	})
	assert.ErrorIs(t, txErr, ErrHostIdentityChanged)
}

// --- precheck_vs_adopt_before_handshake ---

// 立即 Verify：撥號前查庫 (a) 通過後，實例二採用 B 並讓替身換 B：握手拒絕、不再送出認證。
func runPrecheckAdoptImmediate(t *testing.T, e *pgIdentityEnv) {
	f := e.f
	wireStopAudit(f)
	fired := 0
	base := f.runner.executors
	f.runner.executors = func(ch string) rotationExecutor {
		return verifyHookExecutor{rotationExecutor: base(ch), beforeVerify: func() {
			fired++
			adoptRemoteKey(t, f.server, e.db2, f.assetID, true) // 實例二的連線池採用
		}}
	}
	records := f.runner.RunPlan(f.plan(t, nil))
	require.Len(t, records, 1)
	require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")
	assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, records[0].Error)
	assert.EqualValues(t, 1, f.server.authAttempts.Load(), "只有下達時舊憑證的那一次認證；候選密碼不得再送出")
	f.server.mu.Lock()
	assert.Equal(t, []string{"oldpass123"}, f.server.authPasswords)
	f.server.mu.Unlock()
	requireOneStop(t, f, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentFalse)
}

// newPGRetryScenario 比照 newRetryScenario：已綁定、已下達、驗證失敗而保留的一般候選（PG 版夾具）。
func newPGRetryScenario(t *testing.T, e *pgIdentityEnv) *retryScenario {
	t.Helper()
	f := e.f
	authz := newAllowAllAuthorizer()
	f.retry.WithManagementAuthorizer(authz)
	f.retry.WithAuditSink(audit.NewTxSink())
	f.server.mu.Lock()
	f.server.rejectVerifyLogin = true
	f.server.mu.Unlock()
	records := f.runner.RunPlan(f.plan(t, nil))
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	require.Positive(t, f.server.verifyRejectFired.Load(), "驗證失敗注入器必須觸發")
	f.server.mu.Lock()
	f.server.rejectVerifyLogin = false
	f.server.mu.Unlock()
	cand := candidateOfAccount(t, f)
	require.True(t, cand.Applied)
	require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding, "首次派送經綁定回呼")
	return &retryScenario{f: f, authz: authz, baseAuth: f.server.authAttempts.Load()}
}

// 排程 retry：同上，但走重試路徑（無主體的排程呼叫）。
func runPrecheckAdoptRetry(t *testing.T, e *pgIdentityEnv) {
	s := newPGRetryScenario(t, e)
	fired := 0
	orig := s.f.retry.executors
	s.f.retry.executors = func(ch string) rotationExecutor {
		return verifyHookExecutor{rotationExecutor: orig(ch), beforeVerify: func() {
			fired++
			adoptRemoteKey(t, s.f.server, e.db2, s.f.assetID, true)
		}}
	}
	assert.False(t, s.retry(t, false))
	require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")
	s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
	s.requireStopAudit(t, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentFalse)
}

// --- handshake_vs_reset_no_write ---

// identityStore 主機身分相關三組資料的完整逐欄快照：自身列（含 reset_pending）、觀察列。
type identityStore struct {
	Own         []model.AssetHostKey
	Observation []model.AssetHostKeyMismatch
}

func (e *pgIdentityEnv) storeSnapshot(t *testing.T) identityStore {
	t.Helper()
	var s identityStore
	require.NoError(t, e.db2.Where("asset_id = ?", e.f.assetID).Order("id ASC").Find(&s.Own).Error)
	require.NoError(t, e.db2.Where("asset_id = ?", e.f.assetID).Order("id ASC").Find(&s.Observation).Error)
	return s
}

// (a) 通過後，另一實例重置（或刪列），替身出示 B：回呼拒絕、不送出認證，
// asset_host_keys 列、reset_pending 與觀察列在握手前後逐欄相同（握手不得寫入）。
func runHandshakeVsResetNoWrite(t *testing.T, e *pgIdentityEnv, deleteRow bool) {
	f := e.f
	wireStopAudit(f)
	var before identityStore
	fired := 0
	base := f.runner.executors
	f.runner.executors = func(ch string) rotationExecutor {
		return verifyHookExecutor{rotationExecutor: base(ch), beforeVerify: func() {
			fired++
			if deleteRow {
				if err := e.db2.Where("asset_id = ?", f.assetID).Delete(&model.AssetHostKey{}).Error; err != nil {
					t.Errorf("刪列失敗: %v", err)
				}
			} else if res, err := e.svc2.MarkResetWithGeneration(f.assetID, pgIdentityActor); err != nil || !res.Reset {
				t.Errorf("重置未生效: res=%+v err=%v", res, err)
			}
			f.server.swapHostKey(t) // 替身出示 B（不經採用）
			before = e.storeSnapshot(t)
		}}
	}
	records := f.runner.RunPlan(f.plan(t, nil))
	require.Len(t, records, 1)
	require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")
	assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, records[0].Error)
	assert.EqualValues(t, 1, f.server.authAttempts.Load(), "只有下達時的那一次認證；握手被拒，候選密碼未送出")

	after := e.storeSnapshot(t)
	assert.Equal(t, before, after, "自身列、reset_pending、觀察列在握手前後逐欄相同")
	if deleteRow {
		assert.Empty(t, after.Own, "刪列後握手不得重建列")
	} else {
		require.Len(t, after.Own, 1)
		assert.True(t, after.Own[0].ResetPending, "reset_pending 維持")
	}
	assert.Empty(t, after.Observation, "握手拒絕不得留下觀察列")
	stops := stopAuditDetails(t, f)
	require.Len(t, stops, 1)
	assert.Equal(t, hostIdentityPhaseHandshake, stops[0]["phase"])
	assert.Equal(t, verificationSentFalse, stops[0]["verification_sent"])
}

// --- reset_relearn_same_key ---

// 真實重置（不刪列）後，由正常連線的主機金鑰回呼重錄同一把 A：記錄 ID 與指紋相同，世代不同；
// 舊工作停止，detail generation_changed，不送出認證。
func runResetRelearnSameKey(t *testing.T, e *pgIdentityEnv) {
	s := newPGRetryScenario(t, e)
	cand := candidateOfAccount(t, s.f)
	before := e.ownRecord(t)
	require.Equal(t, cand.HostKeyGeneration, before.TrustGeneration)

	res, err := e.svc2.MarkResetWithGeneration(s.f.assetID, pgIdentityActor)
	require.NoError(t, err)
	require.True(t, res.Reset, "真實重置")
	pending := e.ownRecord(t)
	require.True(t, pending.ResetPending)
	require.Equal(t, before.ID, pending.ID, "重置不刪列")

	// 正常連線：實例二的背景作業回呼遇到同一把 A，走重置後重錄
	host, port := e.serverHostPort(t)
	cb, _ := e.svc2.CallbackFor(e.dialContext())
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	require.NoError(t, cb(net.JoinHostPort(host, strconv.Itoa(port)), remote, s.f.server.currentHostKey().PublicKey()))

	relearned := e.ownRecord(t)
	assert.Equal(t, before.ID, relearned.ID, "同一列重錄（非刪列重建）")
	assert.Equal(t, before.Fingerprint, relearned.Fingerprint, "同一把 A")
	assert.False(t, relearned.ResetPending)
	assert.NotEqual(t, before.TrustGeneration, relearned.TrustGeneration, "世代不同")

	assert.False(t, s.retry(t, false))
	s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
	s.requireStopAudit(t, hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse)
}
