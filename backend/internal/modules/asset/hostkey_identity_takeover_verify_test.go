package asset

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 一般候選的承接驗證子案例（root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.1/驗證/）。
// 夾具的綁定與主機金鑰記錄都經正式回呼建立；審計列與去重鍵不刪，一律用基線差值。

// writeStmt 一條寫入語句與它所屬的連線（交易）。
type writeStmt struct {
	table string
	kind  string
	pool  any
	inTx  bool
}

// writeRecorder 記錄寫入語句所在的連線物件：同一個 *sql.Tx 即同一交易。
type writeRecorder struct {
	mu    sync.Mutex
	stmts []writeStmt
}

func (r *writeRecorder) install(t *testing.T, db *gorm.DB) {
	t.Helper()
	rec := func(kind string) func(*gorm.DB) {
		return func(tx *gorm.DB) {
			if tx.Statement == nil || tx.Error != nil {
				return
			}
			_, isTx := tx.Statement.ConnPool.(interface{ Commit() error })
			r.mu.Lock()
			r.stmts = append(r.stmts, writeStmt{table: tx.Statement.Table, kind: kind,
				pool: tx.Statement.ConnPool, inTx: isTx})
			r.mu.Unlock()
		}
	}
	name := "test:verify_write_rec_" + strings.ReplaceAll(t.Name(), "/", "_")
	require.NoError(t, db.Callback().Update().After("gorm:update").Register(name+"_u", rec("update")))
	require.NoError(t, db.Callback().Create().After("gorm:create").Register(name+"_c", rec("create")))
	require.NoError(t, db.Callback().Delete().After("gorm:delete").Register(name+"_d", rec("delete")))
}

func (r *writeRecorder) of(table, kind string) []writeStmt {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []writeStmt
	for _, s := range r.stmts {
		if s.table == table && s.kind == kind {
			out = append(out, s)
		}
	}
	return out
}

// verifyTarget 一個可由承接服務完整驗證的候選（密碼或 SSH 金鑰）。
type verifyTarget struct {
	takeoverTarget
	f     *csFixture
	isKey bool
}

func (v verifyTarget) localSecret(t *testing.T) string {
	t.Helper()
	if v.isKey {
		return v.f.storedPrivateKey(t)
	}
	return v.f.storedPassword(t)
}

func (v verifyTarget) request() HostIdentityConfirmRequest { return acceptDifferent(v.req) }

func newVerifyTarget(t *testing.T, isKey bool) verifyTarget {
	t.Helper()
	var f *csFixture
	var authz *fakeCredentialAuthorizer
	if !isKey {
		s := newRetryScenario(t)
		f, authz = s.f, s.authz
	} else {
		f = keyRotationFixture(t)
		authz = newAllowAllAuthorizer()
		f.retry.WithManagementAuthorizer(authz)
		f.retry.WithAuditSink(audit.NewTxSink())
		require.NoError(t, f.db.AutoMigrate(&model.AssetHostKeyMismatch{}))
		f.hostKeys.SetAuditTxSink(audit.NewTxSink())
		f.hostKeys.SetSystemAlertSink(newFakeAlertSink())
		wireStopAudit(f)
		// 首次派送經正式回呼綁定；驗證成功後、提交前主機身分被換掉，候選保留
		fired := 0
		orig := f.runner.executors
		f.runner.executors = func(ch string) rotationExecutor {
			return verifyAfterExecutor{orig(ch), bumpAfterVerify(t, f.db, f.assetID, &fired)}
		}
		records := f.runner.RunPlan(f.keyPlan(t))
		f.runner.executors = orig
		require.Len(t, records, 1)
		require.Equal(t, 1, fired, "注入器必須真的觸發")
		require.EqualValues(t, 1, f.candidateCount(t))
	}
	cand := candidateOfAccount(t, f)
	adoptRemoteKey(t, f.server, f.db, f.assetID, true)
	svc := NewHostIdentityTakeoverService(f.db, authz).WithCandidateRunner(f.retry)
	svc.SetAuditTxSink(audit.NewTxSink())
	tg := takeoverTarget{kind: takeoverKindCandidate, jobID: cand.ID, svc: svc, db: f.db, authz: authz,
		capKey: CredCapAccountRotate, assetID: f.assetID,
		req: validConfirmRequest(t, f.db, f.assetID), attempts: f.server.authAttempts.Load}
	require.NoError(t, f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
	return verifyTarget{takeoverTarget: tg, f: f, isKey: isKey}
}

// snapshotColumns 候選列上的原快照四欄（綁定、傳輸之外的身分四欄）與期限相關欄位。
type candidateRow struct {
	Binding     string
	Transport   string
	RecordID    uint
	Algorithm   string
	Fingerprint string
	Generation  int64
	Attempts    int
	NextAttempt string
	LastError   string
	Abandoned   bool
	CreatedAt   string
}

func candRowOf(t *testing.T, f *csFixture, id uint) candidateRow {
	t.Helper()
	var c model.ChangeSecretCandidate
	require.NoError(t, f.db.First(&c, id).Error)
	return candidateRow{c.HostKeyBinding, c.HostKeyTransport, c.HostKeyRecordID, c.HostKeyAlgorithm,
		c.HostKeyFingerprint, c.HostKeyGeneration, c.AttemptCount, c.NextAttemptAt.UTC().String(),
		c.LastError, c.Abandoned, c.CreatedAt.UTC().String()}
}

func onlyRecord(t *testing.T, tg takeoverTarget) model.CredentialHostIdentityConfirmation {
	t.Helper()
	rows := confirmRecords(t, tg)
	require.Len(t, rows, 1)
	return rows[0]
}

func runTakeoverVerify(t *testing.T) {
	for _, isKey := range []bool{false, true} {
		kind := "密碼"
		if isKey {
			kind = "SSH金鑰"
		}
		p := "4.1/驗證/候選/" + kind + "/"

		t.Run(p+"四欄相等成功_消耗與提交同交易_只Verify不Rotate", func(t *testing.T) {
			v := newVerifyTarget(t, isKey)
			before := v.localSecret(t)
			keysBefore := readAuthorizedKeysFile(t, v.f.server)
			if isKey {
				require.NotEmpty(t, strings.TrimSpace(keysBefore), "前置：靶機上已有候選的公鑰")
				require.NotEmpty(t, candidateOfAccount(t, v.f).PreviousPublicKey, "前置：候選記有舊公鑰（承接不得據此刪鑰）")
			}
			chBase, attBase := v.f.server.chpasswdCalls.Load(), v.attempts()
			auditBase := confirmAuditCount(t, v.db)
			orig := candRowOf(t, v.f, v.jobID)
			wr := &writeRecorder{}
			wr.install(t, v.db)

			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.request())
			require.NoError(t, err)

			assert.EqualValues(t, 0, v.f.candidateCount(t), "候選轉正後刪除")
			assert.NotEqual(t, before, v.localSecret(t), "本地憑證換成候選")
			assert.EqualValues(t, attBase+1, v.attempts(), "POSIX SSH 恰一次邏輯驗證（一次認證）")
			assert.Equal(t, chBase, v.f.server.chpasswdCalls.Load(), "改密指令 0：只 Verify 不 Rotate")
			assert.Equal(t, keysBefore, readAuthorizedKeysFile(t, v.f.server), "不刪舊鑰、不還原、不新增")
			assert.Equal(t, auditBase+1, confirmAuditCount(t, v.db), "只有建立時的一筆承接審計")

			rec := onlyRecord(t, v.takeoverTarget)
			require.NotNil(t, rec.ConsumedAt)
			assert.Equal(t, takeoverOutcomeVerified, rec.Outcome)
			assert.NotNil(t, rec.StartedAt)
			assert.Equal(t, orig.Fingerprint, rec.OriginalFingerprint, "候選刪除後紀錄仍在，原快照仍可對照")
			assert.Equal(t, orig.RecordID, rec.OriginalRecordID)
			assert.NotEqual(t, rec.OriginalFingerprint, rec.ConfirmedFingerprint)

			// SQL 攔截：消耗紀錄、刪候選與本地憑證寫入在同一個交易連線上
			consume := wr.of("credential_host_identity_confirmations", "update")
			require.Len(t, consume, 1, "成功路徑只有一次條件式消耗更新")
			require.True(t, consume[0].inTx, "消耗在交易內")
			del := wr.of("change_secret_candidates", "delete")
			require.Len(t, del, 1)
			assert.True(t, del[0].pool == consume[0].pool, "刪候選與消耗在同一個交易")
			var local []writeStmt
			for _, tb := range []string{"credential_secret_versions", "asset_accounts"} {
				local = append(local, wr.of(tb, "create")...)
				local = append(local, wr.of(tb, "update")...)
			}
			require.NotEmpty(t, local, "本地提交確實寫了憑證版本或掛載")
			for _, s := range local {
				assert.True(t, s.pool == consume[0].pool, "本地提交的 %s 寫入與消耗在同一個交易", s.table)
			}
		})

		t.Run(p+"消耗後提交前注入失敗_兩者一起回滾", func(t *testing.T) {
			v := newVerifyTarget(t, isKey)
			before := v.localSecret(t)
			keysBefore := readAuthorizedKeysFile(t, v.f.server)
			orig := candRowOf(t, v.f, v.jobID)
			boom := errors.New("injected failure before commit")
			var sawConsumed atomic.Int32
			v.f.candidates.confirmedCommitHook = func(tx *gorm.DB) error {
				var n int64
				require.NoError(t, tx.Model(&model.CredentialHostIdentityConfirmation{}).
					Where("kind = ? AND job_id = ? AND outcome = ?", v.kind, v.jobID, takeoverOutcomeVerified).
					Count(&n).Error)
				sawConsumed.Store(int32(n))
				return boom
			}
			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.request())
			require.ErrorIs(t, err, boom)
			require.EqualValues(t, 1, sawConsumed.Load(), "掛點觸發時，交易內消耗已寫入：回滾的是真東西")

			assert.EqualValues(t, 1, v.f.candidateCount(t), "候選保留")
			assert.Equal(t, before, v.localSecret(t), "本地憑證不動")
			assert.Equal(t, orig, candRowOf(t, v.f, v.jobID), "原快照四欄與期限欄位不變")
			assert.Equal(t, keysBefore, readAuthorizedKeysFile(t, v.f.server))
			rec := onlyRecord(t, v.takeoverTarget)
			assert.Equal(t, takeoverOutcomeCommitFailed, rec.Outcome, "回滾後另寫 commit_failed，不是 verified")
			assert.NotNil(t, rec.ConsumedAt)
		})

		t.Run(p+"消耗條件式更新受影響0列_整筆回滾", func(t *testing.T) {
			v := newVerifyTarget(t, isKey)
			before := v.localSecret(t)
			orig := candRowOf(t, v.f, v.jobID)
			var fired atomic.Int32
			origEx := v.f.retry.executors
			v.f.retry.executors = func(ch string) rotationExecutor {
				return verifyAfterExecutor{origEx(ch), func() {
					fired.Add(1)
					// 驗證成功之後、提交之前，紀錄被別處消耗（例如啟動收束）
					res := v.db.Model(&model.CredentialHostIdentityConfirmation{}).
						Where("kind = ? AND job_id = ?", v.kind, v.jobID).
						Updates(map[string]any{"consumed_at": gorm.Expr("CURRENT_TIMESTAMP"), "outcome": "unknown"})
					if res.Error != nil || res.RowsAffected != 1 {
						t.Errorf("前置消耗失敗 err=%v rows=%d", res.Error, res.RowsAffected)
					}
				}}
			}
			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.request())
			require.EqualValues(t, 1, fired.Load(), "注入器必須真的觸發")
			require.ErrorIs(t, err, ErrConfirmationNotConsumable)
			assert.EqualValues(t, 1, v.f.candidateCount(t), "候選保留：受影響列數不為 1 即整筆回滾")
			assert.Equal(t, before, v.localSecret(t), "本地憑證不動")
			assert.Equal(t, orig, candRowOf(t, v.f, v.jobID))
			rec := onlyRecord(t, v.takeoverTarget)
			assert.Equal(t, "unknown", rec.Outcome, "別處已寫的結果不被覆蓋")
		})

		t.Run(p+"確認到執行之間採用_得identity_moved", func(t *testing.T) {
			for _, phase := range []string{"撥號前", "驗證後提交前"} {
				v := newVerifyTarget(t, isKey)
				before := v.localSecret(t)
				attBase := v.attempts()
				orig := candRowOf(t, v.f, v.jobID)
				var fired atomic.Int32
				origEx := v.f.retry.executors
				swap := func() {
					fired.Add(1)
					adoptRemoteKey(t, v.f.server, v.f.db, v.f.assetID, true)
				}
				v.f.retry.executors = func(ch string) rotationExecutor {
					if phase == "撥號前" {
						return verifyHookExecutor{origEx(ch), swap}
					}
					return verifyAfterExecutor{origEx(ch), swap}
				}
				err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.request())
				require.EqualValues(t, 1, fired.Load(), phase+"：注入器必須真的觸發")
				requireConflict(t, err, "")
				rec := onlyRecord(t, v.takeoverTarget)
				assert.Equal(t, takeoverOutcomeMoved, rec.Outcome, phase)
				assert.NotNil(t, rec.ConsumedAt)
				assert.EqualValues(t, 1, v.f.candidateCount(t), phase+"：不提交")
				assert.Equal(t, before, v.localSecret(t), phase)
				assert.Equal(t, orig, candRowOf(t, v.f, v.jobID), phase)
				if phase == "撥號前" {
					assert.Equal(t, attBase, v.attempts(), "握手即拒絕：沒有送出任何認證")
				} else {
					assert.EqualValues(t, attBase+1, v.attempts(), "驗證已通過一次才在提交交易內被擋下")
				}
			}
		})

		t.Run(p+"驗證失敗_原期限不重設_背景仍被擋下", func(t *testing.T) {
			v := newVerifyTarget(t, isKey)
			before := v.localSecret(t)
			keysBefore := readAuthorizedKeysFile(t, v.f.server)
			chBase := v.f.server.chpasswdCalls.Load()
			orig := candRowOf(t, v.f, v.jobID)
			// 讓候選秘密在靶機上無法登入：與主機身分無關的純驗證失敗
			if isKey {
				v.f.server.mu.Lock()
				v.f.server.authorizedKeys = func() string { return "" }
				v.f.server.mu.Unlock()
			} else {
				v.f.server.setPassword("someone-else-changed-it")
			}
			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.request())
			require.ErrorIs(t, err, ErrHostIdentityVerifyFailed)
			assert.NotErrorIs(t, err, ErrHostIdentityMoved)
			attAfter := v.attempts()
			assert.Equal(t, takeoverOutcomeVerifyFailed, onlyRecord(t, v.takeoverTarget).Outcome)
			assert.EqualValues(t, 1, v.f.candidateCount(t))
			assert.Equal(t, before, v.localSecret(t))
			assert.Equal(t, orig, candRowOf(t, v.f, v.jobID), "next_attempt_at、截止時間、原因碼與次數都不變")
			assert.Equal(t, keysBefore, readAuthorizedKeysFile(t, v.f.server), "失敗也不還原、不刪鑰")
			assert.Equal(t, chBase, v.f.server.chpasswdCalls.Load())

			// 背景下一輪：仍被 (a) 擋下，撥號前就停，不送出任何認證
			cand := candidateOfAccount(t, v.f)
			assert.False(t, v.f.retry.RetryOne(&cand))
			assert.Equal(t, attAfter, v.attempts(), "背景不送認證")
			assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, candidateOfAccount(t, v.f).LastError)
			assert.Equal(t, orig.CreatedAt, candRowOf(t, v.f, v.jobID).CreatedAt, "截止時間基準不重設")

			// 可再次明示確認：建立新 revision
			err = v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.request())
			require.ErrorIs(t, err, ErrHostIdentityVerifyFailed)
			rows := confirmRecords(t, v.takeoverTarget)
			require.Len(t, rows, 2)
			assert.EqualValues(t, 2, rows[1].Revision)
			assert.Equal(t, takeoverOutcomeVerifyFailed, rows[1].Outcome)
		})
	}

	t.Run("4.1/驗證/候選/未注入執行器仍停在建立紀錄", func(t *testing.T) {
		tg := candidateTakeoverTarget(t)
		newCreateBase(t, tg)
		err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
		require.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
		assert.Nil(t, confirmRecords(t, tg)[0].ConsumedAt)
	})
	_ = context.Background
}
