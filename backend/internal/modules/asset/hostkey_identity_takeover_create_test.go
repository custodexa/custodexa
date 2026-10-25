package asset

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 承接建立短交易的子案例（root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.1/建立/）。
// 每案斷言：承接紀錄數、確認審計列數（對基線取差值，審計列不刪）、authAttempts。

// createBase 建立前的基線：審計列與 authAttempts 用差值比對，不刪任何列。
type createBase struct {
	audits   int64
	attempts int32
}

func newCreateBase(t *testing.T, tg takeoverTarget) createBase {
	t.Helper()
	require.NoError(t, tg.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
	return createBase{audits: confirmAuditCount(t, tg.db), attempts: tg.attempts()}
}

func confirmAuditCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&model.AuditLog{}).Where("details LIKE ?", `%host_identity_confirm%`).Count(&n).Error)
	return n
}

func confirmRecords(t *testing.T, tg takeoverTarget) []model.CredentialHostIdentityConfirmation {
	t.Helper()
	var rows []model.CredentialHostIdentityConfirmation
	require.NoError(t, tg.db.Where("kind = ? AND job_id = ?", tg.kind, tg.jobID).Order("revision").Find(&rows).Error)
	return rows
}

// requireNoCreate 拒絕案例的共同斷言：無紀錄、審計列不增、authAttempts 不增。
func (b createBase) requireNoCreate(t *testing.T, tg takeoverTarget) {
	t.Helper()
	assert.Empty(t, confirmRecords(t, tg), "無承接紀錄")
	assert.Equal(t, b.audits, confirmAuditCount(t, tg.db), "確認審計列不增")
	assert.Equal(t, b.attempts, tg.attempts(), "authAttempts 0")
}

func acceptDifferent(req HostIdentityConfirmRequest) HostIdentityConfirmRequest {
	req.AcceptDifferentKey = true
	return req
}

func requireConflict(t *testing.T, err error, detail string) {
	t.Helper()
	require.ErrorIs(t, err, ErrHostIdentityMoved)
	var ce *HostIdentityConflictError
	require.True(t, errors.As(err, &ce))
	assert.Equal(t, detail, ce.Detail)
}

func runTakeoverCreate(t *testing.T) {
	kinds := []struct {
		name string
		make func(*testing.T) takeoverTarget
	}{{"候選", candidateTakeoverTarget}, {"成員", memberTakeoverTarget}}

	for _, k := range kinds {
		p := "4.1/建立/" + k.name + "/"

		// 世代、指紋、記錄 ID 任一不等：三案分開
		mismatches := map[string]func(*HostIdentityConfirmRequest){
			"世代不等":   func(r *HostIdentityConfirmRequest) { r.Generation++ },
			"指紋不等":   func(r *HostIdentityConfirmRequest) { r.Fingerprint = "SHA256:other" },
			"記錄ID不等": func(r *HostIdentityConfirmRequest) { r.RecordID++ },
		}
		for name, mutate := range mismatches {
			t.Run(p+name+"回409", func(t *testing.T) {
				tg := k.make(t)
				base := newCreateBase(t, tg)
				req := acceptDifferent(tg.req)
				mutate(&req)
				err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, req)
				requireConflict(t, err, "")
				base.requireNoCreate(t, tg)
			})
		}

		t.Run(p+"未帶accept_different_key回409", func(t *testing.T) {
			tg := k.make(t)
			base := newCreateBase(t, tg)
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, tg.req)
			requireConflict(t, err, takeoverDetailDifferentKeyNotAccepted)
			base.requireNoCreate(t, tg)
		})

		t.Run(p+"審計注入失敗整筆回滾", func(t *testing.T) {
			tg := k.make(t)
			base := newCreateBase(t, tg)
			tg.svc.SetAuditTxSink(failingTxSink{err: errors.New("audit down")})
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
			base.requireNoCreate(t, tg)
			// 落地面缺席同樣 fail closed
			tg.svc.SetAuditTxSink(nil)
			err = tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			require.ErrorIs(t, err, port.ErrTxSinkMissing)
			base.requireNoCreate(t, tg)
		})

		t.Run(p+"兩個並行確認恰一列生效", func(t *testing.T) {
			tg := k.make(t)
			base := newCreateBase(t, tg)
			var wg sync.WaitGroup
			errs := make([]error, 2)
			for i := range errs {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					errs[i] = tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
				}(i)
			}
			wg.Wait()
			var incomplete, conflicts int
			for _, err := range errs {
				switch {
				case errors.Is(err, ErrHostIdentityConfirmIncomplete):
					incomplete++
				case errors.Is(err, ErrHostIdentityMoved):
					conflicts++
					requireConflict(t, err, takeoverDetailConfirmationPending)
				default:
					t.Fatalf("非預期錯誤: %v", err)
				}
			}
			assert.Equal(t, 1, incomplete, "恰一個生效")
			assert.Equal(t, 1, conflicts, "另一個 409")
			rows := confirmRecords(t, tg)
			require.Len(t, rows, 1)
			assert.EqualValues(t, 1, rows[0].Revision)
			assert.Equal(t, base.audits+1, confirmAuditCount(t, tg.db))
			assert.Equal(t, base.attempts, tg.attempts())
		})

		t.Run(p+"crash barrier (i) 建立交易提交前", func(t *testing.T) {
			tg := k.make(t)
			base := newCreateBase(t, tg)
			crash := errors.New("simulated process exit")
			tg.svc.createTxBarrier = func(tx *gorm.DB) error {
				// 掛點觸發時，紀錄與審計都已在交易內寫入：證明回滾的是真東西
				var n int64
				require.NoError(t, tx.Model(&model.CredentialHostIdentityConfirmation{}).
					Where("kind = ? AND job_id = ?", tg.kind, tg.jobID).Count(&n).Error)
				assert.EqualValues(t, 1, n)
				return crash
			}
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			require.ErrorIs(t, err, crash)
			base.requireNoCreate(t, tg)

			tg.svc.createTxBarrier = nil
			err = tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			require.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
			rows := confirmRecords(t, tg)
			require.Len(t, rows, 1)
			assert.EqualValues(t, 1, rows[0].Revision, "新確認直接建立 revision 1")
			assert.Equal(t, base.audits+1, confirmAuditCount(t, tg.db))
			assert.Equal(t, base.attempts, tg.attempts())
		})

		t.Run(p+"對照組：四欄相等且帶accept_different_key", func(t *testing.T) {
			tg := k.make(t)
			base := newCreateBase(t, tg)
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			require.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
			rows := confirmRecords(t, tg)
			require.Len(t, rows, 1, "恰一筆紀錄")
			r := rows[0]
			assert.EqualValues(t, 1, r.Revision)
			assert.NotNil(t, r.StartedAt, "started_at 與紀錄同一筆 INSERT")
			assert.Nil(t, r.ConsumedAt)
			assert.Empty(t, r.Outcome)
			assert.True(t, r.AcceptDifferentKey)
			assert.Equal(t, tg.req.RecordID, r.ConfirmedRecordID)
			assert.Equal(t, tg.req.Fingerprint, r.ConfirmedFingerprint)
			assert.Equal(t, tg.req.Generation, r.ConfirmedGeneration)
			assert.EqualValues(t, 1, r.ConfirmedBy)
			assert.Equal(t, model.HostKeyBindingBound, r.OriginalBinding)
			assert.NotEqual(t, r.ConfirmedFingerprint, r.OriginalFingerprint, "原快照不被覆寫")
			assert.Equal(t, base.audits+1, confirmAuditCount(t, tg.db), "同交易一筆審計")
			assert.Equal(t, base.attempts, tg.attempts())

			// 第二次確認：仍有未消耗紀錄，409 且不增列
			err = tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			requireConflict(t, err, takeoverDetailConfirmationPending)
			assert.Len(t, confirmRecords(t, tg), 1)
			assert.Equal(t, base.audits+1, confirmAuditCount(t, tg.db))
		})
	}
}
