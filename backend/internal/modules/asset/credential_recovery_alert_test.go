package asset

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

const recoveryAlertRule = "改密工作於授權失效後進入有限驗證"

// failRecoveryAlertWrites 讓寫入 recovery_alerted_at 的更新一律失敗（模擬去重狀態寫不進去）。
func failRecoveryAlertWrites(t *testing.T, db *gorm.DB) {
	t.Helper()
	name := "test:fail_recovery_alert_write"
	require.NoError(t, db.Callback().Update().Before("gorm:update").Register(name, func(tx *gorm.DB) {
		if m, ok := tx.Statement.Dest.(map[string]interface{}); ok {
			if _, hit := m["recovery_alerted_at"]; hit {
				_ = tx.AddError(errors.New("injected: recovery_alerted_at write failed"))
			}
		}
	}))
	t.Cleanup(func() { _ = db.Callback().Update().Remove(name) })
}

// failQueriesWhile 在 on 為真時讓所有查詢失敗（模擬去重狀態讀不到）。
func failQueriesWhile(t *testing.T, db *gorm.DB, on *atomic.Bool) {
	t.Helper()
	name := "test:fail_queries_while"
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if on.Load() {
			_ = tx.AddError(errors.New("injected: query failed"))
		}
	}))
	t.Cleanup(func() { _ = db.Callback().Query().Remove(name) })
}

// revokedMember 建一個「已下達、驗證未過、之後發起者失權」的輪替成員，回傳輪替、成員與掛載。
func (f *batchFixture) revokedMember(t *testing.T, rec *secretRecorder, name, host1, host2 string) (uint, *model.CredentialRotationMember, uint) {
	t.Helper()
	credID, accounts := f.sharedOn(t, name, "ops", "old-shared", host1, host2)
	rec.verifyErr[host2] = errRemoteDropped
	f.useRotationExecutor(rec)
	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	member := f.memberOf(t, rot.ID, accounts[1])
	require.Equal(t, model.CredentialMemberChangedUnverified, member.State)
	// 主機金鑰記錄與成員綁定由替身經正式回呼建立（不手插記錄列）
	require.Equal(t, model.HostKeyBindingBound, member.HostKeyBinding)
	return rot.ID, member, accounts[1]
}

func countRule(rules []string, want string) int {
	n := 0
	for _, r := range rules {
		if r == want {
			n++
		}
	}
	return n
}

func TestRecoveryAlertDedup(t *testing.T) {
	t.Run("候選：多輪有限驗證只告警一次，去重記在候選列上", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.21.1.1", "10.21.1.2")
		f.retry.WithAuditSink(audit.NewTxSink())
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.retry.notifier = notifier
		rec.mu.Lock()
		rec.verifyErr["10.21.1.2"] = errRemoteDropped
		rec.mu.Unlock()
		f.authz.deny(CredCapAccountRotate)

		for i := 0; i < 3; i++ {
			assert.False(t, f.retry.RetryOne(f.candidateOf(t, cand.ID)), "驗證失敗，第 %d 輪", i+1)
		}
		assert.EqualValues(t, 1, notifier.PendingNotifications(), "三輪只發一次")
		assert.NotNil(t, f.candidateOf(t, cand.ID).RecoveryAlertedAt, "候選列記下已告警")
	})

	t.Run("候選：去重狀態寫不進去仍照發告警", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.21.2.1", "10.21.2.2")
		f.retry.WithAuditSink(audit.NewTxSink())
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.retry.notifier = notifier
		rec.mu.Lock()
		rec.verifyErr["10.21.2.2"] = errRemoteDropped
		rec.mu.Unlock()
		f.authz.deny(CredCapAccountRotate)
		failRecoveryAlertWrites(t, f.db)

		assert.False(t, f.retry.RetryOne(f.candidateOf(t, cand.ID)))
		assert.EqualValues(t, 1, notifier.PendingNotifications(), "寫不進去也要發")
		assert.False(t, f.retry.RetryOne(f.candidateOf(t, cand.ID)))
		assert.EqualValues(t, 2, notifier.PendingNotifications(), "無從去重時寧可重複")
	})

	t.Run("輪替成員：多輪有限驗證只告警一次，去重記在成員列上", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		rotID, member, accountID := f.revokedMember(t, rec, "告警去重", "10.21.3.1", "10.21.3.2")
		var stops []string
		f.rotations.WithStopNotifier(func(rule, _ string) { stops = append(stops, rule) })
		f.authz.deny(CredCapRotate)

		require.NoError(t, f.rotations.RunMember(adminCtx(), rotID, member.ID))
		require.Equal(t, model.CredentialMemberChangedUnverified, f.memberOf(t, rotID, accountID).State, "首輪仍驗證失敗")
		rec.mu.Lock()
		delete(rec.verifyErr, "10.21.3.2")
		rec.mu.Unlock()
		require.NoError(t, f.rotations.RunMember(adminCtx(), rotID, member.ID))
		got := f.memberOf(t, rotID, accountID)
		assert.Equal(t, model.CredentialMemberApplied, got.State, "第二輪驗證成功")
		assert.Equal(t, 1, countRule(stops, recoveryAlertRule), "兩輪只發一次")
		assert.NotNil(t, got.RecoveryAlertedAt)
	})

	t.Run("輪替成員：去重狀態寫不進去仍照發告警", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		rotID, member, _ := f.revokedMember(t, rec, "告警去重失敗", "10.21.4.1", "10.21.4.2")
		var stops []string
		f.rotations.WithStopNotifier(func(rule, _ string) { stops = append(stops, rule) })
		f.authz.deny(CredCapRotate)
		failRecoveryAlertWrites(t, f.db)

		require.NoError(t, f.rotations.RunMember(adminCtx(), rotID, member.ID))
		assert.Equal(t, 1, countRule(stops, recoveryAlertRule), "寫不進去也要發")
	})

	t.Run("claimRecoveryAlert：首次搶到、之後落空；讀寫失敗或列不存在都照發", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.21.5.1", "10.21.5.2")
		row := &model.ChangeSecretCandidate{}

		assert.True(t, claimRecoveryAlert(f.db, row, cand.ID), "首次")
		assert.False(t, claimRecoveryAlert(f.db, row, cand.ID), "已記過")
		assert.True(t, claimRecoveryAlert(f.db, row, 987654), "列不存在：無從證實已發過")

		var on atomic.Bool
		failQueriesWhile(t, f.db, &on)
		on.Store(true)
		assert.True(t, claimRecoveryAlert(f.db, row, cand.ID), "更新落空且讀不到狀態：照發")
		on.Store(false)

		require.NoError(t, f.db.Model(row).Where("id = ?", cand.ID).Update("recovery_alerted_at", nil).Error)
		failRecoveryAlertWrites(t, f.db)
		assert.True(t, claimRecoveryAlert(f.db, row, cand.ID), "寫入失敗：照發")
		assert.True(t, claimRecoveryAlert(f.db, row, cand.ID), "寫入持續失敗：每次都發")
	})
}
