package asset

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// 候選轉正的交易邊界子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.3/）：
// 加密在開交易之前、消耗候選要確認受影響列數。

// txOrderTrace 依序記下「加密呼叫」與「交易內第一條語句」，用來證明加密發生在開交易之前。
type txOrderTrace struct {
	material.BytesColumnCodec
	mu     sync.Mutex
	events []string
}

func (c *txOrderTrace) add(ev string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *txOrderTrace) EncryptBytesFor(ctx context.Context, ref crypto.CipherRef, raw []byte) (string, error) {
	c.add("encrypt")
	return c.BytesColumnCodec.EncryptBytesFor(ctx, ref, raw)
}

func (c *txOrderTrace) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.events...)
}

// traceTxStatements 在 db 上掛回呼：語句經由進行中的交易連線送出時記下 "tx"。回傳解除函式。
func traceTxStatements(t *testing.T, db *gorm.DB, trace *txOrderTrace) func() {
	record := func(tx *gorm.DB) {
		if _, inTx := tx.Statement.ConnPool.(*sql.Tx); inTx {
			trace.add("tx")
		}
	}
	const name = "test:trace-tx"
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register(name, record))
	require.NoError(t, db.Callback().Row().Before("gorm:row").Register(name, record))
	require.NoError(t, db.Callback().Raw().Before("gorm:raw").Register(name, record))
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register(name, record))
	require.NoError(t, db.Callback().Update().Before("gorm:update").Register(name, record))
	require.NoError(t, db.Callback().Delete().Before("gorm:delete").Register(name, record))
	return func() {
		_ = db.Callback().Query().Remove(name)
		_ = db.Callback().Row().Remove(name)
		_ = db.Callback().Raw().Remove(name)
		_ = db.Callback().Create().Remove(name)
		_ = db.Callback().Update().Remove(name)
		_ = db.Callback().Delete().Remove(name)
	}
}

// unverifiedCandidate 經正式 RunPlan 產生一筆「遠端已改、立即驗證失敗」的未驗證候選，之後讓驗證恢復。
func unverifiedCandidate(t *testing.T, f *csFixture) model.ChangeSecretCandidate {
	t.Helper()
	f.server.mu.Lock()
	f.server.rejectVerifyLogin = true
	f.server.mu.Unlock()
	records := f.runner.RunPlan(f.plan(t, nil))
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretUnverified, records[0].Status, "錯誤: %s", records[0].Error)
	f.server.mu.Lock()
	f.server.rejectVerifyLogin = false
	f.server.mu.Unlock()
	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.First(&cand).Error)
	require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding, "綁定經正式回呼建立")
	return cand
}

// runPromoteEncryptsBeforeTx 一般候選轉正：目的欄位加密發生在開交易之前，交易內不再加密。
func runPromoteEncryptsBeforeTx(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keyPlan bool
	}{{"密碼", false}, {"SSH金鑰", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var f *csFixture
			var cand model.ChangeSecretCandidate
			if tc.keyPlan {
				// 金鑰輪替的驗證失敗會還原遠端而不留候選，故直接以服務建立候選，綁定仍經正式回呼
				f = keyRotationFixture(t)
				newPriv, _ := testKeyPair(t, "next-system-key")
				created, err := f.candidates.Create(context.Background(), CandidateInput{
					AssetID: f.assetID, AccountID: f.accountID, AccountUsername: "root",
					SecretType: model.ChangeSecretTypeSSHKey, PrivateKey: newPriv,
				})
				require.NoError(t, err)
				cand = *bindCandidateViaCallback(t, f.db, f.hostKeys, created.ID, defaultRecorderHostKey())
			} else {
				f = setupChangeSecretFixture(t, "root", "oldpass123")
				cand = unverifiedCandidate(t, f)
			}
			versions := credentialVersionCount(t, f)

			trace := &txOrderTrace{BytesColumnCodec: f.assets.bytesCrypto}
			f.assets.bytesCrypto = trace
			untrace := traceTxStatements(t, f.db, trace)
			defer untrace()

			require.NoError(t, f.candidates.Promote(context.Background(), &cand))
			untrace()

			events := trace.snapshot()
			firstTx, encrypts := -1, 0
			for i, ev := range events {
				if ev == "tx" && firstTx < 0 {
					firstTx = i
				}
				if ev == "encrypt" {
					encrypts++
					assert.True(t, firstTx < 0, "加密發生在交易開始之後（事件序：%v）", events)
				}
			}
			require.GreaterOrEqual(t, firstTx, 0, "必須真的有交易內語句（否則為假綠），事件序：%v", events)
			assert.Equal(t, 1, encrypts, "轉正恰加密一次，事件序：%v", events)
			assert.Equal(t, versions+1, credentialVersionCount(t, f), "轉正確實新增一版")
			assert.EqualValues(t, 0, f.candidateCount(t))
		})
	}
}

// clearCandidateBeforeDelete 在 Promote 交易內、刪候選語句之前，經同一交易連線把候選列清掉，
// 模擬「重讀與身分比較通過後被並行清除」。回傳觸發次數與解除函式。
func clearCandidateBeforeDelete(t *testing.T, db *gorm.DB) (*int, func()) {
	t.Helper()
	fired := new(int)
	const name = "test:clear-candidate"
	require.NoError(t, db.Callback().Delete().Before("gorm:delete").Register(name, func(tx *gorm.DB) {
		if _, ok := tx.Statement.Model.(*model.ChangeSecretCandidate); !ok || *fired > 0 {
			return
		}
		*fired++
		if err := tx.Session(&gorm.Session{NewDB: true}).Exec("DELETE FROM change_secret_candidates").Error; err != nil {
			t.Errorf("注入並行清除失敗: %v", err)
		}
	}))
	return fired, func() { _ = db.Callback().Delete().Remove(name) }
}

func auditRowCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&model.AuditLog{}).Count(&n).Error)
	return n
}

// runPromoteCandidateClearedMidTx 比較通過後、刪候選前候選被並行清除：整筆回滾，不宣稱轉正。
func runPromoteCandidateClearedMidTx(t *testing.T) {
	t.Run("一般Promote", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		cand := unverifiedCandidate(t, f)
		versions := credentialVersionCount(t, f)
		password := f.storedPassword(t)
		audits := auditRowCount(t, f.db)
		var successes int64
		require.NoError(t, f.db.Model(&model.ChangeSecretRecord{}).
			Where("status = ?", model.ChangeSecretSuccess).Count(&successes).Error)

		fired, remove := clearCandidateBeforeDelete(t, f.db)
		defer remove()
		ok := f.retry.RetryOneAs(context.Background(), &cand)
		remove()

		require.Equal(t, 1, *fired, "注入器必須真的觸發（否則為假綠）")
		assert.False(t, ok, "候選已被清除：不宣稱轉正")
		assert.Equal(t, password, f.storedPassword(t), "正式憑證不變")
		assert.Equal(t, versions, credentialVersionCount(t, f), "版本新增已回滾")
		assert.Equal(t, audits, auditRowCount(t, f.db), "無審計殘留")
		var after int64
		require.NoError(t, f.db.Model(&model.ChangeSecretRecord{}).
			Where("status = ?", model.ChangeSecretSuccess).Count(&after).Error)
		assert.Equal(t, successes, after, "不記成功")
	})

	t.Run("promoteToCredential", func(t *testing.T) {
		f := setupBatchFixture(t)
		_, acc1 := f.addHost(t, "h1", "10.3.4.1", "ops")
		a2, acc2 := f.addHost(t, "h2", "10.3.4.2", "ops")
		_ = acc1
		rec := newSecretRecorder()
		rec.verifyErr["10.3.4.2"] = errors.New("verify timeout")
		f.useExecutor(rec)
		batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "並行清除"), 1, "admin")
		require.NoError(t, err)
		records := f.runner.RunBatch(batch, assetIDs)
		require.Equal(t, model.ChangeSecretUnverified, recordByAsset(records, a2).Status)
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
		require.NotZero(t, cand.TargetVersionID)
		require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding)
		bound := f.bindingOf(t, acc2)
		audits := auditRowCount(t, f.db)

		rec.mu.Lock()
		delete(rec.verifyErr, "10.3.4.2")
		rec.mu.Unlock()
		fired, remove := clearCandidateBeforeDelete(t, f.db)
		defer remove()
		ok := f.retry.RetryOneAs(context.Background(), &cand)
		remove()

		require.Equal(t, 1, *fired, "注入器必須真的觸發（否則為假綠）")
		assert.False(t, ok, "候選已被清除：不宣稱轉正")
		after := f.bindingOf(t, acc2)
		assert.Equal(t, bound.CredentialID, after.CredentialID, "未改綁")
		assert.Equal(t, bound.EffectiveVersionID, after.EffectiveVersionID, "就位版本不動")
		assert.Equal(t, audits, auditRowCount(t, f.db), "無審計殘留")
	})
}
