package asset

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 釘住、互斥與共用專用帳號：開工時釘住的專用帳號版本在代改前重驗；專用帳號自己的輪替與代改互斥；
// 一筆共用憑證掛在多台資產時各台以自己掛載的就位版本登入。

// 開工後專用帳號的就位版本前進：該目標跳過並記 CHANGE_SECRET_EXECUTOR_CHANGED，遠端零接觸。
func TestDelegatedRotationPinAdvancedMidRun(t *testing.T) {
	e := newDelegEnv(t)
	e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
	e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
	plan := e.plan(t, nil)
	job := jobFromPlan(plan)
	job.initiatorID, job.initiatorName = 1, "tester"
	targets, skip := e.runner.resolveTargets(job, e.assetID)
	require.Nil(t, skip)
	require.Len(t, targets, 1)
	require.NotNil(t, targets[0].executorPin)

	// 第一個目標完成之後專用帳號的就位版本前進（模擬同一輪裡另一個作業推進了版本）
	require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", targets[0].executorPin.AccountID).
		Update("effective_version_id", targets[0].executorPin.EffectiveVersionID+100).Error)
	before := len(e.srv.execSessions())
	rec, _ := e.runner.runTarget(job, targets[0])
	assert.Equal(t, model.ChangeSecretSkipped, rec.Status)
	assert.Equal(t, model.ChangeSecretReasonExecutorChanged, rec.Error)
	assert.Equal(t, before, len(e.srv.execSessions()), "遠端零接觸")
	assert.Zero(t, e.srv.attemptsAs(delegExecutorUser, delegExecutorSecret), "專用帳號未被撥號")
	e.assertSelfNeverTried(t)
	assert.EqualValues(t, 0, e.candidateCount(t))
}

// 專用帳號自己的整組輪替正在處理它的掛載帳號（持有該帳號的鎖）時，代改等待；放開後才進行。
func TestDelegatedRotationWaitsForExecutorOwnRotation(t *testing.T) {
	e := newDelegEnv(t)
	e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
	e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
	pin, err := readExecutorPin(e.db, e.assetID)
	require.NoError(t, err)
	require.NotNil(t, pin)

	// 以屏障模擬整組輪替的成員派送：持有專用帳號掛載的鎖
	release := lockRotationAccount(pin.AccountID)
	done := make(chan model.ChangeSecretRecord, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		done <- e.runOne(t)
	}()
	select {
	case <-done:
		release()
		wg.Wait()
		t.Fatal("ASSERT: 專用帳號的鎖被持有時，代改不得進行")
	case <-time.After(1500 * time.Millisecond):
	}
	assert.Zero(t, e.srv.attemptsAs(delegExecutorUser, delegExecutorSecret), "鎖放開之前專用帳號未被撥號")
	release()
	select {
	case rec := <-done:
		assert.Equal(t, model.ChangeSecretSuccess, rec.Status, "error=%s", rec.Error)
	case <-time.After(30 * time.Second):
		t.Fatal("ASSERT: 放開鎖後代改應完成（無死鎖）")
	}
	wg.Wait()
}

// 一筆共用憑證掛三台當專用帳號：各台以自己掛載的就位版本登入；整組輪替中三台全跳過；
// 只有一台掛載有未驗證候選時只有那一台跳過。
func TestDelegatedRotationSharedExecutorAcrossHosts(t *testing.T) {
	e := newDelegEnv(t)
	e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
	host, portStr, err := net.SplitHostPort(e.srv.addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	ctx := adminCtx()
	ef := newExecutorFixture(t, e.db)
	cred, err := ef.creds.Create(ctx, &CreateCredentialRequest{Name: "exec-shared", Username: delegExecutorUser,
		ProtocolFamily: model.ProtocolFamilySSH, Password: delegExecutorSecret})
	require.NoError(t, err)
	ids := []uint{e.assetID}
	for i, name := range []string{"app2", "app3"} {
		e.srv.addAccount(name, delegServerOldPW, fakeSudoNone)
		ids = append(ids, e.addRotationAsset(t, &CreateAssetRequest{
			Name: "host-" + name, Protocol: model.ProtocolSSH, Host: host, Port: port,
			Username: name, Password: delegStoredOldPW, RotationChannel: model.RotationChannelPosixSSH,
		}))
		_ = i
	}
	for i, id := range ids {
		ack := i + 1
		_, err := e.svc.Set(ctx, id, &SetExecutorRequest{
			Source: ExecutorSourceShared, CredentialID: cred.ID, ExpectedAccountID: uptr(0),
			AcknowledgedHostCount: &ack,
		})
		require.NoError(t, err)
	}
	first := model.AssetAccount{CredentialID: cred.ID}
	var mounts []model.AssetAccount
	require.NoError(t, e.db.Where("purpose = ? AND credential_id = ?", model.AccountPurposeExecutor, first.CredentialID).Find(&mounts).Error)
	require.Len(t, mounts, 3)

	// 整組輪替進行中：三台全為 ROTATION_PENDING，靶機零連線
	rid := uint(7)
	require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", first.CredentialID).Update("active_rotation_id", rid).Error)
	sessionsBefore, attemptsBefore := len(e.srv.execSessions()), len(e.srv.authAttempts())
	records := e.runner.RunPlan(e.planForAssets(t, ids, nil))
	require.Len(t, records, 3)
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSkipped, r.Status)
		assert.Equal(t, model.ChangeSecretReasonExecutorRotationPending, r.Error)
	}
	assert.Equal(t, sessionsBefore, len(e.srv.execSessions()))
	assert.Equal(t, attemptsBefore, len(e.srv.authAttempts()), "靶機零連線")
	require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", first.CredentialID).Update("active_rotation_id", nil).Error)

	// 其中一台掛載有未驗證候選：只有那一台跳過
	blocked := mounts[1]
	require.NoError(t, e.db.Create(&model.ChangeSecretCandidate{
		AccountID: blocked.ID, AssetID: blocked.AssetID, AccountUsername: blocked.Username, SecretType: model.ChangeSecretTypePassword,
	}).Error)
	records = e.runner.RunPlan(e.planForAssets(t, ids, nil))
	require.Len(t, records, 3)
	for _, r := range records {
		if r.AssetID == blocked.AssetID {
			assert.Equal(t, model.ChangeSecretSkipped, r.Status)
			assert.Equal(t, model.ChangeSecretReasonExecutorRotationPending, r.Error)
			continue
		}
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, "asset=%d error=%s", r.AssetID, r.Error)
		assert.Equal(t, model.ChangeSecretExecutionExecutorSudoNopasswd, r.ExecutionMethod)
		assert.Equal(t, first.CredentialID, r.ExecutorCredentialID)
	}

	// 放掉候選：三台皆代改，各自記自己掛載的專用帳號識別
	require.NoError(t, e.db.Where("account_id = ?", blocked.ID).Delete(&model.ChangeSecretCandidate{}).Error)
	records = e.runner.RunPlan(e.planForAssets(t, ids, nil))
	require.Len(t, records, 3)
	seen := map[uint]bool{}
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, "asset=%d error=%s", r.AssetID, r.Error)
		assert.Equal(t, model.ChangeSecretExecutionExecutorSudoNopasswd, r.ExecutionMethod)
		seen[r.ExecutorAccountID] = true
	}
	assert.Len(t, seen, 3, "三台各記自己掛載的專用帳號識別")
}
