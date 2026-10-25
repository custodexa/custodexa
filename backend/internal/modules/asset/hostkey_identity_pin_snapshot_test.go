package asset

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 預檢與撥號的資產快照一致、下達握手被身分回呼拒絕的停止留痕、放行計數的接線
// （root：TestCredentialRecoveryHostIdentityPin，前綴 3.4／3.5）。

// runMemberVerifySnapshotSwap 補跑驗證：第一道預檢通過之後、取回目標描述之前，資產被改成 WinRM 通道與另一個端點。
// 實際撥號用的資產必須再判一次，WinRM 執行器的 Verify 0 次、不送任何認證、不提交。
func runMemberVerifySnapshotSwap(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		branch := "授權正常"
		if revoked {
			branch = "失權有限驗證"
		}
		t.Run(branch+"/預檢後取資產前換成WinRM端點", func(t *testing.T) {
			f, rot, m := sentUnverified(t, false)
			if revoked {
				revokeRotationInitiator(t, f, rot, m)
			}
			probe := &winrmProbe{inner: newRotationRecorder()}
			inner := f.rotations.executors
			f.rotations.executors = func(ch string) rotationExecutor {
				if ch == model.RotationChannelWindowsWinRM {
					return probe
				}
				return inner(ch)
			}
			fired := 0
			f.rotations.verifyPrecheckHook = func() {
				fired++
				useWinRMChannel(t, f.db, f.assetID)
				require.NoError(t, f.db.Model(&model.Asset{}).Where("id = ?", f.assetID).
					Update("host", "10.77.0.9").Error)
			}
			base := f.server.authAttempts.Load()
			before := snapshotOf(f.member(t, rot.ID))

			require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
			require.Equal(t, 1, fired, "切換必須發生在第一道預檢之後、第二次取資產之前（否則為假綠）")
			_, _, verifies := probe.inner.snapshot()
			assert.Empty(t, verifies, "WinRM 執行器的 Verify 呼叫 0 次")
			assert.Equal(t, 0, probe.rotateCalls())
			assert.EqualValues(t, base, f.server.authAttempts.Load(), "不得對任何端點送出認證")
			after := requireMemberHeld(t, f, rot.ID)
			assert.Equal(t, before, snapshotOf(after), "不提交、快照不變")
			assert.Equal(t, memberServerPassword, f.secretOfBinding(t, f.accountID), "本地就位憑證不動")
			requireMemberOneStop(t, f, m.ID, hostIdentityTransportChanged, hostIdentityPhasePrecheck, verificationSentFalse)
		})
	}
}

func lastMemberStop(t *testing.T, f *memberBindFixture) map[string]any {
	t.Helper()
	stops := memberStops(t, f.db)
	require.NotEmpty(t, stops)
	return stops[len(stops)-1]
}

// foreignKeyHook 在下達握手之前把靶機換成另一把金鑰並採用（資料面結果）。
func foreignKeyHook(t *testing.T, f *memberBindFixture, fired *int) func() {
	return func() {
		*fired++
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
	}
}

// resetIdentityTo 把靶機金鑰與自身列復原成成員快照的身分（含世代），讓已送出的成員能再通過撥號前查庫。
func resetIdentityTo(t *testing.T, f *memberBindFixture, key ssh.Signer, m *model.CredentialRotationMember) {
	t.Helper()
	f.server.mu.Lock()
	f.server.hostKey = key
	f.server.mu.Unlock()
	// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：還原到成員快照的身分（世代回退不是產品動作），只為讓已送出的成員再通過撥號前查庫
	require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", f.assetID).
		Updates(map[string]any{
			"algorithm": m.HostKeyAlgorithm, "fingerprint": m.HostKeyFingerprint,
			"public_key":       base64.StdEncoding.EncodeToString(key.PublicKey().Marshal()),
			"trust_generation": m.HostKeyGeneration,
		}).Error)
}

// runDeliveryHandshakeStop 已送出的成員重新派送：Pinned 在舊憑證握手拒絕主機身分。
// 不是遠端確定沒改成：保留工作證據與候選副本、轉身分停止，並寫 phase=handshake 的停止審計。
func runDeliveryHandshakeStop(t *testing.T) {
	for _, split := range []bool{false, true} {
		mode := "整組"
		if split {
			mode = "拆分"
		}

		requeue := func(t *testing.T, f *memberBindFixture, rot *model.CredentialRotation, m *model.CredentialRotationMember) {
			t.Helper()
			require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).
				Updates(map[string]any{"state": model.CredentialMemberTerminalFailed, "next_attempt_at": nil}).Error)
			f.server.authAttempts.Store(0)
			f.server.chpasswdCalls.Store(0)
		}
		requireHeldAfterDelivery := func(t *testing.T, f *memberBindFixture, rot *model.CredentialRotation, before memberSnapshot) *model.CredentialRotationMember {
			t.Helper()
			m := requireMemberHeld(t, f, rot.ID)
			assert.Equal(t, before, snapshotOf(m), "快照不變")
			assert.EqualValues(t, 1, f.candidateCountFor(t, f.accountID), "候選副本保留，不得走乾淨失敗清除")
			assert.EqualValues(t, 0, f.server.authAttempts.Load(), "握手即拒絕：沒有任何認證嘗試")
			assert.EqualValues(t, 0, f.server.chpasswdCalls.Load(), "不得動遠端")
			assert.Equal(t, memberServerPassword, f.secretOfBinding(t, f.accountID), "本地就位憑證不動")
			return m
		}

		t.Run("密碼/"+mode+"/握手拒絕留停止審計且保留候選", func(t *testing.T) {
			f, rot, m := sentUnverified(t, split)
			before := snapshotOf(m)
			requeue(t, f, rot, m)
			fired := 0
			cap := &stopNotifyCapture{}
			f.rotations.WithStopNotifier(cap.fn)
			f.wrapExecutors(func(e rotationExecutor) rotationExecutor {
				return preRotateHook{rotationExecutor: e, hook: foreignKeyHook(t, f, &fired)}
			})

			require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
			require.Equal(t, 1, fired, "換鑰必須發生在撥號前查庫之後、握手之前（否則為假綠）")
			requireHeldAfterDelivery(t, f, rot, before)
			requireMemberOneStop(t, f, m.ID, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentFalse)
			assert.Equal(t, 1, cap.count(), "通知恰一次")
		})

		t.Run("密碼/"+mode+"/審計寫入失敗仍停止且下一輪補寫", func(t *testing.T) {
			f, rot, m := sentUnverified(t, split)
			before := snapshotOf(m)
			requeue(t, f, rot, m)
			fired := 0
			cap := &stopNotifyCapture{}
			f.rotations.WithStopNotifier(cap.fn)
			f.wrapExecutors(func(e rotationExecutor) rotationExecutor {
				return preRotateHook{rotationExecutor: e, hook: foreignKeyHook(t, f, &fired)}
			})
			good := f.rotations.auditTx
			f.rotations.auditTx = failingAuditTxSink{}

			_ = f.rotations.RunMember(adminCtx(), rot.ID, m.ID)
			require.Equal(t, 1, fired)
			requireHeldAfterDelivery(t, f, rot, before)
			assert.Empty(t, memberStops(t, f.db), "審計寫不進去：不留半筆")
			var row model.CredentialRotationMember
			require.NoError(t, f.db.First(&row, m.ID).Error)
			assert.Nil(t, row.HostIdentityAlertedKey, "去重鍵不前進")
			assert.Zero(t, cap.count(), "審計失敗不通知")

			f.rotations.auditTx = good
			require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
			requireMemberHeld(t, f, rot.ID)
			assert.Len(t, memberStops(t, f.db), 1, "下一輪補寫一筆")
			assert.Equal(t, 1, cap.count())
		})

		t.Run("密碼/"+mode+"/同token重試去重", func(t *testing.T) {
			f, rot, m := sentUnverified(t, split)
			requeue(t, f, rot, m)
			fired := 0
			cap := &stopNotifyCapture{}
			f.rotations.WithStopNotifier(cap.fn)
			f.wrapExecutors(func(e rotationExecutor) rotationExecutor {
				return preRotateHook{rotationExecutor: e, hook: foreignKeyHook(t, f, &fired)}
			})
			require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
			require.Equal(t, 1, fired)
			requireMemberOneStop(t, f, m.ID, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentFalse)

			// 同一個身分狀態再重排兩輪：撥號前查庫擋下，不再多寫、不再通知
			for i := 0; i < 2; i++ {
				requeue(t, f, rot, m)
				require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
			}
			assert.Equal(t, 1, fired, "後兩輪在撥號前就被擋下")
			assert.Len(t, memberStops(t, f.db), 1, "同 token 不重複留痕")
			assert.Equal(t, 1, cap.count(), "只通知一次")
		})
	}

	for _, split := range []bool{false, true} {
		runKeyDeliveryHandshakeStop(t, split)
	}
}

// keyHeldFixture SSH 金鑰成員的「已送出」前置：第一次驗證握手被換鑰擋下，成員停在已下達未驗證，新鑰留在遠端。
// 之後把自身列與靶機金鑰復原成成員快照的身分並重排，下一輪會在下達的舊憑證握手被拒。
type keyHeldFixture struct {
	f       *memberBindFixture
	rot     *model.CredentialRotation
	m       *model.CredentialRotationMember
	before  memberSnapshot
	oldLine string
	origKey ssh.Signer
}

func newKeyHeldFixture(t *testing.T, split bool) *keyHeldFixture {
	t.Helper()
	f, oldLine := setupMemberKeyFixture(t)
	origKey := f.server.currentHostKey()
	origExecutors := f.rotations.executors
	firstFired := 0
	f.hookBeforeVerify(func() {
		firstFired++
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
	})
	rot := f.start(t, split)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	require.Equal(t, 1, firstFired)
	m := requireMemberHeld(t, f, rot.ID)
	f.rotations.executors = origExecutors
	require.Len(t, memberStops(t, f.db), 1)
	return &keyHeldFixture{f: f, rot: rot, m: m, before: snapshotOf(m), oldLine: oldLine, origKey: origKey}
}

// requeue 復原身分並把成員重排成可再下達。
func (k *keyHeldFixture) requeue(t *testing.T) {
	t.Helper()
	resetIdentityTo(t, k.f, k.origKey, k.m)
	k.requeueOnly(t)
}

func (k *keyHeldFixture) requeueOnly(t *testing.T) {
	t.Helper()
	require.NoError(t, k.f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", k.m.ID).
		Updates(map[string]any{"state": model.CredentialMemberTerminalFailed, "next_attempt_at": nil}).Error)
	k.f.server.authAttempts.Store(0)
}

// armDeliverySwap 下達時（舊憑證握手之前）把靶機換成又一把金鑰並採用，世代再加一。
func (k *keyHeldFixture) armDeliverySwap(t *testing.T, fired *int) {
	t.Helper()
	f := k.f
	inner := f.rotations.keyApplier
	f.rotations.keyApplier = func(ctx context.Context, exec rotationExecutor, rt rotationTarget,
		tgt changeSecretTarget, oldPassword, oldPrivateKey, newPrivate []byte, newLine, previousLine,
		keyStrategy string, onDelivered func() error, recheck func(string) string) error {
		foreignKeyHook(t, f, fired)()
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		return inner(ctx, exec, rt, tgt, oldPassword, oldPrivateKey, newPrivate, newLine, previousLine, keyStrategy, onDelivered, recheck)
	}
}

// requireKeyHeld 保留唯一候選、遠端授權金鑰不動且仍含舊鑰與新鑰、不送認證。
func (k *keyHeldFixture) requireKeyHeld(t *testing.T, keysBefore string) {
	t.Helper()
	f := k.f
	held := requireMemberHeld(t, f, k.rot.ID)
	assert.Equal(t, k.before, snapshotOf(held), "快照不變")
	assert.EqualValues(t, 1, f.candidateCountFor(t, f.accountID), "唯一候選保留")
	assert.Equal(t, keysBefore, f.server.readAuthorizedKeys(), "遠端 authorized_keys 不動（新鑰仍在）")
	assert.Contains(t, f.server.readAuthorizedKeys(), strings.Fields(k.oldLine)[1], "舊鑰未刪")
	assert.GreaterOrEqual(t, len(strings.Fields(strings.ReplaceAll(keysBefore, "\n", " "))), 4, "遠端同時有舊鑰與新鑰")
	assert.EqualValues(t, 0, f.server.authAttempts.Load(), "握手即拒絕：沒有認證嘗試")
}

func runKeyDeliveryHandshakeStop(t *testing.T, split bool) {
	mode := "整組"
	if split {
		mode = "拆分"
	}

	t.Run("SSH金鑰/"+mode+"/握手拒絕留停止審計且保留候選與新鑰", func(t *testing.T) {
		k := newKeyHeldFixture(t, split)
		f := k.f
		k.requeue(t)
		keysBefore := f.server.readAuthorizedKeys()
		fired := 0
		k.armDeliverySwap(t, &fired)
		require.NoError(t, f.rotations.RunMember(adminCtx(), k.rot.ID, k.m.ID))
		require.Equal(t, 1, fired, "換鑰必須發生在撥號前查庫之後、握手之前（否則為假綠）")

		k.requireKeyHeld(t, keysBefore)
		require.Len(t, memberStops(t, f.db), 2, "第二個身分狀態多一筆")
		last := lastMemberStop(t, f)
		assert.Equal(t, hostIdentityGenerationChanged, last["detail"])
		assert.Equal(t, hostIdentityPhaseHandshake, last["phase"])
		assert.Equal(t, verificationSentFalse, last["verification_sent"])
		assert.Equal(t, true, last["candidate_retained"])
	})

	t.Run("SSH金鑰/"+mode+"/審計寫入失敗仍停止且下一輪補寫", func(t *testing.T) {
		k := newKeyHeldFixture(t, split)
		f := k.f
		var firstRow model.CredentialRotationMember
		require.NoError(t, f.db.First(&firstRow, k.m.ID).Error)
		require.NotNil(t, firstRow.HostIdentityAlertedKey, "第一筆停止已前進去重鍵")
		firstKey := *firstRow.HostIdentityAlertedKey

		k.requeue(t)
		keysBefore := f.server.readAuthorizedKeys()
		fired := 0
		cap := &stopNotifyCapture{}
		f.rotations.WithStopNotifier(cap.fn)
		k.armDeliverySwap(t, &fired)
		good := f.rotations.auditTx
		f.rotations.auditTx = failingAuditTxSink{}

		_ = f.rotations.RunMember(adminCtx(), k.rot.ID, k.m.ID)
		require.Equal(t, 1, fired)
		k.requireKeyHeld(t, keysBefore)
		assert.Len(t, memberStops(t, f.db), 1, "審計寫不進去：不留半筆，仍只有第一筆")
		var row model.CredentialRotationMember
		require.NoError(t, f.db.First(&row, k.m.ID).Error)
		require.NotNil(t, row.HostIdentityAlertedKey)
		assert.Equal(t, firstKey, *row.HostIdentityAlertedKey, "去重鍵不提前前進")
		assert.Zero(t, cap.count(), "審計失敗不通知")

		f.rotations.auditTx = good
		require.NoError(t, f.rotations.RunMember(adminCtx(), k.rot.ID, k.m.ID))
		requireMemberHeld(t, f, k.rot.ID)
		assert.Len(t, memberStops(t, f.db), 2, "下一輪補寫一筆")
		assert.Equal(t, 1, cap.count())
		assert.EqualValues(t, 1, f.candidateCountFor(t, f.accountID), "唯一候選保留")
		assert.Equal(t, keysBefore, f.server.readAuthorizedKeys(), "遠端 authorized_keys 不動")
		assert.EqualValues(t, 0, f.server.authAttempts.Load(), "補寫不送認證")
	})

	t.Run("SSH金鑰/"+mode+"/同token重試去重", func(t *testing.T) {
		k := newKeyHeldFixture(t, split)
		f := k.f
		k.requeue(t)
		keysBefore := f.server.readAuthorizedKeys()
		fired := 0
		cap := &stopNotifyCapture{}
		f.rotations.WithStopNotifier(cap.fn)
		k.armDeliverySwap(t, &fired)
		require.NoError(t, f.rotations.RunMember(adminCtx(), k.rot.ID, k.m.ID))
		require.Equal(t, 1, fired)
		require.Len(t, memberStops(t, f.db), 2)

		// 同一個身分狀態再重排兩輪：撥號前查庫擋下，不再多寫、不再通知
		for i := 0; i < 2; i++ {
			k.requeueOnly(t)
			require.NoError(t, f.rotations.RunMember(adminCtx(), k.rot.ID, k.m.ID))
		}
		assert.Equal(t, 1, fired, "後兩輪在撥號前就被擋下")
		assert.Len(t, memberStops(t, f.db), 2, "同 token 不重複留痕")
		assert.Equal(t, 1, cap.count(), "只通知一次")
		k.requireKeyHeld(t, keysBefore)
	})
}

// pendingWindowsSSH 握手前中斷、尚未綁定的 Windows SSH 候選：重試的 Verify 會多次撥號。
func pendingWindowsSSH(t *testing.T) (*csFixture, *testSSHServer, uint, uint) {
	t.Helper()
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.retry.WithManagementAuthorizer(newAllowAllAuthorizer())
	f.retry.WithAuditSink(audit.NewTxSink())
	require.NoError(t, f.db.AutoMigrate(&model.AssetHostKeyMismatch{}))
	f.hostKeys.SetAuditTxSink(audit.NewTxSink())
	f.hostKeys.SetSystemAlertSink(newFakeAlertSink())
	wireStopAudit(f)

	srv := newTestSSHServer(t, "Administrator", "winoldpass")
	srv.mu.Lock()
	srv.windowsApplyStdinPassword = true
	srv.mu.Unlock()
	id := addWindowsSSHAsset(t, f, srv)
	f.runner.executors = func(string) rotationExecutor { return interruptBeforeHandshake{testWindowsSSHExecutor(nil)} }
	records := f.runner.RunPlan(f.planForAssets(t, []uint{id}, nil))
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretUnverified, records[0].Status, "錯誤: %s", records[0].Error)
	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("asset_id = ?", id).First(&cand).Error)
	require.Equal(t, model.HostKeyBindingPending, cand.HostKeyBinding)
	require.EqualValues(t, 0, srv.authAttempts.Load())

	secret, err := f.candidates.Secret(context.Background(), &cand)
	require.NoError(t, err)
	require.NoError(t, withProtocolSecret(secret.Password, func(b []byte) error {
		srv.setPassword(string(b))
		return nil
	}))
	secret.Destroy()
	f.retry.executors = func(string) rotationExecutor { return testWindowsSSHExecutor(nil) }
	return f, srv, id, cand.ID
}

// runPendingBindingPassCount pending 候選重試的綁定回呼與預期身分回呼共用放行計數。
func runPendingBindingPassCount(t *testing.T) {
	t.Run("pending WindowsSSH/第一次撥號經綁定送出密碼第二次被拒", func(t *testing.T) {
		f, srv, id, candID := pendingWindowsSSH(t)
		fired := 0
		srv.mu.Lock()
		srv.execExitByCall = map[int32]int{1: 1} // 第一次驗證指令失敗，逼出第二次撥號
		srv.onExec = func(n int32) {
			if n == 1 {
				fired++
				adoptRemoteKey(t, srv, f.db, id, true)
			}
		}
		srv.mu.Unlock()

		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.First(&cand, candID).Error)
		assert.False(t, f.retry.RetryOneAs(context.Background(), &cand))
		require.Equal(t, 1, fired, "注入器必須真的觸發")
		assert.EqualValues(t, 1, srv.authAttempts.Load(), "第一次撥號已用候選密碼認證成功")
		requireOneStop(t, f, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentTrue)
	})

	t.Run("對照/已綁定候選兩次撥號都在回呼被拒", func(t *testing.T) {
		f, srv, id, candID := pendingWindowsSSH(t)
		// 先讓綁定完成：第一次重試的驗證指令失敗但認證已送出
		srv.mu.Lock()
		srv.execExitByCall = map[int32]int{1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1}
		srv.mu.Unlock()
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.First(&cand, candID).Error)
		assert.False(t, f.retry.RetryOneAs(context.Background(), &cand))
		require.NoError(t, f.db.First(&cand, candID).Error)
		require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding)
		require.Empty(t, stopAuditDetails(t, f))

		// 換鑰後第二輪：預期身分回呼在每一次撥號都拒絕
		base := srv.authAttempts.Load()
		fired := 0
		inner := f.retry.executors
		f.retry.executors = func(ch string) rotationExecutor {
			return verifyHookExecutor{rotationExecutor: inner(ch), beforeVerify: func() {
				fired++
				adoptRemoteKey(t, srv, f.db, id, true)
			}}
		}
		require.NoError(t, f.db.First(&cand, candID).Error)
		assert.False(t, f.retry.RetryOneAs(context.Background(), &cand))
		require.Equal(t, 1, fired, "注入器必須真的觸發")
		assert.EqualValues(t, base, srv.authAttempts.Load(), "所有撥號都被回呼拒絕：沒有認證")
		requireOneStop(t, f, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentFalse)
	})

	t.Run("計數來源缺席記unknown而非0", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		_ = rot
		guard := f.rotations.memberVerifyGuard(rot, m)
		asset, err := f.rotations.assets.GetByID(m.AssetID)
		require.NoError(t, err)
		// 握手階段的停止，但沒有任何回呼經過放行計數
		require.False(t, guard.counted)
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		guard.recordStop(asset)
		stops := memberStops(t, f.db)
		require.Len(t, stops, 1)
		assert.Equal(t, hostIdentityPhaseHandshake, stops[0]["phase"])
		assert.Equal(t, verificationSentUnknown, stops[0]["verification_sent"], "取不到計數記 unknown，不以 0 代替")
	})
}

// runMemberBaseCallbackFailClosed 目標描述上的基底回呼 fail-closed：漏覆寫的撥號點在握手就被拒絕。
func runMemberBaseCallbackFailClosed(t *testing.T) {
	f := setupMemberBindFixture(t, "")
	rot := f.start(t, false)
	m := f.member(t, rot.ID)
	mc, reason := f.rotations.prepareMember(adminCtx(), rot, m)
	require.Empty(t, reason)
	defer mc.Destroy()
	require.NotNil(t, mc.target.hostKeyCB, "不是 nil 回呼")
	err := mc.target.hostKeyCB("127.0.0.1:22", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, f.server.currentHostKey().PublicKey())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrHostKeyCheckFailed))
	var rows int64
	require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", f.assetID).Count(&rows).Error)
	assert.EqualValues(t, 0, rows, "基底回呼不得首次信任寫入")
}

// identityRejectRotate 下達時以身分拒絕結束：passFirst 為真時先讓撥號用的回呼放行一次（綁定成功，其後即會送出認證），
// 再回傳被包裝的 ErrHostIdentityChanged；為假時回呼從未放行（認證之前就被拒絕）。
type identityRejectRotate struct {
	rotationExecutor
	passFirst bool
	key       ssh.PublicKey
}

func (r identityRejectRotate) Rotate(_ context.Context, t rotationTarget, _, _ []byte) error {
	if r.passFirst {
		if err := t.hostKeyCB(t.addr, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, r.key); err != nil {
			return err
		}
	}
	return fmt.Errorf("撥號失敗: %w", ErrHostIdentityChanged)
}

// runFirstDeliveryIdentityRejection 首次派送（綁定路線）的身分拒絕分流：
// 回呼從未放行＝認證之前被拒絕，秘密未送出，維持乾淨失敗；回呼已放行過＝已送出，轉身分停止。
func runFirstDeliveryIdentityRejection(t *testing.T) {
	for _, split := range []bool{false, true} {
		mode := "整組"
		if split {
			mode = "拆分"
		}
		t.Run(mode+"/回呼從未放行維持乾淨失敗且可重試", func(t *testing.T) {
			f := setupMemberBindFixture(t, "")
			rot := f.start(t, split)
			cap := &stopNotifyCapture{}
			f.rotations.WithStopNotifier(cap.fn)
			f.wrapExecutors(func(e rotationExecutor) rotationExecutor {
				return identityRejectRotate{rotationExecutor: e, key: f.server.currentHostKey().PublicKey()}
			})
			base := f.server.authAttempts.Load()

			require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
			m := f.member(t, rot.ID)
			assert.NotEqual(t, model.CredentialMemberChangedUnverified, m.State, "不得轉已下達未驗證")
			assert.Nil(t, m.SecretSentAt, "未標記已送出")
			assert.Equal(t, model.ChangeSecretReasonHostKeyCheckFailed, m.LastError)
			assert.Equal(t, model.HostKeyBindingPending, m.HostKeyBinding, "綁定未成立")
			assert.EqualValues(t, base, f.server.authAttempts.Load())
			if split {
				assert.EqualValues(t, 1, f.candidateCountFor(t, f.accountID), "拆分候選為起始交易所建，不清除")
			} else {
				assert.EqualValues(t, 0, f.candidateCountFor(t, f.accountID), "整組候選依首次派送規則清除")
			}
			requireMemberCleanStop(t, f, m.ID, verificationSentFalse)
			assert.Equal(t, 1, cap.count(), "仍通知一次")

			// 可乾淨重試：拿掉注入、重排後照常下達並驗證成功
			f.rotations.executors = rotationExecutorFor
			require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).
				Updates(map[string]any{"state": model.CredentialMemberTerminalFailed, "next_attempt_at": nil}).Error)
			require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
			after := f.member(t, rot.ID)
			assert.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
			assert.Equal(t, model.HostKeyBindingBound, after.HostKeyBinding)
		})

		t.Run(mode+"/對照回呼已放行過則轉身分停止", func(t *testing.T) {
			f := setupMemberBindFixture(t, "")
			rot := f.start(t, split)
			f.wrapExecutors(func(e rotationExecutor) rotationExecutor {
				return identityRejectRotate{rotationExecutor: e, passFirst: true, key: f.server.currentHostKey().PublicKey()}
			})

			require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
			m := f.member(t, rot.ID)
			assert.Equal(t, model.CredentialMemberChangedUnverified, m.State)
			assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, m.LastError)
			assert.NotNil(t, m.SecretSentAt, "已標記送出")
			assert.Equal(t, model.HostKeyBindingBound, m.HostKeyBinding, "放行即綁定")
			assert.EqualValues(t, 1, f.candidateCountFor(t, f.accountID), "候選副本保留")
			requireMemberCleanStopFields(t, f, m.ID, verificationSentTrue)
		})
	}
}

// requireMemberCleanStop 恰一筆成員停止審計，階段為握手、verification_sent 如指定（不檢查候選保留旗標與原因）。
func requireMemberCleanStop(t *testing.T, f *memberBindFixture, memberID uint, sent string) {
	t.Helper()
	requireMemberCleanStopFields(t, f, memberID, sent)
}

func requireMemberCleanStopFields(t *testing.T, f *memberBindFixture, memberID uint, sent string) {
	t.Helper()
	stops := memberStops(t, f.db)
	require.Len(t, stops, 1, "每個停止工作恰一筆停止審計")
	assert.Equal(t, "member", stops[0]["job_kind"])
	assert.EqualValues(t, memberID, stops[0]["member_id"])
	assert.Equal(t, hostIdentityPhaseHandshake, stops[0]["phase"])
	assert.Equal(t, sent, stops[0]["verification_sent"])
	assert.NotEmpty(t, stops[0]["detail"])
}
