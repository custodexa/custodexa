package asset

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 輪替成員首次派送的綁定與分流子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.1/）。

const memberServerUser = "root"
const memberServerPassword = "oldpass123"

// memberBindFixture 真 SSH 靶機上的一台共用憑證掛載，經正式輪替服務下達。
type memberBindFixture struct {
	*rotationFixture
	server    *testSSHServer
	credID    uint
	accountID uint
	assetID   uint
}

// setupMemberBindFixture channel 為空＝POSIX SSH；windows_ssh 讓靶機走 Windows 指令集。
func setupMemberBindFixture(t *testing.T, channel string) *memberBindFixture {
	t.Helper()
	f := setupRotationFixture(t)
	srv := newTestSSHServer(t, memberServerUser, memberServerPassword)
	host, port := serverAddr2(t, srv)

	f.rotations.executors = func(ch string) rotationExecutor {
		if ch == model.RotationChannelWindowsSSH {
			return testWindowsSSHExecutor(nil)
		}
		return rotationExecutorFor(ch)
	}
	f.rotations.keyApplier = applySSHKeyOnTargetChecked
	if channel == model.RotationChannelWindowsSSH {
		srv.mu.Lock()
		srv.windowsApplyStdinPassword = true
		srv.mu.Unlock()
	}

	family := model.ProtocolFamilySSH
	if channel != "" {
		family = model.ProtocolFamilyWindows
	}
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "成員綁定", Username: memberServerUser, ProtocolFamily: family,
		Password: memberServerPassword,
	})
	require.NoError(t, err)
	asset, err := f.assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: "member-target", Protocol: model.ProtocolSSH, Host: host, Port: port,
		Username: "seed", Password: "seed-pw", CreatedBy: 1, RotationChannel: channel,
	})
	require.NoError(t, err)
	binding, err := f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: asset.ID})
	require.NoError(t, err)
	return &memberBindFixture{rotationFixture: f, server: srv, credID: cred.ID, accountID: binding.ID, assetID: asset.ID}
}

func serverAddr2(t *testing.T, srv *testSSHServer) (string, int) {
	t.Helper()
	f := &csFixture{server: srv}
	return serverAddr(t, f)
}

// memberAuthSnap 靶機收到一次認證嘗試的那一刻，從資料庫讀到的成員列、候選列與自身列。
type memberAuthSnap struct {
	member  model.CredentialRotationMember
	cand    model.ChangeSecretCandidate
	candErr error
	own     model.AssetHostKey
	ownErr  error
}

type memberAuthWatch struct {
	mu    sync.Mutex
	snaps []memberAuthSnap
}

func (w *memberAuthWatch) list() []memberAuthSnap {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]memberAuthSnap(nil), w.snaps...)
}

func (f *memberBindFixture) watchAuth() *memberAuthWatch {
	w := &memberAuthWatch{}
	f.server.mu.Lock()
	f.server.onAuthAttempt = func() {
		var s memberAuthSnap
		_ = f.db.Where("account_id = ?", f.accountID).Order("id DESC").First(&s.member).Error
		s.candErr = f.db.Where("account_id = ?", f.accountID).First(&s.cand).Error
		s.ownErr = f.db.Where("asset_id = ?", f.assetID).First(&s.own).Error
		w.mu.Lock()
		w.snaps = append(w.snaps, s)
		w.mu.Unlock()
	}
	f.server.mu.Unlock()
	return w
}

func (f *memberBindFixture) start(t *testing.T, split bool) *model.CredentialRotation {
	t.Helper()
	var rot *model.CredentialRotation
	var err error
	if split {
		rot, err = f.rotations.StartSplit(adminCtx(), f.credID, StartRotationRequest{})
	} else {
		rot, err = f.rotations.Start(adminCtx(), f.credID, StartRotationRequest{})
	}
	require.NoError(t, err)
	return rot
}

func (f *memberBindFixture) member(t *testing.T, rotID uint) *model.CredentialRotationMember {
	t.Helper()
	return f.memberFor(t, rotID, f.accountID)
}

type memberSnapshot struct {
	binding, transport, algorithm, fingerprint string
	recordID                                   uint
	generation                                 int64
}

func snapshotOf(m *model.CredentialRotationMember) memberSnapshot {
	return memberSnapshot{m.HostKeyBinding, m.HostKeyTransport, m.HostKeyAlgorithm, m.HostKeyFingerprint,
		m.HostKeyRecordID, m.HostKeyGeneration}
}

// requireMemberBoundAtAuth 每次認證嘗試發生時，成員列都已是 bound、ssh，且四個快照欄等於靶機出示的金鑰與自身列世代；
// 第一次認證時成員為 changing；輪替候選列恆為 pending，身分只在成員列。
func requireMemberBoundAtAuth(t *testing.T, f *memberBindFixture, w *memberAuthWatch) []memberAuthSnap {
	t.Helper()
	snaps := w.list()
	require.NotEmpty(t, snaps, "靶機沒有收到任何認證：斷言將由空值假綠")
	require.EqualValues(t, f.server.authAttempts.Load(), len(snaps))
	pub := f.server.hostKey.PublicKey()
	assert.Equal(t, model.CredentialMemberChanging, snaps[0].member.State, "第一次認證時成員為 changing")
	for i, s := range snaps {
		require.NoError(t, s.ownErr, "第 %d 次認證時自身列應存在", i+1)
		assert.Equal(t, model.HostKeyBindingBound, s.member.HostKeyBinding, "第 %d 次認證前成員應已綁定", i+1)
		assert.Equal(t, model.HostKeyTransportSSH, s.member.HostKeyTransport)
		assert.Equal(t, s.own.ID, s.member.HostKeyRecordID)
		assert.Equal(t, pub.Type(), s.member.HostKeyAlgorithm)
		assert.Equal(t, ssh.FingerprintSHA256(pub), s.member.HostKeyFingerprint)
		assert.Equal(t, s.own.TrustGeneration, s.member.HostKeyGeneration)
		assert.NotNil(t, s.member.HostKeyBoundAt)
		require.NoError(t, s.candErr, "第 %d 次認證時輪替候選應存在", i+1)
		assert.Equal(t, model.HostKeyBindingPending, s.cand.HostKeyBinding, "輪替候選列保持 pending")
		assert.Empty(t, s.cand.HostKeyFingerprint, "輪替候選不帶身分快照")
	}
	return snaps
}

func runMemberFirstDelivery(t *testing.T) {
	cases := []struct {
		name    string
		channel string
		split   bool
	}{
		{"整組成員", "", false},
		{"拆分成員", "", true},
		{"WindowsSSH", model.RotationChannelWindowsSSH, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := setupMemberBindFixture(t, c.channel)
			w := f.watchAuth()
			rot := f.start(t, c.split)
			require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
			m := f.member(t, rot.ID)
			require.Equal(t, model.CredentialMemberApplied, m.State, "錯誤: %s", m.LastError)
			snaps := requireMemberBoundAtAuth(t, f, w)
			assert.GreaterOrEqual(t, len(snaps), 2, "下達與立即驗證各至少一次認證，驗證經同一個回呼物件")
			assert.Equal(t, model.HostKeyBindingBound, m.HostKeyBinding, "完成後身分仍在成員列")
			if c.channel == model.RotationChannelWindowsSSH {
				assert.Positive(t, f.server.chpasswdCalls.Load(), "Windows 指令實際送達")
			}
		})
	}
}

// 綁定寫入失敗：認證嘗試 0、新原因碼、候選依乾淨失敗規則處置（整組清除、拆分保留）。
// barrier 案的前置：先經正式派送製造「已綁定、遠端乾淨失敗」的成員，再裝 barrier 經 RunMember 重試。
func runMemberBindingFailure(t *testing.T) {
	type injection struct {
		name string
		// priorBind＝需要先有一次正式綁定（bound 且派送標記為 NULL）才能作用
		priorBind bool
		apply     func(t *testing.T, f *memberBindFixture) *int
	}
	injections := []injection{
		{"標記在讀列後被寫入(barrier)", true, func(t *testing.T, f *memberBindFixture) *int {
			fired := new(int)
			f.rotations.hostKeys.bindTxBarrier = func(tx *gorm.DB) {
				*fired++
				require.NoError(t, tx.Model(&model.CredentialRotationMember{}).Where("account_id = ?", f.accountID).
					UpdateColumn("secret_sent_at", time.Now()).Error)
			}
			return fired
		}},
		{"更新語句出錯(SQLite trigger)", false, func(t *testing.T, f *memberBindFixture) *int {
			require.NoError(t, f.db.Exec(`CREATE TRIGGER fail_bind_member BEFORE UPDATE OF host_key_binding ON credential_rotation_members
				BEGIN SELECT RAISE(ABORT, 'injected bind failure'); END`).Error)
			return nil
		}},
	}
	for _, split := range []bool{false, true} {
		mode := "整組成員"
		if split {
			mode = "拆分成員"
		}
		for _, inj := range injections {
			t.Run(mode+"/"+inj.name, func(t *testing.T) {
				f := setupMemberBindFixture(t, "")
				rot := f.start(t, split)
				origPw := f.secretOfBinding(t, f.accountID)
				var authBase, chpasswdBase int32
				if inj.priorBind {
					// 第一次正式派送：綁定成功、遠端 chpasswd 乾淨失敗
					f.server.mu.Lock()
					f.server.chpasswdExitCode = 1
					f.server.mu.Unlock()
					require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
					prior := f.member(t, rot.ID)
					require.Equal(t, model.CredentialMemberRetryWait, prior.State, "錯誤: %s", prior.LastError)
					require.Nil(t, prior.SecretSentAt, "乾淨失敗不寫標記")
					require.Equal(t, model.HostKeyBindingBound, prior.HostKeyBinding, "前置派送已經正式回呼綁定")
					var own model.AssetHostKey
					require.NoError(t, f.db.Where("asset_id = ?", f.assetID).First(&own).Error)
					pub := f.server.hostKey.PublicKey()
					assert.Equal(t, model.HostKeyTransportSSH, prior.HostKeyTransport)
					assert.Equal(t, pub.Type(), prior.HostKeyAlgorithm)
					assert.Equal(t, ssh.FingerprintSHA256(pub), prior.HostKeyFingerprint, "快照是靶機出示的真金鑰")
					assert.Equal(t, own.ID, prior.HostKeyRecordID)
					assert.Equal(t, own.TrustGeneration, prior.HostKeyGeneration)
					require.EqualValues(t, 1, f.server.chpasswdExitFired.Load(), "前置注入器必須真的觸發")
					f.server.mu.Lock()
					f.server.chpasswdExitCode = 0
					f.server.mu.Unlock()
					authBase, chpasswdBase = f.server.authAttempts.Load(), f.server.chpasswdCalls.Load()
					require.Positive(t, authBase, "前置派送確實認證過")
				}
				fired := inj.apply(t, f)
				if inj.priorBind {
					require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, f.member(t, rot.ID).ID))
				} else {
					require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
				}
				m := f.member(t, rot.ID)
				assert.Equal(t, model.CredentialMemberRetryWait, m.State, "乾淨失敗進入重試等待")
				assert.Equal(t, model.ChangeSecretReasonHostKeyCheckFailed, m.LastError,
					"須為新增的綁定失敗原因碼，不是舊憑證登入失敗或主機金鑰不符")
				assert.Equal(t, authBase, f.server.authAttempts.Load(), "綁定失敗時本次不得送出任何認證")
				assert.Equal(t, chpasswdBase, f.server.chpasswdCalls.Load(), "本次不得動遠端")
				assert.Equal(t, origPw, f.secretOfBinding(t, f.accountID), "本地憑證不動")
				if split {
					assert.EqualValues(t, 1, f.candidateCountFor(t, f.accountID), "拆分候選是唯一副本，乾淨失敗也保留")
				} else {
					assert.EqualValues(t, 0, f.candidateCountFor(t, f.accountID), "整組候選依乾淨失敗規則清除")
				}
				if fired != nil {
					assert.Equal(t, 1, *fired, "注入器必須真的觸發（否則為假綠）")
				} else {
					assert.Nil(t, m.SecretSentAt, "failClean 不寫派送標記")
				}
			})
		}
	}
}

// winrmProbe WinRM 的 fake executor：Rotate 被呼叫的那一刻先讀庫，再交給記錄器。
type winrmProbe struct {
	inner *rotationRecorder
	onRot func()
	mu    sync.Mutex
	calls int
}

func (p *winrmProbe) Rotate(ctx context.Context, t rotationTarget, o, n []byte) error {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	if p.onRot != nil {
		p.onRot()
	}
	return p.inner.Rotate(ctx, t, o, n)
}

func (p *winrmProbe) Verify(ctx context.Context, t rotationTarget, n []byte) error {
	return p.inner.Verify(ctx, t, n)
}

func (p *winrmProbe) rotateCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func requireWinRMSnapshot(t *testing.T, binding, transport, algorithm, fingerprint string, recordID uint, gen int64, boundAt *time.Time) {
	t.Helper()
	assert.Equal(t, model.HostKeyBindingBound, binding)
	assert.Equal(t, model.HostKeyTransportWinRM, transport)
	assert.Empty(t, algorithm, "WinRM 沒有金鑰：快照欄為零值")
	assert.Empty(t, fingerprint)
	assert.EqualValues(t, 0, recordID)
	assert.EqualValues(t, 0, gen)
	assert.NotNil(t, boundAt)
}

func useWinRMChannel(t *testing.T, db *gorm.DB, assetIDs ...uint) {
	t.Helper()
	require.NoError(t, db.Model(&model.Asset{}).Where("id IN ?", assetIDs).
		Updates(map[string]any{"rotation_channel": model.RotationChannelWindowsWinRM, "winrm_scheme": model.WinrmSchemeHTTP}).Error)
}

func runWinRMFirstDelivery(t *testing.T) {
	t.Run("成員", func(t *testing.T) {
		for _, split := range []bool{false, true} {
			name := "整組"
			if split {
				name = "拆分"
			}
			t.Run(name+"/Rotate前列已綁定", func(t *testing.T) {
				f := setupRotationFixture(t)
				credID, accounts := f.sharedOn(t, "winrm甲", "ops", "old", "10.61.0.1")
				useWinRMChannel(t, f.db, f.binding(t, accounts[0]).AssetID)
				var seen model.CredentialRotationMember
				var seenCand model.ChangeSecretCandidate
				probe := &winrmProbe{inner: f.remote}
				probe.onRot = func() {
					require.NoError(t, f.db.Where("account_id = ?", accounts[0]).First(&seen).Error)
					require.NoError(t, f.db.Where("account_id = ?", accounts[0]).First(&seenCand).Error)
				}
				f.rotations.executors = func(string) rotationExecutor { return probe }
				var rot *model.CredentialRotation
				var err error
				if split {
					rot, err = f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
				} else {
					rot, err = f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
				}
				require.NoError(t, err)
				require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
				require.Equal(t, 1, probe.rotateCalls())
				assert.Equal(t, model.CredentialMemberChanging, seen.State, "Rotate 被呼叫時成員為 changing")
				requireWinRMSnapshot(t, seen.HostKeyBinding, seen.HostKeyTransport, seen.HostKeyAlgorithm,
					seen.HostKeyFingerprint, seen.HostKeyRecordID, seen.HostKeyGeneration, seen.HostKeyBoundAt)
				assert.Equal(t, model.HostKeyBindingPending, seenCand.HostKeyBinding, "輪替候選列保持 pending")
				assert.Equal(t, model.CredentialMemberApplied, f.memberFor(t, rot.ID, accounts[0]).State)
			})
			t.Run(name+"/綁定寫入失敗Rotate呼叫0次", func(t *testing.T) {
				f := setupRotationFixture(t)
				credID, accounts := f.sharedOn(t, "winrm乙", "ops", "old", "10.61.1.1")
				useWinRMChannel(t, f.db, f.binding(t, accounts[0]).AssetID)
				probe := &winrmProbe{inner: f.remote}
				f.rotations.executors = func(string) rotationExecutor { return probe }
				var rot *model.CredentialRotation
				var err error
				if split {
					rot, err = f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
				} else {
					rot, err = f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
				}
				require.NoError(t, err)
				require.NoError(t, f.db.Exec(`CREATE TRIGGER fail_bind_winrm BEFORE UPDATE OF host_key_binding ON credential_rotation_members
					BEGIN SELECT RAISE(ABORT, 'injected bind failure'); END`).Error)
				require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
				assert.Equal(t, 0, probe.rotateCalls(), "綁定寫入失敗即不派送")
				m := f.memberFor(t, rot.ID, accounts[0])
				assert.Equal(t, model.CredentialMemberRetryWait, m.State)
				assert.Equal(t, model.ChangeSecretReasonHostKeyCheckFailed, m.LastError)
				assert.Nil(t, m.SecretSentAt)
				if split {
					assert.EqualValues(t, 1, f.candidateCountFor(t, accounts[0]), "拆分保留候選")
				} else {
					assert.EqualValues(t, 0, f.candidateCountFor(t, accounts[0]), "整組清除候選")
				}
			})
		}
	})

	t.Run("一般候選", func(t *testing.T) {
		newFx := func(t *testing.T) (*csFixture, *winrmProbe) {
			f := setupChangeSecretFixture(t, "root", "oldpass123")
			useWinRMChannel(t, f.db, f.assetID)
			probe := &winrmProbe{inner: newRotationRecorder()}
			f.runner.executors = func(string) rotationExecutor { return probe }
			return f, probe
		}
		t.Run("Rotate前候選已綁定", func(t *testing.T) {
			f, probe := newFx(t)
			var seen model.ChangeSecretCandidate
			probe.onRot = func() {
				require.NoError(t, f.db.Where("account_id = ?", f.accountID).First(&seen).Error)
			}
			records := f.runner.RunPlan(f.plan(t, nil))
			require.Len(t, records, 1)
			require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
			require.Equal(t, 1, probe.rotateCalls())
			requireWinRMSnapshot(t, seen.HostKeyBinding, seen.HostKeyTransport, seen.HostKeyAlgorithm,
				seen.HostKeyFingerprint, seen.HostKeyRecordID, seen.HostKeyGeneration, seen.HostKeyBoundAt)
		})
		t.Run("綁定寫入失敗Rotate呼叫0次", func(t *testing.T) {
			f, probe := newFx(t)
			require.NoError(t, f.db.Exec(`CREATE TRIGGER fail_bind_cand_winrm BEFORE UPDATE OF host_key_binding ON change_secret_candidates
				BEGIN SELECT RAISE(ABORT, 'injected bind failure'); END`).Error)
			records := f.runner.RunPlan(f.plan(t, nil))
			require.Len(t, records, 1)
			assert.Equal(t, model.ChangeSecretFailed, records[0].Status)
			assert.Equal(t, model.ChangeSecretReasonHostKeyCheckFailed, records[0].Error)
			assert.Equal(t, 0, probe.rotateCalls())
			assert.EqualValues(t, 0, f.candidateCount(t), "乾淨失敗清除候選")
		})
	})
}

// preRotateHook 在真正撥號之前（預檢與回呼都已就緒）先執行 hook，其餘委派給內層執行器。
type preRotateHook struct {
	rotationExecutor
	hook func()
}

func (p preRotateHook) Rotate(ctx context.Context, t rotationTarget, o, n []byte) error {
	p.hook()
	return p.rotationExecutor.Rotate(ctx, t, o, n)
}

// requireForeignHandshakeRefused 預檢通過之後、握手之前：靶機換成另一把金鑰，且該資產的信任列同步被採用成新金鑰。
// 普通回呼會依當下信任列放行；以成員快照為預期身分的回呼必須拒絕。斷言本次認證 0 次、不動遠端、快照不變，
// 之後把靶機金鑰、信任列與成員狀態復原，讓呼叫端接著驗證正常重排。
func requireForeignHandshakeRefused(t *testing.T, f *memberBindFixture, rot *model.CredentialRotation, before memberSnapshot) {
	t.Helper()
	var origOwn model.AssetHostKey
	require.NoError(t, f.db.Where("asset_id = ?", f.assetID).First(&origOwn).Error)
	origKey := f.server.hostKey
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	foreign, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	require.NotEqual(t, ssh.FingerprintSHA256(origKey.PublicKey()), ssh.FingerprintSHA256(foreign.PublicKey()))

	innerExecutors := f.rotations.executors
	fired := 0
	f.rotations.executors = func(ch string) rotationExecutor {
		return preRotateHook{rotationExecutor: innerExecutors(ch), hook: func() {
			fired++
			f.server.mu.Lock()
			f.server.hostKey = foreign
			f.server.mu.Unlock()
			// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：換鑰與世代推進的資料面結果，之後要原樣還原世代，無法走單向的正式採用
			require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", f.assetID).
				Updates(map[string]any{
					"algorithm":        foreign.PublicKey().Type(),
					"fingerprint":      ssh.FingerprintSHA256(foreign.PublicKey()),
					"public_key":       base64.StdEncoding.EncodeToString(foreign.PublicKey().Marshal()),
					"trust_generation": origOwn.TrustGeneration + 1,
				}).Error)
		}}
	}
	f.server.authAttempts.Store(0)
	f.server.chpasswdCalls.Store(0)

	require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, f.member(t, rot.ID).ID))
	after := f.member(t, rot.ID)
	require.Equal(t, 1, fired, "換鑰必須發生在預檢之後、撥號之前（否則為假綠）")
	assert.EqualValues(t, 0, f.server.authAttempts.Load(), "非原 pin 的金鑰：握手即拒絕，不得進入認證")
	assert.EqualValues(t, 0, f.server.chpasswdCalls.Load(), "不得動遠端")
	assert.NotEqual(t, model.CredentialMemberApplied, after.State)
	assert.Equal(t, before, snapshotOf(after), "快照不變")

	f.rotations.executors = innerExecutors
	f.server.mu.Lock()
	f.server.hostKey = origKey
	f.server.mu.Unlock()
	// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：還原到注入前的自身列（世代回退不是產品動作）
	require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", f.assetID).
		Updates(map[string]any{
			"algorithm": origOwn.Algorithm, "fingerprint": origOwn.Fingerprint,
			"public_key": origOwn.PublicKey, "trust_generation": origOwn.TrustGeneration,
		}).Error)
	require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", after.ID).
		Updates(map[string]any{"state": model.CredentialMemberTerminalFailed, "last_error": ""}).Error)
	f.server.authAttempts.Store(0)
	f.server.chpasswdCalls.Store(0)
}

// 派送證據分流 (i)–(iii) 與 legacy 停止；(iv) 見綁定失敗反例的 barrier 案例。
func runMemberDeliveryRouting(t *testing.T) {
	// firstSend 讓第一次下達送出（遠端已換密）但驗證失敗，成員停在 changed_unverified，
	// 派送標記非空、身分已綁；之後把遠端與狀態還原成「可再次下達」的樣子。
	firstSend := func(t *testing.T) (*memberBindFixture, *model.CredentialRotation, memberSnapshot) {
		f := setupMemberBindFixture(t, "")
		rot := f.start(t, false)
		f.server.mu.Lock()
		f.server.rejectVerifyLogin = true
		f.server.mu.Unlock()
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		m := f.member(t, rot.ID)
		require.Equal(t, model.CredentialMemberChangedUnverified, m.State, "錯誤: %s", m.LastError)
		require.NotNil(t, m.SecretSentAt)
		require.Equal(t, model.HostKeyBindingBound, m.HostKeyBinding)
		f.server.mu.Lock()
		f.server.rejectVerifyLogin = false
		f.server.mu.Unlock()
		f.server.setPassword(memberServerPassword)
		require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).
			Update("state", model.CredentialMemberTerminalFailed).Error)
		f.server.chpasswdCalls.Store(0)
		f.server.authAttempts.Store(0)
		return f, rot, snapshotOf(m)
	}

	t.Run("已送出的成員重排再派送：不重綁、撥號用預期身分", func(t *testing.T) {
		f, rot, before := firstSend(t)
		binds := 0
		f.rotations.hostKeys.bindTxBarrier = func(*gorm.DB) { binds++ }
		require.EqualValues(t, 1, f.candidateCountFor(t, f.accountID), "候選列仍在")
		requireForeignHandshakeRefused(t, f, rot, before)
		w := f.watchAuth()
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, f.member(t, rot.ID).ID))
		after := f.member(t, rot.ID)
		require.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
		assert.Equal(t, before, snapshotOf(after), "快照四欄不變")
		assert.Equal(t, 0, binds, "沒有進入綁定寫入")
		assert.NotEmpty(t, w.list(), "確實撥號")
		assert.Positive(t, f.server.chpasswdCalls.Load())
	})

	t.Run("同上但候選副本已被清除入口刪除：重建後仍沿原pin", func(t *testing.T) {
		f, rot, before := firstSend(t)
		cand, err := f.candidates.FindByAccount(f.accountID)
		require.NoError(t, err)
		require.NotNil(t, cand)
		require.NoError(t, f.candidates.Discard(cand.ID))
		require.EqualValues(t, 0, f.candidateCountFor(t, f.accountID))
		requireForeignHandshakeRefused(t, f, rot, before)
		binds := 0
		f.rotations.hostKeys.bindTxBarrier = func(*gorm.DB) { binds++ }
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, f.member(t, rot.ID).ID))
		after := f.member(t, rot.ID)
		require.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
		assert.Equal(t, before, snapshotOf(after), "快照四欄不變")
		assert.Equal(t, 0, binds)
		assert.Positive(t, f.server.authAttempts.Load())
	})

	t.Run("已送出但自身列世代已變：撥號前停止且不送出", func(t *testing.T) {
		f, rot, before := firstSend(t)
		// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：世代被改而記錄列其餘不變
		require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", f.assetID).
			Update("trust_generation", before.generation+1).Error)
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, f.member(t, rot.ID).ID))
		after := f.member(t, rot.ID)
		assert.Equal(t, model.CredentialMemberChangedUnverified, after.State)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, after.LastError)
		assert.EqualValues(t, 0, f.server.authAttempts.Load(), "撥號前停止")
		assert.EqualValues(t, 0, f.server.chpasswdCalls.Load())
		assert.Equal(t, before, snapshotOf(after), "不覆寫原快照")
	})

	t.Run("曾綁定但歷次派送都是乾淨失敗：重新綁定到當下記錄", func(t *testing.T) {
		f := setupMemberBindFixture(t, "")
		rot := f.start(t, false)
		f.server.mu.Lock()
		f.server.chpasswdExitCode = 1
		f.server.mu.Unlock()
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		m := f.member(t, rot.ID)
		require.Equal(t, model.CredentialMemberRetryWait, m.State, "錯誤: %s", m.LastError)
		require.Nil(t, m.SecretSentAt, "乾淨失敗不寫標記")
		require.Equal(t, model.HostKeyBindingBound, m.HostKeyBinding, "第一次下達已綁定")
		require.EqualValues(t, 1, f.server.chpasswdExitFired.Load(), "注入器必須真的觸發")

		// 管理員在期間採用了新世代：當下記錄與舊快照不同
		// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：世代被推進，驗重新綁定到當下記錄
		require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", f.assetID).
			Update("trust_generation", m.HostKeyGeneration+4).Error)
		f.server.mu.Lock()
		f.server.chpasswdExitCode = 0
		f.server.mu.Unlock()
		binds := 0
		f.rotations.hostKeys.bindTxBarrier = func(*gorm.DB) { binds++ }
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
		after := f.member(t, rot.ID)
		require.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
		assert.Equal(t, 1, binds, "重新進入綁定寫入")
		assert.Equal(t, m.HostKeyGeneration+4, after.HostKeyGeneration, "重新綁定到當下記錄的世代")
		assert.Equal(t, m.HostKeyFingerprint, after.HostKeyFingerprint)
	})

	t.Run("legacy且標記非空：撥號前停止", func(t *testing.T) {
		f := setupMemberBindFixture(t, "")
		rot := f.start(t, false)
		m := f.member(t, rot.ID)
		require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).
			Updates(map[string]any{"host_key_binding": model.HostKeyBindingLegacy, "secret_sent_at": time.Now()}).Error)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		after := f.member(t, rot.ID)
		assert.Equal(t, model.CredentialMemberChangedUnverified, after.State)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, after.LastError)
		assert.EqualValues(t, 0, f.server.authAttempts.Load())
		assert.EqualValues(t, 0, f.server.chpasswdCalls.Load())
		assert.Equal(t, model.HostKeyBindingLegacy, after.HostKeyBinding, "legacy 不被綁定覆寫")
	})
}
