package asset

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 輪替成員的主機身分守衛子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.4/成員）：
// 下達後立即 Verify、補跑驗證兩個授權分支、升級前（legacy）成員重排、派送歷史、一員停止他員繼續。
// 綁定一律由 Run／RunMember 的首次派送經正式回呼建立，沒有直接寫 bound；
// legacy 成員以升級前的資料面結果（綁定欄清空、標記欄依情境）製造。

// rotateHookExecutor 在 Rotate 成功之後插入一段動作（秘密已送出、立即 Verify 撥號之前）。
type rotateHookExecutor struct {
	rotationExecutor
	after func()
}

func (h rotateHookExecutor) Rotate(ctx context.Context, rt rotationTarget, o, n []byte) error {
	err := h.rotationExecutor.Rotate(ctx, rt, o, n)
	if err == nil && h.after != nil {
		h.after()
	}
	return err
}

// rotateCounter 記下 Rotate 的呼叫次數。
type rotateCounter struct {
	rotationExecutor
	calls *int
}

func (c rotateCounter) Rotate(ctx context.Context, rt rotationTarget, o, n []byte) error {
	*c.calls++
	return c.rotationExecutor.Rotate(ctx, rt, o, n)
}

func (f *memberBindFixture) wrapExecutors(wrap func(rotationExecutor) rotationExecutor) {
	inner := f.rotations.executors
	f.rotations.executors = func(ch string) rotationExecutor { return wrap(inner(ch)) }
}

func (f *memberBindFixture) hookAfterRotate(after func()) {
	f.wrapExecutors(func(e rotationExecutor) rotationExecutor { return rotateHookExecutor{e, after} })
}

func (f *memberBindFixture) hookBeforeVerify(before func()) {
	f.wrapExecutors(func(e rotationExecutor) rotationExecutor { return verifyHookExecutor{e, before} })
}

// memberStops 取所有主機身分停止審計（依序）。
func memberStops(t *testing.T, db *gorm.DB) []map[string]any {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, db.Where("details LIKE ?", `%"operation":"host_identity_stop"%`).Order("id ASC").Find(&rows).Error)
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.Details), &d))
		out = append(out, d)
	}
	return out
}

// requireMemberOneStop 恰一筆成員停止審計，detail、階段與 verification_sent 符合，候選保留旗標為真且無秘密欄。
func requireMemberOneStop(t *testing.T, f *memberBindFixture, memberID uint, detail, phase, sent string) {
	t.Helper()
	stops := memberStops(t, f.db)
	require.Len(t, stops, 1, "每個停止工作每個身分狀態 token 恰一筆停止審計")
	assert.Equal(t, "member", stops[0]["job_kind"])
	assert.EqualValues(t, memberID, stops[0]["member_id"])
	assert.Equal(t, detail, stops[0]["detail"])
	assert.Equal(t, phase, stops[0]["phase"])
	assert.Equal(t, sent, stops[0]["verification_sent"])
	assert.Equal(t, true, stops[0]["candidate_retained"])
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, stops[0]["reason"])
}

// setupMemberKeyFixture 同 setupMemberBindFixture，但共用憑證是 SSH 金鑰型別（靶機授權舊鑰）。
func setupMemberKeyFixture(t *testing.T) (*memberBindFixture, string) {
	t.Helper()
	f := setupRotationFixture(t)
	srv := newTestSSHServer(t, memberServerUser, memberServerPassword)
	host, port := serverAddr2(t, srv)
	f.rotations.executors = rotationExecutorFor
	f.rotations.keyApplier = applySSHKeyOnTargetChecked
	oldPriv, oldLine := testKeyPair(t, "old-system-key")
	srv.seedAuthorizedKeys(oldLine + "\n")
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "成員金鑰綁定", Username: memberServerUser, ProtocolFamily: model.ProtocolFamilySSH,
		SecretType: model.ChangeSecretTypeSSHKey, PrivateKey: oldPriv,
	})
	require.NoError(t, err)
	asset, err := f.assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: "member-key-target", Protocol: model.ProtocolSSH, Host: host, Port: port,
		Username: "seed", Password: "seed-pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	binding, err := f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: asset.ID})
	require.NoError(t, err)
	return &memberBindFixture{rotationFixture: f, server: srv, credID: cred.ID, accountID: binding.ID, assetID: asset.ID}, oldLine
}

func (f *memberBindFixture) setRejectVerify(v bool) {
	f.server.mu.Lock()
	f.server.rejectVerifyLogin = v
	f.server.mu.Unlock()
}

// requireMemberHeld 成員因主機身分停在已下達未驗證：原因碼為新碼、派送標記非空、候選保留且 applied、
// 本地就位憑證不動。
func requireMemberHeld(t *testing.T, f *memberBindFixture, rotID uint) *model.CredentialRotationMember {
	t.Helper()
	m := f.member(t, rotID)
	assert.Equal(t, model.CredentialMemberChangedUnverified, m.State)
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, m.LastError)
	assert.NotNil(t, m.SecretSentAt)
	cand, err := f.candidates.FindByAccount(f.accountID)
	require.NoError(t, err)
	require.NotNil(t, cand, "候選保留")
	assert.True(t, cand.Applied)
	return m
}

func runMemberImmediateVerify(t *testing.T) {
	type injection struct {
		name    string
		install func(t *testing.T, f *memberBindFixture, fired *int)
		detail  string
		phase   string
	}
	adopt := func(f *memberBindFixture, t *testing.T, fired *int, remoteShowsNew bool) func() {
		return func() {
			*fired++
			adoptRemoteKey(t, f.server, f.db, f.assetID, remoteShowsNew)
		}
	}
	tamper := func(f *memberBindFixture, t *testing.T, fired *int) func() {
		return func() {
			*fired++
			// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：指紋被竄改而世代不動，驗 fingerprint_changed 防禦分支
			require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", f.assetID).
				UpdateColumn("fingerprint", "SHA256:tampered").Error)
		}
	}
	cases := []injection{
		{"下達後採用B且靶機換B", func(t *testing.T, f *memberBindFixture, fired *int) { f.hookAfterRotate(adopt(f, t, fired, true)) },
			hostIdentityGenerationChanged, hostIdentityPhasePrecheck},
		{"下達後只採用而遠端仍是舊身分", func(t *testing.T, f *memberBindFixture, fired *int) { f.hookAfterRotate(adopt(f, t, fired, false)) },
			hostIdentityGenerationChanged, hostIdentityPhasePrecheck},
		{"下達後直接改指紋而世代不動", func(t *testing.T, f *memberBindFixture, fired *int) { f.hookAfterRotate(tamper(f, t, fired)) },
			hostIdentityFingerprintChanged, hostIdentityPhasePrecheck},
		{"撥號前查庫放行後握手前換B", func(t *testing.T, f *memberBindFixture, fired *int) { f.hookBeforeVerify(adopt(f, t, fired, true)) },
			hostIdentityGenerationChanged, hostIdentityPhaseHandshake},
	}
	for _, split := range []bool{false, true} {
		mode := "整組"
		if split {
			mode = "拆分"
		}
		for _, c := range cases {
			t.Run("密碼/"+mode+"/"+c.name, func(t *testing.T) {
				f := setupMemberBindFixture(t, "")
				fired := 0
				c.install(t, f, &fired)
				rot := f.start(t, split)
				before := f.member(t, rot.ID)
				require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
				require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")

				m := requireMemberHeld(t, f, rot.ID)
				assert.Equal(t, model.HostKeyBindingBound, m.HostKeyBinding, "首次派送經正式回呼已綁定")
				assert.NotEqual(t, before.State, m.State)
				assert.EqualValues(t, 1, f.server.authAttempts.Load(), "只有下達時舊憑證的那一次認證；候選密碼不得再送出")
				f.server.mu.Lock()
				assert.Equal(t, []string{memberServerPassword}, f.server.authPasswords)
				f.server.mu.Unlock()
				assert.Equal(t, memberServerPassword, f.secretOfBinding(t, f.accountID), "本地就位憑證不動")
				requireMemberOneStop(t, f, m.ID, c.detail, c.phase, verificationSentFalse)
			})
		}
	}

	keyCase := func(name string, install func(t *testing.T, f *memberBindFixture, fired *int), detail, phase string) {
		t.Run("SSH金鑰/"+name, func(t *testing.T) {
			f, oldLine := setupMemberKeyFixture(t)
			fired := 0
			install(t, f, &fired)
			rot := f.start(t, false)
			require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
			require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")

			m := requireMemberHeld(t, f, rot.ID)
			assert.NotEqual(t, model.ChangeSecretReasonKeyVerifyFailedRestored, m.LastError)
			keys := f.server.readAuthorizedKeys()
			assert.Contains(t, keys, strings.Fields(oldLine)[1], "舊鑰未刪")
			lines := 0
			for _, l := range strings.Split(keys, "\n") {
				if strings.TrimSpace(l) != "" {
					lines++
				}
			}
			assert.Equal(t, 2, lines, "新鑰留在 authorized_keys、不還原")
			requireMemberOneStop(t, f, m.ID, detail, phase, verificationSentFalse)
		})
	}
	keyCase("撥號前查庫不放行", func(t *testing.T, f *memberBindFixture, fired *int) {
		inner := f.rotations.keyApplier
		f.rotations.keyApplier = func(ctx context.Context, exec rotationExecutor, rt rotationTarget,
			tgt changeSecretTarget, oldPassword, oldPrivateKey, newPrivate []byte, newLine, previousLine,
			keyStrategy string, onDelivered func() error, recheck func(string) string) error {
			return inner(ctx, exec, rt, tgt, oldPassword, oldPrivateKey, newPrivate, newLine, previousLine, keyStrategy,
				func() error {
					err := onDelivered()
					*fired++
					adoptRemoteKey(t, f.server, f.db, f.assetID, true)
					return err
				}, recheck)
		}
	}, hostIdentityGenerationChanged, hostIdentityPhasePrecheck)
	keyCase("握手回呼拒絕", func(t *testing.T, f *memberBindFixture, fired *int) {
		f.hookBeforeVerify(func() {
			*fired++
			adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		})
	}, hostIdentityGenerationChanged, hostIdentityPhaseHandshake)
}

// sentUnverified 第一次下達送出（遠端已換密）但驗證被注入失敗，成員停在已下達未驗證；
// 之後解除注入並把退避清掉，讓成員立即到期。回傳輪替與成員快照。
func sentUnverified(t *testing.T, split bool) (*memberBindFixture, *model.CredentialRotation, *model.CredentialRotationMember) {
	t.Helper()
	f := setupMemberBindFixture(t, "")
	rot := f.start(t, split)
	f.setRejectVerify(true)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	m := f.member(t, rot.ID)
	require.Equal(t, model.CredentialMemberChangedUnverified, m.State, "錯誤: %s", m.LastError)
	require.NotNil(t, m.SecretSentAt)
	require.Equal(t, model.HostKeyBindingBound, m.HostKeyBinding)
	f.setRejectVerify(false)
	require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).
		Update("next_attempt_at", nil).Error)
	return f, rot, f.member(t, rot.ID)
}

func revokeRotationInitiator(t *testing.T, f *memberBindFixture, rot *model.CredentialRotation, m *model.CredentialRotationMember) {
	t.Helper()
	f.perms.deny(CredCapRotate, CredCapAccountRotate)
	require.Equal(t, model.ChangeSecretReasonAuthzRevoked, f.rotations.revalidateMember(context.Background(), rot, m),
		"夾具必須真的使發起者失權（否則後續斷言由授權正常分支假綠）")
}

func runMemberVerifyBranches(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		branch := "授權正常"
		if revoked {
			branch = "失權有限驗證"
		}
		prep := func(t *testing.T) (*memberBindFixture, *model.CredentialRotation, *model.CredentialRotationMember, int32) {
			f, rot, m := sentUnverified(t, false)
			if revoked {
				revokeRotationInitiator(t, f, rot, m)
			}
			return f, rot, m, f.server.authAttempts.Load()
		}
		t.Run(branch+"/對照：身分未變照常驗證並就位", func(t *testing.T) {
			f, rot, m, base := prep(t)
			require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
			after := f.member(t, rot.ID)
			assert.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
			assert.Greater(t, f.server.authAttempts.Load(), base, "確實撥號驗證")
			assert.Empty(t, memberStops(t, f.db))
		})
		t.Run(branch+"/撥號前查庫停止", func(t *testing.T) {
			f, rot, m, base := prep(t)
			adoptRemoteKey(t, f.server, f.db, f.assetID, true)
			require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
			requireMemberHeld(t, f, rot.ID)
			assert.EqualValues(t, base, f.server.authAttempts.Load(), "候選密碼不得送出")
			requireMemberOneStop(t, f, m.ID, hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse)
		})
		t.Run(branch+"/握手回呼拒絕", func(t *testing.T) {
			f, rot, m, base := prep(t)
			fired := 0
			f.hookBeforeVerify(func() {
				fired++
				adoptRemoteKey(t, f.server, f.db, f.assetID, true)
			})
			require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
			require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")
			requireMemberHeld(t, f, rot.ID)
			assert.EqualValues(t, base, f.server.authAttempts.Load(), "握手即拒絕：沒有認證嘗試")
			requireMemberOneStop(t, f, m.ID, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentFalse)
		})
	}
}

// makeLegacy 把成員列改成升級前的樣子：綁定欄全部清空、綁定狀態為 legacy；marker 決定派送標記是否保留。
func makeLegacy(t *testing.T, db *gorm.DB, memberID uint, marker bool) {
	t.Helper()
	updates := map[string]any{
		"host_key_binding": model.HostKeyBindingLegacy, "host_key_transport": "", "host_key_record_id": 0,
		"host_key_algorithm": "", "host_key_fingerprint": "", "host_key_generation": 0, "host_key_bound_at": nil,
	}
	if !marker {
		updates["secret_sent_at"] = nil
	}
	require.NoError(t, db.Model(&model.CredentialRotationMember{}).Where("id = ?", memberID).Updates(updates).Error)
}

func runMemberLegacyRequeue(t *testing.T) {
	type tc struct {
		name      string
		split     bool
		marker    bool
		state     string
		lastError string
		clearCand bool
	}
	cases := []tc{
		{"升級前已送出且LastError被其他失敗覆蓋", false, false, model.CredentialMemberTerminalFailed, model.ChangeSecretReasonRetryLoginFailed, false},
		{"中斷", false, false, model.CredentialMemberTerminalFailed, model.ChangeSecretReasonInterrupted, false},
		{"放棄", false, false, model.CredentialMemberAbandoned, model.ChangeSecretReasonRetryLoginFailed, false},
		{"migration已標記且候選被管理員清除", false, true, model.CredentialMemberTerminalFailed, model.ChangeSecretReasonRetryLoginFailed, true},
		{"拆分模式已標記", true, true, model.CredentialMemberTerminalFailed, model.ChangeSecretReasonRetryLoginFailed, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, rot, m := sentUnverified(t, c.split)
			makeLegacy(t, f.db, m.ID, c.marker)
			if c.clearCand {
				cand, err := f.candidates.FindByAccount(f.accountID)
				require.NoError(t, err)
				require.NotNil(t, cand)
				require.NoError(t, f.candidates.Discard(cand.ID))
			}
			require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).
				Updates(map[string]any{"state": c.state, "last_error": c.lastError}).Error)
			legacy := f.member(t, rot.ID)

			adoptRemoteKey(t, f.server, f.db, f.assetID, true)
			rotates := 0
			f.wrapExecutors(func(e rotationExecutor) rotationExecutor { return rotateCounter{e, &rotates} })
			f.server.authAttempts.Store(0)
			f.server.chpasswdCalls.Store(0)
			require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))

			after := f.member(t, rot.ID)
			assert.Equal(t, model.CredentialMemberChangedUnverified, after.State, "重排成功但下達前被擋下")
			assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, after.LastError)
			assert.EqualValues(t, 0, f.server.authAttempts.Load(), "沒有任何認證嘗試")
			assert.EqualValues(t, 0, f.server.chpasswdCalls.Load())
			assert.Equal(t, 0, rotates, "Rotate 呼叫 0")
			assert.Equal(t, snapshotOf(legacy), snapshotOf(after), "快照欄仍為升級前的零值")
			assert.Equal(t, model.HostKeyBindingLegacy, after.HostKeyBinding)
			requireMemberOneStop(t, f, m.ID, hostIdentityUnboundLegacy, hostIdentityPhasePrecheck, verificationSentFalse)
		})
	}
}

// 正面案例：升級前建立、確定從未送出（未標記）的成員照常首次派送並綁定。
func runMemberLegacyPositive(t *testing.T) {
	for _, split := range []bool{false, true} {
		name := "整組模式未標記且無候選列"
		if split {
			name = "拆分模式未標記且候選列為起始所建"
		}
		t.Run(name, func(t *testing.T) {
			f := setupMemberBindFixture(t, "")
			rot := f.start(t, split)
			m := f.member(t, rot.ID)
			makeLegacy(t, f.db, m.ID, false)
			if split {
				require.EqualValues(t, 1, f.candidateCountFor(t, f.accountID), "拆分候選為起始交易所建、從未送出")
			} else {
				require.EqualValues(t, 0, f.candidateCountFor(t, f.accountID), "整組模式沒有候選列")
			}
			binds := 0
			f.rotations.hostKeys.bindTxBarrier = func(*gorm.DB) { binds++ }
			w := f.watchAuth()
			require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
			after := f.member(t, rot.ID)
			require.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
			assert.Equal(t, 1, binds, "進入綁定寫入，且條件式更新受影響 1 列（兩層資格不回歸：副本重建後仍可綁定）")
			assert.Equal(t, model.HostKeyBindingBound, after.HostKeyBinding)
			requireMemberBoundAtAuth(t, f, w)
			assert.Empty(t, memberStops(t, f.db), "不出現 host_identity 停止")
		})
	}
}

// moveRemoteTo 把資產指向另一台靶機，並經正式不符觀察加 Adopt 採用它的金鑰（超管採用新主機；世代加一，位址隨觀察更新）。
func moveRemoteTo(t *testing.T, f *memberBindFixture, b *testSSHServer) {
	t.Helper()
	host, port := serverAddr2(t, b)
	require.NoError(t, f.db.Model(&model.Asset{}).Where("id = ?", f.assetID).
		Updates(map[string]any{"host": host, "port": port}).Error)
	adoptObservedKey(t, f.db, f.assetID, b.currentHostKey().PublicKey())
}

func secretAttemptsAt(srv *testSSHServer, secret string) int {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	n := 0
	for _, p := range srv.authPasswords {
		if p == secret {
			n++
		}
	}
	return n
}

func lastAuthPassword(srv *testSSHServer) string {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.authPasswords[len(srv.authPasswords)-1]
}

func runMemberDeliveryHistory(t *testing.T) {
	// 已對 A 下達過秘密 S 的成員，在主機換成 B 之後補跑：不得把 S 或任何認證送到 B。
	requireNothingSentToB := func(t *testing.T, f *memberBindFixture, b *testSSHServer, secret string, before *model.CredentialRotationMember, rotID uint) {
		t.Helper()
		after := f.member(t, rotID)
		assert.EqualValues(t, 0, secretAttemptsAt(b, secret), "S 不得出現在 B")
		assert.EqualValues(t, 0, b.authAttempts.Load(), "B 沒有任何認證嘗試")
		assert.EqualValues(t, 0, b.chpasswdCalls.Load())
		assert.Equal(t, snapshotOf(before), snapshotOf(after), "成員快照四欄不變")
		require.NotNil(t, after.SecretSentAt)
		assert.True(t, before.SecretSentAt.Equal(*after.SecretSentAt), "派送標記不變")
		assert.Equal(t, model.CredentialMemberChangedUnverified, after.State)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, after.LastError)
		requireMemberOneStop(t, f, after.ID, hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse)
	}

	t.Run("反例1/整組成員已下達S且候選被清除後主機換成B", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		secret := lastAuthPassword(f.server)
		require.NotEqual(t, memberServerPassword, secret)
		require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).
			Update("state", model.CredentialMemberTerminalFailed).Error)
		cand, err := f.candidates.FindByAccount(f.accountID)
		require.NoError(t, err)
		require.NotNil(t, cand)
		require.NoError(t, f.candidates.Discard(cand.ID))
		b := newTestSSHServer(t, memberServerUser, memberServerPassword)
		moveRemoteTo(t, f, b)
		rotates := 0
		f.wrapExecutors(func(e rotationExecutor) rotationExecutor { return rotateCounter{e, &rotates} })
		before := f.member(t, rot.ID)

		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
		assert.Equal(t, 0, rotates, "Rotate 呼叫 0")
		requireNothingSentToB(t, f, b, secret, before, rot.ID)
	})

	t.Run("反例2/送出後補跑舊憑證被拒再主機換成B", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		secret := lastAuthPassword(f.server)
		require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).
			Update("state", model.CredentialMemberTerminalFailed).Error)
		before := f.member(t, rot.ID)
		// 補跑：A 現在的密碼是 S，舊憑證登入被拒（乾淨失敗：候選副本被刪、標記不變）
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
		mid := f.member(t, rot.ID)
		require.Equal(t, model.CredentialMemberRetryWait, mid.State, "錯誤: %s", mid.LastError)
		require.EqualValues(t, 0, f.candidateCountFor(t, f.accountID), "乾淨失敗：候選副本被刪")
		require.NotNil(t, mid.SecretSentAt)
		require.True(t, before.SecretSentAt.Equal(*mid.SecretSentAt), "標記不變")
		assert.Equal(t, snapshotOf(before), snapshotOf(mid))

		b := newTestSSHServer(t, memberServerUser, memberServerPassword)
		moveRemoteTo(t, f, b)
		rotates := 0
		f.wrapExecutors(func(e rotationExecutor) rotationExecutor { return rotateCounter{e, &rotates} })
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
		assert.Equal(t, 0, rotates, "Rotate 呼叫 0")
		requireNothingSentToB(t, f, b, secret, before, rot.ID)
	})

	t.Run("對照3/首次下達即舊憑證被拒的成員在採用B後重新綁定", func(t *testing.T) {
		f := setupMemberBindFixture(t, "")
		rot := f.start(t, false)
		f.server.setPassword("someone-else-entirely")
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		m := f.member(t, rot.ID)
		require.Equal(t, model.CredentialMemberRetryWait, m.State, "錯誤: %s", m.LastError)
		require.Nil(t, m.SecretSentAt, "首次下達即乾淨失敗：標記為 NULL")
		require.Equal(t, model.HostKeyBindingBound, m.HostKeyBinding, "第一次握手已綁定")

		b := newTestSSHServer(t, memberServerUser, memberServerPassword)
		moveRemoteTo(t, f, b)
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
		after := f.member(t, rot.ID)
		require.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
		var own model.AssetHostKey
		require.NoError(t, f.db.Where("asset_id = ?", f.assetID).First(&own).Error)
		assert.Equal(t, ssh.FingerprintSHA256(b.currentHostKey().PublicKey()), after.HostKeyFingerprint, "重新綁定到 B")
		assert.Equal(t, own.TrustGeneration, after.HostKeyGeneration)
		assert.Equal(t, own.ID, after.HostKeyRecordID)
		require.NotNil(t, after.SecretSentAt, "標記於轉 changed_unverified 時寫入")
		assert.Greater(t, b.authAttempts.Load(), int32(0))
		assert.Empty(t, memberStops(t, f.db))
	})
}

// addMemberTarget 為同一筆共用憑證再掛一台真 SSH 靶機，回傳靶機、資產與掛載識別。
func addMemberTarget(t *testing.T, f *memberBindFixture) (*testSSHServer, uint, uint) {
	t.Helper()
	srv := newTestSSHServer(t, memberServerUser, memberServerPassword)
	host, port := serverAddr2(t, srv)
	asset, err := f.assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: "member-target-2", Protocol: model.ProtocolSSH, Host: host, Port: port,
		Username: "seed", Password: "seed-pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	binding, err := f.creds.Bind(adminCtx(), f.credID, &BindCredentialRequest{AssetID: asset.ID})
	require.NoError(t, err)
	return srv, asset.ID, binding.ID
}

func runMemberOneStopsOthersContinue(t *testing.T) {
	for _, split := range []bool{false, true} {
		name := "整組"
		if split {
			name = "拆分"
		}
		t.Run(name, func(t *testing.T) {
			f := setupMemberBindFixture(t, "")
			srv2, _, acc2 := addMemberTarget(t, f)
			rot := f.start(t, split)
			f.setRejectVerify(true)
			srv2.mu.Lock()
			srv2.rejectVerifyLogin = true
			srv2.mu.Unlock()
			require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
			m1, m2 := f.member(t, rot.ID), f.memberFor(t, rot.ID, acc2)
			require.Equal(t, model.CredentialMemberChangedUnverified, m1.State, "錯誤: %s", m1.LastError)
			require.Equal(t, model.CredentialMemberChangedUnverified, m2.State, "錯誤: %s", m2.LastError)

			f.setRejectVerify(false)
			srv2.mu.Lock()
			srv2.rejectVerifyLogin = false
			srv2.mu.Unlock()
			require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("rotation_id = ?", rot.ID).
				Update("next_attempt_at", nil).Error)
			adoptRemoteKey(t, f.server, f.db, f.assetID, true) // 只有第一台的身分改變
			base1, base2 := f.server.authAttempts.Load(), srv2.authAttempts.Load()

			for _, mid := range []uint{m1.ID, m2.ID} {
				advanced, aerr := f.rotations.AdvanceMemberInBackground(context.Background(), rot.ID, mid)
				require.NoError(t, aerr)
				require.True(t, advanced, "到期成員被背景推進")
			}

			after1, after2 := f.member(t, rot.ID), f.memberFor(t, rot.ID, acc2)
			assert.Equal(t, model.CredentialMemberChangedUnverified, after1.State, "異動的成員停止")
			assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, after1.LastError)
			assert.EqualValues(t, base1, f.server.authAttempts.Load(), "被停止的成員沒有新的認證")
			assert.Equal(t, model.CredentialMemberApplied, after2.State, "其他成員照常驗證與就位，錯誤: %s", after2.LastError)
			assert.Greater(t, srv2.authAttempts.Load(), base2)
			requireMemberOneStop(t, f, after1.ID, hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse)
		})
	}
}

func runNewWorkAfterAdoption(t *testing.T) {
	t.Run("一般新工作", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		records := f.runner.RunPlan(f.plan(t, nil))
		require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		var own model.AssetHostKey
		require.NoError(t, f.db.Where("asset_id = ?", f.assetID).First(&own).Error)

		w := watchAuth(f)
		f.server.authAttempts.Store(0)
		f.server.setPassword(f.storedPassword(t)) // 靶機密碼與本地一致（第一次輪替已生效）
		records = f.runner.RunPlan(f.plan(t, nil))
		require.Len(t, records, 1)
		require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
		snaps := requireBoundAtAuth(t, f, w)
		assert.Equal(t, own.TrustGeneration, snaps[0].cand.HostKeyGeneration, "以採用後的新身分綁定")
		assert.Equal(t, ssh.FingerprintSHA256(f.server.currentHostKey().PublicKey()), snaps[0].cand.HostKeyFingerprint)
		assert.Empty(t, stopAuditDetails(t, f))
	})
	t.Run("輪替新工作", func(t *testing.T) {
		f := setupMemberBindFixture(t, "")
		rot := f.start(t, false)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		first := f.member(t, rot.ID)
		require.Equal(t, model.CredentialMemberApplied, first.State, "錯誤: %s", first.LastError)
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		var own model.AssetHostKey
		require.NoError(t, f.db.Where("asset_id = ?", f.assetID).First(&own).Error)
		f.server.setPassword(f.secretOfBinding(t, f.accountID))

		rot2 := f.start(t, false)
		w := f.watchAuth()
		f.server.authAttempts.Store(0)
		require.NoError(t, f.rotations.Run(adminCtx(), rot2.ID))
		m := f.member(t, rot2.ID)
		require.Equal(t, model.CredentialMemberApplied, m.State, "錯誤: %s", m.LastError)
		assert.Equal(t, own.TrustGeneration, m.HostKeyGeneration, "以採用後的新身分綁定")
		assert.Equal(t, ssh.FingerprintSHA256(f.server.currentHostKey().PublicKey()), m.HostKeyFingerprint)
		requireMemberBoundAtAuth(t, f, w)
		assert.Empty(t, memberStops(t, f.db))
	})
}
