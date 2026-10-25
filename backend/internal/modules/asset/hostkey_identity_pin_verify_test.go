package asset

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 派送後立即 Verify 的主機身分守衛子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.4/）。
// 夾具的綁定一律經正式回呼（RunPlan 的首次派送）；採用經正式的觀察加 Adopt 路徑。

// adoptRemoteKey 靶機切鑰，並由正式的不符觀察加 HostKeyService.Adopt 把新金鑰採用為該資產的自身記錄
// （指紋、演算法、公鑰格式與信任世代遞增、觀察消耗、採用審計全部走產品路徑）。
// remoteShowsNew=false 時採用後靶機換回原金鑰（只採用、遠端仍是舊身分）。
// 常在靶機的 goroutine 內呼叫：不得用 require（FailNow 會讓客戶端永遠等不到回應）。
func adoptRemoteKey(t *testing.T, srv *testSSHServer, db *gorm.DB, assetID uint, remoteShowsNew bool) {
	t.Helper()
	orig := srv.currentHostKey()
	pub := srv.swapHostKey(t)
	adoptObservedKey(t, db, assetID, pub)
	if !remoteShowsNew {
		srv.setHostKey(orig)
	}
}

// adoptBackToSigner 靶機換成指定金鑰，並經正式觀察加 Adopt 把它採用為自身記錄（世代遞增）。
func adoptBackToSigner(t *testing.T, srv *testSSHServer, db *gorm.DB, assetID uint, signer ssh.Signer) {
	t.Helper()
	srv.setHostKey(signer)
	adoptObservedKey(t, db, assetID, signer.PublicKey())
}

// adoptObservedKey 以背景作業的撥號脈絡讓正式回呼觀察到 pub（與自身記錄不符，寫觀察紀錄並拒絕），
// 再由超管身分呼叫 Adopt 採用該指紋。正式服務的狀態全在資料庫，這裡另建一個服務實例即可。
func adoptObservedKey(t *testing.T, db *gorm.DB, assetID uint, pub ssh.PublicKey) {
	t.Helper()
	if !db.Migrator().HasTable(&model.AssetHostKeyMismatch{}) {
		if err := db.AutoMigrate(&model.AssetHostKeyMismatch{}); err != nil {
			t.Errorf("建立觀察表失敗: %v", err)
			return
		}
	}
	svc := NewHostKeyService(db)
	svc.SetAuditTxSink(audit.NewTxSink())
	svc.SetSystemAlertSink(newFakeAlertSink())
	var asset model.Asset
	if err := db.First(&asset, assetID).Error; err != nil {
		t.Errorf("讀資產失敗: %v", err)
		return
	}
	dc := HostKeyDialContext{AssetID: assetID, Path: HostKeyPathCredentialChange, UserID: 1, Username: "super"}
	cb, _ := svc.CallbackFor(dc)
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: asset.Port}
	if err := cb(net.JoinHostPort(asset.Host, strconv.Itoa(asset.Port)), remote, pub); !errors.Is(err, ErrHostKeyChanged) {
		t.Errorf("正式回呼應觀察到不符並拒絕，實際 err=%v", err)
		return
	}
	if _, err := svc.Adopt(assetID, ssh.FingerprintSHA256(pub), HostKeyActor{UserID: 1, Username: "super"}); err != nil {
		t.Errorf("Adopt 失敗: %v", err)
	}
}

func wireStopAudit(f *csFixture) {
	f.runner.WithAuditSink(audit.NewTxSink())
}

func stopAuditDetails(t *testing.T, f *csFixture) []map[string]any {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, f.db.Where("details LIKE ?", `%"operation":"host_identity_stop"%`).Order("id ASC").Find(&rows).Error)
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.Details), &d))
		out = append(out, d)
	}
	return out
}

func requireOneStop(t *testing.T, f *csFixture, detail, phase, sent string) {
	t.Helper()
	stops := stopAuditDetails(t, f)
	require.Len(t, stops, 1, "每個停止工作每個身分狀態 token 恰一筆停止審計")
	assert.Equal(t, detail, stops[0]["detail"])
	assert.Equal(t, phase, stops[0]["phase"])
	assert.Equal(t, sent, stops[0]["verification_sent"])
	assert.Equal(t, true, stops[0]["candidate_retained"])
}

func candidateOfAccount(t *testing.T, f *csFixture) model.ChangeSecretCandidate {
	t.Helper()
	var c model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("account_id = ?", f.accountID).First(&c).Error)
	return c
}

// verifyHookExecutor 在 Verify 撥號之前插入一段動作（撥號前查庫已放行之後、握手之前）。
type verifyHookExecutor struct {
	rotationExecutor
	beforeVerify func()
}

func (h verifyHookExecutor) Verify(ctx context.Context, rt rotationTarget, secret []byte) error {
	if h.beforeVerify != nil {
		h.beforeVerify()
	}
	return h.rotationExecutor.Verify(ctx, rt, secret)
}

func runImmediateVerifyPassword(t *testing.T) {
	cases := []struct {
		name   string
		inject func(t *testing.T, f *csFixture)
		detail string
	}{
		{"驗證前採用B且靶機換B", func(t *testing.T, f *csFixture) { adoptRemoteKey(t, f.server, f.db, f.assetID, true) }, hostIdentityGenerationChanged},
		{"只採用而遠端仍是舊身分", func(t *testing.T, f *csFixture) { adoptRemoteKey(t, f.server, f.db, f.assetID, false) }, hostIdentityGenerationChanged},
		{"直接改指紋而世代不動", func(t *testing.T, f *csFixture) {
			// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：指紋被竄改而世代不動，驗 fingerprint_changed 防禦分支
			require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", f.assetID).
				UpdateColumn("fingerprint", "SHA256:tampered").Error)
		}, hostIdentityFingerprintChanged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := setupChangeSecretFixture(t, "root", "oldpass123")
			wireStopAudit(f)
			fired := 0
			f.server.mu.Lock()
			f.server.onExec = func(n int32) {
				if n == 1 {
					fired++
					c.inject(t, f)
				}
			}
			f.server.mu.Unlock()

			records := f.runner.RunPlan(f.plan(t, nil))
			require.Len(t, records, 1)
			require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")
			assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
			assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, records[0].Error)
			cand := candidateOfAccount(t, f)
			assert.True(t, cand.Applied, "派送已完成：applied 保留為 true")
			assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, cand.LastError)
			assert.Equal(t, "oldpass123", f.storedPassword(t), "本地憑證不動")
			assert.EqualValues(t, 1, f.server.authAttempts.Load(), "只有下達時舊憑證的那一次認證；候選密碼不得再送出")
			f.server.mu.Lock()
			assert.Equal(t, []string{"oldpass123"}, f.server.authPasswords)
			f.server.mu.Unlock()
			requireOneStop(t, f, c.detail, hostIdentityPhasePrecheck, verificationSentFalse)
		})
	}
}

func runImmediateVerifyKey(t *testing.T) {
	assertNotRestored := func(t *testing.T, f *csFixture, oldLine string) {
		t.Helper()
		keys := 0
		for _, ln := range strings.Split(f.server.readAuthorizedKeys(), "\n") {
			if strings.TrimSpace(ln) != "" {
				keys++
			}
		}
		assert.Equal(t, 2, keys, "新鑰留在 authorized_keys：不還原")
		assert.Contains(t, f.server.readAuthorizedKeys(), strings.Fields(oldLine)[1], "舊鑰未刪")
	}
	prep := func(t *testing.T) (*csFixture, string) {
		f := keyRotationFixture(t)
		wireStopAudit(f)
		return f, strings.TrimSpace(f.server.readAuthorizedKeys())
	}
	check := func(t *testing.T, f *csFixture, rec model.ChangeSecretRecord, oldLine string) {
		t.Helper()
		assert.Equal(t, model.ChangeSecretUnverified, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, rec.Error)
		assert.NotEqual(t, model.ChangeSecretReasonKeyVerifyFailedRestored, rec.Error)
		assertNotRestored(t, f, oldLine)
		cand := candidateOfAccount(t, f)
		assert.True(t, cand.Applied)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, cand.LastError)
	}

	t.Run("撥號前查庫不放行", func(t *testing.T) {
		f, oldLine := prep(t)
		fired := 0
		f.server.mu.Lock()
		f.server.onSFTP = func() { fired++; adoptRemoteKey(t, f.server, f.db, f.assetID, true) }
		f.server.mu.Unlock()
		records := f.runner.RunPlan(f.keyPlan(t))
		require.Len(t, records, 1)
		require.Equal(t, 1, fired, "注入器必須真的觸發")
		check(t, f, records[0], oldLine)
		assert.EqualValues(t, 1, f.server.authAttempts.Load(), "只有下達時舊憑證的認證，新私鑰不得送出")
		requireOneStop(t, f, hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse)
	})

	t.Run("握手回呼拒絕", func(t *testing.T) {
		f, oldLine := prep(t)
		fired := 0
		base := f.runner.executors
		f.runner.executors = func(ch string) rotationExecutor {
			return verifyHookExecutor{rotationExecutor: base(ch), beforeVerify: func() {
				fired++
				adoptRemoteKey(t, f.server, f.db, f.assetID, true)
			}}
		}
		records := f.runner.RunPlan(f.keyPlan(t))
		require.Len(t, records, 1)
		require.Equal(t, 1, fired, "注入器必須真的觸發")
		check(t, f, records[0], oldLine)
		assert.EqualValues(t, 1, f.server.authAttempts.Load(), "握手即被拒，新私鑰未送出")
		requireOneStop(t, f, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentFalse)
	})
}

func addWindowsSSHAsset(t *testing.T, fx *csFixture, srv *testSSHServer) uint {
	t.Helper()
	_, portStr, err := net.SplitHostPort(srv.addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return fx.addRotationAsset(t, &CreateAssetRequest{
		Name: "win-ssh-identity", Protocol: model.ProtocolRDP, Host: "127.0.0.1", Port: 3389,
		Username: "Administrator", Password: "winoldpass",
		RotationChannel: model.RotationChannelWindowsSSH, RotationSSHPort: port,
	})
}

func runImmediateVerifyWindowsSSH(t *testing.T) {
	setup := func(t *testing.T) (*csFixture, *testSSHServer, uint) {
		fx := setupChangeSecretFixture(t, "root", "oldpass123")
		wireStopAudit(fx)
		srv := newTestSSHServer(t, "Administrator", "winoldpass")
		srv.mu.Lock()
		srv.windowsApplyStdinPassword = true
		srv.mu.Unlock()
		id := addWindowsSSHAsset(t, fx, srv)
		fx.runner.executors = func(string) rotationExecutor { return testWindowsSSHExecutor(nil) }
		return fx, srv, id
	}
	planFor := func(fx *csFixture, id uint) *model.ChangeSecretPlan { return fx.planForAssets(t, []uint{id}, nil) }

	t.Run("第一次撥號已用候選認證成功後第二次撥號被拒", func(t *testing.T) {
		fx, srv, id := setup(t)
		fired := 0
		srv.mu.Lock()
		srv.execExitByCall = map[int32]int{2: 1} // 第一次驗證指令失敗，逼出第二次撥號
		srv.onExec = func(n int32) {
			if n == 2 {
				fired++
				adoptRemoteKey(t, srv, fx.db, id, true)
			}
		}
		srv.mu.Unlock()
		records := fx.runner.RunPlan(planFor(fx, id))
		require.Len(t, records, 1)
		require.Equal(t, 1, fired, "注入器必須真的觸發")
		assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, records[0].Error)
		requireOneStop(t, fx, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentTrue)
	})

	t.Run("兩次撥號都在回呼被拒", func(t *testing.T) {
		fx, srv, id := setup(t)
		fired := 0
		base := fx.runner.executors
		fx.runner.executors = func(ch string) rotationExecutor {
			return verifyHookExecutor{rotationExecutor: base(ch), beforeVerify: func() {
				fired++
				adoptRemoteKey(t, srv, fx.db, id, true)
			}}
		}
		records := fx.runner.RunPlan(planFor(fx, id))
		require.Len(t, records, 1)
		require.Equal(t, 1, fired, "注入器必須真的觸發")
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, records[0].Error)
		requireOneStop(t, fx, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentFalse)
		assert.EqualValues(t, 1, srv.chpasswdCalls.Load(), "驗證指令一次都沒有跑")
	})
}

const failMarkTriggerSQL = `CREATE TRIGGER fail_mark_applied BEFORE UPDATE OF applied ON change_secret_candidates
	BEGIN SELECT RAISE(ABORT, 'mark failed'); END`

// runMarkAppliedMatrix 四個下達標記點各注入失敗一案，每案再分 (i) 驗證另失敗、(ii) 驗證與提交成功。
func runMarkAppliedMatrix(t *testing.T) {
	t.Run("一般密碼", func(t *testing.T) {
		t.Run("驗證另失敗", func(t *testing.T) {
			f := setupChangeSecretFixture(t, "root", "oldpass123")
			require.NoError(t, f.db.Exec(failMarkTriggerSQL).Error)
			f.server.mu.Lock()
			f.server.rejectVerifyLogin = true
			f.server.mu.Unlock()
			logs := captureLog(t)
			records := f.runner.RunPlan(f.plan(t, nil))
			require.Len(t, records, 1)
			require.Positive(t, f.server.verifyRejectFired.Load(), "驗證失敗注入器必須觸發")
			assert.Contains(t, logs(), "標記候選已下達失敗", "標記失敗記 log 並繼續驗證")
			assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
			assert.Equal(t, model.ChangeSecretReasonVerifyFailed, records[0].Error, "既有驗證失敗碼")
			cand := candidateOfAccount(t, f)
			assert.False(t, cand.Applied, "標記沒寫進去：applied 保持 false")
			assert.Equal(t, "oldpass123", f.storedPassword(t))
		})
		t.Run("驗證與提交成功", func(t *testing.T) {
			f := setupChangeSecretFixture(t, "root", "oldpass123")
			require.NoError(t, f.db.Exec(failMarkTriggerSQL).Error)
			records := f.runner.RunPlan(f.plan(t, nil))
			require.Len(t, records, 1)
			assert.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
			assert.EqualValues(t, 0, f.candidateCount(t), "照常就位、候選刪除")
			assert.Equal(t, f.server.currentPassword(), f.storedPassword(t))
		})
	})

	t.Run("一般SSH金鑰", func(t *testing.T) {
		t.Run("驗證另失敗且還原也失敗", func(t *testing.T) {
			f := keyRotationFixture(t)
			require.NoError(t, f.db.Exec(failMarkTriggerSQL).Error)
			var attempts int
			f.server.mu.Lock()
			f.server.onAuthAttempt = func() {
				attempts++
				if attempts != 2 {
					return
				}
				// 驗證登入前把 .ssh 換成檔案：驗證讀不到 authorized_keys，同一條 SFTP 連線上的還原也寫不進去
				ssh := filepath.Join(f.server.homeDir, ".ssh")
				_ = os.Rename(ssh, ssh+".bak")
				_ = os.WriteFile(ssh, []byte("x"), 0o600)
			}
			f.server.mu.Unlock()
			logs := captureLog(t)
			records := f.runner.RunPlan(f.keyPlan(t))
			require.Len(t, records, 1)
			require.Equal(t, 2, attempts, "驗證失敗注入器必須觸發")
			assert.Contains(t, logs(), "標記候選已下達失敗")
			assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
			assert.Equal(t, model.ChangeSecretReasonKeyVerifyFailedRestoreFailed, records[0].Error)
			assert.False(t, candidateOfAccount(t, f).Applied, "applied 保持 false，候選保留")
		})
		t.Run("驗證與提交成功", func(t *testing.T) {
			f := keyRotationFixture(t)
			require.NoError(t, f.db.Exec(failMarkTriggerSQL).Error)
			records := f.runner.RunPlan(f.keyPlan(t))
			require.Len(t, records, 1)
			assert.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
			assert.EqualValues(t, 0, f.candidateCount(t))
		})
	})

	t.Run("成員密碼", func(t *testing.T) {
		prep := func(t *testing.T, host string, verifyFails bool) (*batchFixture, uint, uint, *model.CredentialRotation) {
			f := setupBatchFixture(t)
			credID, accounts := f.sharedOn(t, "標記失敗-"+host, "ops", "old-shared", host)
			rec := newSecretRecorder()
			if verifyFails {
				rec.verifyErr[host] = assert.AnError
			}
			f.useRotationExecutor(rec)
			require.NoError(t, f.db.Exec(failMarkTriggerSQL).Error)
			rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
			require.NoError(t, err)
			require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
			return f, credID, accounts[0], rot
		}
		t.Run("驗證另失敗", func(t *testing.T) {
			f, _, acc, rot := prep(t, "10.41.1.1", true)
			m := f.memberOf(t, rot.ID, acc)
			assert.Equal(t, model.CredentialMemberChangedUnverified, m.State, "成員仍轉已下達未驗證")
			assert.NotNil(t, m.SecretSentAt, "派送標記照寫")
			assert.False(t, f.candidateByAccount(t, acc).Applied, "applied 保持 false，候選保留")
		})
		t.Run("驗證與提交成功", func(t *testing.T) {
			f, _, acc, rot := prep(t, "10.41.2.1", false)
			m := f.memberOf(t, rot.ID, acc)
			assert.Equal(t, model.CredentialMemberApplied, m.State)
			assert.NotNil(t, m.SecretSentAt)
			assert.EqualValues(t, 0, f.candidateCountFor(t, acc), "照常就位、候選刪除")
		})
	})
}
