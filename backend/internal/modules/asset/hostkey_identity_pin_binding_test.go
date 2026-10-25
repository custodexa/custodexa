package asset

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 綁定回呼的子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.1/）。

// authSnap 伺服器收到一次認證嘗試的那一刻，從資料庫讀到的候選列與自身列。
type authSnap struct {
	cand    model.ChangeSecretCandidate
	candErr error
	own     model.AssetHostKey
	ownErr  error
}

type authWatch struct {
	mu    sync.Mutex
	snaps []authSnap
}

func (w *authWatch) list() []authSnap {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]authSnap(nil), w.snaps...)
}

// watchAuth 讓靶機在每次認證嘗試的回呼內讀庫（證明「認證前」的資料庫狀態）。
func watchAuth(f *csFixture) *authWatch {
	w := &authWatch{}
	f.server.mu.Lock()
	f.server.onAuthAttempt = func() {
		var s authSnap
		s.candErr = f.db.Where("account_id = ?", f.accountID).First(&s.cand).Error
		s.ownErr = f.db.Where("asset_id = ?", f.assetID).First(&s.own).Error
		w.mu.Lock()
		w.snaps = append(w.snaps, s)
		w.mu.Unlock()
	}
	f.server.mu.Unlock()
	return w
}

// requireBoundAtAuth 每次認證嘗試發生時，候選列都已是 bound、ssh，且四個快照欄等於靶機出示的金鑰與自身列世代。
func requireBoundAtAuth(t *testing.T, f *csFixture, w *authWatch) []authSnap {
	t.Helper()
	snaps := w.list()
	require.NotEmpty(t, snaps, "靶機沒有收到任何認證：斷言將由空值假綠")
	require.EqualValues(t, f.server.authAttempts.Load(), len(snaps))
	pub := f.server.hostKey.PublicKey()
	for i, s := range snaps {
		require.NoError(t, s.candErr, "第 %d 次認證時候選列應存在", i+1)
		require.NoError(t, s.ownErr, "第 %d 次認證時自身列應存在", i+1)
		assert.Equal(t, model.HostKeyBindingBound, s.cand.HostKeyBinding, "第 %d 次認證前應已綁定", i+1)
		assert.Equal(t, model.HostKeyTransportSSH, s.cand.HostKeyTransport)
		assert.Equal(t, s.own.ID, s.cand.HostKeyRecordID)
		assert.Equal(t, pub.Type(), s.cand.HostKeyAlgorithm)
		assert.Equal(t, ssh.FingerprintSHA256(pub), s.cand.HostKeyFingerprint)
		assert.Equal(t, s.own.TrustGeneration, s.cand.HostKeyGeneration)
		assert.NotNil(t, s.cand.HostKeyBoundAt)
	}
	return snaps
}

func keyRotationFixture(t *testing.T) *csFixture {
	t.Helper()
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	oldPriv, oldLine := testKeyPair(t, "old-system-key")
	f.server.seedAuthorizedKeys(oldLine + "\n")
	require.NoError(t, f.assets.UpdatePrivateKey(f.assetID, f.accountID, "root", oldPriv))
	return f
}

func (f *csFixture) keyPlan(t *testing.T) *model.ChangeSecretPlan {
	return f.plan(t, func(p *model.ChangeSecretPlan) { p.SecretType = model.ChangeSecretTypeSSHKey })
}

func serverAddr(t *testing.T, f *csFixture) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(f.server.addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}

// runBindingFirstDelivery 經正式 RunPlan 觸發的首次派送：密碼與 SSH 金鑰兩種。
func runBindingFirstDelivery(t *testing.T) {
	t.Run("密碼與SSH金鑰首次派送在認證前已綁定", func(t *testing.T) {
		t.Run("密碼", func(t *testing.T) {
			f := setupChangeSecretFixture(t, "root", "oldpass123")
			w := watchAuth(f)
			records := f.runner.RunPlan(f.plan(t, nil))
			require.Len(t, records, 1)
			require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
			snaps := requireBoundAtAuth(t, f, w)
			assert.GreaterOrEqual(t, len(snaps), 2, "改密與立即驗證各至少一次認證，驗證經同一個回呼物件")
		})
		t.Run("SSH金鑰", func(t *testing.T) {
			f := keyRotationFixture(t)
			w := watchAuth(f)
			records := f.runner.RunPlan(f.keyPlan(t))
			require.Len(t, records, 1)
			require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
			requireBoundAtAuth(t, f, w)
			require.Positive(t, f.server.publicKeyAuthOK.Load(), "公鑰驗證未實際發生")
		})
	})

	t.Run("首次信任與同位址沿用與既有自身列照常綁定", func(t *testing.T) {
		t.Run("首次信任", func(t *testing.T) {
			f := setupChangeSecretFixture(t, "root", "oldpass123")
			w := watchAuth(f)
			records := f.runner.RunPlan(f.plan(t, nil))
			require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
			snaps := requireBoundAtAuth(t, f, w)
			assert.EqualValues(t, 1, snaps[0].own.TrustGeneration)
			assert.Equal(t, ssh.FingerprintSHA256(f.server.hostKey.PublicKey()), snaps[0].own.Fingerprint)
		})
		t.Run("同位址沿用", func(t *testing.T) {
			f := setupChangeSecretFixture(t, "root", "oldpass123")
			host, port := serverAddr(t, f)
			seedHostKeyRow(t, f.db, rowOf(f.server.hostKey.PublicKey(), f.assetID+1000, host, port))
			w := watchAuth(f)
			records := f.runner.RunPlan(f.plan(t, nil))
			require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
			snaps := requireBoundAtAuth(t, f, w)
			assert.Equal(t, f.assetID, snaps[0].own.AssetID, "沿用後建立自身列")
			assert.EqualValues(t, 1, snaps[0].own.TrustGeneration)
		})
		t.Run("既有自身列沿用其世代", func(t *testing.T) {
			f := setupChangeSecretFixture(t, "root", "oldpass123")
			host, port := serverAddr(t, f)
			own := rowOf(f.server.hostKey.PublicKey(), f.assetID, host, port)
			own.TrustGeneration = 7
			seeded := seedHostKeyRow(t, f.db, own)
			w := watchAuth(f)
			records := f.runner.RunPlan(f.plan(t, nil))
			require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
			snaps := requireBoundAtAuth(t, f, w)
			assert.Equal(t, seeded.ID, snaps[0].cand.HostKeyRecordID)
			assert.EqualValues(t, 7, snaps[0].cand.HostKeyGeneration)
		})
	})
}

// runBindingFailure 綁定寫入失敗：認證嘗試 0、新原因碼、候選清除。
func runBindingFailure(t *testing.T) {
	type kind struct {
		name  string
		setup func(t *testing.T) (*csFixture, *model.ChangeSecretPlan)
	}
	kinds := []kind{
		{"密碼", func(t *testing.T) (*csFixture, *model.ChangeSecretPlan) {
			f := setupChangeSecretFixture(t, "root", "oldpass123")
			return f, f.plan(t, nil)
		}},
		{"SSH金鑰", func(t *testing.T) (*csFixture, *model.ChangeSecretPlan) {
			f := keyRotationFixture(t)
			return f, f.keyPlan(t)
		}},
	}
	type injection struct {
		name  string
		apply func(t *testing.T, f *csFixture) *int
	}
	injections := []injection{
		{"綁定交易內候選列被刪（受影響0列，刪列注入）", func(t *testing.T, f *csFixture) *int {
			fired := new(int)
			f.hostKeys.bindTxBarrier = func(tx *gorm.DB) {
				*fired++
				require.NoError(t, tx.Where("account_id = ?", f.accountID).Delete(&model.ChangeSecretCandidate{}).Error)
			}
			return fired
		}},
		{"更新語句出錯（UPDATE 故障注入）", func(t *testing.T, f *csFixture) *int {
			require.NoError(t, f.db.Exec(`CREATE TRIGGER fail_bind BEFORE UPDATE OF host_key_binding ON change_secret_candidates
				BEGIN SELECT RAISE(ABORT, 'injected bind failure'); END`).Error)
			return nil
		}},
	}
	for _, k := range kinds {
		for _, inj := range injections {
			t.Run(k.name+"/"+inj.name, func(t *testing.T) {
				f, plan := k.setup(t)
				origPw := f.storedPassword(t)
				origKeys := f.server.readAuthorizedKeys()
				fired := inj.apply(t, f)
				records := f.runner.RunPlan(plan)
				require.Len(t, records, 1)
				assert.Equal(t, model.ChangeSecretFailed, records[0].Status)
				assert.Equal(t, model.ChangeSecretReasonHostKeyCheckFailed, records[0].Error,
					"須為新增的綁定失敗原因碼，不是舊憑證登入失敗或主機金鑰不符")
				assert.EqualValues(t, 0, f.server.authAttempts.Load(), "綁定失敗時不得送出任何認證")
				assert.EqualValues(t, 0, f.server.chpasswdCalls.Load(), "不得動遠端")
				assert.EqualValues(t, 0, f.candidateCount(t), "沒有送出任何東西，候選依乾淨失敗規則清除")
				assert.Equal(t, origPw, f.storedPassword(t), "本地憑證不動")
				assert.Equal(t, origKeys, f.server.readAuthorizedKeys(), "遠端 authorized_keys 不動")
				if fired != nil {
					assert.Equal(t, 1, *fired, "注入器必須真的觸發（否則為假綠）")
				}
			})
		}
	}
}

// bindingDB 綁定單元案例所需的最小表。
func migrateBindingTables(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&model.AssetHostKey{}, &model.AssetHostKeyMismatch{},
		&model.ChangeSecretCandidate{}, &model.CredentialRotationMember{}))
}

var bindingSeq struct {
	sync.Mutex
	n uint
}

func nextBindingID() uint {
	bindingSeq.Lock()
	defer bindingSeq.Unlock()
	bindingSeq.n++
	return bindingSeq.n + 5000
}

// bindUnitCases 直接驅動回呼的案例（兩種方言共用）。
func bindUnitCases(t *testing.T, db *gorm.DB) {
	migrateBindingTables(t, db)
	dc := func(assetID uint) HostKeyDialContext {
		return HostKeyDialContext{AssetID: assetID, Path: HostKeyPathCredentialChange, UserID: 1, Username: "tester"}
	}
	// 每個案例各用一個位址，避免同位址的既有記錄讓後來的案例變成不符
	hostnameOf := func(id uint) string { return fmt.Sprintf("10.9.%d.%d:22", id/250, id%250) }
	newCandidate := func(binding string) *model.ChangeSecretCandidate {
		id := nextBindingID()
		c := &model.ChangeSecretCandidate{AssetID: id, AccountID: id, AccountUsername: "u", HostKeyBinding: binding}
		require.NoError(t, db.Create(c).Error)
		return c
	}
	reload := func(c *model.ChangeSecretCandidate) model.ChangeSecretCandidate {
		var got model.ChangeSecretCandidate
		require.NoError(t, db.First(&got, c.ID).Error)
		return got
	}

	t.Run("回呼為有狀態物件：首次綁定，其後只比對自己的快照且零寫入", func(t *testing.T) {
		svc := NewHostKeyService(db)
		c := newCandidate(model.HostKeyBindingPending)
		cb, _ := svc.CallbackForBinding(dc(c.AssetID), HostKeyBindTarget{CandidateID: c.ID})
		keyA, keyB := genHostKey(t), genHostKey(t)
		require.NoError(t, cb(hostnameOf(c.AssetID), nil, keyA))
		bound := reload(c)
		assert.Equal(t, model.HostKeyBindingBound, bound.HostKeyBinding)
		assert.Equal(t, ssh.FingerprintSHA256(keyA), bound.HostKeyFingerprint)

		var wc writeCounter
		wc.install(t, db)
		require.NoError(t, cb(hostnameOf(c.AssetID), nil, keyA), "同一物件、同一金鑰：放行")
		require.NoError(t, cb(hostnameOf(c.AssetID), nil, keyA))
		assert.EqualValues(t, 0, wc.count(), "綁定後的每次握手純讀，不再寫入")
		require.Error(t, cb(hostnameOf(c.AssetID), nil, keyB), "同一物件、另一把金鑰：拒絕")
		after := reload(c)
		assert.Equal(t, bound.HostKeyFingerprint, after.HostKeyFingerprint, "快照不被改寫")
		assert.Equal(t, bound.HostKeyRecordID, after.HostKeyRecordID)
	})

	t.Run("一般候選只在pending時綁定", func(t *testing.T) {
		for _, binding := range []string{model.HostKeyBindingBound, model.HostKeyBindingLegacy} {
			svc := NewHostKeyService(db)
			c := newCandidate(model.HostKeyBindingPending)
			if binding == model.HostKeyBindingBound {
				// bound 只能經正式綁定回呼建立
				seedCB, _ := NewHostKeyService(db).CallbackForBinding(dc(c.AssetID), HostKeyBindTarget{CandidateID: c.ID})
				require.NoError(t, seedCB(hostnameOf(c.AssetID), nil, genHostKey(t)))
				require.Equal(t, model.HostKeyBindingBound, reload(c).HostKeyBinding)
			} else {
				require.NoError(t, db.Model(c).UpdateColumn("host_key_binding", binding).Error) // legacy 為遷移前資料，無回呼可建
			}
			before := reload(c)
			cb, _ := svc.CallbackForBinding(dc(c.AssetID), HostKeyBindTarget{CandidateID: c.ID})
			assert.ErrorIs(t, cb(hostnameOf(c.AssetID), nil, genHostKey(t)), ErrHostKeyCheckFailed, "binding=%s 不得綁定", binding)
			assert.Equal(t, before.HostKeyBinding, reload(c).HostKeyBinding)
			assert.Equal(t, before.HostKeyFingerprint, reload(c).HostKeyFingerprint, "快照不被覆寫")
		}
		svc := NewHostKeyService(db)
		c := newCandidate(model.HostKeyBindingPending)
		cb, _ := svc.CallbackForBinding(dc(c.AssetID), HostKeyBindTarget{CandidateID: c.ID})
		require.NoError(t, cb(hostnameOf(c.AssetID), nil, genHostKey(t)))
		assert.Equal(t, model.HostKeyBindingBound, reload(c).HostKeyBinding)
	})

	t.Run("成員交易層條件只認三項可重驗事實", func(t *testing.T) {
		sent := db.NowFunc()
		cases := []struct {
			name    string
			state   string
			binding string
			marker  bool
			want    bool
		}{
			{"changing+pending", model.CredentialMemberChanging, model.HostKeyBindingPending, false, true},
			{"changing+pending 已有標記", model.CredentialMemberChanging, model.HostKeyBindingPending, true, true},
			{"changing+bound 無標記重綁", model.CredentialMemberChanging, model.HostKeyBindingBound, false, true},
			{"changing+legacy 無標記", model.CredentialMemberChanging, model.HostKeyBindingLegacy, false, true},
			{"changing+bound 有標記", model.CredentialMemberChanging, model.HostKeyBindingBound, true, false},
			{"changing+legacy 有標記", model.CredentialMemberChanging, model.HostKeyBindingLegacy, true, false},
			{"queued+pending", model.CredentialMemberQueued, model.HostKeyBindingPending, false, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				svc := NewHostKeyService(db)
				id := nextBindingID()
				m := &model.CredentialRotationMember{RotationID: 1, AccountID: id, CredentialID: 1, AssetID: id,
					State: model.CredentialMemberChanging, HostKeyBinding: model.HostKeyBindingPending}
				require.NoError(t, db.Create(m).Error)
				targetKey := genHostKey(t)
				switch tc.binding {
				case model.HostKeyBindingBound: // bound 只能經正式綁定回呼建立
					seedCB, _ := NewHostKeyService(db).CallbackForBinding(dc(id), HostKeyBindTarget{MemberID: m.ID})
					require.NoError(t, seedCB(hostnameOf(id), nil, targetKey))
				case model.HostKeyBindingLegacy: // 遷移前資料，無回呼可建
					require.NoError(t, db.Model(m).UpdateColumn("host_key_binding", tc.binding).Error)
				}
				extra := map[string]any{"state": tc.state}
				if tc.marker {
					extra["secret_sent_at"] = sent
				}
				require.NoError(t, db.Model(m).Updates(extra).Error)
				var seeded model.CredentialRotationMember
				require.NoError(t, db.First(&seeded, m.ID).Error)
				cb, _ := svc.CallbackForBinding(dc(id), HostKeyBindTarget{MemberID: m.ID})
				err := cb(hostnameOf(id), nil, targetKey)
				var got model.CredentialRotationMember
				require.NoError(t, db.First(&got, m.ID).Error)
				if tc.want {
					require.NoError(t, err)
					assert.Equal(t, model.HostKeyBindingBound, got.HostKeyBinding)
					assert.Equal(t, model.HostKeyTransportSSH, got.HostKeyTransport)
					assert.NotEmpty(t, got.HostKeyFingerprint)
				} else {
					assert.ErrorIs(t, err, ErrHostKeyCheckFailed)
					assert.Equal(t, tc.binding, got.HostKeyBinding, "不具資格時列不變")
					assert.Equal(t, seeded.HostKeyFingerprint, got.HostKeyFingerprint, "快照不被覆寫")
				}
			})
		}

		t.Run("讀列之後綁定之前標記被寫入", func(t *testing.T) {
			svc := NewHostKeyService(db)
			id := nextBindingID()
			m := &model.CredentialRotationMember{RotationID: 1, AccountID: id, CredentialID: 1, AssetID: id,
				State: model.CredentialMemberChanging, HostKeyBinding: model.HostKeyBindingPending}
			require.NoError(t, db.Create(m).Error)
			seedCB, _ := NewHostKeyService(db).CallbackForBinding(dc(id), HostKeyBindTarget{MemberID: m.ID})
			seedKey := genHostKey(t)
			require.NoError(t, seedCB(hostnameOf(id), nil, seedKey)) // bound 只能經正式綁定回呼建立
			fired := 0
			svc.bindTxBarrier = func(tx *gorm.DB) {
				fired++
				require.NoError(t, tx.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).
					UpdateColumn("secret_sent_at", sent).Error)
			}
			cb, _ := svc.CallbackForBinding(dc(id), HostKeyBindTarget{MemberID: m.ID})
			assert.ErrorIs(t, cb(hostnameOf(id), nil, seedKey), ErrHostKeyCheckFailed)
			assert.Equal(t, 1, fired, "注入器必須真的觸發")
			var got model.CredentialRotationMember
			require.NoError(t, db.First(&got, m.ID).Error)
			assert.Equal(t, ssh.FingerprintSHA256(seedKey), got.HostKeyFingerprint, "標記被寫入後不得重綁")
		})
	})
}

func runBindingUnits(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { bindUnitCases(t, openSentMarkSQLite(t)) })
	t.Run("postgres", func(t *testing.T) {
		bindUnitCases(t, openSentMarkPG(t))
		if !t.Failed() {
			fmt.Println("EVIDENCE dialect=postgres")
			t.Log("EVIDENCE dialect=postgres")
		}
	})
}
