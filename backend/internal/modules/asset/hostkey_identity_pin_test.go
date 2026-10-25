package asset

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// writeCounter 計數經由此 db 的所有資料表寫入語句（create／update／delete），用來證明純讀路徑零寫入。
type writeCounter struct{ n atomic.Int64 }

func (w *writeCounter) install(t *testing.T, db *gorm.DB) {
	t.Helper()
	inc := func(*gorm.DB) { w.n.Add(1) }
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(db.Callback().Create().Before("gorm:create").Register("test:wc_create", inc))
	must(db.Callback().Update().Before("gorm:update").Register("test:wc_update", inc))
	must(db.Callback().Delete().Before("gorm:delete").Register("test:wc_delete", inc))
	must(db.Callback().Raw().Before("gorm:raw").Register("test:wc_raw", inc))
}

func (w *writeCounter) count() int64 { return w.n.Load() }

func seedHostKeyRow(t *testing.T, db *gorm.DB, row model.AssetHostKey) model.AssetHostKey {
	t.Helper()
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	// 重置待記錄在建立時會被 default 蓋掉零值，明確寫回
	if row.ResetPending {
		if err := db.Model(&row).UpdateColumn("reset_pending", true).Error; err != nil {
			t.Fatal(err)
		}
	}
	return row
}

func rowOf(key ssh.PublicKey, assetID uint, host string, port int) model.AssetHostKey {
	return model.AssetHostKey{
		AssetID: assetID, Algorithm: key.Type(), Fingerprint: ssh.FingerprintSHA256(key),
		PublicKey: "x", Host: host, Port: port, TrustGeneration: 1,
	}
}

func snapshotRows(t *testing.T, db *gorm.DB) []model.AssetHostKey {
	t.Helper()
	var rows []model.AssetHostKey
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestCredentialRecoveryHostIdentityPin 改密與憑證輪替的主機身分守衛；各子案例以 task 編號為前綴逐單追加。
func TestCredentialRecoveryHostIdentityPin(t *testing.T) {
	const addr = "10.0.0.5:22"
	const host, port = "10.0.0.5", 22

	// 3.2 (1)：classifyHostKey 六種輸入，各回對應 decision，資料庫零寫入
	t.Run("3.2/classifyHostKey", func(t *testing.T) {
		keyA, keyB := genHostKey(t), genHostKey(t)
		cases := []struct {
			name    string
			seed    func(t *testing.T, db *gorm.DB)
			key     ssh.PublicKey
			outcome HostKeyOutcome
			source  HostKeyRecordSource
			wantRec bool // 是否回傳判定所依據的記錄
			reset   bool
		}{
			{"首次信任", func(*testing.T, *gorm.DB) {}, keyA, HostKeyRecorded, "", false, false},
			{"沿用同位址記錄", func(t *testing.T, db *gorm.DB) { seedHostKeyRow(t, db, rowOf(keyA, 99, host, port)) },
				keyA, HostKeyAdopted, HostKeyRecordAddress, true, false},
			{"自身列相符", func(t *testing.T, db *gorm.DB) { seedHostKeyRow(t, db, rowOf(keyA, 1, host, port)) },
				keyA, HostKeyMatched, HostKeyRecordOwn, true, false},
			{"自身列不符", func(t *testing.T, db *gorm.DB) { seedHostKeyRow(t, db, rowOf(keyA, 1, host, port)) },
				keyB, HostKeyMismatch, HostKeyRecordOwn, true, false},
			{"自身列缺而同位址記錄不符", func(t *testing.T, db *gorm.DB) { seedHostKeyRow(t, db, rowOf(keyA, 99, host, port)) },
				keyB, HostKeyMismatch, HostKeyRecordAddress, true, false},
			{"reset_pending", func(t *testing.T, db *gorm.DB) {
				r := rowOf(keyA, 1, host, port)
				r.ResetPending = true
				seedHostKeyRow(t, db, r)
			}, keyB, HostKeyRecorded, "", true, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				db := setupHostKeyDB(t)
				svc, _ := newHostKeyTestService(db)
				tc.seed(t, db)
				before := snapshotRows(t, db)
				wc := &writeCounter{}
				wc.install(t, db)

				dec, rec, err := svc.classifyHostKey(1, host, port, tc.key)
				if err != nil {
					t.Fatalf("classify: %v", err)
				}
				if dec.Outcome != tc.outcome || dec.Source != tc.source {
					t.Fatalf("decision = %s/%s，期望 %s/%s", dec.Outcome, dec.Source, tc.outcome, tc.source)
				}
				if dec.ObservedFingerprint != ssh.FingerprintSHA256(tc.key) {
					t.Fatalf("觀察指紋不符: %s", dec.ObservedFingerprint)
				}
				if (rec != nil) != tc.wantRec {
					t.Fatalf("回傳記錄 = %v，期望存在=%v", rec, tc.wantRec)
				}
				if rec != nil && rec.ResetPending != tc.reset {
					t.Fatalf("記錄 ResetPending = %v，期望 %v", rec.ResetPending, tc.reset)
				}
				if n := wc.count(); n != 0 {
					t.Fatalf("純讀分類寫入了 %d 筆語句", n)
				}
				after := snapshotRows(t, db)
				if len(before) != len(after) {
					t.Fatalf("列數 %d -> %d", len(before), len(after))
				}
				for i := range before {
					if before[i] != after[i] {
						t.Fatalf("列 %d 被改動: %+v -> %+v", i, before[i], after[i])
					}
				}
			})
		}
	})

	// 3.2 (3)：CallbackForPinned
	t.Run("3.2/CallbackForPinned", func(t *testing.T) {
		keyA, keyB, keyC := genHostKey(t), genHostKey(t), genHostKey(t)
		pinA := HostKeyPin{Algorithm: keyA.Type(), Fingerprint: ssh.FingerprintSHA256(keyA)}
		dc := HostKeyDialContext{AssetID: 1, Path: HostKeyPathCredentialChange, UserID: hostKeyTestUserID,
			Username: hostKeyTestUsername, AccountID: 3, ClientIP: "203.0.113.9", ConnectionRef: "credential_change:7"}

		t.Run("等於pin放行且零寫入", func(t *testing.T) {
			db := setupHostKeyDB(t)
			svc, _ := newHostKeyTestService(db)
			// 記錄已被重置成 B：只要實際金鑰等於 pin 就放行，不查庫、不寫庫
			seedHostKeyRow(t, db, rowOf(keyB, 1, host, port))
			wc := &writeCounter{}
			wc.install(t, db)
			if err := svc.CallbackForPinned(dc, pinA)(addr, nil, keyA); err != nil {
				t.Fatalf("等於 pin 應放行: %v", err)
			}
			if n := wc.count(); n != 0 {
				t.Fatalf("寫入 %d 筆", n)
			}
		})

		t.Run("等於當下記錄但非pin回ErrHostIdentityChanged且零寫入", func(t *testing.T) {
			db := setupHostKeyDB(t)
			svc, alerts := newHostKeyTestService(db)
			seedHostKeyRow(t, db, rowOf(keyB, 1, host, port)) // 採用 B 後的記錄
			before := snapshotRows(t, db)
			wc := &writeCounter{}
			wc.install(t, db)
			err := svc.CallbackForPinned(dc, pinA)(addr, nil, keyB)
			if !errors.Is(err, ErrHostIdentityChanged) {
				t.Fatalf("err = %v，期望 ErrHostIdentityChanged", err)
			}
			if n := wc.count(); n != 0 {
				t.Fatalf("寫入 %d 筆", n)
			}
			if countObservations(t, db, 1) != 0 || countAudit(t, db, model.ActionHostKeyMismatch) != 0 || len(alerts.events) != 0 {
				t.Fatal("不得留下不符觀察、審計或告警")
			}
			after := snapshotRows(t, db)
			if len(after) != 1 || after[0] != before[0] {
				t.Fatalf("記錄被改動: %+v -> %+v", before, after)
			}
		})

		t.Run("自身列缺或reset_pending一律拒絕且不建列不重錄", func(t *testing.T) {
			for _, name := range []string{"自身列缺", "reset_pending"} {
				db := setupHostKeyDB(t)
				svc, _ := newHostKeyTestService(db)
				if name == "reset_pending" {
					r := rowOf(keyA, 1, host, port)
					r.ResetPending = true
					seedHostKeyRow(t, db, r)
				}
				before := snapshotRows(t, db)
				wc := &writeCounter{}
				wc.install(t, db)
				if err := svc.CallbackForPinned(dc, pinA)(addr, nil, keyB); !errors.Is(err, ErrHostIdentityChanged) {
					t.Fatalf("%s: err = %v", name, err)
				}
				if wc.count() != 0 {
					t.Fatalf("%s: 有寫入", name)
				}
				after := snapshotRows(t, db)
				if len(after) != len(before) || (len(before) == 1 && after[0] != before[0]) {
					t.Fatalf("%s: 記錄被改動", name)
				}
			}
		})

		t.Run("與記錄也不符走既有不符留痕並拒絕", func(t *testing.T) {
			db := setupHostKeyDB(t)
			svc, alerts := newHostKeyTestService(db)
			seedHostKeyRow(t, db, rowOf(keyB, 1, host, port))
			before := snapshotRows(t, db)
			err := svc.CallbackForPinned(dc, pinA)(addr, nil, keyC)
			if !errors.Is(err, ErrHostKeyChanged) {
				t.Fatalf("err = %v，期望 ErrHostKeyChanged", err)
			}
			if countObservations(t, db, 1) != 1 {
				t.Fatal("應留下一筆不符觀察")
			}
			if countAudit(t, db, model.ActionHostKeyMismatch) != 1 || len(alerts.events) != 1 {
				t.Fatalf("應有一筆不符審計與一則告警，實得 %d／%d", countAudit(t, db, model.ActionHostKeyMismatch), len(alerts.events))
			}
			after := snapshotRows(t, db)
			if len(after) != 1 || after[0] != before[0] {
				t.Fatal("不符不得改寫記錄")
			}
		})
	})

	// 3.2 補強（審查補件）：CallbackForPinned 的邊角
	t.Run("3.2/CallbackForPinned邊角", func(t *testing.T) {
		keyA, keyB, keyC := genHostKey(t), genHostKey(t), genHostKey(t)
		dc := HostKeyDialContext{AssetID: 1, Path: HostKeyPathCredentialChange, UserID: hostKeyTestUserID,
			Username: hostKeyTestUsername, AccountID: 3, ClientIP: "203.0.113.9", ConnectionRef: "credential_change:7"}

		t.Run("指紋相同只改pin演算法須拒絕", func(t *testing.T) {
			db := setupHostKeyDB(t)
			svc, _ := newHostKeyTestService(db)
			seedHostKeyRow(t, db, rowOf(keyA, 1, host, port))
			wc := &writeCounter{}
			wc.install(t, db)
			pin := HostKeyPin{Algorithm: "ssh-rsa", Fingerprint: ssh.FingerprintSHA256(keyA)}
			if err := svc.CallbackForPinned(dc, pin)(addr, nil, keyA); !errors.Is(err, ErrHostIdentityChanged) {
				t.Fatalf("演算法不同的 pin 應拒絕: %v", err)
			}
			if wc.count() != 0 {
				t.Fatal("有寫入")
			}
		})

		t.Run("查庫失敗與留痕失敗回ErrHostKeyCheckFailed", func(t *testing.T) {
			pinA := HostKeyPin{Algorithm: keyA.Type(), Fingerprint: ssh.FingerprintSHA256(keyA)}
			// 查庫失敗：資料表不存在
			db := setupHostKeyDB(t)
			svc, _ := newHostKeyTestService(db)
			if err := db.Migrator().DropTable(&model.AssetHostKey{}); err != nil {
				t.Fatal(err)
			}
			if err := svc.CallbackForPinned(dc, pinA)(addr, nil, keyB); !errors.Is(err, ErrHostKeyCheckFailed) {
				t.Fatalf("查庫失敗: err = %v", err)
			}
			// 留痕失敗：真不符但審計落地面回錯
			db2 := setupHostKeyDB(t)
			svc2, _ := newHostKeyTestService(db2)
			svc2.SetAuditTxSink(failingTxSink{err: errors.New("audit down")})
			seedHostKeyRow(t, db2, rowOf(keyB, 1, host, port))
			if err := svc2.CallbackForPinned(dc, pinA)(addr, nil, keyC); !errors.Is(err, ErrHostKeyCheckFailed) {
				t.Fatalf("留痕失敗: err = %v", err)
			}
		})

		t.Run("同位址沿用與同位址不符皆拒絕且零寫入", func(t *testing.T) {
			pinA := HostKeyPin{Algorithm: keyA.Type(), Fingerprint: ssh.FingerprintSHA256(keyA)}
			for name, seedKey := range map[string]ssh.PublicKey{"同位址沿用": keyB, "同位址不符": keyC} {
				db := setupHostKeyDB(t)
				svc, alerts := newHostKeyTestService(db)
				seedHostKeyRow(t, db, rowOf(seedKey, 99, host, port)) // 別的資產在同位址的記錄；本資產無自身列
				before := snapshotRows(t, db)
				wc := &writeCounter{}
				wc.install(t, db)
				if err := svc.CallbackForPinned(dc, pinA)(addr, nil, keyB); !errors.Is(err, ErrHostIdentityChanged) {
					t.Fatalf("%s: err = %v", name, err)
				}
				if wc.count() != 0 || countObservations(t, db, 1) != 0 || len(alerts.events) != 0 {
					t.Fatalf("%s: 有寫入、觀察或告警", name)
				}
				after := snapshotRows(t, db)
				if len(after) != len(before) {
					t.Fatalf("%s: 不得為本資產建列", name)
				}
			}
		})
	})

	// 3.2 (2)：hostIdentityVerdict 對撥號前查庫表的各列回對應 detail，且零寫入
	t.Run("3.2/hostIdentityVerdict", func(t *testing.T) {
		keyA, keyB := genHostKey(t), genHostKey(t)
		sshAsset := &model.Asset{ID: 1, Protocol: model.ProtocolSSH, Host: host, Port: port}
		winAsset := &model.Asset{ID: 1, Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM}
		pinA := HostKeyPin{Algorithm: keyA.Type(), Fingerprint: ssh.FingerprintSHA256(keyA)}
		cand := func(binding, transport string, rec uint, gen int64, pin HostKeyPin) *model.ChangeSecretCandidate {
			return &model.ChangeSecretCandidate{AssetID: 1, HostKeyBinding: binding, HostKeyTransport: transport,
				HostKeyRecordID: rec, HostKeyGeneration: gen, HostKeyAlgorithm: pin.Algorithm, HostKeyFingerprint: pin.Fingerprint}
		}
		sentAt := time.Now()
		type tc struct {
			name  string
			asset *model.Asset
			job   func(rowID uint) hostIdentityJob
			seed  func(t *testing.T, db *gorm.DB) uint
			want  string
		}
		seedA := func(t *testing.T, db *gorm.DB) uint { return seedHostKeyRow(t, db, rowOf(keyA, 1, host, port)).ID }
		none := func(*testing.T, *gorm.DB) uint { return 0 }
		cases := []tc{
			{"1 legacy已送出", sshAsset, func(uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingLegacy, "", 0, 0, HostKeyPin{}))
			}, seedA, hostIdentityUnboundLegacy},
			{"1b legacy成員有標記", sshAsset, func(uint) hostIdentityJob {
				return hostIdentityJobOfMember(&model.CredentialRotationMember{AssetID: 1, HostKeyBinding: model.HostKeyBindingLegacy, SecretSentAt: &sentAt}, false)
			}, seedA, hostIdentityUnboundLegacy},
			{"1c legacy整組成員無標記但候選列存在", sshAsset, func(uint) hostIdentityJob {
				return hostIdentityJobOfMember(&model.CredentialRotationMember{AssetID: 1, HostKeyBinding: model.HostKeyBindingLegacy}, true)
			}, seedA, hostIdentityUnboundLegacy},
			{"1d legacy成員無標記無候選（拆分或無副本）放行", sshAsset, func(uint) hostIdentityJob {
				return hostIdentityJobOfMember(&model.CredentialRotationMember{AssetID: 1, HostKeyBinding: model.HostKeyBindingLegacy}, false)
			}, none, ""},
			{"2 pending", sshAsset, func(uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingPending, "", 0, 0, HostKeyPin{}))
			}, none, ""},
			{"3 成員bound且標記NULL", sshAsset, func(uint) hostIdentityJob {
				return hostIdentityJobOfMember(&model.CredentialRotationMember{AssetID: 1, HostKeyBinding: model.HostKeyBindingBound,
					HostKeyTransport: model.HostKeyTransportSSH, HostKeyRecordID: 77, HostKeyGeneration: 9}, false)
			}, none, ""},
			{"4 ssh綁定但通道已是WinRM", winAsset, func(id uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportSSH, id, 1, pinA))
			}, seedA, hostIdentityTransportChanged},
			{"4b winrm綁定但通道已是SSH", sshAsset, func(id uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportWinRM, 0, 0, HostKeyPin{}))
			}, seedA, hostIdentityTransportChanged},
			{"5 winrm綁定且仍為WinRM", winAsset, func(uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportWinRM, 0, 0, HostKeyPin{}))
			}, none, ""},
			{"6 自身列不存在", sshAsset, func(uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportSSH, 1, 1, pinA))
			}, none, hostIdentityRecordMissing},
			{"7 reset_pending", sshAsset, func(id uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportSSH, id, 1, pinA))
			}, func(t *testing.T, db *gorm.DB) uint {
				r := rowOf(keyA, 1, host, port)
				r.ResetPending = true
				return seedHostKeyRow(t, db, r).ID
			}, hostIdentityResetPending},
			{"8 世代不同", sshAsset, func(id uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportSSH, id, 1, pinA))
			}, func(t *testing.T, db *gorm.DB) uint {
				r := rowOf(keyA, 1, host, port)
				r.TrustGeneration = 2
				return seedHostKeyRow(t, db, r).ID
			}, hostIdentityGenerationChanged},
			{"8b 列id不同（刪列重建）", sshAsset, func(id uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportSSH, id+5, 1, pinA))
			}, seedA, hostIdentityGenerationChanged},
			{"8c 指紋也變但世代不同時世代優先", sshAsset, func(id uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportSSH, id, 1, pinA))
			}, func(t *testing.T, db *gorm.DB) uint {
				r := rowOf(keyB, 1, host, port)
				r.TrustGeneration = 2
				return seedHostKeyRow(t, db, r).ID
			}, hostIdentityGenerationChanged},
			{"9 世代相同指紋不同", sshAsset, func(id uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportSSH, id, 1, pinA))
			}, func(t *testing.T, db *gorm.DB) uint { return seedHostKeyRow(t, db, rowOf(keyB, 1, host, port)).ID }, hostIdentityFingerprintChanged},
			{"9b 世代相同演算法不同", sshAsset, func(id uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportSSH, id, 1,
					HostKeyPin{Algorithm: "ssh-rsa", Fingerprint: pinA.Fingerprint}))
			}, seedA, hostIdentityFingerprintChanged},
			{"10 全部相符", sshAsset, func(id uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportSSH, id, 1, pinA))
			}, seedA, ""},
			{"11 無法辨識的綁定狀態不放行", sshAsset, func(uint) hostIdentityJob {
				return hostIdentityJobOfCandidate(cand("weird", "", 0, 0, HostKeyPin{}))
			}, seedA, hostIdentityUnboundLegacy},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				db := setupHostKeyDB(t)
				id := c.seed(t, db)
				before := snapshotRows(t, db)
				wc := &writeCounter{}
				wc.install(t, db)
				if got := hostIdentityVerdict(db, c.job(id), c.asset); got != c.want {
					t.Fatalf("detail = %q，期望 %q", got, c.want)
				}
				if wc.count() != 0 {
					t.Fatalf("撥號前查庫寫入了 %d 筆", wc.count())
				}
				after := snapshotRows(t, db)
				if len(after) != len(before) {
					t.Fatal("列數改變")
				}
			})
		}
		t.Run("讀取自身列失敗fail-closed", func(t *testing.T) {
			db := setupHostKeyDB(t)
			if err := db.Migrator().DropTable(&model.AssetHostKey{}); err != nil {
				t.Fatal(err)
			}
			job := hostIdentityJobOfCandidate(cand(model.HostKeyBindingBound, model.HostKeyTransportSSH, 1, 1, pinA))
			if got := hostIdentityVerdict(db, job, sshAsset); got != hostIdentityLookupFailed {
				t.Fatalf("detail = %q", got)
			}
		})
		t.Run("停止細節對應原因碼與錯誤辨識", func(t *testing.T) {
			if hostIdentityRecoveryReason("") != "" ||
				hostIdentityRecoveryReason(hostIdentityRecordMissing) != model.ChangeSecretReasonHostIdentityChanged ||
				hostIdentityRecoveryReason(hostIdentityLookupFailed) != model.ChangeSecretReasonAuthzUnavailable {
				t.Fatal("recovery 原因碼對應錯誤")
			}
			wrapped := fmt.Errorf("dial: %w", ErrHostIdentityChanged)
			if verifyFailureReason(wrapped, "FALLBACK") != model.ChangeSecretReasonHostIdentityChanged {
				t.Fatal("verifyFailureReason 未辨識 ErrHostIdentityChanged")
			}
			if verifyFailureReason(ErrHostKeyChanged, "FALLBACK") != model.ChangeSecretReasonHostKeyMismatch ||
				verifyFailureReason(ErrHostKeyCheckFailed, "FALLBACK") != "FALLBACK" {
				t.Fatal("verifyFailureReason 既有分支改變")
			}
			if oldCredentialLoginReason(fmt.Errorf("x: %w", ErrHostKeyCheckFailed)) != model.ChangeSecretReasonHostKeyCheckFailed ||
				oldCredentialLoginReason(ErrHostKeyChanged) != model.ChangeSecretReasonHostKeyMismatch ||
				oldCredentialLoginReason(errors.New("other")) != model.ChangeSecretReasonOldCredentialLoginFailed {
				t.Fatal("oldCredentialLoginReason 分支錯誤")
			}
		})
	})

	// 3.2 (4)：assertHostIdentityUnchangedTx
	t.Run("3.2/assertHostIdentityUnchangedTx", func(t *testing.T) {
		keyA, keyB := genHostKey(t), genHostKey(t)
		pinA := HostKeyPin{Algorithm: keyA.Type(), Fingerprint: ssh.FingerprintSHA256(keyA)}
		boundJob := func(id uint) hostIdentityJob {
			return hostIdentityJobOfCandidate(&model.ChangeSecretCandidate{AssetID: 1, HostKeyBinding: model.HostKeyBindingBound,
				HostKeyTransport: model.HostKeyTransportSSH, HostKeyRecordID: id, HostKeyGeneration: 1,
				HostKeyAlgorithm: pinA.Algorithm, HostKeyFingerprint: pinA.Fingerprint})
		}
		run := func(db *gorm.DB, job hostIdentityJob, exp *hostIdentityExpected) error {
			return db.Transaction(func(tx *gorm.DB) error { return assertHostIdentityUnchangedTx(tx, job, exp) })
		}
		mut := func(f func(r *model.AssetHostKey)) func(t *testing.T, db *gorm.DB) uint {
			return func(t *testing.T, db *gorm.DB) uint {
				r := rowOf(keyA, 1, host, port)
				f(&r)
				id := seedHostKeyRow(t, db, r).ID
				return id
			}
		}
		cases := []struct {
			name string
			seed func(t *testing.T, db *gorm.DB) uint
			want error
		}{
			{"相等放行", mut(func(*model.AssetHostKey) {}), nil},
			{"世代不等", mut(func(r *model.AssetHostKey) { r.TrustGeneration = 2 }), ErrHostIdentityChanged},
			{"列id不等", func(t *testing.T, db *gorm.DB) uint {
				seedHostKeyRow(t, db, rowOf(keyB, 2, "10.9.9.9", 22)) // 佔掉 id 1，使本資產的列 id 為 2
				seedHostKeyRow(t, db, rowOf(keyA, 1, host, port))
				return 1 // 預期的是刪列重建之前的 id
			}, ErrHostIdentityChanged},
			{"指紋不等", mut(func(r *model.AssetHostKey) { r.Fingerprint = ssh.FingerprintSHA256(keyB) }), ErrHostIdentityChanged},
			{"演算法不等", mut(func(r *model.AssetHostKey) { r.Algorithm = "ssh-rsa" }), ErrHostIdentityChanged},
			{"reset_pending", mut(func(r *model.AssetHostKey) { r.ResetPending = true }), ErrHostIdentityChanged},
			{"自身列不存在", func(*testing.T, *gorm.DB) uint { return 1 }, ErrHostIdentityChanged},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				db := setupHostKeyDB(t)
				id := c.seed(t, db)
				err := run(db, boundJob(id), nil)
				if c.want == nil && err != nil {
					t.Fatalf("應放行: %v", err)
				}
				if c.want != nil && !errors.Is(err, c.want) {
					t.Fatalf("err = %v，期望 %v", err, c.want)
				}
			})
		}

		t.Run("transport為winrm跳過", func(t *testing.T) {
			db := setupHostKeyDB(t)
			job := hostIdentityJobOfCandidate(&model.ChangeSecretCandidate{AssetID: 1, HostKeyBinding: model.HostKeyBindingBound,
				HostKeyTransport: model.HostKeyTransportWinRM})
			if err := run(db, job, nil); err != nil {
				t.Fatalf("winrm 應跳過: %v", err)
			}
		})

		t.Run("非bound的SSH工作列", func(t *testing.T) {
			db := setupHostKeyDB(t)
			id := seedHostKeyRow(t, db, rowOf(keyA, 1, host, port)).ID
			for _, binding := range []string{model.HostKeyBindingPending, model.HostKeyBindingLegacy} {
				job := hostIdentityJobOfCandidate(&model.ChangeSecretCandidate{AssetID: 1, HostKeyBinding: binding})
				err := run(db, job, nil)
				if !errors.Is(err, ErrHostKeyCheckFailed) || errors.Is(err, ErrHostIdentityChanged) {
					t.Fatalf("%s 無承接紀錄應 fail-closed 回 ErrHostKeyCheckFailed: %v", binding, err)
				}
				// 有承接紀錄作為 expected 時以它為準
				if err := run(db, job, &hostIdentityExpected{RecordID: id, Generation: 1, Pin: pinA}); err != nil {
					t.Fatalf("%s 有承接預期且相符應放行: %v", binding, err)
				}
				bad := &hostIdentityExpected{RecordID: id, Generation: 2, Pin: pinA}
				if err := run(db, job, bad); !errors.Is(err, ErrHostIdentityChanged) {
					t.Fatalf("%s 承接預期世代不等應回 ErrHostIdentityChanged: %v", binding, err)
				}
			}
		})

		t.Run("讀取失敗回ErrHostKeyCheckFailed", func(t *testing.T) {
			db := setupHostKeyDB(t)
			if err := db.Migrator().DropTable(&model.AssetHostKey{}); err != nil {
				t.Fatal(err)
			}
			if err := run(db, boundJob(1), nil); !errors.Is(err, ErrHostKeyCheckFailed) {
				t.Fatalf("err = %v", err)
			}
		})
	})

	// 3.1 派送標記（單調）與派送證據分類
	t.Run("3.1/派送標記/transitionMember", func(t *testing.T) {
		t.Run("sqlite", func(t *testing.T) { runSentMarkCore(t, openSentMarkSQLite(t)) })
		t.Run("postgres", func(t *testing.T) {
			runSentMarkCore(t, openSentMarkPG(t))
			if !t.Failed() {
				fmt.Println("EVIDENCE dialect=postgres")
				t.Log("EVIDENCE dialect=postgres")
			}
		})
	})
	t.Run("3.1/派送標記/經正式路徑", runSentMarkThroughService)
	t.Run("3.1/派送證據分類", runDeliveryClassification)

	// 3.1 綁定回呼（一般密碼與 SSH 金鑰的首次派送）
	t.Run("3.1/綁定/首次派送", runBindingFirstDelivery)
	t.Run("3.1/綁定/失敗反例", runBindingFailure)
	t.Run("3.1/綁定/回呼單元", runBindingUnits)

	// 3.1 輪替成員下達（整組、拆分、Windows SSH、WinRM）與派送證據分流
	t.Run("3.1/成員/首次派送在認證前已綁定", runMemberFirstDelivery)
	t.Run("3.1/成員/綁定失敗反例", runMemberBindingFailure)
	t.Run("3.1/成員/WinRM首次派送", runWinRMFirstDelivery)
	t.Run("3.1/成員/派送證據分流", runMemberDeliveryRouting)

	// 3.3 提交交易內的主機身分比對與原因碼辨識
	t.Run("3.3/提交交易身分不符", runPromoteIdentityChanged)
	t.Run("3.3/Pinned回呼拒絕舊憑證撥號", runPinnedRotateIdentityChanged)
	t.Run("3.3/成員提交交易身分不符", runMemberCommitIdentityChanged)
	t.Run("3.3/候選轉正後再重試的冪等", runCandidateRetryIdempotent)
	t.Run("3.3/下達標記失敗不中止", runDeliveredMarkFailureDoesNotAbort)
	t.Run("3.3/轉正加密在開交易之前", runPromoteEncryptsBeforeTx)
	t.Run("3.3/比較後刪候選前被並行清除則整筆回滾", runPromoteCandidateClearedMidTx)

	// 3.4 立即 Verify 與下達標記矩陣
	t.Run("3.4/立即Verify/密碼", runImmediateVerifyPassword)
	t.Run("3.4/立即Verify/SSH金鑰", runImmediateVerifyKey)
	t.Run("3.4/立即Verify/WindowsSSH多次撥號", runImmediateVerifyWindowsSSH)
	t.Run("3.4/下達標記失敗矩陣", runMarkAppliedMatrix)
	t.Run("3.4/下達標記失敗矩陣/成員SSH金鑰", runMemberKeyMarkApplied)
	t.Run("3.4/retry/三授權狀態x六異動", runRetryAuthMatrix)
	t.Run("3.4/retry/目標指紋與身分不混且失權放行有限驗證", runRetryTargetFingerprintNotMixed)
	t.Run("3.4/retry/握手比對", runRetryHandshake)
	t.Run("3.4/retry/傳輸切換與WinRM照舊", runRetryTransport)
	t.Run("3.4/retry/pending候選首次派送綁定", runRetryPendingBinding)
	t.Run("3.4/成員/立即Verify", runMemberImmediateVerify)
	t.Run("3.4/成員/補跑驗證兩分支", runMemberVerifyBranches)
	t.Run("3.4/成員/legacy重排", runMemberLegacyRequeue)
	t.Run("3.4/成員/升級前未標記成員正面", runMemberLegacyPositive)
	t.Run("3.4/成員/派送歷史", runMemberDeliveryHistory)
	t.Run("3.4/成員/一員停止他員繼續", runMemberOneStopsOthersContinue)
	t.Run("3.4/新工作照常", runNewWorkAfterAdoption)
	t.Run("3.4/成員/補跑預檢與撥號同一資產", runMemberVerifySnapshotSwap)
	t.Run("3.4/成員/下達握手拒絕留痕", runDeliveryHandshakeStop)
	t.Run("3.4/成員/首次派送身分拒絕分流", runFirstDeliveryIdentityRejection)
	t.Run("3.4/成員/預檢查詢不可用", runPrecheckLookupFailed)
	t.Run("3.4/retry/pending綁定回呼放行計數", runPendingBindingPassCount)
	t.Run("3.4/成員/基底回呼fail-closed", runMemberBaseCallbackFailClosed)

	// 3.5 身分停止的審計、去重與通知（writer 直接呼叫與接入各停止分支的端到端）
	t.Run("3.5/writer/token去重與狀態轉移", runStopWriterDedup)
	t.Run("3.5/writer/審計內容與資源歸屬", runStopAuditContent)
	t.Run("3.5/writer/審計失敗去重鍵不前進", runStopAuditFailureKeepsKey)
	t.Run("3.5/通知/提交後恰一次且依verification_sent選句", runStopNotifyOnceByVerificationSent)
	t.Run("3.5/verification_sent對映", runStopVerificationSentMapping)

	// 3.5 接入正式停止分支後的端到端：提交階段、去重與 token 轉移、審計失敗、期限
	t.Run("3.5/提交階段/一般候選", runCommitStopCandidate)
	t.Run("3.5/提交階段/成員", runCommitStopMember)
	t.Run("3.5/端到端/候選/去重與token轉移", runRetryStopTokens)
	t.Run("3.5/端到端/成員/去重與token轉移", runMemberStopTokens)
	t.Run("3.4/期限", runStopDeadlines)

	// 3.4 提交注入：真 Verify 之後、提交之前主機身分被重置
	t.Run("3.4/提交注入/ResetBarrier", runCommitResetBarrier)
}
