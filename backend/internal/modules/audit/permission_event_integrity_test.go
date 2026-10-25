package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var acceptWho = audit.PermissionAcceptActor{
	Actor:   gatewayapi.Actor{UserID: 1, Username: "root"},
	Request: gatewayapi.RequestMeta{Method: "POST", Path: "/api/v1/audit-failures/permission-state/accept", ClientIP: "192.0.2.9", StatusCode: 200},
}

// 排程鏈驗證的最小依賴（簽章服務就緒、政策取預設、出廠調校）。
type chainProbeStub struct{}

func (chainProbeStub) ActiveVersion() int            { return 1 }
func (chainProbeStub) ActivePublicKeyBase64() string { return "stub" }

type chainPolicyStub struct{}

func (chainPolicyStub) GetInt(string) int { return 0 }

type chainTuningStub struct{}

func (chainTuningStub) RecentWindowDays() int       { return 7 }
func (chainTuningStub) FullInterval() time.Duration { return time.Hour }
func (chainTuningStub) RowsPerHour() int64          { return 1000000 }

// 權限狀態事件的逐列完整性驗證碼。
//
// 威脅模型：只持資料庫帳密的人知道事件格式與雜湊演算法，算得出鏈接得上的摘要，
// 但沒有伺服器的完整性密鑰。這類人補寫的事件（含偽造的確認與重設基準）不得讓直接修改
// 被對帳成相符，也不得清掉已偵測到的無來源變動。
func TestPermissionEventIntegrity(t *testing.T) {
	ctx := context.Background()
	const superAdminRow = `[2,"user_roles"]`
	directWrite := `INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (2, 1, 'manual', 'global')`
	setup := func(t *testing.T) (*permEnv, *audit.RoleStateReconciler, *fakeFailureSink) {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		rec.SetPermissionAttestSigner(e.signer)
		return e, rec, fs
	}
	events := func(t *testing.T, db *gorm.DB) []model.PermissionStateEvent {
		var out []model.PermissionStateEvent
		require.NoError(t, db.Order("seq").Find(&out).Error)
		return out
	}

	t.Run("合法路徑每列帶驗證碼，重放相符", func(t *testing.T) {
		e, _, _ := setup(t)
		require.NoError(t, e.change(t, func(tx *gorm.DB) error {
			return tx.Create(&model.UserRole{UserID: 2, RoleID: 1, Source: "manual", ScopeKind: "global"}).Error
		}))
		for _, ev := range events(t, e.db) {
			require.Len(t, ev.IntegrityHMAC, 64, "seq=%d", ev.Seq)
			require.Equal(t, 1, ev.KeyVersion)
		}
		require.Equal(t, "match", e.reconcile().State)
	})

	// 實證情境：直寫掛上超管，只用資料庫連線補一筆自算事件。
	for name, key := range map[string][]byte{"驗證碼留空": nil, "攻擊者自備的鑰": []byte("attacker-key")} {
		t.Run("直寫超管＋自算事件仍不符並告警/"+name, func(t *testing.T) {
			e, rec, fs := setup(t)
			require.NoError(t, e.db.Exec(directWrite).Error)
			require.Equal(t, "mismatch", e.reconcile().State)
			forged, err := audit.ForgePermissionEvent(e.db, model.PermEventChange, false, key)
			require.NoError(t, err)
			require.Equal(t, forged.AfterDigest, events(t, e.db)[len(events(t, e.db))-1].AfterDigest, "鏈頭已是直寫後的狀態")

			rep := rec.ReconcilePermission(ctx)
			require.Equal(t, "mismatch", rep.State, "自算的事件不被採信")
			require.Contains(t, rep.Extra, superAdminRow, "差集指出被掛上的超管")
			require.Len(t, fs.permReports(), 1, "經失效事件通道告警")
			require.Zero(t, fs.permResolved())

			cp, err := e.svc.SealNow()
			require.NoError(t, err)
			require.NotNil(t, cp.PermReconciled)
			require.True(t, isFalse(cp.PermReconciled), "封章如實記下不符，不讓偽造的鏈頭成為基準")
			require.Equal(t, "mismatch", e.reconcile().State)
		})
	}

	t.Run("偽造的確認不得洗白，本身也計為無來源變動", func(t *testing.T) {
		e, rec, fs := setup(t)
		require.NoError(t, e.db.Exec(directWrite).Error)
		// 一次合法變更：應用程式先把直寫獨立記成 untraced 事件（帶驗證碼）
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error { return authz.SetUserGroupRoles(tx, 1, []uint{1}, 1) }))
		require.Equal(t, "mismatch", e.reconcile().State)
		_, err := audit.ForgePermissionEvent(e.db, model.PermEventAccept, false, []byte("attacker-key"))
		require.NoError(t, err)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "mismatch", rep.State)
		require.Contains(t, rep.Extra, superAdminRow)
		require.Len(t, fs.permReports(), 1)
		require.Zero(t, fs.permResolved(), "告警不因偽造的確認結案")
	})

	t.Run("偽造的重設基準不被採信", func(t *testing.T) {
		e, _, _ := setup(t)
		for i := 0; i < 2; i++ {
			require.NoError(t, e.change(t, func(tx *gorm.DB) error {
				return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
			}))
		}
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events WHERE seq = 2`).Error)
		require.Equal(t, "unknown", e.reconcile().State)
		require.NoError(t, e.db.Exec(directWrite).Error)
		_, err := audit.ForgePermissionEvent(e.db, model.PermEventAccept, true, []byte("attacker-key"))
		require.NoError(t, err)
		require.Equal(t, "unknown", e.reconcile().State, "只持資料庫帳密者不得自行重設基準")
	})

	t.Run("驗證碼有效但內容被改：不被採信", func(t *testing.T) {
		e, _, _ := setup(t)
		require.NoError(t, e.change(t, func(tx *gorm.DB) error { return nil }))
		// 改 after_body（不在摘要內）讓下一筆合法事件的差集以竄改後的狀態為起點
		head := events(t, e.db)[1]
		require.NoError(t, e.db.Exec(`UPDATE permission_state_events SET after_body = ? WHERE seq = 2`, head.AfterBody+" ").Error)
		rep := e.reconcile()
		require.Equal(t, "mismatch", rep.State, "改過的列驗不過，計為無來源變動")
	})

	t.Run("升級前的未蓋章舊列計為無來源變動，超管確認後恢復偵測", func(t *testing.T) {
		e, rec, fs := setup(t)
		require.NoError(t, e.change(t, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
		}))
		// 模擬升級前寫入的事件列：驗證碼欄由 migration 補上、值為空
		require.NoError(t, e.db.Exec(`UPDATE permission_state_events SET integrity_hmac = '', key_version = 0 WHERE seq > 1`).Error)
		require.Equal(t, "mismatch", rec.ReconcilePermission(ctx).State)
		require.Len(t, fs.permReports(), 1)
		svc := audit.NewPermissionAcceptService(e.db, audit.NewTxSink(), rec)
		_, err := svc.Accept(ctx, acceptWho, "升級前的事件列，已核對與當時操作紀錄一致")
		require.NoError(t, err)
		require.Equal(t, "match", e.reconcile().State)
		require.Equal(t, 1, fs.permResolved())
		require.NoError(t, e.db.Exec(directWrite).Error)
		require.Equal(t, "mismatch", e.reconcile().State, "之後的直寫照常偵測")
	})

	t.Run("段 2 之前寫下的事件由同一行程補章；被改過的不補", func(t *testing.T) {
		for _, tamper := range []bool{false, true} {
			e, _, _ := setup(t)
			restore := audit.UnregisterIntegrityForTest()
			require.NoError(t, e.change(t, func(tx *gorm.DB) error {
				return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
			}))
			restore()
			evs := events(t, e.db)
			require.Empty(t, evs[len(evs)-1].IntegrityHMAC, "寫入當下沒有完整性服務")
			if tamper {
				require.NoError(t, e.db.Exec(`UPDATE permission_state_events SET after_body = after_body || ' ' WHERE seq = ?`, evs[len(evs)-1].Seq).Error)
			}
			audit.StampPendingPermissionEvents(e.db)
			evs = events(t, e.db)
			if tamper {
				require.Empty(t, evs[len(evs)-1].IntegrityHMAC, "內容與本行程寫入的不同，不補章")
				require.Equal(t, "mismatch", e.reconcile().State)
				continue
			}
			require.Len(t, evs[len(evs)-1].IntegrityHMAC, 64)
			require.Equal(t, "match", e.reconcile().State)
		}
	})

	t.Run("事件鏈整段被刪：無法判定，不回退成尚未涵蓋", func(t *testing.T) {
		e, _, _ := setup(t)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		rep := e.reconcile()
		require.Equal(t, "unknown", rep.State)
		require.NotEmpty(t, rep.Error)
	})

	// 組合攻擊：直改權限、弄壞尾端事件讓對帳無法判定，再等一次例行封章，
	// 期望下一輪以封章當下（攻擊後）的快照為起點而相符。無法判定時封出的附證不是基準。
	for name, tamper := range map[string]string{
		"尾端摘要被改": `UPDATE permission_state_events SET digest = 'deadbeef' WHERE seq = (SELECT MAX(seq) FROM permission_state_events)`,
		"缺中段事件":  `DELETE FROM permission_state_events WHERE seq = (SELECT MAX(seq) FROM permission_state_events) - 1`,
	} {
		t.Run("直寫＋"+name+"＋例行封章：仍無法判定，超管重設後恢復偵測", func(t *testing.T) {
			e, rec, fs := setup(t)
			cp, err := e.svc.SealNow()
			require.NoError(t, err)
			require.True(t, isTrue(cp.PermReconciled), "C0：相符附證")
			for i := 0; i < 2; i++ {
				require.NoError(t, e.change(t, func(tx *gorm.DB) error {
					return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
				}))
			}
			require.NoError(t, e.db.Exec(directWrite).Error)
			require.NoError(t, e.db.Exec(tamper).Error)
			require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)

			c1, err := e.svc.SealNow()
			require.NoError(t, err, "封章不被擋")
			require.Nil(t, c1.PermReconciled)
			require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State, "留空的附證不成為基準")
			require.Len(t, fs.permReports(), 1)
			require.Zero(t, fs.permResolved(), "告警不被例行封章結案")

			svc := audit.NewPermissionAcceptService(e.db, audit.NewTxSink(), rec)
			res, err := svc.Accept(ctx, acceptWho, "事件列遭改，已與維運核對")
			require.NoError(t, err)
			require.Contains(t, res.Extra, superAdminRow, "接受的差集（相對最後可信參考點）留在回應與審計上")
			require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
			require.Equal(t, 1, fs.permResolved())
			require.NoError(t, e.db.Exec(`UPDATE group_role_mappings SET role_id = 1`).Error)
			require.Equal(t, "mismatch", e.reconcile().State, "重設之後的直寫照常偵測")
		})
	}

	// 寫入當下取不到完整性密鑰：一般事件照寫（不擋）但不可信；確認必須整筆回滾；
	// 之後的例行封章不把這段異常洗成可信。
	t.Run("取不到密鑰時事件照寫但不可信，確認回滾，封章不洗白", func(t *testing.T) {
		e, rec, fs := setup(t)
		_, err := e.svc.SealNow()
		require.NoError(t, err)
		undo := audit.UnregisterIntegrityForTest()
		require.NoError(t, e.change(t, func(tx *gorm.DB) error { return tx.Exec(directWrite).Error }), "一般權限寫入不被擋")
		audit.DrainPendingPermissionStampsForTest() // 行程在補章前結束
		svc := audit.NewPermissionAcceptService(e.db, audit.NewTxSink(), rec)
		_, err = svc.Accept(ctx, acceptWho, "密鑰不可用時嘗試確認")
		require.Error(t, err)
		undo()
		var n int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventAccept).Count(&n).Error)
		require.Zero(t, n, "確認整筆回滾")
		require.NoError(t, e.db.Model(&model.AuditLog{}).Where("action = ?", model.ActionPermissionStateAccepted).Count(&n).Error)
		require.Zero(t, n)
		require.Equal(t, "mismatch", rec.ReconcilePermission(ctx).State, "未蓋章的事件計為無來源變動")
		cp, err := e.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isFalse(cp.PermReconciled), "封章如實記不符")
		require.Equal(t, "mismatch", rec.ReconcilePermission(ctx).State)
		require.Zero(t, fs.permResolved())
		_, err = svc.Accept(ctx, acceptWho, "密鑰恢復後確認")
		require.NoError(t, err)
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
	})

	t.Run("計算驗證碼途中 lease 被撤回：事件照寫但不可信，確認回滾，封章不洗白", func(t *testing.T) {
		e, rec, fs := setup(t)
		_, err := e.svc.SealNow()
		require.NoError(t, err)
		undo := audit.UsePermissionEventRevokingKey([]byte("revoked-generation-key"))
		require.NoError(t, e.change(t, func(tx *gorm.DB) error { return tx.Exec(directWrite).Error }), "一般權限寫入不被擋")
		evs := events(t, e.db)
		require.Empty(t, evs[len(evs)-1].IntegrityHMAC, "lease 撤回後不留驗證碼")
		svc := audit.NewPermissionAcceptService(e.db, audit.NewTxSink(), rec)
		_, err = svc.Accept(ctx, acceptWho, "lease 撤回時嘗試確認")
		require.Error(t, err, "確認拿不到有效驗證碼即失敗")
		undo()
		audit.DrainPendingPermissionStampsForTest() // 行程在補章前結束
		var n int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventAccept).Count(&n).Error)
		require.Zero(t, n, "確認整筆回滾")
		require.Equal(t, "mismatch", rec.ReconcilePermission(ctx).State, "未蓋章的事件計為無來源變動")
		cp, err := e.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isFalse(cp.PermReconciled), "封章如實記不符")
		require.Zero(t, fs.permResolved())
	})

	t.Run("直寫＋刪除基準之後的全部事件：不符", func(t *testing.T) {
		e, _, _ := setup(t)
		_, err := e.svc.SealNow()
		require.NoError(t, err)
		require.NoError(t, e.change(t, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
		}))
		require.NoError(t, e.db.Exec(directWrite).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events WHERE seq > 1`).Error)
		require.Equal(t, "mismatch", e.reconcile().State)
	})

	// 只持資料庫帳密者把恢復狀態設成「待完成」並改權限資料，等下一次重啟讓應用程式替這份差異
	// 寫下帶有效驗證碼的 restore 事件。restore 事件只合法化恢復本身的版本與世代轉換。
	t.Run("偽造待完成恢復：restore 事件驗證碼有效，集合差異仍為無來源變動", func(t *testing.T) {
		for _, beforeStage2 := range []bool{false, true} {
			e, rec, fs := setup(t)
			require.NoError(t, e.db.Exec(`UPDATE group_role_mappings SET role_id = 1`).Error)
			require.NoError(t, e.db.Exec(`UPDATE authz_state SET restore_status = 'pending', restore_op_id = 'forged-op'`).Error)
			var undo func()
			if beforeStage2 {
				undo = audit.UnregisterIntegrityForTest()
			}
			done, err := authz.CompletePendingRestore(ctx, e.db)
			if beforeStage2 {
				undo()
				audit.StampPendingPermissionEvents(e.db) // 段 2 就緒後同一行程補章
			}
			require.NoError(t, err)
			require.True(t, done)
			evs := events(t, e.db)
			last := evs[len(evs)-1]
			require.Equal(t, model.PermEventRestore, last.Kind)
			require.Len(t, last.IntegrityHMAC, 64, "應用程式自己寫的 restore 事件帶有效驗證碼")
			rep := rec.ReconcilePermission(ctx)
			require.Equal(t, "mismatch", rep.State, "beforeStage2=%v", beforeStage2)
			require.Contains(t, rep.Extra, `[1,"role_maps"]`, "差集指出被換目標的映射")
			require.Len(t, fs.permReports(), 1)
		}
	})

	t.Run("真實恢復交易只改版本與世代：restore 事件不誤報", func(t *testing.T) {
		e, _, _ := setup(t)
		require.NoError(t, e.db.AutoMigrate(&model.AssetAuthorization{}))
		_, fresh, err := authz.CommitRestoreOnce(e.db, "op-restore-1", "digest-1")
		require.NoError(t, err)
		require.True(t, fresh)
		done, err := authz.CompletePendingRestore(ctx, e.db)
		require.NoError(t, err)
		require.True(t, done)
		evs := events(t, e.db)
		require.Equal(t, model.PermEventRestore, evs[len(evs)-1].Kind)
		require.Equal(t, "match", e.reconcile().State)
	})
}

// 附證啟用後的「無法判定」：開固定識別的告警、驗證結果看得到；超管可重設基準留下接受風險的紀錄。
func TestPermissionUnknownAlertAndRebase(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*permEnv, *audit.RoleStateReconciler, *fakeFailureSink) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		rec.SetPermissionAttestSigner(e.signer)
		for i := 0; i < 3; i++ {
			require.NoError(t, e.change(t, func(tx *gorm.DB) error {
				return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
			}))
		}
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events WHERE seq = 2`).Error) // 鏈損壞
		return e, rec, fs
	}

	t.Run("首次啟用與起點同交易提交：不開單；清空唯一的起點附證即無法判定", func(t *testing.T) {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		rec.SetPermissionAttestSigner(e.signer)
		e.svc.SetRoleStateReconciler(rec) // 封章前的對帳走同一個對帳器
		require.NoError(t, e.svc.EnsureGenesis())
		require.Empty(t, fs.permReports(), "全新安裝的首次啟用不開單")
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
		// 起點附證被清空：附證在簽章內，該點自己驗不過，無法判定
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_state_snapshot = NULL, perm_origin = NULL, perm_format = NULL, perm_event_seq = NULL, perm_event_head = NULL`).Error)
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
		require.Len(t, fs.permReports(), 1)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		v := audit.NewCheckpointVerifier(e.db, e.svc, audit.NewCheckpointPurger(e.db, e.signer), nil, nil)
		v.SetRoleStateReconciler(rec)
		chain, err := v.VerifyChain()
		require.NoError(t, err)
		require.Equal(t, audit.IntervalStatusSignatureInvalid, chain.Status, "清空附證的起點自己驗不過")
	})

	t.Run("鏈損壞：告警一筆（固定識別、不重開）且驗證結果顯示", func(t *testing.T) {
		e, rec, fs := setup(t)
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
		reps := fs.permReports()
		require.Len(t, reps, 1, "整段無法判定期間只開一張單")
		require.Equal(t, "unknown", reps[0]["actual_hash"])
		require.Equal(t, "0", reps[0]["since_seq"])

		v := audit.NewCheckpointVerifier(e.db, e.svc, audit.NewCheckpointPurger(e.db, e.signer), nil, nil)
		v.SetRoleStateReconciler(rec)
		chain, err := v.VerifyChain()
		require.NoError(t, err)
		require.NotNil(t, chain.Permission, "驗證結果帶權限附證維度")
		require.Equal(t, "unknown", chain.Permission.State)
		require.Len(t, fs.permReports(), 1, "驗證路徑同一張單")
	})

	t.Run("超管重設基準：寫審計（原因與狀態摘要）、告警結案、恢復偵測", func(t *testing.T) {
		e, rec, fs := setup(t)
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
		svc := audit.NewPermissionAcceptService(e.db, audit.NewTxSink(), rec)
		res, err := svc.Accept(ctx, acceptWho, "事件列遭誤刪，已與維運核對現況")
		require.NoError(t, err)
		require.Equal(t, "match", e.reconcile().State)
		require.Equal(t, 1, fs.permResolved(), "告警結案")

		var row model.AuditLog
		require.NoError(t, e.db.Where("action = ?", model.ActionPermissionStateAccepted).First(&row).Error)
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(row.Details), &d))
		require.Equal(t, "rebase", d["mode"])
		require.Equal(t, "unknown", d["state"])
		require.NotEmpty(t, d["cause"], "記下無法判定的原因摘要")
		require.Equal(t, "事件列遭誤刪，已與維運核對現況", d["reason"])
		require.EqualValues(t, res.EventSeq, d["event_seq"])

		var n int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("seq = 3").Count(&n).Error)
		require.EqualValues(t, 1, n, "被破壞的那段不被修補或刪除")

		require.NoError(t, e.db.Exec(`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (2, 1, 'manual', 'global')`).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "mismatch", rep.State, "重設之後的直寫照常偵測")
		require.Contains(t, rep.Extra, `[2,"user_roles"]`)

		// 下一次封章：附證記不符，基準不前進；確認後再封章成為新基準
		cp, err := e.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isFalse(cp.PermReconciled))
		_, err = svc.Accept(ctx, acceptWho, "已核對")
		require.NoError(t, err)
		cp, err = e.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isTrue(cp.PermReconciled))
		require.Equal(t, "match", e.reconcile().State)
	})

	// 一個附證完好、事件鏈完整的已啟用環境：genesis（起點附證）＋兩次封章，中間有合法變更。
	attested := func(t *testing.T) (*permEnv, *audit.RoleStateReconciler, *fakeFailureSink) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		for i := 0; i < 2; i++ {
			require.NoError(t, e.change(t, func(tx *gorm.DB) error {
				return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
			}))
			cp, err := e.svc.SealNow()
			require.NoError(t, err)
			require.True(t, isTrue(cp.PermReconciled))
		}
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		rec.SetPermissionAttestSigner(e.signer)
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
		return e, rec, fs
	}
	verifier := func(e *permEnv, rec *audit.RoleStateReconciler) *audit.CheckpointVerifier {
		v := audit.NewCheckpointVerifier(e.db, e.svc, audit.NewCheckpointPurger(e.db, e.signer), nil, nil)
		v.SetRoleStateReconciler(rec)
		return v
	}
	const clearAll = `UPDATE audit_checkpoints SET perm_state_snapshot = NULL, perm_origin = NULL, perm_format = NULL, perm_event_seq = NULL, perm_event_head = NULL, perm_reconciled = NULL`

	// 只持資料庫帳密者：直改權限、清空全部附證、把啟用界標改到遠大於目前序號，
	// 企圖讓對帳以為「首次封章進行中」而回到尚未涵蓋，再讓下一次封章重建起點。
	t.Run("清空全部附證並改大啟用界標：無法判定、單一張單、封章不洗成起點", func(t *testing.T) {
		e, rec, fs := attested(t)
		require.NoError(t, e.db.Exec(`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (2, 1, 'manual', 'global')`).Error)
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`UPDATE permission_state_events SET activated_seq = 999 WHERE kind = 'activate'`).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State)
		require.Contains(t, rep.Error, "現存鏈結構驗證失敗", "被清空附證的點自己驗不過，證明不了從未啟用")
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
		require.Len(t, fs.permReports(), 1, "固定識別，一張單")
		require.Equal(t, "unknown", fs.permReports()[0]["actual_hash"])

		cp, err := e.svc.SealNow()
		require.NoError(t, err, "封章不被擋")
		require.Nil(t, cp.PermReconciled, "無法判定時附證對帳結果留空")
		require.True(t, isFalse(cp.PermOrigin), "攻擊後封出的點，簽章內的起點旗標為 false")
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State, "留空的附證不成為起點")
		require.Zero(t, fs.permResolved())
		chain, err := verifier(e, rec).VerifyChain()
		require.NoError(t, err)
		require.Equal(t, audit.IntervalStatusSignatureInvalid, chain.Status, "被清空附證的點自己驗不過")
	})

	// 刪光事件（或只刪啟用事件）並清空全部附證：鏈尾的鏈接綁著前一點的附證簽章，
	// 無法證明「從未啟用」，不回退成尚未涵蓋。
	for name, del := range map[string]string{
		"刪全部事件":  `DELETE FROM permission_state_events`,
		"刪啟用事件": `DELETE FROM permission_state_events WHERE kind = 'activate'`,
	} {
		t.Run("清空全部附證並"+name+"：無法判定", func(t *testing.T) {
			e, rec, fs := attested(t)
			require.NoError(t, e.db.Exec(clearAll).Error)
			require.NoError(t, e.db.Exec(del).Error)
			rep := rec.ReconcilePermission(ctx)
			require.Equal(t, "unknown", rep.State, rep.Error)
			require.Len(t, fs.permReports(), 1)
			cp, err := e.svc.SealNow()
			require.NoError(t, err)
			require.Nil(t, cp.PermReconciled)
			require.True(t, isFalse(cp.PermOrigin))
			require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State, "重新啟用的附證不是起點")
		})
	}

	// 導向「尚未涵蓋」的輸入必須受保護：讀不到、欄位缺失、只剩鏈尾一點、事件表被刪除，
	// 一律無法判定並開單，不以「讀不到」當作「沒有」。
	t.Run("刪光鏈尾以外的檢查點並清空附證與事件：無法判定", func(t *testing.T) {
		e, rec, fs := attested(t)
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoints WHERE seq < 3`).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "鏈頭既非 genesis 亦無修剪錨，不能證明從未啟用")
		require.Contains(t, rep.Error, "現存鏈結構驗證失敗")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("事件表被刪除並清空唯一的起點附證：無法判定", func(t *testing.T) {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		rec.SetPermissionAttestSigner(e.signer)
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`DROP TABLE permission_state_events`).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State)
		require.Contains(t, rep.Error, "事件表不存在")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("附證欄讀取失敗：無法判定並開單", func(t *testing.T) {
		e, rec, fs := attested(t)
		require.NoError(t, e.db.Exec(`ALTER TABLE audit_checkpoints DROP COLUMN perm_reconciled`).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State)
		require.Contains(t, rep.Error, "讀取權限附證失敗")
		require.Len(t, fs.permReports(), 1)
		// 再刪光事件：鏈尾鏈接仍完好，若把「讀不到附證」當作「沒有附證」就會回到尚未涵蓋
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		rep = rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "讀不到附證不等於沒有附證")
		require.Contains(t, rep.Error, "讀取權限附證失敗")
	})

	// 讀取失敗注入：符合條件的查詢回錯且不帶資料（模擬連線中斷、權限被收回、表被鎖）。
	failQuery := func(t *testing.T, db *gorm.DB, table string, match func(sql string) bool) {
		name := "test:fail-read:" + t.Name()
		require.NoError(t, db.Callback().Query().After("gorm:query").Register(name, func(d *gorm.DB) {
			if d.Statement.Table != table || !match(d.Statement.SQL.String()) {
				return
			}
			if d.Statement.ReflectValue.CanSet() {
				d.Statement.ReflectValue.Set(reflect.Zero(d.Statement.ReflectValue.Type()))
			}
			_ = d.AddError(errors.New("injected read failure"))
		}))
		t.Cleanup(func() { _ = db.Callback().Query().Remove(name) })
	}
	// 只有一個起點附證的環境（首次封章後）：鏈尾是 genesis，鏈尾鏈接本身完好。
	genesisOnly := func(t *testing.T) (*permEnv, *audit.RoleStateReconciler, *fakeFailureSink) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		rec.SetPermissionAttestSigner(e.signer)
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
		return e, rec, fs
	}
	t.Run("事件讀取失敗：不當作沒有事件，無法判定並開單", func(t *testing.T) {
		e, rec, fs := genesisOnly(t)
		require.NoError(t, e.db.Exec(clearAll).Error)
		failQuery(t, e.db, "permission_state_events", func(sql string) bool {
			return !strings.Contains(sql, "kind") && strings.Contains(sql, "ORDER BY seq ASC LIMIT 1")
		})
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "讀不到事件不得回到尚未涵蓋")
		require.Contains(t, rep.Error, "讀取權限狀態事件失敗")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("清空唯一的起點附證：單點附證驗證判無效，不判尚未涵蓋", func(t *testing.T) {
		e, _, _ := genesisOnly(t)
		require.NoError(t, e.db.Exec(clearAll).Error)
		var cp model.AuditCheckpoint
		require.NoError(t, e.db.First(&cp, "seq = 1").Error)
		st := audit.VerifyPermissionAttestation(e.db, &cp, e.signer)
		require.Equal(t, audit.PermAttestInvalid, st.State, "附證在簽章內：清空後該點自己驗不過")
		require.Contains(t, st.Reason, "簽章驗證失敗")
	})
	t.Run("修剪記錄讀取失敗：無法判定，不略過", func(t *testing.T) {
		e, rec, fs := attested(t)
		failQuery(t, e.db, "audit_checkpoint_trims", func(string) bool { return true })
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State)
		require.Contains(t, rep.Error, "讀取鏈修剪記錄失敗")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("鏈讀取失敗：不當作空鏈，無法判定", func(t *testing.T) {
		e, rec, fs := attested(t)
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		failQuery(t, e.db, "audit_checkpoints", func(sql string) bool {
			return strings.Contains(sql, "ORDER BY seq ASC") && !strings.Contains(sql, "LIMIT")
		})
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "讀不到鏈不等於空鏈")
		require.Contains(t, rep.Error, "讀取檢查點鏈失敗")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("偽造修剪記錄接住只剩一點的鏈：修剪記錄簽章驗不過，無法判定", func(t *testing.T) {
		e, rec, fs := attested(t)
		var cp2 model.AuditCheckpoint
		require.NoError(t, e.db.First(&cp2, "seq = 2").Error)
		link, err := audit.CheckpointLinkHash(&cp2)
		require.NoError(t, err)
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoints WHERE seq < 3`).Error)
		require.NoError(t, e.db.Create(&model.AuditCheckpointTrim{FromSeq: 1, LastTrimmedSeq: 2, TrimmedCount: 2,
			LastTrimmedLinkHash: link, PolicyDays: 1, TrimmedAt: time.Now().UTC(), SigningKeyVersion: 1, Signature: "AAAA"}).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "照公開算法算出的修剪錨不能證明鏈頭是合法修剪")
		require.Contains(t, rep.Error, "現存鏈結構驗證失敗")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("修剪記錄簽章有效但錨定值不是鏈頭的前一雜湊：不視為接得上", func(t *testing.T) {
		e, rec, fs := attested(t)
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoints WHERE seq < 3`).Error)
		trim := &model.AuditCheckpointTrim{FromSeq: 1, LastTrimmedSeq: 2, TrimmedCount: 2, Format: model.CheckpointTrimFormatV1,
			LastTrimmedLinkHash: strings.Repeat("0", 64), PolicyDays: 1, TrimmedAt: time.Now().UTC().Truncate(time.Microsecond)}
		payload, err := audit.CheckpointTrimSignBytes(trim)
		require.NoError(t, err)
		trim.SigningKeyVersion, trim.Signature = e.signer.Sign(payload)
		require.NoError(t, e.db.Create(trim).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "修剪記錄須錨定的正是鏈頭的前一雜湊")
		require.Contains(t, rep.Error, "現存鏈結構驗證失敗")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("刪光事件等重新啟用後刪掉最新檢查點並清空附證：不能回到尚未涵蓋", func(t *testing.T) {
		e, rec, fs := attested(t)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		cp, err := e.svc.SealNow() // 重新啟用：新啟用事件的界標＝這個檢查點
		require.NoError(t, err)
		require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoints WHERE seq = ?`, cp.Seq).Error)
		require.NoError(t, e.db.Exec(clearAll).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "被清空附證的點自己驗不過")
		require.Contains(t, rep.Error, "現存鏈結構驗證失敗")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("刪光檢查點、事件表留著（含偽造的較早事件）：無法判定", func(t *testing.T) {
		e, rec, fs := genesisOnly(t)
		require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoints`).Error)
		var act model.PermissionStateEvent
		require.NoError(t, e.db.First(&act, "kind = ?", model.PermEventActivate).Error)
		forged := act
		forged.ID, forged.Seq, forged.Kind, forged.ActivatedSeq = 0, act.Seq-1, model.PermEventChange, nil
		require.NoError(t, e.db.Create(&forged).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "事件表非空就不是乾淨起點")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("首次附證後清空起點附證並把啟用界標改成下一序號：無法判定", func(t *testing.T) {
		e, rec, fs := genesisOnly(t)
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`UPDATE permission_state_events SET activated_seq = 2 WHERE kind = 'activate'`).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "清空的起點驗不過；啟用界標不是判定輸入")
		require.Contains(t, rep.Error, "現存鏈結構驗證失敗")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("直寫＋刪全部事件（附證保留）＋例行封章：重新啟用的附證不是起點", func(t *testing.T) {
		e, rec, fs := attested(t)
		require.NoError(t, e.db.Exec(`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (2, 1, 'manual', 'global')`).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
		cp, err := e.svc.SealNow()
		require.NoError(t, err, "封章不被擋")
		require.Nil(t, cp.PermReconciled)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "較早的附證仍在，新啟用事件所在的附證不是鏈上最早的附證")
		require.Len(t, fs.permReports(), 1)
		require.Zero(t, fs.permResolved())
	})

	// 完整性驗證在驗不了時一律不算通過：鏈尾簽章、驗章能力、完整性服務、涵蓋事實讀取。
	forgeTail := func(t *testing.T, e *permEnv, seq uint, prevOf *uint) {
		var cp model.AuditCheckpoint
		require.NoError(t, e.db.First(&cp, "seq = ?", seq).Error)
		forged := cp
		forged.ID = 0
		forged.Signature = "AAAA"
		if prevOf != nil {
			var prev model.AuditCheckpoint
			require.NoError(t, e.db.First(&prev, "seq = ?", *prevOf).Error)
			link, err := audit.CheckpointLinkHash(&prev)
			require.NoError(t, err)
			forged.PrevCheckpointHash = link // 照公開算法算出的「完好」鏈接
		}
		require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoints WHERE seq = ?`, seq).Error)
		require.NoError(t, e.db.Create(&forged).Error)
	}
	t.Run("偽造鏈尾檢查點讓鏈尾鏈接相符：簽章驗不過，無法判定", func(t *testing.T) {
		e, rec, fs := attested(t)
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		prev := uint(2)
		forgeTail(t, e, 3, &prev)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State)
		require.Contains(t, rep.Error, "現存鏈結構驗證失敗")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("刪光檢查點後只留一個偽造的 genesis：簽章驗不過，無法判定", func(t *testing.T) {
		e, rec, fs := attested(t)
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoints WHERE seq > 1`).Error)
		forgeTail(t, e, 1, nil)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State)
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("未注入驗章能力：無法判定，不回相符或尚未涵蓋", func(t *testing.T) {
		e, _, _ := attested(t)
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
		require.Len(t, fs.permReports(), 1)
		// 驗不了鏈尾簽章時，清空痕跡並偽造鏈尾也不得回到尚未涵蓋
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		prev := uint(2)
		forgeTail(t, e, 3, &prev)
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
	})
	t.Run("完整性服務不可用（解封未完成或密鑰取不到）：起點由簽章內的旗標採信，其後未蓋章的事件計無來源變動", func(t *testing.T) {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		rec.SetPermissionAttestSigner(e.signer)
		undo := audit.UnregisterIntegrityForTest()
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State, "起點不依賴啟用事件的驗證碼：快照與界標在檢查點簽章內")
		require.NoError(t, e.change(t, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
		}))
		audit.DrainPendingPermissionStampsForTest() // 行程在補章前結束
		undo()
		require.Equal(t, "mismatch", rec.ReconcilePermission(ctx).State, "未蓋章的事件計為無來源變動，不回相符")
		require.Len(t, fs.permReports(), 1)
	})
	t.Run("起點事實讀取失敗：結構層逐點驗章獨立照判，對帳無法判定", func(t *testing.T) {
		e, rec, _ := attested(t)
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_reconciled = false WHERE seq = 3`).Error)
		require.NoError(t, e.db.Exec(`DROP TABLE permission_state_events`).Error)
		chain, err := verifier(e, rec).VerifyChain()
		require.NoError(t, err)
		got := map[uint]string{}
		for _, f := range chain.Failures {
			got[f.Seq] = f.Status
		}
		require.Equal(t, audit.IntervalStatusSignatureInvalid, got[3], "改附證欄使該點自己驗不過")
		require.Equal(t, "unknown", chain.Permission.State)
	})

	// 每一個必要附證都要可驗：被清空的附證不被較早或較新的可用基準遮住。
	for name, tamper := range map[string]string{
		"清空鏈尾附證":    clearAll + ` WHERE seq = 3`,
		"改鏈尾附證對帳結果": `UPDATE audit_checkpoints SET perm_reconciled = false WHERE seq = 3`,
	} {
		t.Run(name+"：該點自己驗不過並計入失敗，對帳仍以較早附證相符", func(t *testing.T) {
			e, rec, fs := attested(t)
			require.NoError(t, e.db.Exec(tamper).Error)
			chain, err := verifier(e, rec).VerifyChain()
			require.NoError(t, err)
			require.EqualValues(t, 1, chain.Failed)
			require.Equal(t, audit.IntervalStatusSignatureInvalid, chain.Status)
			require.Equal(t, uint(3), chain.Failures[0].Seq)
			require.Equal(t, "match", chain.Permission.State, "偵測不中斷")
			require.Empty(t, fs.permReports())

			// 排程驗證把附證失效經結構層告警送進持久通道
			require.NoError(t, e.db.AutoMigrate(&model.AuditChainVerifyState{}, &model.AuditFailureEvent{}, &model.SecurityPolicy{}))
			cvs := audit.NewChainVerifyService(e.db, verifier(e, rec), e.svc, chainProbeStub{}, chainPolicyStub{},
				chainTuningStub{}, audit.NewAuditFailureServiceForTest(e.db))
			require.NoError(t, cvs.RunFullNow(ctx))
			var ev model.AuditFailureEvent
			require.NoError(t, e.db.Where("mechanism = ? AND ended_at IS NULL", model.MechanismAuditChainStructure).First(&ev).Error)
			require.Equal(t, model.CauseAuditChainStructureInvalid, ev.CauseCode)
		})
	}
	t.Run("改非鏈尾附證欄：該點驗不過、下一點斷鏈", func(t *testing.T) {
		e, rec, _ := attested(t)
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_reconciled = false WHERE seq = 2`).Error)
		chain, err := verifier(e, rec).VerifyChain()
		require.NoError(t, err)
		got := map[uint]string{}
		for _, f := range chain.Failures {
			got[f.Seq] = f.Status
		}
		require.Equal(t, map[uint]string{2: audit.IntervalStatusSignatureInvalid, 3: audit.ChainStatusChainBroken}, got)
	})

	// 告警冪等以資料庫為準：單被刪除或被填上結案時間，下一次對帳重建；同識別連續對帳只一列。
	t.Run("告警列被刪或偽造結案：下一次對帳重建（持久通道）", func(t *testing.T) {
		e, _, _ := setup(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditFailureEvent{}, &model.SecurityPolicy{}))
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(audit.NewAuditFailureServiceForTest(e.db))
		rec.SetPermissionAttestSigner(e.signer)
		open := func(t *testing.T, table string) int64 {
			var n int64
			require.NoError(t, e.db.Model(&model.AuditFailureEvent{}).
				Where("ended_at IS NULL AND cause_params LIKE ?", `%"table":"`+table+`"%`).Count(&n).Error)
			return n
		}
		for i := 0; i < 3; i++ {
			require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
		}
		require.EqualValues(t, 1, open(t, audit.StateTablePermission), "同識別連續對帳只一列")
		require.NoError(t, e.db.Exec(`DELETE FROM audit_failure_events`).Error)
		rec.ReconcilePermission(ctx)
		require.EqualValues(t, 1, open(t, audit.StateTablePermission), "被刪的單重建")
		require.NoError(t, e.db.Exec(`UPDATE audit_failure_events SET ended_at = CURRENT_TIMESTAMP`).Error)
		rec.ReconcilePermission(ctx)
		require.EqualValues(t, 1, open(t, audit.StateTablePermission), "偽造結案後重開")

		// 主體投影走同一條持久通道
		require.NoError(t, e.db.Exec(`UPDATE users SET kind = 'agent', owner_user_id = 1 WHERE id = 2`).Error)
		rec.ReconcileTables(ctx)
		require.EqualValues(t, 1, open(t, audit.StateTablePrincipals))
		require.NoError(t, e.db.Exec(`DELETE FROM audit_failure_events WHERE cause_params LIKE ?`, `%"table":"`+audit.StateTablePrincipals+`"%`).Error)
		rec.ReconcileTables(ctx)
		require.EqualValues(t, 1, open(t, audit.StateTablePrincipals), "主體投影的單同樣重建")
	})

	// 保存期限修剪會把「啟用是在破壞之後重建」的鏈形狀合法剪掉、換成有效的修剪錨。
	// 暫定起點標記寫在啟用事件（事件表不受修剪影響），修剪後仍不得自動升格為可信起點。
	// 夾具：三點正常鏈（舊時點）→ 直改權限、清空全部附證、刪光事件 → 例行封章 4、5、6
	// （4 重新啟用）→ 真正的 TrimChain 剪掉到期的點，保留最新的 keep 點。
	trimmed := func(t *testing.T, keep int) (*permEnv, *audit.RoleStateReconciler, func() int64) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}, &model.AuditFailureEvent{}, &model.SecurityPolicy{}))
		seedPerm(t, e.db, false)
		audit.SetSealClockForTest(e.svc, time.Now().UTC().Add(-72*time.Hour))
		require.NoError(t, e.svc.EnsureGenesis())
		for i := 0; i < 2; i++ {
			_, err := e.svc.SealNow()
			require.NoError(t, err)
		}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetPermissionAttestSigner(e.signer)
		rec.SetStateFailureSink(audit.NewAuditFailureServiceForTest(e.db))
		open := func() int64 {
			var n int64
			require.NoError(t, e.db.Model(&model.AuditFailureEvent{}).
				Where("ended_at IS NULL AND cause_params LIKE ?", `%"table":"`+audit.StateTablePermission+`"%`).Count(&n).Error)
			return n
		}
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
		require.NoError(t, e.db.Exec(`UPDATE group_role_mappings SET role_id = 1`).Error)
		require.NoError(t, e.db.Exec(clearAll).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
		cut := 6 - keep
		for seq := 4; seq <= 6; seq++ {
			if seq > cut {
				audit.SetSealClockForTest(e.svc, time.Now().UTC())
			}
			cp, err := e.svc.SealNow()
			require.NoError(t, err, "封章不被擋")
			require.Nil(t, cp.PermReconciled)
		}
		var rebuilt model.AuditCheckpoint
		require.NoError(t, e.db.First(&rebuilt, "seq = 4").Error)
		require.NotNil(t, rebuilt.PermOrigin)
		require.True(t, isFalse(rebuilt.PermOrigin), "破壞之後重建啟用的點，簽章內的起點旗標為 false")
		require.Equal(t, "unknown", rec.ReconcilePermission(ctx).State)
		p := audit.NewCheckpointPurger(e.db, e.signer)
		n, trim, err := p.TrimChain(1)
		require.NoError(t, err)
		require.EqualValues(t, cut, n, "到期的點被真正的修剪流程剪掉")
		valid, err := p.VerifyTrim(trim)
		require.NoError(t, err)
		require.True(t, valid, "修剪錨簽章有效")
		require.EqualValues(t, keep, e.count(t, "audit_checkpoints"))
		return e, rec, open
	}
	t.Run("清空附證刪光事件後例行封章再經修剪（保留三點）：仍無法判定，超管重設後恢復偵測", func(t *testing.T) {
		e, rec, open := trimmed(t, 3)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "修剪錨接得上鏈頭，但殘鏈各點的起點旗標在簽章內為 false")
		require.Contains(t, rep.Error, "有附證痕跡但無可信基準")
		require.EqualValues(t, 1, open(), "告警不因修剪結案")
		chain, err := verifier(e, rec).VerifyChain()
		require.NoError(t, err)
		require.Equal(t, "unknown", chain.Permission.State)
		var accepts int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventAccept).Count(&accepts).Error)
		require.Zero(t, accepts, "沒有任何確認事件")

		svc := audit.NewPermissionAcceptService(e.db, audit.NewTxSink(), rec)
		_, err = svc.Accept(ctx, acceptWho, "附證與變更紀錄遭清除，已與維運核對現況")
		require.NoError(t, err)
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State, "受審計的重設是唯一出口")
		require.Zero(t, open(), "重設後結案")
		cp, err := e.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isTrue(cp.PermReconciled), "重設之後的封章相符")
		require.NoError(t, e.db.Exec(`UPDATE group_role_mappings SET role_id = 2`).Error)
		require.Equal(t, "mismatch", rec.ReconcilePermission(ctx).State, "重設之後的直寫照常偵測")
	})
	t.Run("清空附證刪光事件後例行封章再經修剪（連重建啟用所在的點一起剪掉、保留兩點）：仍無法判定", func(t *testing.T) {
		_, rec, open := trimmed(t, 2)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "殘鏈各點的起點旗標為 false、對帳結果為空")
		require.EqualValues(t, 1, open())
	})

	// 正向：全新安裝與升級後的首次啟用能證明「從未啟用」，不帶暫定標記，是可信起點；
	// 修剪掉啟用之前的舊鏈段（換成修剪錨）後仍自它起算，直寫照常偵測。
	t.Run("全新安裝首次啟用：自動成為可信起點、不開單", func(t *testing.T) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		rec.SetPermissionAttestSigner(e.signer)
		var genesis model.AuditCheckpoint
		require.NoError(t, e.db.First(&genesis, "seq = 1").Error)
		require.True(t, isTrue(genesis.PermOrigin), "全新安裝的 genesis 是起點")
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
		require.Empty(t, fs.permReports())
		require.NoError(t, e.db.Exec(`UPDATE group_role_mappings SET role_id = 1`).Error)
		require.Equal(t, "mismatch", rec.ReconcilePermission(ctx).State, "自起點起算，直寫被偵測")
	})
	t.Run("升級後首次啟用：可信起點，修剪掉啟用前的舊鏈段後仍自它起算", func(t *testing.T) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		audit.SetSealClockForTest(e.svc, time.Now().UTC().Add(-72*time.Hour))
		audit.SetPermissionSources(nil, nil) // 升級前的封章：第三版載荷、沒有附證、沒有事件
		audit.SetSealSchemeForTest(e.svc, model.AggSchemeV3)
		require.NoError(t, e.svc.EnsureGenesis())
		for i := 0; i < 2; i++ {
			_, err := e.svc.SealNow()
			require.NoError(t, err)
		}
		audit.SetSealSchemeForTest(e.svc, "")
		newPermDBWire(t)
		audit.SetSealClockForTest(e.svc, time.Now().UTC())
		cp, err := e.svc.SealNow() // 升級後第一次封章＝啟用
		require.NoError(t, err)
		require.EqualValues(t, 4, cp.Seq)
		require.Nil(t, cp.PermReconciled, "首次封章窗口內對帳為尚未涵蓋，附證對帳結果留空")
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		rec.SetPermissionAttestSigner(e.signer)
		require.True(t, isTrue(cp.PermOrigin), "舊鏈逐點驗章通過、無任何痕跡：首個第四版點是起點")
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State, "起點附證為基準")
		p := audit.NewCheckpointPurger(e.db, e.signer)
		n, _, err := p.TrimChain(1)
		require.NoError(t, err)
		require.EqualValues(t, 3, n, "啟用前的舊鏈段到期被剪掉")
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State, "起點接在修剪錨後，仍是可信基準")
		require.Empty(t, fs.permReports())
		require.NoError(t, e.db.Exec(`UPDATE group_role_mappings SET role_id = 1`).Error)
		require.Equal(t, "mismatch", rec.ReconcilePermission(ctx).State, "修剪後仍自起點起算，直寫被偵測")
	})
	// 正常啟用的成功路徑。起點的形狀只有一種（origin=true、reconciled=null），候選判定必須保留
	// 對帳結果的三態：封出起點後立即相符、不開單，下一點相符；反向：origin=false、reconciled=null 的點
	// （攻擊後重建啟用）不是候選。
	t.Run("正常啟用（全新安裝）：起點封出後立即相符、不開單、下一點相符、直寫照常偵測", func(t *testing.T) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		var g model.AuditCheckpoint
		require.NoError(t, e.db.First(&g, "seq = 1").Error)
		require.True(t, isTrue(g.PermOrigin))
		require.Nil(t, g.PermReconciled)
		rec, fs := permRec(e)
		chain, err := verifier(e, rec).VerifyChain()
		require.NoError(t, err)
		require.Equal(t, audit.IntervalStatusPassed, chain.Status, "起點載荷驗過")
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State, "封出後立即相符")
		require.Empty(t, fs.permReports(), "未結案單數 0")
		var accepts int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventAccept).Count(&accepts).Error)
		require.Zero(t, accepts)
		cp, err := e.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isTrue(cp.PermReconciled), "下一點自起點起算而相符")
		require.True(t, isFalse(cp.PermOrigin))
		require.NoError(t, e.db.Exec(`UPDATE group_role_mappings SET role_id = 1`).Error)
		require.Equal(t, "mismatch", rec.ReconcilePermission(ctx).State)
	})
	t.Run("正常啟用（升級）：真第三版鏈之後的首個第四版點為起點，立即相符、下一點相符", func(t *testing.T) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		audit.SetPermissionSources(nil, nil)
		audit.SetSealSchemeForTest(e.svc, model.AggSchemeV3)
		require.NoError(t, e.svc.EnsureGenesis())
		for i := 0; i < 2; i++ {
			_, err := e.svc.SealNow()
			require.NoError(t, err)
		}
		audit.SetSealSchemeForTest(e.svc, "")
		newPermDBWire(t)
		cp, err := e.svc.SealNow()
		require.NoError(t, err)
		require.Equal(t, model.AggSchemeV4, cp.AggScheme)
		require.True(t, isTrue(cp.PermOrigin))
		require.Nil(t, cp.PermReconciled)
		rec, fs := permRec(e)
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
		require.Empty(t, fs.permReports())
		next, err := e.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isTrue(next.PermReconciled))
	})
	t.Run("正常啟用的反向：origin=false、reconciled=null 的點不是候選；部分清空的點計入診斷", func(t *testing.T) {
		e, rec, fs := genesisOnly(t)
		var g model.AuditCheckpoint
		require.NoError(t, e.db.First(&g, "seq = 1").Error)
		// 以持有簽章鑰者的身分重簽：模擬「攻擊後重建啟用」形狀的唯一附證點
		f := false
		g.PermOrigin = &f
		payload, err := audit.CheckpointSignBytes(&g)
		require.NoError(t, err)
		_, sig := e.signer.Sign(payload)
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_origin = false, signature = ? WHERE seq = 1`, sig).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "簽章有效但不是起點、也不相符：不是候選")
		require.Contains(t, rep.Error, "有附證痕跡但無可信基準")
		require.Len(t, fs.permReports(), 1)
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_event_head = NULL WHERE seq = 1`).Error)
		rep = rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State)
		require.Contains(t, rep.Error, "第四版檢查點載荷無法重建 1 點", "診斷計數真的走到")
	})
	// 生命週期（本體在 permission_lifecycle_test.go；每個情境記同一張時間表）
	t.Run("生命週期：清空附證＋刪事件→封一點→再清空＋刪事件→封三點→修剪→重設→直寫", func(t *testing.T) {
		lifeClearTwiceThenTrim(t, true)
	})
	t.Run("生命週期：同上但第一次不刪事件", func(t *testing.T) { lifeClearTwiceThenTrim(t, false) })
	t.Run("生命週期：清空＋刪事件後封三點，修剪保留三點（錨 unverified）", func(t *testing.T) { lifeClearThenTrimKeep(t, 3) })
	t.Run("生命週期：清空＋刪事件後封三點，修剪連重建啟用的點一起剪、保留兩點", func(t *testing.T) { lifeClearThenTrimKeep(t, 2) })
	t.Run("生命週期：升級混合鏈的第四版點改標第三版並清空附證", lifeRelabelV3)
	t.Run("生命週期：修剪到只剩一點、鏈被刪空、錨與事件逐一刪除", lifeSinglePoint)
	t.Run("生命週期：合法修剪過的鏈刪啟用後的點與修剪錨、事件：鏈頭接不上任何錨", lifeHeadAnchorDeleted)
	t.Run("升級：中段壞簽章、頭尾有效、無附證無事件：首個第四版點不是起點", lifeUpgradeMiddleBadSignature)
	for _, variant := range []string{"一般", "舊格式修剪錨", "升級前已斷鏈"} {
		v := variant
		t.Run("升級（"+v+"）：首個第四版點的起點判定與鏈接單一規則", func(t *testing.T) { lifeUpgrade(t, v) })
	}
	t.Run("標記竄改：各附證欄的結構層去向與權限維度", lifeTamperMarks)
	t.Run("只損壞一個附證", lifeSingleDamage)
	t.Run("事件竄改", lifeEventTamper)
	t.Run("升級混合鏈只改標第三版、不清欄：痕跡，無法判定", func(t *testing.T) {
		l := newLifeEnv(t)
		audit.SetPermissionSources(nil, nil)
		audit.SetSealSchemeForTest(l.svc, model.AggSchemeV3)
		l.genesis()
		audit.SetSealSchemeForTest(l.svc, "")
		newPermDBWire(t)
		l.seal()
		l.seal()
		require.NoError(t, l.db.Exec(`UPDATE audit_checkpoints SET agg_scheme = 'cp-agg-v3' WHERE seq >= 2`).Error)
		rep := l.row("只改標後")
		require.Equal(t, "unknown", rep.State)
		require.Contains(t, rep.Error, "第四版之前的檢查點帶附證欄 2 點")
	})
	t.Run("修剪記錄讀取失敗：TrimChain 本輪不剪、回錯，不當成沒有前錨", func(t *testing.T) {
		l := newLifeEnv(t)
		l.at(72 * time.Hour)
		l.genesis()
		l.seal()
		l.at(0)
		l.seal()
		failQuery(t, l.db, "audit_checkpoint_trims", func(string) bool { return true })
		n, tr, err := l.p.TrimChain(1)
		require.Error(t, err)
		require.Zero(t, n)
		require.Nil(t, tr)
		require.EqualValues(t, 3, l.count(t, "audit_checkpoints"), "檢查點全在")
	})
	t.Run("把重建啟用之點的起點旗標改成 true：簽章驗不過，無法判定", func(t *testing.T) {
		e, rec, open := trimmed(t, 3)
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_origin = true WHERE seq = 4`).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State)
		require.Contains(t, rep.Error, "第四版檢查點簽章驗不過 1 點", "旗標在簽章內，改掉即不可信")
		require.EqualValues(t, 1, open())
	})
}
