package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type failingTxSink struct{}

func (failingTxSink) WriteInTx(*gorm.DB, port.AuditEvent) error { return errors.New("audit down") }

// 超管確認「無來源變動」——事件、審計列同交易；確認後告警結案、基準更新；
// 沒有可確認的差異或對帳無法判定時拒絕，審計寫不進去則整筆回滾。
func TestPermissionStateAccept(t *testing.T) {
	who := audit.PermissionAcceptActor{
		Actor:   gatewayapi.Actor{UserID: 1, Username: "root"},
		Request: gatewayapi.RequestMeta{Method: "POST", Path: "/api/v1/audit-failures/permission-state/accept", ClientIP: "192.0.2.9", StatusCode: 200},
	}
	// 一個已有「無來源變動」告警的環境：直寫一列＋隨後一次合法變更。
	setup := func(t *testing.T, sink port.TxSink) (*permEnv, *audit.PermissionAcceptService, *fakeFailureSink) {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		fs := &fakeFailureSink{}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetStateFailureSink(fs)
		rec.SetPermissionAttestSigner(e.signer)
		require.NoError(t, e.db.Exec(`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (2, 1, 'manual', 'global')`).Error)
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error { return authz.SetUserGroupRoles(tx, 1, []uint{1}, 1) }))
		require.Equal(t, "mismatch", rec.ReconcilePermission(context.Background()).State)
		require.Len(t, fs.permReports(), 1, "確認前有告警")
		require.Zero(t, fs.permResolved())
		return e, audit.NewPermissionAcceptService(e.db, sink, rec), fs
	}
	countKind := func(t *testing.T, e *permEnv, kind string) (n int64) {
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", kind).Count(&n).Error)
		return
	}

	t.Run("確認後告警結案、基準更新、審計列內容齊全", func(t *testing.T) {
		e, svc, fs := setup(t, audit.NewTxSink())
		res, err := svc.Accept(context.Background(), who, "  已查明是維運人員的緊急修復  ")
		require.NoError(t, err)
		require.NotEmpty(t, res.OpID)
		require.Positive(t, res.ExtraCount+res.MissingCount)

		// 事件：一筆 accept，接在鏈上。
		require.EqualValues(t, 1, countKind(t, e, model.PermEventAccept))
		// 告警結案、對帳相符。
		require.Equal(t, 1, fs.permResolved(), "確認後告警結案")
		require.Equal(t, "match", e.reconcile().State)

		// 審計列：動作、資源、確認人、來源位址、原因（去頭尾空白）、差集摘要、事件序號。
		var rows []model.AuditLog
		require.NoError(t, e.db.Where("action = ?", model.ActionPermissionStateAccepted).Find(&rows).Error)
		require.Len(t, rows, 1)
		row := rows[0]
		require.Equal(t, model.ResourceAuditFailure, row.Resource)
		require.EqualValues(t, 1, row.UserID)
		require.Equal(t, "root", row.Username)
		require.Equal(t, "192.0.2.9", row.ClientIP)
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(row.Details), &d))
		require.Equal(t, "已查明是維運人員的緊急修復", d["reason"])
		require.Equal(t, res.OpID, d["op_id"])
		require.EqualValues(t, res.EventSeq, d["event_seq"])
		require.EqualValues(t, res.ExtraCount, d["extra_count"])
		require.EqualValues(t, res.MissingCount, d["missing_count"])
		require.NotEmpty(t, d["extra"], "差集摘要含具型別 ID")
		for _, k := range []string{"password", "email", "token"} {
			require.NotContains(t, strings.ToLower(row.Details), k, "差集摘要不含個資或秘密")
		}

		// 新基準：下一次封章的附證以確認後的狀態為準（reconciled=true），其後的直寫仍會被偵測。
		cp, err := e.svc.SealNow()
		require.NoError(t, err)
		require.NotNil(t, cp.PermReconciled)
		require.True(t, isTrue(cp.PermReconciled))
		require.NoError(t, e.db.Exec(`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (1, 2, 'manual', 'global')`).Error)
		require.Equal(t, "mismatch", e.reconcile().State, "確認只涵蓋當下，之後的新直寫照樣偵測")

		// 再確認一次也可以：第二筆 accept，鏈仍可重放。
		_, err = svc.Accept(context.Background(), who, "第二次")
		require.NoError(t, err)
		require.Equal(t, "match", e.reconcile().State)
	})

	t.Run("原因缺少、過長或含控制字元被拒，不寫任何東西", func(t *testing.T) {
		e, svc, _ := setup(t, audit.NewTxSink())
		for _, bad := range []string{"", "   ", strings.Repeat("字", audit.PermissionAcceptReasonMaxRunes+1), "a\x00b", "a\nb"} {
			_, err := svc.Accept(context.Background(), who, bad)
			require.ErrorIs(t, err, audit.ErrPermissionAcceptReason, "%q", bad)
		}
		require.Zero(t, countKind(t, e, model.PermEventAccept))
		var n int64
		require.NoError(t, e.db.Model(&model.AuditLog{}).Where("action = ?", model.ActionPermissionStateAccepted).Count(&n).Error)
		require.Zero(t, n)
		_, err := svc.Accept(context.Background(), who, strings.Repeat("字", audit.PermissionAcceptReasonMaxRunes))
		require.NoError(t, err, "恰好上限可通過")
	})

	t.Run("沒有可確認的差異時拒絕且不留任何東西", func(t *testing.T) {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetPermissionAttestSigner(e.signer)
		svc := audit.NewPermissionAcceptService(e.db, audit.NewTxSink(), rec)
		_, err := svc.Accept(context.Background(), who, "沒事")
		var na *audit.PermissionNotAcceptableError
		require.ErrorAs(t, err, &na)
		require.Equal(t, "match", na.State)
		require.Zero(t, countKind(t, e, model.PermEventAccept))
	})

	t.Run("事件鏈被破壞時改為重設基準：寫審計記原因與狀態，不修補被破壞的列", func(t *testing.T) {
		e, svc, _ := setup(t, audit.NewTxSink())
		require.NoError(t, e.db.Exec(`UPDATE permission_state_events SET delta = '{}' WHERE kind = 'untraced'`).Error)
		require.Equal(t, "unknown", e.reconcile().State)
		_, err := svc.Accept(context.Background(), who, "已查明事件列被誤改")
		require.NoError(t, err)
		require.EqualValues(t, 1, countKind(t, e, model.PermEventAccept))
		var row model.AuditLog
		require.NoError(t, e.db.Where("action = ?", model.ActionPermissionStateAccepted).First(&row).Error)
		require.Contains(t, row.Details, `"mode":"rebase"`)
		var broken int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = 'untraced' AND delta = '{}'").Count(&broken).Error)
		require.EqualValues(t, 1, broken, "被破壞的列原樣保留")
		require.Equal(t, "match", e.reconcile().State)
	})

	t.Run("審計寫不進去則確認整筆回滾，告警仍在", func(t *testing.T) {
		e, svc, fs := setup(t, failingTxSink{})
		_, err := svc.Accept(context.Background(), who, "原因")
		require.Error(t, err)
		require.Zero(t, countKind(t, e, model.PermEventAccept), "事件隨交易回滾")
		require.Zero(t, fs.permResolved())
		require.Equal(t, "mismatch", e.reconcile().State)
		_, err = audit.NewPermissionAcceptService(e.db, nil, audit.NewRoleStateReconciler(e.db, nil)).Accept(context.Background(), who, "原因")
		require.Error(t, err, "未注入審計落地面同樣 fail-close")
	})

	// 已有高事件序號的相符附證，之後事件表被全刪：重設從序號 1 重起。先後以重設寫入當下的
	// 檢查點序號判定（在驗證碼內），不比可能歸零的事件序號；重設確實生效才回成功。
	t.Run("全刪事件後重設：以檢查點序號定先後、確實生效、之後合法變更相符、直寫照常偵測", func(t *testing.T) {
		ctx := context.Background()
		e := newPermEnv(t)
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
		high, err := e.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isTrue(high.PermReconciled))
		require.Greater(t, *high.PermEventSeq, int64(1), "附證釘住較高的事件序號")
		require.NoError(t, e.db.Exec(`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (2, 1, 'manual', 'global')`).Error)
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		rep := rec.ReconcilePermission(ctx)
		require.Equal(t, "unknown", rep.State, "附證錨定的事件不在了")
		require.Len(t, fs.permReports(), 1)

		svc := audit.NewPermissionAcceptService(e.db, audit.NewTxSink(), rec)
		res, err := svc.Accept(ctx, who, "事件表遭清空，已與維運核對現況")
		require.NoError(t, err)
		require.EqualValues(t, 1, res.EventSeq, "事件序號自 1 重起")
		require.NotNil(t, res.ReferenceCpSeq)
		require.Equal(t, high.Seq, *res.ReferenceCpSeq, "參考點為最後相符的附證")
		require.Contains(t, res.Extra, `[2,"user_roles"]`, "被接受的直寫留在回應上")
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State, "重設確實被採用")
		require.Equal(t, 1, fs.permResolved(), "告警結案")

		var row model.AuditLog
		require.NoError(t, e.db.Where("action = ?", model.ActionPermissionStateAccepted).First(&row).Error)
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(row.Details), &d))
		require.Equal(t, "rebase", d["mode"])
		require.EqualValues(t, high.Seq, d["after_cp_seq"])
		require.EqualValues(t, high.Seq, d["reference_cp_seq"])
		require.EqualValues(t, res.ExtraCount, d["extra_count"])
		require.Positive(t, res.ExtraCount)

		require.NoError(t, e.change(t, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
		}))
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State, "重設之後的合法變更不誤報")
		require.NoError(t, e.db.Exec(`UPDATE group_role_mappings SET role_id = 1`).Error)
		require.Equal(t, "mismatch", rec.ReconcilePermission(ctx).State, "重設之後的直寫照常偵測")
	})
}
