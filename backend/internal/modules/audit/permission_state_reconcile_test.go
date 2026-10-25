package audit_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// ed25519 假簽章鑰（測試用，單一版本 1）。
type permFakeSigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newPermSigner(t *testing.T) *permFakeSigner {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &permFakeSigner{pub: pub, priv: priv}
}
func (s *permFakeSigner) ActiveVersion() int { return 1 }
func (s *permFakeSigner) Sign(data []byte) (int, string) {
	return 1, base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, data))
}
func (s *permFakeSigner) Verify(version int, data []byte, sig string) (bool, error) {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false, nil
	}
	return version == 1 && ed25519.Verify(s.pub, data, raw), nil
}

type permEnv struct {
	db     *gorm.DB
	signer *permFakeSigner
	svc    *audit.CheckpointService
}

// newPermEnv 建出可封章的環境：基礎三項來源與權限來源皆注入，完整性基準存在。
func newPermEnv(t *testing.T) *permEnv {
	t.Helper()
	db := newPermDB(t)
	require.NoError(t, db.AutoMigrate(&model.AuditLog{}, &model.IntegrityBaseline{}, &model.AgentToolCall{}, &model.AgentToken{}))
	require.NoError(t, db.Create(&model.IntegrityBaseline{ID: 1, BaselineAt: time.Now().UTC(), MaxLogID: 0}).Error)
	audit.SetUserRolesSource(identity.SnapshotUserRolePairs)
	audit.SetPrincipalSource(identity.SnapshotPrincipalStates)
	audit.SetAgentTokenSource(identity.SnapshotAgentTokenStates)
	signer := newPermSigner(t)
	return &permEnv{db: db, signer: signer, svc: audit.NewCheckpointService(db, signer, nil, nil)}
}

// change 模擬一條權限寫入路徑：同交易內寫資料並推進版本（與事件）。
func (e *permEnv) change(t *testing.T, write func(tx *gorm.DB) error) error {
	t.Helper()
	return e.db.Transaction(func(tx *gorm.DB) error {
		if err := write(tx); err != nil {
			return err
		}
		return authz.AdvanceVersion(tx)
	})
}

func (e *permEnv) reconcile() audit.PermissionReport {
	return audit.ReconcilePermissionState(context.Background(), e.db, e.signer)
}

func (e *permEnv) count(t *testing.T, table string) int64 {
	var n int64
	require.NoError(t, e.db.Table(table).Count(&n).Error)
	return n
}

func TestPermissionStateReconcile(t *testing.T) {
	setup := func(t *testing.T) *permEnv {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		return e
	}

	t.Run("啟用後立即相符，附證可驗", func(t *testing.T) {
		e := setup(t)
		rep := e.reconcile()
		require.Equal(t, "match", rep.State, rep.Error)
		var cp model.AuditCheckpoint
		require.NoError(t, e.db.First(&cp, "seq = 1").Error)
		require.NotNil(t, cp.PermStateSnapshot)
		require.True(t, isTrue(cp.PermOrigin), "全新安裝的 genesis 是起點")
		require.Nil(t, cp.PermReconciled, "起點沒有前一個基準可比")
		require.Equal(t, audit.PermAttestValid, audit.VerifyPermissionAttestation(e.db, &cp, e.signer).State)
		require.EqualValues(t, 1, e.count(t, "permission_state_events"), "只有啟用事件")
	})

	// 各種合法寫入路徑（各寫入點的代表：直接指派、群組指派、群組成員、映射規則、主體）。
	// 其餘寫入點的逐條重放另行驗證。
	paths := map[string]func(tx *gorm.DB) error{
		"直接指派追加": func(tx *gorm.DB) error {
			return tx.Create(&model.UserRole{UserID: 2, RoleID: 1, Source: "manual", ScopeKind: "global"}).Error
		},
		"直接指派來源 mapped→both": func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE user_roles SET source = 'both' WHERE user_id = 2`).Error
		},
		"群組指派替換": func(tx *gorm.DB) error { return authz.SetUserGroupRoles(tx, 1, []uint{1}, 1) },
		"群組指派移除": func(tx *gorm.DB) error { return authz.RemoveUserGroupRole(tx, 1, 2) },
		"群組成員加入": func(tx *gorm.DB) error {
			return tx.Create(&model.UserGroupMember{UserGroupID: 1, UserID: 1, Manual: true}).Error
		},
		"映射規則停用": func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE group_role_mappings SET enabled = 0`).Error
		},
		"主體停用": func(tx *gorm.DB) error { return tx.Exec(`UPDATE users SET active = 0 WHERE id = 2`).Error },
	}
	for name, write := range paths {
		t.Run("合法變更可重放為相符/"+name, func(t *testing.T) {
			e := setup(t)
			logsBefore := e.count(t, "audit_logs")
			require.NoError(t, e.change(t, write))
			// 路徑 群組指派替換／移除 內已自行推進版本，change 又推進一次：兩者皆為合法事件
			rep := e.reconcile()
			require.Equal(t, "match", rep.State, rep.Error)
			require.Equal(t, logsBefore, e.count(t, "audit_logs"), "既有 audit_logs 不因新維度增減")
			// 再封章一次：新附證成為基準，仍相符
			_, err := e.svc.SealNow()
			require.NoError(t, err)
			require.Equal(t, "match", e.reconcile().State)
		})
	}

	t.Run("事件寫入失敗使狀態與版本一併回滾", func(t *testing.T) {
		e := setup(t)
		v0, err := authz.CurrentVersion(e.db)
		require.NoError(t, err)
		require.NoError(t, e.db.Exec(`CREATE TRIGGER fail_event_insert BEFORE INSERT ON permission_state_events BEGIN SELECT RAISE(ABORT, 'injected event failure'); END`).Error)
		err = e.change(t, func(tx *gorm.DB) error {
			return tx.Create(&model.UserRole{UserID: 2, RoleID: 1, Source: "manual", ScopeKind: "global"}).Error
		})
		require.Error(t, err)
		v1, _ := authz.CurrentVersion(e.db)
		require.Equal(t, v0, v1)
		require.EqualValues(t, 0, e.count(t, "user_roles")-2, "追加的指派已回滾")
	})

	t.Run("唯讀不產生事件", func(t *testing.T) {
		e := setup(t)
		before := e.count(t, "permission_state_events")
		_, err := audit.ReadPermissionState(context.Background(), e.db)
		require.NoError(t, err)
		_ = e.reconcile()
		_, _ = authz.CurrentVersion(e.db)
		require.Equal(t, before, e.count(t, "permission_state_events"))
	})

	tampers := map[string]string{
		"角色內容（內建身分被改）":     `UPDATE roles SET builtin_key = 'user' WHERE id = 2`,
		"直接 binding（掛上超管）": `INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (2, 1, 'manual', 'global')`,
		"映射來源（換目標角色）":      `UPDATE group_role_mappings SET role_id = 1`,
		"節點集合":             `INSERT INTO role_binding_nodes (subject_kind, subject_id, role_id, node_id) VALUES ('user', 2, 2, 7)`,
	}
	for name, stmt := range tampers {
		t.Run("直接改庫被指出/"+name, func(t *testing.T) {
			e := setup(t)
			require.NoError(t, e.db.Exec(stmt).Error)
			rep := e.reconcile()
			require.Equal(t, "mismatch", rep.State)
			require.True(t, len(rep.Missing)+len(rep.Extra) > 0, "差集要帶具型別 ID")
		})
	}

	t.Run("不符後再次封章不洗成相符", func(t *testing.T) {
		e := setup(t)
		require.NoError(t, e.db.Exec(`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (2, 1, 'manual', 'global')`).Error)
		require.Equal(t, "mismatch", e.reconcile().State)
		cp, err := e.svc.SealNow()
		require.NoError(t, err)
		require.NotNil(t, cp.PermReconciled)
		require.True(t, isFalse(cp.PermReconciled), "封章如實記下不符")
		require.Equal(t, "mismatch", e.reconcile().State, "不符附證不成為新基準")
	})

	t.Run("缺事件或斷鏈為未知", func(t *testing.T) {
		for name, tamper := range map[string]string{
			"缺中段事件": `DELETE FROM permission_state_events WHERE seq = 2`,
			"摘要被改":  `UPDATE permission_state_events SET digest = 'deadbeef' WHERE seq = 3`,
			"差集被改":  `UPDATE permission_state_events SET delta = '{"meta":{}}' WHERE seq = 3`,
		} {
			e := setup(t)
			for i := 0; i < 3; i++ {
				require.NoError(t, e.change(t, func(tx *gorm.DB) error {
					return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
				}))
			}
			require.NoError(t, e.db.Exec(tamper).Error)
			rep := e.reconcile()
			require.Equal(t, "unknown", rep.State, name)
			require.NotEmpty(t, rep.Error, name)
		}
	})

	t.Run("事件鏈與版本連續", func(t *testing.T) {
		e := setup(t)
		for i := 0; i < 3; i++ {
			require.NoError(t, e.change(t, func(tx *gorm.DB) error { return nil }))
		}
		var seqs []int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Order("seq").Pluck("seq", &seqs).Error)
		require.Equal(t, []int64{1, 2, 3, 4}, seqs)
	})
}
