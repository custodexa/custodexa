package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestRoleDefinitionStateCompatibility 擋：自訂角色集合／定義版本／相容目錄改變卻不改摘要、
// 四種合法事件重放不等於現況、直改集合沒被對帳指出、名稱說明進快照、
// 還原核對把無效內容當空集合放行。舊格式（版本 1）的解碼與驗章相容在 role_definition_state_format_test.go。
func TestRoleDefinitionStateCompatibility(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*permEnv, *identity.RoleDefinitionService) {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis()) // 啟用界標：接線後的第一個封章
		svc := identity.NewRoleDefinitionService(e.db, audit.NewTxSink(), identity.NewPermissionChainEventWriter(),
			identity.NewGrantGrader(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))
		return e, svc
	}
	digest := func(t *testing.T, e *permEnv) string {
		t.Helper()
		var d string
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			st, err := audit.ReadPermissionState(ctx, tx)
			if err != nil {
				return err
			}
			d, err = st.Digest()
			return err
		}))
		return d
	}
	const admin = uint(1) // seedPerm 的 u-admin 持有內建超管角色

	t.Run("摘要隨自訂集合、定義版本、相容目錄改變，不隨名稱說明改變", func(t *testing.T) {
		e, svc := setup(t)
		d0 := digest(t, e)
		r, err := svc.Create(ctx, admin, identity.RoleInput{Name: "viewer", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		d1 := digest(t, e)
		require.NotEqual(t, d0, d1, "新增自訂角色")
		_, err = svc.Update(ctx, admin, r.ID, 1, identity.RoleInput{Name: "viewer", Permissions: []string{"asset:view", "session:view"}})
		require.NoError(t, err)
		d2 := digest(t, e)
		require.NotEqual(t, d1, d2, "集合與定義版本改變")
		// 版本還原成同值、集合不變、只改名稱說明：摘要不變
		require.NoError(t, e.db.Model(&model.Role{}).Where("id = ?", r.ID).
			Updates(map[string]any{"name": "other-name", "description": "other text"}).Error)
		require.Equal(t, d2, digest(t, e), "名稱與說明不進快照")
		legacy := model.Role{Name: "legacy-x"}
		require.NoError(t, e.db.Create(&legacy).Error)
		d3 := digest(t, e)
		require.NotEqual(t, d2, d3, "相容目錄（版本 0）角色出現")
		require.NoError(t, e.db.Model(&model.Role{}).Where("id = ?", legacy.ID).Update("definition_version", 5).Error)
		require.NotEqual(t, d3, digest(t, e), "定義版本改變")
	})

	t.Run("四種 mutation 各寫事件、重放等於現況；直改集合被對帳指出", func(t *testing.T) {
		e, svc := setup(t)
		require.Equal(t, "match", e.reconcile().State)
		var n0 int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Count(&n0).Error)
		a, err := svc.Create(ctx, admin, identity.RoleInput{Name: "a", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		cp, err := svc.Copy(ctx, admin, a.ID, "b", "")
		require.NoError(t, err)
		_, err = svc.Update(ctx, admin, a.ID, 1, identity.RoleInput{Name: "a", Permissions: []string{"asset:view", "session:view"}})
		require.NoError(t, err)
		require.NoError(t, svc.Delete(ctx, admin, cp.ID, 1))
		var n1 int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Count(&n1).Error)
		require.EqualValues(t, 4, n1-n0, "四種 mutation 各一筆事件（無額外的無來源變動事件）")
		var untraced int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventUntraced).Count(&untraced).Error)
		require.Zero(t, untraced)
		rep := e.reconcile()
		require.Equal(t, "match", rep.State, rep.Error)
		// 直改集合：沒有事件、版本不動
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: a.ID, PermissionKey: "audit:view"}).Error)
		rep = e.reconcile()
		require.Equal(t, "mismatch", rep.State)
		require.Contains(t, strings.Join(rep.Extra, ","), `"role_perms"`)
	})

	t.Run("快照不含角色名稱、說明或自由文字", func(t *testing.T) {
		e, svc := setup(t)
		_, err := svc.Create(ctx, admin, identity.RoleInput{Name: "secret-looking-name", Description: "free text here", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		var body string
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			st, err := audit.ReadPermissionState(ctx, tx)
			if err != nil {
				return err
			}
			b, err := st.Encode()
			body = string(b)
			return err
		}))
		require.NotContains(t, body, "secret-looking-name")
		require.NotContains(t, body, "free text here")
		require.Contains(t, body, `"role_perms":[[`)
	})

	t.Run("事件鏈寫入失敗時角色內容與兩個版本整筆回滾", func(t *testing.T) {
		e, svc := setup(t)
		a, err := svc.Create(ctx, admin, identity.RoleInput{Name: "a", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		count := func() []int64 {
			var roles, perms, ver, evs int64
			require.NoError(t, e.db.Unscoped().Model(&model.Role{}).Count(&roles).Error)
			require.NoError(t, e.db.Model(&model.RolePermission{}).Count(&perms).Error)
			require.NoError(t, e.db.Raw("SELECT version FROM authz_state WHERE id = 1").Scan(&ver).Error)
			require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Count(&evs).Error)
			return []int64{roles, perms, ver, evs}
		}
		before := count()
		require.NoError(t, e.db.Callback().Create().Before("gorm:create").Register("fail_perm_event", func(tx *gorm.DB) {
			if tx.Statement.Schema != nil && tx.Statement.Schema.Table == "permission_state_events" {
				_ = tx.AddError(errors.New("event down"))
			}
		}))
		_, err = svc.Create(ctx, admin, identity.RoleInput{Name: "y", Permissions: []string{"asset:view"}})
		require.ErrorContains(t, err, "event down")
		_, err = svc.Update(ctx, admin, a.ID, 1, identity.RoleInput{Name: "a", Permissions: []string{}})
		require.ErrorContains(t, err, "event down")
		require.ErrorContains(t, svc.Delete(ctx, admin, a.ID, 1), "event down")
		require.Equal(t, before, count(), "角色內容、定義版本、全域版本與事件鏈全回滾")
	})

	t.Run("舊格式（版本 1）快照與封章仍可解碼、驗章與對帳，新事件不誤報無來源變動", func(t *testing.T) {
		e, svc := setup(t)
		var cur *audit.PermissionState
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			var err error
			cur, err = audit.ReadPermissionState(ctx, tx)
			return err
		}))
		old := cur.ProjectTo(audit.PermissionStateFormatV1)
		oldBody, err := old.Encode()
		require.NoError(t, err)
		require.NotContains(t, string(oldBody), "role_defs")
		dec, err := audit.DecodePermissionState(oldBody)
		require.NoError(t, err)
		require.Equal(t, audit.PermissionStateFormatV1, dec.Meta.FormatVersion)
		again, err := dec.Encode()
		require.NoError(t, err)
		require.Equal(t, string(oldBody), string(again), "舊格式 canonical 編碼逐位元組不變")

		// 把啟用封章換成舊格式快照並重簽：舊封章仍可驗，對帳在舊格式下比較而不誤判
		var cp model.AuditCheckpoint
		require.NoError(t, e.db.Order("seq ASC").First(&cp).Error)
		require.NotNil(t, cp.PermStateSnapshot)
		snap, format := string(oldBody), audit.PermissionStateFormatV1
		cp.PermStateSnapshot, cp.PermFormat = &snap, &format
		// 事件鏈也換成舊格式：升級前寫入的啟用事件，鏈頭快照是版本 1
		require.NoError(t, e.db.Exec(`DELETE FROM permission_state_events`).Error)
		var head *model.PermissionStateEvent
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			var err error
			head, err = audit.EnsurePermissionActivation(ctx, tx, old, int64(cp.Seq))
			return err
		}))
		require.Contains(t, head.AfterBody, `"v":1,`)
		cp.PermEventSeq, cp.PermEventHead = &head.Seq, &head.Digest
		// 附證在檢查點簽章之內：換成舊格式快照後以同一把鑰重簽整個檢查點
		payload, err := audit.CheckpointSignBytes(&cp)
		require.NoError(t, err)
		_, sig := e.signer.Sign(payload)
		cp.Signature = sig
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_state_snapshot = ?, perm_format = ?, perm_event_seq = ?, perm_event_head = ?, signature = ? WHERE seq = ?`,
			snap, format, head.Seq, head.Digest, sig, cp.Seq).Error) // 不可變證據表只能以原生 SQL 換成舊格式夾具
		require.Equal(t, audit.PermAttestValid, audit.VerifyPermissionAttestation(e.db, &cp, e.signer).State, "舊格式附證可驗")
		require.Equal(t, "match", e.reconcile().State, "舊基準、無後續事件：舊格式下相符")

		// 附證欄與快照內記載的格式不一致、未知格式一律不可驗
		v99 := 99
		bad := cp
		bad.PermFormat = &v99
		_, err = audit.CheckpointSignBytes(&bad)
		require.ErrorIs(t, err, audit.ErrCheckpointPayloadInvalid)
		v2 := audit.PermissionStateFormatVersion
		bad = cp
		bad.PermFormat = &v2
		_, err = audit.CheckpointSignBytes(&bad)
		require.ErrorIs(t, err, audit.ErrCheckpointPayloadInvalid, "舊快照不得改標新格式")

		// 之後的角色定義寫入：鏈頭仍是舊格式，不誤記無來源變動，且舊基準加新事件重放後與現況相符
		_, err = svc.Create(ctx, admin, identity.RoleInput{Name: "late", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		var untraced int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventUntraced).Count(&untraced).Error)
		require.Zero(t, untraced)
		rep := e.reconcile()
		require.Equal(t, "match", rep.State, rep.Error)
	})

	t.Run("種入兩個範圍化範本後：種入事件重放為現況、直改範本集合被對帳與還原核對指出、兩列保留", func(t *testing.T) {
		e, _ := setup(t)
		require.NoError(t, e.db.AutoMigrate(&model.LDAPDirectory{}, &model.OIDCProvider{}))
		require.Equal(t, "match", e.reconcile().State)
		seed, err := identity.SeedScopedTemplates(ctx, e.db, false)
		require.NoError(t, err)
		require.True(t, seed.Applied)
		rep := e.reconcile()
		require.Equal(t, "match", rep.State, rep.Error)
		var untraced int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventUntraced).Count(&untraced).Error)
		require.Zero(t, untraced, "合法種入事件之外沒有無來源變動")
		findings := func() map[string]int {
			r, err := authz.CheckRestoreIntegrity(e.db, identity.CountLocalAdmins, identity.RestoreMappingRefChecks())
			require.NoError(t, err)
			out := map[string]int{}
			for _, f := range r.Findings {
				out[f.Code]++
			}
			return out
		}
		require.Zero(t, findings()["role_permissions_on_locked_role"], "還原核對對種入後的兩列沒有發現")
		var tpl model.Role
		require.NoError(t, e.db.Where("builtin_key = ?", model.BuiltinAssetAdmin).First(&tpl).Error)
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: tpl.ID, PermissionKey: "audit:view"}).Error)
		rep = e.reconcile()
		require.Equal(t, "mismatch", rep.State)
		require.Contains(t, strings.Join(rep.Extra, ","), `"role_perms"`)
		require.Equal(t, 1, findings()["role_permissions_on_locked_role"])
		var n int64
		require.NoError(t, e.db.Model(&model.Role{}).Where("builtin_key IN ?", []string{model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin}).Count(&n).Error)
		require.EqualValues(t, 2, n, "兩列保留")
	})

	t.Run("還原核對拒絕無效角色定義，不當成空集合", func(t *testing.T) {
		e, svc := setup(t)
		require.NoError(t, e.db.AutoMigrate(&model.LDAPDirectory{}, &model.OIDCProvider{}))
		r, err := svc.Create(ctx, admin, identity.RoleInput{Name: "a", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		findings := func() map[string]int {
			rep, err := authz.CheckRestoreIntegrity(e.db, identity.CountLocalAdmins, identity.RestoreMappingRefChecks())
			require.NoError(t, err)
			out := map[string]int{}
			for _, f := range rep.Findings {
				out[f.Code]++
			}
			return out
		}
		codes := []string{"dangling_role_permission_role", "unknown_role_permission_key", "non_assignable_role_permission_key",
			"dangling_role_template_source", "invalid_role_definition_version", "role_permissions_on_locked_role"}
		clean := findings()
		for _, c := range codes {
			require.Zero(t, clean[c], "有效角色定義不產生 %s", c)
		}
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: "nope:key"}).Error)
		require.Equal(t, 1, findings()["unknown_role_permission_key"])
		// 目錄內但超管保留、不可指派的鍵：與 ValidateRoleDefinitionState 同一判準，不當成合法鍵放過
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(authz.PermHostKeyReset)}).Error)
		require.Equal(t, 1, findings()["non_assignable_role_permission_key"])
		require.Equal(t, 1, findings()["unknown_role_permission_key"], "保留鍵另立發現碼，不混進未知鍵")
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: 98765, PermissionKey: "asset:view"}).Error)
		require.Equal(t, 1, findings()["dangling_role_permission_role"])
		require.NoError(t, e.db.Exec("UPDATE roles SET template_role_id = 98765 WHERE id = ?", r.ID).Error)
		require.Equal(t, 1, findings()["dangling_role_template_source"])
		require.NoError(t, e.db.Exec("UPDATE roles SET definition_version = -1 WHERE id = ?", r.ID).Error)
		require.Equal(t, 1, findings()["invalid_role_definition_version"])
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: 1, PermissionKey: "asset:view"}).Error) // 內建超管角色
		require.Equal(t, 1, findings()["role_permissions_on_locked_role"])
	})
}
