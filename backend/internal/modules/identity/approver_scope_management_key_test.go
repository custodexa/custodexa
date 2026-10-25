package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// approverKeyEnv 依 TEST_PG_DSN 選方言：非空時用獨立 schema 的 PostgreSQL 並印出 EVIDENCE，否則 SQLite。
func approverKeyEnv(t *testing.T) *roleDefEnv {
	t.Helper()
	dsn := os.Getenv("TEST_PG_DSN")
	if dsn == "" {
		e := newRoleDefEnv(t)
		require.NoError(t, e.db.AutoMigrate(&database.SchemaMigration{}))
		return e
	}
	schema := fmt.Sprintf("ask_%d", time.Now().UnixNano())
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if sd, e := admin.DB(); e == nil {
			_ = sd.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sd, e := db.DB(); e == nil {
			_ = sd.Close()
		}
	})
	require.Equal(t, "postgres", db.Dialector.Name(), "TEST_PG_DSN 非空時不得回退 SQLite")
	t.Logf("EVIDENCE dialect=%s", db.Dialector.Name())
	e := newRoleDefEnvOn(t, db)
	require.NoError(t, e.db.AutoMigrate(&database.SchemaMigration{}))
	return e
}

func approverKeyState(t *testing.T, e *roleDefEnv, roleID uint) (perms []string, defVer int64) {
	t.Helper()
	var r model.Role
	require.NoError(t, e.db.First(&r, roleID).Error)
	require.NoError(t, e.db.Model(&model.RolePermission{}).Where("role_id = ?", roleID).Order("permission_key").Pluck("permission_key", &perms).Error)
	return perms, r.DefinitionVersion
}

// TestApproverScopeManagementKeys 擋：申請人型管理鍵的屬性與依賴、路由閘只認審核範圍管理鍵、
// 補鍵資料步驟只替「有審核範圍管理鍵而無申請人型管理鍵」的自訂角色補鍵，且走角色定義寫入鏈
// （版本各推進一次、系統身分審計與狀態事件各一筆、重放等於現況）、失敗整筆回滾、重跑零寫入。
func TestApproverScopeManagementKeys(t *testing.T) {
	ctx := context.Background()
	K, KA := string(authz.PermApproverScopeManage), string(authz.PermApproverScopeApplicantManage)

	t.Run("目錄屬性與路由閘", func(t *testing.T) {
		def, ok := authz.LookupPermission(authz.PermApproverScopeApplicantManage)
		require.True(t, ok)
		assert.Equal(t, authz.ScopeGlobalOnly, def.Scope)
		assert.Equal(t, []authz.Permission{authz.PermApproverScopeManage}, authz.PermissionDependencies(authz.PermApproverScopeApplicantManage))
		// 只持申請人型管理鍵、不持審核範圍管理鍵者過不了任何審核範圍路由：三條路由的要求都是 K。
		n := 0
		for _, e := range authz.RegistryEntries() {
			if e.Path == "/api/v1/approver-scopes" || e.Path == "/api/v1/approver-scopes/:id" {
				n++
				assert.Equal(t, authz.PermApproverScopeManage, e.Perm, "%s %s", e.Method, e.Path)
			}
		}
		assert.Equal(t, 3, n)
		super := map[string]bool{}
		for _, k := range authz.TemplatePermissions("super_admin") {
			super[string(k)] = true
		}
		assert.True(t, super[K] && super[KA], "超級管理者兩鍵皆有")
		for _, k := range authz.ScopedTemplateAuthorizationAdminPermissions() {
			assert.NotEqual(t, authz.PermApproverScopeApplicantManage, k, "授權管理員集合不含申請人型管理鍵")
		}
	})

	t.Run("補鍵：寫入鏈原語、版本、審計、事件、重放", func(t *testing.T) {
		e := approverKeyEnv(t)
		hit := e.create(t, "has-k", K, "asset:view")
		both := e.create(t, "has-both", K, KA)
		none := e.create(t, "no-k", "asset:view")
		onlyKA := e.create(t, "only-ka", KA)
		sink := audit.NewTxSink()

		dry, err := BackfillApproverScopeManagementKey(ctx, e.db, sink, e.events, true)
		require.NoError(t, err)
		assert.Equal(t, ApproverScopeKeyReport{DryRun: true, Candidates: 1, RoleIDs: []uint{hit.ID}}, dry)
		_, _, v0, a0 := e.snapshot(t)
		ev0 := len(e.events.events)
		_, dv0 := approverKeyState(t, e, hit.ID)

		rep, err := BackfillApproverScopeManagementKey(ctx, e.db, sink, e.events, false)
		require.NoError(t, err)
		assert.Equal(t, 1, rep.Candidates)
		assert.Equal(t, 1, rep.Updated)
		assert.Equal(t, dry.RoleIDs, rep.RoleIDs, "dry-run 與正式報告的角色集合相同")

		perms, dv1 := approverKeyState(t, e, hit.ID)
		assert.Contains(t, perms, KA)
		assert.Contains(t, perms, K)
		assert.Equal(t, dv0+1, dv1, "定義版本恰推進一次")
		_, _, v1, a1 := e.snapshot(t)
		assert.Equal(t, v0+1, v1, "權限版本恰推進一次")
		assert.Equal(t, a0+1, a1, "恰一筆審計")
		require.Len(t, e.events.events, ev0+1, "恰一筆狀態事件")
		last := e.events.events[ev0]
		assert.Equal(t, hit.ID, last.RoleID)
		assert.Equal(t, v1, last.AuthzVersion)
		assert.Equal(t, dv1, last.DefinitionVersion)

		var row model.AuditLog
		require.NoError(t, e.db.Where("resource = ? AND resource_id = ?", string(model.ResourceRole), hit.ID).Order("id DESC").First(&row).Error)
		assert.Equal(t, model.ActionRoleDefinitionUpdate, row.Action)
		assert.Equal(t, uint(0), row.UserID)
		assert.Equal(t, "system", row.Username)
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(row.Details), &d))
		assert.Equal(t, ApproverScopeKeySystemStep, d["system_step"])
		assert.Equal(t, []any{KA}, d["added"])

		// 其他角色不動
		for _, id := range []uint{both.ID, none.ID, onlyKA.ID} {
			_, dv := approverKeyState(t, e, id)
			assert.EqualValues(t, 1, dv)
		}
		pn, _ := approverKeyState(t, e, none.ID)
		assert.NotContains(t, pn, KA)

		// 合法事件重放等於現況
		var evs []authz.RoleDefinitionStateEvent
		for _, ev := range e.events.events {
			evs = append(evs, authz.RoleDefinitionStateEvent{Action: ev.Action, RoleID: ev.RoleID, DefinitionVersion: ev.DefinitionVersion, Before: ev.Before, After: ev.After})
		}
		replayed, err := authz.ReplayRoleDefinitionEvents(evs)
		require.NoError(t, err)
		live, err := e.svc.State(ctx)
		require.NoError(t, err)
		assert.Empty(t, authz.DiffRoleDefinitionState(replayed, live))

		// 重跑：零寫入、不推進版本、不新增審計或事件；dry-run 與正式報告相同
		again, err := BackfillApproverScopeManagementKey(ctx, e.db, sink, e.events, false)
		require.NoError(t, err)
		againDry, err := BackfillApproverScopeManagementKey(ctx, e.db, sink, e.events, true)
		require.NoError(t, err)
		assert.Equal(t, 0, again.Candidates)
		assert.Equal(t, 0, again.Updated)
		assert.Equal(t, again.Candidates, againDry.Candidates)
		assert.Equal(t, again.RoleIDs, againDry.RoleIDs)
		_, _, v2, a2 := e.snapshot(t)
		assert.Equal(t, v1, v2)
		assert.Equal(t, a1, a2)
		assert.Len(t, e.events.events, ev0+1)
	})

	t.Run("只執行一次：撤掉的申請人型管理鍵不被補回", func(t *testing.T) {
		e := approverKeyEnv(t)
		hit := e.create(t, "has-k", K)
		sink := audit.NewTxSink()
		rep, err := BackfillApproverScopeManagementKey(ctx, e.db, sink, e.events, false)
		require.NoError(t, err)
		require.Equal(t, 1, rep.Updated)
		// 管理員經正常寫入路徑撤掉申請人型管理鍵、保留審核範圍管理鍵
		cur, err := e.svc.GetDefinition(ctx, hit.ID)
		require.NoError(t, err)
		_, err = e.svc.Update(ctx, e.admin, hit.ID, cur.DefinitionVersion, RoleInput{Name: "has-k", Permissions: []string{K}})
		require.NoError(t, err)
		_, _, v0, a0 := e.snapshot(t)
		ev0 := len(e.events.events)
		// 模擬重啟：正式與 dry-run 皆不挑候選、零寫入
		for _, dry := range []bool{false, true} {
			again, err := BackfillApproverScopeManagementKey(ctx, e.db, sink, e.events, dry)
			require.NoError(t, err)
			assert.True(t, again.AlreadyDone)
			assert.Equal(t, 0, again.Candidates)
			assert.Equal(t, 0, again.Updated)
		}
		perms, _ := approverKeyState(t, e, hit.ID)
		assert.NotContains(t, perms, KA, "撤掉的鍵仍是撤掉的狀態")
		_, _, v1, a1 := e.snapshot(t)
		assert.Equal(t, v0, v1)
		assert.Equal(t, a0, a1)
		assert.Len(t, e.events.events, ev0)
	})

	t.Run("審計或事件寫入失敗整筆回滾", func(t *testing.T) {
		for _, mode := range []string{"audit", "event"} {
			t.Run(mode, func(t *testing.T) {
				e := approverKeyEnv(t)
				a := e.create(t, "a", K)
				b := e.create(t, "b", K)
				r0, p0, v0, a0 := e.snapshot(t)
				ev0 := len(e.events.events)
				_, dvA := approverKeyState(t, e, a.ID)
				boom := errors.New("injected")
				var sink = audit.NewTxSink()
				events := RoleStateEventWriter(e.events)
				if mode == "audit" {
					_, err := BackfillApproverScopeManagementKey(ctx, e.db, failingSink{err: boom}, events, false)
					require.ErrorIs(t, err, boom)
				} else {
					e.events.fail = boom
					_, err := BackfillApproverScopeManagementKey(ctx, e.db, sink, events, false)
					require.ErrorIs(t, err, boom)
					e.events.fail = nil
				}
				r1, p1, v1, a1 := e.snapshot(t)
				assert.Equal(t, []int64{r0, p0, v0, a0}, []int64{r1, p1, v1, a1}, "角色集合、權限筆數、版本與審計皆不變")
				_, dvA1 := approverKeyState(t, e, a.ID)
				assert.Equal(t, dvA, dvA1)
				assert.Len(t, e.events.events, ev0)
				_ = b
			})
		}
	})

	t.Run("接線缺漏回錯而非靜默略過", func(t *testing.T) {
		e := approverKeyEnv(t)
		e.create(t, "a", K)
		_, err := BackfillApproverScopeManagementKey(ctx, e.db, nil, nil, false)
		require.Error(t, err)
		dry, err := BackfillApproverScopeManagementKey(ctx, e.db, nil, nil, true)
		require.NoError(t, err)
		assert.Equal(t, 1, dry.Candidates)
	})

	t.Run("目標解析矩陣", func(t *testing.T) {
		e := approverKeyEnv(t)
		require.NoError(t, migrateWithAuthz(e.db, &model.Asset{}, &model.AssetNode{}, &model.ApproverScope{}))
		node := func(name string, parent *uint) uint {
			g := model.AssetGroup{Name: name, ParentID: parent}
			require.NoError(t, e.db.Create(&g).Error)
			return g.ID
		}
		hostAsset := func(name string, nodes ...uint) uint {
			a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: "10.8.8.1", Port: 22}
			require.NoError(t, e.db.Create(&a).Error)
			for _, n := range nodes {
				require.NoError(t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: n}).Error)
			}
			return a.ID
		}
		prod := node("prod", nil)
		prodDB := node("db", &prod)
		prodDBA := node("a", &prodDB)
		sit := node("sit", nil)
		goneNode := node("gone", &prodDB)
		require.NoError(t, e.db.Delete(&model.AssetGroup{}, goneNode).Error)
		aIn := hostAsset("in-scope", prodDBA)
		aOut := hostAsset("out-of-scope", sit)
		aNone := hostAsset("ungrouped")

		user := func(name string) uint {
			u := model.User{Username: name, Password: "x", Active: true}
			require.NoError(t, e.db.Create(&u).Error)
			return u.ID
		}
		role := func(name string, perms ...string) uint {
			r := model.Role{Name: name, DefinitionVersion: 1}
			require.NoError(t, e.db.Create(&r).Error)
			for _, p := range perms {
				require.NoError(t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: p}).Error)
			}
			return r.ID
		}
		grantGlobal := func(uid, rid uint) {
			require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: rid, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		}
		grantNode := func(uid, rid, nid uint) {
			require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: rid, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
			require.NoError(t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: uid, RoleID: rid, NodeID: nid}).Error)
		}
		seed := func(s model.ApproverScope) uint {
			s.GrantedBy = e.admin
			require.NoError(t, e.db.Create(&s).Error)
			return s.ID
		}
		approver := user("approver-x")
		applicant := user("applicant-x")
		grp := model.UserGroup{Name: "applicant-group"}
		require.NoError(t, e.db.Create(&grp).Error)
		rowAssetIn := seed(model.ApproverScope{ApproverID: &approver, AssetID: &aIn})
		rowAssetOut := seed(model.ApproverScope{ApproverID: &approver, AssetID: &aOut})
		rowNodeRoot := seed(model.ApproverScope{ApproverID: &approver, AssetGroupID: &prodDB})
		rowNodeChild := seed(model.ApproverScope{ApproverID: &approver, AssetGroupID: &prodDBA})
		rowNodeOut := seed(model.ApproverScope{ApproverID: &approver, AssetGroupID: &sit})
		rowUser := seed(model.ApproverScope{ApproverID: &approver, SubjectUserID: &applicant})
		rowGroup := seed(model.ApproverScope{ApproverID: &approver, SubjectGroupID: &grp.ID})

		cat := authz.ProductCatalogue()
		ws := authz.NewApproverScopeWriteScope(authz.NewAuthorizationScopeEvaluator(cat, asset.NewScopeTopologyReader()))
		principalCtx := func(uid uint) context.Context {
			p, err := authz.ResolveUserOnWithCatalogue(e.db, cat, uid, authz.TokenFacts{})
			require.NoError(t, err)
			return authz.ContextWithPrincipal(ctx, p)
		}
		asset_ := func(id uint) authz.ApproverScopeSpec { return authz.ApproverScopeSpec{AssetID: &id} }
		node_ := func(id uint) authz.ApproverScopeSpec { return authz.ApproverScopeSpec{AssetGroupID: &id} }
		applicantSpec := authz.ApproverScopeSpec{SubjectUserID: &applicant}
		isScopeDenied := func(err error) bool { var d *authz.ErrScopeDenied; return errors.As(err, &d) }
		isCapability := func(err error) bool { var c *authz.ApproverScopeCapabilityError; return errors.As(err, &c) }

		nodeK := user("node-k")
		grantNode(nodeK, role("r-node-k", K), prodDB)
		nodeKglobalKA := user("node-k-global-ka")
		grantNode(nodeKglobalKA, role("r-node-k-2", K), prodDB)
		grantGlobal(nodeKglobalKA, role("r-global-ka", KA))
		globalK := user("global-k")
		grantGlobal(globalK, role("r-global-k", K))
		globalKKA := user("global-k-ka")
		grantGlobal(globalKKA, role("r-global-k-ka", K, KA))

		for _, uid := range []uint{nodeK, nodeKglobalKA} {
			c := principalCtx(uid)
			// 放行：資產掛在範圍內子節點；節點型為範圍根本身與子節點
			assert.NoError(t, ws.DecideCreate(c, e.db, asset_(aIn)), "範圍內資產")
			assert.NoError(t, ws.DecideCreate(c, e.db, node_(prodDB)), "範圍根節點")
			assert.NoError(t, ws.DecideCreate(c, e.db, node_(prodDBA)), "範圍內子節點")
			// 範圍拒絕：範圍外、未分組資產、已軟刪節點
			assert.True(t, isScopeDenied(ws.DecideCreate(c, e.db, asset_(aOut))), "範圍外資產")
			assert.True(t, isScopeDenied(ws.DecideCreate(c, e.db, asset_(aNone))), "未分組資產")
			assert.True(t, isScopeDenied(ws.DecideCreate(c, e.db, node_(sit))), "範圍外節點")
			assert.True(t, isScopeDenied(ws.DecideCreate(c, e.db, node_(goneNode))), "已軟刪節點")
			// 申請人型：節點範圍的審核範圍管理鍵一律拒絕，即使另有全域申請人型管理鍵
			assert.True(t, isCapability(ws.DecideCreate(c, e.db, applicantSpec)), "申請人型建立")
			// 既有列：資產型與節點型依客體，申請人型列一律範圍外
			for _, id := range []uint{rowAssetIn, rowNodeRoot, rowNodeChild} {
				assert.NoError(t, ws.DecideRow(c, e.db, id), "範圍內列 %d", id)
			}
			for _, id := range []uint{rowAssetOut, rowNodeOut, rowUser, rowGroup} {
				assert.True(t, isScopeDenied(ws.DecideRow(c, e.db, id)), "範圍外列 %d", id)
			}
		}

		// 全域指派：資產型、節點型、申請人型（用戶與群組列）皆放行；申請人型另需全域申請人型管理鍵
		for _, uid := range []uint{globalK, globalKKA} {
			c := principalCtx(uid)
			for _, spec := range []authz.ApproverScopeSpec{asset_(aIn), asset_(aOut), asset_(aNone), node_(prodDBA), node_(sit)} {
				assert.NoError(t, ws.DecideCreate(c, e.db, spec))
			}
			for _, id := range []uint{rowAssetIn, rowAssetOut, rowNodeRoot, rowNodeOut, rowUser, rowGroup} {
				assert.NoError(t, ws.DecideRow(c, e.db, id), "全域審核範圍管理鍵移除列 %d", id)
			}
		}
		c := principalCtx(globalKKA)
		assert.NoError(t, ws.DecideCreate(c, e.db, applicantSpec))
		for _, id := range []uint{rowUser, rowGroup} {
			assert.NoError(t, ws.DecideApplicantRow(c, e.db, id))
		}
		c = principalCtx(globalK)
		assert.True(t, isCapability(ws.DecideCreate(c, e.db, applicantSpec)), "只持全域審核範圍管理鍵不能建立申請人型")
		for _, id := range []uint{rowUser, rowGroup} {
			assert.ErrorIs(t, ws.DecideApplicantRow(c, e.db, id), authz.ErrScopeNotFound)
		}
	})
}
