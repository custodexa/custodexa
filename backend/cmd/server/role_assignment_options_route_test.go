package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 指派選項路由的測試來源替身：回固定結果或固定錯誤。
type optionsNodeSource struct{ err error }

func (s optionsNodeSource) AssignmentNodes() ([]asset.AssignmentNode, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []asset.AssignmentNode{{ID: 1, Name: "n", Depth: 1, Path: "n", SubtreeAssetCount: 1}}, nil
}

type optionsRoleSource struct{ err error }

func (s optionsRoleSource) List() ([]identity.RoleNodeScopabilityEntry, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []identity.RoleNodeScopabilityEntry{{RoleID: 1, Class: authz.NodeScopabilityEffective}}, nil
}

// TestRoleAssignmentOptionsRoute 擋：指派選項路由登錄為指派角色權限點；只持該權限點的身分管理員
// 取得全部未刪除節點與台數且與超管逐欄相同；回應不含任何資產資料；不持該權限點者被拒；
// 可限定節點的角色清單與寫入關卡的判定逐一相符；呼叫是唯讀的；節點清單的查詢次數不隨節點數成長；
// 來源未接線時回內部錯誤、不回部分資料。
func TestRoleAssignmentOptionsRoute(t *testing.T) {
	const path = "/api/v1/role-assignment-options"
	e, ok := authz.LookupRoute("GET", path)
	require.True(t, ok, "GET %s 未登錄", path)
	assert.Equal(t, authz.BasePerm, e.Base)
	assert.Equal(t, authz.PermRoleAssign, e.Perm)

	env := newBaselineEnv(t)
	inventory := false
	for _, r := range env.engine().Routes() {
		if r.Method == "GET" && r.Path == path {
			inventory = true
		}
	}
	assert.True(t, inventory, "路由清冊沒有 GET %s", path)
	require.NotNil(t, env.graph.deps.roleAssignmentOptions, "正式組裝必須建出 handler")

	f := newPreviewFixture(t, env)
	w := &contractWorld{t: t, f: f, env: env}

	addSubject := func(id string, uid uint) {
		env.subjects[id] = &baselineSubject{ID: id, Username: id, UserID: uid, Kind: "session", Token: env.issueSessionToken(uid)}
	}
	// 只持身分管理員範本的身分管理員：有指派角色權限點，沒有任何資產權限與連線授權。
	ida := env.createUser("opt-ida", nil)
	k := model.BuiltinIdentityAdmin
	var idRole model.Role
	if err := env.db.Where("name = ?", "identity_admin").First(&idRole).Error; err != nil {
		idRole = model.Role{Name: "identity_admin", BuiltinKey: &k, DefinitionVersion: 1}
		require.NoError(t, env.db.Create(&idRole).Error)
	}
	require.NoError(t, model.AssignUserRoleWithSource(env.db, ida, idRole.ID, model.RoleSourceManual, model.RoleOriginSystem))
	addSubject("IDA", ida)
	idaPrincipal, err := authz.NewResolver(env.db).ResolveUser(ida, authz.TokenFacts{})
	require.NoError(t, err)
	require.True(t, idaPrincipal.Has(authz.PermRoleAssign))
	for _, p := range []authz.Permission{authz.PermAssetView, authz.PermAssetUpdate} {
		require.False(t, idaPrincipal.Has(p), "身分管理員不得持有 %s", p)
	}
	var grants int64
	require.NoError(t, env.db.Model(&model.AssetAuthorization{}).Where("user_id = ?", ida).Count(&grants).Error)
	require.EqualValues(t, 0, grants)

	// 節點：父 P、子 C、已刪除的子 D。資產：X 同掛 P 與 C，Y 掛 C，Z 掛 P，W 只掛 D。
	mkNode := func(name string, parent *uint) uint {
		g := model.AssetGroup{Name: name, ParentID: parent}
		require.NoError(t, env.db.Create(&g).Error)
		return g.ID
	}
	var assetNames, assetHosts []string
	mkAsset := func(tag string, nodes ...uint) {
		a := model.Asset{Name: "zz-opt-asset-" + tag, Protocol: model.ProtocolSSH, Host: "zz-opt-host-" + tag + ".example", Port: 22}
		require.NoError(t, env.db.Create(&a).Error)
		assetNames, assetHosts = append(assetNames, a.Name), append(assetHosts, a.Host)
		for _, n := range nodes {
			require.NoError(t, env.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: n}).Error)
		}
	}
	P := mkNode("opt-parent", nil)
	C := mkNode("opt-child", &P)
	D := mkNode("opt-deleted", &P)
	mkAsset("x", P, C)
	mkAsset("y", C)
	mkAsset("z", P)
	mkAsset("w", D)
	require.NoError(t, env.db.Delete(&model.AssetGroup{}, D).Error)

	getRaw := func(subject, p string) (int, string) {
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("Authorization", "Bearer "+env.subjects[subject].Token)
		rec := env.serve(req)
		return rec.Code, rec.Body.String()
	}
	decode := func(raw string) map[string]any {
		m := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(raw), &m), raw)
		return m
	}
	nodesOf := func(m map[string]any) []map[string]any {
		var out []map[string]any
		for _, n := range m["nodes"].([]any) {
			out = append(out, n.(map[string]any))
		}
		return out
	}
	nodeByID := func(ns []map[string]any, id uint) map[string]any {
		for _, n := range ns {
			if uint(n["id"].(float64)) == id {
				return n
			}
		}
		return nil
	}
	ids := func(v any) []uint {
		out := []uint{}
		for _, x := range v.([]any) {
			out = append(out, uint(x.(float64)))
		}
		return out
	}

	var scopedRole uint
	{
		var perms []string
		for _, p := range authz.ScopedTemplateAssetAdminPermissions() {
			perms = append(perms, string(p))
		}
		c, out := env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{"name": "opt-assetmgr", "permissions": perms})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		scopedRole = uint(out["id"].(float64))
	}
	emptyRole := f.role("opt-empty")
	globalOnlyRole := f.role("opt-user-manage", "user:manage")
	userRole := env.roleID(model.RoleUser)

	t.Run("身分管理員取得全部未刪除節點，欄位與超管逐欄相同，回應不含資產資料", func(t *testing.T) {
		// 同一主體的節點樹回應：呼叫選項路由前後相同
		treeCode, treeBefore := getRaw("IDA", "/api/v1/asset-groups/tree")

		cs, rawSuper := getRaw("S01", path)
		ci, rawIDA := getRaw("IDA", path)
		require.Equal(t, http.StatusOK, cs, rawSuper)
		require.Equal(t, http.StatusOK, ci, rawIDA)
		super, idaOut := decode(rawSuper), decode(rawIDA)
		assert.Equal(t, super["nodes"], idaOut["nodes"], "name／parent_id／depth／path／subtree_asset_count 與超管逐欄相同")

		ns := nodesOf(idaOut)
		for _, n := range ns {
			keys := make([]string, 0, len(n))
			for k := range n {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			assert.Equal(t, []string{"depth", "id", "name", "parent_id", "path", "subtree_asset_count"}, keys)
		}
		pn, cn := nodeByID(ns, P), nodeByID(ns, C)
		require.NotNil(t, pn)
		require.NotNil(t, cn)
		assert.EqualValues(t, 3, pn["subtree_asset_count"], "同掛父與子的資產在父節點只計一次，已刪除節點下的資產不計")
		assert.EqualValues(t, 2, cn["subtree_asset_count"])
		assert.Nil(t, nodeByID(ns, D), "已刪除節點不出現")
		assert.EqualValues(t, P, cn["parent_id"], "子節點帶父節點編號")

		for _, s := range append(append([]string{}, assetNames...), assetHosts...) {
			assert.NotContains(t, rawIDA, s, "回應不得含資產名稱或位址")
		}

		treeCode2, treeAfter := getRaw("IDA", "/api/v1/asset-groups/tree")
		assert.Equal(t, treeCode, treeCode2)
		assert.Equal(t, treeBefore, treeAfter, "同一主體的節點樹回應不因選項路由而不同")
	})

	t.Run("不持指派角色權限點者被拒，回應沒有節點", func(t *testing.T) {
		role := f.role("opt-um-av", "user:manage", "asset:view")
		uid := f.user("opt-um-av-user")
		f.hold(uid, role)
		addSubject("UMAV", uid)
		code, raw := getRaw("UMAV", path)
		assert.Equal(t, http.StatusForbidden, code)
		assert.NotContains(t, decode(raw), "nodes")
		assert.NotContains(t, raw, "opt-parent")
		c, _ := getRaw("S00", path)
		assert.Equal(t, http.StatusUnauthorized, c)
	})

	t.Run("角色判定：可限定清單與寫入關卡逐一相符，原因映射與無效果清單一致", func(t *testing.T) {
		_, raw := getRaw("S01", path)
		out := decode(raw)
		assignable, noEffect := ids(out["node_assignable_role_ids"]), ids(out["node_range_no_effect_role_ids"])
		reasons := out["node_range_no_effect_reasons"].(map[string]any)

		has := func(list []uint, id uint) bool {
			for _, x := range list {
				if x == id {
					return true
				}
			}
			return false
		}
		assert.True(t, has(assignable, emptyRole) && has(noEffect, emptyRole), "空權限集的自訂角色同時列在兩份清單")
		assert.True(t, has(assignable, userRole) && has(noEffect, userRole), "內建一般使用者同時列在兩份清單")
		assert.Equal(t, "no_scoped_permission", reasons[strconv.Itoa(int(emptyRole))])
		assert.Equal(t, "builtin_global_only", reasons[strconv.Itoa(int(userRole))])
		assert.True(t, has(assignable, scopedRole) && !has(noEffect, scopedRole), "範本建的管理角色判為生效")
		assert.False(t, has(assignable, globalOnlyRole), "只含全域權限點的自訂角色不可限定節點")
		keys := make([]string, 0, len(reasons))
		for kk := range reasons {
			keys = append(keys, kk)
		}
		sort.Strings(keys)
		want := make([]string, 0, len(noEffect))
		for _, id := range noEffect {
			want = append(want, strconv.Itoa(int(id)))
		}
		sort.Strings(want)
		assert.Equal(t, want, keys, "原因映射的鍵集合恰等於無效果清單")

		// 逐一以有效節點範圍指派：列入者不回 VALIDATION_ROLE_NOT_NODE_SCOPABLE，未列入者回之
		var roles []model.Role
		require.NoError(t, env.db.Find(&roles).Error)
		for _, r := range roles {
			uid := f.user(fmt.Sprintf("opt-gate-%d", r.ID))
			c, resp := env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", uid), map[string]any{
				"manual_roles": []string{r.Name}, "role_nodes": map[string][]uint{r.Name: {P}},
			})
			code, _ := resp["code"].(string)
			if has(assignable, r.ID) {
				assert.NotEqual(t, string(apierror.CodeValidationRoleNotNodeScopable), code, "角色 %s 已列入卻被關卡拒絕", r.Name)
				if r.ID == emptyRole || r.ID == userRole {
					require.Equal(t, http.StatusOK, c, "%v", resp)
					list, _ := resp["node_range_no_effect"].([]any)
					require.Len(t, list, 1, "%v", resp)
					item := list[0].(map[string]any)
					assert.Equal(t, r.Name, item["role"])
					assert.Equal(t, reasons[strconv.Itoa(int(r.ID))], item["reason"], "寫入回應的原因與本路由同值")
				}
			} else {
				assert.Equal(t, http.StatusBadRequest, c, "角色 %s 未列入卻沒被拒絕：%v", r.Name, resp)
				assert.Equal(t, string(apierror.CodeValidationRoleNotNodeScopable), code, "角色 %s", r.Name)
			}
		}
	})

	t.Run("呼叫是唯讀的：角色、指派、權限版本不變，沒有授權變更審計與告警", func(t *testing.T) {
		before, snapBefore := w.counts(), w.snapshot()
		mk := w.mark()
		for _, sub := range []string{"S01", "IDA"} {
			code, _ := getRaw(sub, path)
			require.Equal(t, http.StatusOK, code)
		}
		after, snapAfter := w.counts(), w.snapshot()
		for _, tb := range authzTables {
			assert.Equal(t, snapBefore[tb], snapAfter[tb], "不得改動 %s", tb)
		}
		assert.Equal(t, before.version, after.version)
		assert.Equal(t, before.alerts, after.alerts)
		assert.Equal(t, before.graded, after.graded)
		events, graded := w.written(mk)
		assert.Empty(t, events)
		assert.EqualValues(t, 0, graded)
		// 新增的審計只可能是這兩次請求自身的 HTTP 請求紀錄
		var rows []model.AuditLog
		require.NoError(t, env.db.Where("id > ?", mk.audit).Find(&rows).Error)
		for _, r := range rows {
			assert.True(t, strings.HasSuffix(r.Path, "/role-assignment-options"), "非本請求自身的審計列：%s %s", r.Action, r.Path)
		}
	})

	t.Run("節點清單的查詢次數不隨節點數成長（50 與 200 節點）", func(t *testing.T) {
		var reads int
		inc := func(*gorm.DB) { reads++ }
		require.NoError(t, env.db.Callback().Query().Before("gorm:query").Register("opt_count_query", inc))
		require.NoError(t, env.db.Callback().Row().Before("gorm:row").Register("opt_count_row", inc))
		defer func() {
			_ = env.db.Callback().Query().Remove("opt_count_query")
			_ = env.db.Callback().Row().Remove("opt_count_row")
		}()
		grow := func(total int) {
			var live int64
			require.NoError(t, env.db.Model(&model.AssetGroup{}).Count(&live).Error)
			require.LessOrEqual(t, int(live), total)
			for i := int(live); i < total; i++ {
				var parent *uint
				if i%10 != 0 {
					var last model.AssetGroup
					require.NoError(t, env.db.Order("id DESC").First(&last).Error)
					parent = &last.ID
				}
				id := mkNode(fmt.Sprintf("opt-bulk-%d", i), parent)
				mkAsset(fmt.Sprintf("bulk-%d", i), id)
			}
		}
		measure := func() (int, int) {
			code, raw := getRaw("S01", path) // 暖機
			require.Equal(t, http.StatusOK, code)
			got := len(nodesOf(decode(raw)))
			reads = 0
			code, _ = getRaw("S01", path)
			require.Equal(t, http.StatusOK, code)
			return got, reads
		}
		grow(50)
		n50, q50 := measure()
		grow(200)
		n200, q200 := measure()
		t.Logf("nodes=%d queries=%d; nodes=%d queries=%d", n50, q50, n200, q200)
		assert.Equal(t, 50, n50)
		assert.Equal(t, 200, n200)
		assert.NotZero(t, q50)
		assert.Equal(t, q50, q200, "查詢次數不得隨節點數成長")
	})

	t.Run("來源未接線：回內部錯誤、不回部分資料", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		run := func(h *api.RoleAssignmentOptionsHandler) (int, string) {
			r := gin.New()
			r.GET("/x", h.Options)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
			return rec.Code, rec.Body.String()
		}
		boom := errors.New("boom")
		sealed := sealedStageOneDeps(stageOneRouteConfig{}, nil).roleAssignmentOptions
		for name, h := range map[string]*api.RoleAssignmentOptionsHandler{
			"封印段組裝的零值 handler": sealed,
			"兩個來源皆未注入":         api.NewRoleAssignmentOptionsHandler(nil, nil),
			"只注入節點來源":          api.NewRoleAssignmentOptionsHandler(optionsNodeSource{}, nil),
			"只注入角色來源":          api.NewRoleAssignmentOptionsHandler(nil, optionsRoleSource{}),
			"節點來源讀取失敗":         api.NewRoleAssignmentOptionsHandler(optionsNodeSource{err: boom}, optionsRoleSource{}),
			"角色來源讀取失敗":         api.NewRoleAssignmentOptionsHandler(optionsNodeSource{}, optionsRoleSource{err: boom}),
		} {
			code, raw := run(h)
			assert.Equal(t, http.StatusInternalServerError, code, name)
			m := decode(raw)
			assert.NotContains(t, m, "nodes", name)
			assert.NotContains(t, m, "node_assignable_role_ids", name)
			assert.NotContains(t, raw, "boom", name)
		}
		code, raw := run(api.NewRoleAssignmentOptionsHandler(optionsNodeSource{}, optionsRoleSource{}))
		assert.Equal(t, http.StatusOK, code, raw)
		assert.Contains(t, decode(raw), "nodes")
	})
}
