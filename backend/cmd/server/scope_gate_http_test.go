package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 登錄閘接上範圍判定器的 HTTP 子案例（掛在 TestScopeDenialOutlet）。
//
// 注入目錄把資產四個權限點標為 scoped-enforced；判定器以同一份目錄與 asset 端拓撲讀取器建構，
// 宣告表由測試自建（正式宣告表為空）。路由以「登錄閘＋真實 handler」掛載，外層套真的審計中介層。
// 判定器在資料庫內重解主體，所以三個主體在庫內與請求脈絡內的指派一致。

// scopeGatePerms 範圍化主體與全域主體持有的權限點（注入目錄改標為範圍生效）。
var scopeGatePerms = []authz.Permission{authz.PermAssetView, authz.PermAssetUpdate, authz.PermAssetDelete, authz.PermAssetTest}

const scopeGateMissing = "999901" // 不存在的資產 ID

// scopeGateEnv 一份資料庫：兩個節點、範圍內／外／已刪除資產各一，與三個主體。
type scopeGateEnv struct {
	*markerEnv
	cat                             authz.Catalogue
	gate                            *middleware.ScopeGate
	nodeIn, nodeOut                 uint
	assetIn, assetOut, assetDeleted uint
	accIn, accOut                   uint
	scoped, global, noCap           *authz.Principal
	scopedUID, globalUID, noCapUID  uint
	fixtureNames                    []string
}

func scopeGateDecls() []authz.RouteScopeDecl {
	d := func(method, path string, src authz.RequirementSource, perm authz.Permission, field string, kind authz.ScopeTargetKind) authz.RouteScopeDecl {
		return authz.RouteScopeDecl{Method: method, Path: path, Source: src, Perm: perm, Field: field,
			Kind: authz.ScopeDeclTarget, Target: kind, Owner: "test"}
	}
	const a, acc = authz.ScopeTargetAsset, authz.ScopeTargetAssetAccount
	return []authz.RouteScopeDecl{
		d("GET", "/api/v1/assets/:id", authz.ReqSourcePerm, authz.PermAssetView, "", a),
		d("DELETE", "/api/v1/assets/:id", authz.ReqSourcePerm, authz.PermAssetDelete, "", a),
		d("PUT", "/api/v1/assets/:id", authz.ReqSourceFields, authz.PermAssetUpdate, authz.FieldWildcard, a),
		d("POST", "/api/v1/assets/:id/test-connection", authz.ReqSourcePerm, authz.PermAssetTest, "", a),
		d("POST", "/api/v1/assets/:id/accounts", authz.ReqSourcePerm, authz.PermAssetUpdate, "", a),
		d("PUT", "/api/v1/assets/:id/accounts/:accountId", authz.ReqSourcePerm, authz.PermAssetUpdate, "", acc),
		d("DELETE", "/api/v1/assets/:id/accounts/:accountId", authz.ReqSourcePerm, authz.PermAssetUpdate, "", acc),
	}
}

func newScopeGateEnv(t *testing.T) *scopeGateEnv {
	t.Helper()
	env := &scopeGateEnv{markerEnv: newMarkerEnv(t, "")}
	db := env.db
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.RolePermission{}, &model.UserGroup{},
		&model.AuthzState{}, &model.AssetAuthorization{}, &model.ApproverScope{}))
	require.NoError(t, db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}))
	return seedScopeGateEnv(t, env)
}

// seedScopeGateEnv 在已建好表的資料庫上種入節點、資產與三個主體（SQLite 與 PostgreSQL 共用）。
func seedScopeGateEnv(t *testing.T, env *scopeGateEnv) *scopeGateEnv {
	t.Helper()
	db := env.db
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0) ON CONFLICT DO NOTHING").Error)

	env.nodeIn = scopeGateNode(t, env, "zz-gate-node-in")
	env.nodeOut = scopeGateNode(t, env, "zz-gate-node-out")
	env.assetIn, env.accIn = env.mountedAsset(t, "zz-gate-asset-in", "10.9.1.1", env.nodeIn)
	env.assetOut, env.accOut = env.mountedAsset(t, "zz-gate-asset-out", "10.9.1.2", env.nodeOut)
	env.assetDeleted, _ = env.mountedAsset(t, "zz-gate-asset-deleted", "10.9.1.3", env.nodeIn)
	require.NoError(t, db.Delete(&model.Asset{}, env.assetDeleted).Error)

	var err error
	env.cat, err = authz.CatalogueWithScopedEnforcedForTest(scopeGatePerms...)
	require.NoError(t, err)
	env.gate = middleware.NewScopeGate(db, authz.NewScopeEvaluator(env.cat, asset.NewScopeTopologyReader()), scopeGateDecls())

	role := model.Role{Name: "zz-gate-role", DefinitionVersion: 1}
	require.NoError(t, db.Create(&role).Error)
	for _, p := range scopeGatePerms {
		require.NoError(t, db.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(p)}).Error)
	}
	env.scopedUID = env.user(t, "zz-gate-scoped")
	require.NoError(t, db.Create(&model.UserRole{UserID: env.scopedUID, RoleID: role.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: env.scopedUID, RoleID: role.ID, NodeID: env.nodeIn}).Error)
	env.globalUID = env.user(t, "zz-gate-global")
	require.NoError(t, db.Create(&model.UserRole{UserID: env.globalUID, RoleID: role.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	// 無能力主體：只有一個空集合的自訂角色（零角色會視同一般使用者而持有 asset:view）
	empty := model.Role{Name: "zz-gate-empty", DefinitionVersion: 1}
	require.NoError(t, db.Create(&empty).Error)
	env.noCapUID = env.user(t, "zz-gate-nocap")
	require.NoError(t, db.Create(&model.UserRole{UserID: env.noCapUID, RoleID: empty.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)

	asg := func(scope string, nodes ...uint) []authz.Assignment {
		return []authz.Assignment{{RoleName: role.Name, Via: authz.ViaDirect, Scope: scope, LiveNodeIDs: nodes,
			Permissions: scopeGatePerms, Custom: true}}
	}
	env.scoped = authz.NewPrincipalOn(env.cat, env.scopedUID, authz.TokenFacts{}, asg(model.ScopeKindNodes, env.nodeIn))
	env.global = authz.NewPrincipalOn(env.cat, env.globalUID, authz.TokenFacts{}, asg(model.ScopeKindGlobal))
	env.noCap = authz.NewPrincipalOn(env.cat, env.noCapUID, authz.TokenFacts{}, []authz.Assignment{{RoleName: empty.Name,
		Via: authz.ViaDirect, Scope: model.ScopeKindGlobal, Custom: true}})
	require.False(t, env.noCap.Has(authz.PermAssetView), "無能力主體不得持有任何資產權限點")
	require.True(t, env.scoped.Has(authz.PermAssetUpdate), "注入目錄下範圍化主體須有能力，才走得到範圍判定")
	env.fixtureNames = []string{"zz-gate-node-in", "zz-gate-node-out", "zz-gate-asset-in", "zz-gate-asset-out",
		"zz-gate-asset-deleted", "10.9.1.2", "10.9.1.3"}
	return env
}

func scopeGateNode(t *testing.T, env *scopeGateEnv, name string) uint {
	t.Helper()
	n := model.AssetGroup{Name: name}
	require.NoError(t, env.db.Create(&n).Error)
	return n.ID
}

func (e *scopeGateEnv) user(t *testing.T, name string) uint {
	t.Helper()
	email := name + "@test.local"
	u := model.User{Username: name, Password: "x", Email: &email, Active: true}
	require.NoError(t, e.db.Create(&u).Error)
	return u.ID
}

// mountedAsset 建資產（含預設帳號）並掛到節點。
func (e *scopeGateEnv) mountedAsset(t *testing.T, name, host string, node uint) (assetID, accountID uint) {
	t.Helper()
	a, err := e.assets.Create(asset.WithSystemCaller(operatorCtx()), &asset.CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: host, Port: 22, CreatedBy: 1, Username: "root", Password: "Pw-0"})
	require.NoError(t, err)
	require.NoError(t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: node}).Error)
	var acc model.AssetAccount
	require.NoError(t, e.db.Where("asset_id = ?", a.ID).First(&acc).Error)
	return a.ID, acc.ID
}

// mount 掛被測路由：登錄閘（gate 為 nil 時不帶判定依賴）＋真實 handler。
func (e *scopeGateEnv) mount(gate *middleware.ScopeGate) func(r gin.IRoutes) {
	return func(r gin.IRoutes) {
		h := api.NewAssetHandler(e.assets, nil, nil, gate)
		r.GET("/api/v1/assets/:id", middleware.EnforceRegistry(gate), h.Get)
		r.DELETE("/api/v1/assets/:id", middleware.EnforceRegistry(gate), h.Delete)
		r.PUT("/api/v1/assets/:id", middleware.EnforceRegistry(gate), h.Update)
		r.POST("/api/v1/assets/:id/test-connection", middleware.EnforceRegistry(gate), h.TestConnection)
		svc := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
			WithManagementAuthorizer(e.auth).WithSystemAlertSink(noopAlertSink{}).WithAccountWriteScope(allowAllAccountWriteScope{})
		ah := api.NewAssetAccountHandler(svc, nil, gate)
		r.POST("/api/v1/assets/:id/accounts", middleware.EnforceRegistry(gate), ah.Create)
		r.PUT("/api/v1/assets/:id/accounts/:accountId", middleware.EnforceRegistry(gate), ah.Update)
		r.DELETE("/api/v1/assets/:id/accounts/:accountId", middleware.EnforceRegistry(gate), ah.Delete)
	}
}

// scopeGateRoute 一條被測路由；path 以 {a}／{acc} 代入資產與帳號 ID。
type scopeGateRoute struct {
	name, method, path, body string
	baseline                 string // scopeNotFoundBaselines 的鍵（全域主體打不存在的現行回應）；空＝只比本 env 的全域基準
}

func scopeGateRoutes() []scopeGateRoute {
	return []scopeGateRoute{
		{"資產詳情", "GET", "/api/v1/assets/{a}", "", "asset_get"},
		{"資產刪除", "DELETE", "/api/v1/assets/{a}", "", "asset_delete"},
		{"資產更新", "PUT", "/api/v1/assets/{a}", `{"name":"renamed"}`, "asset_update"},
		{"測試連線", "POST", "/api/v1/assets/{a}/test-connection", `{"timeout":1}`, ""},
		{"帳號新增", "POST", "/api/v1/assets/{a}/accounts", `{"username":"u2","password":"p","note":"n"}`, ""},
		{"帳號更新", "PUT", "/api/v1/assets/{a}/accounts/{acc}", `{"note":"n"}`, "account_missing_asset"},
		{"帳號刪除", "DELETE", "/api/v1/assets/{a}/accounts/{acc}", "", ""},
	}
}

func (r scopeGateRoute) url(assetID, accountID string) string {
	return strings.NewReplacer("{a}", assetID, "{acc}", accountID).Replace(r.path)
}

// scopeGateResult 一次請求的回應、審計列與業務表快照差異。
type scopeGateResult struct {
	code       int
	raw        string
	auditRows  int64
	audit      model.AuditLog
	tablesSame bool
}

// scopeGateBusinessTables 業務表（審計表除外）：判定前後的整表內容須相同。
var scopeGateBusinessTables = []string{"assets", "asset_accounts", "asset_nodes", "asset_groups", "credentials",
	"credential_secret_versions", "change_secret_candidates", "users", "user_roles", "role_binding_nodes"}

func (e *scopeGateEnv) snapshot(t *testing.T) string {
	t.Helper()
	// 逐列序列化後排序比較整表內容（不依賴方言專屬的列序欄）
	out := map[string]any{}
	for _, tb := range scopeGateBusinessTables {
		var rows []map[string]any
		require.NoError(t, e.db.Raw("SELECT * FROM "+tb).Scan(&rows).Error, tb)
		enc := make([]string, 0, len(rows))
		for _, r := range rows {
			b, err := json.Marshal(r)
			require.NoError(t, err)
			enc = append(enc, string(b))
		}
		sort.Strings(enc)
		out[tb] = enc
	}
	b, err := json.Marshal(out)
	require.NoError(t, err)
	return string(b)
}

func (e *scopeGateEnv) send(t *testing.T, p *authz.Principal, uid uint, mount func(gin.IRoutes), method, path, body string) scopeGateResult {
	t.Helper()
	before, auditBefore := e.snapshot(t), countAuditRows(t, e.db)
	e.current = p
	defer func() { e.current = nil }()
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uid)
		c.Set("username", "scope-gate")
		middleware.SetPrincipal(c, p)
		c.Next()
	})
	mount(r)
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	res := scopeGateResult{code: w.Code, raw: w.Body.String(), auditRows: countAuditRows(t, e.db) - auditBefore}
	if res.auditRows > 0 {
		require.NoError(t, e.db.Unscoped().Order("id desc").First(&res.audit).Error)
	}
	res.tablesSame = before == e.snapshot(t)
	return res
}

func runScopeGateHTTPSubtests(t *testing.T, baselines map[string]scopeOutletProbe) {
	env := newScopeGateEnv(t)
	mount := env.mount(env.gate)
	ids := func(assetID uint) string { return strconv.Itoa(int(assetID)) }
	accFor := map[uint]uint{env.assetOut: env.accOut, env.assetDeleted: env.accIn}
	capShape := legacyPermissionDeniedBody(t)

	// 全域主體打不存在的資產：照舊（與現行基準逐位元相同）、審計 failure、無拒絕細節
	globalMissing := map[string]scopeGateResult{}
	t.Run("全域主體打不存在照舊", func(t *testing.T) {
		for _, rt := range scopeGateRoutes() {
			got := env.send(t, env.global, env.globalUID, mount, rt.method, rt.url(scopeGateMissing, ids(env.accIn)), rt.body)
			globalMissing[rt.name] = got
			assert.Equal(t, http.StatusNotFound, got.code, "%s：%s", rt.name, got.raw)
			assert.Contains(t, got.raw, string(apierror.CodeAssetNotFound), rt.name)
			if rt.baseline != "" {
				assert.Equal(t, baselines[rt.baseline].raw, got.raw, "%s：須與現行全域基準逐位元相同", rt.name)
			}
			require.Equal(t, int64(1), got.auditRows, "%s：須恰寫一列審計", rt.name)
			assert.Equal(t, model.StatusFailure, got.audit.Status, rt.name)
			assert.NotContains(t, got.audit.Details, `"denial"`, rt.name)
			assert.True(t, got.tablesSame, "%s：業務表不得變動", rt.name)
		}
	})

	t.Run("範圍外與已刪除等於不存在", func(t *testing.T) {
		for _, rt := range scopeGateRoutes() {
			want := globalMissing[rt.name]
			require.NotEmpty(t, want.raw, rt.name)
			var bodies []string
			for _, target := range []uint{env.assetOut, env.assetDeleted} {
				got := env.send(t, env.scoped, env.scopedUID, mount, rt.method, rt.url(ids(target), ids(accFor[target])), rt.body)
				bodies = append(bodies, got.raw)
				assert.Equal(t, want.code, got.code, "%s（資產 %d）：%s", rt.name, target, got.raw)
				assert.Equal(t, want.raw, got.raw, "%s（資產 %d）：須等於全域主體打不存在", rt.name, target)
				assertScopeDeniedAudit(t, rt.name, got)
				for _, n := range env.fixtureNames {
					assert.NotContains(t, got.raw, n, "%s：回應不得含 fixture 名稱", rt.name)
				}
				assert.True(t, got.tablesSame, "%s（資產 %d）：DB 寫入須為 0", rt.name, target)
			}
			assert.Equal(t, bodies[0], bodies[1], "%s：範圍外與已刪除須逐位元相同", rt.name)
		}
	})

	t.Run("範圍外資產下的帳號等於資產不存在", func(t *testing.T) {
		// 範圍外資產的真實帳號、範圍外資產配不存在帳號：皆為資產層，不是帳號不存在
		for _, acc := range []string{ids(env.accOut), "999902"} {
			got := env.send(t, env.scoped, env.scopedUID, mount, "PUT", "/api/v1/assets/"+ids(env.assetOut)+"/accounts/"+acc, `{"note":"n"}`)
			assert.Equal(t, baselines["account_missing_asset"].raw, got.raw, "帳號 %s", acc)
			assert.NotContains(t, got.raw, string(apierror.CodeAssetAccountNotFound))
			assertScopeDeniedAudit(t, "帳號 "+acc, got)
			assert.True(t, got.tablesSame)
		}
		// 範圍內資產配不存在帳號：帳號層，等於全域主體對同一請求
		in := "/api/v1/assets/" + ids(env.assetIn) + "/accounts/999902"
		scoped := env.send(t, env.scoped, env.scopedUID, mount, "PUT", in, `{"note":"n"}`)
		global := env.send(t, env.global, env.globalUID, mount, "PUT", in, `{"note":"n"}`)
		assert.Equal(t, baselines["account_missing_account"].raw, scoped.raw)
		assert.Equal(t, global.raw, scoped.raw)
		assertScopeDeniedAudit(t, "範圍內資產配不存在帳號", scoped)
		assert.Equal(t, model.StatusFailure, global.audit.Status)
		assert.NotContains(t, global.audit.Details, `"denial"`)
		assert.True(t, scoped.tablesSame)
	})

	t.Run("無能力者兩個 ID 皆 403 單一形狀", func(t *testing.T) {
		for _, rt := range scopeGateRoutes() {
			for _, target := range []uint{env.assetOut, env.assetDeleted} {
				got := env.send(t, env.noCap, env.noCapUID, mount, rt.method, rt.url(ids(target), ids(accFor[target])), rt.body)
				assert.Equal(t, http.StatusForbidden, got.code, "%s（資產 %d）：%s", rt.name, target, got.raw)
				assert.Equal(t, capShape, got.raw, "%s：能力拒絕單一形狀", rt.name)
				assert.Contains(t, got.audit.Details, `"denial":"capability"`, rt.name)
				assert.True(t, got.tablesSame, rt.name)
			}
		}
	})

	t.Run("範圍內放行", func(t *testing.T) {
		got := env.send(t, env.scoped, env.scopedUID, mount, "GET", "/api/v1/assets/"+ids(env.assetIn), "")
		assert.Equal(t, http.StatusOK, got.code, got.raw)
		assert.Contains(t, got.raw, "zz-gate-asset-in")
		assert.Equal(t, model.StatusSuccess, got.audit.Status)
	})

	t.Run("未宣告的登錄項不變", func(t *testing.T) {
		// 同一判定器、宣告表只留刪除：詳情不經範圍判定，有無判定依賴回應相同
		only := middleware.NewScopeGate(env.db, authz.NewScopeEvaluator(env.cat, asset.NewScopeTopologyReader()),
			scopeGateDecls()[1:2])
		path := "/api/v1/assets/" + ids(env.assetOut)
		with := env.send(t, env.scoped, env.scopedUID, env.mount(only), "GET", path, "")
		without := env.send(t, env.scoped, env.scopedUID, env.mount(nil), "GET", path, "")
		assert.Equal(t, http.StatusOK, with.code, with.raw)
		assert.Equal(t, without.raw, with.raw)
	})

	t.Run("宣告與接線不一致不放行", func(t *testing.T) {
		anyOf := authz.RouteScopeDecl{Method: "GET", Path: "/api/v1/assets/:id", Source: authz.ReqSourceAnyOf,
			Perm: authz.PermAssetView, Kind: authz.ScopeDeclTarget, Target: authz.ScopeTargetAsset, Owner: "test"}
		node := scopeGateDecls()[0]
		node.Target = "zz-unsupported-kind"
		ev := authz.NewScopeEvaluator(env.cat, asset.NewScopeTopologyReader())
		for name, g := range map[string]*middleware.ScopeGate{
			"缺判定器":        middleware.NewScopeGate(env.db, nil, scopeGateDecls()),
			"缺讀取連線":       middleware.NewScopeGate(nil, ev, scopeGateDecls()),
			"並列進入能力的目標宣告": middleware.NewScopeGate(env.db, ev, []authz.RouteScopeDecl{anyOf}),
			"不支援的目標種類":    middleware.NewScopeGate(env.db, ev, []authz.RouteScopeDecl{node}),
		} {
			got := env.send(t, env.global, env.globalUID, env.mount(g), "GET", "/api/v1/assets/"+ids(env.assetIn), "")
			assert.Equal(t, http.StatusInternalServerError, got.code, "%s：%s", name, got.raw)
			assert.Contains(t, got.raw, string(apierror.CodeInternalPermissionCheck), name)
			assert.NotContains(t, got.raw, "zz-gate-asset-in", name)
		}
	})
}

// assertScopeDeniedAudit 範圍拒絕的審計列：恰一列、denied、denial=scope、scope_reason=out_of_scope
// （範圍外、已刪除與不存在同一原因）。
func assertScopeDeniedAudit(t *testing.T, name string, got scopeGateResult) {
	t.Helper()
	require.Equal(t, int64(1), got.auditRows, "%s：須恰寫一列審計", name)
	assert.Equal(t, model.StatusDenied, got.audit.Status, "%s：範圍拒絕審計為 denied", name)
	var details map[string]string
	require.NoError(t, json.Unmarshal([]byte(got.audit.Details), &details), "%s：details=%s", name, got.audit.Details)
	assert.Equal(t, "scope", details["denial"], name)
	assert.Equal(t, "out_of_scope", details["scope_reason"], name)
}
