package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產頁範圍化的 HTTP 夾具：注入目錄把資產五個權限點標為 scoped-enforced，判定器以同一份目錄與
// asset 端拓撲讀取器建構；指派直接寫表（指派寫入端點仍拒絕節點範圍）。每個請求自資料庫重解主體。
// 節點、資產名稱一律以 zz-sa- 起頭，範圍外歸屬節點的名稱不與任何祖先同名。

// saPerms 注入目錄改標為範圍生效的資產權限點。
var saPerms = []authz.Permission{authz.PermAssetView, authz.PermAssetCreate, authz.PermAssetUpdate,
	authz.PermAssetDelete, authz.PermAssetTest}

const saMissing = "999907" // 不存在的資產 ID

// saAssetService 資產服務的 pod 清單與測試連線替身：只記呼叫次數，不連叢集、不撥號。
type saAssetService struct {
	api.AssetServiceInterface
	calls     *int
	testCalls *int
}

func (s saAssetService) TestConnection(context.Context, uint, int) (*asset.ConnectionTestResult, error) {
	*s.testCalls++
	return &asset.ConnectionTestResult{Success: true}, nil
}

// AccessPolicyOverrideRowOf 轉給真服務：只含存取政策的更新回應依存取政策權限點投影，與正式組裝同形。
func (s saAssetService) AccessPolicyOverrideRowOf(ctx context.Context, id uint) (*asset.AccessPolicyOverrideRow, bool, error) {
	return s.AssetServiceInterface.(*asset.AssetService).AccessPolicyOverrideRowOf(ctx, id)
}

func (s saAssetService) ListK8sPods(context.Context, uint) ([]k8sproxy.PodInfo, error) {
	*s.calls++
	return []k8sproxy.PodInfo{}, nil
}

// saHostKeys 主機金鑰服務替身：記錄只存在記憶體，重置與採用改動記錄。
type saHostKeys struct{ recs map[uint]*model.AssetHostKey }

func (s saHostKeys) Get(id uint) (*model.AssetHostKey, error) {
	if r, ok := s.recs[id]; ok {
		return r, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (s saHostKeys) Observations(uint, int) ([]model.AssetHostKeyMismatch, error) { return nil, nil }

func (s saHostKeys) Reset(id uint, _ asset.HostKeyActor) (bool, error) {
	_, ok := s.recs[id]
	delete(s.recs, id)
	return ok, nil
}

func (s saHostKeys) Adopt(id uint, fp string, _ asset.HostKeyActor) (*model.AssetHostKey, error) {
	r := &model.AssetHostKey{AssetID: id, Algorithm: "ssh-ed25519", Fingerprint: fp}
	s.recs[id] = r
	return r, nil
}

// saEnv 一份資料庫與其上的判定器、授權服務與替身。
type saEnv struct {
	*markerEnv
	t        *testing.T
	cat      authz.Catalogue
	eval     *authz.ScopeEvaluator
	authzSvc *authz.AssetAuthorizationService
	nodes    map[string]uint
	seq      int
	podCalls int
	// testCalls 測試連線替身的呼叫次數（範圍外請求不得到達服務）
	testCalls int
	hostKeys  saHostKeys
	super     uint
	// source 非 nil 時取代範圍化投影來源（注入失敗用）
	source api.AssetScopeSource
	// batchHooks 非 nil 時，每個請求的脈絡帶上批次測試接縫
	batchHooks *asset.AssetBatchTestHooks
}

func newSAEnv(t *testing.T) *saEnv {
	t.Helper()
	return newSAEnvOn(t, newMarkerEnv(t, ""))
}

// newSAEnvOn 在既有夾具上建；PostgreSQL 的表由正式 migration 建立，不再 AutoMigrate。
func newSAEnvOn(t *testing.T, m *markerEnv) *saEnv {
	t.Helper()
	env := &saEnv{markerEnv: m, t: t, nodes: map[string]uint{},
		hostKeys: saHostKeys{recs: map[uint]*model.AssetHostKey{}}}
	db := env.db
	if db.Dialector.Name() != "postgres" {
		require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.RolePermission{}, &model.UserGroup{},
			&model.AuthzState{}, &model.AssetAuthorization{}, &model.ApproverScope{}))
		require.NoError(t, db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}))
	}
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0) ON CONFLICT DO NOTHING").Error)
	var err error
	env.cat, err = authz.CatalogueWithScopedEnforcedForTest(saPerms...)
	require.NoError(t, err)
	env.eval = authz.NewScopeEvaluator(env.cat, asset.NewScopeTopologyReader())
	// 與正式組裝同形：資產寫入的範圍判定與涵蓋快照用真實作（取代基礎夾具的替身）
	env.assets.SetAssetWriteScopePort(authz.NewAssetWriteScope(env.eval))
	env.assets.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(asset.NewScopeTopologyReader()))
	// 拓撲序列化鎖與權限版本推進用正式轉接（取代基礎夾具的空實作），歸屬變更後版本實際推進
	env.assets.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	// 只含存取政策的更新要讀全域預設做降級判定（正式組裝有注入）
	env.assets.SetAccessPolicyDefaultReader(fixedAccessDefault{})
	env.authzSvc = authz.NewAssetAuthorizationService(db)
	env.super = env.user("zz-sa-super")
	env.builtin(env.super, model.RoleAdmin)
	return env
}

// node 建節點；parent 為空時建在根層。
func (e *saEnv) node(name, parent string) uint {
	e.t.Helper()
	g := model.AssetGroup{Name: name}
	if parent != "" {
		pid := e.nodes[parent]
		g.ParentID = &pid
	}
	require.NoError(e.t, e.db.Create(&g).Error)
	e.nodes[name] = g.ID
	return g.ID
}

func (e *saEnv) user(name string) uint {
	e.t.Helper()
	email := name + "@test.local"
	u := model.User{Username: name, Password: "x", Email: &email, Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

// role 自訂角色（定義版本 1）。
func (e *saEnv) role(perms ...authz.Permission) uint {
	e.t.Helper()
	e.seq++
	r := model.Role{Name: fmt.Sprintf("zz-sa-role-%d", e.seq), DefinitionVersion: 1}
	require.NoError(e.t, e.db.Create(&r).Error)
	for _, p := range perms {
		require.NoError(e.t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error)
	}
	return r.ID
}

// builtin 以內建角色名稱的全域指派。
func (e *saEnv) builtin(userID uint, name string) {
	e.t.Helper()
	var r model.Role
	if err := e.db.Where("name = ?", name).First(&r).Error; err != nil {
		r = model.Role{Name: name}
		require.NoError(e.t, e.db.Create(&r).Error)
	}
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: r.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
}

func (e *saEnv) grantGlobal(userID, roleID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
}

// grantNodes 使用者直接的節點範圍指派（nodes 為節點名稱）。
func (e *saEnv) grantNodes(userID, roleID uint, nodes ...string) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	for _, n := range nodes {
		id, ok := e.nodes[n]
		require.True(e.t, ok, "未知節點 %s", n)
		require.NoError(e.t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
			SubjectID: userID, RoleID: roleID, NodeID: id}).Error)
	}
}

// dropNodeAssignments 移除使用者全部節點範圍指派（指派列與節點綁定）。
func (e *saEnv) dropNodeAssignments(userID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Where("user_id = ? AND scope_kind = ?", userID, model.ScopeKindNodes).Delete(&model.UserRole{}).Error)
	require.NoError(e.t, e.db.Where("subject_kind = ? AND subject_id = ?", model.BindingSubjectUser, userID).Delete(&model.RoleBindingNode{}).Error)
}

// assignments 使用者目前的指派集合（直接指派；供預覽入口比對）。
func (e *saEnv) assignments(userID uint) authz.AssignmentSet {
	e.t.Helper()
	var urs []model.UserRole
	require.NoError(e.t, e.db.Where("user_id = ?", userID).Find(&urs).Error)
	set := authz.AssignmentSet{SubjectKind: model.KindHuman}
	for _, ur := range urs {
		in := authz.AssignmentInput{BindingSubject: model.BindingSubjectUser, RoleID: ur.RoleID, Scope: ur.ScopeKind}
		if in.Scope == "" {
			in.Scope = model.ScopeKindGlobal
		}
		if in.Scope == model.ScopeKindNodes {
			var bs []model.RoleBindingNode
			require.NoError(e.t, e.db.Where("subject_kind = ? AND subject_id = ? AND role_id = ?",
				model.BindingSubjectUser, userID, ur.RoleID).Find(&bs).Error)
			for _, b := range bs {
				in.NodeIDs = append(in.NodeIDs, b.NodeID)
			}
		}
		set.Items = append(set.Items, in)
	}
	return set
}

// asset 直接寫表建資產並掛到節點（以名稱）。
func (e *saEnv) asset(name string, nodes ...string) uint {
	e.t.Helper()
	e.seq++
	a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: fmt.Sprintf("10.77.%d.%d", e.seq/250, e.seq%250+1),
		Port: 22, CreatedBy: e.super, Active: true}
	require.NoError(e.t, e.db.Create(&a).Error)
	for _, n := range nodes {
		id, ok := e.nodes[n]
		require.True(e.t, ok, "未知節點 %s", n)
		require.NoError(e.t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: id}).Error)
	}
	return a.ID
}

// connGrant 使用者對資產的直接連線授權。
func (e *saEnv) connGrant(userID, assetID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.AssetAuthorization{UserID: &userID, AssetID: &assetID,
		Permission: model.PermissionConnect, GrantedBy: e.super}).Error)
}

// router 掛被測路由。scoped＝注入範圍化投影（正式組裝）；否則為現行路徑的對照。
func (e *saEnv) router(uid uint, scoped bool) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		e.current = p
		if e.batchHooks != nil {
			c.Request = c.Request.WithContext(asset.WithAssetBatchTestHooksForTest(c.Request.Context(), e.batchHooks))
		}
		c.Next()
	})
	h := api.NewAssetHandler(saAssetService{AssetServiceInterface: e.assets, calls: &e.podCalls, testCalls: &e.testCalls}, e.authzSvc, nil)
	hk := api.NewHostKeyHandler(e.hostKeys, e.authzSvc)
	var mgmt middleware.AssetManagementVisibility
	if scoped {
		var src api.AssetScopeSource = authz.NewAssetScopeReader(e.eval, e.db)
		if e.source != nil {
			src = e.source
		}
		h.SetAssetScope(src)
		hk.SetAssetManagementVisibility(src)
		mgmt = src
	}
	visible := middleware.RequireAssetVisibleOrManaged(e.authzSvc, mgmt)
	g := r.Group("/api/v1/assets")
	g.GET("", middleware.EnforceRegistry(), h.List)
	g.GET("/tags", middleware.EnforceRegistry(), h.ListTags)
	g.POST("", middleware.EnforceRegistry(), h.Create)
	// 測試連線以登錄閘判定路徑資產（正式宣告表），範圍外不呼叫服務
	g.POST("/:id/test-connection", middleware.EnforceRegistry(middleware.NewScopeGate(e.db, e.eval, authz.RouteScopeDeclarations())), h.TestConnection)
	g.GET("/:id", middleware.EnforceRegistry(), visible, h.Get)
	g.PUT("/:id", middleware.EnforceRegistry(), h.Update)
	g.DELETE("/:id", middleware.EnforceRegistry(), h.Delete)
	// 批次路由與正式組裝同形：路由閘只判能力，逐列範圍由服務在批次交易內判定
	gate := middleware.NewScopeGate(e.db, e.eval, authz.RouteScopeDeclarations())
	g.POST("/batch/move", middleware.EnforceRegistry(gate), h.BatchMove)
	g.POST("/batch/tags", middleware.EnforceRegistry(gate), h.BatchAddTags)
	g.POST("/batch/delete", middleware.EnforceRegistry(gate), h.BatchDelete)
	g.POST("/import/preview", middleware.EnforceRegistry(), h.PreviewImport)
	g.POST("/import", middleware.EnforceRegistry(), h.Import)
	g.GET("/:id/k8s/pods", middleware.EnforceRegistry(), visible, h.ListK8sPods)
	g.GET("/:id/host-key", middleware.EnforceRegistry(), visible, hk.Get)
	g.DELETE("/:id/host-key", middleware.EnforceRegistry(), api.RequireHostKeyResetSuperAdmin, hk.Reset)
	g.POST("/:id/host-key/adopt", middleware.EnforceRegistry(), api.RequireHostKeyResetSuperAdmin, hk.Adopt)
	return r
}

// do 送出請求，回狀態碼與原始本文。
func (e *saEnv) do(uid uint, scoped bool, method, path, body string) (int, string) {
	e.t.Helper()
	defer func() { e.current = nil }()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	e.router(uid, scoped).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// list 以範圍化組裝取列表（page_size 足夠大）。query 不含問號。
func (e *saEnv) list(uid uint, query string) saList {
	e.t.Helper()
	path := "/api/v1/assets?page_size=500"
	if query != "" {
		path += "&" + query
	}
	code, raw := e.do(uid, true, "GET", path, "")
	require.Equal(e.t, http.StatusOK, code, raw)
	var out saList
	require.NoError(e.t, json.Unmarshal([]byte(raw), &out), raw)
	out.raw = raw
	return out
}

// saList 列表回應（列以鍵值保留，以便檢查鍵集）。
type saList struct {
	Data            []map[string]any `json:"data"`
	Total           int64            `json:"total"`
	ManagementScope *struct {
		EffectiveNodeCount int `json:"effective_node_count"`
		InactiveNodeCount  int `json:"inactive_node_count"`
		Nodes              []struct {
			ID   uint   `json:"id"`
			Path string `json:"path"`
		} `json:"nodes"`
	} `json:"management_scope"`
	raw string
}

// row 依資產 ID 取列；不存在回 nil。
func (l saList) row(id uint) map[string]any {
	for _, r := range l.Data {
		if v, ok := r["id"].(float64); ok && uint(v) == id {
			return r
		}
	}
	return nil
}

// ids 列表中資產 ID 的集合。
func (l saList) ids() map[uint]bool {
	out := map[uint]bool{}
	for _, r := range l.Data {
		if v, ok := r["id"].(float64); ok {
			out[uint(v)] = true
		}
	}
	return out
}

// uintsOf 把 JSON 陣列轉成 uint 切片。
func uintsOf(v any) []uint {
	arr, _ := v.([]any)
	out := make([]uint, 0, len(arr))
	for _, x := range arr {
		if f, ok := x.(float64); ok {
			out = append(out, uint(f))
		}
	}
	return out
}

func idPath(id uint) string { return fmt.Sprintf("/api/v1/assets/%d", id) }
