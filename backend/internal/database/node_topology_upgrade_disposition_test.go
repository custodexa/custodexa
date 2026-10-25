package database_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 升級對節點樹的處置（只支援 PostgreSQL 的正式遷移）：升級不改節點樹、不清理空節點；
// 指向已刪除節點的範圍列不阻擋其他節點操作、不擴大管理可視。

var upgradeSchemaSeq atomic.Int64

type upgradeEnv struct {
	t     *testing.T
	db    *gorm.DB
	svc   *asset.AssetGroupService
	eval  *authz.ScopeEvaluator
	nodes map[string]uint
	super uint
	seq   int
}

// newUpgradeEnv 獨立 schema、正式遷移建表，再寫入升級前版本形狀的節點樹資料。
func newUpgradeEnv(t *testing.T) *upgradeEnv {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	schema := fmt.Sprintf("node_upgrade_%d_%d", time.Now().UnixNano(), upgradeSchemaSeq.Add(1))
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.Equal(t, "postgres", db.Dialector.Name(), "本測試不得回退 SQLite")
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	require.NoError(t, database.RunMigrations(), "正式遷移失敗")
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0) ON CONFLICT (id) DO NOTHING").Error)

	topo := asset.NewScopeTopologyReader()
	e := &upgradeEnv{t: t, db: db, nodes: map[string]uint{},
		eval: authz.NewScopeEvaluator(authz.ProductCatalogue(), topo)}
	e.svc = asset.NewAssetGroupService(db, audit.NewTxSink(), authz.NewAssetAuthorizationService(db))
	e.svc.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	e.svc.SetNodeWriteScopePort(authz.NewNodeWriteScope(e.eval))
	e.svc.SetNodeScopeReferencePort(authz.NewNodeScopeReferenceReader())
	e.svc.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(topo))

	e.super = e.newUser("upgrade-super")
	var adminRole model.Role
	require.NoError(t, db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: e.super, RoleID: adminRole.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)

	// 升級前形狀：多層樹、空節點、多歸屬資產
	for _, p := range [][2]string{{"ops", ""}, {"ops/linux", "ops"}, {"ops/linux/web", "ops/linux"},
		{"ops/linux/web/edge", "ops/linux/web"}, {"ops/win", "ops"}, {"ops/empty", "ops"},
		{"lab", ""}, {"lab/old", "lab"}, {"lab/spare", "lab"}, {"idle", ""}} {
		e.node(p[0], p[1])
	}
	e.asset("ops/linux/web/edge", "lab/old")
	e.asset("ops/linux")
	e.asset("ops/win", "ops/linux/web", "lab/old")
	return e
}

func (e *upgradeEnv) newUser(name string) uint {
	e.t.Helper()
	u := model.User{Username: name, Password: "x", Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

func (e *upgradeEnv) node(path, parent string) uint {
	e.t.Helper()
	g := model.AssetGroup{Name: path}
	if parent != "" {
		pid := e.nodes[parent]
		g.ParentID = &pid
	}
	require.NoError(e.t, e.db.Create(&g).Error)
	e.nodes[path] = g.ID
	return g.ID
}

func (e *upgradeEnv) asset(nodes ...string) uint {
	e.t.Helper()
	e.seq++
	a := model.Asset{Name: fmt.Sprintf("upgrade-asset-%d", e.seq), Protocol: model.ProtocolSSH,
		Host: fmt.Sprintf("10.77.0.%d", e.seq), Port: 22, CreatedBy: e.super, Active: true}
	require.NoError(e.t, e.db.Create(&a).Error)
	for _, n := range nodes {
		require.NoError(e.t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: e.nodes[n]}).Error)
	}
	return a.ID
}

// treeRows 節點（識別碼、父節點、刪除狀態）與掛載列逐列快照。
func (e *upgradeEnv) treeRows() ([]string, []string) {
	e.t.Helper()
	var groups []model.AssetGroup
	require.NoError(e.t, e.db.Unscoped().Order("id").Find(&groups).Error)
	var nodes []string
	for _, g := range groups {
		parent := "root"
		if g.ParentID != nil {
			parent = fmt.Sprint(*g.ParentID)
		}
		nodes = append(nodes, fmt.Sprintf("%d:%s:%s:deleted=%t", g.ID, g.Name, parent, g.DeletedAt.Valid))
	}
	var members []model.AssetNode
	require.NoError(e.t, e.db.Order("id").Find(&members).Error)
	var rows []string
	for _, m := range members {
		rows = append(rows, fmt.Sprintf("%d:%d:%d", m.ID, m.AssetID, m.NodeID))
	}
	return nodes, rows
}

func (e *upgradeEnv) ctx(userID uint) context.Context {
	return authz.ContextWithPrincipal(context.Background(), &authz.Principal{UserID: userID})
}

// nodeManager 建節點範圍持有節點管理權限點的使用者（範圍節點為 paths）。
func (e *upgradeEnv) nodeManager(paths ...string) (userID, roleID uint) {
	e.t.Helper()
	userID = e.newUser("upgrade-manager")
	role := model.Role{Name: "upgrade-node-manager", DefinitionVersion: 1}
	require.NoError(e.t, e.db.Create(&role).Error)
	require.NoError(e.t, e.db.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(authz.PermAssetGroupManage)}).Error)
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: role.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	for _, p := range paths {
		require.NoError(e.t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
			SubjectID: userID, RoleID: role.ID, NodeID: e.nodes[p]}).Error)
	}
	return userID, role.ID
}

// outcome 錯誤的分類（比較兩個環境時以類別而非訊息比較）。
func outcome(err error) string {
	var denied *authz.ErrScopeDenied
	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &denied):
		return "scope_denied"
	case errors.Is(err, authz.ErrNodeWriteSuperAdminOnly):
		return "super_admin_only"
	case errors.Is(err, authz.ErrNodeWriteRootLevelGlobalOnly):
		return "root_level_global_only"
	case errors.Is(err, asset.ErrNodeNotEmpty):
		return "not_empty"
	case errors.Is(err, asset.ErrGroupNotFound):
		return "not_found"
	}
	var ref *asset.NodeScopeReferencedError
	if errors.As(err, &ref) {
		return "referenced"
	}
	return "error:" + err.Error()
}

// danglingScenario 管理者範圍為 ops/linux；withDangling 時另寫一列指向已刪除節點 lab/spare 的範圍列。
// 回一連串節點操作的結果與該指派的管理可視（以節點名稱表示）。
func danglingScenario(t *testing.T, withDangling bool) (results []string, visible []string) {
	e := newUpgradeEnv(t)
	mgr, roleID := e.nodeManager("ops/linux")
	_, err := e.svc.Delete(e.ctx(e.super), e.nodes["lab/spare"], e.super, "upgrade", "127.0.0.1")
	require.NoError(t, err, "空節點可由超級管理者刪除")
	if withDangling {
		require.NoError(t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
			SubjectID: mgr, RoleID: roleID, NodeID: e.nodes["lab/spare"]}).Error)
	}
	p := func(path string) *uint { id := e.nodes[path]; return &id }
	create := func(actor uint, parent string, name string) string {
		_, err := e.svc.Create(e.ctx(actor), &asset.AssetGroupRequest{Name: name, ParentID: p(parent)}, actor, "upgrade", "127.0.0.1")
		return "create " + parent + "/" + name + "=" + outcome(err)
	}
	move := func(actor uint, node, parent string) string {
		var dst *uint
		if parent != "" {
			dst = p(parent)
		}
		_, err := e.svc.Move(e.ctx(actor), e.nodes[node], dst, actor, "upgrade", "127.0.0.1")
		return "move " + node + "->" + parent + "=" + outcome(err)
	}
	del := func(actor uint, node string) string {
		_, err := e.svc.Delete(e.ctx(actor), e.nodes[node], actor, "upgrade", "127.0.0.1")
		return "delete " + node + "=" + outcome(err)
	}
	results = []string{
		create(mgr, "ops/linux", "m-new"),
		create(mgr, "lab", "m-lab"),
		create(e.super, "lab", "s-lab"),
		move(mgr, "ops/linux/web/edge", "ops/linux"),
		move(mgr, "lab/old", "ops/linux"),
		move(e.super, "ops/empty", "lab"),
		move(e.super, "idle", "lab"),
		del(mgr, "ops/linux/web"),
		del(e.super, "ops/empty"),
		del(e.super, "idle"),
	}
	var proj authz.NodeProjection
	require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
		var perr error
		proj, perr = e.eval.NodeScopeProjection(tx, &authz.Principal{UserID: mgr}, authz.PermAssetGroupManage)
		return perr
	}))
	names := map[uint]string{}
	var groups []model.AssetGroup
	require.NoError(t, e.db.Unscoped().Find(&groups).Error)
	for _, g := range groups {
		names[g.ID] = g.Name
	}
	for id, ok := range proj.Selectable {
		if ok {
			visible = append(visible, names[id])
		}
	}
	sort.Strings(visible)
	return results, visible
}

func TestNodeTopologyUpgradeDisposition(t *testing.T) {
	testgate.Value(t, testgate.EnvPGDSN) // 未設即略過（要求整合時轉失敗）；之後每個環境另斷言實際方言
	t.Run("upgrade_twice_keeps_tree", func(t *testing.T) {
		e := newUpgradeEnv(t)
		nodes, members := e.treeRows()
		require.NotEmpty(t, members)
		for i := 0; i < 2; i++ {
			require.NoError(t, database.RunMigrations(), "第 %d 次升級遷移", i+1)
			gotNodes, gotMembers := e.treeRows()
			assert.Equal(t, nodes, gotNodes, "第 %d 次升級後節點數與 parent_id 逐列不變、空節點未清理", i+1)
			assert.Equal(t, members, gotMembers, "第 %d 次升級後 asset_nodes 逐列不變", i+1)
		}
		_, err := e.svc.Delete(e.ctx(e.super), e.nodes["idle"], e.super, "upgrade", "127.0.0.1")
		require.NoError(t, err, "空節點升級後可由超級管理者刪除")
	})

	t.Run("dangling_scope_row_changes_nothing", func(t *testing.T) {
		baseResults, baseVisible := danglingScenario(t, false)
		gotResults, gotVisible := danglingScenario(t, true)
		t.Logf("results=%v visible=%v", baseResults, baseVisible)
		assert.Equal(t, baseResults, gotResults, "指向已刪除節點的範圍列不改變其他節點的建立、搬移、刪除結果")
		assert.Equal(t, baseVisible, gotVisible, "該指派的管理可視不擴大")
	})

	if !t.Failed() {
		fmt.Println("EVIDENCE dialect=postgres")
		t.Log("EVIDENCE dialect=postgres")
	}
}
