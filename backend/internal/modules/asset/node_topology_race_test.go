package asset_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
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

// 節點寫入的並發順序：兩個寫入交錯時，後進者的範圍判定與結構檢查以取得拓撲序列化鎖後重讀的狀態為準。
// 未設 PG 連線字串時在 SQLite 執行；設了即在獨立 schema 的 PostgreSQL 執行（斷言實際方言）。
// 樹形：prod、prod/db、prod/db/a、prod/db/b、prod/web、sit。

var raceSchemaSeq atomic.Int64

type raceEnv struct {
	t       *testing.T
	db      *gorm.DB
	dsn     string // PG 時為帶 search_path 的連線字串
	svc     *asset.AssetGroupService
	nodes   map[string]uint
	super   uint
	manager uint
	rec     *raceRecorder
}

// raceDecision 一次搬移判定當下（交易內、判定之後）讀到的觀察節點父節點與判定結果。
type raceDecision struct {
	actor       uint
	watchParent *uint
	err         error
}

// raceRecorder 包住正式的節點寫入判定，記錄搬移判定時的拓撲。
type raceRecorder struct {
	inner asset.NodeWriteScopePort
	watch uint
	mu    sync.Mutex
	moves []raceDecision
}

func (r *raceRecorder) AuthorizeNodeCreate(ctx context.Context, tx *gorm.DB, parentID *uint) error {
	return r.inner.AuthorizeNodeCreate(ctx, tx, parentID)
}

func (r *raceRecorder) AuthorizeNodeEdit(ctx context.Context, tx *gorm.DB, nodeID uint) error {
	return r.inner.AuthorizeNodeEdit(ctx, tx, nodeID)
}

func (r *raceRecorder) AuthorizeNodeMove(ctx context.Context, tx *gorm.DB, nodeID uint, newParentID *uint) (asset.NodeMoveScope, error) {
	scope, err := r.inner.AuthorizeNodeMove(ctx, tx, nodeID, newParentID)
	var g model.AssetGroup
	if rerr := tx.Session(&gorm.Session{NewDB: true}).Unscoped().First(&g, r.watch).Error; rerr != nil {
		return scope, rerr
	}
	var actor uint
	if p := authz.PrincipalFromContext(ctx); p != nil {
		actor = p.UserID
	}
	r.mu.Lock()
	r.moves = append(r.moves, raceDecision{actor: actor, watchParent: g.ParentID, err: err})
	r.mu.Unlock()
	return scope, err
}

func (r *raceRecorder) decisions() []raceDecision {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]raceDecision(nil), r.moves...)
}

func raceModels() ([]any, []any) {
	return []any{&model.AssetGroup{}, &model.AssetNode{}, &model.Asset{}, &model.AuditLog{},
			&model.AssetAuthorization{}, &model.ApproverScope{}, &model.User{}, &model.Role{}, &model.RolePermission{},
			&model.AuthzState{}, &model.PermissionStateEvent{}, &model.UserGroup{}},
		[]any{&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{},
			&model.Credential{}} // 節點刪除承接歸屬該節點的共用憑證
}

// openRaceDB 未設 PG 連線字串時開 SQLite；設了開獨立 schema 的 PostgreSQL。
func openRaceDB(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	dsn := os.Getenv(testgate.EnvPGDSN)
	if dsn == "" {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		sqlDB.SetMaxOpenConns(1) // :memory: 每條連線各自一個庫
		require.Equal(t, "sqlite", db.Dialector.Name())
		return db, ""
	}
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	schema := fmt.Sprintf("node_race_%d_%d", time.Now().UnixNano(), raceSchemaSeq.Add(1))
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	scoped := dsn + " search_path=" + schema
	db, err := gorm.Open(postgres.Open(scoped), &gorm.Config{Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.Equal(t, "postgres", db.Dialector.Name(), "設了 PG 連線字串時不得回退 SQLite")
	return db, scoped
}

func newRaceEnv(t *testing.T) *raceEnv {
	t.Helper()
	db, scoped := openRaceDB(t)
	first, tail := raceModels()
	require.NoError(t, db.AutoMigrate(first...))
	require.NoError(t, db.AutoMigrate(tail...))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	e := &raceEnv{t: t, db: db, dsn: scoped, nodes: map[string]uint{}}
	for _, p := range [][2]string{{"prod", ""}, {"prod/db", "prod"}, {"prod/db/a", "prod/db"}, {"prod/db/b", "prod/db"},
		{"prod/web", "prod"}, {"sit", ""}} {
		g := model.AssetGroup{Name: p[0]}
		if p[1] != "" {
			pid := e.nodes[p[1]]
			g.ParentID = &pid
		}
		require.NoError(t, db.Create(&g).Error)
		e.nodes[p[0]] = g.ID
	}

	e.super = e.user("race-super")
	adminRole := model.Role{Name: model.RoleAdmin}
	require.NoError(t, db.Create(&adminRole).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: e.super, RoleID: adminRole.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)

	e.manager = e.user("race-manager")
	mgrRole := model.Role{Name: "race-node-manager", DefinitionVersion: 1}
	require.NoError(t, db.Create(&mgrRole).Error)
	require.NoError(t, db.Create(&model.RolePermission{RoleID: mgrRole.ID, PermissionKey: string(authz.PermAssetGroupManage)}).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: e.manager, RoleID: mgrRole.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
		SubjectID: e.manager, RoleID: mgrRole.ID, NodeID: e.nodes["prod/db"]}).Error)

	topo := asset.NewScopeTopologyReader()
	e.rec = &raceRecorder{inner: authz.NewNodeWriteScope(authz.NewScopeEvaluator(authz.ProductCatalogue(), topo)),
		watch: e.nodes["prod/db/b"]}
	e.svc = asset.NewAssetGroupService(db, audit.NewTxSink(), authz.NewAssetAuthorizationService(db))
	e.svc.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	e.svc.SetNodeWriteScopePort(e.rec)
	e.svc.SetNodeScopeReferencePort(authz.NewNodeScopeReferenceReader())
	e.svc.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(topo))
	return e
}

func (e *raceEnv) user(name string) uint {
	e.t.Helper()
	u := model.User{Username: name, Password: "x", Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

func (e *raceEnv) ctx(userID uint) context.Context {
	return authz.ContextWithPrincipal(context.Background(), &authz.Principal{UserID: userID})
}

func (e *raceEnv) move(actor uint, node string, parent string) func() error {
	return func() error {
		var p *uint
		if parent != "" {
			id := e.nodes[parent]
			p = &id
		}
		_, err := e.svc.Move(e.ctx(actor), e.nodes[node], p, actor, "race", "127.0.0.1")
		return err
	}
}

// tree 全部節點（含已刪除）的父節點與刪除狀態快照。
func (e *raceEnv) tree() map[uint]string {
	e.t.Helper()
	var rows []model.AssetGroup
	require.NoError(e.t, e.db.Unscoped().Order("id").Find(&rows).Error)
	out := map[uint]string{}
	for _, r := range rows {
		parent := "root"
		if r.ParentID != nil {
			parent = fmt.Sprint(*r.ParentID)
		}
		out[r.ID] = fmt.Sprintf("%s/deleted=%t", parent, r.DeletedAt.Valid)
	}
	return out
}

func (e *raceEnv) parent(node string) *uint {
	e.t.Helper()
	var g model.AssetGroup
	require.NoError(e.t, e.db.Unscoped().First(&g, e.nodes[node]).Error)
	return g.ParentID
}

func (e *raceEnv) serviceAuditCount() int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.AuditLog{}).Where("resource = ? AND status = ?",
		model.ResourceAsset, model.StatusSuccess).Count(&n).Error)
	return n
}

// runOrdered 以拓撲鎖取得後的停點強制提交順序：first 取得拓撲序列化鎖後停住，second 此時才開始，
// 確認 second 在 first 放行前沒有完成，再放行 first。回兩者的錯誤。
func runOrdered(t *testing.T, first, second func() error) (error, error) {
	t.Helper()
	var armed atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	restore := authz.SetTopologyLockAcquiredHookForTest(func(*gorm.DB) {
		if armed.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
	})
	defer restore()
	c1, c2 := make(chan error, 1), make(chan error, 1)
	go func() { c1 <- first() }()
	select {
	case <-entered:
	case err := <-c1:
		t.Fatalf("先行交易未到達拓撲鎖停點即結束：%v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("先行交易未到達拓撲鎖停點")
	}
	go func() { c2 <- second() }()
	select {
	case err := <-c2:
		close(release)
		<-c1
		t.Fatalf("後行交易在先行交易放行前完成：%v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	return <-c1, <-c2
}

func TestNodeTopologyRace(t *testing.T) {
	t.Run("scoped_move_vs_superadmin_moving_destination", func(t *testing.T) {
		t.Run("manager_commits_first", func(t *testing.T) {
			e := newRaceEnv(t)
			errMgr, errSuper := runOrdered(t, e.move(e.manager, "prod/db/a", "prod/db/b"), e.move(e.super, "prod/db/b", "sit"))
			t.Logf("order=manager,super result manager=%v super=%v final parent(a)=%d parent(b)=%d", errMgr, errSuper, *e.parent("prod/db/a"), *e.parent("prod/db/b"))
			require.NoError(t, errMgr, "管理者先提交：裁決時 b 在範圍內，搬移成功")
			require.NoError(t, errSuper, "其後超級管理者搬移成功")
			assertManagerDecisions(t, e)
			assert.Equal(t, e.nodes["prod/db/b"], *e.parent("prod/db/a"), "a 隨 b 位於 sit 屬合法終態")
			assert.Equal(t, e.nodes["sit"], *e.parent("prod/db/b"))
		})
		t.Run("superadmin_commits_first", func(t *testing.T) {
			e := newRaceEnv(t)
			errSuper, errMgr := runOrdered(t, e.move(e.super, "prod/db/b", "sit"), e.move(e.manager, "prod/db/a", "prod/db/b"))
			t.Logf("order=super,manager result super=%v manager=%v final parent(a)=%d parent(b)=%d", errSuper, errMgr, *e.parent("prod/db/a"), *e.parent("prod/db/b"))
			require.NoError(t, errSuper)
			var denied *authz.ErrScopeDenied
			require.True(t, errors.As(errMgr, &denied), "超級管理者先提交：管理者的搬移回與不存在同形的範圍拒絕，得到 %v", errMgr)
			assertManagerDecisions(t, e)
			assert.Equal(t, e.nodes["prod/db"], *e.parent("prod/db/a"), "樹等於超級管理者搬移後的狀態")
			assert.Equal(t, e.nodes["sit"], *e.parent("prod/db/b"))
		})
	})

	t.Run("delete_empty_node_vs_create_child", func(t *testing.T) {
		create := func(e *raceEnv, n uint) func() error {
			return func() error {
				_, err := e.svc.Create(e.ctx(e.super), &asset.AssetGroupRequest{Name: "race-child", ParentID: &n}, e.super, "race", "127.0.0.1")
				return err
			}
		}
		del := func(e *raceEnv, n uint) func() error {
			return func() error {
				_, err := e.svc.Delete(e.ctx(e.super), n, e.super, "race", "127.0.0.1")
				return err
			}
		}
		outcome := func(t *testing.T, e *raceEnv, n uint) (deleted bool, children int64) {
			t.Helper()
			var g model.AssetGroup
			require.NoError(t, e.db.Unscoped().First(&g, n).Error)
			require.NoError(t, e.db.Unscoped().Model(&model.AssetGroup{}).Where("parent_id = ?", n).Count(&children).Error)
			return g.DeletedAt.Valid, children
		}
		t.Run("delete_commits_first", func(t *testing.T) {
			e := newRaceEnv(t)
			n := e.nodes["prod/web"]
			errDel, errCreate := runOrdered(t, del(e, n), create(e, n))
			deleted, children := outcome(t, e, n)
			t.Logf("order=delete,create result delete=%v create=%v final deleted=%v children=%d", errDel, errCreate, deleted, children)
			require.NoError(t, errDel)
			require.Error(t, errCreate, "節點已刪除後的建立須被拒")
			assert.True(t, deleted)
			assert.Zero(t, children, "N 已刪除且沒有新子節點")
		})
		t.Run("create_commits_first", func(t *testing.T) {
			e := newRaceEnv(t)
			n := e.nodes["prod/web"]
			errCreate, errDel := runOrdered(t, create(e, n), del(e, n))
			deleted, children := outcome(t, e, n)
			t.Logf("order=create,delete result create=%v delete=%v final deleted=%v children=%d", errCreate, errDel, deleted, children)
			require.NoError(t, errCreate)
			require.ErrorIs(t, errDel, asset.ErrNodeNotEmpty)
			assert.False(t, deleted, "子節點建立成功且 N 因非空而未刪除")
			assert.Equal(t, int64(1), children)
		})
	})

	t.Run("scope_denied_move_leaves_no_change", func(t *testing.T) {
		e := newRaceEnv(t)
		before, audits := e.tree(), e.serviceAuditCount()
		v0, err := authz.CurrentVersion(e.db)
		require.NoError(t, err)
		err = e.move(e.manager, "prod/db/a", "prod/web")()
		var denied *authz.ErrScopeDenied
		require.True(t, errors.As(err, &denied), "目的在範圍外：範圍拒絕，得到 %v", err)
		assert.Equal(t, before, e.tree(), "樹不變")
		assert.Equal(t, audits, e.serviceAuditCount(), "服務寫入的成功審計列不變")
		v1, err := authz.CurrentVersion(e.db)
		require.NoError(t, err)
		assert.Equal(t, v0, v1, "權限版本不變")
	})

	t.Run("node_existence_read", func(t *testing.T) {
		e := newRaceEnv(t)
		reader := asset.NewNodeExistenceReader()
		gone := e.nodes["prod/web"]
		_, err := e.svc.Delete(e.ctx(e.super), gone, e.super, "race", "127.0.0.1")
		require.NoError(t, err)
		const never uint = 987654

		tx := e.db.Begin()
		require.NoError(t, tx.Error)
		defer tx.Rollback()
		require.NoError(t, authz.LockScopeTopologyTx(tx))
		live, err := reader.LiveNodesTx(tx, []uint{gone, never})
		require.NoError(t, err)
		assert.Equal(t, map[uint]bool{gone: false, never: false}, live,
			"取得序列化點後讀到另一交易已提交的刪除；已刪除與從未存在結果相同、只有識別碼")
		fresh := model.AssetGroup{Name: "race-fresh"}
		require.NoError(t, tx.Create(&fresh).Error)
		live, err = reader.LiveNodesTx(tx, []uint{fresh.ID})
		require.NoError(t, err)
		assert.Equal(t, map[uint]bool{fresh.ID: true}, live, "同交易內剛建立的節點為存在")
		require.NoError(t, tx.Rollback().Error)

		injected := errors.New("race: injected read failure")
		bad := e.extraHandle(t)
		fail := func(d *gorm.DB) { _ = d.AddError(injected) }
		require.NoError(t, bad.Callback().Raw().Before("gorm:raw").Register("race:fail_raw", fail))
		require.NoError(t, bad.Callback().Row().Before("gorm:row").Register("race:fail_row", fail))
		require.NoError(t, bad.Callback().Query().Before("gorm:query").Register("race:fail_query", fail))
		live, err = reader.LiveNodesTx(bad, []uint{e.nodes["prod"]})
		require.ErrorIs(t, err, injected, "底層讀取錯誤須回錯誤，不得當成不存在")
		assert.Nil(t, live)
	})

	if !t.Failed() && os.Getenv(testgate.EnvPGDSN) != "" {
		fmt.Println("EVIDENCE dialect=postgres")
		t.Log("EVIDENCE dialect=postgres")
	}
}

// assertManagerDecisions 管理者的每次搬移判定：成功者裁決時 b 必在 prod/db 之下（不得出現「b 已在範圍外卻成功」）。
func assertManagerDecisions(t *testing.T, e *raceEnv) {
	t.Helper()
	var seen int
	for _, d := range e.rec.decisions() {
		if d.actor != e.manager {
			continue
		}
		seen++
		t.Logf("decision actor=manager watch_parent=%v err=%v", derefOr(d.watchParent), d.err)
		if d.err == nil {
			require.NotNil(t, d.watchParent)
			assert.Equal(t, e.nodes["prod/db"], *d.watchParent, "管理者裁決成功時 b 須在 prod/db 內")
		} else {
			require.NotNil(t, d.watchParent)
			assert.NotEqual(t, e.nodes["prod/db"], *d.watchParent, "拒絕只應發生在 b 已移出範圍時")
		}
	}
	require.Equal(t, 1, seen, "管理者恰有一次搬移判定")
}

func derefOr(p *uint) any {
	if p == nil {
		return "root"
	}
	return *p
}

// extraHandle 同一資料庫後端的另一個獨立連線池（用於注入讀取錯誤，不影響主連線池的回呼）。
func (e *raceEnv) extraHandle(t *testing.T) *gorm.DB {
	t.Helper()
	var db *gorm.DB
	var err error
	if e.dsn == "" {
		db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	} else {
		db, err = gorm.Open(postgres.Open(e.dsn), &gorm.Config{Logger: logger.Discard})
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	return db
}
