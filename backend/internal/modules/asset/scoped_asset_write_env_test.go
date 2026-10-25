package asset_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產寫入範圍（刪停規則、競態、拓撲審計）的服務層夾具：真判定器、真拓撲序列化鎖、真涵蓋快照。
// 資料庫沿用 openRaceDB（未設 PG 連線字串為 SQLite，否則為獨立 schema 的 PostgreSQL）。
// 樹：sw-a、sw-b、sw-c、sw-far；manager 以節點範圍持資產檢視、編輯、刪除於 sw-a。

var swPerms = []authz.Permission{authz.PermAssetView, authz.PermAssetCreate, authz.PermAssetUpdate,
	authz.PermAssetDelete, authz.PermAssetTest}

// swDecision 一次寫入判定（交易內、判定當下）的操作者、操作、歸屬與結果。
type swDecision struct {
	actor   uint
	op      asset.AssetWriteOp
	current []uint
	err     error
}

// swRecorder 包住正式的寫入範圍判定，記每筆裁決當下的歸屬與結果。
type swRecorder struct {
	inner asset.AssetWriteScopePort
	mu    sync.Mutex
	recs  []swDecision
}

func (r *swRecorder) AuthorizeAssetCreate(ctx context.Context, tx *gorm.DB, nodeIDs []uint) error {
	return r.inner.AuthorizeAssetCreate(ctx, tx, nodeIDs)
}

func (r *swRecorder) AuthorizeAssetWrite(ctx context.Context, tx *gorm.DB, op asset.AssetWriteOp, assetID uint, current []uint) error {
	err := r.inner.AuthorizeAssetWrite(ctx, tx, op, assetID, current)
	var actor uint
	if p := authz.PrincipalFromContext(ctx); p != nil {
		actor = p.UserID
	}
	r.mu.Lock()
	r.recs = append(r.recs, swDecision{actor: actor, op: op, current: append([]uint(nil), current...), err: err})
	r.mu.Unlock()
	return err
}

func (r *swRecorder) MergeAssetNodes(ctx context.Context, tx *gorm.DB, assetID uint, current, requested []uint) ([]uint, error) {
	return r.inner.MergeAssetNodes(ctx, tx, assetID, current, requested)
}

func (r *swRecorder) AccessPolicyCoversNodes(ctx context.Context, tx *gorm.DB, nodeSets [][]uint) ([]bool, error) {
	return r.inner.AccessPolicyCoversNodes(ctx, tx, nodeSets)
}

func (r *swRecorder) decisions(actor uint, op asset.AssetWriteOp) []swDecision {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []swDecision
	for _, d := range r.recs {
		if d.actor == actor && d.op == op {
			out = append(out, d)
		}
	}
	return out
}

// swTerminator 收線替身：記收線次數。
type swTerminator struct{ calls atomic.Int64 }

func (s *swTerminator) TerminateByAsset(uint, string) (int, error) {
	s.calls.Add(1)
	return 0, nil
}

// swSink 審計落地面：fail 為真時寫入失敗（整筆回滾）。
type swSink struct {
	inner port.TxSink
	fail  *atomic.Bool
}

var errSwAuditInjected = errors.New("sw: injected audit failure")

func (s swSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	if s.fail.Load() {
		return errSwAuditInjected
	}
	return s.inner.WriteInTx(tx, ev)
}

// swCoverage 涵蓋快照：fail 為真時回錯誤。
type swCoverage struct {
	inner asset.CoverageSnapshotPort
	fail  *atomic.Bool
}

var errSwCoverageInjected = errors.New("sw: injected coverage failure")

func (c swCoverage) CoverageSnapshot(tx *gorm.DB, ids []uint) (asset.CoverageSnapshot, error) {
	if c.fail.Load() {
		return asset.CoverageSnapshot{}, errSwCoverageInjected
	}
	return c.inner.CoverageSnapshot(tx, ids)
}

// swAllowCredentials 憑證管理關卡替身：一律放行（本夾具不測憑證能力）。
type swAllowCredentials struct{}

func (swAllowCredentials) AuthorizeCredentialManagement(context.Context, *gorm.DB,
	asset.CredentialManagementActor, asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	return asset.CredentialManagementDecision{Allowed: true, AuthzVersion: 1}, nil
}

type swNoopAlerts struct{}

func (swNoopAlerts) RaiseInTx(*gorm.DB, port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, nil
}

type swEnv struct {
	t         *testing.T
	db        *gorm.DB
	dsn       string
	svc       *asset.AssetService
	creds     *asset.CredentialService
	rec       *swRecorder
	term      *swTerminator
	auditFail atomic.Bool
	covFail   atomic.Bool
	covPort   swCoverage
	nodes     map[string]uint
	super     uint
	manager   uint
	seq       int
}

func newSwEnv(t *testing.T) *swEnv {
	t.Helper()
	db, scoped := openRaceDB(t)
	first, tail := raceModels()
	require.NoError(t, db.AutoMigrate(first...))
	require.NoError(t, db.AutoMigrate(tail...))
	require.NoError(t, db.AutoMigrate(&model.AssetAccount{}, &model.Credential{}, &model.CredentialSecretVersion{},
		&model.ChangeSecretCandidate{}, &model.AssetHostKey{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	e := &swEnv{t: t, db: db, dsn: scoped, nodes: map[string]uint{}, term: &swTerminator{}}
	for _, n := range []string{"sw-a", "sw-b", "sw-c", "sw-far"} {
		g := model.AssetGroup{Name: n}
		require.NoError(t, db.Create(&g).Error)
		e.nodes[n] = g.ID
	}
	cat, err := authz.CatalogueWithScopedEnforcedForTest(swPerms...)
	require.NoError(t, err)
	topo := asset.NewScopeTopologyReader()
	eval := authz.NewScopeEvaluator(cat, topo)

	svc, err := asset.NewAssetService(asset.ColumnCodecForExternalTest(t), "localhost", 4822,
		swSink{inner: audit.NewTxSink(), fail: &e.auditFail})
	require.NoError(t, err)
	svc.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	svc.SetSecurityChangeAlertSink(swNoopAlerts{})
	svc.WithManagementAuthorizer(swAllowCredentials{}).WithSystemAlertSink(swNoopAlerts{})
	svc.SetAuthorizationRevoker(authz.NewAssetAuthorizationService(db))
	svc.SetSessionTerminator(e.term)
	e.rec = &swRecorder{inner: authz.NewAssetWriteScope(eval)}
	svc.SetAssetWriteScopePort(e.rec)
	e.covPort = swCoverage{inner: authz.NewTopologyCoverageReader(topo), fail: &e.covFail}
	svc.SetCoverageSnapshotPort(e.covPort)
	e.svc = svc
	e.creds = asset.NewCredentialService(svc, asset.ColumnCodecForExternalTest(t), audit.NewTxSink()).WithOwnershipScope(globalOwnershipScopeForTest{}).
		WithManagementAuthorizer(swAllowCredentials{}).WithSystemAlertSink(swNoopAlerts{})

	e.super = e.user("sw-super")
	adminRole := model.Role{Name: model.RoleAdmin}
	require.NoError(t, db.Create(&adminRole).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: e.super, RoleID: adminRole.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	e.manager = e.user("sw-manager")
	e.grantNodes(e.manager, e.role(authz.PermAssetView, authz.PermAssetUpdate, authz.PermAssetDelete), "sw-a")
	return e
}

func (e *swEnv) user(name string) uint {
	e.t.Helper()
	u := model.User{Username: name, Password: "x", Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

func (e *swEnv) role(perms ...authz.Permission) uint {
	e.t.Helper()
	e.seq++
	r := model.Role{Name: fmt.Sprintf("sw-role-%d", e.seq), DefinitionVersion: 1}
	require.NoError(e.t, e.db.Create(&r).Error)
	for _, p := range perms {
		require.NoError(e.t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error)
	}
	return r.ID
}

func (e *swEnv) grantGlobal(userID, roleID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
}

func (e *swEnv) grantNodes(userID, roleID uint, nodes ...string) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	for _, n := range nodes {
		require.NoError(e.t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
			SubjectID: userID, RoleID: roleID, NodeID: e.nodes[n]}).Error)
	}
}

// ctx 操作者 ctx：主體（交易內重解）與審計用的操作者資訊。
func (e *swEnv) ctx(userID uint) context.Context {
	ctx := authz.ContextWithPrincipal(context.Background(), &authz.Principal{UserID: userID})
	ctx = context.WithValue(ctx, "userID", userID)    //nolint:staticcheck // 沿用審計 context 慣例
	ctx = context.WithValue(ctx, "username", "sw-op") //nolint:staticcheck
	return asset.WithFieldCapability(ctx, func(string) asset.FieldCapGrant { return asset.FieldCapViaCompat })
}

// asset 直接寫表建資產並掛到節點（以名稱）。
func (e *swEnv) asset(name string, nodes ...string) uint {
	e.t.Helper()
	e.seq++
	a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: fmt.Sprintf("10.66.%d.%d", e.seq/250, e.seq%250+1),
		Port: 22, CreatedBy: e.super, Active: true}
	require.NoError(e.t, e.db.Create(&a).Error)
	for _, n := range nodes {
		require.NoError(e.t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: e.nodes[n]}).Error)
	}
	return a.ID
}

func (e *swEnv) ids(names ...string) []uint {
	out := make([]uint, 0, len(names))
	for _, n := range names {
		out = append(out, e.nodes[n])
	}
	return out
}

// mounted 資產目前的歸屬（節點名稱，排序）。
func (e *swEnv) mounted(assetID uint) []string {
	e.t.Helper()
	var rows []model.AssetNode
	require.NoError(e.t, e.db.Where("asset_id = ?", assetID).Find(&rows).Error)
	return e.names(func() []uint {
		out := make([]uint, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.NodeID)
		}
		return out
	}())
}

func (e *swEnv) names(ids []uint) []string {
	byID := map[uint]string{}
	for n, id := range e.nodes {
		byID[id] = n
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, byID[id])
	}
	sort.Strings(out)
	return out
}

// live 資產是否存在（未刪除）與是否啟用。
func (e *swEnv) live(assetID uint) (exists, active bool) {
	e.t.Helper()
	var a model.Asset
	err := e.db.Where("id = ?", assetID).Limit(1).Find(&a).Error
	require.NoError(e.t, err)
	return a.ID == assetID, a.Active
}

func (e *swEnv) del(actor, assetID uint) func() error {
	return func() error { return e.svc.Delete(e.ctx(actor), assetID) }
}

func (e *swEnv) disable(actor, assetID uint) func() error {
	return func() error {
		off := false
		_, err := e.svc.Update(e.ctx(actor), assetID, &asset.UpdateAssetRequest{Active: &off})
		return err
	}
}

func (e *swEnv) setNodes(actor, assetID uint, nodes ...string) func() error {
	return func() error {
		ids := e.ids(nodes...)
		_, err := e.svc.Update(e.ctx(actor), assetID, &asset.UpdateAssetRequest{NodeIDs: &ids})
		return err
	}
}
