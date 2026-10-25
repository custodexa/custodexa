package asset_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 憑證管理歸屬的服務層夾具：正式歸屬判定器（憑證權限點標為 scoped-enforced）、真拓撲序列化鎖、
// 計數推進點的拓撲窄 port，與節點刪除服務（承接歸屬該節點的共用憑證）。
// 資料庫沿用 openRaceDB（未設 PG 連線字串為 SQLite，否則為獨立 schema 的 PostgreSQL）。
//
// 樹：co-in（其下 co-in/kid）、co-out、co-parent（其下 co-child）、co-top；
// manager 以節點範圍在 co-in 持憑證建立與範圍轉換。

const coMissingNode uint = 987654

var coPerms = []authz.Permission{authz.PermCredentialView, authz.PermCredentialCreate, authz.PermCredentialUpdate,
	authz.PermCredentialConvertScope}

// coPort 拓撲窄 port：計數權限版本推進，並可掛一次性的「取序列化鎖之前」hook。
type coPort struct {
	inner    authz.TopologyPermissionAdapter
	advances atomic.Int64
	mu       sync.Mutex
	hook     func()
}

func (p *coPort) LockTopology(tx *gorm.DB) error {
	p.mu.Lock()
	h := p.hook
	p.hook = nil
	p.mu.Unlock()
	if h != nil {
		h()
	}
	return p.inner.LockTopology(tx)
}

func (p *coPort) BeginPermissionChange(tx *gorm.DB) error { return p.inner.BeginPermissionChange(tx) }

func (p *coPort) AdvanceVersion(tx *gorm.DB) error {
	p.advances.Add(1)
	return p.inner.AdvanceVersion(tx)
}

func (p *coPort) SettlePermissionChange(tx *gorm.DB) error { return p.inner.SettlePermissionChange(tx) }

func (p *coPort) onceBeforeLock(h func()) {
	p.mu.Lock()
	p.hook = h
	p.mu.Unlock()
}

// coSink 審計落地面：failCascade 為真時，承接寫的歸屬變更審計（帶 ownership_before）寫入失敗。
type coSink struct {
	inner       port.TxSink
	failCascade *atomic.Bool
	// failReassignAt 大於 0 時，第 N 筆帶歸屬前值的審計寫入失敗（seen 為已見筆數）
	failReassignAt *atomic.Int64
	seen           *atomic.Int64
}

var errCoCascadeInjected = errors.New("co: injected cascade audit failure")

func (s coSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	if s.failCascade.Load() && strings.Contains(ev.Details, `"ownership_before"`) {
		return errCoCascadeInjected
	}
	if strings.Contains(ev.Details, `"ownership_before"`) && s.seen != nil {
		if n := s.seen.Add(1); s.failReassignAt.Load() > 0 && n == s.failReassignAt.Load() {
			return errCoCascadeInjected
		}
	}
	return s.inner.WriteInTx(tx, ev)
}

type coEnv struct {
	t           *testing.T
	db          *gorm.DB
	dsn         string
	port        *coPort
	creds       *asset.CredentialService
	groups      *asset.AssetGroupService
	failCascade atomic.Bool
	failAt      atomic.Int64
	seen        atomic.Int64
	gate        *coGate
	nodes       map[string]uint
	super       uint
	manager     uint
	seq         int
}

func newCoEnv(t *testing.T) *coEnv {
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

	e := &coEnv{t: t, db: db, dsn: scoped, nodes: map[string]uint{}, port: &coPort{}}
	for _, p := range [][2]string{{"co-in", ""}, {"co-in/kid", "co-in"}, {"co-out", ""},
		{"co-parent", ""}, {"co-child", "co-parent"}, {"co-top", ""}} {
		e.node(p[0], p[1])
	}

	cat, err := authz.CatalogueWithScopedEnforcedForTest(coPerms...)
	require.NoError(t, err)
	topo := asset.NewScopeTopologyReader()
	eval := authz.NewScopeEvaluator(cat, topo)

	e.gate = &coGate{}
	sink := coSink{inner: audit.NewTxSink(), failCascade: &e.failCascade, failReassignAt: &e.failAt, seen: &e.seen}
	svc, err := asset.NewAssetService(asset.ColumnCodecForExternalTest(t), "localhost", 4822, sink)
	require.NoError(t, err)
	svc.SetTopologyPermissionPort(e.port)
	svc.SetSecurityChangeAlertSink(swNoopAlerts{})
	svc.WithManagementAuthorizer(swAllowCredentials{}).WithSystemAlertSink(swNoopAlerts{})
	e.creds = asset.NewCredentialService(svc, asset.ColumnCodecForExternalTest(t), sink).
		WithOwnershipScope(authz.NewCredentialOwnershipScope(eval)).
		WithManagementAuthorizer(e.gate).WithSystemAlertSink(swNoopAlerts{})

	e.groups = asset.NewAssetGroupService(db, sink, authz.NewAssetAuthorizationService(db))
	e.groups.SetTopologyPermissionPort(e.port)
	e.groups.SetNodeWriteScopePort(authz.NewNodeWriteScope(eval))
	e.groups.SetNodeScopeReferencePort(authz.NewNodeScopeReferenceReader())
	e.groups.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(topo))

	e.super = e.user("co-super")
	adminRole := model.Role{Name: model.RoleAdmin}
	require.NoError(t, db.Create(&adminRole).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: e.super, RoleID: adminRole.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)

	e.manager = e.user("co-manager")
	e.seq++
	role := model.Role{Name: "co-credential-manager", DefinitionVersion: 1}
	require.NoError(t, db.Create(&role).Error)
	for _, p := range []authz.Permission{authz.PermCredentialView, authz.PermCredentialCreate,
		authz.PermCredentialConvertScope} {
		require.NoError(t, db.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(p)}).Error)
	}
	require.NoError(t, db.Create(&model.UserRole{UserID: e.manager, RoleID: role.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
		SubjectID: e.manager, RoleID: role.ID, NodeID: e.nodes["co-in"]}).Error)
	return e
}

func (e *coEnv) node(name, parent string) uint {
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

func (e *coEnv) user(name string) uint {
	e.t.Helper()
	u := model.User{Username: name, Password: "x", Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

func (e *coEnv) ctx(userID uint) context.Context {
	ctx := authz.ContextWithPrincipal(context.Background(), &authz.Principal{UserID: userID})
	ctx = context.WithValue(ctx, "userID", userID)    //nolint:staticcheck // 沿用審計 context 慣例
	ctx = context.WithValue(ctx, "username", "co-op") //nolint:staticcheck
	return ctx
}

// create 建立共用憑證；ownership 為 nil 表示未帶。
func (e *coEnv) create(actor uint, ownership *asset.CredentialOwnershipInput) (*asset.CredentialDTO, error) {
	e.seq++
	return e.creds.Create(e.ctx(actor), &asset.CreateCredentialRequest{
		Name: fmt.Sprintf("co-cred-%d", e.seq), Username: "ops", ProtocolFamily: model.ProtocolFamilySSH,
		Password: fmt.Sprintf("co-fixture-%d", e.seq), Ownership: ownership,
	})
}

func onNode(id uint) *asset.CredentialOwnershipInput {
	return &asset.CredentialOwnershipInput{Kind: model.CredentialOwnerNode, NodeID: &id}
}

func onGlobal() *asset.CredentialOwnershipInput {
	return &asset.CredentialOwnershipInput{Kind: model.CredentialOwnerGlobal}
}

// row 憑證列（含軟刪）。
func (e *coEnv) row(id uint) model.Credential {
	e.t.Helper()
	var c model.Credential
	require.NoError(e.t, e.db.Unscoped().Where("id = ?", id).First(&c).Error)
	return c
}

func (e *coEnv) ownerOf(id uint) (string, *uint) {
	c := e.row(id)
	kind := ""
	if c.OwnerKind != nil {
		kind = *c.OwnerKind
	}
	return kind, c.OwnerNodeID
}

func (e *coEnv) credentialCount() int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.Credential{}).Count(&n).Error)
	return n
}

// ownershipAudits 該憑證帶歸屬欄的審計 details。
func (e *coEnv) ownershipAudits(id uint) []string {
	e.t.Helper()
	var logs []model.AuditLog
	require.NoError(e.t, e.db.Where("resource = ? AND resource_id = ?", string(model.ResourceCredential), id).
		Order("id").Find(&logs).Error)
	var out []string
	for _, l := range logs {
		if strings.Contains(l.Details, `"ownership"`) {
			out = append(out, l.Details)
		}
	}
	return out
}

// dedicated 建一筆共用憑證後掛到一台資產，再轉為專用（歸屬隨資產）。
func (e *coEnv) dedicated() uint {
	e.t.Helper()
	dto, err := e.create(e.super, nil)
	require.NoError(e.t, err)
	e.seq++
	a := model.Asset{Name: fmt.Sprintf("co-asset-%d", e.seq), Protocol: model.ProtocolSSH,
		Host: fmt.Sprintf("10.67.%d.%d", e.seq/250, e.seq%250+1), Port: 22, CreatedBy: e.super, Active: true}
	require.NoError(e.t, e.db.Create(&a).Error)
	require.NoError(e.t, e.db.Create(&model.AssetAccount{AssetID: a.ID, CredentialID: dto.ID, Username: "ops"}).Error)
	_, err = e.creds.ConvertScope(e.ctx(e.super), dto.ID,
		&asset.ConvertCredentialScopeRequest{Scope: model.CredentialScopeDedicated})
	require.NoError(e.t, err)
	return dto.ID
}

// deny 範圍拒絕經共用出口寫出的狀態碼與回應原文。
func deny(t *testing.T, err error) (int, string) {
	t.Helper()
	var denied *authz.ErrScopeDenied
	require.True(t, errors.As(err, &denied), "應為範圍拒絕值，實得 %v", err)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/credentials", nil)
	middleware.RespondScopeDenied(c, denied)
	return w.Code, w.Body.String()
}
