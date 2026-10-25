package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
	"github.com/custodexa/backend/internal/testgate"
)

// 憑證庫範圍化的 HTTP 夾具：判定器、管理授權轉接頭與投影來源與正式組裝同形，
// 憑證與掛載直接寫表，指派直接寫表；每個請求自資料庫重解主體。
// 範圍外節點與資產的名稱一律以 zz-sc-out 起頭，供回應原文的洩漏檢查。

var scCredentialPerms = []authz.Permission{
	authz.PermCredentialView, authz.PermCredentialCreate, authz.PermCredentialUpdate,
	authz.PermCredentialSetSecret, authz.PermCredentialRotate, authz.PermCredentialConvertScope,
	authz.PermCredentialDetach, authz.PermCredentialDelete, authz.PermCredentialBind,
}

// scRotations 輪替引擎替身：只回應詳情與進度查詢需要的方法。
type scRotations struct {
	api.CredentialRotationServiceInterface
}

func (scRotations) AggregateState(uint) (string, error)    { return "idle", nil }
func (scRotations) UnsettledRotationID(uint) (uint, error) { return 0, nil }
func (scRotations) Rotation(uint, uint) (*model.CredentialRotation, error) {
	return nil, asset.ErrCredentialRotationNotFound
}

// scStatus 輪替狀態判定替身：識別為偶數者算逾期，其餘合規。
type scStatus struct{}

func (scStatus) CredentialRotationStatus(id uint, _ time.Time) (string, error) {
	if id%2 == 0 {
		return asset.BucketOverdue, nil
	}
	return asset.BucketCompliant, nil
}

// scTopologyPort 拓撲窄 port：轉呼叫 inner 並計數四個動作（掛載只取序列化鎖、不推進權限版本的證據）。
type scTopologyPort struct {
	inner    asset.TopologyPermissionPort
	locks    atomic.Int64
	begins   atomic.Int64
	advances atomic.Int64
}

func (p *scTopologyPort) LockTopology(tx *gorm.DB) error {
	p.locks.Add(1)
	return p.inner.LockTopology(tx)
}

func (p *scTopologyPort) BeginPermissionChange(tx *gorm.DB) error {
	p.begins.Add(1)
	return p.inner.BeginPermissionChange(tx)
}

func (p *scTopologyPort) AdvanceVersion(tx *gorm.DB) error {
	p.advances.Add(1)
	return p.inner.AdvanceVersion(tx)
}

func (p *scTopologyPort) SettlePermissionChange(tx *gorm.DB) error {
	return p.inner.SettlePermissionChange(tx)
}

// scTopologyCounts 拓撲 port 的計數快照。
type scTopologyCounts struct{ locks, begins, advances int64 }

func (p *scTopologyPort) counts() scTopologyCounts {
	return scTopologyCounts{locks: p.locks.Load(), begins: p.begins.Load(), advances: p.advances.Load()}
}

type scEnv struct {
	*saEnv
	adapter *credentialManagementAdapter
	topo    *scTopologyPort
	seqCred int
}

func newSCEnv(t *testing.T) *scEnv {
	t.Helper()
	return newSCEnvOn(t, newSAEnv(t), noopTopologyPort{})
}

// newSCEnvPG 同一組服務建在 PostgreSQL 的獨立 schema（正式 migration），拓撲序列化鎖用正式實作。
// 需 TEST_PG_DSN（未設時略過，REQUIRE_INTEGRATION=1 時轉失敗）。
func newSCEnvPG(t *testing.T, schema string) *scEnv {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin := pwloOpen(t, dsn)
	drop := "DROP SCHEMA IF EXISTS " + schema + " CASCADE"
	require.NoError(t, admin.Exec(drop).Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", schema, err)
		}
	})
	db := pwloOpen(t, dsn+" search_path="+schema)
	require.Equal(t, "postgres", db.Dialector.Name(), "實際 dialector 必須是 postgres")
	fmt.Println("EVIDENCE dialect=postgres")
	t.Log("EVIDENCE dialect=postgres")
	gin.SetMode(gin.TestMode)
	base := fieldCapEnvOn(t, db)
	require.NoError(t, database.RunMigrations(), "正式 migration 失敗")
	return newSCEnvOn(t, newSAEnvOn(t, newMarkerEnvOn(t, base, "")), authz.TopologyPermissionAdapter{})
}

func newSCEnvOn(t *testing.T, base *saEnv, topo asset.TopologyPermissionPort) *scEnv {
	t.Helper()
	if base.db.Dialector.Name() != "postgres" {
		require.NoError(t, base.db.AutoMigrate(&model.CredentialRotation{}, &model.CredentialRotationMember{},
			&model.AssetHostKey{}, &model.CredentialImpactConfirmation{}))
	}
	counted := &scTopologyPort{inner: topo}
	base.assets.SetTopologyPermissionPort(counted)
	cat, err := authz.CatalogueWithScopedEnforcedForTest(append(append([]authz.Permission{}, saPerms...), scCredentialPerms...)...)
	require.NoError(t, err)
	base.cat = cat
	base.eval = authz.NewScopeEvaluator(cat, asset.NewScopeTopologyReader(), authz.CredentialScopeResolver())
	ad := newCredentialManagementAdapter(authz.NewResolver(base.db)).withScope(base.eval, base.db)
	base.assets.WithManagementAuthorizer(ad)
	base.creds = asset.NewCredentialService(base.assets, base.codec, audit.NewTxSink()).
		WithManagementAuthorizer(ad).WithSystemAlertSink(noopAlertSink{}).
		WithOwnershipScope(authz.NewCredentialOwnershipScope(base.eval)).
		WithScopeSource(authz.NewCredentialScopeReader(base.eval, base.db))
	return &scEnv{saEnv: base, adapter: ad, topo: counted}
}

// cred 直接寫一筆共用憑證；nodeID 為 nil 時歸屬全域。
func (e *scEnv) cred(name string, nodeID *uint) uint {
	e.t.Helper()
	kind := model.CredentialOwnerGlobal
	if nodeID != nil {
		kind = model.CredentialOwnerNode
	}
	c := model.Credential{Name: &name, Scope: model.CredentialScopeShared, Username: "u-" + name,
		SecretType: model.ChangeSecretTypePassword, AuthMethod: "sql",
		ProtocolFamily: model.ProtocolFamilySSH, OwnerKind: &kind, OwnerNodeID: nodeID}
	require.NoError(e.t, e.db.Create(&c).Error)
	return c.ID
}

// dedicated 直接寫一筆專用憑證並掛到資產。
func (e *scEnv) dedicated(assetID uint) uint {
	e.t.Helper()
	e.seqCred++
	kind := model.CredentialOwnerAsset
	c := model.Credential{Scope: model.CredentialScopeDedicated, Username: fmt.Sprintf("ded%d", e.seqCred),
		SecretType: model.ChangeSecretTypePassword, AuthMethod: "sql",
		ProtocolFamily: model.ProtocolFamilySSH, OwnerKind: &kind}
	require.NoError(e.t, e.db.Create(&c).Error)
	e.mount(c.ID, assetID)
	return c.ID
}

// mount 把憑證掛到資產，回掛載（帳號）識別。
func (e *scEnv) mount(credID, assetID uint) uint {
	e.t.Helper()
	var c model.Credential
	require.NoError(e.t, e.db.First(&c, credID).Error)
	acc := model.AssetAccount{AssetID: assetID, CredentialID: credID, Username: c.Username, AuthMethod: "sql"}
	require.NoError(e.t, e.db.Create(&acc).Error)
	return acc.ID
}

func (e *scEnv) nodeID(name string) *uint {
	id := e.nodes[name]
	return &id
}

// grant 以自訂角色在指定節點授權。
func (e *scEnv) grant(userID uint, nodes []string, perms ...authz.Permission) {
	e.t.Helper()
	e.grantNodes(userID, e.role(perms...), nodes...)
}

func (e *scEnv) scRouter(uid uint) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	h := api.NewCredentialHandler(e.creds, scRotations{}, scStatus{})
	g := r.Group("/api/v1/credentials")
	reg := middleware.EnforceRegistry()
	g.GET("", reg, h.List)
	g.POST("/ownership", reg, h.ReassignOwnership)
	g.GET("/:id", reg, h.Get)
	g.PUT("/:id", reg, h.Update)
	g.DELETE("/:id", reg, h.Delete)
	g.POST("/:id/bindings", reg, h.Bind)
	g.DELETE("/:id/bindings/:accountId", reg, h.Unbind)
	g.POST("/:id/scope", reg, h.ConvertScope)
	g.POST("/:id/secret", reg, h.SetSecret)
	g.POST("/:id/impact-confirmations", reg, h.ConfirmImpact)
	g.GET("/:id/rotations/:rid", reg, h.GetRotation)
	r.PUT("/api/v1/assets/:id/accounts/:accountId/credential", reg, h.RebindAccount)
	return r
}

func (e *scEnv) call(uid uint, method, path, body string) (int, string) {
	e.t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	e.scRouter(uid).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// scList 列表回應。
type scList struct {
	Data  []map[string]any `json:"data"`
	Total int              `json:"total"`
	raw   string
}

func (l scList) ids() map[uint]bool {
	out := map[uint]bool{}
	for _, r := range l.Data {
		out[uint(r["id"].(float64))] = true
	}
	return out
}

func (l scList) row(id uint) map[string]any {
	for _, r := range l.Data {
		if uint(r["id"].(float64)) == id {
			return r
		}
	}
	return nil
}

func (e *scEnv) list(uid uint, query string) scList {
	e.t.Helper()
	path := "/api/v1/credentials"
	if query != "" {
		path += "?" + query
	}
	code, raw := e.call(uid, "GET", path, "")
	require.Equal(e.t, http.StatusOK, code, raw)
	var out scList
	require.NoError(e.t, json.Unmarshal([]byte(raw), &out), raw)
	out.raw = raw
	return out
}

func credPath(id uint) string { return fmt.Sprintf("/api/v1/credentials/%d", id) }

// scOutCountJSON 範圍外台數欄經揭露登錄轉出後的序列化結果。
func scOutCountJSON(n int) string {
	raw, _ := json.Marshal(disclosure.AssetCountValue{Value: disclosure.Count(disclosure.OutOfScopeAssetCount, n)})
	return string(raw)
}

// outCountOf 回應物件上範圍外台數欄的序列化結果；缺欄回空字串。
func outCountOf(m map[string]any) string {
	v, ok := m[disclosure.FieldOutOfScopeAssetCount]
	if !ok {
		return ""
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

func idsOf(m map[uint]bool) []uint {
	out := make([]uint, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	return out
}

func disclosureFieldName() string { return disclosure.FieldOutOfScopeAssetCount }
