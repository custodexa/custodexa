package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 服務在寫入交易內判出的範圍拒絕（掛在 TestScopeDenialOutlet）。
//
// 範圍化主體更新範圍內資產、把掛載改到範圍外：登錄閘以改前狀態放行，服務在交易內寫入新掛載後
// 以同一判定器重判，得到範圍拒絕值、整筆回滾，handler 以 errors.As 交共用出口。回應須與
// 3.1 的範圍外案例（同一主體更新範圍外資產）逐位元相同。SQLite 與 PostgreSQL 各跑一次；
// PostgreSQL 子案例需 TEST_PG_DSN（未設時略過，REQUIRE_INTEGRATION=1 時轉失敗）。

const scopeTxSchema = "scope_tx_recheck"

func runScopeTxRecheckSubtests(t *testing.T, baselines map[string]scopeOutletProbe) {
	t.Run("SQLite", func(t *testing.T) { runScopeTxRecheckHTTPCases(t, newScopeGateEnv(t), baselines) })
	t.Run("PostgreSQL", func(t *testing.T) { runScopeTxRecheckHTTPCases(t, newScopeGatePGEnv(t), baselines) })
	t.Run("重判函式的回傳值", func(t *testing.T) { runScopeTxRecheckValueCases(t, newScopeGateEnv(t)) })
}

// newScopeGatePGEnv 獨立 schema、正式 migration，再種入與 SQLite 相同的節點、資產與主體。
func newScopeGatePGEnv(t *testing.T) *scopeGateEnv {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin := pwloOpen(t, dsn)
	drop := "DROP SCHEMA IF EXISTS " + scopeTxSchema + " CASCADE"
	require.NoError(t, admin.Exec(drop).Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+scopeTxSchema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", scopeTxSchema, err)
		}
	})
	db := pwloOpen(t, dsn+" search_path="+scopeTxSchema)
	require.Equal(t, "postgres", db.Dialector.Name(), "實際 dialector 必須是 postgres")
	gin.SetMode(gin.TestMode)
	base := fieldCapEnvOn(t, db)
	require.NoError(t, database.RunMigrations(), "正式 migration 失敗")
	return seedScopeGateEnv(t, &scopeGateEnv{markerEnv: &markerEnv{fieldCapEnv: base, auth: markerAuthorizer{env: base}}})
}

func (e *scopeGateEnv) mountsOf(t *testing.T, assetID uint) []uint {
	t.Helper()
	var ids []uint
	require.NoError(t, e.db.Raw("SELECT node_id FROM asset_nodes WHERE asset_id = ? ORDER BY node_id", assetID).Scan(&ids).Error)
	return ids
}

func runScopeTxRecheckHTTPCases(t *testing.T, env *scopeGateEnv, baselines map[string]scopeOutletProbe) {
	mount := env.mount(env.gate)
	path := func(id uint) string { return "/api/v1/assets/" + strconv.Itoa(int(id)) }
	moveTo := func(node uint) string { return fmt.Sprintf(`{"node_ids":[%d]}`, node) }

	// 3.1 範圍外案例：同一主體更新範圍外資產（登錄閘判出範圍拒絕）
	ref := env.send(t, env.scoped, env.scopedUID, mount, "PUT", path(env.assetOut), `{"name":"renamed"}`)
	require.Equal(t, http.StatusNotFound, ref.code, ref.raw)
	require.Equal(t, baselines["asset_update"].raw, ref.raw, "3.1 範圍外案例須等於全域主體打不存在")

	t.Run("交易內先把掛載改到範圍外再判定", func(t *testing.T) {
		before := env.mountsOf(t, env.assetIn)
		require.Equal(t, []uint{env.nodeIn}, before)
		got := env.send(t, env.scoped, env.scopedUID, mount, "PUT", path(env.assetIn), moveTo(env.nodeOut))
		assert.Equal(t, ref.code, got.code, got.raw)
		assert.Equal(t, ref.raw, got.raw, "須與 3.1 範圍外案例逐位元相同")
		assert.Equal(t, baselines["asset_update"].raw, got.raw, "須與全域主體打不存在逐位元相同")
		assertScopeDeniedAudit(t, "交易內範圍拒絕", got)
		for _, n := range env.fixtureNames {
			assert.NotContains(t, got.raw, n, "回應不得含 fixture 名稱")
		}
		assert.True(t, got.tablesSame, "交易須回滾：業務表整表內容不變")
		assert.Equal(t, before, env.mountsOf(t, env.assetIn), "回滾後掛載不變")
	})

	t.Run("交易內重判放行", func(t *testing.T) {
		// 範圍內改名、範圍內重掛同一節點：登錄閘與交易內重判皆放行
		got := env.send(t, env.scoped, env.scopedUID, mount, "PUT", path(env.assetIn), `{"name":"zz-gate-renamed"}`)
		assert.Equal(t, http.StatusOK, got.code, got.raw)
		assert.Equal(t, model.StatusSuccess, got.audit.Status)
		got = env.send(t, env.scoped, env.scopedUID, mount, "PUT", path(env.assetIn), moveTo(env.nodeIn))
		assert.Equal(t, http.StatusOK, got.code, got.raw)
		assert.Equal(t, []uint{env.nodeIn}, env.mountsOf(t, env.assetIn))
		// 全域主體移到範圍外：全域來源不解析目標，放行且掛載確實改變
		got = env.send(t, env.global, env.globalUID, mount, "PUT", path(env.assetIn), moveTo(env.nodeOut))
		assert.Equal(t, http.StatusOK, got.code, got.raw)
		assert.Equal(t, []uint{env.nodeOut}, env.mountsOf(t, env.assetIn))
	})
}

// captureTxRecheck 經登錄閘取出本請求的交易內重判函式（handler 端的取法）。
func (e *scopeGateEnv) captureTxRecheck(t *testing.T, gate *middleware.ScopeGate, p *authz.Principal, assetID uint) func(*gorm.DB) error {
	t.Helper()
	var fn func(*gorm.DB) error
	reached := false
	r := gin.New()
	r.Use(func(c *gin.Context) { middleware.SetPrincipal(c, p); c.Next() })
	r.PUT("/api/v1/assets/:id", middleware.EnforceRegistry(gate), func(c *gin.Context) {
		fn, reached = middleware.TxScopeRecheck(c), true
		c.Status(http.StatusNoContent)
	})
	req := httptest.NewRequest("PUT", "/api/v1/assets/"+strconv.Itoa(int(assetID)), strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.True(t, reached, "登錄閘須放行：%d %s", w.Code, w.Body.String())
	return fn
}

func runScopeTxRecheckValueCases(t *testing.T, env *scopeGateEnv) {
	inTx := func(t *testing.T, body func(tx *gorm.DB)) {
		tx := env.db.Begin()
		require.NoError(t, tx.Error)
		defer tx.Rollback()
		body(tx)
	}

	t.Run("放行時回 nil 介面", func(t *testing.T) {
		fn := env.captureTxRecheck(t, env.gate, env.scoped, env.assetIn)
		require.NotNil(t, fn)
		inTx(t, func(tx *gorm.DB) {
			err := fn(tx)
			// 不用 assert.Nil：它把帶型別的 nil 指標也當成 nil
			assert.True(t, err == nil, "拒絕值為 nil 時回傳的 error 必須是 nil 介面，實得 %T(%#v)", err, err)
		})
	})

	t.Run("交易內改掛載後回判定器給的拒絕值", func(t *testing.T) {
		fn := env.captureTxRecheck(t, env.gate, env.scoped, env.assetIn)
		inTx(t, func(tx *gorm.DB) {
			require.NoError(t, tx.Exec("UPDATE asset_nodes SET node_id = ? WHERE asset_id = ?", env.nodeOut, env.assetIn).Error)
			err := fn(tx)
			var denied *authz.ErrScopeDenied
			require.True(t, errors.As(err, &denied), "須為範圍拒絕值，實得 %T(%v)", err, err)
			require.NotNil(t, denied)
			assert.Equal(t, authz.ScopeTargetAsset, denied.Kind)
			assert.Equal(t, authz.ScopeLayerAsset, denied.Layer)
			assert.Equal(t, authz.ScopeReasonOutOfScope, denied.Reason)
		})
		assert.Equal(t, []uint{env.nodeIn}, env.mountsOf(t, env.assetIn), "回滾後掛載不變")
	})

	t.Run("交易內能力被收回回能力拒絕", func(t *testing.T) {
		fn := env.captureTxRecheck(t, env.gate, env.scoped, env.assetIn)
		inTx(t, func(tx *gorm.DB) {
			require.NoError(t, tx.Exec("DELETE FROM role_permissions WHERE permission_key = ?", string(authz.PermAssetUpdate)).Error)
			err := fn(tx)
			var capDenied *middleware.TxCapabilityDenied
			require.True(t, errors.As(err, &capDenied), "須為能力拒絕，實得 %T(%v)", err, err)
			assert.Equal(t, authz.ScopeDenyCapability, capDenied.Result.Outcome)
			var denied *authz.ErrScopeDenied
			assert.False(t, errors.As(err, &denied), "能力拒絕不得帶範圍拒絕值")
		})
	})

	t.Run("未經範圍判定的請求不重判", func(t *testing.T) {
		only := middleware.NewScopeGate(env.db, authz.NewScopeEvaluator(env.cat, nil), scopeGateDecls()[0:1])
		assert.Nil(t, env.captureTxRecheck(t, only, env.scoped, env.assetIn), "登錄項未宣告目標時不留重判函式")
		assert.Nil(t, env.captureTxRecheck(t, nil, env.global, env.assetIn))
	})
}
