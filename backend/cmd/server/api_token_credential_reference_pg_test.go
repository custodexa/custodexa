package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 以 API token 引用既有憑證的共同授權判定（PostgreSQL）：同一組服務建在真 PostgreSQL 上，能力與節點範圍的
// 判定走正式的判定器與交易內重驗。token 的主體帶角色限定（只保留 token 授權的角色），對照帳號只持有那些角色。
// 每一次呼叫都在各自新建的目標上進行（目標資產、憑證與既有掛載），比對結果的形狀：回應狀態、錯誤碼、
// 資產與掛載的增減、掛載是否指向所引用的憑證；token 成功掛載時多出恰一則告警（另驗），人類請求沒有。

type pgRefSubject struct {
	userID  uint
	filter  *authz.RoleFilter // 非 nil＝以 API token 認證、主體帶角色限定
	tokenID uint
}

type pgRefEnv struct {
	*scEnv
	accounts *asset.AssetAccountService
	seq      int
}

func (e *pgRefEnv) router(s pgRefSubject) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, s.userID, authz.TokenFacts{RoleFilter: s.filter})
		require.NoError(e.t, err)
		ctx := c.Request.Context()
		if s.filter != nil {
			ctx = model.WithRequestCredential(ctx, model.RequestCredentialAPIToken)
			ctx = model.WithAPITokenRef(ctx, model.APITokenRef{ID: s.tokenID, Name: fmt.Sprintf("pg-token-%d", s.tokenID)})
		} else {
			ctx = model.WithRequestCredential(ctx, model.RequestCredentialHumanSession)
		}
		c.Request = c.Request.WithContext(ctx)
		middleware.SetPrincipal(c, p)
		c.Set("userID", s.userID)
		c.Set("username", fmt.Sprintf("u%d", s.userID))
		c.Next()
	})
	reg := middleware.EnforceRegistry()
	gate := middleware.NewScopeGate(e.db, e.eval, authz.RouteScopeDeclarations())
	ah := api.NewAssetHandler(e.assets, e.authzSvc, nil)
	ah.SetAssetScope(authz.NewAssetScopeReader(e.eval, e.db))
	r.POST("/api/v1/assets", reg, ah.Create)
	r.POST("/api/v1/assets/import/preview", reg, ah.PreviewImport)
	r.POST("/api/v1/assets/import", reg, ah.Import)
	acc := api.NewAssetAccountHandler(e.accounts, e.authzSvc, gate)
	acc.SetAssetManagementVisibility(authz.NewAssetScopeReader(e.eval, e.db))
	acc.SetAccountCredentialScope(authz.NewCredentialScopeReader(e.eval, e.db))
	acc.SetAccountRowActions(asset.NewAccountRowActionJudge(e.creds, e.accounts))
	r.POST("/api/v1/assets/:id/accounts", middleware.EnforceRegistry(gate), acc.Create)
	ch := api.NewCredentialHandler(e.creds, scRotations{}, scStatus{})
	ch.SetAccountRowProjector(authz.NewCredentialScopeReader(e.eval, e.db), nil)
	r.POST("/api/v1/credentials/:id/bindings", reg, ch.Bind)
	r.PUT("/api/v1/assets/:id/accounts/:accountId/credential", reg, ch.RebindAccount)
	return r
}

func (e *pgRefEnv) call(s pgRefSubject, method, path string, body any) (int, map[string]any) {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.router(s).ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (e *pgRefEnv) count(table, where string, args ...any) int64 {
	var n int64
	q := e.db.Table(table)
	if where != "" {
		q = q.Where(where, args...)
	}
	require.NoError(e.t, q.Count(&n).Error)
	return n
}

// pgRefTargets 一次呼叫專用的目標：節點 1 上一台資產（帶一筆專用掛載供更換憑證）與三筆共用憑證。
type pgRefTargets struct {
	asset, account                 uint
	credGlobal, credNode1, credOut uint
	suffix                         string
}

func (e *pgRefEnv) targets() pgRefTargets {
	e.seq++
	sfx := fmt.Sprintf("%03d", e.seq)
	a := e.asset("pg-ref-host-"+sfx, "n1")
	ded := e.dedicated(a)
	var acc model.AssetAccount
	require.NoError(e.t, e.db.Where("credential_id = ?", ded).First(&acc).Error)
	return pgRefTargets{
		asset: a, account: acc.ID, suffix: sfx,
		credGlobal: e.cred("pg-ref-g-"+sfx, nil),
		credNode1:  e.cred("pg-ref-n1-"+sfx, e.nodeID("n1")),
		credOut:    e.cred("pg-ref-n2-"+sfx, e.nodeID("n2")),
	}
}

// pgRefOutcome 一次呼叫的結果形狀（不含各自目標的識別與名稱）。
type pgRefOutcome struct {
	Status        int
	Code          string
	ImportOK      any
	AssetsDelta   int64
	AccountsDelta int64
	Bound         bool
}

func TestAPITokenCredentialReferenceParityPG(t *testing.T) {
	sc := newSCEnvPG(t, "api_token_cred_ref")
	e := &pgRefEnv{scEnv: sc}
	sink := audit.NewSystemAlertSink(nil)
	e.assets.WithSystemAlertSink(sink)
	e.creds.WithSystemAlertSink(sink)
	e.accounts = asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).WithAuthorization(e.authzSvc).
		WithManagementAuthorizer(e.adapter).WithSystemAlertSink(sink).WithAccountWriteScope(authz.NewAssetWriteScope(e.eval))
	e.node("n1", "")
	e.node("n2", "")

	granted := append(append([]authz.Permission{}, saPerms...), authz.PermCredentialView, authz.PermCredentialCreate)
	full := append(append([]authz.Permission{}, granted...), authz.PermCredentialBind)
	bindExtra := e.role(authz.PermCredentialBind, authz.PermCredentialView)

	// 全域：token 授權 full；所屬帳號另持一個角色
	fullRole := e.role(full...)
	globalOwner, globalTwin := e.user("pg-ref-owner-g"), e.user("pg-ref-twin-g")
	e.grantGlobal(globalOwner, fullRole)
	e.grantGlobal(globalOwner, e.role(authz.PermAuditView))
	e.grantGlobal(globalTwin, fullRole)
	// 節點範圍：token 授權節點 1 的 full；所屬帳號另以全域持有掛載能力（token 不得借用）
	nodeRole := e.role(full...)
	nodeOwner, nodeTwin := e.user("pg-ref-owner-n"), e.user("pg-ref-twin-n")
	e.grantNodes(nodeOwner, nodeRole, "n1")
	e.grantGlobal(nodeOwner, bindExtra)
	e.grantNodes(nodeTwin, nodeRole, "n1")
	// 無掛載能力：token 授權不含掛載能力的角色；所屬帳號另以全域持有掛載能力
	noBindRole := e.role(granted...)
	capOwner, capTwin := e.user("pg-ref-owner-c"), e.user("pg-ref-twin-c")
	e.grantGlobal(capOwner, noBindRole)
	e.grantGlobal(capOwner, bindExtra)
	e.grantGlobal(capTwin, noBindRole)

	type pair struct{ token, human pgRefSubject }
	mkPair := func(owner, twin, role uint) pair {
		return pair{token: pgRefSubject{userID: owner, filter: authz.NewRoleFilter([]uint{role}), tokenID: owner},
			human: pgRefSubject{userID: twin}}
	}
	cases := []struct {
		name    string
		p       pair
		cred    func(pgRefTargets) uint
		success bool
	}{
		{"全域指派", mkPair(globalOwner, globalTwin, fullRole), func(x pgRefTargets) uint { return x.credGlobal }, true},
		{"節點範圍內", mkPair(nodeOwner, nodeTwin, nodeRole), func(x pgRefTargets) uint { return x.credNode1 }, true},
		{"節點範圍外", mkPair(nodeOwner, nodeTwin, nodeRole), func(x pgRefTargets) uint { return x.credOut }, false},
		{"無掛載能力", mkPair(capOwner, capTwin, noBindRole), func(x pgRefTargets) uint { return x.credGlobal }, false},
	}
	n1 := e.nodes["n1"]
	entries := []struct {
		name, entry string
		do          func(s pgRefSubject, x pgRefTargets, cred uint) (int, map[string]any)
	}{
		{"建立資產", "asset_create", func(s pgRefSubject, x pgRefTargets, cred uint) (int, map[string]any) {
			return e.call(s, http.MethodPost, "/api/v1/assets", map[string]any{"name": "pg-ref-new-" + x.suffix, "protocol": "ssh",
				"host": "198.51.100.50", "port": 22, "credential_id": cred, "node_ids": []uint{n1}})
		}},
		{"匯入預覽", "", func(s pgRefSubject, x pgRefTargets, cred uint) (int, map[string]any) {
			return e.call(s, http.MethodPost, "/api/v1/assets/import/preview", pgRefImport(x, cred, n1))
		}},
		{"匯入提交", "import", func(s pgRefSubject, x pgRefTargets, cred uint) (int, map[string]any) {
			return e.call(s, http.MethodPost, "/api/v1/assets/import", pgRefImport(x, cred, n1))
		}},
		{"建立資產帳號", "account_create", func(s pgRefSubject, x pgRefTargets, cred uint) (int, map[string]any) {
			return e.call(s, http.MethodPost, fmt.Sprintf("/api/v1/assets/%d/accounts", x.asset), map[string]any{"credential_id": cred})
		}},
		{"掛載", "bind", func(s pgRefSubject, x pgRefTargets, cred uint) (int, map[string]any) {
			return e.call(s, http.MethodPost, fmt.Sprintf("/api/v1/credentials/%d/bindings", cred), map[string]any{"asset_id": x.asset})
		}},
		{"更換憑證", "rebind", func(s pgRefSubject, x pgRefTargets, cred uint) (int, map[string]any) {
			return e.call(s, http.MethodPut, fmt.Sprintf("/api/v1/assets/%d/accounts/%d/credential", x.asset, x.account),
				map[string]any{"credential_id": cred})
		}},
	}
	run := func(entry int, s pgRefSubject, credOf func(pgRefTargets) uint) (pgRefOutcome, int64) {
		x := e.targets()
		cred := credOf(x)
		assets, accounts := e.count("assets", "deleted_at IS NULL"), e.count("asset_accounts", "deleted_at IS NULL")
		alerts := e.count("system_alert_details", "alert_type = ?", attachAlertType)
		code, body := entries[entry].do(s, x, cred)
		out := pgRefOutcome{Status: code, ImportOK: body["ok"],
			AssetsDelta:   e.count("assets", "deleted_at IS NULL") - assets,
			AccountsDelta: e.count("asset_accounts", "deleted_at IS NULL") - accounts,
			Bound:         e.count("asset_accounts", "credential_id = ? AND deleted_at IS NULL", cred) > 0}
		out.Code, _ = body["code"].(string)
		return out, e.count("system_alert_details", "alert_type = ?", attachAlertType) - alerts
	}
	ran := 0
	for i, entry := range entries {
		for _, c := range cases {
			i, entry, c := i, entry, c
			t.Run(entry.name+"／"+c.name, func(t *testing.T) {
				ran++
				tok, tokAlerts := run(i, c.p.token, c.cred)
				hum, humAlerts := run(i, c.p.human, c.cred)
				require.Equal(t, hum, tok, "token 與只持有授權角色的本人結果應相同")
				require.Zero(t, humAlerts, "人類請求不產生掛載告警")
				want := int64(0)
				if c.success && entry.entry != "" {
					want = 1
				}
				require.Equal(t, want, tokAlerts, "token 的掛載告警則數")
				rejected := !is2xx(hum.Status) || hum.ImportOK == false
				require.Equal(t, !c.success, rejected, "情境應%s：%+v", map[bool]string{true: "成功", false: "被拒"}[c.success], hum)
				if c.success && entry.entry != "" {
					require.True(t, tok.Bound, "成功時掛載指向所引用的憑證")
				}
				if !c.success {
					require.Zero(t, tok.AssetsDelta+tok.AccountsDelta, "被拒不寫入")
					require.False(t, tok.Bound)
				}
			})
		}
	}
	require.Equal(t, len(entries)*len(cases), ran)
}

func pgRefImport(x pgRefTargets, cred, node uint) map[string]any {
	return map[string]any{"source": "form", "rows": []map[string]any{
		{"name": "pg-ref-imp-a-" + x.suffix, "protocol": "ssh", "host": "203.0.113.50", "port": 22, "credential_id": cred, "node_ids": []uint{node}},
		{"name": "pg-ref-imp-b-" + x.suffix, "protocol": "ssh", "host": "203.0.113.51", "port": 22, "credential_id": nil, "node_ids": []uint{node}},
	}}
}
