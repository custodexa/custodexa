package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 帳號列的憑證投影：範圍化檢視者讀到引用範圍外（含全域）憑證的帳號列時，不含憑證識別、名稱與台數，
// 帶 credential_out_of_scope 與動作旗標（更換、移除照所屬資產；更正、脫離不可執行）；範圍內憑證的列照舊；
// 全域主體讀同一列與未注入投影時逐欄相同。

// scAccountListRouter 帳號列表路由：管理可視與帳號列憑證投影皆為正式實作；withProjection 為假時不注入投影（現行對照）。
func (e *scEnv) scAccountListRouter(uid uint, withProjection bool) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(e.scPrincipal(uid))
	svc := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(e.adapter).WithSystemAlertSink(noopAlertSink{}).
		WithAccountWriteScope(authz.NewAssetWriteScope(e.eval))
	h := api.NewAssetAccountHandler(svc, e.authzSvc)
	src := authz.NewAssetScopeReader(e.eval, e.db)
	h.SetAssetManagementVisibility(src)
	if withProjection {
		h.SetAccountCredentialScope(authz.NewCredentialScopeReader(e.eval, e.db))
		h.SetAccountRowActions(asset.NewAccountRowActionJudge(e.creds, svc))
	}
	r.GET("/api/v1/assets/:id/accounts", middleware.EnforceRegistry(),
		middleware.RequireAssetVisibleOrManaged(e.authzSvc, src), h.List)
	return r
}

func scAccountRow(t *testing.T, raw string, accountID uint) map[string]any {
	t.Helper()
	var out struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
	for _, r := range out.Data {
		if v, ok := r["id"].(float64); ok && uint(v) == accountID {
			return r
		}
	}
	t.Fatalf("帳號列 %d 不在回應內：%s", accountID, raw)
	return nil
}

func runAccountRowProjectionCase(t *testing.T, m *scMount) {
	viewer := m.user("zz-sc-account-viewer")
	m.grant(viewer, []string{"zz-sc-in"}, authz.PermAssetView, authz.PermAssetUpdate, authz.PermCredentialView)
	// 帳號列的憑證身分欄位只給具憑證管理者（保留權限點，只能全域授予）
	m.grantGlobal(viewer, m.role(authz.PermCredentialManage))
	global := m.user("zz-sc-account-global")
	m.grantGlobal(global, m.role(authz.PermAssetView, authz.PermCredentialView, authz.PermCredentialManage))
	// 非範圍化主體的逐資產守門走連線可視（管理可視只對範圍化檢視者成立）
	m.connGrant(global, m.aIn)

	accGlobal := m.mount(m.globalCred, m.aIn)
	accOut := m.mount(m.outCred, m.aIn)
	accIn := m.mount(m.inCred, m.aIn)
	path := fmt.Sprintf("/api/v1/assets/%d/accounts", m.aIn)

	code, raw := scServe(m.scAccountListRouter(viewer, true), "GET", path, "")
	require.Equal(t, http.StatusOK, code, raw)
	for _, acc := range []uint{accGlobal, accOut} {
		row := scAccountRow(t, raw, acc)
		for _, k := range []string{"credential_id", "credential_name", "binding_count", "ownership"} {
			require.NotContains(t, row, k, "範圍外憑證的帳號列不含 %s", k)
		}
		require.Equal(t, true, row["credential_out_of_scope"])
	}
	// 以 JSON 字串值比對：夾具的帳號 username 由憑證名衍生（u-<名稱>），那是帳號自身欄位、不在移除之列
	require.NotContains(t, raw, `"zz-sc-src-global"`, "回應原文不含範圍外憑證名稱")
	require.NotContains(t, raw, `"zz-sc-src-out"`, "回應原文不含範圍外憑證名稱")
	in := scAccountRow(t, raw, accIn)
	require.EqualValues(t, m.inCred, in["credential_id"], "範圍內憑證的列照舊")
	require.NotContains(t, in, "credential_out_of_scope")
	require.NotContains(t, in, "actions", "範圍內憑證的列不帶帳號列旗標")

	// 動作旗標：只持資產編輯者可移除、不可更換（缺掛載能力）；更正與脫離不可執行
	wantViewer := map[string]any{
		"rebind":     map[string]any{"allowed": false, "reason": "no_capability"},
		"remove":     map[string]any{"allowed": true},
		"secret_fix": map[string]any{"allowed": false, "reason": "no_capability"},
		"detach":     map[string]any{"allowed": false, "reason": "no_capability"},
	}
	for _, acc := range []uint{accGlobal, accOut} {
		require.Equal(t, wantViewer, scAccountRow(t, raw, acc)["actions"], "帳號 %d 的動作旗標", acc)
	}
	// 另持掛載、宣告與脫離能力者：更換照所屬資產可用；更正與脫離因憑證歸屬在範圍外不可執行
	binder := m.user("zz-sc-account-binder")
	m.grant(binder, []string{"zz-sc-in"}, authz.PermAssetView, authz.PermAssetUpdate, authz.PermCredentialView,
		authz.PermCredentialBind, authz.PermCredentialSetSecret, authz.PermCredentialDetach)
	m.grantGlobal(binder, m.role(authz.PermCredentialManage))
	code, rawBinder := scServe(m.scAccountListRouter(binder, true), "GET", path, "")
	require.Equal(t, http.StatusOK, code, rawBinder)
	wantBinder := map[string]any{
		"rebind":     map[string]any{"allowed": true},
		"remove":     map[string]any{"allowed": true},
		"secret_fix": map[string]any{"allowed": false, "reason": "out_of_scope"},
		"detach":     map[string]any{"allowed": false, "reason": "out_of_scope"},
	}
	for _, acc := range []uint{accGlobal, accOut} {
		require.Equal(t, wantBinder, scAccountRow(t, rawBinder, acc)["actions"], "帳號 %d 的動作旗標", acc)
	}
	// 旗標與寫入端點一致：判定相同的兩個主體對同一列實際送出更換，只持資產編輯者被拒、帳號不變；
	// 另持掛載能力者改掛到範圍內憑證成功
	// 改掛目標是另一筆範圍內憑證：m.inCred 已掛在同一台（accIn），改掛到它會撞同資產重複掛載
	rebindTo := m.cred("zz-sc-account-rebind-to", m.nodeID("zz-sc-in"))
	rebind := fmt.Sprintf("/api/v1/assets/%d/accounts/%d/credential", m.aIn, accOut)
	code, body := m.call(viewer, "PUT", rebind, fmt.Sprintf(`{"credential_id":%d}`, rebindTo))
	require.Equal(t, http.StatusForbidden, code, body)
	code, body = m.call(binder, "PUT", rebind, fmt.Sprintf(`{"credential_id":%d}`, rebindTo))
	require.Equal(t, http.StatusOK, code, body)

	// 全域主體：注入投影與否逐欄相同
	code, withProj := scServe(m.scAccountListRouter(global, true), "GET", path, "")
	require.Equal(t, http.StatusOK, code, withProj)
	code, without := scServe(m.scAccountListRouter(global, false), "GET", path, "")
	require.Equal(t, http.StatusOK, code, without)
	require.JSONEq(t, without, withProj, "全域主體讀同一列與現行逐欄相同")
	require.EqualValues(t, m.globalCred, scAccountRow(t, withProj, accGlobal)["credential_id"])
}
