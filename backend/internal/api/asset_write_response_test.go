package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產寫入回應與讀取一致、資產更新的欄位檢核、建立時的啟用狀態（正式接線的資產服務與 handler）。

type assetWriteEnv struct {
	*treeFixture
	h     *AssetHandler
	admin uint
}

func newAssetWriteEnv(t *testing.T) *assetWriteEnv {
	t.Helper()
	f := newTreeFixture(t)
	require.NoError(t, f.db.AutoMigrate(&model.AssetAccount{}, &model.CredentialSecretVersion{}))
	old := database.DB
	database.DB = f.db
	t.Cleanup(func() { database.DB = old })
	svc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	// 與正式組裝相同的寫入埠：拓撲鎖與權限版本、交易內範圍判定、掛載變更的涵蓋快照
	svc.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	svc.SetAssetWriteScopePort(authz.NewAssetWriteScope(f.eval))
	svc.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(asset.NewScopeTopologyReader()))
	h := NewAssetHandler(svc, authz.NewAssetAuthorizationService(f.db), nil)
	h.SetAssetScope(authz.NewAssetScopeReader(f.eval, f.db))
	e := &assetWriteEnv{treeFixture: f, h: h}
	e.admin = e.superAdmin()
	return e
}

// call 以超級管理者送出請求；路由路徑與正式註冊相同（欄位閘依路由登錄判定）。
func (e *assetWriteEnv) call(method, path string, body any) (int, map[string]any, string) {
	e.t.Helper()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, e.admin, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", e.admin)
		c.Set("username", "write-response-admin")
		c.Next()
	})
	g := r.Group("/api/v1/assets")
	g.GET("", e.h.List)
	g.POST("", e.h.Create)
	g.GET("/:id", e.h.Get)
	g.PUT("/:id", e.h.Update)
	var buf bytes.Buffer
	if body != nil {
		require.NoError(e.t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Body.String()
}

func (e *assetWriteEnv) get(id uint) map[string]any {
	e.t.Helper()
	code, out, raw := e.call(http.MethodGet, fmt.Sprintf("/api/v1/assets/%d", id), nil)
	require.Equal(e.t, http.StatusOK, code, raw)
	return out
}

func (e *assetWriteEnv) put(id uint, body map[string]any) (int, map[string]any, string) {
	e.t.Helper()
	return e.call(http.MethodPut, fmt.Sprintf("/api/v1/assets/%d", id), body)
}

// listRow 資產列表中該資產的那一列。
func (e *assetWriteEnv) listRow(id uint) map[string]any {
	e.t.Helper()
	code, out, raw := e.call(http.MethodGet, "/api/v1/assets?page_size=1000", nil)
	require.Equal(e.t, http.StatusOK, code, raw)
	for _, r := range assetRows(out) {
		if uint(r["id"].(float64)) == id {
			return r
		}
	}
	e.t.Fatalf("列表中沒有資產 %d", id)
	return nil
}

// nodeIDsOf 回應中的節點歸屬（缺鍵、null 與空陣列皆視為未分組），升冪。
func nodeIDsOf(m map[string]any) []uint {
	raw, _ := m["node_ids"].([]any)
	out := make([]uint, 0, len(raw))
	for _, v := range raw {
		out = append(out, uint(v.(float64)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func nodePathsOf(m map[string]any) []string {
	raw, _ := m["node_paths"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	sort.Strings(out)
	return out
}

func TestAssetHandler_UpdateResponse(t *testing.T) {
	t.Run("clearing_nodes_returns_ungrouped_like_the_read", func(t *testing.T) {
		e := newAssetWriteEnv(t)
		id := e.assets["a-db"]
		require.Equal(t, []uint{e.id("prod/db")}, nodeIDsOf(e.get(id)), "前提：資產掛在 prod/db")
		code, resp, raw := e.put(id, map[string]any{"node_ids": []uint{}})
		require.Equal(t, http.StatusOK, code, raw)
		assert.Empty(t, nodeIDsOf(resp), "清空歸屬後回應不得帶舊節點：%s", raw)
		assert.Empty(t, nodePathsOf(resp), "清空歸屬後回應不得帶舊路徑：%s", raw)
		read := e.get(id)
		assert.Equal(t, nodeIDsOf(read), nodeIDsOf(resp))
		assert.Equal(t, nodePathsOf(read), nodePathsOf(resp))
		assert.NotContains(t, resp, "node_ids", "與讀取同形：未分組時不帶 node_ids")
		assert.NotContains(t, read, "node_ids")
	})

	t.Run("replacing_nodes_returns_the_new_set", func(t *testing.T) {
		e := newAssetWriteEnv(t)
		id := e.assets["a-db"]
		code, resp, raw := e.put(id, map[string]any{"node_ids": []uint{e.id("sit/web"), e.id("prod/web")}})
		require.Equal(t, http.StatusOK, code, raw)
		want := []uint{e.id("prod/web"), e.id("sit/web")}
		sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
		assert.Equal(t, want, nodeIDsOf(resp))
		assert.Equal(t, []string{"prod / web", "sit / web"}, nodePathsOf(resp))
		read := e.get(id)
		assert.Equal(t, nodeIDsOf(read), nodeIDsOf(resp))
		assert.Equal(t, nodePathsOf(read), nodePathsOf(resp))
	})

	t.Run("update_without_node_ids_keeps_current_nodes", func(t *testing.T) {
		e := newAssetWriteEnv(t)
		id := e.assets["a-db"]
		code, resp, raw := e.put(id, map[string]any{"description": "only the description"})
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []uint{e.id("prod/db")}, nodeIDsOf(resp))
		assert.Equal(t, nodeIDsOf(e.get(id)), nodeIDsOf(resp))
	})
}

// seedAccount 直接寫表建一筆帳號掛載（含一筆專用憑證列）。
func (e *assetWriteEnv) seedAccount(assetID uint, username, purpose string, isDefault bool) uint {
	e.t.Helper()
	cred := model.Credential{Scope: model.CredentialScopeDedicated, Username: username}
	require.NoError(e.t, e.db.Create(&cred).Error)
	acc := model.AssetAccount{AssetID: assetID, CredentialID: cred.ID, Username: username, IsDefault: isDefault, Purpose: purpose}
	require.NoError(e.t, e.db.Create(&acc).Error)
	return acc.ID
}

func TestAssetHandler_CredentialPending(t *testing.T) {
	e := newAssetWriteEnv(t)
	id := e.assets["a-web"]
	step := 0
	check := func(label string, want bool) {
		t.Helper()
		step++
		code, resp, raw := e.put(id, map[string]any{"description": fmt.Sprintf("step %d", step)})
		require.Equal(t, http.StatusOK, code, raw)
		read := e.get(id)
		row := e.listRow(id)
		assert.Equal(t, want, resp["credential_pending"], "%s：寫入回應", label)
		assert.Equal(t, want, read["credential_pending"], "%s：單筆讀取", label)
		assert.Equal(t, want, row["credential_pending"], "%s：列表", label)
	}
	check("零帳號", true)
	login := e.seedAccount(id, "operator", model.AccountPurposeLogin, true)
	check("建立登入帳號後", false)
	require.NoError(t, e.db.Delete(&model.AssetAccount{}, login).Error)
	check("刪除唯一的登入帳號後", true)
	e.seedAccount(id, "svc-exec", model.AccountPurposeExecutor, false)
	check("只有執行身分", true)
	login2 := e.seedAccount(id, "operator2", model.AccountPurposeLogin, true)
	check("執行身分加登入帳號", false)
	require.NoError(t, e.db.Delete(&model.AssetAccount{}, login2).Error)
	check("刪除最後一筆登入帳號、保留執行身分", true)
}

// writeCounts 資產、帳號、憑證與密文版本的列數（含已軟刪），用來確認被拒的更新沒有任何寫入。
func (e *assetWriteEnv) writeCounts() map[string]int64 {
	e.t.Helper()
	out := map[string]int64{}
	for _, tbl := range []string{"assets", "asset_accounts", "credentials", "credential_secret_versions", "audit_logs"} {
		var n int64
		require.NoError(e.t, e.db.Table(tbl).Count(&n).Error)
		out[tbl] = n
	}
	return out
}

// seedRawAsset 直接寫表建一台資產（可帶既有壞值與顯示旗標）。
func (e *assetWriteEnv) seedRawAsset(a model.Asset) model.Asset {
	e.t.Helper()
	if a.Host == "" {
		a.Host = "198.51.100.20"
	}
	require.NoError(e.t, e.db.Create(&a).Error)
	return a
}

func TestAssetHandler_UpdateValidation(t *testing.T) {
	type tc struct {
		name     string
		seed     model.Asset
		accounts func(e *assetWriteEnv, id uint)
		body     func(a model.Asset) map[string]any
		wantCode int
		wantErr  string
		// reject 時檢查未改變的欄位
		unchanged func(t *testing.T, before, after model.Asset)
	}
	cases := []tc{
		{name: "port_valid_to_zero", seed: model.Asset{Name: "p0", Protocol: model.ProtocolSSH, Port: 22},
			body:     func(model.Asset) map[string]any { return map[string]any{"port": 0} },
			wantCode: http.StatusBadRequest, wantErr: "VALIDATION_ASSET_IMPORT_PORT",
			unchanged: func(t *testing.T, b, a model.Asset) { assert.Equal(t, b.Port, a.Port) }},
		{name: "port_valid_to_70000", seed: model.Asset{Name: "p7", Protocol: model.ProtocolSSH, Port: 22},
			body:     func(model.Asset) map[string]any { return map[string]any{"port": 70000} },
			wantCode: http.StatusBadRequest, wantErr: "VALIDATION_ASSET_IMPORT_PORT",
			unchanged: func(t *testing.T, b, a model.Asset) { assert.Equal(t, b.Port, a.Port) }},
		{name: "legacy_bad_port_description_edit_resending_protocol_and_port", seed: model.Asset{Name: "legacy", Protocol: model.ProtocolSSH, Port: 70000},
			body: func(a model.Asset) map[string]any {
				return map[string]any{"description": "edited", "protocol": string(a.Protocol), "port": a.Port, "name": a.Name, "host": a.Host}
			},
			wantCode: http.StatusOK},
		{name: "legacy_bad_port_to_another_bad_port", seed: model.Asset{Name: "legacy2", Protocol: model.ProtocolSSH, Port: 70000},
			body:     func(model.Asset) map[string]any { return map[string]any{"port": 80000} },
			wantCode: http.StatusBadRequest, wantErr: "VALIDATION_ASSET_IMPORT_PORT",
			unchanged: func(t *testing.T, b, a model.Asset) { assert.Equal(t, 70000, a.Port) }},
		{name: "ssh_with_password_clears_username", seed: model.Asset{Name: "sshpw", Protocol: model.ProtocolSSH, Port: 22, Username: "root", HasPassword: true},
			accounts: func(e *assetWriteEnv, id uint) { e.seedAccount(id, "root", model.AccountPurposeLogin, true) },
			body:     func(model.Asset) map[string]any { return map[string]any{"username": ""} },
			wantCode: http.StatusBadRequest, wantErr: "VALIDATION_ASSET_USERNAME_REQUIRED",
			unchanged: func(t *testing.T, b, a model.Asset) {
				assert.Equal(t, "root", a.Username)
				assert.True(t, a.HasPassword)
			}},
		{name: "vnc_password_only_switches_to_ssh", seed: model.Asset{Name: "vncpw", Protocol: model.ProtocolVNC, Port: 5900, HasPassword: true},
			accounts: func(e *assetWriteEnv, id uint) { e.seedAccount(id, "", model.AccountPurposeLogin, true) },
			body:     func(model.Asset) map[string]any { return map[string]any{"protocol": "ssh"} },
			wantCode: http.StatusBadRequest, wantErr: "VALIDATION_ASSET_USERNAME_REQUIRED",
			unchanged: func(t *testing.T, b, a model.Asset) { assert.Equal(t, model.ProtocolVNC, a.Protocol) }},
		{name: "ssh_without_credentials_gets_password_only", seed: model.Asset{Name: "sshbare", Protocol: model.ProtocolSSH, Port: 22},
			body:     func(model.Asset) map[string]any { return map[string]any{"password": "fixture-only-secret"} },
			wantCode: http.StatusBadRequest, wantErr: "VALIDATION_ASSET_USERNAME_REQUIRED",
			unchanged: func(t *testing.T, b, a model.Asset) { assert.False(t, a.HasPassword) }},
		{name: "vnc_password_only_keeps_empty_username", seed: model.Asset{Name: "vnckeep", Protocol: model.ProtocolVNC, Port: 5900, HasPassword: true},
			accounts: func(e *assetWriteEnv, id uint) { e.seedAccount(id, "", model.AccountPurposeLogin, true) },
			body:     func(model.Asset) map[string]any { return map[string]any{"username": "", "description": "vnc edit"} },
			wantCode: http.StatusOK},
		{name: "zero_accounts_description_edit", seed: model.Asset{Name: "zero", Protocol: model.ProtocolSSH, Port: 22},
			body:     func(model.Asset) map[string]any { return map[string]any{"description": "pending is legal"} },
			wantCode: http.StatusOK},
		{name: "executor_only_description_edit", seed: model.Asset{Name: "execonly", Protocol: model.ProtocolSSH, Port: 22},
			accounts: func(e *assetWriteEnv, id uint) { e.seedAccount(id, "svc-exec", model.AccountPurposeExecutor, false) },
			body:     func(model.Asset) map[string]any { return map[string]any{"description": "pending is legal"} },
			wantCode: http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newAssetWriteEnv(t)
			a := e.seedRawAsset(c.seed)
			if c.accounts != nil {
				c.accounts(e, a.ID)
			}
			var before model.Asset
			require.NoError(t, e.db.First(&before, a.ID).Error)
			counts := e.writeCounts()
			code, resp, raw := e.put(a.ID, c.body(before))
			require.Equal(t, c.wantCode, code, raw)
			var after model.Asset
			require.NoError(t, e.db.First(&after, a.ID).Error)
			if c.wantCode != http.StatusOK {
				assert.Equal(t, c.wantErr, resp["code"], raw)
				assert.Equal(t, counts, e.writeCounts(), "被拒的更新不得寫入資產、帳號、憑證或稽核")
				assert.True(t, before.UpdatedAt.Equal(after.UpdatedAt), "被拒的更新不得改動資產列")
				c.unchanged(t, before, after)
				return
			}
			assert.False(t, before.UpdatedAt.Equal(after.UpdatedAt) && before.Description == after.Description, "放行的更新應寫入")
		})
	}
}

// TestAssetHandler_UpdateValidationUIShape 畫面編輯資產的送法（原樣重送名稱、協定、主機、埠號與描述等，不送登入憑證）
// 對合法資產仍然成功。
func TestAssetHandler_UpdateValidationUIShape(t *testing.T) {
	e := newAssetWriteEnv(t)
	a := e.seedRawAsset(model.Asset{Name: "ui-edit", Protocol: model.ProtocolSSH, Port: 22, Username: "root", HasPassword: true})
	e.seedAccount(a.ID, "root", model.AccountPurposeLogin, true)
	code, resp, raw := e.put(a.ID, map[string]any{"name": a.Name, "protocol": "ssh", "host": a.Host, "port": 22,
		"description": "edited from the form", "tags": "", "node_ids": []uint{e.id("prod/web")}})
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, "edited from the form", resp["description"])
}

func TestAssetHandler_CreateActive(t *testing.T) {
	create := func(t *testing.T, e *assetWriteEnv, name string, active any) map[string]any {
		body := map[string]any{"name": name, "protocol": "ssh", "host": "198.51.100.30", "port": 22}
		if active != nil {
			body["active"] = active
		}
		code, resp, raw := e.call(http.MethodPost, "/api/v1/assets", body)
		require.Equal(t, http.StatusCreated, code, raw)
		return resp
	}
	t.Run("inactive_from_creation", func(t *testing.T) {
		e := newAssetWriteEnv(t)
		resp := create(t, e, "born-disabled", false)
		id := uint(resp["id"].(float64))
		assert.Equal(t, false, resp["active"], "建立回應")
		var row model.Asset
		require.NoError(t, e.db.First(&row, id).Error)
		assert.False(t, row.Active, "資料庫中的值")
		assert.Equal(t, false, e.get(id)["active"], "讀回")
		assert.Equal(t, false, e.listRow(id)["active"], "列表")
		// 稽核只有一筆建立、沒有任何更新列：停用不是建立後再改的兩步
		var logs []model.AuditLog
		require.NoError(t, e.db.Where("resource = ? AND resource_id = ?", model.ResourceAsset, id).Order("id").Find(&logs).Error)
		require.Len(t, logs, 1, "稽核列：%+v", logs)
		assert.Equal(t, model.ActionCreate, logs[0].Action)
	})
	t.Run("omitted_is_active", func(t *testing.T) {
		e := newAssetWriteEnv(t)
		resp := create(t, e, "born-enabled", nil)
		id := uint(resp["id"].(float64))
		assert.Equal(t, true, resp["active"])
		var row model.Asset
		require.NoError(t, e.db.First(&row, id).Error)
		assert.True(t, row.Active)
		assert.Equal(t, true, e.get(id)["active"])
	})
	t.Run("explicit_true_is_active", func(t *testing.T) {
		e := newAssetWriteEnv(t)
		resp := create(t, e, "born-enabled-explicit", true)
		var row model.Asset
		require.NoError(t, e.db.First(&row, uint(resp["id"].(float64))).Error)
		assert.True(t, row.Active)
	})
}
