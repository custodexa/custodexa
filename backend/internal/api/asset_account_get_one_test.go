package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產帳號單筆讀取：同一個請求主體，單筆回應等於帳號列表中的那一列（同一個帳號範圍過濾與同一個投影）；
// 404 分兩個維度：資產不可見時，不同的帳號識別彼此同一回應；資產可見時，範圍外、不存在、屬於他台、
// 系統專用帳號四種帳號識別彼此同一回應。回應不含秘密或其密文。

const accountGetOneMissingID = 999999

type accountGetOneEnv struct {
	t        *testing.T
	db       *gorm.DB
	h        *AssetAccountHandler
	authzSvc *authz.AssetAuthorizationService
	ids      map[string]uint // 帳號名 → 識別（資產 1 的 root、app、deploy、executor，資產 2 的 other）
}

func newAccountGetOneEnv(t *testing.T) *accountGetOneEnv {
	t.Helper()
	h, db := setupAccountListEnv(t)
	e := &accountGetOneEnv{t: t, db: db, h: h, authzSvc: authz.NewAssetAuthorizationService(db), ids: map[string]uint{}}
	require.NoError(t, db.Create(&model.Asset{Name: "a2", Protocol: "ssh", Host: "h2", Port: 22, CreatedBy: 1, Active: true}).Error)
	require.NoError(t, db.Create(&model.AssetAccount{AssetID: 2, Username: "other", IsDefault: true}).Error)
	require.NoError(t, db.Create(&model.AssetAccount{AssetID: 1, Username: "custodexa-exec",
		Purpose: model.AccountPurposeExecutor}).Error)
	var rows []model.AssetAccount
	require.NoError(t, db.Find(&rows).Error)
	for _, r := range rows {
		name := r.Username
		if r.Purpose == model.AccountPurposeExecutor {
			name = "executor"
		}
		e.ids[name] = r.ID
	}
	return e
}

func (e *accountGetOneEnv) get(role, path string) (int, []byte) {
	e.t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/assets/:id/accounts", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "u1")
		middleware.SetPrincipal(c, legacyPrincipal(role))
		c.Next()
	}, middleware.RequireAssetVisible(e.authzSvc))
	g.GET("", e.h.List)
	g.GET("/:accountId", e.h.Get)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Code, w.Body.Bytes()
}

func (e *accountGetOneEnv) listRows(role string, assetID uint) map[uint]map[string]any {
	e.t.Helper()
	code, body := e.get(role, fmt.Sprintf("/assets/%d/accounts", assetID))
	require.Equal(e.t, http.StatusOK, code, string(body))
	var out struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(e.t, json.Unmarshal(body, &out))
	rows := map[uint]map[string]any{}
	for _, r := range out.Data {
		rows[uint(r["id"].(float64))] = r
	}
	return rows
}

// assertSingleMatchesList 資產 assetID 下每個候選帳號識別：列表有者單筆逐欄相同；
// 列表沒有者（範圍外、不存在、屬於他台、系統專用帳號）彼此與不存在同一回應。回列表中的識別。
func (e *accountGetOneEnv) assertSingleMatchesList(role string, assetID uint) map[uint]map[string]any {
	e.t.Helper()
	rows := e.listRows(role, assetID)
	missCode, missBody := e.get(role, fmt.Sprintf("/assets/%d/accounts/%d", assetID, accountGetOneMissingID))
	require.Equal(e.t, http.StatusNotFound, missCode, string(missBody))
	for name, id := range e.ids {
		code, raw := e.get(role, fmt.Sprintf("/assets/%d/accounts/%d", assetID, id))
		if row, ok := rows[id]; ok {
			require.Equal(e.t, http.StatusOK, code, "%s：%s", name, raw)
			var got map[string]any
			require.NoError(e.t, json.Unmarshal(raw, &got))
			assert.Equal(e.t, row, got, "%s %s：單筆與列表中那一列逐欄相同", role, name)
			assertNoSecretMaterial(e.t, raw)
			continue
		}
		assert.Equal(e.t, missCode, code, "%s %s：列表看不到時與不存在同狀態碼", role, name)
		assert.Equal(e.t, string(missBody), string(raw), "%s %s：列表看不到時與不存在同本文", role, name)
	}
	return rows
}

func assertNoSecretMaterial(t *testing.T, raw []byte) {
	t.Helper()
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	for k := range got {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "has_") {
			_, isBool := got[k].(bool)
			assert.True(t, isBool, "%s 以布林表示是否已設定", k)
			continue
		}
		for _, banned := range []string{"password", "private_key", "secret", "passphrase", "_enc", "cipher"} {
			assert.NotContains(t, lk, banned, "回應不含秘密或其密文欄位：%s", k)
		}
	}
}

// stubAccountCredentialScope 範圍化形狀：只有 inView 內的憑證在檢視範圍內。
type stubAccountCredentialScope struct{ inView map[uint]bool }

func (s stubAccountCredentialScope) AccountCredentialProjection(_ context.Context, ids []uint) (authz.AccountCredentialShape, map[uint]bool, error) {
	out := map[uint]bool{}
	for _, id := range ids {
		if s.inView[id] {
			out[id] = true
		}
	}
	return authz.AccountCredentialScoped, out, nil
}

type stubAccountRowActions struct{}

func (stubAccountRowActions) AccountRowChecks(context.Context, uint, uint, uint) asset.AccountRowChecks {
	return asset.AccountRowChecks{}
}

func TestAssetAccountHandler_GetOne(t *testing.T) {
	t.Run("full_shape_for_credential_managers", func(t *testing.T) {
		e := newAccountGetOneEnv(t)
		rows := e.assertSingleMatchesList(model.RoleAdmin, 1)
		require.Len(t, rows, 3, "登入用途的三個帳號；系統專用帳號不在列表")
		_, hasCredID := rows[e.ids["root"]]["credential_id"]
		assert.True(t, hasCredID, "完整版帶憑證識別欄位（前提）")
	})

	t.Run("slim_shape_and_account_scope_for_ordinary_user", func(t *testing.T) {
		e := newAccountGetOneEnv(t)
		grantView(t, e.db, model.AccountScope{"app"})
		rows := e.assertSingleMatchesList(model.RoleUser, 1)
		require.Len(t, rows, 1)
		row := rows[e.ids["app"]]
		require.NotNil(t, row, "範圍內帳號可讀")
		_, hasCredID := row["credential_id"]
		assert.False(t, hasCredID, "精簡版不帶憑證識別欄位")
	})

	t.Run("visible_asset_four_kinds_of_unreadable_ids_answer_alike", func(t *testing.T) {
		e := newAccountGetOneEnv(t)
		grantView(t, e.db, model.AccountScope{"app"})
		missCode, missBody := e.get(model.RoleUser, fmt.Sprintf("/assets/1/accounts/%d", accountGetOneMissingID))
		require.Equal(t, http.StatusNotFound, missCode)
		for name, id := range map[string]uint{"範圍外": e.ids["root"], "屬於他台": e.ids["other"], "系統專用帳號": e.ids["executor"]} {
			code, body := e.get(model.RoleUser, fmt.Sprintf("/assets/1/accounts/%d", id))
			assert.Equal(t, missCode, code, "%s：與不存在同狀態碼", name)
			assert.Equal(t, string(missBody), string(body), "%s：與不存在同本文", name)
		}
		// 系統專用帳號對管理者同樣不讀（列表本來就只列登入用途）
		adminMissCode, adminMiss := e.get(model.RoleAdmin, fmt.Sprintf("/assets/1/accounts/%d", accountGetOneMissingID))
		code, body := e.get(model.RoleAdmin, fmt.Sprintf("/assets/1/accounts/%d", e.ids["executor"]))
		assert.Equal(t, adminMissCode, code)
		assert.Equal(t, string(adminMiss), string(body))
	})

	t.Run("invisible_asset_different_account_ids_answer_alike", func(t *testing.T) {
		e := newAccountGetOneEnv(t)
		grantView(t, e.db, model.AccountScope{model.AccountScopeAll}) // 只對資產 1 有授權
		listCode, listBody := e.get(model.RoleUser, "/assets/2/accounts")
		require.Equal(t, http.StatusNotFound, listCode, "前提：資產 2 對此主體不可見，列表回不存在")
		var first []byte
		for _, id := range []uint{e.ids["other"], e.ids["root"], e.ids["executor"], accountGetOneMissingID} {
			code, body := e.get(model.RoleUser, fmt.Sprintf("/assets/2/accounts/%d", id))
			assert.Equal(t, listCode, code, "帳號 %d：與列表同狀態碼", id)
			assert.Equal(t, string(listBody), string(body), "帳號 %d：與列表同本文（資產層出口）", id)
			if first == nil {
				first = body
			}
			assert.Equal(t, string(first), string(body), "不同帳號識別彼此同本文")
		}
	})

	t.Run("in_scope_asset_referencing_out_of_scope_credential_is_narrowed_like_list", func(t *testing.T) {
		e := newAccountGetOneEnv(t)
		mk := func(name string) uint {
			n := name
			c := model.Credential{Name: &n, Scope: model.CredentialScopeShared, Username: "app",
				SecretType: model.ChangeSecretTypePassword, AuthMethod: "sql", ProtocolFamily: model.ProtocolFamilySSH}
			require.NoError(t, e.db.Create(&c).Error)
			return c.ID
		}
		inCred, outCred := mk("cred-in-view"), mk("cred-out-of-view")
		require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", e.ids["app"]).Update("credential_id", outCred).Error)
		require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", e.ids["deploy"]).Update("credential_id", inCred).Error)
		e.h.SetAccountCredentialScope(stubAccountCredentialScope{inView: map[uint]bool{inCred: true}})
		e.h.SetAccountRowActions(stubAccountRowActions{})

		rows := e.assertSingleMatchesList(model.RoleAdmin, 1)
		out := rows[e.ids["app"]]
		require.NotNil(t, out)
		assert.Equal(t, true, out["credential_out_of_scope"], "範圍外憑證的列收窄（前提）")
		_, hasActions := out["actions"]
		assert.True(t, hasActions, "範圍外憑證的列帶動作旗標（前提）")
		for _, k := range []string{"credential_id", "credential_name", "binding_count"} {
			_, has := out[k]
			assert.False(t, has, "範圍外憑證的列不含 %s", k)
		}
		in := rows[e.ids["deploy"]]
		require.NotNil(t, in)
		assert.EqualValues(t, inCred, in["credential_id"], "範圍內憑證的列照舊")
		code, raw := e.get(model.RoleAdmin, fmt.Sprintf("/assets/1/accounts/%d", e.ids["app"]))
		require.Equal(t, http.StatusOK, code)
		assert.NotContains(t, string(raw), "cred-out-of-view", "單筆原文不含範圍外憑證名稱")
	})

	t.Run("invalid_account_id_is_bad_request", func(t *testing.T) {
		e := newAccountGetOneEnv(t)
		code, body := e.get(model.RoleAdmin, "/assets/1/accounts/abc")
		assert.Equal(t, http.StatusBadRequest, code, string(body))
	})

	t.Run("deleted_account_answers_like_missing", func(t *testing.T) {
		e := newAccountGetOneEnv(t)
		gone := model.AssetAccount{AssetID: 1, Username: "retired"}
		require.NoError(t, e.db.Create(&gone).Error)
		require.NoError(t, e.db.Delete(&gone).Error)
		grantView(t, e.db, model.AccountScope{model.AccountScopeAll})
		for _, role := range []string{model.RoleAdmin, model.RoleUser} {
			rows := e.listRows(role, 1)
			require.NotEmpty(t, rows, "%s：前提：同一台資產上有可讀的帳號", role)
			_, listed := rows[gone.ID]
			require.False(t, listed, "%s：前提：已刪除帳號不在列表", role)
			missCode, missBody := e.get(role, fmt.Sprintf("/assets/1/accounts/%d", accountGetOneMissingID))
			code, body := e.get(role, fmt.Sprintf("/assets/1/accounts/%d", gone.ID))
			assert.Equal(t, http.StatusNotFound, code, "%s：已刪除帳號回 404：%s", role, body)
			assert.Equal(t, missCode, code, "%s：已刪除帳號與不存在同狀態碼", role)
			assert.Equal(t, string(missBody), string(body), "%s：已刪除帳號與不存在同本文", role)
		}
	})

	t.Run("id_boundaries_depend_only_on_input", func(t *testing.T) {
		e := newAccountGetOneEnv(t)
		grantView(t, e.db, model.AccountScope{"app"})
		get := func(role string) func(string) (int, []byte) {
			return func(raw string) (int, []byte) { return e.get(role, "/assets/1/accounts/"+raw) }
		}
		// 帳號識別 0 不是合法的帳號識別，與其他不合法格式同一回應
		assertIDBoundaries(t, get(model.RoleAdmin), e.ids["root"], e.ids["executor"], true)
		assertIDBoundaries(t, get(model.RoleUser), e.ids["app"], e.ids["root"], true)
	})

	t.Run("asset_visibility_crossed_with_account_id_validity", func(t *testing.T) {
		e := newAccountGetOneEnv(t)
		gone := model.AssetAccount{AssetID: 1, Username: "retired"}
		require.NoError(t, e.db.Create(&gone).Error)
		require.NoError(t, e.db.Delete(&gone).Error)
		grantView(t, e.db, model.AccountScope{"app"}) // 只對資產 1 有授權，範圍內只有 app
		unreadable := map[string]string{
			"範圍外": fmt.Sprint(e.ids["root"]), "屬於他台": fmt.Sprint(e.ids["other"]),
			"系統專用帳號": fmt.Sprint(e.ids["executor"]), "已刪除": fmt.Sprint(gone.ID),
			"不存在": fmt.Sprint(accountGetOneMissingID), "32 位元上限": "4294967295",
		}
		malformed := append([]string{"0"}, singleReadMalformedIDs...)

		// 可見資產：可讀者 200；看不到的帳號識別彼此同不存在；不合法的帳號識別回 400 且彼此相同
		code, _ := e.get(model.RoleUser, fmt.Sprintf("/assets/1/accounts/%d", e.ids["app"]))
		require.Equal(t, http.StatusOK, code, "前提：範圍內帳號可讀")
		missCode, missBody := e.get(model.RoleUser, fmt.Sprintf("/assets/1/accounts/%d", accountGetOneMissingID))
		require.Equal(t, http.StatusNotFound, missCode)
		for name, raw := range unreadable {
			code, body := e.get(model.RoleUser, "/assets/1/accounts/"+raw)
			assert.Equal(t, missCode, code, "可見資產 %s：與不存在同狀態碼", name)
			assert.Equal(t, string(missBody), string(body), "可見資產 %s：與不存在同本文", name)
		}
		badCode, badBody := e.get(model.RoleUser, "/assets/1/accounts/"+malformed[0])
		require.Equal(t, http.StatusBadRequest, badCode, "可見資產：不合法的帳號識別回 400")
		for _, raw := range malformed[1:] {
			code, body := e.get(model.RoleUser, "/assets/1/accounts/"+raw)
			assert.Equal(t, badCode, code, "可見資產 %q：不合法的帳號識別彼此同狀態碼", raw)
			assert.Equal(t, string(badBody), string(body), "可見資產 %q：不合法的帳號識別彼此同本文", raw)
		}

		// 不可見資產與不存在資產：任何帳號識別（含可讀者、不合法格式）都得到同一個資產層回應，兩者彼此相同
		invisibleCode, invisibleBody := e.get(model.RoleUser, "/assets/2/accounts")
		require.Equal(t, http.StatusNotFound, invisibleCode, "前提：資產 2 不可見")
		all := append([]string{fmt.Sprint(e.ids["app"])}, malformed...)
		for _, raw := range unreadable {
			all = append(all, raw)
		}
		for _, assetRaw := range []string{"2", singleReadMissingRaw} {
			code, body := e.get(model.RoleUser, "/assets/"+assetRaw+"/accounts")
			assert.Equal(t, invisibleCode, code, "資產 %s 的列表：不可見與不存在同狀態碼", assetRaw)
			assert.Equal(t, string(invisibleBody), string(body), "資產 %s 的列表：不可見與不存在同本文", assetRaw)
			for _, raw := range all {
				code, body := e.get(model.RoleUser, "/assets/"+assetRaw+"/accounts/"+raw)
				assert.Equal(t, invisibleCode, code, "資產 %s 帳號 %q：與資產層回應同狀態碼", assetRaw, raw)
				assert.Equal(t, string(invisibleBody), string(body), "資產 %s 帳號 %q：與資產層回應同本文", assetRaw, raw)
			}
		}
	})
}
