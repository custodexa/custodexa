package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 執行身分讀取的 credential 欄：與帳號列表同一個投影器，範圍外共用憑證只帶共用與範圍外標記。

func TestExecutorGetCredentialProjection(t *testing.T) {
	env := newSAEnv(t)
	cat, err := authz.CatalogueWithScopedEnforcedForTest(append(saPerms, authz.PermAssetExecutorManage)...)
	require.NoError(t, err)
	env.cat = cat
	env.eval = authz.NewScopeEvaluator(cat, asset.NewScopeTopologyReader())
	env.assets.SetAssetWriteScopePort(authz.NewAssetWriteScope(env.eval))

	inNode := env.node("zz-sa-ecp-in", "")
	outNode := env.node("zz-sa-ecp-out", "")
	a := env.asset("zz-sa-ecp-a", "zz-sa-ecp-in")
	b := env.asset("zz-sa-ecp-b", "zz-sa-ecp-in")
	credCaps := []authz.Permission{authz.PermCredentialView, authz.PermCredentialCreate, authz.PermCredentialBind,
		authz.PermCredentialUpdate, authz.PermCredentialDelete}

	scoped := env.user("zz-sa-ecp-scoped")
	env.grantNodes(scoped, env.role(append([]authz.Permission{authz.PermAssetView, authz.PermAssetExecutorManage}, credCaps...)...),
		"zz-sa-ecp-in")

	get := func(assetID uint) (int, map[string]any, string) {
		res := env.doExecutor(scoped, "GET", idPath(assetID)+"/executor", "")
		m := map[string]any{}
		_ = json.Unmarshal([]byte(res.body), &m)
		return res.code, m, res.body
	}

	t.Run("f_dedicated_credential_is_a_full_account_row", func(t *testing.T) {
		put := env.doExecutor(scoped, "PUT", idPath(a)+"/executor", executorGenerateBody)
		require.Equal(t, http.StatusOK, put.code, put.body)
		code, m, raw := get(a)
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, "generate", m["source"])
		cred, ok := m["credential"].(map[string]any)
		require.True(t, ok, "credential 欄存在: %s", raw)
		assert.Equal(t, false, cred["shared_credential"])
		assert.EqualValues(t, 1, cred["binding_count"])
		assert.Contains(t, cred, "credential_id")
		assert.NotContains(t, cred, "credential_out_of_scope")
		var putBody map[string]any
		require.NoError(t, json.Unmarshal([]byte(put.body), &putBody))
		assert.Contains(t, putBody, "credential", "PUT 回應與 GET 同形")
		assert.Contains(t, putBody, "source")
	})

	t.Run("g_out_of_scope_shared_credential_is_masked", func(t *testing.T) {
		name := "zz-sa-ecp-secret-shared-name"
		kind := model.CredentialOwnerNode
		outID := outNode
		cred := model.Credential{Name: &name, Scope: model.CredentialScopeShared, Username: "svc-ecp",
			SecretType: model.ChangeSecretTypeSSHKey, AuthMethod: "sql", ProtocolFamily: model.ProtocolFamilySSH,
			OwnerKind: &kind, OwnerNodeID: &outID}
		require.NoError(t, env.db.Create(&cred).Error)
		acct := model.AssetAccount{AssetID: b, CredentialID: cred.ID, Username: "svc-ecp",
			Purpose: model.AccountPurposeExecutor, ExecutorSource: "shared", Privileged: true}
		require.NoError(t, env.db.Create(&acct).Error)
		_ = inNode

		code, m, raw := get(b)
		require.Equal(t, http.StatusOK, code, raw)
		c, ok := m["credential"].(map[string]any)
		require.True(t, ok, raw)
		assert.Equal(t, true, c["credential_out_of_scope"])
		assert.Equal(t, true, c["shared_credential"])
		for _, k := range []string{"credential_id", "credential_name", "binding_count"} {
			assert.NotContains(t, c, k, "範圍外共用憑證不帶 %s", k)
		}
		assert.NotContains(t, raw, name, "回應不含該憑證名稱")
		assert.NotContains(t, m, "has_public_key")
		assert.NotContains(t, m, "fingerprint")
		// 除 credential、source 外鍵集與 BASE（未設定／一般設定的形狀）相同
		allowed := map[string]bool{"configured": true, "account_id": true, "username": true, "secret_type": true,
			"credential": true, "source": true}
		for k := range m {
			assert.True(t, allowed[k], "非預期的鍵 %s", k)
		}
	})
}
