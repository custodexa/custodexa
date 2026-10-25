package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 範圍化主體以正式管理授權轉接頭操作範圍外憑證時，回應不得與「不存在」分得出來：
// 批次改歸混入範圍外、歸屬全域或不存在的識別，三者回應逐位元相同、只帶筆數；
// 轉換、宣告新秘密、刪除遇到範圍外且輪替進行中的憑證，回應與不存在相同，不先回進行中衝突。
func TestScopedCredentialExistenceSameShape(t *testing.T) {
	t.Run("SQLite", func(t *testing.T) {
		runScopedCredentialExistenceCases(t, func(t *testing.T) *scMount { return newSCMount(t) })
	})
	t.Run("PostgreSQL", func(t *testing.T) {
		runScopedCredentialExistenceCases(t, func(t *testing.T) *scMount {
			return newSCMountOn(t, newSCEnvPG(t, "sc_existence_shape"))
		})
	})
}

func runScopedCredentialExistenceCases(t *testing.T, open func(t *testing.T) *scMount) {
	t.Run("批次改歸的範圍外、歸屬全域與不存在三者回應相同且零寫入", func(t *testing.T) {
		runBatchReassignSameShape(t, open(t))
	})
	t.Run("範圍外且輪替進行中與不存在同為不存在回應", func(t *testing.T) {
		runRotationActiveOutOfScopeSameShape(t, open(t))
	})
	t.Run("自憑證側卸載的範圍外憑證與不存在同形且零寫入", func(t *testing.T) {
		runUnbindOutOfScopeSameShape(t, open(t))
	})
	t.Run("整組輪替起始的範圍外各狀態與不存在同形且零寫入", func(t *testing.T) {
		runRotationStartOutOfScopeSameShape(t, open(t))
	})
	t.Run("補跑與放棄的範圍外各狀態與不存在同形且零寫入", func(t *testing.T) {
		runRetryAbandonOutOfScopeSameShape(t, open(t))
	})
}

func runBatchReassignSameShape(t *testing.T, m *scMount) {
	m.node("zz-sc-in-child", "zz-sc-in")
	mgr := m.user("zz-sc-reassigner")
	m.grant(mgr, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialUpdate)
	target := *m.nodeID("zz-sc-in-child")
	reassign := func(ids ...uint) (int, string) {
		raw, err := json.Marshal(map[string]any{
			"credential_ids": ids,
			"ownership":      map[string]any{"kind": model.CredentialOwnerNode, "node_id": target},
		})
		require.NoError(t, err)
		return m.call(mgr, "POST", "/api/v1/credentials/ownership", string(raw))
	}
	owners := func() map[uint]string {
		out := map[uint]string{}
		for _, id := range []uint{m.inCred, m.outCred, m.globalCred} {
			var c model.Credential
			require.NoError(t, m.db.First(&c, id).Error)
			node := "-"
			if c.OwnerNodeID != nil {
				node = fmt.Sprint(*c.OwnerNodeID)
			}
			out[id] = fmt.Sprintf("%v/%s", *c.OwnerKind, node)
		}
		return out
	}
	before := owners()
	advances := m.topo.counts().advances

	for _, combo := range []struct {
		name    string
		withIn  bool
		wantCnt float64
	}{{"單筆", false, 1}, {"混入一筆可操作者", true, 1}} {
		ids := func(x uint) []uint {
			if combo.withIn {
				return []uint{m.inCred, x}
			}
			return []uint{x}
		}
		wantCode, wantBody := reassign(ids(m.ghost)...)
		require.Equal(t, http.StatusNotFound, wantCode, wantBody)
		for _, x := range []struct {
			label string
			id    uint
		}{{"範圍外節點", m.outCred}, {"歸屬全域", m.globalCred}} {
			code, body := reassign(ids(x.id)...)
			require.Equal(t, wantCode, code, combo.name+"／"+x.label+"：%s", body)
			require.JSONEq(t, wantBody, body, combo.name+"／"+x.label)
			require.Equal(t, wantBody, body, combo.name+"／"+x.label+"：逐位元相同")
		}
		var parsed map[string]any
		require.NoError(t, json.Unmarshal([]byte(wantBody), &parsed), wantBody)
		require.Equal(t, string(apierror.CodeBatchItemsUnavailable), parsed["code"], wantBody)
		assertNoIdentityInBody(t, parsed, wantBody, combo.wantCnt, m.inCred, m.outCred, m.globalCred, m.ghost)
	}
	require.Equal(t, before, owners(), "整批拒絕時任何一筆的歸屬都不動")
	require.Equal(t, advances, m.topo.counts().advances, "整批拒絕不推進權限版本")

	// 正向對照：只送可操作者即成功改歸，證明拒絕來自混入的那一筆
	code, body := reassign(m.inCred)
	require.Equal(t, http.StatusOK, code, body)
	require.JSONEq(t, `{"changed":1}`, body)
}

// assertNoIdentityInBody 回應只帶錯誤碼與筆數：不含名稱，也不含任何一筆送入的識別。
func assertNoIdentityInBody(t *testing.T, parsed map[string]any, raw string, wantCount float64, ids ...uint) {
	t.Helper()
	require.NotContains(t, raw, "zz-sc", "回應不含名稱")
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				require.NotContains(t, []string{"id", "ids", "credential_id", "credential_ids", "name", "names"}, k, raw)
				walk(k, vv)
			}
		case []any:
			for _, vv := range x {
				walk(key, vv)
			}
		case float64:
			if key == "count" {
				require.Equal(t, wantCount, x, raw)
				return
			}
			for _, id := range ids {
				require.NotEqual(t, float64(id), x, "欄位 %s 的值是送入的識別: %s", key, raw)
			}
		}
	}
	walk("", parsed)
	require.Contains(t, raw, `"count"`, "帶不可操作筆數")
}

func runRotationActiveOutOfScopeSameShape(t *testing.T, m *scMount) {
	mgr := m.user("zz-sc-rotation-mgr")
	m.grant(mgr, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialUpdate,
		authz.PermCredentialSetSecret, authz.PermCredentialConvertScope, authz.PermCredentialDelete)
	out := m.cred("zz-sc-rot-out", m.nodeID("zz-sc-out"))
	in := m.cred("zz-sc-rot-in", m.nodeID("zz-sc-in"))
	for _, id := range []uint{out, in} {
		require.NoError(t, m.db.Model(&model.Credential{}).Where("id = ?", id).
			Update("active_rotation_id", 424242).Error)
	}
	for _, rq := range []struct{ method, suffix, body string }{
		{"POST", "/scope", `{"scope":"dedicated"}`},
		{"POST", "/secret", `{"password":"zz-sc-rot-secret"}`},
		{"DELETE", "", ""},
		{"PUT", "", `{"note":"zz-sc-rot-note"}`},
	} {
		label := rq.method + rq.suffix
		wantCode, wantBody := m.call(mgr, rq.method, credPath(m.ghost)+rq.suffix, rq.body)
		require.Equal(t, http.StatusNotFound, wantCode, label+"：%s", wantBody)
		code, body := m.call(mgr, rq.method, credPath(out)+rq.suffix, rq.body)
		require.Equal(t, wantCode, code, label+"：%s", body)
		require.Equal(t, wantBody, body, label+"：範圍外且輪替進行中與不存在逐位元相同")

		// 正向對照：範圍內且輪替進行中仍回進行中衝突，進行中拒絕沒有因順序調整而消失
		code, body = m.call(mgr, rq.method, credPath(in)+rq.suffix, rq.body)
		require.Equal(t, http.StatusConflict, code, label+"：%s", body)
		require.Contains(t, body, string(apierror.CodeCredentialRotationActive), label)
	}
	var c model.Credential
	require.NoError(t, m.db.First(&c, out).Error, "範圍外憑證未被刪除")
	require.Equal(t, model.CredentialScopeShared, c.Scope, "範圍外憑證未被轉換")
	require.Empty(t, c.Note, "範圍外憑證未被修改")
}
