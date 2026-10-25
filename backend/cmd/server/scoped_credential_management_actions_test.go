package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 管理動作以憑證歸屬判定：範圍化主體對歸屬在範圍內的共用憑證可管理，不因另有掛載在範圍外而被拒；
// 歸屬在範圍外的憑證所有管理動作與不存在同形且零變更。
func TestScopedCredentialManagementActions(t *testing.T) {
	m := newSCMount(t)
	mgr := m.user("zz-sc-manager")
	m.grant(mgr, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialUpdate,
		authz.PermCredentialSetSecret, authz.PermCredentialConvertScope, authz.PermCredentialDetach,
		authz.PermCredentialBind, authz.PermCredentialDelete)

	t.Run("歸屬在範圍內但另掛範圍外資產時可改中繼資料", func(t *testing.T) {
		part := m.cred("zz-sc-act-part", m.nodeID("zz-sc-in"))
		m.mount(part, m.aIn)
		m.mount(part, m.aOut)
		code, body := m.call(mgr, "PUT", credPath(part), `{"note":"scoped-note"}`)
		require.Equal(t, http.StatusOK, code, body)
		var c model.Credential
		require.NoError(t, m.db.First(&c, part).Error)
		require.Equal(t, "scoped-note", c.Note)
		require.NotContains(t, body, "impact_confirmation", "中繼資料修改不要求確認")
	})

	t.Run("轉專用要求唯一掛載資產在範圍內", func(t *testing.T) {
		ghostCode, ghostBody := m.call(mgr, "POST", credPath(m.inCred)+"/bindings", `{"asset_id":999995}`)
		outSolo := m.cred("zz-sc-act-solo-out", m.nodeID("zz-sc-in"))
		m.mount(outSolo, m.aOut)
		code, body := m.call(mgr, "POST", credPath(outSolo)+"/scope", `{"scope":"dedicated"}`)
		require.Equal(t, ghostCode, code, body)
		require.Equal(t, ghostBody, body, "與目標資產不存在同形")
		var c model.Credential
		require.NoError(t, m.db.First(&c, outSolo).Error)
		require.Equal(t, model.CredentialScopeShared, c.Scope)

		inSolo := m.cred("zz-sc-act-solo-in", m.nodeID("zz-sc-in"))
		m.mount(inSolo, m.aIn2)
		code, body = m.call(mgr, "POST", credPath(inSolo)+"/scope", `{"scope":"dedicated"}`)
		require.Equal(t, http.StatusOK, code, body)
		// 新變數：沿用已帶主鍵的 c 會讓查詢多一個 id 條件而查無
		c = model.Credential{}
		require.NoError(t, m.db.First(&c, inSolo).Error)
		require.Equal(t, model.CredentialScopeDedicated, c.Scope)
	})

	t.Run("卸載範圍外掛載與不存在掛載同形", func(t *testing.T) {
		part := m.cred("zz-sc-act-unbind", m.nodeID("zz-sc-in"))
		accOut := m.mount(part, m.aOut)
		wantCode, wantBody := m.call(mgr, "DELETE", fmt.Sprintf("%s/bindings/%d", credPath(part), 999996), "")
		code, body := m.call(mgr, "DELETE", fmt.Sprintf("%s/bindings/%d", credPath(part), accOut), "")
		require.Equal(t, wantCode, code)
		require.Equal(t, wantBody, body)
		require.EqualValues(t, 1, m.mountCount(part))
	})

	t.Run("脫離範圍外掛載與不存在掛載同形且零變更", func(t *testing.T) {
		part := m.cred("zz-sc-act-detach", m.nodeID("zz-sc-in"))
		accOut := m.mount(part, m.aOut)
		rot := asset.NewCredentialRotationService(m.db, m.assets, nil, nil, m.codec, audit.NewTxSink(), m.adapter)
		req := asset.DetachCredentialRequest{Source: asset.DetachSourceRandom}
		_, wantErr := rot.Detach(m.ctx(mgr), part, 999997, req)
		require.ErrorIs(t, wantErr, asset.ErrCredentialBindingNotFound)
		_, err := rot.Detach(m.ctx(mgr), part, accOut, req)
		require.ErrorIs(t, err, asset.ErrCredentialBindingNotFound, "範圍外資產上的掛載與不存在掛載同一哨兵")
		var a model.AssetAccount
		require.NoError(t, m.db.First(&a, accOut).Error)
		require.Equal(t, part, a.CredentialID, "掛載不動")
		var c model.Credential
		require.NoError(t, m.db.First(&c, part).Error)
		require.Nil(t, c.ActiveRotationID, "未建立輪替")
	})

	t.Run("範圍外憑證的所有管理動作與不存在相同且零變更", func(t *testing.T) {
		out := m.cred("zz-sc-act-out", m.nodeID("zz-sc-out"))
		accOut := m.mount(out, m.aOut)
		var before model.Credential
		require.NoError(t, m.db.First(&before, out).Error)
		versions := func() int64 {
			var n int64
			require.NoError(t, m.db.Model(&model.CredentialSecretVersion{}).Where("credential_id = ?", out).Count(&n).Error)
			return n
		}
		v0 := versions()
		for _, rq := range []struct{ method, suffix, body string }{
			{"PUT", "", `{"note":"leak"}`},
			{"POST", "/secret", `{"password":"zz-sc-leak-secret"}`},
			{"POST", "/scope", `{"scope":"dedicated"}`},
			{"POST", "/bindings", fmt.Sprintf(`{"asset_id":%d}`, m.aIn)},
			{"DELETE", "", ""},
		} {
			wantCode, wantBody := m.call(mgr, rq.method, credPath(m.ghost)+rq.suffix, rq.body)
			code, body := m.call(mgr, rq.method, credPath(out)+rq.suffix, rq.body)
			require.Equal(t, wantCode, code, rq.method+rq.suffix)
			require.Equal(t, wantBody, body, rq.method+rq.suffix)
		}
		var after model.Credential
		require.NoError(t, m.db.First(&after, out).Error)
		require.Equal(t, before.Note, after.Note)
		require.Equal(t, before.Scope, after.Scope)
		require.Equal(t, v0, versions())
		require.EqualValues(t, 1, m.mountCount(out))
		_ = accOut

		// 改綁的新憑證方向：新憑證歸屬在範圍外，與不存在同形，掛載不動
		acc := m.mount(m.globalCred, m.aIn)
		path := fmt.Sprintf("/api/v1/assets/%d/accounts/%d/credential", m.aIn, acc)
		wantCode, wantBody := m.call(mgr, "PUT", path, fmt.Sprintf(`{"credential_id":%d}`, m.ghost))
		code, body := m.call(mgr, "PUT", path, fmt.Sprintf(`{"credential_id":%d}`, out))
		require.Equal(t, wantCode, code)
		require.Equal(t, wantBody, body)
		var a model.AssetAccount
		require.NoError(t, m.db.First(&a, acc).Error)
		require.Equal(t, m.globalCred, a.CredentialID)
	})

	t.Run("範圍化檢視者讀引用範圍外憑證的帳號列不含其身分", func(t *testing.T) {
		runAccountRowProjectionCase(t, newSCMount(t))
	})

	t.Run("管理授權未注入時仍拒絕", func(t *testing.T) {
		bare := asset.NewCredentialService(m.assets, m.codec, audit.NewTxSink())
		note := "x"
		_, err := bare.Update(m.ctx(m.super), m.inCred, &asset.UpdateCredentialRequest{Note: &note})
		require.ErrorIs(t, err, asset.ErrCredentialAuthzUnavailable)
	})
}
