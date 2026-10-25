package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// scMount 掛載來源檢查的資料集：範圍內節點與資產、範圍外節點與資產、四種來源憑證。
type scMount struct {
	*scEnv
	binder, holder    uint
	aIn, aIn2, aOut   uint
	inCred, outCred   uint
	globalCred, ghost uint
}

func newSCMount(t *testing.T) *scMount {
	t.Helper()
	return newSCMountOn(t, newSCEnv(t))
}

func newSCMountOn(t *testing.T, e *scEnv) *scMount {
	t.Helper()
	m := &scMount{scEnv: e, ghost: 999993}
	e.node("zz-sc-in", "")
	e.node("zz-sc-out", "")
	m.aIn = e.asset("zz-sc-asset-in-1", "zz-sc-in")
	m.aIn2 = e.asset("zz-sc-asset-in-2", "zz-sc-in")
	m.aOut = e.asset("zz-sc-asset-out-1", "zz-sc-out")
	m.inCred = e.cred("zz-sc-src-in", e.nodeID("zz-sc-in"))
	m.outCred = e.cred("zz-sc-src-out", e.nodeID("zz-sc-out"))
	m.globalCred = e.cred("zz-sc-src-global", nil)
	m.binder = e.user("zz-sc-binder")
	e.grant(m.binder, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialBind,
		authz.PermCredentialUpdate)
	m.holder = e.user("zz-sc-holder")
	e.grantGlobal(m.holder, e.role(authz.PermCredentialView, authz.PermCredentialUpdate,
		authz.PermCredentialBind, authz.PermCredentialRotate, authz.PermCredentialSetSecret))
	return m
}

func (m *scMount) mountCount(credID uint) int64 {
	var n int64
	require.NoError(m.t, m.db.Model(&model.AssetAccount{}).Where("credential_id = ?", credID).Count(&n).Error)
	return n
}

func (m *scMount) accountCount() int64 {
	var n int64
	require.NoError(m.t, m.db.Model(&model.AssetAccount{}).Count(&n).Error)
	return n
}

func TestCredentialMountSourceScope(t *testing.T) {
	t.Run("Bind 的三種不可用來源同形且不掛載", func(t *testing.T) {
		m := newSCMount(t)
		bind := func(credID, assetID uint) (int, string) {
			return m.call(m.binder, "POST", credPath(credID)+"/bindings", fmt.Sprintf(`{"asset_id":%d}`, assetID))
		}
		wantCode, wantBody := bind(m.ghost, m.aIn)
		require.Equal(t, http.StatusNotFound, wantCode, wantBody)
		before := m.accountCount()
		for _, src := range []uint{m.outCred, m.globalCred} {
			code, body := bind(src, m.aIn)
			require.Equal(t, wantCode, code)
			require.Equal(t, wantBody, body)
			require.Zero(t, m.mountCount(src))
		}
		require.Equal(t, before, m.accountCount(), "掛載數不變")

		// 範圍內來源成功；範圍內憑證掛到範圍外資產與不存在資產同形
		code, body := bind(m.inCred, m.aIn)
		require.Less(t, code, 300, body)
		require.EqualValues(t, 1, m.mountCount(m.inCred))
		wantCode, wantBody = bind(m.inCred, 999994)
		code, body = bind(m.inCred, m.aOut)
		require.Equal(t, wantCode, code)
		require.Equal(t, wantBody, body)
		require.EqualValues(t, 1, m.mountCount(m.inCred), "範圍外資產不得被掛上")
	})

	t.Run("Bind 的拒絕在審計留下範圍拒絕", func(t *testing.T) {
		m := newSCMount(t)
		for _, id := range []uint{m.outCred, m.ghost} {
			m.call(m.binder, "POST", credPath(id)+"/bindings", fmt.Sprintf(`{"asset_id":%d}`, m.aIn))
		}
		var logs []model.AuditLog
		require.NoError(t, m.db.Where("details LIKE ?", "%\"denial\":\"scope\"%").Find(&logs).Error)
		require.GreaterOrEqual(t, len(logs), 2, "範圍外與不存在來源的審計皆為範圍拒絕")
	})

	t.Run("Rebind 新憑證三種不可用來源同形", func(t *testing.T) {
		m := newSCMount(t)
		acc := m.mount(m.globalCred, m.aIn)
		path := fmt.Sprintf("/api/v1/assets/%d/accounts/%d/credential", m.aIn, acc)
		put := func(credID uint) (int, string) {
			return m.call(m.binder, "PUT", path, fmt.Sprintf(`{"credential_id":%d}`, credID))
		}
		wantCode, wantBody := put(m.ghost)
		require.Equal(t, http.StatusNotFound, wantCode, wantBody)
		for _, src := range []uint{m.outCred} {
			code, body := put(src)
			require.Equal(t, wantCode, code)
			require.Equal(t, wantBody, body)
		}
		var a model.AssetAccount
		require.NoError(t, m.db.First(&a, acc).Error)
		require.Equal(t, m.globalCred, a.CredentialID, "掛載未被換走")
	})

	t.Run("Rebind 舊憑證在範圍外或全域時不驗歸屬且審計記下新憑證", func(t *testing.T) {
		m := newSCMount(t)
		oldOut := m.cred("zz-sc-old-out", m.nodeID("zz-sc-out"))
		accOut := m.mount(oldOut, m.aIn)
		accGlobal := m.mount(m.globalCred, m.aIn2)
		for _, c := range []struct{ assetID, acc, previous uint }{{m.aIn, accOut, oldOut}, {m.aIn2, accGlobal, m.globalCred}} {
			target := m.cred(fmt.Sprintf("zz-sc-target-%d", c.acc), m.nodeID("zz-sc-in"))
			code, body := m.call(m.binder, "PUT",
				fmt.Sprintf("/api/v1/assets/%d/accounts/%d/credential", c.assetID, c.acc),
				fmt.Sprintf(`{"credential_id":%d}`, target))
			require.Equal(t, http.StatusOK, code, body)
			var a model.AssetAccount
			require.NoError(t, m.db.First(&a, c.acc).Error)
			require.Equal(t, target, a.CredentialID)
			var logs []model.AuditLog
			require.NoError(t, m.db.Where("resource_id = ? AND details LIKE ?", target, "%\"operation\":\"rebind\"%").
				Find(&logs).Error)
			require.NotEmpty(t, logs, "改綁審計記下新憑證")
			require.Contains(t, logs[0].Details, fmt.Sprintf(`"account_id":%d`, c.acc))
			var details map[string]any
			require.NoError(t, json.Unmarshal([]byte(logs[0].Details), &details))
			require.EqualValues(t, target, details["credential_id"], "credential_id 為改綁後的新憑證")
			require.EqualValues(t, c.previous, details["previous_credential_id"], "審計記下改綁前的憑證")
		}
	})

	t.Run("全域持有者對部分掛載在其他節點的憑證只看能力", func(t *testing.T) {
		m := newSCMount(t)
		part := m.cred("zz-sc-part", m.nodeID("zz-sc-in"))
		accIn := m.mount(part, m.aIn)
		accOut := m.mount(part, m.aOut)

		// 中繼資料、改密、改綁皆成功
		code, body := m.call(m.holder, "PUT", credPath(part), `{"note":"global-holder"}`)
		require.Equal(t, http.StatusOK, code, body)
		code, body = m.call(m.holder, "POST", credPath(part)+"/secret", `{"password":"zz-sc-new-secret"}`)
		require.Less(t, code, 300, body)
		target := m.cred("zz-sc-part-target", nil)
		code, body = m.call(m.holder, "PUT",
			fmt.Sprintf("/api/v1/assets/%d/accounts/%d/credential", m.aOut, accOut),
			fmt.Sprintf(`{"credential_id":%d}`, target))
		require.Equal(t, http.StatusOK, code, body)
		_ = accIn

		// 輪替的授權判定與只看能力的全域口徑一致：持有 rotate 即放行，缺能力才拒絕
		d, err := m.adapter.AuthorizeCredentialManagement(m.ctx(m.holder), nil,
			asset.CredentialManagementActor{UserID: m.holder}, asset.CredentialManagementRequest{
				Operation: asset.CredOpRotate, Capabilities: []string{asset.CredCapRotate},
				CredentialIDs: []uint{part}, MountedAssetIDs: []uint{m.aIn, m.aOut}})
		require.NoError(t, err)
		require.True(t, d.Allowed)
		require.Nil(t, d.ScopeDenial)
		d, err = m.adapter.AuthorizeCredentialManagement(m.ctx(m.binder), nil,
			asset.CredentialManagementActor{UserID: m.binder}, asset.CredentialManagementRequest{
				Operation: asset.CredOpRotate, Capabilities: []string{asset.CredCapRotate},
				CredentialIDs: []uint{part}, MountedAssetIDs: []uint{m.aIn, m.aOut}})
		require.NoError(t, err)
		require.False(t, d.Allowed)
		require.Equal(t, asset.CredCapRotate, d.Missing)
	})

	t.Run("注入憑證查詢錯誤時 Bind 回內部錯誤且零寫入", func(t *testing.T) {
		m := newSCMount(t)
		before := m.accountCount()
		const cb = "zz-sc-inject-credential-query-error"
		require.NoError(t, m.db.Callback().Query().After("gorm:query").Register(cb, func(db *gorm.DB) {
			if db.Statement.Table == "credentials" {
				_ = db.AddError(errors.New("injected credential query error"))
			}
		}))
		code, body := m.call(m.binder, "POST", credPath(m.inCred)+"/bindings", fmt.Sprintf(`{"asset_id":%d}`, m.aIn))
		require.NoError(t, m.db.Callback().Query().Remove(cb))
		require.GreaterOrEqual(t, code, http.StatusInternalServerError, body)
		require.NotEqual(t, http.StatusNotFound, code, body)
		require.Equal(t, before, m.accountCount(), "零寫入")
		require.Zero(t, m.mountCount(m.inCred))
	})

	t.Run("建資產帶 credential_id 的三種不可用來源同形且資產表筆數不變", func(t *testing.T) {
		m := newSCMount(t)
		creator := m.user("zz-sc-asset-creator")
		m.grant(creator, []string{"zz-sc-in"}, authz.PermAssetView, authz.PermAssetCreate,
			authz.PermCredentialView, authz.PermCredentialBind)
		// 另持全域 credential:manage：本案例不依賴 credential_id 欄位條件的權限點
		m.grantGlobal(creator, m.role(authz.PermCredentialManage))
		inNode := *m.nodeID("zz-sc-in")
		create := func(name string, credID uint) (int, string) {
			return m.do(creator, true, "POST", "/api/v1/assets", fmt.Sprintf(
				`{"name":%q,"protocol":"ssh","host":"10.89.0.%d","port":22,"node_ids":[%d],"credential_id":%d}`,
				name, len(name), inNode, credID))
		}
		before, accounts := saAssetCount(t, m.saEnv), m.accountCount()
		wantCode, wantBody := create("zz-sc-new-ghost", m.ghost)
		require.GreaterOrEqual(t, wantCode, 400, wantBody)
		for _, src := range []uint{m.outCred, m.globalCred} {
			code, body := create("zz-sc-new-ghost", src)
			require.Equal(t, wantCode, code)
			require.Equal(t, wantBody, body)
			require.Zero(t, m.mountCount(src))
		}
		require.Equal(t, before, saAssetCount(t, m.saEnv), "資產表筆數不變")
		require.Equal(t, accounts, m.accountCount(), "帳號表筆數不變")

		code, body := create("zz-sc-new-in", m.inCred)
		require.Equal(t, http.StatusCreated, code, body)
		require.EqualValues(t, 1, m.mountCount(m.inCred))
	})

	runMountEntryCases(t)

	t.Run("SQLite 掛載交易內重判", func(t *testing.T) { runBindRecheckCases(t, newSCMount(t), false) })
	t.Run("PostgreSQL 掛載交易內重判", func(t *testing.T) {
		runBindRecheckCases(t, newSCMountOn(t, newSCEnvPG(t, "sc_mount_source")), true)
	})
}

func (e *scEnv) ctx(uid uint) context.Context {
	ctx := authz.ContextWithPrincipal(context.Background(), &authz.Principal{UserID: uid})
	return context.WithValue(ctx, "userID", uid) //nolint:staticcheck // 沿用審計 context 慣例
}
