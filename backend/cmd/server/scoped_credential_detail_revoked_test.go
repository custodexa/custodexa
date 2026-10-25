package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// detailRevokeSource 在第一次算檢視時先執行撤權，再委派內層：請求已通過能力閘，
// 撤權正好落在授權與檢視投影之間。輸出判定原樣委派，與正式組裝的單一範圍來源同型。
type detailRevokeSource struct {
	inner *authz.CredentialScopeReader
	hook  func()
	calls int
}

func (w *detailRevokeSource) CredentialScopeView(ctx context.Context) (asset.CredentialScopeView, error) {
	w.calls++
	if w.calls == 1 {
		w.hook()
	}
	return w.inner.CredentialScopeView(ctx)
}

func (w *detailRevokeSource) CredentialImpactScopeIn(ctx context.Context, tx *gorm.DB, capability string, ids []uint) (map[uint]bool, map[uint]bool, bool, error) {
	return w.inner.CredentialImpactScopeIn(ctx, tx, capability, ids)
}

func (w *detailRevokeSource) CredentialOutputScope(ctx context.Context) (asset.CredentialOutputScope, error) {
	return w.inner.CredentialOutputScope(ctx)
}

// 授權通過後、算檢視前撤掉主體最後一筆節點指派：詳情與刪除衝突名單都不得輸出範圍外掛載。
func TestScopedCredentialDetailRevokedBeforeView(t *testing.T) {
	forbidden := func(outAsset, outAcc uint) []soToken {
		return []soToken{soName("zz-det-out-host"), soNum("asset_id", outAsset), soNum("account_id", outAcc)}
	}
	setup := func(t *testing.T) (*outEnv, *detailRevokeSource, uint, []soToken) {
		e := newOutEnv(t)
		cred := e.soCred("zz-det-shared", "zz-det-user", e.nodeID(soNodeIn))
		inAsset := e.asset("zz-det-in-host", soNodeIn)
		outAsset := e.asset("zz-det-out-host", soNodeOut)
		e.mount(cred, inAsset)
		outAcc := e.mount(cred, outAsset)
		w := &detailRevokeSource{inner: authz.NewCredentialScopeReader(e.eval, e.db),
			hook: func() { e.soDropNodeAssignments(e.mgr) }}
		e.creds.WithScopeSource(w)
		return e, w, cred, forbidden(outAsset, outAcc)
	}

	t.Run("detail", func(t *testing.T) {
		e, w, cred, leaks := setup(t)
		code, raw := soServe(e.scRouter(e.mgr), http.MethodGet, credPath(cred), "")
		require.Equal(t, 1, w.calls, "PRECONDITION: revoke hook not fired")
		t.Logf("status=%d 包裝計數=%d", code, w.calls)
		soAssertNoLeak(t, raw, leaks, nil)
		require.NotEqual(t, http.StatusOK, code, raw)
	})

	t.Run("delete_in_use", func(t *testing.T) {
		e, w, cred, leaks := setup(t)
		code, raw := soServe(e.scRouter(e.mgr), http.MethodDelete, credPath(cred), "")
		require.Equal(t, 1, w.calls, "PRECONDITION: revoke hook not fired")
		t.Logf("status=%d 包裝計數=%d", code, w.calls)
		soAssertNoLeak(t, raw, leaks, nil)
	})
}
