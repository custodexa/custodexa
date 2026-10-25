package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/modules/authz"
)

// assertDedicatedFirstMountProjection 多掛載專用憑證（遷移報告列為異常的形狀）的範圍判定：
// 列表集合、帳號列投影、列級旗標與單筆解析一律以最早一筆未刪除掛載判定。
//
// outFirst 先掛範圍外、後掛範圍內；inFirst 反之。只管範圍內節點的檢視者只看得到 inFirst，
// outFirst 的列表、詳情與帳號列都不得放行，顯示名（取最早一筆掛載的資產名）也不得外露；
// 只管範圍外節點的檢視者正好相反。
func assertDedicatedFirstMountProjection(t *testing.T, e *scEnv) {
	t.Helper()
	e.node("zz-fm-in", "")
	e.node("zz-fm-out", "")
	aIn := e.asset("zz-fm-asset-in", "zz-fm-in")
	aOut := e.asset("zz-fm-asset-out", "zz-fm-out")
	outFirst := e.dedicated(aOut)
	e.mount(outFirst, aIn)
	inFirst := e.dedicated(aIn)
	e.mount(inFirst, aOut)

	perms := []authz.Permission{authz.PermCredentialView, authz.PermCredentialUpdate, authz.PermCredentialSetSecret}
	viewerIn := e.user("zz-fm-viewer-in")
	e.grant(viewerIn, []string{"zz-fm-in"}, perms...)
	viewerOut := e.user("zz-fm-viewer-out")
	e.grant(viewerOut, []string{"zz-fm-out"}, perms...)

	const missing = uint(999992)
	reader := authz.NewCredentialScopeReader(e.eval, e.db)
	for _, c := range []struct {
		name          string
		uid           uint
		visible, hide uint
		hiddenAsset   string
	}{
		{"範圍內檢視者", viewerIn, inFirst, outFirst, "zz-fm-asset-out"},
		{"範圍外檢視者", viewerOut, outFirst, inFirst, "zz-fm-asset-in"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := e.list(c.uid, "page_size=200")
			require.Equal(t, map[uint]bool{c.visible: true}, l.ids(), "列表只含最早一筆掛載在範圍內的專用憑證")
			require.NotContains(t, l.raw, c.hiddenAsset, "列表不得帶出範圍外資產名")
			ded := e.list(c.uid, "ownership=asset&page_size=200")
			require.Equal(t, map[uint]bool{c.visible: true}, ded.ids())

			// 列級旗標依最早一筆掛載（範圍內）判定
			acts := l.row(c.visible)["actions"].(map[string]any)
			require.Equal(t, true, acts["edit"].(map[string]any)["allowed"])
			require.Equal(t, true, acts["set_secret"].(map[string]any)["allowed"])

			// 詳情：可見者 200 且不帶範圍外資產名；不可見者與不存在者逐字同形
			code, raw := e.call(c.uid, "GET", credPath(c.visible), "")
			require.Equal(t, http.StatusOK, code, raw)
			require.NotContains(t, raw, c.hiddenAsset)
			wantCode, wantBody := e.call(c.uid, "GET", credPath(missing), "")
			require.Equal(t, http.StatusNotFound, wantCode)
			code, raw = e.call(c.uid, "GET", credPath(c.hide), "")
			require.Equal(t, wantCode, code)
			require.Equal(t, wantBody, raw)

			// 帳號列投影與列表同一個集合述詞
			p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, c.uid, authz.TokenFacts{})
			require.NoError(t, err)
			inView, scoped, err := reader.CredentialsInView(authz.ContextWithPrincipal(context.Background(), p),
				[]uint{outFirst, inFirst})
			require.NoError(t, err)
			require.True(t, scoped)
			require.Equal(t, map[uint]bool{c.visible: true}, inView)
		})
	}
}
