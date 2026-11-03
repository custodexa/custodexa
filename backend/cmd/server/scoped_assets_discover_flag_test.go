package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 列級旗標 discover_accounts：依主機帳號盤點權限點自己的有效範圍判定；
// 只經節點範圍持有盤點權限點不構成範圍化檢視者（不附旗標、不改列表語義）。
func TestAssetRowActionsDiscoverAccounts(t *testing.T) {
	e := newSAEnv(t)
	saTree(e)
	in := e.asset("zz-sa-disc-in", "zz-sa-a1")
	out := e.asset("zz-sa-disc-out", "zz-sa-b")

	t.Run("scoped_viewer_in_scope_allowed", func(t *testing.T) {
		u := e.user("zz-sa-disc-ok")
		e.grantNodes(u, e.role(authz.PermAssetView, authz.PermAccountDiscover), "zz-sa-a")
		a := saActions(t, e.list(u, "").row(in))
		assert.Equal(t, true, a["discover_accounts"]["allowed"])
	})

	t.Run("scoped_viewer_without_permission_denied", func(t *testing.T) {
		u := e.user("zz-sa-disc-no")
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		a := saActions(t, e.list(u, "").row(in))
		assert.Equal(t, false, a["discover_accounts"]["allowed"])
		assert.Equal(t, "no_capability", a["discover_accounts"]["reason"])
	})

	t.Run("discover_scope_independent_of_update_scope", func(t *testing.T) {
		u := e.user("zz-sa-disc-split")
		e.grantNodes(u, e.role(authz.PermAssetView, authz.PermAssetUpdate), "zz-sa-a")
		e.grantNodes(u, e.role(authz.PermAccountDiscover), "zz-sa-b")
		l := e.list(u, "")
		assert.Equal(t, true, saActions(t, l.row(in))["edit"]["allowed"])
		assert.Equal(t, false, saActions(t, l.row(in))["discover_accounts"]["allowed"], "盤點範圍不跟 asset:update")
	})

	t.Run("global_holder_unrestricted", func(t *testing.T) {
		u := e.user("zz-sa-disc-global")
		e.builtin(u, model.RoleUser)
		e.grantGlobal(u, e.role(authz.PermAccountDiscover))
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		e.connGrant(u, out)
		a := saActions(t, e.list(u, "").row(out))
		assert.Equal(t, true, a["discover_accounts"]["allowed"])
	})

	t.Run("node_scope_discover_only_is_not_scoped_viewer", func(t *testing.T) {
		u := e.user("zz-sa-disc-only")
		e.builtin(u, model.RoleUser)
		e.grantNodes(u, e.role(authz.PermAccountDiscover), "zz-sa-a")
		e.connGrant(u, in)
		code, raw := e.do(u, true, "GET", "/api/v1/assets?page_size=500", "")
		require.Equal(t, http.StatusOK, code, raw)
		assert.False(t, strings.Contains(raw, `"actions"`), "列不附旗標")
		assert.False(t, strings.Contains(raw, `"management_scope"`), "不構成範圍化檢視者")
		code, raw = e.do(u, true, "GET", idPath(in), "")
		require.Equal(t, http.StatusOK, code, raw)
		assert.False(t, strings.Contains(raw, `"actions"`), "詳情不附旗標")
	})
}
