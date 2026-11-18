package main

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 全唯讀的 API token 對每一條開放的寫入路由都回專屬的 403（正式的路由註冊函式建鏈）。
//
// 受測集合由登錄驅動：登錄中開放且執行期性質不是讀的每一條路由，之後新增的開放寫入路由自動涵蓋。另併入逐條
// 對照檔（testdata/api-token-route-scope.tsv）中開放且性質為寫的每一條：登錄的某一列被誤改成讀時，對照檔
// 仍要求它被拒絕，這支測試因此失敗（與登錄和對照檔的逐條比對互為兩道）。拒絕發生在處理函式之前，所以不需要
// 合法的請求內容；路徑上的參數一律以 1 代入。

const apiTokenScopeListRel = "../../internal/middleware/testdata/api-token-route-scope.tsv"

// openWriteRoutesFromScopeList 對照檔中開放且性質為寫的「方法 樣板路徑」。
func openWriteRoutesFromScopeList(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open(filepath.FromSlash(apiTokenScopeListRel))
	require.NoError(t, err)
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			require.Equal(t, "method\tpath\tdecision\tnature\toutbound", sc.Text(), "對照檔表頭")
			continue
		}
		cols := strings.Split(sc.Text(), "\t")
		require.Len(t, cols, 5, sc.Text())
		if cols[2] == string(middleware.RouteAccessOpen) && cols[3] == string(middleware.RouteNatureWrite) {
			out[cols[0]+" "+cols[1]] = true
		}
	}
	require.NoError(t, sc.Err())
	return out
}

// concreteRoutePath 把樣板路徑的參數段換成實際值（:x → 1，*x → x）。
func concreteRoutePath(pattern string) string {
	segs := strings.Split(pattern, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, ":"):
			segs[i] = "1"
		case strings.HasPrefix(s, "*"):
			segs[i] = "x"
		}
	}
	return strings.Join(segs, "/")
}

// issueReadOnlyToken 替閘門測試的所屬帳號建立一把每個授權角色皆為唯讀的 token。
func (f *apiTokenRouteFixture) issueReadOnlyToken(t *testing.T) string {
	t.Helper()
	var owner model.User
	require.NoError(t, f.db.Where("username = ?", "token-owner").First(&owner).Error)
	var role model.Role
	require.NoError(t, f.db.Where("name = ?", "identity_admin").First(&role).Error)
	svc := identity.NewAPITokenService(f.db, apiTokenGateEvents{})
	op := identity.Operator{UserID: owner.ID, Username: owner.Username,
		Principal: authz.NewPrincipal(owner.ID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)}
	created, err := svc.Create(op, identity.CreateAPITokenInput{Name: "read-only",
		Roles: []identity.APITokenRoleGrant{{RoleID: role.ID, Level: model.APITokenLevelRead}}, NeverExpires: true})
	require.NoError(t, err)
	require.Equal(t, model.APITokenAccessRead, created.View.Access)
	return created.Token
}

// TestAPITokenReadOnlyRejectsEveryOpenWriteRoute 見檔頭。另以讀寫的 token 抽查一條開放的寫入路由，確認拒絕來自層級
// 而不是路由本身不開放。
func TestAPITokenReadOnlyRejectsEveryOpenWriteRoute(t *testing.T) {
	f := newAPITokenRouteFixture(t)
	r := f.router(false)
	readOnly := f.issueReadOnlyToken(t)

	targets := openWriteRoutesFromScopeList(t)
	fromList := len(targets)
	fromRegistry := 0
	for _, k := range middleware.APITokenRouteRegistryKeys() {
		method, path, _ := strings.Cut(k, " ")
		if v := middleware.LookupAPITokenRoute(method, path); v.Open && !v.CountsAllGrantedRoles() {
			targets[k] = true
			fromRegistry++
		}
	}
	// 下界：讀檔或登錄退化成空集合時，逐條迴圈會假綠
	require.GreaterOrEqual(t, fromList, 90, "對照檔的開放寫入路由數")
	require.GreaterOrEqual(t, fromRegistry, 90, "登錄的開放寫入路由數")

	keys := make([]string, 0, len(targets))
	for k := range targets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	readOnlyCode := string(apierror.CodeAuthAPITokenReadOnly)
	var failures []string
	for _, k := range keys {
		method, pattern, _ := strings.Cut(k, " ")
		w := apiTokenRouteCall(r, method, concreteRoutePath(pattern), readOnly)
		if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":"`+readOnlyCode+`"`) {
			failures = append(failures, k+" → "+w.Body.String())
		}
	}
	if len(failures) > 0 {
		t.Fatalf("全唯讀的 token 對 %d 條開放的寫入路由沒有回 403 %s：\n  %s", len(failures), readOnlyCode, strings.Join(failures, "\n  "))
	}
	t.Logf("全唯讀的 token 對 %d 條開放的寫入路由皆回 403 %s（登錄 %d 條、對照檔 %d 條）", len(keys), readOnlyCode, fromRegistry, fromList)

	// 讀寫的 token 呼叫同一類路由不被閘門以層級拒絕（拒絕若有，來自端點本身的權限檢查）
	w := apiTokenRouteCall(r, "POST", "/api/v1/users", f.token)
	require.NotContains(t, w.Body.String(), readOnlyCode, w.Body.String())
	require.NotContains(t, w.Body.String(), string(apierror.CodeAuthAPITokenForbiddenRoute), w.Body.String())
	// 全唯讀的 token 呼叫開放的讀取路由不被閘門拒絕
	w = apiTokenRouteCall(r, "GET", "/api/v1/assets", readOnly)
	require.NotContains(t, w.Body.String(), readOnlyCode, w.Body.String())
	require.NotContains(t, w.Body.String(), string(apierror.CodeAuthAPITokenForbiddenRoute), w.Body.String())
	// 全唯讀的 token 呼叫不開放的路由仍回既有的 403
	w = apiTokenRouteCall(r, "POST", "/api/v1/connect-tokens", readOnly)
	require.Equal(t, 403, w.Code)
	require.Contains(t, w.Body.String(), string(apierror.CodeAuthAPITokenForbiddenRoute))
}
