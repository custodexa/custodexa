package middleware

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestScopeGateWildcardMatchesBodyKeyGate 萬用欄位條件的生效判準與 authz.BodyKeyGate 一致：
// 只持 access_policy 權限點的主體被欄位閘放行，若且唯若萬用條件對該本文不生效。
func TestScopeGateWildcardMatchesBodyKeyGate(t *testing.T) {
	p := authz.NewPrincipal(1, authz.TokenFacts{}, []authz.Assignment{{RoleName: "ap-only", Via: authz.ViaDirect,
		Scope: model.ScopeKindGlobal, Permissions: []authz.Permission{authz.PermAccessPolicyManage}, Custom: true}})
	cases := []struct {
		name   string
		keys   []string
		parsed bool
	}{
		{"不可解析", nil, false},
		{"空物件", nil, true},
		{"只含 access_policy", []string{"access_policy"}, true},
		{"大小寫變體", []string{"Access_Policy"}, true},
		{"其他鍵", []string{"name"}, true},
		{"混合", []string{"access_policy", "name"}, true},
		{"憑證欄位", []string{"username"}, true},
	}
	for _, c := range cases {
		allowed, _ := authz.BodyKeyGate("PUT", "/api/v1/assets/:id", p, c.keys, c.parsed)
		if got := wildcardFieldInEffect(c.keys, c.parsed); got == allowed {
			t.Errorf("%s：萬用條件生效=%v，但欄位閘放行=%v（兩者須互斥）", c.name, got, allowed)
		}
	}
	if !fieldInEffect("username", []string{"UserName"}, true) || fieldInEffect("username", []string{"name"}, true) {
		t.Error("具名欄位須在本文出現（不分大小寫）時才生效")
	}
}
