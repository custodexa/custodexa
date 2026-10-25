package policy_test

import (
	"slices"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
)

// TestMappingRevalidationPolicyKeyOwner 重新驗證時限鍵歸系統安全管理員範本所含的設定組。
//
// 政策鍵沒有逐鍵的權限欄：所有政策鍵經同一組安全政策路由讀寫，路由要求的權限點
// 就是鍵的歸屬。故本測試沿這條鏈斷言：鍵已定義、寫入路由要求安全政策管理權、
// 該權限在系統安全管理員範本內，而不在身分管理員範本內。
//
// 放在外部測試包：authz 匯入 policy，policy 的內部測試無法反向匯入 authz。
func TestMappingRevalidationPolicyKeyOwner(t *testing.T) {
	if policy.FindPolicyDef(policy.PolicyMappingRevalidationHours) == nil {
		t.Fatalf("政策鍵 %s 未定義", policy.PolicyMappingRevalidationHours)
	}
	for _, method := range []string{"GET", "PUT"} {
		entry, ok := authz.LookupRoute(method, "/api/v1/security-policies")
		if !ok {
			t.Fatalf("%s /api/v1/security-policies 未登記於授權登錄", method)
		}
		if entry.Perm != authz.PermSecurityPolicyManage {
			t.Errorf("%s /api/v1/security-policies 要求 %q，want %q", method, entry.Perm, authz.PermSecurityPolicyManage)
		}
	}
	if !slices.Contains(authz.TemplatePermissions(model.BuiltinSecurityAdmin), authz.PermSecurityPolicyManage) {
		t.Errorf("系統安全管理員範本不含 %q", authz.PermSecurityPolicyManage)
	}
	if slices.Contains(authz.TemplatePermissions(model.BuiltinIdentityAdmin), authz.PermSecurityPolicyManage) {
		t.Errorf("身分管理員範本不應含 %q", authz.PermSecurityPolicyManage)
	}
}
