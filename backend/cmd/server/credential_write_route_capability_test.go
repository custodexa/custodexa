package main

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 憑證寫入路由的進入閘：持有任一憑證語義管理能力即可進入（服務層逐項判定），
// 只有檢視能力或毫無憑證能力者在路由層被擋；輪替的補跑與放棄只認輪替能力。
func TestCredentialWriteRoutesAcceptAnySemanticCapability(t *testing.T) {
	writes := []string{
		"POST /api/v1/credentials",
		"PUT /api/v1/credentials/:id",
		"DELETE /api/v1/credentials/:id",
		"POST /api/v1/credentials/:id/bindings",
		"DELETE /api/v1/credentials/:id/bindings/:accountId",
		"POST /api/v1/credentials/:id/bindings/:accountId/detach",
		"POST /api/v1/credentials/:id/rotations",
		"POST /api/v1/credentials/:id/scope",
		"POST /api/v1/credentials/:id/secret",
		"PUT /api/v1/assets/:id/accounts/:accountId/credential",
	}
	rotationOnly := []string{
		"POST /api/v1/credentials/:id/rotations/:rid/abandon",
		"POST /api/v1/credentials/:id/rotations/:rid/members/:mid/retry",
	}
	decide := func(key string, p *authz.Principal) bool {
		t.Helper()
		method, path, _ := strings.Cut(key, " ")
		if _, ok := authz.LookupRoute(method, path); !ok {
			t.Fatalf("%s 未登錄", key)
		}
		return authz.DecideRoute(method, path, p).Allowed
	}
	semantic := []authz.Permission{
		authz.PermCredentialCreate, authz.PermCredentialUpdate, authz.PermCredentialSetSecret,
		authz.PermCredentialRotate, authz.PermCredentialConvertScope, authz.PermCredentialDetach,
		authz.PermCredentialDelete, authz.PermCredentialBind,
	}
	for _, perm := range semantic {
		p := customRolePrincipal("cred-"+string(perm), authz.PermAssetView, perm)
		for _, key := range writes {
			if !decide(key, p) {
				t.Errorf("只持 %s 的自訂角色應能進入 %s", perm, key)
			}
		}
		for _, key := range rotationOnly {
			if got, want := decide(key, p), perm == authz.PermCredentialRotate; got != want {
				t.Errorf("只持 %s 進入 %s = %v，want %v", perm, key, got, want)
			}
		}
	}
	for name, p := range map[string]*authz.Principal{
		"只持憑證檢視": customRolePrincipal("cred-view", authz.PermAssetView, authz.PermCredentialView),
		"只持帳號改密": customRolePrincipal("acct-rotate", authz.PermAssetView, authz.PermAccountRotate),
		"只持資產管理": assetManagerCustomPrincipal(t),
		"一般使用者":  principalWith(model.BuiltinUser, model.RoleUser),
	} {
		for _, key := range append(append([]string{}, writes...), rotationOnly...) {
			if decide(key, p) {
				t.Errorf("%s 不應進入 %s", name, key)
			}
		}
	}
	admin := principalWith(model.BuiltinSuperAdmin, model.RoleAdmin)
	for _, key := range append(append([]string{}, writes...), rotationOnly...) {
		if !decide(key, admin) {
			t.Errorf("超管應能進入 %s", key)
		}
	}
}

// 批次改歸只認 credential:update（歸屬變更的能力）；其餘憑證語義能力與檢視、一般使用者皆不得進入。
func TestCredentialOwnershipRouteAdmitsUpdateCapabilityOnly(t *testing.T) {
	const method, path = "POST", "/api/v1/credentials/ownership"
	if _, ok := authz.LookupRoute(method, path); !ok {
		t.Fatalf("%s %s 未登錄", method, path)
	}
	for _, perm := range []authz.Permission{
		authz.PermCredentialCreate, authz.PermCredentialSetSecret, authz.PermCredentialRotate,
		authz.PermCredentialConvertScope, authz.PermCredentialDetach, authz.PermCredentialDelete,
		authz.PermCredentialBind, authz.PermCredentialView,
	} {
		p := customRolePrincipal("own-"+string(perm), authz.PermAssetView, perm)
		if authz.DecideRoute(method, path, p).Allowed {
			t.Errorf("只持 %s 不應進入批次改歸", perm)
		}
	}
	p := customRolePrincipal("own-update", authz.PermAssetView, authz.PermCredentialUpdate)
	if !authz.DecideRoute(method, path, p).Allowed {
		t.Errorf("持 credential:update 應能進入批次改歸")
	}
}

// 影響確認端點只認宣告新秘密或遠端輪替能力：其餘憑證語義能力與檢視、一般使用者皆不得進入。
func TestCredentialImpactConfirmationRouteAdmitsSecretCapabilitiesOnly(t *testing.T) {
	const method, path = "POST", "/api/v1/credentials/:id/impact-confirmations"
	if _, ok := authz.LookupRoute(method, path); !ok {
		t.Fatalf("%s %s 未登錄", method, path)
	}
	for _, perm := range []authz.Permission{
		authz.PermCredentialCreate, authz.PermCredentialUpdate, authz.PermCredentialConvertScope,
		authz.PermCredentialDetach, authz.PermCredentialDelete, authz.PermCredentialBind, authz.PermCredentialView,
	} {
		p := customRolePrincipal("imp-"+string(perm), authz.PermAssetView, perm)
		if authz.DecideRoute(method, path, p).Allowed {
			t.Errorf("只持 %s 不應進入影響確認", perm)
		}
	}
	for _, perm := range []authz.Permission{authz.PermCredentialSetSecret, authz.PermCredentialRotate} {
		p := customRolePrincipal("imp-"+string(perm), authz.PermAssetView, perm)
		if !authz.DecideRoute(method, path, p).Allowed {
			t.Errorf("持 %s 應能進入影響確認", perm)
		}
	}
	if authz.DecideRoute(method, path, principalWith(model.BuiltinUser, model.RoleUser)).Allowed {
		t.Errorf("一般使用者不應進入影響確認")
	}
}
