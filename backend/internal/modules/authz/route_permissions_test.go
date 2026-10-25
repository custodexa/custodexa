package authz

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 欄位條件的並列相容能力：持有權限點或任一並列能力即通過；持有並列能力時一律回報經相容能力，
// 未宣告並列能力的欄位只看權限點，未宣告的欄位一律不通過。
func TestFieldCapabilityAnyOf(t *testing.T) {
	with := func(perms ...Permission) *Principal {
		return NewPrincipal(7, TokenFacts{}, []Assignment{{
			RoleName: "field-anyof", Via: ViaDirect, Scope: model.ScopeKindGlobal, Permissions: perms, Custom: true,
		}})
	}
	const list, field = "/api/v1/assets/:id/accounts", "credential_identity_fields"
	cases := []struct {
		name              string
		method, path, fld string
		p                 *Principal
		want              FieldGrant
	}{
		{"只持權限點：通過且經權限點", "GET", list, field, with(PermAssetView, PermCredentialView), FieldGrantPerm},
		{"只持並列能力：通過且經相容能力", "GET", list, field, with(PermAssetView, PermCredentialManage), FieldGrantCompat},
		{"兩者皆持：經相容能力", "GET", list, field, with(PermCredentialView, PermCredentialManage), FieldGrantCompat},
		{"皆無：不通過", "GET", list, field, with(PermAssetView, PermCredentialCreate), FieldGrantNone},
		{"未宣告的欄位：不通過", "GET", list, "no_such_field", with(PermCredentialView, PermCredentialManage), FieldGrantNone},
		{"未宣告並列能力的欄位：持相容能力不算經相容能力", "POST", "/api/v1/assets", "credential_id",
			with(PermCredentialBind, PermCredentialManage), FieldGrantPerm},
		{"未宣告並列能力的欄位：只持相容能力不通過", "POST", "/api/v1/assets", "credential_id",
			with(PermCredentialManage), FieldGrantNone},
	}
	for _, c := range cases {
		got := FieldCapabilityGrantOf(c.method, c.path, c.fld, c.p)
		if got != c.want {
			t.Errorf("%s：回報 %v，應為 %v", c.name, got, c.want)
		}
		if ok := FieldCapability(c.method, c.path, c.fld, c.p); ok != (c.want != FieldGrantNone) {
			t.Errorf("%s：FieldCapability=%v 與回報途徑不一致", c.name, ok)
		}
	}
	if FieldCapabilityGrantOf("GET", list, field, nil) != FieldGrantNone {
		t.Error("無主體應不通過")
	}
}
