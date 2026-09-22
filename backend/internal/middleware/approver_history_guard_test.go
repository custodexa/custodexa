package middleware

import (
	"github.com/custodexa/backend/internal/model"
	"testing"
)

func TestApproverGuardHistoryAuditor(t *testing.T) {
	db := setupApproverGuardDB(t)
	role := model.Role{Name: model.RoleAuditor}
	if err := db.Create(&role).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO user_roles(user_id,role_id) VALUES (?,?)", 1, role.ID).Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint{1, 2, 3, 0} {
		want := 403
		if id == 1 || id == 2 {
			want = 200
		}
		if id == 0 {
			want = 401
		}
		code, keys := callWithGuard(db, id, RequireAccessRequestHistoryReader)
		if code != want {
			t.Fatal(id, code, want)
		}
		if id == 1 && keys["accessRequestHistoryAuditor"] != true {
			t.Fatal(keys)
		}
	}
	if code, _ := callGuard(db, 1); code != 403 {
		t.Fatal("auditor approval", code)
	}
	if code, _ := callRevokeGuard(db, 1); code != 403 {
		t.Fatal("auditor revoke", code)
	}
}
