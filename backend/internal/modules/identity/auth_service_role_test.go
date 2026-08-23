package identity

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/bcrypt"
)

// TestPrimaryRoleOf_Priority 有效角色優先序固定 admin > auditor > user：
// 不得受 Roles 綁定順序影響——[user,auditor] 取到 user 會造成後端 403 前端放行的破版
func TestPrimaryRoleOf_Priority(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
		want  string
	}{
		{"user 先綁仍判 auditor", []string{"user", "auditor"}, "auditor"},
		{"auditor 先綁判 auditor", []string{"auditor", "user"}, "auditor"},
		{"admin 蓋過 auditor", []string{"auditor", "admin"}, "admin"},
		{"admin 蓋過全部", []string{"user", "auditor", "admin"}, "admin"},
		{"單一 user", []string{"user"}, "user"},
		{"無角色預設 user", []string{}, "user"},
		{"未知角色沿舊行為取第一個", []string{"ops"}, "ops"},
		{"未知角色混已知取已知", []string{"ops", "auditor"}, "auditor"},
		// approver 為可疊加職能角色：不參與三階排序、
		// 不改變有效角色判定——釘死防止未來把 approver 塞進 priority 表
		{"approver 疊加不改 user 判定", []string{"user", "approver"}, "user"},
		{"approver 疊加不改 admin 判定", []string{"approver", "admin"}, "admin"},
		{"approver 疊加不改 auditor 判定", []string{"approver", "auditor"}, "auditor"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			user := &model.User{}
			for _, name := range c.roles {
				user.Roles = append(user.Roles, model.Role{Name: name})
			}
			if got := primaryRoleOf(user); got != c.want {
				t.Errorf("primaryRoleOf(%v) = %q, want %q", c.roles, got, c.want)
			}
		})
	}
}

// TestMultiRoleEffectiveRoleSurvivesRefresh [user,auditor] 帳號登入與 refresh 換發的
// access token 有效角色皆為 auditor（登入與刷新兩條核發路徑共用 primaryRoleOf）
func TestMultiRoleEffectiveRoleSurvivesRefresh(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)

	// 先建 user 角色（較小 ID）再建 auditor，確保 Roles preload 順序為 [user, auditor]——
	// 正是舊「取 Roles[0]」邏輯會誤判為 user 的排列
	roleUser := model.Role{Name: "user"}
	roleAuditor := model.Role{Name: "auditor"}
	if err := db.Create(&roleUser).Error; err != nil {
		t.Fatalf("create role user: %v", err)
	}
	if err := db.Create(&roleAuditor).Error; err != nil {
		t.Fatalf("create role auditor: %v", err)
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte("multi-pass-1"), bcrypt.MinCost)
	user := &model.User{Username: "multi", Email: strPtr("m@x"), Password: string(hash), Active: true}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	for _, roleID := range []uint{roleUser.ID, roleAuditor.ID} {
		if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", user.ID, roleID).Error; err != nil {
			t.Fatalf("bind role %d: %v", roleID, err)
		}
	}

	resp, err := auth.Login(&LoginRequest{Username: "multi", Password: "multi-pass-1"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	claims, err := auth.ValidateToken(resp.Token)
	if err != nil {
		t.Fatalf("validate login token: %v", err)
	}
	if claims.Role != "auditor" {
		t.Errorf("登入 token 有效角色 = %q, want auditor", claims.Role)
	}

	rotated, err := auth.RefreshSession(resp.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	claims, err = auth.ValidateToken(rotated.Token)
	if err != nil {
		t.Fatalf("validate refreshed token: %v", err)
	}
	if claims.Role != "auditor" {
		t.Errorf("refresh 後 token 有效角色 = %q, want auditor", claims.Role)
	}
}
