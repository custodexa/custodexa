package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupApproverGuardDB 真 SQLite：守門即時查 DB roles 的語義（撤職即刻生效）
// 必須用實際查詢驗證
func setupApproverGuardDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.ApproverScope{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	roles := []model.Role{{Name: model.RoleAdmin}, {Name: model.RoleUser}, {Name: model.RoleApprover}}
	for i := range roles {
		if err := db.Create(&roles[i]).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}
	users := []model.User{{Username: "plain", Email: emailPtr("p@x")}, {Username: "appr", Email: emailPtr("a@x")}, {Username: "boss", Email: emailPtr("b@x")}}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	// plain=user、appr=user+approver、boss=admin
	assign := func(userID, roleID uint) {
		if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", userID, roleID).Error; err != nil {
			t.Fatalf("assign role: %v", err)
		}
	}
	assign(1, 2)
	assign(2, 2)
	assign(2, 3)
	assign(3, 1)
	return db
}

func callWithGuard(db *gorm.DB, userID uint, guard func(*gorm.DB) gin.HandlerFunc) (int, map[string]interface{}) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var keys map[string]interface{}
	r.GET("/guarded", func(c *gin.Context) {
		if userID != 0 {
			c.Set("userID", userID)
		}
		guard(db)(c)
		if !c.IsAborted() {
			keys = c.Keys
			c.JSON(http.StatusOK, gin.H{"ok": true})
		}
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/guarded", nil))
	return w.Code, keys
}

func callGuard(db *gorm.DB, userID uint) (int, map[string]interface{}) {
	return callWithGuard(db, userID, RequireApproverRole)
}

func callRevokeGuard(db *gorm.DB, userID uint) (int, map[string]interface{}) {
	return callWithGuard(db, userID, RequireRevokeEligibility)
}

// TestRequireApproverRole 守門即時查 DB roles（access-policy-approval D5）：
// approver 放行、一般 user 403、撤 approver 即刻生效（無 token 殘窗）。
//
// **W7b（D-12）行為變更**：僅具 `admin` 角色者**不再放行**（原「admin 兜底放行」
// 子測試改為斷言 403），且守衛不再寫入 admin 兜底旗標（`ApproverAdminKey` 已刪除）
func TestRequireApproverRole(t *testing.T) {
	db := setupApproverGuardDB(t)

	t.Run("一般 user 403", func(t *testing.T) {
		code, _ := callGuard(db, 1)
		if code != http.StatusForbidden {
			t.Fatalf("plain user 應 403, got %d", code)
		}
	})

	t.Run("approver 放行", func(t *testing.T) {
		code, keys := callGuard(db, 2)
		if code != http.StatusOK {
			t.Fatalf("approver 應放行, got %d", code)
		}
		if _, ok := keys[RevokeAdminKey]; ok {
			t.Fatal("審核端點守衛不應寫入任何 admin 旗標（D-12 收斂）")
		}
	})

	// D-12 行為變更（W7b 8.1，BREAKING）：僅具 admin 角色者不再是有效審核者
	t.Run("僅具 admin 者 403（D-12 收斂）", func(t *testing.T) {
		code, _ := callGuard(db, 3)
		if code != http.StatusForbidden {
			t.Fatalf("僅具 admin 者應 403（D-12：admin 不構成審核資格）, got %d", code)
		}
	})

	t.Run("撤 approver 即刻生效", func(t *testing.T) {
		if err := db.Exec("DELETE FROM user_roles WHERE user_id = 2 AND role_id = 3").Error; err != nil {
			t.Fatalf("revoke: %v", err)
		}
		code, _ := callGuard(db, 2)
		if code != http.StatusForbidden {
			t.Fatalf("撤職後應即刻 403, got %d", code)
		}
	})

	t.Run("未認證 401", func(t *testing.T) {
		code, _ := callGuard(db, 0)
		if code != http.StatusUnauthorized {
			t.Fatalf("未認證應 401, got %d", code)
		}
	})

	t.Run("審核方群組成員即資格（D-7 群組即資格）", func(t *testing.T) {
		// plain(user 1) 無 approver 角色；入 DBA 群組且群組為審核方 → 放行
		if err := db.Create(&model.UserGroup{Name: "DBA"}).Error; err != nil {
			t.Fatalf("seed group: %v", err)
		}
		if err := db.Exec("INSERT INTO user_group_members (user_group_id, user_id) VALUES (1, 1)").Error; err != nil {
			t.Fatalf("seed member: %v", err)
		}
		gid, aid := uint(1), uint(99)
		if err := db.Create(&model.ApproverScope{ApproverGroupID: &gid, AssetID: &aid, GrantedBy: 3}).Error; err != nil {
			t.Fatalf("seed group scope: %v", err)
		}
		code, keys := callGuard(db, 1)
		if code != http.StatusOK {
			t.Fatalf("審核方群組成員應放行, got %d", code)
		}
		if _, ok := keys[RevokeAdminKey]; ok {
			t.Fatal("審核端點守衛不應寫入任何 admin 旗標（D-12 收斂）")
		}
		// 離組即失效
		if err := db.Exec("DELETE FROM user_group_members WHERE user_group_id = 1 AND user_id = 1").Error; err != nil {
			t.Fatalf("remove member: %v", err)
		}
		code, _ = callGuard(db, 1)
		if code != http.StatusForbidden {
			t.Fatalf("離組後應即刻 403, got %d", code)
		}
	})
}

// TestRequireRevokeEligibility 撤銷端點守門（W7b 8.2 端點分離）：判準＝
// 收斂前的 RequireApproverRole（admin OR 有效審核者），故 admin 無 approver 角色
// 時**仍可通過**——若一併收斂會造成 admin 無法撤銷已核票證的安全倒退
func TestRequireRevokeEligibility(t *testing.T) {
	db := setupApproverGuardDB(t)

	t.Run("僅具 admin 者放行且帶 admin 旗標", func(t *testing.T) {
		code, keys := callRevokeGuard(db, 3)
		if code != http.StatusOK {
			t.Fatalf("admin 應可撤銷, got %d", code)
		}
		if isAdmin, _ := keys[RevokeAdminKey].(bool); !isAdmin {
			t.Fatal("admin 應標記 RevokeAdminKey=true（service 據此走 admin 資格分支）")
		}
	})

	t.Run("有效審核者放行且非 admin", func(t *testing.T) {
		code, keys := callRevokeGuard(db, 2)
		if code != http.StatusOK {
			t.Fatalf("approver 應放行, got %d", code)
		}
		if isAdmin, _ := keys[RevokeAdminKey].(bool); isAdmin {
			t.Fatal("非 admin 不應標記 RevokeAdminKey=true")
		}
	})

	t.Run("一般 user 403", func(t *testing.T) {
		code, _ := callRevokeGuard(db, 1)
		if code != http.StatusForbidden {
			t.Fatalf("plain user 應 403, got %d", code)
		}
	})

	t.Run("未認證 401", func(t *testing.T) {
		code, _ := callRevokeGuard(db, 0)
		if code != http.StatusUnauthorized {
			t.Fatalf("未認證應 401, got %d", code)
		}
	})
}
