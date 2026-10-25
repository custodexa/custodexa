package api

import (
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// asSuperAdmin 建一名超級管理者並回傳把他設為目前操作者的中介層。
// 指派入口經共用關卡裁決，需要可指認的操作者；沒有認證中介層的測試路由用它補上。
func asSuperAdmin(t *testing.T, db *gorm.DB) gin.HandlerFunc {
	t.Helper()
	var role model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&role).Error; err != nil {
		role = model.Role{Name: model.RoleAdmin}
		if err := db.Create(&role).Error; err != nil {
			t.Fatalf("seed admin role: %v", err)
		}
	}
	op := model.User{Username: "operator-super", Password: "x", Active: true}
	if err := db.Create(&op).Error; err != nil {
		t.Fatalf("seed operator: %v", err)
	}
	if err := db.Create(&model.UserRole{UserID: op.ID, RoleID: role.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
		t.Fatalf("seed operator role: %v", err)
	}
	return func(c *gin.Context) {
		c.Set("userID", op.ID)
		c.Set("username", op.Username)
		c.Next()
	}
}
