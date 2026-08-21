package audit

import (
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestAuditLogDeleteGuard audit-log-compliance 10.3.2：audit_logs 經 ORM 的
// 刪除（含軟刪與 Unscoped 硬刪）都必須被 BeforeDelete 拒絕；
// 保留清除走 repository 原生 SQL 路徑不受影響
func TestAuditLogDeleteGuard(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	row := model.AuditLog{
		Action: model.ActionCreate, Resource: model.ResourceAsset,
		Status: model.StatusSuccess, UserID: 1, Username: "admin",
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := db.Delete(&model.AuditLog{}, row.ID).Error; !errors.Is(err, gorm.ErrInvalidValue) {
		t.Errorf("軟刪應被 BeforeDelete 拒絕, got %v", err)
	}
	if err := db.Unscoped().Delete(&model.AuditLog{}, row.ID).Error; !errors.Is(err, gorm.ErrInvalidValue) {
		t.Errorf("Unscoped 硬刪應被 BeforeDelete 拒絕, got %v", err)
	}

	var count int64
	db.Model(&model.AuditLog{}).Count(&count)
	if count != 1 {
		t.Errorf("守衛後列數 = %d, want 1（未被刪除）", count)
	}

	// 原生 SQL 路徑（retention purge 專用）不經 hook，可刪
	if err := db.Exec("DELETE FROM audit_logs WHERE id = ?", row.ID).Error; err != nil {
		t.Errorf("原生 SQL 刪除（retention 專用路徑）應可執行: %v", err)
	}
	db.Model(&model.AuditLog{}).Count(&count)
	if count != 0 {
		t.Errorf("原生 SQL 刪除後列數 = %d, want 0", count)
	}
}
