package database

import (
	"testing"

	"gorm.io/gorm"
)

// 給外部測試套件（database_test）用的入口：建立乾淨 schema，並套用通知投遞層之前或它本身的遷移。

// FreshSchemaForTest 建立乾淨的 pg schema 並回傳綁定該 schema 的連線（測試結束時刪除）。
func FreshSchemaForTest(t *testing.T, dsn, name string) *gorm.DB { return freshSchema(t, dsn, name) }

// ApplyMigrationsAroundNotificationDeliveryLayer before 為真時套用通知投遞層之前的全部遷移，否則套用它本身與之後的全部遷移
// （升級到目前版本）。
func ApplyMigrationsAroundNotificationDeliveryLayer(t *testing.T, db *gorm.DB, before bool) {
	t.Helper()
	reached := false
	for _, m := range migrations {
		if m.Version == notificationDeliveryLayerVersion {
			reached = true
			if before {
				return
			}
		}
		if before != reached {
			if err := m.Up(db); err != nil {
				t.Fatal(m.Version, err)
			}
		}
	}
	if !reached {
		t.Fatal("找不到通知投遞層的遷移")
	}
}
