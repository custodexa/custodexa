package model

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newRoleAuditDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // :memory: 連線池陷阱：多連線各自拿到空 DB
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec("CREATE TABLE user_roles (user_id integer, role_id integer, PRIMARY KEY (user_id, role_id))").Error; err != nil {
		t.Fatalf("user_roles: %v", err)
	}
	return db
}

func roleAuditRows(t *testing.T, db *gorm.DB) []AuditLog {
	t.Helper()
	var rows []AuditLog
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀審計列: %v", err)
	}
	return rows
}

// 帶請求脈絡的指派、移除、只改範圍三種列，操作者與請求識別六欄必須取自該次請求；
// 不帶脈絡時維持 system 且四欄空；details 形狀與脈絡無關。
func TestUserRoleAuditCarriesRequestContext(t *testing.T) {
	want := AuditRequest{
		UserID: 7, Username: "ops-lee", ClientIP: "10.1.2.3",
		Method: "PUT", Path: "/api/v1/users/9/roles", RequestID: "req-abc-123",
	}
	run := func(t *testing.T, ctx context.Context) []AuditLog {
		db := newRoleAuditDB(t)
		tx := db.WithContext(ctx).Begin()
		if tx.Error != nil {
			t.Fatalf("begin: %v", tx.Error)
		}
		defer tx.Rollback()
		if err := AssignUserRoleInRange(tx, 9, 3, "api", []uint{167}); err != nil {
			t.Fatalf("assign: %v", err)
		}
		if err := RecordUserRoleRangeChange(tx, 9, 3, "api", []uint{167}, []uint{158}); err != nil {
			t.Fatalf("range: %v", err)
		}
		if err := RevokeUserRole(tx, 9, 3, "api"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		return roleAuditRows(t, tx)
	}

	t.Run("with_context", func(t *testing.T) {
		rows := run(t, WithAuditRequest(context.Background(), want))
		if len(rows) != 3 {
			t.Fatalf("應有 3 列，得到 %d", len(rows))
		}
		for i, r := range rows {
			if r.UserID != want.UserID || r.Username != want.Username || r.ClientIP != want.ClientIP ||
				r.Method != want.Method || r.Path != want.Path || r.RequestID != want.RequestID {
				t.Errorf("第 %d 列脈絡不符: %+v", i, r)
			}
		}
	})

	t.Run("without_context", func(t *testing.T) {
		rows := run(t, context.Background())
		if len(rows) != 3 {
			t.Fatalf("應有 3 列，得到 %d", len(rows))
		}
		for i, r := range rows {
			if r.UserID != 0 || r.Username != "system" {
				t.Errorf("第 %d 列應為 system: %d/%s", i, r.UserID, r.Username)
			}
			if r.ClientIP != "" || r.Method != "" || r.Path != "" || r.RequestID != "" {
				t.Errorf("第 %d 列的請求四欄應為空: %+v", i, r)
			}
		}
	})

	t.Run("details_unchanged", func(t *testing.T) {
		with := run(t, WithAuditRequest(context.Background(), want))
		without := run(t, context.Background())
		for i := range with {
			if with[i].Details != without[i].Details {
				t.Errorf("第 %d 列 details 不應受脈絡影響:\n%s\n%s", i, with[i].Details, without[i].Details)
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(with[i].Details), &m); err != nil {
				t.Fatalf("details 非 JSON: %v", err)
			}
			for _, k := range []string{"username", "operator", "request_id"} {
				if _, ok := m[k]; ok {
					t.Errorf("details 不得含 %s", k)
				}
			}
		}
	})

	t.Run("zero_user_falls_back", func(t *testing.T) {
		rows := run(t, WithAuditRequest(context.Background(), AuditRequest{Path: "/x"}))
		if rows[0].Username != "system" || rows[0].Path != "" {
			t.Errorf("無可指認操作者時應視為無脈絡: %+v", rows[0])
		}
	})
}
