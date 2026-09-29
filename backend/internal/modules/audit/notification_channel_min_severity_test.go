package audit

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupMinSeverityChannelDB(t *testing.T) (*NotificationChannelService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// One connection: every connection of a ":memory:" pool is a separate empty DB.
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.NotificationChannel{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewNotificationChannelService(db, nil), db
}

func mustMinSeverity(t *testing.T, svc *NotificationChannelService, id uint) string {
	t.Helper()
	ch, err := svc.GetByID(id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	return ch.MinSeverity
}

// TestChannelMinSeverityPersistence: create defaults to "all alerts", an update that
// omits the field (the list's enable toggle sends only name/type/enabled) keeps the
// stored threshold, and empty or out-of-domain values are rejected without writing.
func TestChannelMinSeverityPersistence(t *testing.T) {
	svc, _ := setupMinSeverityChannelDB(t)

	created, err := svc.Create(&NotificationChannelRequest{Name: "siem", URL: "https://hooks.example.com/a"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := mustMinSeverity(t, svc, created.ID); got != model.AlertSeverityLow {
		t.Fatalf("default min_severity = %q, want low", got)
	}

	p1, err := svc.Create(&NotificationChannelRequest{Name: "p1", URL: "https://hooks.example.com/b",
		MinSeverity: strPtr(model.AlertSeverityHigh)})
	if err != nil {
		t.Fatalf("Create high: %v", err)
	}
	if got := mustMinSeverity(t, svc, p1.ID); got != model.AlertSeverityHigh {
		t.Fatalf("created min_severity = %q, want high", got)
	}

	disabled := false
	if _, err := svc.Update(p1.ID, &NotificationChannelRequest{Name: "p1", Type: "webhook", Enabled: &disabled}); err != nil {
		t.Fatalf("toggle Update: %v", err)
	}
	if got := mustMinSeverity(t, svc, p1.ID); got != model.AlertSeverityHigh {
		t.Fatalf("enable toggle reset min_severity to %q, want high", got)
	}

	if _, err := svc.Update(p1.ID, &NotificationChannelRequest{Name: "p1", MinSeverity: strPtr(model.AlertSeverityMedium)}); err != nil {
		t.Fatalf("Update medium: %v", err)
	}
	if got := mustMinSeverity(t, svc, p1.ID); got != model.AlertSeverityMedium {
		t.Fatalf("updated min_severity = %q, want medium", got)
	}

	for _, bad := range []string{"", "critical", "HIGH"} {
		if _, err := svc.Update(p1.ID, &NotificationChannelRequest{Name: "p1", MinSeverity: strPtr(bad)}); !errors.Is(err, ErrInvalidChannelMinSeverity) {
			t.Errorf("Update min_severity=%q err = %v, want ErrInvalidChannelMinSeverity", bad, err)
		}
		if _, err := svc.Create(&NotificationChannelRequest{Name: "x", URL: "https://hooks.example.com/c", MinSeverity: strPtr(bad)}); !errors.Is(err, ErrInvalidChannelMinSeverity) {
			t.Errorf("Create min_severity=%q err = %v, want ErrInvalidChannelMinSeverity", bad, err)
		}
	}
	if got := mustMinSeverity(t, svc, p1.ID); got != model.AlertSeverityMedium {
		t.Fatalf("rejected update changed min_severity to %q", got)
	}
}

// TestChannelMinSeverityChangeAudited: narrowing a channel's threshold must leave a
// record that answers "changed from which level to which"; an update that leaves the
// threshold unchanged adds no such record.
func TestChannelMinSeverityChangeAudited(t *testing.T) {
	svc, db := setupMinSeverityChannelDB(t)
	created, err := svc.Create(&NotificationChannelRequest{Name: "p1-oncall", URL: "https://hooks.example.com/a"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	countRows := func() int64 {
		var n int64
		db.Model(&model.AuditLog{}).Where("resource = ?", model.ResourceNotifyChannel).Count(&n)
		return n
	}

	req := &NotificationChannelRequest{Name: "p1-oncall", MinSeverity: strPtr(model.AlertSeverityHigh),
		ActorID: 7, ActorName: "admin", ActorIP: "10.0.0.8"}
	if _, err := svc.Update(created.ID, req); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := countRows(); got != 1 {
		t.Fatalf("audit rows after low->high = %d, want 1", got)
	}
	var row model.AuditLog
	if err := db.Where("resource = ?", model.ResourceNotifyChannel).First(&row).Error; err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if row.Action != model.ActionUpdate || row.Status != model.StatusSuccess ||
		row.UserID != 7 || row.Username != "admin" || row.ClientIP != "10.0.0.8" {
		t.Errorf("audit row actor/action = %+v", row)
	}
	if row.ResourceID == nil || *row.ResourceID != created.ID {
		t.Errorf("audit resource_id = %v, want %d", row.ResourceID, created.ID)
	}
	var details struct {
		Name    string `json:"name"`
		Changes []struct {
			Field string `json:"field"`
			Old   string `json:"old"`
			New   string `json:"new"`
		} `json:"changes"`
	}
	if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
		t.Fatalf("details not JSON: %q (%v)", row.Details, err)
	}
	if details.Name != "p1-oncall" || len(details.Changes) != 1 ||
		details.Changes[0].Field != "min_severity" ||
		details.Changes[0].Old != model.AlertSeverityLow || details.Changes[0].New != model.AlertSeverityHigh {
		t.Errorf("details = %+v, want name p1-oncall and min_severity low->high", details)
	}

	// Same value again, and an update that omits the field: no additional row.
	if _, err := svc.Update(created.ID, req); err != nil {
		t.Fatalf("Update same: %v", err)
	}
	if _, err := svc.Update(created.ID, &NotificationChannelRequest{Name: "p1-renamed"}); err != nil {
		t.Fatalf("Update rename: %v", err)
	}
	if got := countRows(); got != 1 {
		t.Fatalf("audit rows after unchanged updates = %d, want 1", got)
	}
}
