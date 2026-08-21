package asset

import (
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupPlanDB(t *testing.T) *ChangeSecretPlanService {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.ChangeSecretPlan{}, &model.ChangeSecretRecord{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewChangeSecretPlanService(db)
}

func boolPtr(b bool) *bool { return &b }

func TestPlanCRUD(t *testing.T) {
	svc := setupPlanDB(t)

	plan, err := svc.Create(&ChangeSecretPlanRequest{
		Name: "weekly", AssetIDs: []uint{1, 3}, Cron: "0 3 * * 0",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !plan.Enabled {
		t.Error("default enabled should be true")
	}
	if got := AssetIDList(plan); len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Errorf("AssetIDList = %v", got)
	}

	plans, _ := svc.List()
	if len(plans) != 1 {
		t.Fatalf("List = %d", len(plans))
	}

	updated, err := svc.Update(plan.ID, &ChangeSecretPlanRequest{
		Name: "weekly", AssetIDs: []uint{1}, Enabled: boolPtr(false),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Enabled || updated.Cron != "" {
		t.Errorf("updated = %+v", updated)
	}

	if err := svc.Delete(plan.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := svc.Delete(plan.ID); !errors.Is(err, ErrPlanNotFound) {
		t.Errorf("second delete = %v", err)
	}
}

func TestPlanValidation(t *testing.T) {
	svc := setupPlanDB(t)

	if _, err := svc.Create(&ChangeSecretPlanRequest{Name: "x", AssetIDs: nil}); !errors.Is(err, ErrPlanNoAssets) {
		t.Errorf("empty assets = %v", err)
	}
	if _, err := svc.Create(&ChangeSecretPlanRequest{Name: "x", AssetIDs: []uint{1}, Cron: "not-cron"}); !errors.Is(err, ErrPlanBadCron) {
		t.Errorf("bad cron = %v", err)
	}

	if _, err := svc.Create(&ChangeSecretPlanRequest{Name: "dup", AssetIDs: []uint{1}}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := svc.Create(&ChangeSecretPlanRequest{Name: "dup", AssetIDs: []uint{2}}); !errors.Is(err, ErrPlanNameExists) {
		t.Errorf("dup name = %v", err)
	}
}

func TestPlanRecords(t *testing.T) {
	svc := setupPlanDB(t)
	plan, _ := svc.Create(&ChangeSecretPlanRequest{Name: "r", AssetIDs: []uint{1}})

	svc.db.Create(&model.ChangeSecretRecord{PlanID: plan.ID, AssetID: 1, Status: model.ChangeSecretSuccess})
	svc.db.Create(&model.ChangeSecretRecord{PlanID: plan.ID, AssetID: 3, Status: model.ChangeSecretFailed, Error: "unreachable"})

	records, err := svc.Records(plan.ID, 0)
	if err != nil || len(records) != 2 {
		t.Fatalf("Records = %d, %v", len(records), err)
	}
	// 新到舊
	if records[0].AssetID != 3 {
		t.Errorf("order: first = %+v", records[0])
	}
}
