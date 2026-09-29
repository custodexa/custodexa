package asset

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
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

// TestPlanCreateDisabledPersists 建立時傳 enabled:false 必須落庫為 false：
// model 的 default:true 會讓 gorm 把零值欄位排除在 INSERT 外，交給 DB 預設值。
func TestPlanCreateDisabledPersists(t *testing.T) {
	svc := setupPlanDB(t)
	plan, err := svc.Create(&ChangeSecretPlanRequest{
		Name: "paused", AssetIDs: []uint{1}, Enabled: boolPtr(false),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if plan.Enabled {
		t.Fatal("returned plan should be disabled")
	}
	reloaded, err := svc.Get(plan.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reloaded.Enabled {
		t.Fatal("persisted plan should be disabled, got enabled")
	}

	// 同一欄位型態的另外兩欄：密碼生成策略的兩個布林同樣帶資料庫預設值 true，
	// 建成「不含符號」若靜默變成含符號，排程產生的就是另一種密碼
	for _, tc := range []struct {
		name string
		val  *bool
		want bool
	}{
		{"帶_false_存成關閉", boolPtr(false), false},
		{"未帶預設開啟", nil, true},
		{"帶_true_存成開啟", boolPtr(true), true},
	} {
		t.Run("密碼策略旗標/"+tc.name, func(t *testing.T) {
			svc := setupPlanDB(t)
			plan, err := svc.Create(&ChangeSecretPlanRequest{
				Name: "policy", AssetIDs: []uint{1},
				PasswordIncludeSymbol: tc.val, PasswordExcludeAmbiguous: tc.val,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if plan.PasswordIncludeSymbol != tc.want || plan.PasswordExcludeAmbiguous != tc.want {
				t.Errorf("回傳 include_symbol=%v exclude_ambiguous=%v，want 皆為 %v",
					plan.PasswordIncludeSymbol, plan.PasswordExcludeAmbiguous, tc.want)
			}
			reloaded, err := svc.Get(plan.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if reloaded.PasswordIncludeSymbol != tc.want || reloaded.PasswordExcludeAmbiguous != tc.want {
				t.Errorf("落庫 include_symbol=%v exclude_ambiguous=%v，want 皆為 %v",
					reloaded.PasswordIncludeSymbol, reloaded.PasswordExcludeAmbiguous, tc.want)
			}
			if !reloaded.Enabled {
				t.Error("未帶 enabled 應維持預設啟用")
			}
		})
	}
}
