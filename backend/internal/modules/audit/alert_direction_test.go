package audit

import (
	"errors"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sensitivescan"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAlertMatcherDirectionSplit(t *testing.T) {
	m := NewAlertMatcher(nil, nil)
	m.setRules([]model.AlertRule{
		{ID: 1, Pattern: "secret", Direction: model.DirectionInput, Enabled: true, Action: "block"},
		{ID: 2, Pattern: "secret", Direction: model.DirectionOutput, Enabled: true, Action: "alert"},
	})
	if hits := m.Match("secret", "ssh"); len(hits) != 1 || hits[0].ID != 1 {
		t.Fatalf("input: %+v", hits)
	}
	if r, ok := m.MatchBlock("secret", "ssh"); !ok || r.ID != 1 {
		t.Fatal("input block split")
	}
	rules, err := sensitivescan.Compile(m.OutputRules("ssh", gatewayapi.PrincipalKindUnknown), "ssh")
	if err != nil {
		t.Fatal(err)
	}
	if hits := rules.Scan("secret"); len(hits) != 1 || hits[0].RuleID != 2 {
		t.Fatalf("output: %+v", hits)
	}
}

func TestAlertRuleServiceDirection(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	if err := db.AutoMigrate(&model.AlertRule{}); err != nil {
		t.Fatal(err)
	}
	svc := NewAlertRuleService(db)
	for _, direction := range []string{"sideways", "output"} {
		t.Run(direction, func(t *testing.T) {
			action := "alert"
			want := ErrInvalidDirection
			if direction == "output" {
				action = "block"
				want = ErrOutputBlock
			}
			req := &AlertRuleRequest{Name: "bad", Pattern: "x", Severity: "high", Direction: &direction, Action: action}
			if _, err := svc.Create(req); !errors.Is(err, want) {
				t.Fatalf("create: %v", err)
			}
			var n int64
			db.Model(&model.AlertRule{}).Count(&n)
			if n != 0 {
				t.Fatal("rejected create wrote a row")
			}
			good, err := svc.Create(&AlertRuleRequest{Name: "good", Pattern: "x", Severity: "high"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.Update(good.ID, req); !errors.Is(err, want) {
				t.Fatalf("update: %v", err)
			}
			var saved model.AlertRule
			db.First(&saved, good.ID)
			if saved.Name != "good" || saved.Direction != "input" || saved.Action != "alert" {
				t.Fatalf("changed rejected row: %+v", saved)
			}
			db.Delete(&saved)
		})
	}
	direction := "output"
	good, err := svc.Create(&AlertRuleRequest{Name: "output", Pattern: "x", Severity: "high", Direction: &direction})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(good.ID, &AlertRuleRequest{Name: "output", Pattern: "x", Severity: "high", Action: "block"}); !errors.Is(err, ErrOutputBlock) {
		t.Fatalf("omitted direction bypass: %v", err)
	}
	saved, err := svc.Update(good.ID, &AlertRuleRequest{Name: "output", Pattern: "x", Severity: "high"})
	if err != nil || saved.Direction != "output" {
		t.Fatalf("preserve output: %+v %v", saved, err)
	}
}
