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

// TestAlertRuleCreateHonorsEnabledFlag 建立時的啟用旗標原樣落庫，且停用的阻斷規則不擋命令。
//
// 模型欄位帶資料庫預設值 true，而 ORM 對帶預設值的欄位遇零值會交給資料庫預設：
// 「建成停用」若靜默變成啟用，一條 action=block 的規則會在建立當下就開始擋命令。
// 最後一格以真比對器重新載入規則，驗的是阻斷行為而不只是欄位值。
func TestAlertRuleCreateHonorsEnabledFlag(t *testing.T) {
	f, tr := false, true
	for _, tc := range []struct {
		name    string
		enabled *bool
		want    bool
	}{
		{"帶_false_存成停用", &f, false},
		{"未帶預設啟用", nil, true},
		{"帶_true_存成啟用", &tr, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, db := setupAlertRuleDB(t)
			rule, err := svc.Create(&AlertRuleRequest{
				Name: "阻斷刪除", Pattern: `rm\s+-rf`, Severity: "high", Action: "block", Enabled: tc.enabled,
			})
			if err != nil {
				t.Fatalf("建立規則: %v", err)
			}
			if rule.Enabled != tc.want {
				t.Errorf("回傳 enabled = %v，want %v", rule.Enabled, tc.want)
			}
			var saved model.AlertRule
			if err := db.First(&saved, rule.ID).Error; err != nil {
				t.Fatalf("讀規則列: %v", err)
			}
			if saved.Enabled != tc.want {
				t.Errorf("落庫 enabled = %v，want %v", saved.Enabled, tc.want)
			}
			m := NewAlertMatcher(db, nil)
			if err := m.Reload(); err != nil {
				t.Fatalf("載入規則: %v", err)
			}
			if _, blocked := m.MatchBlock("rm -rf /tmp/x", "ssh"); blocked != tc.want {
				t.Errorf("阻斷 = %v，want %v（停用規則不得擋命令）", blocked, tc.want)
			}
		})
	}
}
