package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 本檔守的是升級路徑上唯一的行為差異：**已安裝站點**的出廠橫向移動規則會被
// 改寫成現行 pattern，而管理員改過的不會。出廠種子只在建表時插入，所以沒有
// 這條資料 migration 的話，升級後的站點仍以舊 pattern 執行，且不會有任何症狀
// 能從 schema 面看出來——parity 與 baseline 守衛都不涵蓋種子資料的值。

// TestAgentLateralRulePatternMigrationRegistered 登記面：版本存在、排在加欄之後、Up／Down 非 nil。
//
// 順序是語義的一部分：這條只改資料，必須在同批 schema 增量都套用完之後跑，
// 否則在「表還沒到位」的中間狀態上執行 UPDATE。
func TestAgentLateralRulePatternMigrationRegistered(t *testing.T) {
	const version = "20260923_agent_lateral_rule_pattern"
	const prior = "20260922_agent_session_token_name"

	idx, priorIdx := -1, -1
	for i := range migrations {
		switch migrations[i].Version {
		case version:
			idx = i
		case prior:
			priorIdx = i
		}
	}
	if idx < 0 {
		t.Fatalf("migrations 內找不到版本 %s：寫了 Up 但沒登記，升級站點不會套用", version)
	}
	if priorIdx < 0 {
		t.Fatalf("migrations 內找不到前置版本 %s", prior)
	}
	if idx <= priorIdx {
		t.Fatalf("%s 必須排在 %s 之後（得 idx=%d, prior=%d）", version, prior, idx, priorIdx)
	}
	if migrations[idx].Up == nil || migrations[idx].Down == nil {
		t.Fatal("Up／Down 不得為 nil")
	}
	// 新 pattern 與歷史值必須來自同一份常數，migration 內不得另抄字面值。
	if AgentLateralRulePattern == "" || len(agentLateralLegacyPatterns) != 2 {
		t.Fatalf("常數失真：pattern=%q，歷史值 %d 個（應為 2）",
			AgentLateralRulePattern, len(agentLateralLegacyPatterns))
	}
	for _, legacy := range agentLateralLegacyPatterns {
		if legacy == AgentLateralRulePattern {
			t.Fatal("歷史值與現行值相同：WHERE 條件會失去意義")
		}
	}
	// 出廠種子清單必須用同一份常數（避免種子與 migration 各寫一份而分岔）。
	var seeded string
	for _, r := range builtinAlertRules {
		if r.Name == AgentLateralRuleName {
			seeded = r.Pattern
		}
	}
	if seeded != AgentLateralRulePattern {
		t.Fatalf("出廠種子的 pattern 與常數不一致：新安裝與升級站點會拿到不同規則\n種子=%q", seeded)
	}
}

// lateralRuleFixtures 三種列：一個歷史出廠值（由 legacy 指定是哪一個）、
// 一個管理員改過的、一個名稱不同但 pattern 剛好是歷史值的。
func lateralRuleFixtures(legacy string) []model.AlertRule {
	rows := []model.AlertRule{
		{Name: AgentLateralRuleName, Pattern: legacy},
		{Name: AgentLateralRuleName + "（管理員調校）", Pattern: adminEditedLateralPattern},
		{Name: "遞迴強制刪除", Pattern: agentLateralLegacyPatterns[0]},
	}
	for i := range rows {
		rows[i].Severity = "high"
		rows[i].Action = "block"
		rows[i].Protocols = "ssh,k8s"
		rows[i].Enabled = true
		rows[i].Direction = model.DirectionInput
		rows[i].SubjectKind = model.KindAgent
		rows[i].CreatedAt = time.Now()
		rows[i].UpdatedAt = time.Now()
	}
	return rows
}

// adminEditedLateralPattern 代表站點自行調校過的值：不在歷史清單內，故不得被改寫。
const adminEditedLateralPattern = `(?i)\bssh\b.*prod`

// assertLateralRuleOutcome 三條驗收：歷史值更新、管理員值保留、名稱不同者保留。
//
// 第三列的名稱不同而 pattern 相同，釘住 WHERE 的名稱條件——少了它，
// 一條只看 pattern 的 UPDATE 也會通過。
func assertLateralRuleOutcome(t *testing.T, db *gorm.DB) {
	t.Helper()
	get := func(name string) model.AlertRule {
		var r model.AlertRule
		if err := db.Where("name = ?", name).Take(&r).Error; err != nil {
			t.Fatalf("讀取規則 %q 失敗: %v", name, err)
		}
		return r
	}
	if got := get(AgentLateralRuleName).Pattern; got != AgentLateralRulePattern {
		t.Errorf("歷史出廠值未被更新：\n得   %q\n預期 %q", got, AgentLateralRulePattern)
	}
	if got := get(AgentLateralRuleName + "（管理員調校）").Pattern; got != adminEditedLateralPattern {
		t.Errorf("管理員改過的規則被覆寫：得 %q", got)
	}
	if got := get("遞迴強制刪除").Pattern; got != agentLateralLegacyPatterns[0] {
		t.Errorf("名稱不符的規則被誤改：得 %q", got)
	}
}

// TestAgentLateralRulePatternSQLite 語義面：兩個歷史值各跑一輪，逐列比對結果。
func TestAgentLateralRulePatternSQLite(t *testing.T) {
	for i, legacy := range agentLateralLegacyPatterns {
		t.Run(fmt.Sprintf("legacy_%d", i), func(t *testing.T) {
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
			if err != nil {
				t.Fatalf("sqlite 連線失敗: %v", err)
			}
			// `:memory:` 每條連線是各自獨立的庫；不收口連線池會讓建表與查詢落在不同庫上。
			if sqlDB, err := db.DB(); err == nil {
				sqlDB.SetMaxOpenConns(1)
			}
			if err := db.AutoMigrate(&model.AlertRule{}); err != nil {
				t.Fatalf("建表失敗: %v", err)
			}
			if err := db.Create(lateralRuleFixtures(legacy)).Error; err != nil {
				t.Fatalf("寫入測試列失敗: %v", err)
			}

			if err := applyAgentLateralRulePattern(db); err != nil {
				t.Fatalf("migration Up 失敗: %v", err)
			}
			assertLateralRuleOutcome(t, db)

			// 冪等：再跑一次不得改變任何列（第二次的 WHERE 已無命中）。
			if err := applyAgentLateralRulePattern(db); err != nil {
				t.Fatalf("重跑 Up 失敗: %v", err)
			}
			assertLateralRuleOutcome(t, db)

			// Down 是 no-op：明文釘住，避免日後有人「順手」補上回寫而覆蓋管理員的值。
			if err := rollbackAgentLateralRulePattern(db); err != nil {
				t.Fatalf("Down 應為 no-op: %v", err)
			}
			assertLateralRuleOutcome(t, db)
		})
	}
}

// TestAgentLateralRulePatternPostgres 結構面：在真的 postgres 上走完整 migration 鏈，
// 再把出廠規則改回歷史值模擬 1.11.0 站點，重跑本條 migration 驗收。
// （gating：未設 TEST_PG_DSN 即 skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail）
func TestAgentLateralRulePatternPostgres(t *testing.T) {
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN),
		fmt.Sprintf("lateral_rule_%d", time.Now().UnixNano()))
	for _, m := range migrations {
		if err := m.Up(db); err != nil {
			t.Fatalf("migration %s 失敗: %v", m.Version, err)
		}
	}

	// 全新安裝即應是現行 pattern（種子與 migration 同源的直接證據）。
	var fresh model.AlertRule
	if err := db.Where("name = ?", AgentLateralRuleName).Take(&fresh).Error; err != nil {
		t.Fatalf("全新安裝找不到出廠規則: %v", err)
	}
	if fresh.Pattern != AgentLateralRulePattern {
		t.Fatalf("全新安裝的 pattern 不是現行值：得 %q", fresh.Pattern)
	}

	for i, legacy := range agentLateralLegacyPatterns {
		t.Run(fmt.Sprintf("legacy_%d", i), func(t *testing.T) {
			// 模擬 1.11.0 已安裝站點：出廠規則退回歷史值，
			// 另有一條管理員調校過的與一條 pattern 相同但名稱不同的。
			if err := db.Exec(`UPDATE alert_rules SET pattern = ? WHERE name = ?`,
				legacy, AgentLateralRuleName).Error; err != nil {
				t.Fatalf("退回歷史值失敗: %v", err)
			}
			if err := db.Exec(`UPDATE alert_rules SET pattern = ? WHERE name = ?`,
				agentLateralLegacyPatterns[0], "遞迴強制刪除").Error; err != nil {
				t.Fatalf("改寫他名規則失敗: %v", err)
			}
			if err := db.Exec(`DELETE FROM alert_rules WHERE name = ?`,
				AgentLateralRuleName+"（管理員調校）").Error; err != nil {
				t.Fatalf("清理失敗: %v", err)
			}
			admin := lateralRuleFixtures(legacy)[1]
			if err := db.Create(&admin).Error; err != nil {
				t.Fatalf("寫入管理員調校列失敗: %v", err)
			}

			if err := applyAgentLateralRulePattern(db); err != nil {
				t.Fatalf("migration Up 失敗: %v", err)
			}
			assertLateralRuleOutcome(t, db)
		})
	}
}
