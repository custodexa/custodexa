package audit

import (
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 阻斷歸因的確定性：同一行指令同時命中多條阻斷規則時，歸因必須與資料庫
// 回傳列的順序無關。
//
// 資料庫不帶排序的查詢回傳的是實體儲存順序，而更新過的列在 PostgreSQL 會移到
// 堆積尾端——同一組規則在新站點與升級過的站點上，回傳順序可以相反。這裡用
// sqlmock 分別以兩種順序回傳同一組規則，模擬這兩種站點。
//
// 兩條規則取自出廠的兩條 agent 阻斷規則（名稱、pattern、適用範圍與種子一致），
// 兩者嚴重度相同，歸因只能由規則 id 決定。
const (
	blockOrderLateralID   uint = 19
	blockOrderSensitiveID uint = 20
)

func blockOrderRules() map[uint]model.AlertRule {
	return map[uint]model.AlertRule{
		blockOrderLateralID: {
			ID: blockOrderLateralID, Name: database.AgentLateralRuleName, Pattern: database.AgentLateralRulePattern,
			Severity: model.AlertSeverityHigh, Action: "block", Protocols: "ssh,k8s",
			Direction: model.DirectionInput, SubjectKind: model.KindAgent, Enabled: true,
		},
		blockOrderSensitiveID: {
			ID: blockOrderSensitiveID, Name: "Agent 敏感路徑讀取阻斷", Pattern: `(?i)(\.ssh/|\bauthorized_keys\b|/etc/shadow\b|\bid_rsa\b)`,
			Severity: model.AlertSeverityHigh, Action: "block", Protocols: "ssh,k8s",
			Direction: model.DirectionInput, SubjectKind: model.KindAgent, Enabled: true,
		},
	}
}

// blockOrderRows 依 ids 給定的順序組出 alert_rules 查詢結果
func blockOrderRows(ids []uint) *sqlmock.Rows {
	rules := blockOrderRules()
	rows := sqlmock.NewRows([]string{
		"id", "name", "pattern", "severity", "action", "protocols",
		"direction", "subject_kind", "enabled", "created_at", "updated_at",
	})
	for _, id := range ids {
		r := rules[id]
		rows.AddRow(r.ID, r.Name, r.Pattern, r.Severity, r.Action, r.Protocols,
			r.Direction, r.SubjectKind, r.Enabled, time.Now(), time.Now())
	}
	return rows
}

var blockOrderCommands = []string{
	"scp ~/.ssh/id_rsa host:/tmp",
	"grep ssh ~/.ssh/config",
}

var blockOrderRowOrders = [][]uint{
	{blockOrderLateralID, blockOrderSensitiveID},
	{blockOrderSensitiveID, blockOrderLateralID},
}

func TestMatchBlock_AttributionIndependentOfRowOrder(t *testing.T) {
	for _, order := range blockOrderRowOrders {
		t.Run(fmt.Sprintf("rows_%v", order), func(t *testing.T) {
			mock, gormDB := setupMatcherMockDB(t)
			m := NewAlertMatcher(gormDB, &recordingAlertSink{})
			mock.ExpectQuery(`SELECT \* FROM "alert_rules"`).WillReturnRows(blockOrderRows(order))
			require.NoError(t, m.LoadRules())
			require.NoError(t, mock.ExpectationsWereMet())

			agent := m.ForSubject(model.KindAgent)
			for _, cmd := range blockOrderCommands {
				// 前提：兩條規則都命中，否則歸因沒有可選的對象，斷言是空轉
				require.Len(t, agent.Match(cmd, "ssh"), 2, "指令 %q 應同時命中兩條阻斷規則", cmd)

				rule, hit := agent.MatchBlock(cmd, "ssh")
				require.True(t, hit, "指令 %q 應被阻斷", cmd)
				assert.Equal(t, blockOrderLateralID, rule.ID,
					"指令 %q 在回傳順序 %v 下應歸因於 id 最小的規則", cmd, order)
			}
		})
	}
}

// 快取的另一個注入點（setRules）同樣不得依賴呼叫端給的順序；
// 無主體綁定的 MatchBlock 與主體綁定版共用同一份比對結果，一併釘住。
func TestMatchBlock_SetRulesOrderIndependent(t *testing.T) {
	for _, order := range blockOrderRowOrders {
		t.Run(fmt.Sprintf("rules_%v", order), func(t *testing.T) {
			m := NewAlertMatcher(nil, nil)
			all := blockOrderRules()
			rules := make([]model.AlertRule, 0, len(order))
			for _, id := range order {
				r := all[id]
				r.SubjectKind = model.AlertSubjectAll
				rules = append(rules, r)
			}
			m.setRules(rules)

			for _, cmd := range blockOrderCommands {
				rule, hit := m.MatchBlock(cmd, "ssh")
				require.True(t, hit, "指令 %q 應被阻斷", cmd)
				assert.Equal(t, blockOrderLateralID, rule.ID,
					"指令 %q 在輸入順序 %v 下應歸因於 id 最小的規則", cmd, order)
			}
		})
	}
}

// 告警路徑逐條記錄每一條命中規則（不取第一條、不去重）；排序只決定同一指令
// 多筆告警在批次中的先後，固定為規則 id 升冪。
func TestMatchAndStore_RecordsEveryHitInRuleIDOrder(t *testing.T) {
	for _, order := range blockOrderRowOrders {
		t.Run(fmt.Sprintf("rows_%v", order), func(t *testing.T) {
			mock, gormDB := setupMatcherMockDB(t)
			sink := &recordingAlertSink{}
			m := NewAlertMatcher(gormDB, sink)
			mock.ExpectQuery(`SELECT \* FROM "alert_rules"`).WillReturnRows(blockOrderRows(order))
			require.NoError(t, m.LoadRules())

			m.ForSubject(model.KindAgent).MatchAndStore([]model.SessionCommand{
				{SessionID: 7, UserID: 3, Command: blockOrderCommands[0], Seq: 1},
			}, "ssh")

			var got []uint
			for _, a := range sink.alerts {
				require.NotNil(t, a.RuleID)
				got = append(got, *a.RuleID)
			}
			assert.Equal(t, []uint{blockOrderLateralID, blockOrderSensitiveID}, got)
		})
	}
}
