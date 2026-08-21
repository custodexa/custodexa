package audit

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// compiledRule 預編譯規則：Match 位於指令入庫熱路徑，
// 每次比對重編 regex 浪費 CPU，啟動/Reload 時一次編好（design D1）
type compiledRule struct {
	rule model.AlertRule
	re   *regexp.Regexp
}

// AlertMatcher 告警規則比對器（design D1）：
// RWMutex 保護的全量預編譯快取——規則量級小（數十條），
// 全量替換比增量維護簡單且無一致性問題；Go RE2 線性時間，無災難性回溯風險
type AlertMatcher struct {
	db *gorm.DB
	// alerts 告警落地面（modular-architecture W5 5.3）：入庫＋通知＋syslog tee 收成
	// 一個出口。比對路徑改走它**不是為了比對路徑自己**（它本來就 tee 得好好的），
	// 而是為了讓阻斷路徑無從繞過——兩條路徑共用同一個落地面，tee 才結構性不可漏。
	alerts gatewayapi.AlertSink

	mu    sync.RWMutex
	rules []compiledRule
}

// 套件級單例（design D1）：比對掛在 proxy.CommandRecorder 的寫入路徑，
// recorder 建構點深在連線處理流程內，逐層改建構簽名只為傳遞一個
// 全進程唯一的依賴不划算；單體架構下以 getter 取用、main 啟動時注入
var (
	alertMatcherMu       sync.RWMutex
	alertMatcherInstance *AlertMatcher
)

// NewAlertMatcher 建立比對器（不含單例註冊，供測試直接使用）。
//
// alerts 為告警落地面（W5 5.3）。**刻意由呼叫端注入而非在此 NewAlertRecorder(db)**：
// 內建構會讓組裝根的 requireAlertSink 自檢形同虛設（每個建構點各自生一份，
// 檢查不到），也讓「唯一建構點在組裝根」這條可守的規則失去意義。
func NewAlertMatcher(db *gorm.DB, alerts gatewayapi.AlertSink) *AlertMatcher {
	return &AlertMatcher{db: db, alerts: alerts}
}

// InitAlertMatcher 建立並註冊單例；main 啟動時呼叫一次
func InitAlertMatcher(db *gorm.DB, alerts gatewayapi.AlertSink) *AlertMatcher {
	m := NewAlertMatcher(db, alerts)
	alertMatcherMu.Lock()
	alertMatcherInstance = m
	alertMatcherMu.Unlock()
	return m
}

// GetAlertMatcher 取得單例；未初始化（單元測試環境）回 nil，呼叫端需 nil 檢查
func GetAlertMatcher() *AlertMatcher {
	alertMatcherMu.RLock()
	defer alertMatcherMu.RUnlock()
	return alertMatcherInstance
}

// ReloadAlertMatcher 規則 CUD 後刷新單例快取（design D1：同進程直接刷新）。
// 未初始化時 no-op；刷新失敗僅記 log——舊快取仍可用，規則變更下次 Reload 補上
func ReloadAlertMatcher() {
	m := GetAlertMatcher()
	if m == nil {
		return
	}
	if err := m.Reload(); err != nil {
		log.Printf("[AlertMatcher] 規則快取刷新失敗（沿用舊快取）: %v", err)
	}
}

// compileRules 純函數：過濾停用規則、預編譯 regex。
// 無效 regex 跳過並記 log 而非整批失敗——一條壞規則不應癱瘓其他規則
// （正常路徑 API 已驗證 pattern，此處防的是直接改 DB 等旁路寫入）
func compileRules(rules []model.AlertRule) []compiledRule {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			log.Printf("[AlertMatcher] 規則 %q (id=%d) pattern 無效，跳過: %v", r.Name, r.ID, err)
			continue
		}
		compiled = append(compiled, compiledRule{rule: r, re: re})
	}
	return compiled
}

// setRules 全量替換快取（Reload 與單元測試共用的注入點）；
// 回傳啟用且編譯成功的規則數，供呼叫端記 log（避免鎖外讀 m.rules 造成 race）
func (m *AlertMatcher) setRules(rules []model.AlertRule) int {
	compiled := compileRules(rules)
	m.mu.Lock()
	m.rules = compiled
	m.mu.Unlock()
	return len(compiled)
}

// LoadRules 從 DB 全量載入規則並重建快取
func (m *AlertMatcher) LoadRules() error {
	var rules []model.AlertRule
	if err := m.db.Find(&rules).Error; err != nil {
		return fmt.Errorf("載入告警規則失敗: %w", err)
	}
	count := m.setRules(rules)
	log.Printf("[AlertMatcher] 規則快取已載入 (%d 條啟用規則)", count)
	return nil
}

// Reload 重新載入規則（規則 CUD 後呼叫，design D1）
func (m *AlertMatcher) Reload() error {
	return m.LoadRules()
}

// Match 比對單條指令，回傳所有命中的啟用規則。
// 讀鎖下迭代：Reload 全量替換 slice，已回傳的指標指向舊 slice 元素，
// 不會被後續 Reload 改動，呼叫端可安全持有
// MatchBlock 回傳第一條命中的 block 規則（command-blocking 輪 A）：
// 阻斷判定走與告警同一規則快取，無額外查庫
func (m *AlertMatcher) MatchBlock(command, protocol string) (*model.AlertRule, bool) {
	for _, rule := range m.Match(command, protocol) {
		if rule.Action == "block" {
			return rule, true
		}
	}
	return nil, false
}

// ruleAppliesToProtocol 規則是否適用於該會話協議：rule.Protocols 為空＝全協議；
// 否則逗號分隔清單需含 protocol（避免 shell 規則誤掃 SQL、SQL 規則誤掃 shell）
func ruleAppliesToProtocol(ruleProtocols, protocol string) bool {
	if ruleProtocols == "" {
		return true
	}
	for _, p := range strings.Split(ruleProtocols, ",") {
		if strings.TrimSpace(p) == protocol {
			return true
		}
	}
	return false
}

func (m *AlertMatcher) Match(command, protocol string) []*model.AlertRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []*model.AlertRule
	for i := range m.rules {
		if !ruleAppliesToProtocol(m.rules[i].rule.Protocols, protocol) {
			continue
		}
		if m.rules[i].re.MatchString(command) {
			matched = append(matched, &m.rules[i].rule)
		}
	}
	return matched
}

// MatchAndStore 對一批指令逐條比對，命中即經 AlertSink 落地（design D2；W5 5.3 收口）。
// 由 recorder writeLoop 在指令批次 flush 成功後呼叫；
// 任何錯誤僅 log——告警是指令審計的附加價值，絕不反向影響指令入庫與會話。
//
// **W5 收口說明（零行為變更）**：入庫→通知→syslog tee 三步整段搬進 alertRecorder，
// 順序、批次形態（單次 Create）、通知與 tee 的「未初始化即靜默跳過」逐條保留。
// 這裡不再直寫 DB 的理由不是本路徑有問題，而是要讓 command_alerts 只剩一個落地面，
// 阻斷路徑就無從再開一條繞過 tee 的旁路（BD-1）。
func (m *AlertMatcher) MatchAndStore(cmds []model.SessionCommand, protocol string) {
	var alerts []gatewayapi.CommandAlert
	for _, cmd := range cmds {
		if cmd.Degraded {
			// 降級列的 command 恆為空字串（DB CHECK 釘死）。內建規則不會命中空字串，
			// 但**使用者可以自建 `.*` 這種規則**（規則 API 只驗 regex 可編譯），
			// 屆時每一筆降級列都會生出一筆 Command="" 的告警——那是把
			// 「這一輪的內容無法還原」呈現成「使用者執行了一條空指令」，
			// 即另一種捏造。降級的告警走專用發射器（sshproxy/command_degrade_alert.go），
			// 不經規則表。由 TestDegradedRowsNeverEnterRuleMatching 釘住。
			continue
		}
		for _, rule := range m.Match(cmd.Command, protocol) {
			ruleID := rule.ID
			alerts = append(alerts, gatewayapi.CommandAlert{
				Kind:      model.AlertKindRule,
				RuleID:    &ruleID,
				RuleName:  rule.Name,
				SessionID: cmd.SessionID,
				Actor:     gatewayapi.Actor{UserID: cmd.UserID},
				AssetID:   cmd.AssetID,
				Command:   cmd.Command,
				Level:     rule.Severity,
				// 以指令執行時間為觸發時間：比對是異步批次進行的，
				// 用入庫時刻會讓告警時間漂移、無法對齊指令流
				OccurredAt: cmd.ExecutedAt,
				// 新告警預設未審閱（audit-workflows D3）：顯式設 pending 而非依賴
				// gorm default tag，保 Create INSERT 欄位確定、不觸發 RETURNING
				Disposition: model.AlertDispositionPending,
				// Blocked 留 false：本路徑是「執行後比對」，指令已送達目標。
				// 阻斷事實只由 command_blocker 那條路徑產生
			})
		}
	}
	if len(alerts) == 0 {
		return
	}
	// 批次落地：SHALL 一次 RecordAlerts，SHALL NOT 逐筆呼叫 RecordAlert
	//（後者是 N 次 INSERT，屬效能與交易語義的行為變更）
	if err := gatewayapi.RecordAlerts(context.Background(), m.alerts, alerts); err != nil {
		log.Printf("[AlertMatcher] 告警寫入失敗 (count=%d): %v", len(alerts), err)
		return
	}
}
