package database

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sensitivescan"

	"gorm.io/gorm"
)

// builtinAlertRule 一條內建的危險指令告警規則。
type builtinAlertRule struct {
	Name        string
	Pattern     string
	Severity    string
	Protocols   string
	Direction   string
	SubjectKind string
	Action      string
}

// builtinAlertRules 16 條內建告警規則的**最終狀態**。
//
// 這 12 條在壓縮前是三個 migration 疊加的結果，baseline 直接寫終態：
//
//	v7.9                          插入 8 條 shell 危險規則（當時無 protocols 欄）
//	20260620_alert_rules_protocols 回填前 8 條為 'ssh,k8s'，再插 4 條 SQL/Redis 規則
//	20260813_mssql_web_cli         把 3 條 SQL 規則的 protocols 擴為含 mssql
//
// **第三步最容易漏**：schema 等價比對（pg_dump --schema-only）完全看不到種子資料，
// 漏掉它的後果是 MSSQL 會話的危險 SQL 無規則覆蓋，且沒有任何測試會紅。
// 故 protocols 的分佈本身即為驗收項：ssh,k8s × 8、mysql,postgres,mssql × 3、redis × 1。
//
// severity 取向（沿 v7.9 的原始裁決）：不可逆破壞（資料／系統／防火牆）＝ high，
// 高風險但可回復的設定變更 ＝ medium。全部 action = alert、enabled = true。
var builtinAlertRules = []builtinAlertRule{
	// shell 危險指令（文字終端）——protocols 限定使 SQL 字面值不再誤觸
	{"遞迴強制刪除", `rm\s+-(rf|fr)\b`, "high", "ssh,k8s", model.DirectionInput, model.AlertSubjectAll, "alert"},
	{"格式化檔案系統", `\bmkfs(\.\w+)?\b`, "high", "ssh,k8s", model.DirectionInput, model.AlertSubjectAll, "alert"},
	{"dd 寫入裝置", `\bdd\s+.*of=/dev/`, "high", "ssh,k8s", model.DirectionInput, model.AlertSubjectAll, "alert"},
	{"chmod 777 全開權限", `\bchmod\s+(-R\s+)?777\b`, "medium", "ssh,k8s", model.DirectionInput, model.AlertSubjectAll, "alert"},
	{"遞迴變更擁有者為 root", `\bchown\s+-R\s+root\b`, "medium", "ssh,k8s", model.DirectionInput, model.AlertSubjectAll, "alert"},
	{"關機或重啟", `\b(shutdown|poweroff|reboot)\b`, "medium", "ssh,k8s", model.DirectionInput, model.AlertSubjectAll, "alert"},
	{"清空防火牆規則", `\biptables\s+-F\b`, "high", "ssh,k8s", model.DirectionInput, model.AlertSubjectAll, "alert"},
	{"下載並管道執行腳本", `\b(curl|wget)\b.*\|\s*(ba|z)?sh\b`, "high", "ssh,k8s", model.DirectionInput, model.AlertSubjectAll, "alert"},
	// SQL 危險指令（DB CLI）——含 mssql，即 20260813 那一步的終態
	{"SQL 刪除資料表或資料庫", `(?i)\bdrop\s+(table|database|schema)\b`, "high", "mysql,postgres,mssql", model.DirectionInput, model.AlertSubjectAll, "alert"},
	{"SQL 清空資料表", `(?i)\btruncate\b`, "high", "mysql,postgres,mssql", model.DirectionInput, model.AlertSubjectAll, "alert"},
	{"SQL 授予全部權限", `(?i)\bgrant\s+all\b`, "medium", "mysql,postgres,mssql", model.DirectionInput, model.AlertSubjectAll, "alert"},
	// Redis 危險指令
	{"Redis 清空資料庫", `(?i)\bflush(all|db)\b`, "high", "redis", model.DirectionInput, model.AlertSubjectAll, "alert"},
	{"輸出可能含信用卡號", sensitivescan.CardPattern, "high", "ssh,k8s,mysql,postgres,mssql,redis", model.DirectionOutput, model.AlertSubjectAll, "alert"},
	{"輸出可能含私鑰標頭", sensitivescan.PrivateKeyPattern, "high", "ssh,k8s,mysql,postgres,mssql,redis", model.DirectionOutput, model.AlertSubjectAll, "alert"},
	{AgentLateralRuleName, AgentLateralRulePattern, "high", "ssh,k8s", model.DirectionInput, model.KindAgent, "block"},
	{"Agent 敏感路徑讀取阻斷", `(?i)(\.ssh/|\bauthorized_keys\b|/etc/shadow\b|\bid_rsa\b)`, "high", "ssh,k8s", model.DirectionInput, model.KindAgent, "block"},
}

// Agent 橫向移動阻斷規則的名稱與 pattern 的**唯一事實源**。
//
// 出廠種子（baseline／agent_subject_rules）與資料 migration
// （20260923_agent_lateral_rule_pattern）都由此取值：pattern 內含大量反斜線與
// 引號，任何一處另抄一份字面值，日後只改一邊的後果是「新安裝擋得住、升級站點
// 擋不住」而沒有任何測試會紅。
const (
	AgentLateralRuleName = "Agent 橫向移動阻斷"

	// AgentLateralRulePattern 現行版：比對整行原文，不做 shell 分詞。名稱須以
	// 行首、空白、`;&|(`、反引號、換行、`$`、`=`、`\` 起頭（可略過引號與路徑前綴），
	// 並以空白、行尾或 `;&|)` 收尾（可接引號）。故引數位置的同名詞也會命中
	// （`man ssh`、`which nc`、`ls /usr/bin/ssh`）；名稱前緊接 `.`（`~/.ssh`）或
	// 後接 `/`、`-`、`.` 等其他字元（`/etc/ssh/`、`sshd`、`ssh-keygen`、`ssh.exe`）
	// 則不命中。寧可多擋、不漏擋：誤擋的代價只是中斷 agent 的工作。
	AgentLateralRulePattern = `(?i)(^|[\s;&|(\x60\n\r$=\\])["']*(\S*/)?(ssh|scp|sftp|nc|ncat|socat|Enter-PSSession|Invoke-Command|psexec)["']*(\s|$|[;&|)])`
)

// agentLateralLegacyPatterns 1.11.0（含其開發期）出廠過的兩個歷史 pattern。
//
// 升級時只有 pattern 仍等於其中之一者才視為「未被管理員改過」而更新；
// 任何其他值一律保留——管理員的調校不該被升級覆寫。
var agentLateralLegacyPatterns = []string{
	`(?i)\b(ssh|scp|sftp|nc|socat|Enter-PSSession|Invoke-Command|psexec)\b`,
	`(?i)(^\s*|[;&|(\x60]\s*|\bsudo\s+(\S+\s+)*)(ssh|scp|sftp|nc|socat|Enter-PSSession|Invoke-Command|psexec)\b`,
}

// seedBuiltinAlertRules 在 baseline 階段冪等寫入 12 條既有輸入規則。
// 此時 direction 尚不存在；兩條 output 終態種子由加欄增量寫入。
//
// 冪等靠 `alert_rules.name` 的唯一索引（baseline 新增物）＋ `ON CONFLICT DO NOTHING`。
// **這一層是縱深而非主防線**：主防線是 RunMigrations 的 fail-close（既有資料庫根本
// 跑不到這裡）。但若哪天有人繞過版本判定重跑種子，沒有唯一索引的後果是靜默的
// ——每條危險指令觸發兩次告警、審閱計數翻倍，且不報錯。
//
// 以 bind 參數而非字串拼接：pattern 內含大量反斜線與引號，拼接一次寫錯就是
// 規則永久失效而無人察覺（regex 編不過只在觸發時才顯現）。
func seedBuiltinAlertRules(db *gorm.DB) error {
	return seedBuiltinAlertRulesForDirection(db, model.DirectionInput)
}

// seedBuiltinAlertRulesForDirection 沿用同一份 16 條終態清單。
// input 在 baseline（無 direction 欄）寫入；output 僅在加欄後寫入。
func seedBuiltinAlertRulesForDirection(db *gorm.DB, direction string) error {
	if len(builtinAlertRules) != 16 {
		return fmt.Errorf("內建告警規則清單有 %d 條（應為 16）：種子清單已失真", len(builtinAlertRules))
	}
	const inputStmt = `INSERT INTO alert_rules (name, pattern, severity, action, enabled, protocols, created_at, updated_at)
  VALUES (?, ?, ?, 'alert', TRUE, ?, NOW(), NOW())
  ON CONFLICT (name) DO NOTHING`
	const outputStmt = `INSERT INTO alert_rules (name, pattern, severity, action, enabled, protocols, direction, created_at, updated_at)
  VALUES (?, ?, ?, 'alert', TRUE, ?, ?, NOW(), NOW())
  ON CONFLICT (name) DO NOTHING`
	for _, r := range builtinAlertRules {
		if r.Direction != direction || r.SubjectKind != model.AlertSubjectAll {
			continue
		}
		stmt := inputStmt
		args := []interface{}{r.Name, r.Pattern, r.Severity, r.Protocols}
		if direction == model.DirectionOutput {
			stmt = outputStmt
			args = append(args, r.Direction)
		}
		if err := db.Exec(stmt, args...).Error; err != nil {
			return fmt.Errorf("種子告警規則 %q 失敗: %w", r.Name, err)
		}
	}
	return nil
}
