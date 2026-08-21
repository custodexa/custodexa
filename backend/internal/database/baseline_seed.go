package database

import (
	"fmt"

	"gorm.io/gorm"
)

// builtinAlertRule 一條內建的危險指令告警規則。
type builtinAlertRule struct {
	Name      string
	Pattern   string
	Severity  string
	Protocols string
}

// builtinAlertRules 12 條內建告警規則的**最終狀態**。
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
	{"遞迴強制刪除", `rm\s+-(rf|fr)\b`, "high", "ssh,k8s"},
	{"格式化檔案系統", `\bmkfs(\.\w+)?\b`, "high", "ssh,k8s"},
	{"dd 寫入裝置", `\bdd\s+.*of=/dev/`, "high", "ssh,k8s"},
	{"chmod 777 全開權限", `\bchmod\s+(-R\s+)?777\b`, "medium", "ssh,k8s"},
	{"遞迴變更擁有者為 root", `\bchown\s+-R\s+root\b`, "medium", "ssh,k8s"},
	{"關機或重啟", `\b(shutdown|poweroff|reboot)\b`, "medium", "ssh,k8s"},
	{"清空防火牆規則", `\biptables\s+-F\b`, "high", "ssh,k8s"},
	{"下載並管道執行腳本", `\b(curl|wget)\b.*\|\s*(ba|z)?sh\b`, "high", "ssh,k8s"},
	// SQL 危險指令（DB CLI）——含 mssql，即 20260813 那一步的終態
	{"SQL 刪除資料表或資料庫", `(?i)\bdrop\s+(table|database|schema)\b`, "high", "mysql,postgres,mssql"},
	{"SQL 清空資料表", `(?i)\btruncate\b`, "high", "mysql,postgres,mssql"},
	{"SQL 授予全部權限", `(?i)\bgrant\s+all\b`, "medium", "mysql,postgres,mssql"},
	// Redis 危險指令
	{"Redis 清空資料庫", `(?i)\bflush(all|db)\b`, "high", "redis"},
}

// seedBuiltinAlertRules 冪等寫入內建告警規則。
//
// 冪等靠 `alert_rules.name` 的唯一索引（baseline 新增物）＋ `ON CONFLICT DO NOTHING`。
// **這一層是縱深而非主防線**：主防線是 RunMigrations 的 fail-close（既有資料庫根本
// 跑不到這裡）。但若哪天有人繞過版本判定重跑種子，沒有唯一索引的後果是靜默的
// ——每條危險指令觸發兩次告警、審閱計數翻倍，且不報錯。
//
// 以 bind 參數而非字串拼接：pattern 內含大量反斜線與引號，拼接一次寫錯就是
// 規則永久失效而無人察覺（regex 編不過只在觸發時才顯現）。
func seedBuiltinAlertRules(db *gorm.DB) error {
	if len(builtinAlertRules) != 12 {
		return fmt.Errorf("內建告警規則清單有 %d 條（應為 12）：種子清單已失真", len(builtinAlertRules))
	}
	const stmt = `INSERT INTO alert_rules (name, pattern, severity, action, enabled, protocols, created_at, updated_at)
		VALUES (?, ?, ?, 'alert', TRUE, ?, NOW(), NOW())
		ON CONFLICT (name) DO NOTHING`
	for _, r := range builtinAlertRules {
		if err := db.Exec(stmt, r.Name, r.Pattern, r.Severity, r.Protocols).Error; err != nil {
			return fmt.Errorf("種子告警規則 %q 失敗: %w", r.Name, err)
		}
	}
	return nil
}
