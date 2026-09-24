package audit

import (
	"fmt"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 非規則類告警的 Slack 呈現。
//
// 規則類告警有規則名可當標題、有指令可放進程式碼區塊；非規則類（指令稽核降級、
// 帳號新來源位址、敏感原文調閱等）兩者皆無：rule_name 存的是機器碼、指令欄刻意為空。
// 照規則類版型組字，收件人讀到的是一個機器碼標題加一個空的程式碼區塊，
// 看起來像通知壞了。故這幾類改以「白話標題＋一行說明（發生什麼、去哪裡看）」呈現。
//
// **只改給人讀的 Slack 文字**：webhook／syslog 的機器欄位（kind、reason_code、
// rule_name、command）名稱與值一律不動，那是收端的解析契約。

// isRuleKindAlert 是否走規則類版型。kind 為空者（早於來源類別欄位的舊列、測試通知）
// 一律視為規則類，保持其既有輸出。
func isRuleKindAlert(kind string) bool {
	return kind == "" || kind == model.AlertKindRule
}

// lexiconPhrase 取詞庫短語；鍵不存在時回空字串（Phrase 的慣例是回吐鍵本身，
// 本檔需要分辨「沒有短語」以省略整行，而不是把機器碼當成說明印出來）。
func lexiconPhrase(lang string, lex notifycat.Lexicon, key string) string {
	if key == "" {
		return ""
	}
	if phrase := notifycat.Phrase(lang, lex, key); phrase != key {
		return phrase
	}
	return ""
}

// buildNonRuleSlackText 組非規則類告警的 Slack 文字：
// 首行 emoji＋白話標題＋等級（＋阻斷標示）、其後為說明行、末行脈絡。
//
// 指令欄為空時不輸出程式碼區塊——空區塊只會被讀成「有一條空指令」或「通知壞了」。
// 等級照告警列原值呈現，不因改寫文字而升降。
func buildNonRuleSlackText(lang string, alert model.CommandAlert, names alertSubjectNames) string {
	title := lexiconPhrase(lang, notifycat.LexiconAlertKind, alert.Kind)
	if title == "" {
		// 尚未收錄的類別：退回既有行為（規則名欄位），寧可露出機器碼也不缺標題
		title = alert.RuleName
	}
	header := fmt.Sprintf("%s *%s* · %s",
		severityEmoji(alert.Severity), slackEscape(title),
		notifycat.Phrase(lang, notifycat.LexiconSeverity, alert.Severity))
	if alert.Blocked {
		header += " · " + notifycat.Phrase(lang, notifycat.LexiconAlertState,
			notifycat.AlertStateBlocked)
	}

	lines := []string{header}
	if text := lexiconPhrase(lang, notifycat.LexiconAlertKindText, alert.Kind); text != "" {
		lines = append(lines, text)
	}
	switch alert.Kind {
	case model.AlertKindAuditDegraded:
		// 取不到原因（或尚未收錄的原因碼）就不帶這一行，不以推測補上
		if reason := lexiconPhrase(lang, notifycat.LexiconDegradeReason, names.DegradeReason); reason != "" {
			lines = append(lines, reason)
		}
	case model.AlertKindNewSourceIP:
		if names.ClientIP != "" {
			lines = append(lines, notifycat.Phrase(lang, notifycat.LexiconEntity, notifycat.EntitySourceIP)+
				" "+slackEscape(names.ClientIP))
		}
	}
	if alert.Command != "" {
		lines = append(lines, fmt.Sprintf("```\n%s\n```", slackEscape(alert.Command)))
	}
	lines = append(lines, buildAlertContext(lang, alert, names))
	return strings.Join(lines, "\n")
}

// lookupDegradeReason 取開啟這段降級的那一輪的降級原因碼。
//
// 降級告警的觸發時刻即取自開啟該段降級的指令列的執行時刻，故以
// （會話, degraded, 執行時刻）精確對齊；同一時刻多列時取最早寫入者。
// 查不到（列已清除、查詢失敗、非降級類、零值會話）一律回空字串——
// 這一行是輔助說明，不為它延誤或阻擋通知。
func lookupDegradeReason(db *gorm.DB, alert model.CommandAlert) string {
	if db == nil || alert.Kind != model.AlertKindAuditDegraded || alert.SessionID == 0 {
		return ""
	}
	var reason string
	_ = db.Model(&model.SessionCommand{}).
		Select("degrade_reason").
		Where("session_id = ? AND degraded = ? AND executed_at = ?",
			alert.SessionID, true, alert.TriggeredAt).
		Order("id").
		Limit(1).
		Scan(&reason).Error
	return reason
}
