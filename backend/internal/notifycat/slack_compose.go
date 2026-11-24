package notifycat

import (
	"strings"
	"time"
)

// SlackMessage 組一則 Slack 文字的成分。Title、Body、Extra 為已渲染（已跳脫）的文字。
type SlackMessage struct {
	// Prefix 開頭符號：一則訊息只有這一個符號，放在第一行最前面。告警與系統事件用 SeveritySymbol
	// 依等級取得，測試通知用 TestSymbol；空字串＝不加。內文、固定說明與最後一行都不放符號
	Prefix string
	Title  string
	// Severity 第一行的分級標籤（high／medium／low；空字串＝不加）。分級只在第一行呈現一次
	Severity string
	Body     string
	// Extra 內文之後的固定說明（例如系統安全告警的「去哪裡看」句；空字串＝不加）
	Extra string
	// Occurred 發生時間；零值＝不加最後一行
	Occurred time.Time
	// Link 完整連結（已驗證的對外基準網址＋事件路徑；空字串＝不附）
	Link      string
	LinkLabel LinkLabel
}

// 開頭符號。等級符號讓讀者在訊息列表中一眼分出先後；測試通知不屬於任何等級，另用一個符號。
const (
	SymbolHigh    = "🔴"
	SymbolMedium  = "🟠"
	SymbolLow     = "🟡"
	SymbolUnknown = "⚪"
	TestSymbol    = "🔔"
)

// SeveritySymbol 依等級取得 Slack 訊息的開頭符號。等級不在三值內（空字串或未知值）時回中性的
// SymbolUnknown：第一行仍有可對齊的開頭，但不暗示任何急迫程度。
func SeveritySymbol(severity string) string {
	switch severity {
	case SeverityHigh:
		return SymbolHigh
	case SeverityMedium:
		return SymbolMedium
	case SeverityLow:
		return SymbolLow
	default:
		return SymbolUnknown
	}
}

// ComposeSlack 依通道語系組出完整 Slack 文字：第一行開頭符號、粗體標題與分級標籤；接著內文與固定說明；
// 最後一行發生時間（Slack 日期語法）與有連結時的前往連結。
func ComposeSlack(lang string, m SlackMessage) string {
	first := "*" + m.Title + "*"
	if m.Prefix != "" {
		first = m.Prefix + " " + first
	}
	if m.Severity != "" {
		first += " · " + Phrase(lang, LexiconSeverity, m.Severity)
	}
	lines := []string{first}
	if m.Body != "" {
		lines = append(lines, m.Body)
	}
	if m.Extra != "" {
		lines = append(lines, m.Extra)
	}
	if !m.Occurred.IsZero() {
		lines = append(lines, SlackFooter(lang, m.Occurred, m.Link, m.LinkLabel))
	}
	return strings.Join(lines, "\n")
}
