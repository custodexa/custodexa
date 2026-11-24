package notifycat

import (
	"strconv"
	"strings"
	"time"
)

// LinkPath 依事件規格的路徑樣板代入參數，回傳站內路徑；事件未宣告樣板、引用的參數不是大於零的整數時回空字串
// （整個連結省略，不留殘缺路徑）。
func LinkPath(event Event, params map[string]string) string {
	spec, ok := registry[event]
	if !ok || spec.Link.Path == "" {
		return ""
	}
	return expandLinkTemplate(spec.Link.Path, params)
}

// LinkLabelOf 事件的連結文字種類；未登錄的事件為「前往查看」。
func LinkLabelOf(event Event) LinkLabel {
	if spec, ok := registry[event]; ok && spec.Link.Label != "" {
		return spec.Link.Label
	}
	return LinkLabelView
}

// expandLinkTemplate 展開 `{name}` 佔位；代入值必須是大於零的十進位整數。
func expandLinkTemplate(tmpl string, params map[string]string) string {
	var b strings.Builder
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] != '{' {
			b.WriteByte(tmpl[i])
			continue
		}
		end := strings.IndexByte(tmpl[i:], '}')
		if end < 0 {
			return ""
		}
		name := tmpl[i+1 : i+end]
		v := params[name]
		n, err := strconv.ParseUint(v, 10, 63)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != v {
			return ""
		}
		b.WriteString(v)
		i += end
	}
	return b.String()
}

// SlackFooter Slack 文字的最後一行：發生時間（Slack 日期語法，閱讀者以自己的時區看到；退回文字為 UTC）
// 與有連結時的「<連結|前往處理或前往查看>」。link 為空時不留任何連結語法或分隔符。
//
// link 由投遞層以已驗證的對外基準網址加事件樣板組成（不含 `<`、`>`、`|` 與空白），此處不再跳脫。
func SlackFooter(lang string, occurred time.Time, link string, label LinkLabel) string {
	return Phrase(lang, LexiconNotifyFooter, NotifyFooterKeyOccurred) + " " + SlackDate(occurred) + slackLinkSuffix(lang, link, label)
}

// SlackLinkSuffix 只有連結的那一段（` · <連結|文字>`）；link 為空回空字串。給時間已在脈絡行的指令告警使用。
func SlackLinkSuffix(lang string, link string, label LinkLabel) string {
	return slackLinkSuffix(lang, link, label)
}

func slackLinkSuffix(lang, link string, label LinkLabel) string {
	if link == "" {
		return ""
	}
	key := NotifyFooterKeyView
	if label == LinkLabelAction {
		key = NotifyFooterKeyAction
	}
	// 連結本身也跳脫：查詢字串的 `&` 是 Slack 文字的控制字元，以 `&amp;` 表示（Slack 會還原）
	return " · <" + slackEscape(link) + "|" + slackEscape(Phrase(lang, LexiconNotifyFooter, key)) + ">"
}

// SlackDate Slack 日期語法：`<!date^{unix}^{date_num} {time_secs}|YYYY-MM-DD HH:MM:SS UTC>`。
func SlackDate(t time.Time) string {
	u := t.UTC()
	return "<!date^" + strconv.FormatInt(u.Unix(), 10) + "^{date_num} {time_secs}|" + u.Format("2006-01-02 15:04:05") + " UTC>"
}
