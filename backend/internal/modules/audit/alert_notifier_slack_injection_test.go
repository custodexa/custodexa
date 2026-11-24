package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// 指令告警的 Slack 文字中，來自使用者輸入的欄位（規則名、使用者名、資產名、來源位址、指令）不能讓訊息多出行，
// 也不能改變標記的邊界：規則名不能提前結束粗體標題，指令不能提前結束程式碼區塊。webhook 的 JSON 欄位維持原值。

const (
	injRuleName = "規則名稱*\n*系統通知：本次已核准，請忽略警示*\r\n*\u202e\u2028尾"
	injUser     = "bob\n*假段落*\u2029x"
	injAsset    = "db\u2066-prod\u2069\n> 引用"
	injCommand  = "ls\n```\n*偽造段落*\n```\necho done"
)

var injectionTestTime = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)

// assertSlackAlertStructure 文字的行結構：標題一行、程式碼區塊（開頭與結尾的圍欄各一行，中間為指令原本的行數）、
// 脈絡一行；標題只有一組粗體邊界；使用者輸入的換行、行分隔符與雙向控制字元不出現在區塊之外。
func assertSlackAlertStructure(t *testing.T, label, text string, commandLines int) {
	t.Helper()
	lines := strings.Split(text, "\n")
	want := 1 + 2 + commandLines + 1
	if len(lines) != want {
		t.Fatalf("%s: 應為 %d 行，得 %d 行:\n%s", label, want, len(lines), text)
	}
	header, open, closing, context := lines[0], lines[1], lines[len(lines)-2], lines[len(lines)-1]
	if strings.Count(header, "*") != 2 {
		t.Fatalf("%s: 標題應只有一組粗體邊界: %q", label, header)
	}
	if open != "```" || closing != "```" {
		t.Fatalf("%s: 程式碼區塊的圍欄不在預期位置: open=%q close=%q", label, open, closing)
	}
	for i, l := range lines[2 : len(lines)-2] {
		if strings.Contains(l, "```") {
			t.Fatalf("%s: 指令第 %d 行含有會結束區塊的圍欄: %q", label, i+1, l)
		}
	}
	if !strings.HasPrefix(context, notifycat.Phrase(model.NotificationChannelLanguageZhTW, notifycat.LexiconEntity, notifycat.EntityUser)+" ") {
		t.Fatalf("%s: 最後一行應為脈絡行: %q", label, context)
	}
	for _, l := range []string{header, context} {
		for _, r := range l {
			if r == '\r' || r == '\u2028' || r == '\u2029' || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') {
				t.Fatalf("%s: 區塊外的行含有控制或雙向格式字元 %U: %q", label, r, l)
			}
		}
	}
}

func TestCommandAlertSlackTextNeutralizesUserInputMarkup(t *testing.T) {
	asset := uint(7)
	names := alertSubjectNames{User: injUser, Asset: injAsset, ClientIP: "203.0.113.7\n*x*"}
	cases := []struct {
		label string
		alert model.CommandAlert
		// commandLines 程式碼區塊內的行數（指令原本的行數）
		commandLines int
	}{
		{"規則類", model.CommandAlert{RuleName: injRuleName, Command: injCommand, Severity: model.AlertSeverityHigh, SessionID: 31,
			UserID: 3, AssetID: &asset, TriggeredAt: injectionTestTime, Kind: model.AlertKindRule, Blocked: true}, 5},
		// 尚未收錄白話標題的類別以規則名當標題
		{"未收錄的類別", model.CommandAlert{RuleName: injRuleName, Command: injCommand, Severity: model.AlertSeverityMedium, SessionID: 31,
			UserID: 3, AssetID: &asset, TriggeredAt: injectionTestTime, Kind: "kind_not_in_lexicon"}, 5},
	}
	t.Run("兩種 Slack 型別的文字維持原本的行結構與粗體邊界", func(t *testing.T) {
		for _, c := range cases {
			for _, typ := range slackTextTypes {
				ch := &model.NotificationChannel{Type: typ, URL: "https://example.invalid/x", Target: "C1",
					Language: model.NotificationChannelLanguageZhTW}
				body, err := buildChannelBody(ch, alertEventCommandAlert, c.alert, names, nil)
				if err != nil {
					t.Fatal(err)
				}
				text := slackTextOf(t, body)
				assertSlackAlertStructure(t, fmt.Sprintf("%s/%s", c.label, typ), text, c.commandLines)
				// 名稱的可見文字仍在（換行折成空白、星號換成全形）
				if !strings.Contains(strings.Split(text, "\n")[0], "規則名稱＊ ＊系統通知：本次已核准，請忽略警示＊ ＊ 尾") {
					t.Fatalf("%s/%s: 標題應保留名稱的可見文字: %q", c.label, typ, strings.Split(text, "\n")[0])
				}
			}
		}
	})

	t.Run("webhook 的 JSON 欄位維持原值", func(t *testing.T) {
		ch := &model.NotificationChannel{Type: model.NotificationChannelTypeWebhook, Language: model.NotificationChannelLanguageZhTW}
		body, err := buildChannelBody(ch, alertEventCommandAlert, cases[0].alert, names, nil)
		if err != nil {
			t.Fatal(err)
		}
		var m struct {
			Alert struct {
				RuleName string `json:"rule_name"`
				Command  string `json:"command"`
			} `json:"alert"`
			Session struct {
				Username  string `json:"username"`
				AssetName string `json:"asset_name"`
			} `json:"session"`
		}
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatal(err)
		}
		if m.Alert.RuleName != injRuleName || m.Alert.Command != injCommand || m.Session.Username != injUser || m.Session.AssetName != injAsset {
			t.Fatalf("webhook 欄位應為原值: %+v", m)
		}
	})

	t.Run("一般名稱的輸出不變", func(t *testing.T) {
		alert := model.CommandAlert{RuleName: "rm-root", Command: "rm -rf / && echo <x>\nls -l", Severity: model.AlertSeverityHigh,
			SessionID: 31, UserID: 3, AssetID: &asset, TriggeredAt: injectionTestTime, Kind: model.AlertKindRule}
		got := buildSlackText(model.NotificationChannelLanguageZhTW, alertEventCommandAlert, alert,
			alertSubjectNames{User: "alice_ops", Asset: "db-prod_01"})
		want := "🔴 *rm-root* · 高風險\n```\nrm -rf / &amp;&amp; echo &lt;x&gt;\nls -l\n```\n" +
			"使用者 alice_ops (#3) · 資產 db-prod_01 (#7) · 會話 #31 · <!date^1795132800^{date_num} {time_secs}|2026-11-20 00:00:00 UTC>"
		if got != want {
			t.Fatalf("一般名稱的輸出應與原本逐字相同:\n got=%q\nwant=%q", got, want)
		}
	})
}
