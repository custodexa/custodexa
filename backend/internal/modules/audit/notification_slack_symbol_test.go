package audit

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// Slack 訊息的開頭符號契約：一則訊息只有一個符號，位於第一行最前面，且與該則通知的等級相符
// （高 🔴、中 🟠、低 🟡；測試通知 🔔）。內文、固定說明與最後一行都不放符號。
//
// 「符號」的判準涵蓋圖形 emoji 區段與 Slack 的 :shortcode: 寫法，兩種寫法都算一個符號。

var slackSymbolPattern = regexp.MustCompile(`[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{2B00}-\x{2BFF}\x{2300}-\x{23FF}]|:[a-z_][a-z0-9_+-]*:`)

var symbolTestTime = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)

// slackTextOf 取出 Slack 本文（webhook 與應用程式兩種型別都以 text 欄位承載文字）。
func slackTextOf(t *testing.T, body []byte) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("Slack 本文不是 JSON: %v (%s)", err, body)
	}
	s, ok := m["text"].(string)
	if !ok || s == "" {
		t.Fatalf("Slack 本文沒有 text: %s", body)
	}
	return s
}

// assertSingleLeadingSymbol 斷言全文恰好一個符號、位於第一行開頭，且為 want。
func assertSingleLeadingSymbol(t *testing.T, label, text, want string) {
	t.Helper()
	found := slackSymbolPattern.FindAllStringIndex(text, -1)
	if len(found) != 1 {
		t.Errorf("%s: 符號數 %d，應為 1\n%s", label, len(found), text)
		return
	}
	if found[0][0] != 0 {
		t.Errorf("%s: 符號不在第一行開頭\n%s", label, text)
		return
	}
	if got := text[found[0][0]:found[0][1]]; got != want {
		t.Errorf("%s: 開頭符號 %q，應為 %q\n%s", label, got, want, text)
	}
	if !strings.HasPrefix(text, want+" ") {
		t.Errorf("%s: 符號後應接一個空白再接標題\n%s", label, text)
	}
}

func symbolSampleValue(p notifycat.ParamSpec) string {
	switch p.Kind {
	case notifycat.KindEnum:
		return p.Enum[0]
	case notifycat.KindInt:
		return "1"
	case notifycat.KindDateList:
		return "2026-01-01"
	default:
		return "x"
	}
}

// symbolParamSets 每個事件的參數組：所有宣告參數都填上合法值；決定 variant 的參數逐一走過每個值。
func symbolParamSets(spec notifycat.EventSpec) []map[string]string {
	base := map[string]string{}
	var variantEnum []string
	for _, p := range spec.Params {
		base[p.Name] = symbolSampleValue(p)
		if p.Name == spec.VariantParam {
			variantEnum = p.Enum
		}
	}
	if len(variantEnum) == 0 {
		return []map[string]string{base}
	}
	out := make([]map[string]string, 0, len(variantEnum))
	for _, v := range variantEnum {
		m := map[string]string{}
		for k, val := range base {
			m[k] = val
		}
		m[spec.VariantParam] = v
		out = append(out, m)
	}
	return out
}

var slackTextTypes = []string{model.NotificationChannelTypeSlack, model.NotificationChannelTypeSlackApp}

// TestSlackLeadingSymbolSystemEvents 事件目錄中每一種事件、三種語系、兩種 Slack 型別（含個人訊息標題、
// 降級渲染）：開頭符號只有一個且依等級。沿用類型目錄分級的事件以三種有效分級各跑一次。
func TestSlackLeadingSymbolSystemEvents(t *testing.T) {
	events := notifycat.Events()
	sort.Slice(events, func(i, j int) bool { return events[i] < events[j] })
	dmKeys := notifycat.LexiconEntries(notifycat.DefaultLang, notifycat.LexiconDMTitle)
	dmKey := ""
	for k := range dmKeys {
		if dmKey == "" || k < dmKey {
			dmKey = k
		}
	}
	checked, validated := 0, 0
	for _, ev := range events {
		spec, _ := notifycat.Spec(ev)
		severities := []string{spec.Severity}
		if spec.Severity == notifycat.SeverityFromCatalog {
			severities = []string{model.AlertSeverityHigh, model.AlertSeverityMedium, model.AlertSeverityLow}
		}
		for _, sev := range severities {
			for _, params := range symbolParamSets(spec) {
				if _, err := notifycat.Validate(ev, params); err == nil {
					validated++
				}
				raw, _ := json.Marshal(params)
				for _, degraded := range []bool{false, true} {
					msg := model.NotificationMessage{ID: 1, Category: model.NotificationCategorySystemEvent,
						EventKey: string(ev), Severity: sev, OccurredAt: symbolTestTime, Params: string(raw),
						LinkPath: notifycat.LinkPath(ev, params), Degraded: degraded}
					for _, lang := range notifycat.SupportedLangs {
						for _, typ := range slackTextTypes {
							for _, dm := range []string{"", dmKey} {
								dest := ChannelDestination{Type: typ, URL: "https://example.invalid/x", Target: "C1", Language: lang}
								body, err := renderSystemEventBodyFor(msg, params, dest, "d", symbolTestTime, dm)
								if err != nil {
									t.Fatalf("%s/%s/%s: %v", ev, lang, typ, err)
								}
								label := fmt.Sprintf("%s sev=%s lang=%s type=%s degraded=%v dm=%q variant=%s",
									ev, sev, lang, typ, degraded, dm, params[spec.VariantParam])
								assertSingleLeadingSymbol(t, label, slackTextOf(t, body), notifycat.SeveritySymbol(sev))
								checked++
							}
						}
					}
				}
			}
		}
	}
	if validated == 0 || checked < len(events)*len(notifycat.SupportedLangs) {
		t.Fatalf("覆蓋不足：事件 %d、通過驗證的參數組 %d、檢查 %d 則", len(events), validated, checked)
	}
	t.Logf("系統事件：%d 種事件、%d 則 Slack 訊息", len(events), checked)
}

// TestSlackLeadingSymbolSystemAlertSnapshot 系統安全告警（帶快照紀錄的投遞路徑）：每一種告警類型、
// 三種分級、三種語系。
func TestSlackLeadingSymbolSystemAlertSnapshot(t *testing.T) {
	e := newNDLEnv(t)
	checked := 0
	for _, def := range SystemAlertCatalog() {
		params := sampleSystemAlertParams(def)
		params["actor"] = "alice"
		raw, _ := json.Marshal(params)
		for _, sev := range []string{model.AlertSeverityHigh, model.AlertSeverityMedium, model.AlertSeverityLow} {
			a := model.CommandAlert{RuleName: "sys", Severity: sev, TriggeredAt: symbolTestTime,
				Disposition: "pending", Kind: model.AlertKindSystemSecurity}
			if err := e.db.Create(&a).Error; err != nil {
				t.Fatal(err)
			}
			if err := e.db.Create(&model.SystemAlertDetail{AlertID: a.ID, AlertType: string(def.Type), Params: string(raw)}).Error; err != nil {
				t.Fatal(err)
			}
			id := a.ID
			for _, lang := range notifycat.SupportedLangs {
				for _, typ := range slackTextTypes {
					row := model.NotificationDelivery{AlertID: &id, Severity: sev, DestType: typ, DestLanguage: lang}
					dest := ChannelDestination{Type: typ, URL: "https://example.invalid/x", Target: "C1", Language: lang}
					body, err := e.w.renderSnapshot(row, dest)
					if err != nil {
						t.Fatalf("%s/%s: %v", def.Type, lang, err)
					}
					assertSingleLeadingSymbol(t, fmt.Sprintf("%s sev=%s lang=%s type=%s", def.Type, sev, lang, typ),
						slackTextOf(t, body), notifycat.SeveritySymbol(sev))
					checked++
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("沒有檢查到任何系統安全告警")
	}
	t.Logf("系統安全告警：%d 則 Slack 訊息", checked)
}

// TestSlackLeadingSymbolCommandAlertsAndTest 指令告警各類別（含輸出疑似敏感內容）三種分級、三種語系，
// 以及測試通知：開頭符號只有一個。
func TestSlackLeadingSymbolCommandAlertsAndTest(t *testing.T) {
	asset := uint(7)
	kinds := []struct {
		kind, reason, command string
	}{
		{model.AlertKindRule, "", "rm -rf / && echo <x>"},
		{model.AlertKindRule, OutputAlertPrefix + "3", "cat /etc/shadow"},
		{model.AlertKindNewSourceIP, "", ""},
		{model.AlertKindAuditDegraded, model.AlertReasonDegradedSpan, ""},
		{model.AlertKindSensitiveReveal, "", ""},
		{model.AlertKindAgentBreaker, "", ""},
	}
	for _, k := range kinds {
		for _, sev := range []string{model.AlertSeverityHigh, model.AlertSeverityMedium, model.AlertSeverityLow} {
			alert := model.CommandAlert{RuleName: "r", Command: k.command, Severity: sev, SessionID: 31, UserID: 3,
				AssetID: &asset, TriggeredAt: symbolTestTime, Kind: k.kind, ReasonCode: k.reason, Blocked: true}
			names := alertSubjectNames{User: "alice", Asset: "db", ClientIP: "203.0.113.7", DegradeReason: model.DegradeAltScreen}
			for _, lang := range notifycat.SupportedLangs {
				for _, typ := range slackTextTypes {
					ch := &model.NotificationChannel{Type: typ, URL: "https://example.invalid/x", Target: "C1", Language: lang}
					body, err := buildChannelBody(ch, alertEventCommandAlert, alert, names, nil)
					if err != nil {
						t.Fatal(err)
					}
					assertSingleLeadingSymbol(t, fmt.Sprintf("%s/%s sev=%s lang=%s type=%s", k.kind, k.reason, sev, lang, typ),
						slackTextOf(t, body), notifycat.SeveritySymbol(sev))
				}
			}
		}
	}
	for _, lang := range notifycat.SupportedLangs {
		text := buildTestSlackText(lang, "ops", symbolTestTime)
		assertSingleLeadingSymbol(t, "test/"+lang, text, notifycat.TestSymbol)
	}
}

// TestSeveritySymbolMapping 等級對照；未知或空值落中性符號，不留空字串。
func TestSeveritySymbolMapping(t *testing.T) {
	cases := map[string]string{
		model.AlertSeverityHigh: "🔴", model.AlertSeverityMedium: "🟠", model.AlertSeverityLow: "🟡",
		"": "⚪", "critical": "⚪",
	}
	for sev, want := range cases {
		if got := notifycat.SeveritySymbol(sev); got != want {
			t.Errorf("SeveritySymbol(%q)=%q，應為 %q", sev, got, want)
		}
		if got := severityEmoji(sev); got != want {
			t.Errorf("severityEmoji(%q)=%q，應為 %q", sev, got, want)
		}
	}
}
