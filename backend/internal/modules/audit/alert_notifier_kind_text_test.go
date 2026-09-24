package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 非規則類告警的 Slack 白話呈現。
//
// 三件事各有一組斷言：
//   - 規則類（含 kind 為空的舊列與測試通知）的 Slack 文字與改動前逐字相同；
//   - 全部類別的 webhook body 與改動前逐字相同（機器欄是收端契約）；
//   - 非規則類不再以機器碼當標題、不再輸出空的程式碼區塊。

var kindTextTS = time.Date(2026, 9, 24, 8, 14, 48, 0, time.UTC)

func kindTextNames() alertSubjectNames {
	return alertSubjectNames{User: "alice@example.com", Asset: "files-01", ClientIP: "203.0.113.42"}
}

// kindTextCases 與基準擷取時的輸入完全相同。
func kindTextCases() map[string]model.CommandAlert {
	asset := uint(6)
	ruleID := uint(1)
	ts := kindTextTS
	return map[string]model.CommandAlert{
		"rule":          {ID: 1, RuleID: &ruleID, Kind: model.AlertKindRule, RuleName: "rm & <x>", Command: "rm -rf / > /dev/null && echo <ok>", Severity: "high", SessionID: 19, UserID: 2, AssetID: &asset, TriggeredAt: ts},
		"rule_blocked":  {ID: 2, RuleID: &ruleID, Kind: model.AlertKindRule, RuleName: "block", Command: "shutdown -h now", Severity: "medium", Blocked: true, SessionID: 19, UserID: 2, TriggeredAt: ts},
		"rule_output":   {ID: 3, RuleID: &ruleID, Kind: model.AlertKindRule, RuleName: "out", ReasonCode: "o1:3", Command: "", Severity: "low", SessionID: 19, UserID: 2, AssetID: &asset, TriggeredAt: ts},
		"legacy_nokind": {ID: 4, RuleName: "legacy", Command: "ls", Severity: "", SessionID: 19, UserID: 2, TriggeredAt: ts},
		// kind 為空且指令為空的舊列：兩條版型在這裡輸出不同（舊版型有空區塊），
		// 用來釘住「kind 為空一律走規則類版型」這個分支
		"legacy_nokind_empty":  {ID: 8, RuleName: "legacy-empty", Command: "", Severity: "low", SessionID: 19, UserID: 2, TriggeredAt: ts},
		"legacy_nokind_output": {ID: 9, RuleName: "legacy-out", ReasonCode: "o1:2", Command: "", Severity: "medium", SessionID: 19, UserID: 2, TriggeredAt: ts},
		"degraded":             {ID: 5, Kind: model.AlertKindAuditDegraded, RuleName: model.AlertReasonDegradedSpan, ReasonCode: model.AlertReasonDegradedSpan, Severity: "medium", SessionID: 19, UserID: 2, AssetID: &asset, TriggeredAt: ts},
		"new_source_ip":        {ID: 6, Kind: model.AlertKindNewSourceIP, RuleName: model.AlertKindNewSourceIP, ReasonCode: model.AlertReasonNewSourceIPSession, Severity: "medium", SessionID: 19, UserID: 2, AssetID: &asset, TriggeredAt: ts},
		"sensitive":            {ID: 7, Kind: model.AlertKindSensitiveReveal, RuleName: model.AlertKindSensitiveReveal, ReasonCode: model.AlertKindSensitiveReveal, Severity: "medium", SessionID: 19, UserID: 2, AssetID: &asset, TriggeredAt: ts},
	}
}

var kindTextLangs = []string{
	model.NotificationChannelLanguageZhTW,
	model.NotificationChannelLanguageEnUS,
	model.NotificationChannelLanguageJaJP,
}

// 以下為改動前的實際輸出（逐字），規則類 Slack 與全部 webhook body 必須與之相同。
var baselineRuleSlack = []struct{ kase, lang, want string }{
	{"rule", "zh-TW", "🔴 *rm &amp; &lt;x&gt;* · 高風險\n```\nrm -rf / &gt; /dev/null &amp;&amp; echo &lt;ok&gt;\n```\n使用者 alice@example.com (#2) · 資產 files-01 (#6) · 會話 #19 · 2026-09-24T08:14:48Z"},
	{"rule", "en-US", "🔴 *rm &amp; &lt;x&gt;* · High\n```\nrm -rf / &gt; /dev/null &amp;&amp; echo &lt;ok&gt;\n```\nuser alice@example.com (#2) · asset files-01 (#6) · session #19 · 2026-09-24T08:14:48Z"},
	{"rule", "ja-JP", "🔴 *rm &amp; &lt;x&gt;* · 高\n```\nrm -rf / &gt; /dev/null &amp;&amp; echo &lt;ok&gt;\n```\nユーザー alice@example.com (#2) · 資産 files-01 (#6) · セッション #19 · 2026-09-24T08:14:48Z"},
	{"rule_blocked", "zh-TW", "🟠 *block* · 中風險 · 已阻斷\n```\nshutdown -h now\n```\n使用者 alice@example.com (#2) · 會話 #19 · 2026-09-24T08:14:48Z"},
	{"rule_blocked", "en-US", "🟠 *block* · Medium · Blocked\n```\nshutdown -h now\n```\nuser alice@example.com (#2) · session #19 · 2026-09-24T08:14:48Z"},
	{"rule_blocked", "ja-JP", "🟠 *block* · 中 · ブロック済み\n```\nshutdown -h now\n```\nユーザー alice@example.com (#2) · セッション #19 · 2026-09-24T08:14:48Z"},
	{"rule_output", "zh-TW", "🟡 *out* · 低風險\n輸出可能含敏感資料 (3)\n使用者 alice@example.com (#2) · 資產 files-01 (#6) · 會話 #19 · 2026-09-24T08:14:48Z"},
	{"rule_output", "en-US", "🟡 *out* · Low\nOutput may contain sensitive data (3)\nuser alice@example.com (#2) · asset files-01 (#6) · session #19 · 2026-09-24T08:14:48Z"},
	{"rule_output", "ja-JP", "🟡 *out* · 低\n出力に機密情報が含まれる可能性 (3)\nユーザー alice@example.com (#2) · 資産 files-01 (#6) · セッション #19 · 2026-09-24T08:14:48Z"},
	{"legacy_nokind", "zh-TW", "⚪ *legacy* · \n```\nls\n```\n使用者 alice@example.com (#2) · 會話 #19 · 2026-09-24T08:14:48Z"},
	{"legacy_nokind", "en-US", "⚪ *legacy* · \n```\nls\n```\nuser alice@example.com (#2) · session #19 · 2026-09-24T08:14:48Z"},
	{"legacy_nokind", "ja-JP", "⚪ *legacy* · \n```\nls\n```\nユーザー alice@example.com (#2) · セッション #19 · 2026-09-24T08:14:48Z"},
	{"legacy_nokind_empty", "zh-TW", "🟡 *legacy-empty* · 低風險\n```\n\n```\n使用者 alice@example.com (#2) · 會話 #19 · 2026-09-24T08:14:48Z"},
	{"legacy_nokind_empty", "en-US", "🟡 *legacy-empty* · Low\n```\n\n```\nuser alice@example.com (#2) · session #19 · 2026-09-24T08:14:48Z"},
	{"legacy_nokind_empty", "ja-JP", "🟡 *legacy-empty* · 低\n```\n\n```\nユーザー alice@example.com (#2) · セッション #19 · 2026-09-24T08:14:48Z"},
	{"legacy_nokind_output", "zh-TW", "🟠 *legacy-out* · 中風險\n輸出可能含敏感資料 (2)\n使用者 alice@example.com (#2) · 會話 #19 · 2026-09-24T08:14:48Z"},
	{"legacy_nokind_output", "en-US", "🟠 *legacy-out* · Medium\nOutput may contain sensitive data (2)\nuser alice@example.com (#2) · session #19 · 2026-09-24T08:14:48Z"},
	{"legacy_nokind_output", "ja-JP", "🟠 *legacy-out* · 中\n出力に機密情報が含まれる可能性 (2)\nユーザー alice@example.com (#2) · セッション #19 · 2026-09-24T08:14:48Z"},
	{"test", "zh-TW", "🔔 *Custodexa 測試通知*\n這是一則測試通知，用於驗證通知通道設定是否正確。\n```\necho x\n```\n使用者 #0 · 會話 #0 · 2026-09-24T08:14:48Z"},
	{"test", "en-US", "🔔 *Custodexa test notification*\nThis is a test notification used to verify that the channel is configured correctly.\n```\necho x\n```\nuser #0 · session #0 · 2026-09-24T08:14:48Z"},
	{"test", "ja-JP", "🔔 *Custodexa テスト通知*\nこれは通知チャネルの設定が正しいか確認するためのテスト通知です。\n```\necho x\n```\nユーザー #0 · セッション #0 · 2026-09-24T08:14:48Z"},
}

var baselineWebhook = map[string]string{
	"rule":                 `{"event":"command_alert","alert":{"id":1,"command":"rm -rf / \u003e /dev/null \u0026\u0026 echo \u003cok\u003e","severity":"high","rule_name":"rm \u0026 \u003cx\u003e","kind":"rule","blocked":false,"triggered_at":"2026-09-24T08:14:48Z"},"session":{"id":19,"user_id":2,"asset_id":6,"username":"alice@example.com","asset_name":"files-01","client_ip":"203.0.113.42"}}`,
	"rule_blocked":         `{"event":"command_alert","alert":{"id":2,"command":"shutdown -h now","severity":"medium","rule_name":"block","kind":"rule","blocked":true,"triggered_at":"2026-09-24T08:14:48Z"},"session":{"id":19,"user_id":2,"asset_id":null,"username":"alice@example.com","asset_name":"files-01","client_ip":"203.0.113.42"}}`,
	"rule_output":          `{"event":"command_alert","alert":{"possible_sensitive_output":{"count":3},"id":3,"command":"","severity":"low","rule_name":"out","kind":"rule","reason_code":"o1:3","blocked":false,"triggered_at":"2026-09-24T08:14:48Z"},"session":{"id":19,"user_id":2,"asset_id":6,"username":"alice@example.com","asset_name":"files-01","client_ip":"203.0.113.42"}}`,
	"legacy_nokind":        `{"event":"command_alert","alert":{"id":4,"command":"ls","severity":"","rule_name":"legacy","kind":"","blocked":false,"triggered_at":"2026-09-24T08:14:48Z"},"session":{"id":19,"user_id":2,"asset_id":null,"username":"alice@example.com","asset_name":"files-01","client_ip":"203.0.113.42"}}`,
	"legacy_nokind_empty":  `{"event":"command_alert","alert":{"id":8,"command":"","severity":"low","rule_name":"legacy-empty","kind":"","blocked":false,"triggered_at":"2026-09-24T08:14:48Z"},"session":{"id":19,"user_id":2,"asset_id":null,"username":"alice@example.com","asset_name":"files-01","client_ip":"203.0.113.42"}}`,
	"legacy_nokind_output": `{"event":"command_alert","alert":{"possible_sensitive_output":{"count":2},"id":9,"command":"","severity":"medium","rule_name":"legacy-out","kind":"","reason_code":"o1:2","blocked":false,"triggered_at":"2026-09-24T08:14:48Z"},"session":{"id":19,"user_id":2,"asset_id":null,"username":"alice@example.com","asset_name":"files-01","client_ip":"203.0.113.42"}}`,
	"degraded":             `{"event":"command_alert","alert":{"id":5,"command":"","severity":"medium","rule_name":"audit_degraded_span","kind":"audit_degraded","reason_code":"audit_degraded_span","blocked":false,"triggered_at":"2026-09-24T08:14:48Z"},"session":{"id":19,"user_id":2,"asset_id":6,"username":"alice@example.com","asset_name":"files-01","client_ip":"203.0.113.42"}}`,
	"new_source_ip":        `{"event":"command_alert","alert":{"id":6,"command":"","severity":"medium","rule_name":"new_source_ip","kind":"new_source_ip","reason_code":"new_source_ip_session","blocked":false,"triggered_at":"2026-09-24T08:14:48Z"},"session":{"id":19,"user_id":2,"asset_id":6,"username":"alice@example.com","asset_name":"files-01","client_ip":"203.0.113.42"}}`,
	"sensitive":            `{"event":"command_alert","alert":{"id":7,"command":"","severity":"medium","rule_name":"sensitive_reveal","kind":"sensitive_reveal","reason_code":"sensitive_reveal","blocked":false,"triggered_at":"2026-09-24T08:14:48Z"},"session":{"id":19,"user_id":2,"asset_id":6,"username":"alice@example.com","asset_name":"files-01","client_ip":"203.0.113.42"}}`,
}

func TestRuleKindSlackTextUnchanged(t *testing.T) {
	cases := kindTextCases()
	for _, c := range baselineRuleSlack {
		var got string
		if c.kase == "test" {
			got = buildSlackText(c.lang, alertEventTest, model.CommandAlert{
				Command: "echo x", Severity: "low", RuleName: "test", TriggeredAt: kindTextTS,
			}, alertSubjectNames{})
		} else {
			got = buildSlackText(c.lang, alertEventCommandAlert, cases[c.kase], kindTextNames())
		}
		assert.Equal(t, c.want, got, "%s/%s 的 Slack 文字與改動前不同", c.kase, c.lang)
	}
}

func TestWebhookBodyUnchangedForAllKinds(t *testing.T) {
	names := kindTextNames()
	// 降級原因只供 Slack 說明行使用，即使解析到了也不得出現在 webhook body
	names.DegradeReason = model.DegradeAltScreen
	ch := &model.NotificationChannel{Type: model.NotificationChannelTypeWebhook, Language: model.NotificationChannelLanguageZhTW}
	for kase, alert := range kindTextCases() {
		body, err := buildChannelBody(ch, alertEventCommandAlert, alert, names)
		require.NoError(t, err)
		assert.Equal(t, baselineWebhook[kase], string(body), "%s 的 webhook body 與改動前不同", kase)
	}
}

// TestDegradedSlackTextPlainLanguage 降級告警在三語下
// 都要有白話標題、指向錄影、沒有機器碼標題與空的程式碼區塊。
func TestDegradedSlackTextPlainLanguage(t *testing.T) {
	alert := kindTextCases()["degraded"]

	t.Run("繁中全文快照（含降級原因）", func(t *testing.T) {
		names := kindTextNames()
		names.DegradeReason = model.DegradeAltScreen
		got := buildSlackText(model.NotificationChannelLanguageZhTW, alertEventCommandAlert, alert, names)
		want := "🟠 *無法還原指令內容* · 中風險\n" +
			"這段輸入無法可靠還原成指令文字。實際內容請查看該會話的錄影。\n" +
			"當時畫面在全螢幕程式中（例如編輯器、分頁器）。\n" +
			"使用者 alice@example.com (#2) · 資產 files-01 (#6) · 會話 #19 · 2026-09-24T08:14:48Z"
		assert.Equal(t, want, got)
	})

	t.Run("取不到降級原因就不帶那一行", func(t *testing.T) {
		got := buildSlackText(model.NotificationChannelLanguageZhTW, alertEventCommandAlert, alert, kindTextNames())
		want := "🟠 *無法還原指令內容* · 中風險\n" +
			"這段輸入無法可靠還原成指令文字。實際內容請查看該會話的錄影。\n" +
			"使用者 alice@example.com (#2) · 資產 files-01 (#6) · 會話 #19 · 2026-09-24T08:14:48Z"
		assert.Equal(t, want, got)
	})

	t.Run("未收錄的原因碼不以機器碼代替", func(t *testing.T) {
		names := kindTextNames()
		names.DegradeReason = "some_future_reason"
		got := buildSlackText(model.NotificationChannelLanguageEnUS, alertEventCommandAlert, alert, names)
		assert.NotContains(t, got, "some_future_reason")
		assert.Equal(t, 3, strings.Count(got, "\n")+1, "應只有標題、說明、脈絡三行：%q", got)
	})

	for _, lang := range kindTextLangs {
		t.Run("三語共通："+lang, func(t *testing.T) {
			names := kindTextNames()
			names.DegradeReason = model.DegradeNoEcho
			got := buildSlackText(lang, alertEventCommandAlert, alert, names)
			assert.NotContains(t, got, "```", "不得輸出程式碼區塊")
			assert.NotContains(t, got, model.AlertReasonDegradedSpan, "標題不得是機器碼")
			assert.NotContains(t, got, model.AlertKindAuditDegraded)
			assert.NotContains(t, got, model.DegradeNoEcho)
			assert.True(t, strings.HasPrefix(got, "🟠 *"), "等級維持 medium：%q", got)
		})
	}

	t.Run("英日文措辭", func(t *testing.T) {
		en := buildSlackText(model.NotificationChannelLanguageEnUS, alertEventCommandAlert, alert, kindTextNames())
		assert.Contains(t, en, "*Command could not be reconstructed* · Medium")
		assert.Contains(t, en, "session recording")
		ja := buildSlackText(model.NotificationChannelLanguageJaJP, alertEventCommandAlert, alert, kindTextNames())
		assert.Contains(t, ja, "*コマンド内容を復元できません* · 中")
		assert.Contains(t, ja, "録画")
	})
}

func TestOtherNonRuleKindsSlackTextPlainLanguage(t *testing.T) {
	cases := kindTextCases()

	t.Run("新來源位址：白話標題＋位址", func(t *testing.T) {
		got := buildSlackText(model.NotificationChannelLanguageZhTW, alertEventCommandAlert, cases["new_source_ip"], kindTextNames())
		want := "🟠 *帳號自新的來源位址連線* · 中風險\n" +
			"這個帳號首次自這個位址建立連線。如需確認，請以這個位址查看當日的紀錄。\n" +
			"來源位址 203.0.113.42\n" +
			"使用者 alice@example.com (#2) · 資產 files-01 (#6) · 會話 #19 · 2026-09-24T08:14:48Z"
		assert.Equal(t, want, got)

		noIP := kindTextNames()
		noIP.ClientIP = ""
		got = buildSlackText(model.NotificationChannelLanguageZhTW, alertEventCommandAlert, cases["new_source_ip"], noIP)
		assert.NotContains(t, got, "來源位址 ", "查不到位址時不帶位址行")
	})

	t.Run("敏感原文調閱：白話標題＋去處", func(t *testing.T) {
		got := buildSlackText(model.NotificationChannelLanguageZhTW, alertEventCommandAlert, cases["sensitive"], kindTextNames())
		want := "🟠 *有人調閱了敏感原文* · 中風險\n" +
			"詳情請查看該筆調閱的稽核紀錄。\n" +
			"使用者 alice@example.com (#2) · 資產 files-01 (#6) · 會話 #19 · 2026-09-24T08:14:48Z"
		assert.Equal(t, want, got)
	})

	t.Run("說明行三語都指出去處", func(t *testing.T) {
		where := map[string][]string{
			model.NotificationChannelLanguageZhTW: {"查看當日的紀錄", "稽核紀錄"},
			model.NotificationChannelLanguageEnUS: {"review that day's records", "audit record"},
			model.NotificationChannelLanguageJaJP: {"当日の記録を確認", "監査記録を確認"},
		}
		for lang, markers := range where {
			assert.Contains(t, buildSlackText(lang, alertEventCommandAlert, cases["new_source_ip"], kindTextNames()), markers[0], lang)
			assert.Contains(t, buildSlackText(lang, alertEventCommandAlert, cases["sensitive"], kindTextNames()), markers[1], lang)
		}
	})

	for _, kase := range []string{"new_source_ip", "sensitive"} {
		for _, lang := range kindTextLangs {
			got := buildSlackText(lang, alertEventCommandAlert, cases[kase], kindTextNames())
			assert.NotContains(t, got, "```", "%s/%s 不得輸出程式碼區塊", kase, lang)
			assert.NotContains(t, got, "*"+cases[kase].RuleName+"*", "%s/%s 標題不得是機器碼", kase, lang)
		}
	}

	t.Run("尚未收錄的非規則類別：退回原標題但仍不出空區塊", func(t *testing.T) {
		alert := cases["degraded"]
		alert.Kind = "some_future_kind"
		alert.RuleName = "some_future_kind"
		got := buildSlackText(model.NotificationChannelLanguageZhTW, alertEventCommandAlert, alert, kindTextNames())
		assert.True(t, strings.HasPrefix(got, "🟠 *some_future_kind* · 中風險\n"), got)
		assert.NotContains(t, got, "```")
	})
}

func TestLookupDegradeReason(t *testing.T) {
	db := setupTimelineDB(t)
	ts := kindTextTS
	insert := func(sessionID uint, at time.Time, degraded bool, reason string) {
		t.Helper()
		require.NoError(t, db.Exec(`INSERT INTO session_commands
			(session_id, user_id, command, seq, executed_at, degraded, degrade_reason)
			VALUES (?, 2, '', 1, ?, ?, ?)`, sessionID, at, degraded, reason).Error)
	}
	insert(19, ts.Add(-time.Minute), true, model.DegradeRedrawUnanchored) // 同會話、較早的另一段
	insert(19, ts, true, model.DegradeAltScreen)                          // 開啟本段的那一輪
	insert(19, ts, true, model.DegradeQueueDiscarded)                     // 同一時刻的後續列
	insert(20, ts, false, "")                                             // 別的會話、非降級

	alert := kindTextCases()["degraded"]
	assert.Equal(t, model.DegradeAltScreen, lookupDegradeReason(db, alert), "取開啟本段那一輪（同時刻最早寫入者）")

	other := alert
	other.TriggeredAt = ts.Add(time.Hour)
	assert.Equal(t, "", lookupDegradeReason(db, other), "時刻對不上時不猜")

	notDegraded := kindTextCases()["new_source_ip"]
	assert.Equal(t, "", lookupDegradeReason(db, notDegraded), "非降級類不查")

	noSession := alert
	noSession.SessionID = 0
	assert.Equal(t, "", lookupDegradeReason(db, noSession))
	assert.Equal(t, "", lookupDegradeReason(nil, alert))
}

// TestNotifyDegradedAlertToSlackEndToEnd 經 worker 同一路徑（解析主體與降級原因）
// 實際投遞到 Slack 型收端，檢查收端拿到的文字。
func TestNotifyDegradedAlertToSlackEndToEnd(t *testing.T) {
	db := setupTimelineDB(t)
	require.NoError(t, db.Exec(`INSERT INTO session_commands
		(session_id, user_id, command, seq, executed_at, degraded, degrade_reason)
		VALUES (19, 2, '', 1, ?, 1, ?)`, kindTextTS, model.DegradeAltScreen).Error)

	url, received := captureOne(t)
	n := NewAlertNotifier(db, nil)
	n.backoff = []time.Duration{time.Millisecond}
	n.setChannels([]model.NotificationChannel{
		{ID: 1, Name: "ops", Type: model.NotificationChannelTypeSlack, URL: url, Enabled: true,
			Language: model.NotificationChannelLanguageZhTW},
	})
	n.notify(kindTextCases()["degraded"])

	var payload map[string]string
	require.NoError(t, json.Unmarshal(awaitBody(t, received), &payload))
	text := payload["text"]
	assert.Contains(t, text, "*無法還原指令內容* · 中風險")
	assert.Contains(t, text, "當時畫面在全螢幕程式中")
	assert.NotContains(t, text, "```")
	assert.NotContains(t, text, model.AlertReasonDegradedSpan)
}
