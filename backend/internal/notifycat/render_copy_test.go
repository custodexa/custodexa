package notifycat

import (
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func sampleValue(p ParamSpec) string {
	switch p.Kind {
	case KindEnum:
		return p.Enum[0]
	case KindInt:
		return "1"
	case KindDateList:
		return "2026-01-01"
	default:
		return "x"
	}
}

// minimalParams 只帶必要參數、決定 variant 的參數，以及該 variant 模板中不在可選段內的參數
// （variant 專屬參數）；其餘可選參數一律留空。
func minimalParams(spec EventSpec, variant string) map[string]string {
	return minimalParamsFor("", spec, variant)
}

func minimalParamsFor(ev Event, spec EventSpec, variant string) map[string]string {
	out := map[string]string{}
	for _, p := range spec.Params {
		if p.Required {
			out[p.Name] = sampleValue(p)
		}
	}
	base := strings.TrimSuffix(variant, linkedSuffix)
	if spec.VariantParam != "" {
		// 組合 variant「<值>_<鍵>」：前段是 VariantParam 的值，後段是 PresenceVariants 的鍵
		value := base
		for k := range spec.PresenceVariants {
			if strings.HasSuffix(base, "_"+k) {
				value = strings.TrimSuffix(base, "_"+k)
				base = k
			}
		}
		out[spec.VariantParam] = value
	}
	if param, ok := spec.PresenceVariants[base]; ok {
		if p, ok := spec.param(param); ok {
			out[param] = sampleValue(p)
		}
	}
	if ev != "" {
		if msg, ok := catalog[DefaultLang][ev][variant]; ok {
			for _, tmpl := range []string{msg.Title, msg.Text} {
				f := parseTemplate(tmpl)
				for name := range f.all {
					if f.optional[name] {
						continue
					}
					if p, ok := spec.param(name); ok && out[name] == "" {
						out[name] = sampleValue(p)
					}
				}
			}
		}
	}
	return out
}

// TestOptionalParamsLeaveNoEmptyQuotes 可選參數為空時，任何事件、任何 variant、三種語系的文字都沒有空引號或空括號。
func TestOptionalParamsLeaveNoEmptyQuotes(t *testing.T) {
	bad := []string{"「」", `""`, "“”", "（）", "()", "{", "}", "[", "]", "  ", " ,", "，，", "。。"}
	events := Events()
	sort.Slice(events, func(i, j int) bool { return events[i] < events[j] })
	checked := 0
	for _, ev := range events {
		spec, _ := Spec(ev)
		for _, variant := range spec.variants() {
			params := minimalParamsFor(ev, spec, variant)
			clean, err := Validate(ev, params)
			if err != nil {
				t.Fatalf("%s/%s 的最小參數驗證失敗: %v", ev, variant, err)
			}
			for _, lang := range SupportedLangs {
				title, text := RenderLinked(lang, ev, clean, strings.HasSuffix(variant, linkedSuffix))
				checked++
				for _, b := range bad {
					if strings.Contains(title, b) || strings.Contains(text, b) {
						t.Errorf("%s/%s/%s 出現 %q：title=%q text=%q", ev, variant, lang, b, title, text)
					}
				}
			}
		}
	}
	if checked < 100 {
		t.Fatalf("只檢查了 %d 則：事件或 variant 列舉失真", checked)
	}
}

// TestSystemAlertSeverityLabelOnce 系統安全告警的完整 Slack 文字中分級標籤只出現一次（第一行），句尾不再重複。
func TestSystemAlertSeverityLabelOnce(t *testing.T) {
	occurred := time.Date(2026, 11, 20, 7, 55, 25, 0, time.UTC)
	for ev, spec := range systemAlertEventSpecs() {
		for _, variant := range (EventSpec{Params: spec.Params, VariantParam: spec.VariantParam, PresenceVariants: spec.PresenceVariants}).variants() {
			params := minimalParamsFor(ev, spec, variant)
			params["severity"] = SeverityHigh
			clean, err := Validate(ev, params)
			if err != nil {
				t.Fatalf("%s/%s 驗證失敗: %v", ev, variant, err)
			}
			for _, lang := range []string{"zh-TW", "en-US"} {
				title, text := Render(lang, ev, clean)
				full := ComposeSlack(lang, SlackMessage{
					Prefix: SeveritySymbol(SeverityHigh), Title: title, Severity: SeverityHigh, Body: text,
					Extra:    Phrase(lang, LexiconAlertKindText, "system_security"),
					Occurred: occurred,
				})
				label := Phrase(lang, LexiconSeverity, SeverityHigh)
				if n := strings.Count(full, label); n != 1 {
					t.Errorf("%s/%s/%s 分級標籤 %q 出現 %d 次：%q", ev, variant, lang, label, n, full)
				}
			}
			_, ja := Render("ja-JP", ev, clean)
			if strings.Contains(ja, "レベル：") {
				t.Errorf("%s/%s/ja-JP 句尾仍帶分級：%q", ev, variant, ja)
			}
		}
	}
}

// TestAccessRequestReviewCenterHintOnlyWithoutLink 連線申請族：有連結時不寫「詳見審核中心」，沒有連結時寫。
func TestAccessRequestReviewCenterHintOnlyWithoutLink(t *testing.T) {
	hint := map[string]string{"zh-TW": "詳見審核中心", "en-US": "see the review center", "ja-JP": "審査センターをご確認ください"}
	family := []Event{EventAccessRequestCreated, EventAccessRequestApproved, EventAccessRequestApprovalProgress,
		EventAccessRequestRejected, EventBreakGlassUsed, EventTicketRevoked, EventBreakGlassReviewOverdue}
	for _, ev := range family {
		spec, _ := Spec(ev)
		if !spec.LinkedVariants {
			t.Fatalf("%s 沒有宣告有連結版本", ev)
		}
		params := minimalParams(spec, variantKeyFor(spec))
		for _, lang := range SupportedLangs {
			_, withLink := RenderLinked(lang, ev, params, true)
			_, noLink := RenderLinked(lang, ev, params, false)
			if strings.Contains(withLink, hint[lang]) {
				t.Errorf("%s/%s 有連結時仍寫「%s」：%q", ev, lang, hint[lang], withLink)
			}
			if !strings.Contains(noLink, hint[lang]) {
				t.Errorf("%s/%s 沒有連結時缺「%s」：%q", ev, lang, hint[lang], noLink)
			}
		}
	}
}

func variantKeyFor(spec EventSpec) string {
	return spec.variants()[0]
}

// TestOngoingFailureOmitsReportedAt 持續失效的文字不含回報時刻（最後一行已有發生時間）。
func TestOngoingFailureOmitsReportedAt(t *testing.T) {
	params := map[string]string{"mechanism": "syslog_forward", "cause_code": causeEnum[0], "reported_at": "2026-11-20T07:55:25Z"}
	for _, lang := range SupportedLangs {
		_, text := Render(lang, EventAuditFailureOngoing, params)
		if strings.Contains(text, "2026-11-20") || strings.Contains(text, "07:55") {
			t.Errorf("%s 持續失效文字仍含回報時刻：%q", lang, text)
		}
		if strings.Contains(text, "syslog_forward") {
			t.Errorf("%s 機制以機器碼呈現：%q", lang, text)
		}
	}
}

// TestTestNotificationCopy 測試通知：第一行（標題）表明是測試、不需處理，內文帶通道名稱，沒有 #0。
func TestTestNotificationCopy(t *testing.T) {
	want := map[string][]string{"zh-TW": {"測試", "不需處理"}, "en-US": {"test", "no action needed"}, "ja-JP": {"テスト", "対応不要"}}
	for _, lang := range SupportedLangs {
		title, text := Render(lang, EventTest, map[string]string{"product": "Custodexa", "channel_name": "ops-alerts"})
		for _, w := range want[lang] {
			if !strings.Contains(title, w) {
				t.Errorf("%s 測試通知標題缺 %q：%q", lang, w, title)
			}
		}
		if !strings.Contains(text, "ops-alerts") || strings.Contains(title+text, "#0") {
			t.Errorf("%s 測試通知內文不符：%q", lang, text)
		}
	}
}

// TestMultiAssetAndItemVariants 多台資產三語共用總數；逐項拒絕與撤銷指明那一項；角色定義變更不把角色名當受發放者。
func TestMultiAssetAndItemVariants(t *testing.T) {
	multi := map[string]string{"request_id": "7", "asset_name": "web-1", "asset_count": "3"}
	want := map[string]string{"zh-TW": "web-1 等 3 台", "en-US": "web-1 and others (3 assets)", "ja-JP": "web-1 ほか計 3 台"}
	for lang, w := range want {
		title, _ := Render(lang, EventAccessRequestCreated, multi)
		if !strings.Contains(title, w) {
			t.Errorf("%s 多台資產標題 %q 不含 %q", lang, title, w)
		}
	}
	item := map[string]string{"request_id": "7", "asset_name": "web-1", "item_asset_name": "db-9", "decider_name": "alice", "requester_name": "bob"}
	_, rejected := Render("zh-TW", EventAccessRequestRejected, item)
	if !strings.Contains(rejected, "db-9 這一項") || !strings.Contains(rejected, "alice") || !strings.Contains(rejected, "bob") {
		t.Errorf("逐項拒絕文字不符：%q", rejected)
	}
	_, revoked := Render("zh-TW", EventTicketRevoked, map[string]string{"request_id": "7", "item_asset_name": "db-9", "revoker_name": "carol"})
	if !strings.Contains(revoked, "在 db-9 的限時連線") || !strings.Contains(revoked, "carol") {
		t.Errorf("逐項撤銷文字不符：%q", revoked)
	}
	_, whole := Render("zh-TW", EventAccessRequestRejected, map[string]string{"request_id": "7", "decider_name": "alice"})
	if strings.Contains(whole, "這一項") {
		t.Errorf("整單拒絕不應用逐項句型：%q", whole)
	}
	roleDef := map[string]string{"actor": "admin", "severity": "high", "path": "role_definition", "role_name": "Auditor",
		"recipient": "Auditor", "other_holder_count": "4"}
	clean, err := Validate(EventSystemAlertManagementRoleGranted, roleDef)
	if err != nil {
		t.Fatal(err)
	}
	for _, lang := range SupportedLangs {
		_, text := Render(lang, EventSystemAlertManagementRoleGranted, clean)
		if !strings.Contains(text, "4") || strings.Count(text, "Auditor") != 1 {
			t.Errorf("%s 角色定義變更句型不符（角色名應只出現一次、帶受影響人數）：%q", lang, text)
		}
	}
}

// TestSlackFooter 最後一行：Slack 日期語法與 UTC 退回文字；有連結時附連結，沒有連結時不留語法或分隔符。
func TestSlackFooter(t *testing.T) {
	at := time.Date(2026, 11, 20, 15, 55, 25, 0, time.FixedZone("UTC+8", 8*3600))
	got := SlackFooter("zh-TW", at, "", LinkLabelAction)
	if got != "發生時間 <!date^1795161325^{date_num} {time_secs}|2026-11-20 07:55:25 UTC>" {
		t.Fatalf("沒有連結的最後一行 = %q", got)
	}
	got = SlackFooter("en-US", at, "https://h/sub/alerts", LinkLabelView)
	if !strings.HasSuffix(got, " UTC> · <https://h/sub/alerts|View in Custodexa>") {
		t.Fatalf("有連結的最後一行 = %q", got)
	}
}

// TestEnumParamsRenderAsPhrases 列舉值以通道語系的語句呈現（存取政策降級送到 ja-JP），文字中沒有原樣的機器碼；
// webhook 參數仍為原值。
func TestEnumParamsRenderAsPhrases(t *testing.T) {
	// 存取政策降級：段位用真實存在的值（open、reason、approval），降級方式與前後段位都以語句呈現
	params := map[string]string{"actor": "admin", "severity": "high", "relax_type": "override_cleared",
		"before_level": "approval", "after_level": "open", "asset_name": "web-1"}
	clean, err := Validate(EventSystemAlertAccessPolicyRelaxed, params)
	if err != nil {
		t.Fatal(err)
	}
	_, ja := Render("ja-JP", EventSystemAlertAccessPolicyRelaxed, clean)
	if strings.Contains(ja, "override_cleared") || !strings.Contains(ja, "この資産の個別設定を解除し、既定値に戻しました") {
		t.Fatalf("ja-JP 的降級方式不是語句：%q", ja)
	}
	if strings.Contains(ja, "approval") || strings.Contains(ja, "open") ||
		!strings.Contains(ja, "承認者の承認が必要") || !strings.Contains(ja, "申請不要") {
		t.Fatalf("ja-JP 的前後段位不是語句：%q", ja)
	}
	for lang, want := range map[string][]string{"zh-TW": {"需審核人核准", "不需申請"}, "en-US": {"approval required", "no request needed"}} {
		_, text := Render(lang, EventSystemAlertAccessPolicyRelaxed, clean)
		for _, w := range want {
			if !strings.Contains(text, w) {
				t.Fatalf("%s 的段位不是語句（應含 %q）：%q", lang, w, text)
			}
		}
	}
	wire := WireParams(EventSystemAlertAccessPolicyRelaxed, clean)
	if wire["relax_type"] != "override_cleared" || wire["before_level"] != "approval" || wire["after_level"] != "open" {
		t.Fatalf("webhook 參數應為原值，得 %v", wire)
	}
	_, mech := Render("en-US", EventAuditFailure, map[string]string{"mechanism": "notification_dispatch", "started_at": "T", "cause_code": "notification_dispatch_failed"})
	if strings.Contains(mech, "notification_dispatch") || !strings.Contains(mech, "Notification dispatch") {
		t.Fatalf("新機制與原因沒有以語句呈現：%q", mech)
	}
}

// TestFieldListParamsRenderAsPhrases 欄位清單逐項以語句呈現並以該語系的分隔符連接；webhook 維持原值。
func TestFieldListParamsRenderAsPhrases(t *testing.T) {
	cases := []struct {
		ev     Event
		params map[string]string
		key    string
		raw    []string
		want   map[string]string
	}{
		{EventSystemAlertAssetAddressChanged, map[string]string{"actor": "admin", "severity": "high", "changed_fields": "host,port", "asset_name": "web-1"},
			"changed_fields", []string{"host", "port"},
			map[string]string{"zh-TW": "主機位址、連接埠", "en-US": "host address, port", "ja-JP": "ホストアドレス、ポート"}},
		{EventSystemAlertNotificationChannelChanged, map[string]string{"actor": "admin", "severity": "high", "change": "updated", "changed_fields": "language,target", "channel_name": "ops"},
			"changed_fields", []string{"language", "target"},
			map[string]string{"zh-TW": "語系、目標頻道", "en-US": "language, target channel", "ja-JP": "言語、送信先チャンネル"}},
		{EventSystemAlertTransportVerificationRelaxed, map[string]string{"actor": "admin", "severity": "high", "relaxed_settings": "rdp_verify_cert,db_tls_mode", "asset_name": "db-1"},
			"relaxed_settings", []string{"rdp_verify_cert", "db_tls_mode"},
			map[string]string{"zh-TW": "RDP 憑證驗證、資料庫 TLS 模式", "en-US": "RDP certificate verification, database TLS mode", "ja-JP": "RDP 証明書の検証、データベース TLS モード"}},
		{EventSystemAlertIdentitySourceChanged, map[string]string{"actor": "admin", "severity": "high", "source_kind": "oidc", "changed_fields": "scopes,client_secret"},
			"changed_fields", []string{"scopes", "client_secret"},
			map[string]string{"zh-TW": "授權範圍、用戶端密鑰", "en-US": "scopes, client secret", "ja-JP": "スコープ、クライアントシークレット"}},
	}
	for _, tc := range cases {
		clean, err := Validate(tc.ev, tc.params)
		if err != nil {
			t.Fatalf("%s: %v", tc.ev, err)
		}
		for lang, want := range tc.want {
			_, text := Render(lang, tc.ev, clean)
			if !strings.Contains(text, want) {
				t.Fatalf("%s %s 應含 %q：%q", tc.ev, lang, want, text)
			}
			// 原樣的清單值（逗號相連）與含底線的欄位碼都不得出現；英文語句可能本來就含同一個英文單字
			if strings.Contains(text, tc.params[tc.key]) {
				t.Fatalf("%s %s 不得含原樣的清單值 %q：%q", tc.ev, lang, tc.params[tc.key], text)
			}
			for _, r := range tc.raw {
				if strings.Contains(r, "_") && strings.Contains(text, r) {
					t.Fatalf("%s %s 不得含機器碼 %q：%q", tc.ev, lang, r, text)
				}
			}
		}
		if wire := WireParams(tc.ev, clean); wire[tc.key] != tc.params[tc.key] {
			t.Fatalf("%s webhook 參數應為原值，得 %v", tc.ev, wire[tc.key])
		}
	}
}

// TestJaParticleNameSpacing ja-JP 模板中，假名助詞後面緊接名稱參數的可選段時要留一個空白
// （「申請が boss により」而不是「申請がboss により」）。
func TestJaParticleNameSpacing(t *testing.T) {
	bad := regexp.MustCompile(`[ぁ-んー]\[\{[a-z_]+_name\}`)
	for ev, variants := range catalog["ja-JP"] {
		for v, msg := range variants {
			for _, tmpl := range []string{msg.Title, msg.Text} {
				if m := bad.FindString(tmpl); m != "" {
					t.Errorf("%s/%s：助詞與名稱之間缺空白（%s）：%s", ev, v, m, tmpl)
				}
			}
		}
	}
	_, ja := Render("ja-JP", EventAccessRequestApproved, map[string]string{"request_id": "1", "mode": "manual", "requester_name": "alice", "decider_name": "bob"})
	if !strings.Contains(ja, "申請が bob により") {
		t.Fatalf("ja-JP 助詞與名稱之間應有空白: %s", ja)
	}
}
