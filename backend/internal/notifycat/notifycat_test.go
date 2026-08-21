package notifycat

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
)

func TestSanitizeOpaque(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"純文字原樣", "web-prod-01", "web-prod-01"},
		{"中日文不受傷", "生產資料庫・本番", "生產資料庫・本番"},
		{"換行改空白", "a\nb\r\nc", "a b c"},
		{"tab 改空白", "a\tb", "a b"},
		{"CSI 序列整段移除", "\x1b[31mred\x1b[0m", "red"},
		{"OSC 序列吃到 BEL", "\x1b]0;title\x07ok", "ok"},
		{"OSC 序列吃到 ST", "\x1b]8;;http://evil\x1b\\ok", "ok"},
		{"兩字元序列", "\x1bcreset", "reset"},
		{"尾端孤兒 ESC", "abc\x1b", "abc"},
		{"其餘控制字元移除", "a\x00b\x07c\x7f", "abc"},
		{"C1 控制字元移除", "a\u0085b", "ab"},
		{"空字串", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeOpaque(tc.in); got != tc.want {
				t.Fatalf("SanitizeOpaque(%q) = %q，預期 %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeOpaqueTruncation(t *testing.T) {
	// 128 rune 以內不動
	exact := strings.Repeat("漢", MaxOpaqueRunes)
	if got := SanitizeOpaque(exact); got != exact {
		t.Fatalf("剛好 %d rune 不應截斷", MaxOpaqueRunes)
	}
	// 超限：截斷至 128 rune 且尾附省略號（rune 計數，非 byte）
	long := strings.Repeat("漢", MaxOpaqueRunes+50)
	got := SanitizeOpaque(long)
	if n := utf8.RuneCountInString(got); n != MaxOpaqueRunes {
		t.Fatalf("截斷後應為 %d rune，實得 %d", MaxOpaqueRunes, n)
	}
	if !strings.HasSuffix(got, truncationMark) {
		t.Fatalf("截斷後應附截斷標記，實得 %q", got)
	}
	// 冪等
	if again := SanitizeOpaque(got); again != got {
		t.Fatalf("SanitizeOpaque 非冪等: %q -> %q", got, again)
	}
}

func TestValidateHappyPath(t *testing.T) {
	out, err := Validate(EventBreakGlassUsed, map[string]string{
		"request_id":       "42",
		"asset_name":       "web\n-prod",
		"username":         "alice",
		"duration_minutes": "30",
	})
	if err != nil {
		t.Fatalf("預期通過，實得: %v", err)
	}
	if out["asset_name"] != "web -prod" {
		t.Fatalf("opaque 值應已淨化，實得 %q", out["asset_name"])
	}
	if out["duration_minutes"] != "30" {
		t.Fatalf("int 值應原樣保留，實得 %q", out["duration_minutes"])
	}
}

func TestValidateRejections(t *testing.T) {
	cases := []struct {
		name   string
		event  Event
		params map[string]string
		reason string
	}{
		{"未宣告鍵", EventTicketRevoked,
			map[string]string{"request_id": "1", "reason_text": "全文事由"}, ReasonUnknownParam},
		{"缺必要鍵", EventDailyReviewOverdue,
			map[string]string{}, ReasonMissingRequired},
		{"enum 值域外", EventAuditFailure,
			map[string]string{"mechanism": "not_a_mechanism", "started_at": "t", "cause": "c"},
			ReasonEnumOutOfRange},
		{"int 非數字", EventAccessRequestApprovalProgress,
			map[string]string{"request_id": "1", "votes": "一", "required": "2"},
			ReasonNotAnInteger},
		{"opaque 全為控制字元視同缺值", EventDailyReviewOverdue,
			map[string]string{"date": "\x00\x07"}, ReasonMissingRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(tc.event, tc.params)
			if err == nil {
				t.Fatal("預期拒絕，實得通過")
			}
			var errs ParamErrors
			if !errors.As(err, &errs) {
				t.Fatalf("預期 ParamErrors，實得 %T: %v", err, err)
			}
			found := false
			for _, e := range errs {
				if e.Reason == tc.reason {
					found = true
				}
			}
			if !found {
				t.Fatalf("預期原因 %s，實得 %v", tc.reason, err)
			}
		})
	}
}

func TestValidateUnregisteredEvent(t *testing.T) {
	_, err := Validate("totally.unknown", map[string]string{"a": "b"})
	if err == nil {
		t.Fatal("未註冊事件應回錯誤（供呼叫端降級）")
	}
	if !errors.Is(err, ErrUnregisteredEvent) {
		t.Fatalf("應可 errors.Is 到 ErrUnregisteredEvent，實得 %v", err)
	}
	var ue *UnregisteredEventError
	if !errors.As(err, &ue) || ue.Event != "totally.unknown" {
		t.Fatalf("錯誤應攜帶事件識別字，實得 %v", err)
	}
}

func TestValidateDoesNotMutateInput(t *testing.T) {
	in := map[string]string{"date": "2026-07-31\n"}
	if _, err := Validate(EventDailyReviewOverdue, in); err != nil {
		t.Fatalf("預期通過: %v", err)
	}
	if in["date"] != "2026-07-31\n" {
		t.Fatalf("Validate 不得改動呼叫端 map，實得 %q", in["date"])
	}
}

func TestRenderThreeLanguages(t *testing.T) {
	params := map[string]string{"request_id": "7", "asset_name": "web-prod", "votes": "1", "required": "3"}
	cases := []struct {
		lang      string
		wantTitle string
		wantText  string
	}{
		{"zh-TW", "連線申請 #7：web-prod", "已核准 1/3，待其他審核人員補足（詳見審核中心）"},
		{"en-US", "Access request #7: web-prod",
			"Approved 1/3; waiting for the remaining approvers (see the review center)."},
		{"ja-JP", "接続申請 #7：web-prod",
			"承認 1/3 件。残りの承認者の対応待ちです（審査センターをご確認ください）。"},
	}
	for _, tc := range cases {
		t.Run(tc.lang, func(t *testing.T) {
			title, text := Render(tc.lang, EventAccessRequestApprovalProgress, params)
			if title != tc.wantTitle {
				t.Fatalf("title = %q，預期 %q", title, tc.wantTitle)
			}
			if text != tc.wantText {
				t.Fatalf("text = %q，預期 %q", text, tc.wantText)
			}
		})
	}
}

func TestRenderUnknownLangFallsBackToDefault(t *testing.T) {
	params := map[string]string{"date": "2026-07-31"}
	wantTitle, wantText := Render(DefaultLang, EventDailyReviewOverdue, params)
	for _, lang := range []string{"", "fr-FR", "zh-CN"} {
		title, text := Render(lang, EventDailyReviewOverdue, params)
		if title != wantTitle || text != wantText {
			t.Fatalf("語系 %q 應 fallback %s，實得 (%q, %q)", lang, DefaultLang, title, text)
		}
	}
}

func TestRenderOptionalSegment(t *testing.T) {
	// 資產名查得到：分隔符與名字都在
	title, _ := Render("zh-TW", EventTicketRevoked,
		map[string]string{"request_id": "9", "asset_name": "db-01"})
	if title != "連線申請 #9：db-01" {
		t.Fatalf("實得 %q", title)
	}
	// 資產名查不到（assetName() 於資產列不存在時回空字串）：整段連分隔符一併略過
	title, _ = Render("zh-TW", EventTicketRevoked, map[string]string{"request_id": "9"})
	if title != "連線申請 #9" {
		t.Fatalf("空 asset_name 應略過可選段，實得 %q", title)
	}
	title, _ = Render("en-US", EventTicketRevoked,
		map[string]string{"request_id": "9", "asset_name": ""})
	if title != "Access request #9" {
		t.Fatalf("空字串應等同缺值，實得 %q", title)
	}
}

func TestRenderVariants(t *testing.T) {
	base := map[string]string{"request_id": "3", "asset_name": "a"}
	auto := map[string]string{"request_id": "3", "asset_name": "a", "mode": ApprovalModeAuto}
	manual := map[string]string{"request_id": "3", "asset_name": "a", "mode": ApprovalModeManual}

	_, autoText := Render("zh-TW", EventAccessRequestApproved, auto)
	_, manualText := Render("zh-TW", EventAccessRequestApproved, manual)
	if autoText == manualText {
		t.Fatal("auto 與 manual variant 文案不應相同")
	}
	if !strings.Contains(autoText, "自動核准") {
		t.Fatalf("auto variant 文案異常: %q", autoText)
	}

	// variant 值缺失 → 目錄無 default 鍵 → 降級渲染，絕不回空字串。
	// 降級標題自 M4 起是語系化的 generic 文案，event 識別字改由內文承載
	title, text := Render("zh-TW", EventAccessRequestApproved, base)
	if title == "" || !strings.Contains(text, string(EventAccessRequestApproved)) {
		t.Fatalf("缺 variant 應降級渲染且帶 event 識別字，實得 (%q, %q)", title, text)
	}

	// audit_failure_resolved 的區間雙模板
	known := map[string]string{"mechanism": model.MechanismAuditWrite,
		"interval": IntervalKnown, "started_at": "T1", "ended_at": "T2"}
	unknown := map[string]string{"mechanism": model.MechanismAuditWrite, "interval": IntervalUnknown}
	_, knownText := Render("zh-TW", EventAuditFailureResolved, known)
	_, unknownText := Render("zh-TW", EventAuditFailureResolved, unknown)
	if !strings.Contains(knownText, "T1") || !strings.Contains(knownText, "T2") {
		t.Fatalf("known variant 應帶起訖: %q", knownText)
	}
	if strings.Contains(unknownText, "T1") || !strings.Contains(unknownText, "起點不明") {
		t.Fatalf("unknown variant 文案異常: %q", unknownText)
	}
}

func TestRenderEscapesOpaqueValuesOnly(t *testing.T) {
	_, text := Render("zh-TW", EventBreakGlassUsed, map[string]string{
		"request_id": "1", "asset_name": "a",
		"username": "a<b>&c", "duration_minutes": "5",
	})
	if !strings.Contains(text, "a&lt;b&gt;&amp;c") {
		t.Fatalf("opaque 值應經 Slack mrkdwn 轉義，實得 %q", text)
	}
	// 模板本體的全形括號等文案字元不受影響
	if !strings.Contains(text, "（5 分鐘）") {
		t.Fatalf("模板本體不應被轉義，實得 %q", text)
	}
}

func TestRenderSanitizesEvenWithoutValidate(t *testing.T) {
	_, text := Render("zh-TW", EventAuditFailureOngoing, map[string]string{
		"mechanism":   model.MechanismKEKRetirement,
		"cause":       "boom\x1b[31m\ninjected",
		"reported_at": "2026-07-31T00:00:00Z",
	})
	if strings.ContainsRune(text, 0x1b) || strings.ContainsRune(text, '\n') {
		t.Fatalf("未經 Validate 的 opaque 值仍須淨化，實得 %q", text)
	}
}

// TestRenderDegradedIsLocalised 降級文案走通道語系（codex 批 2 M4）：
// 標題與骨幹取自 LexiconDegraded，event 識別字以 {event} 插入。
func TestRenderDegradedIsLocalised(t *testing.T) {
	for _, lang := range SupportedLangs {
		title, text := RenderDegraded(lang, "some.new.event", nil)
		if title != lexiconCat[lang][LexiconDegraded][DegradedKeyTitle] {
			t.Fatalf("語系 %s 降級標題應取自詞庫，實得 %q", lang, title)
		}
		if !strings.Contains(text, "some.new.event") {
			t.Fatalf("語系 %s 降級內文須帶 event 識別字，實得 %q", lang, text)
		}
	}
	// 三語文案必須互異（否則等同沒有語系化）
	_, zh := RenderDegraded("zh-TW", "some.new.event", nil)
	_, en := RenderDegraded("en-US", "some.new.event", nil)
	_, ja := RenderDegraded("ja-JP", "some.new.event", nil)
	if zh == en || en == ja || zh == ja {
		t.Fatalf("三語降級文案不應相同: %q / %q / %q", zh, en, ja)
	}
	// 未支援語系落 DefaultLang
	if _, de := RenderDegraded("de-DE", "some.new.event", nil); de != zh {
		t.Fatalf("未支援語系應 fallback %s，實得 %q", DefaultLang, de)
	}
}

// TestRenderDegradedDropsUndeclaredParams 降級路徑的出站面收口（codex 批 2 M1）：
// 未註冊 event 一鍵不列；已註冊 event 只列 EventSpec 宣告的鍵。
func TestRenderDegradedDropsUndeclaredParams(t *testing.T) {
	_, text := RenderDegraded("zh-TW", "some.new.event", map[string]string{
		"b": "second", "a": "first<x>",
	})
	if strings.Contains(text, "first") || strings.Contains(text, "second") {
		t.Fatalf("未註冊 event 的 params 值不得出站，實得 %q", text)
	}

	_, text = RenderDegraded("zh-TW", EventDailyReviewOverdue, map[string]string{
		"date":   "2026-07-31",
		"detail": "dial tcp 10.0.0.5:514: connection refused",
	})
	if !strings.Contains(text, "date: 2026-07-31") {
		t.Fatalf("已宣告鍵應保留，實得 %q", text)
	}
	if strings.Contains(text, "10.0.0.5") || strings.Contains(text, "detail") {
		t.Fatalf("未宣告鍵不得出站，實得 %q", text)
	}
}

func TestRenderUnregisteredEventFallsBackToDegraded(t *testing.T) {
	title, text := Render("zh-TW", "never.registered", map[string]string{"k": "v"})
	if title == "" || !strings.Contains(text, "never.registered") {
		t.Fatalf("未註冊事件應降級渲染而非回空，實得 (%q, %q)", title, text)
	}
	if strings.Contains(text, "k: v") {
		t.Fatalf("未註冊事件的 params 值不得出站，實得 %q", text)
	}
}

// TestFilterDeclared 宣告鍵過濾與剔除清單（M1 的單元契約）。
func TestFilterDeclared(t *testing.T) {
	kept, dropped := FilterDeclared(EventAuditFailure, map[string]string{
		"mechanism": "syslog_forward",
		"detail":    "boom\nnext",
		"typo_key":  "x",
	})
	if kept["mechanism"] != "syslog_forward" {
		t.Fatalf("已宣告鍵應保留，實得 %v", kept)
	}
	if _, ok := kept["detail"]; ok {
		t.Fatalf("未宣告鍵不得保留，實得 %v", kept)
	}
	if len(dropped) != 2 || dropped[0] != "detail" || dropped[1] != "typo_key" {
		t.Fatalf("剔除清單應排序回報，實得 %v", dropped)
	}

	kept, dropped = FilterDeclared("never.registered", map[string]string{"a": "1", "b": "2"})
	if len(kept) != 0 {
		t.Fatalf("未註冊 event 應全數剔除，實得 %v", kept)
	}
	if len(dropped) != 2 {
		t.Fatalf("剔除清單應含全部鍵，實得 %v", dropped)
	}
	if kept == nil {
		t.Fatal("kept 應為空 map 而非 nil（webhook payload 需序列化為 {}）")
	}

	// 保留值仍過淨化（免驗證路徑不得豁免）
	kept, _ = FilterDeclared(EventDailyReviewOverdue, map[string]string{"date": "a\x1b[31m\nb"})
	if strings.ContainsRune(kept["date"], 0x1b) || strings.ContainsRune(kept["date"], '\n') {
		t.Fatalf("保留值仍須淨化，實得 %q", kept["date"])
	}
}

func TestSpecAndEvents(t *testing.T) {
	if _, ok := Spec("nope"); ok {
		t.Fatal("未註冊事件不應回 ok")
	}
	if _, ok := Spec(EventTest); !ok {
		t.Fatal("已註冊事件應回 ok")
	}
	if len(Events()) != len(registry) {
		t.Fatalf("Events() 應涵蓋全部註冊事件")
	}
}

// ---------------------------------------------------------------------------
// V2 對抗驗收：淨化強化（C2/C3）、免驗證路徑淨化（C1）、單一錯誤（validate）、
// 週期重發帶 backlog（L1）
// ---------------------------------------------------------------------------

// TestSanitizeOpaqueLineSeparators U+2028/U+2029 折成空白（C2）。
//
// 兩者的 unicode.IsControl 為 false，卻在 JSON/JS 與部分渲染器中構成換行——
// 放行等於留下偽造多行訊息的路（在告警文字裡另起一段假的「系統通知」）。
func TestSanitizeOpaqueLineSeparators(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"行分隔符折成空白", "a\u2028b", "a b"},
		{"段分隔符折成空白", "a\u2029b", "a b"},
		{"與換行混用只折一個空白", "a\n\u2028\u2029b", "a b"},
		{"首尾者去除", "\u2028a\u2029", "a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeOpaque(tc.in)
			if got != tc.want {
				t.Fatalf("SanitizeOpaque(%q) = %q，預期 %q", tc.in, got, tc.want)
			}
			if strings.ContainsRune(got, '\u2028') || strings.ContainsRune(got, '\u2029') {
				t.Fatalf("行/段分隔符殘留: %q", got)
			}
			if again := SanitizeOpaque(got); again != got {
				t.Fatalf("非冪等: %q -> %q", got, again)
			}
		})
	}
}

// TestSanitizeOpaqueFormatChars Unicode Cf 類（零寬、bidi 控制）整類移除（C3）。
//
// 零寬字元可讓兩個不同的名字看起來完全一樣（告警中的資產名冒充）；bidi 覆寫
// 可讓顯示順序與實際字串相反。合法告警文字不需要這些字元。
func TestSanitizeOpaqueFormatChars(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"零寬空格", "we\u200bb-prod", "web-prod"},
		{"零寬連接", "a\u200db", "ab"},
		{"BOM/零寬不斷行空格", "\ufeffweb", "web"},
		{"bidi 覆寫", "admin\u202e txt.exe", "admin txt.exe"},
		{"bidi 嵌入與隔離", "\u202aa\u2066b\u2069c\u202c", "abc"},
		{"軟連字符", "web\u00adprod", "webprod"},
		{"合法中日文與空白不受影響", "生產 資料庫", "生產 資料庫"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeOpaque(tc.in)
			if got != tc.want {
				t.Fatalf("SanitizeOpaque(%q) = %q，預期 %q", tc.in, got, tc.want)
			}
			for _, r := range got {
				if unicode.Is(unicode.Cf, r) {
					t.Fatalf("Cf 類字元殘留 U+%04X: %q", r, got)
				}
			}
			if again := SanitizeOpaque(got); again != got {
				t.Fatalf("非冪等: %q -> %q", got, again)
			}
		})
	}
}

// TestRenderSanitizesNonOpaqueKinds 免驗證路徑上 enum/int/Lexicon 值一律淨化（C1）。
//
// Render 的契約明載「未經 Validate 直接呼叫亦安全」，但修正前只有 opaque 值走
// 淨化，enum/int 被當成「值域封閉故安全」——那個前提只在 Validate 走過時成立。
// 降級投遞、單測與未來新呼叫點都可能直呼 Render。
func TestRenderSanitizesNonOpaqueKinds(t *testing.T) {
	title, text := Render("zh-TW", EventAuditFailureOngoing, map[string]string{
		// enum 參數（未驗證，值可為任意字串）
		"mechanism": "kek_retirement\x1b[31m\n:warning: *偽造的系統通知*",
		// Lexicon 參數：詞庫缺鍵時 Phrase 回吐傳入的原字串，同屬未驗證輸入
		"cause_code":  "bogus\u2028cause\u200b",
		"reported_at": "2026-07-31T00:00:00Z",
	})
	for _, s := range []string{title, text} {
		if strings.ContainsRune(s, 0x1b) {
			t.Fatalf("ESC 殘留: %q", s)
		}
		if strings.ContainsAny(s, "\n\r") || strings.ContainsRune(s, '\u2028') {
			t.Fatalf("換行類字元殘留（可偽造多行訊息）: %q", s)
		}
		if strings.ContainsRune(s, '\u200b') {
			t.Fatalf("零寬字元殘留: %q", s)
		}
	}
}

// TestValidateSingleErrorPerParam 同一參數只出一個錯（codex low）。
//
// 修正前：必要參數的值格式錯誤時，該值不進 out，required 檢查於是再補一筆
// missing_required——「votes=abc」同時被說成「不是整數」與「沒給」，
// 誤導修錯方向。
func TestValidateSingleErrorPerParam(t *testing.T) {
	cases := []struct {
		name   string
		event  Event
		params map[string]string
		param  string
		reason string
	}{
		{"必要 int 格式錯", EventAccessRequestApprovalProgress,
			map[string]string{"request_id": "1", "votes": "abc", "required": "2"}, "votes", ReasonNotAnInteger},
		{"必要 enum 值域外", EventAuditFailureOngoing,
			map[string]string{"mechanism": "not_a_mechanism", "cause_code": "kek_retirement_backlog",
				"reported_at": "t"}, "mechanism", ReasonEnumOutOfRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(tc.event, tc.params)
			var errs ParamErrors
			if !errors.As(err, &errs) {
				t.Fatalf("預期 ParamErrors，實得 %T: %v", err, err)
			}
			var got []string
			for _, e := range errs {
				if e.Param == tc.param {
					got = append(got, e.Reason)
				}
			}
			if len(got) != 1 {
				t.Fatalf("參數 %s 應只出一個錯，實得 %v", tc.param, got)
			}
			if got[0] != tc.reason {
				t.Fatalf("參數 %s 的原因 = %s，預期 %s", tc.param, got[0], tc.reason)
			}
		})
	}
}

// TestValidateMissingRequiredStillReported 上一項修正不得掩蓋真正的缺參
func TestValidateMissingRequiredStillReported(t *testing.T) {
	_, err := Validate(EventAccessRequestApprovalProgress,
		map[string]string{"request_id": "1", "votes": "2"}) // required 未給
	var errs ParamErrors
	if !errors.As(err, &errs) || len(errs) != 1 ||
		errs[0].Param != "required" || errs[0].Reason != ReasonMissingRequired {
		t.Fatalf("真正缺參仍須回報 missing_required，實得 %v", err)
	}
}

// TestRenderOngoingBacklog 週期重發帶 backlog 筆數（L1）。
//
// 出站文案原本只有機制與時刻，收件人看不出「積壓多少」——遷移前的本地 log
// 文案（N 筆舊 KEK 包裹列仍未退役）反而更有資訊。backlog 為可選：本事件是
// 泛用的週期重發入口，缺參的其他機制不得因此被拒發。
func TestRenderOngoingBacklog(t *testing.T) {
	base := map[string]string{
		"mechanism":   model.MechanismKEKRetirement,
		"cause_code":  model.CauseKEKRetirementBacklog,
		"reported_at": "2026-07-31T00:00:00Z",
	}
	withBacklog := map[string]string{}
	for k, v := range base {
		withBacklog[k] = v
	}
	withBacklog["backlog"] = "12"

	for _, lang := range SupportedLangs {
		t.Run(lang, func(t *testing.T) {
			// 帶筆數：數字現身
			if _, text := Render(lang, EventAuditFailureOngoing, withBacklog); !strings.Contains(text, "12") {
				t.Fatalf("%s 應帶 backlog 筆數，實得 %q", lang, text)
			}
			// 缺筆數：可選段整段略過，不留殘缺標點或空佔位
			_, text := Render(lang, EventAuditFailureOngoing, base)
			if strings.Contains(text, "{backlog}") || strings.Contains(text, "[") || strings.Contains(text, "]") {
				t.Fatalf("%s 缺值時可選段應整段略過，實得 %q", lang, text)
			}
		})
	}

	// 可選：缺 backlog 仍須通過驗證（其他機制的呼叫不得被拒發而降級）
	if _, err := Validate(EventAuditFailureOngoing, base); err != nil {
		t.Fatalf("backlog 必須是可選參數，缺值不得拒發: %v", err)
	}
	out, err := Validate(EventAuditFailureOngoing, withBacklog)
	if err != nil {
		t.Fatalf("帶 backlog 應通過驗證: %v", err)
	}
	if out["backlog"] != "12" {
		t.Fatalf("backlog 應原樣通過，實得 %q", out["backlog"])
	}
	if _, err := Validate(EventAuditFailureOngoing, map[string]string{
		"mechanism": model.MechanismKEKRetirement, "cause_code": model.CauseKEKRetirementBacklog,
		"reported_at": "t", "backlog": "十二"}); err == nil {
		t.Fatal("backlog 非整數應被拒（KindInt 值域）")
	}
}
