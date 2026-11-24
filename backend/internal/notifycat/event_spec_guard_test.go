package notifycat

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var linkPlaceholderRe = regexp.MustCompile(`\{(\w+)\}`)

// checkEventSpecs 事件規格的分級、連結樣板、名稱參數與旗標的守衛；回傳違規清單（排序後）。
func checkEventSpecs(reg map[Event]EventSpec) []string {
	var v []string
	add := func(format string, args ...any) { v = append(v, fmt.Sprintf(format, args...)) }
	systemAlerts := systemAlertEventSpecs()
	for ev, spec := range reg {
		_, isSystemAlert := systemAlerts[ev]
		switch spec.Severity {
		case SeverityHigh, SeverityMedium, SeverityLow:
			if isSystemAlert {
				add("%s 是系統安全告警事件，分級應沿用類型目錄（%s），不得寫死 %s", ev, SeverityFromCatalog, spec.Severity)
			}
		case SeverityFromCatalog:
			if !isSystemAlert {
				add("%s 不是系統安全告警事件，不得宣告 %s", ev, SeverityFromCatalog)
			}
		case "":
			add("%s 沒有宣告分級", ev)
		default:
			add("%s 的分級 %q 不在值域內", ev, spec.Severity)
		}

		if spec.Link.Path != "" {
			if !strings.HasPrefix(spec.Link.Path, "/") {
				add("%s 的連結樣板 %q 不是站內路徑", ev, spec.Link.Path)
			}
			if spec.Link.Label != LinkLabelAction && spec.Link.Label != LinkLabelView {
				add("%s 的連結文字種類 %q 不合法", ev, spec.Link.Label)
			}
			for _, m := range linkPlaceholderRe.FindAllStringSubmatch(spec.Link.Path, -1) {
				p, ok := spec.param(m[1])
				if !ok {
					add("%s 的連結樣板引用未宣告的參數 %s", ev, m[1])
					continue
				}
				if p.Kind != KindInt {
					add("%s 的連結樣板引用 %s 型參數 %s（只准整數參數）", ev, p.Kind, m[1])
				}
			}
			if strings.ContainsAny(spec.Link.Path, " <>|\"'") {
				add("%s 的連結樣板含會破壞連結語法的字元", ev)
			}
		}

		for _, p := range spec.Params {
			if strings.HasSuffix(p.Name, "_name") && p.NameOf == "" {
				add("%s 的名稱參數 %s 沒有宣告識別碼種類", ev, p.Name)
			}
			if p.NameOf != "" && p.Kind != KindOpaque {
				add("%s 的參數 %s 宣告了識別碼種類卻不是 opaque", ev, p.Name)
			}
			switch p.NameOf {
			case "", IDKindUser, IDKindAsset, IDKindAPIToken, IDKindNotificationChannel, IDKindProducerOnly:
			default:
				add("%s 的參數 %s 的識別碼種類 %q 不在值域內", ev, p.Name, p.NameOf)
			}
		}
		for variant, param := range spec.PresenceVariants {
			p, ok := spec.param(param)
			if !ok || p.Required {
				add("%s 的 variant %s 依據的參數 %s 須為已宣告的可選參數", ev, variant, param)
			}
			// 同時宣告 VariantParam 時，組合鍵「<值>_<鍵>」不得與 VariantParam 的任何值相同（否則分不出句型）
			if spec.VariantParam != "" {
				if vp, ok := spec.param(spec.VariantParam); ok {
					for _, e := range vp.Enum {
						for _, e2 := range vp.Enum {
							if e+"_"+variant == e2 {
								add("%s 的組合 variant %s_%s 與 %s 的值相同", ev, e, variant, spec.VariantParam)
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(v)
	return v
}

// TestEventSpecGuards 每個事件都有分級、連結樣板只引用 int 型參數、每個名稱參數都宣告識別碼種類。
func TestEventSpecGuards(t *testing.T) {
	if v := checkEventSpecs(registry); len(v) > 0 {
		t.Fatalf("事件規格違規 %d 項:\n  %s", len(v), strings.Join(v, "\n  "))
	}
}

// TestEventSpecGuardSensitivity 守衛對兩種突變都會紅：連結樣板代入 opaque 參數、刪掉某事件的分級。
func TestEventSpecGuardSensitivity(t *testing.T) {
	opaqueLink := cloneRegistry()
	spec := opaqueLink[EventAgentTaskReport]
	spec.Link.Path = "/audit/agent-tasks/{agent_name}"
	opaqueLink[EventAgentTaskReport] = spec
	if v := checkEventSpecs(opaqueLink); !containsAll(v, "只准整數參數") {
		t.Fatalf("連結樣板代入 opaque 參數未被擋下: %v", v)
	}

	noSeverity := cloneRegistry()
	spec = noSeverity[EventDailyReviewOverdue]
	spec.Severity = ""
	noSeverity[EventDailyReviewOverdue] = spec
	if v := checkEventSpecs(noSeverity); !containsAll(v, "沒有宣告分級") {
		t.Fatalf("刪掉分級未被擋下: %v", v)
	}

	noKind := cloneRegistry()
	spec = noKind[EventNotificationDeliveryAbandoned]
	params := append([]ParamSpec(nil), spec.Params...)
	for i := range params {
		if params[i].Name == "channel_name" {
			params[i].NameOf = ""
		}
	}
	spec.Params = params
	noKind[EventNotificationDeliveryAbandoned] = spec
	if v := checkEventSpecs(noKind); !containsAll(v, "沒有宣告識別碼種類") {
		t.Fatalf("名稱參數缺識別碼種類未被擋下: %v", v)
	}
}

// TestNotificationDeliveryAbandonedSpec 新事件：分級 medium、連結通道頁、不送往目標通道。
func TestNotificationDeliveryAbandonedSpec(t *testing.T) {
	spec, ok := Spec(EventNotificationDeliveryAbandoned)
	if !ok {
		t.Fatal("notification_delivery_abandoned 未登錄")
	}
	if spec.Severity != SeverityMedium || spec.Link.Path != "/notification-channels" || !spec.ExcludeTargetChannel {
		t.Fatalf("規格不符: severity=%s link=%s exclude=%v", spec.Severity, spec.Link.Path, spec.ExcludeTargetChannel)
	}
	if string(EventNotificationDeliveryAbandoned) != "notification_delivery_abandoned" {
		t.Fatal("事件鍵改變")
	}
	if got := LinkPath(EventNotificationDeliveryAbandoned, nil); got != "/notification-channels" {
		t.Fatalf("連結路徑 = %q", got)
	}
}

// TestAuditFailureFamilyFlag 稽核失效一族旗標恰好標在三個事件上。
func TestAuditFailureFamilyFlag(t *testing.T) {
	var got []string
	for ev, spec := range registry {
		if spec.AuditFailureFamily {
			got = append(got, string(ev))
		}
	}
	sort.Strings(got)
	want := []string{"audit_failure", "audit_failure_ongoing", "audit_failure_resolved"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("稽核失效一族 = %v，want %v", got, want)
	}
}

// TestLinkPathSubstitution 連結只由固定路徑與大於零的整數組成；不合格的代入值使整個連結省略。
func TestLinkPathSubstitution(t *testing.T) {
	cases := []struct {
		event  Event
		params map[string]string
		want   string
	}{
		{EventAgentTaskReport, map[string]string{"request_id": "42"}, "/audit/agent-tasks/42"},
		{EventAgentTaskReport, map[string]string{"request_id": "0"}, ""},
		{EventAgentTaskReport, map[string]string{"request_id": "-3"}, ""},
		{EventAgentTaskReport, map[string]string{"request_id": "4a"}, ""},
		{EventAgentTaskReport, map[string]string{"request_id": "007"}, ""},
		{EventAgentTaskReport, map[string]string{}, ""},
		{EventAgentBreakerTripped, map[string]string{"user_id": "9"}, "/agent-breakers?user_id=9"},
		{EventAuditFailure, nil, "/audit-logs?tab=failures"},
		{EventDailyReviewOverdue, nil, "/audit-logs?tab=reviews"},
		{EventAccessRequestCreated, map[string]string{"request_id": "5"}, "/approvals?tab=pending&request=5"},
		{EventAccessRequestCreated, map[string]string{"request_id": "05"}, ""},
		{EventAccessRequestCreated, map[string]string{}, ""},
		{EventSystemAlertHostKeyMismatch, nil, "/alerts"},
		{EventTest, nil, ""},
		{Event("ghost.event"), nil, ""},
	}
	for _, tc := range cases {
		if got := LinkPath(tc.event, tc.params); got != tc.want {
			t.Errorf("LinkPath(%s, %v) = %q，want %q", tc.event, tc.params, got, tc.want)
		}
	}
}

func containsAll(v []string, frag string) bool {
	for _, s := range v {
		if strings.Contains(s, frag) {
			return true
		}
	}
	return false
}

// TestApprovalsLinkTemplates 連線申請族、破窗與補審逾期的連結落在審核中心對應頁籤的那一張單（一律明寫 tab）；
// 每日審閱逾期不變。
func TestApprovalsLinkTemplates(t *testing.T) {
	params := map[string]string{"request_id": "42"}
	cases := []struct {
		event Event
		want  string
		label LinkLabel
	}{
		{EventAccessRequestCreated, "/approvals?tab=pending&request=42", LinkLabelAction},
		{EventAccessRequestApprovalProgress, "/approvals?tab=pending&request=42", LinkLabelView},
		{EventAccessRequestApproved, "/approvals?tab=history&request=42", LinkLabelView},
		{EventAccessRequestRejected, "/approvals?tab=history&request=42", LinkLabelView},
		{EventTicketRevoked, "/approvals?tab=history&request=42", LinkLabelView},
		{EventBreakGlassUsed, "/approvals?tab=reviews&request=42", LinkLabelAction},
		{EventBreakGlassReviewOverdue, "/approvals?tab=reviews&request=42", LinkLabelAction},
		{EventDailyReviewOverdue, "/audit-logs?tab=reviews", LinkLabelAction},
	}
	for _, tc := range cases {
		if got := LinkPath(tc.event, params); got != tc.want {
			t.Errorf("LinkPath(%s) = %q，want %q", tc.event, got, tc.want)
		}
		if got := LinkLabelOf(tc.event); got != tc.label {
			t.Errorf("LinkLabelOf(%s) = %q，want %q", tc.event, got, tc.label)
		}
	}
}

// TestSlackLinkEscapesQuery Slack 文字裡的連結以 `&amp;` 表示查詢字串的 `&`。
func TestSlackLinkEscapesQuery(t *testing.T) {
	got := SlackLinkSuffix("en-US", "https://h/approvals?tab=pending&request=42", LinkLabelAction)
	if !strings.Contains(got, "<https://h/approvals?tab=pending&amp;request=42|") {
		t.Fatalf("連結的 & 沒有跳脫: %q", got)
	}
}
