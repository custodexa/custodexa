package policy

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestApplyPreviewSignoffRecord 擋：關閉時套用預覽不提出開啟；或開啟而未簽時把該鍵
// 列成待變更（套用改不了未簽的日子，列進去會讓管理者以為按下套用就會符合）。
func TestApplyPreviewSignoffRecord(t *testing.T) {
	defs := []PolicyDef{*findDef(PolicyDailyReviewEnabled)}
	group := testGroup("pci", true)
	clauses := []model.PolicyClause{testClause("pci", "10.4.1", model.PolicyClauseKindSetting, "")}
	controls := []model.PolicyClauseControl{testControl("pci", "10.4.1", PolicyDailyReviewEnabled,
		model.PolicyControlComparatorSignoffRecord, "true", false)}
	scope := []string{PolicyDailyReviewEnabled}
	preview := func(t *testing.T, value string, rec *SignoffRecord) ApplyPreview {
		t.Helper()
		values := map[string]string{PolicyDailyReviewEnabled: value}
		snap := BuildSnapshotWithSignoff(defs, values, nil, []model.PolicyGroup{group}, clauses, controls, nil, rec)
		return buildApplyPreview(defs, values, snap, scope, ApplyModeGroup, "pci")
	}
	unsigned := func(t *testing.T) *SignoffRecord {
		return buildSignoffRecord(t, enabledFrom(t, "2026-09-01"), signAll("2026-09-11", "2026-10-05"), false)
	}

	t.Run("關閉時列出改為開啟", func(t *testing.T) {
		p := preview(t, "false", unsigned(t))
		if len(p.Changes) != 1 || p.Changes[0].Key != PolicyDailyReviewEnabled || p.Changes[0].Proposed != "true" {
			t.Fatalf("變更列 %+v, want daily_review_enabled → true", p.Changes)
		}
		if len(p.Notes) != 0 {
			t.Errorf("關閉時的偏離套用解決得了，不該有補簽說明：%+v", p.Notes)
		}
	})
	t.Run("開啟且因未簽偏離時不列變更、附補簽說明", func(t *testing.T) {
		p := preview(t, "true", unsigned(t))
		for _, c := range p.Changes {
			if c.Key == PolicyDailyReviewEnabled {
				t.Errorf("開關已開仍被列為待變更：%+v", c)
			}
		}
		if len(p.Conflicts) != 0 {
			t.Errorf("不是衝突：%+v", p.Conflicts)
		}
		if len(p.Notes) != 1 {
			t.Fatalf("補簽說明 %d 筆, want 1", len(p.Notes))
		}
		n := p.Notes[0]
		if n.Key != PolicyDailyReviewEnabled || n.Group != "pci" || n.ClauseNo != "10.4.1" ||
			n.Reason != ComplianceReasonSignoffUnsignedDays || n.Unsigned != 4 || n.EarliestUnsigned != "2026-10-06" {
			t.Errorf("說明 %+v, want 10.4.1 未簽 4 天、最早 2026-10-06", n)
		}
	})
	t.Run("對照：開啟且全簽時沒有說明", func(t *testing.T) {
		p := preview(t, "true", buildSignoffRecord(t, enabledFrom(t, "2026-09-01"), signAll("2026-09-11", "2026-10-09"), false))
		if len(p.Changes) != 0 || len(p.Notes) != 0 {
			t.Errorf("變更 %+v 說明 %+v, want 皆空", p.Changes, p.Notes)
		}
	})
	t.Run("範圍外的鍵不出說明", func(t *testing.T) {
		values := map[string]string{PolicyDailyReviewEnabled: "true"}
		snap := BuildSnapshotWithSignoff(defs, values, nil, []model.PolicyGroup{group}, clauses, controls, nil, unsigned(t))
		p := buildApplyPreview(defs, values, snap, []string{PolicyPasswordMinLength}, ApplyModeGroup, "pci")
		if len(p.Notes) != 0 {
			t.Errorf("範圍外仍出說明：%+v", p.Notes)
		}
	})
}
