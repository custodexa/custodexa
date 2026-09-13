package audit

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
)

// TestDekUnwrapFailureUsesExistingChannel 資料金鑰解封失敗沿既有失效事件族上報：
// 開列、通知、結案都不另立路徑，且與 KEK 退役收斂各自獨立去重。
//
// 「單次抖動不告警」的門檻判斷在 keyvault 呼叫層（連續失敗計數），本處驗的是
// 上報之後的那一段——事件確實落地、通知確實送出、恢復確實結案。
func TestDekUnwrapFailureUsesExistingChannel(t *testing.T) {
	svc, db := setupFailureDB(t)
	if _, err := svc.policy.UpdateBatch(map[string]string{policy.PolicyFailureAlertEnabled: "true"}, "admin"); err != nil {
		t.Fatalf("開啟失效告警政策: %v", err)
	}
	var sent []notifycat.Event
	svc.notify = func(e notifycat.Event, _ map[string]string) { sent = append(sent, e) }

	svc.Report(model.MechanismDEKUnwrap, model.CauseDEKUnwrapFailed,
		map[string]string{model.FailureParamUnwrapFailures: "3"})

	var event model.AuditFailureEvent
	if err := db.Where("mechanism = ?", model.MechanismDEKUnwrap).First(&event).Error; err != nil {
		t.Fatalf("失效事件未落地: %v", err)
	}
	if event.CauseCode != model.CauseDEKUnwrapFailed {
		t.Errorf("cause_code = %q, want %q", event.CauseCode, model.CauseDEKUnwrapFailed)
	}
	if event.Cause == "" {
		t.Error("Cause 散文為空（PCI 10.7.3 要求記錄 cause）")
	}
	if len(sent) != 1 {
		t.Fatalf("通知數 = %d, want 1", len(sent))
	}

	// 與 KEK 退役收斂各自獨立：一者結案不得把另一者也結掉
	svc.Report(model.MechanismKEKRetirement, model.CauseKEKRetirementBacklog, nil)
	svc.Resolve(model.MechanismKEKRetirement)
	var stillOpen int64
	db.Model(&model.AuditFailureEvent{}).
		Where("mechanism = ? AND ended_at IS NULL", model.MechanismDEKUnwrap).Count(&stillOpen)
	if stillOpen != 1 {
		t.Errorf("解封失效事件被別的機制結案了：未結案列數 = %d, want 1", stillOpen)
	}

	svc.Resolve(model.MechanismDEKUnwrap)
	if err := db.Where("mechanism = ?", model.MechanismDEKUnwrap).First(&event).Error; err != nil {
		t.Fatalf("重讀失效事件: %v", err)
	}
	if event.EndedAt == nil {
		t.Error("恢復後未回填 EndedAt，失效區間沒有結束端")
	}
}

// TestDekUnwrapCausePhraseExists 原因碼有三語短語：缺詞庫時通知內容會回吐機器碼。
func TestDekUnwrapCausePhraseExists(t *testing.T) {
	for _, lang := range notifycat.SupportedLangs {
		got := notifycat.Phrase(lang, notifycat.LexiconCause, model.CauseDEKUnwrapFailed)
		if got == "" || got == model.CauseDEKUnwrapFailed {
			t.Errorf("%s 的 %s 短語缺失（得 %q）", lang, model.CauseDEKUnwrapFailed, got)
		}
	}
}
