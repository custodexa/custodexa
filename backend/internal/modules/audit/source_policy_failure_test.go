package audit

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
)

// 來源政策失效在既有失效通道上的接線。
//
// 上報端在 identity（判定點讀取後記帳），本檔驗的是**接上之後**的行為：
// 通知確實出站、cause 文案查得到、出站 payload 只帶碼。
// 兩者分屬不同 package，故分兩處測——合在一起就得讓 identity 去碰
// 失效服務的私有注入口。
func TestSourcePolicyFailureNotifiesWithCodeOnly(t *testing.T) {
	svc, db := setupFailureDB(t)
	db.Create(&model.SecurityPolicy{Key: policy.PolicyFailureAlertEnabled, Value: "true"})

	var events []notifycat.Event
	var lastParams map[string]string
	svc.notify = func(event notifycat.Event, params map[string]string) {
		events = append(events, event)
		lastParams = params
	}

	svc.Report(model.MechanismSourcePolicy, model.CauseSourcePolicyCorrupt,
		map[string]string{"user_id": "7"})

	if len(events) != 1 || events[0] != notifycat.EventAuditFailure {
		t.Fatalf("來源政策失效未經既有失效通道發出通知: got=%v", events)
	}
	if lastParams["mechanism"] != model.MechanismSourcePolicy {
		t.Errorf("通知 mechanism = %q, want %q", lastParams["mechanism"], model.MechanismSourcePolicy)
	}
	if lastParams["cause_code"] != model.CauseSourcePolicyCorrupt {
		t.Errorf("通知 cause_code = %q, want %q",
			lastParams["cause_code"], model.CauseSourcePolicyCorrupt)
	}
	// 出站只帶碼：受影響的帳號編號不出站（去識別紅線）
	if _, ok := lastParams["user_id"]; ok {
		t.Errorf("user_id 不得進出站 params: got=%v", lastParams)
	}

	// 失效列的 cause 文案查得到（詞條缺失時失效面只剩一個碼）
	var ev model.AuditFailureEvent
	if err := db.Where("mechanism = ?", model.MechanismSourcePolicy).First(&ev).Error; err != nil {
		t.Fatalf("查失效列: %v", err)
	}
	if ev.Cause == "" || ev.Cause == model.CauseSourcePolicyCorrupt {
		t.Errorf("cause 文案未經 notifycat 轉譯: %q", ev.Cause)
	}
	if ev.CauseParams == "" {
		t.Error("cause_params 未落庫（forensic 明細只走 DB，不出站）")
	}

	// 恢復對稱：Resolve 結案並發出恢復通知
	svc.Resolve(model.MechanismSourcePolicy)
	if len(events) != 2 {
		t.Fatalf("恢復未發出通知: got=%v", events)
	}
	var closed model.AuditFailureEvent
	if err := db.Where("mechanism = ?", model.MechanismSourcePolicy).First(&closed).Error; err != nil {
		t.Fatalf("查失效列: %v", err)
	}
	if closed.EndedAt == nil {
		t.Error("Resolve 後 ended_at 仍為 null（失效區間永遠懸掛）")
	}
}

// TestSourcePolicyCauseTextsAreTranslated 兩個 cause 的預設語系文案存在。
//
// 缺詞條時 CauseText 會回退成碼本身，失效面板與通知就只剩一串英數
// ——那是「有告警但看不懂」，與沒有告警的處置速度相同。
func TestSourcePolicyCauseTextsAreTranslated(t *testing.T) {
	for _, cause := range []string{
		model.CauseSourcePolicyUnreadable, model.CauseSourcePolicyCorrupt,
	} {
		text := CauseText(cause, nil)
		if text == "" || text == cause {
			t.Errorf("cause %q 無對應文案（回退為碼本身）: %q", cause, text)
		}
	}
}
