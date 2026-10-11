package api

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// TestPolicyChangeAuditFieldsUsesSharedFormat 擋：開關型政策鍵的審計訊息格式與
// 升級遷移解析的格式分岔——遷移會把每一筆啟用變更都略過，整段歷史落入推定。
// 遷移測試的審計 fixture 由 model.PolicyChangeAuditMessage 產生，本測試釘住
// handler 實際寫出的訊息與它逐字相同，且能被同一支解析器讀回。
func TestPolicyChangeAuditFieldsUsesSharedFormat(t *testing.T) {
	for _, tc := range [][2]string{{"false", "true"}, {"true", "false"}} {
		details, errorMsg := policyChangeAuditFields(policy.PolicyDailyReviewEnabled, tc[0], tc[1])
		if details != "" {
			t.Errorf("開關型鍵不應有變更詳情: %q", details)
		}
		if want := model.PolicyChangeAuditMessage(policy.PolicyDailyReviewEnabled, tc[0], tc[1]); errorMsg != want {
			t.Errorf("handler 訊息 %q ≠ 共用格式 %q", errorMsg, want)
		}
		key, oldV, newV, ok := model.ParsePolicyChangeAuditMessage(errorMsg)
		if !ok || key != policy.PolicyDailyReviewEnabled || oldV != tc[0] || newV != tc[1] {
			t.Errorf("解析 %q 得 %q %q %q ok=%v", errorMsg, key, oldV, newV, ok)
		}
	}
}
