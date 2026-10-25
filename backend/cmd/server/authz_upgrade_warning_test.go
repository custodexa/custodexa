package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

type captureAudit struct{ entries []*audit.AuditLogEntry }

func (c *captureAudit) Log(e *audit.AuditLogEntry) { c.entries = append(c.entries, e) }

// TestAuthzUpgradeWarningAudit 擋：升級當下已不具還原資格的資料沒有審計留痕，或留痕不含
// 「之後的備份不可還原」與補救代碼，或沒有警示時憑空多出一列，或同一行程補記兩次。
// 警示事實由遷移暫存（database.TakeAuthzUpgradeWarning），這裡驗段 2 的補記。
func TestAuthzUpgradeWarningAudit(t *testing.T) {
	t.Run("無暫存警示：不寫審計", func(t *testing.T) {
		database.TakeAuthzUpgradeWarning()
		c := &captureAudit{}
		logAuthzUpgradeWarning(c)
		if len(c.entries) != 0 {
			t.Fatalf("無警示卻寫了 %d 列", len(c.entries))
		}
	})

	t.Run("有暫存警示：補寫一列，內容如實，補寫後不重複", func(t *testing.T) {
		database.TakeAuthzUpgradeWarning()
		database.AnnounceAuthzWarningForTest(0, 3)
		c := &captureAudit{}
		logAuthzUpgradeWarning(c)
		if len(c.entries) != 1 {
			t.Fatalf("寫了 %d 列, want 1", len(c.entries))
		}
		e := c.entries[0]
		if e.Username != "system" || e.Action != model.ActionExecute || e.Resource != model.ResourceRole ||
			e.Status != model.StatusFailure || e.ErrorMsg != "permission_model_upgrade_warning" {
			t.Errorf("審計列形狀不符: %+v", e)
		}
		var d map[string]any
		if err := json.Unmarshal([]byte(e.Details), &d); err != nil {
			t.Fatal(err)
		}
		if d["local_super_admins"] != float64(0) || d["dangling_assignments"] != float64(3) ||
			d["later_backups_restorable"] != false || d["restore_refuses_this_data"] != true ||
			!strings.Contains(d["remedy"].(string), "back_up_again") {
			t.Errorf("details 不符: %s", e.Details)
		}
		logAuthzUpgradeWarning(c)
		if len(c.entries) != 1 {
			t.Errorf("同一警示補記了兩次")
		}
	})
}
