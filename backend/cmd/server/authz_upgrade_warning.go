package main

import (
	"encoding/json"
	"log"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// auditLogger 是 logAuthzUpgradeWarning 需要的審計面（測試以替身注入）。
type auditLogger interface {
	Log(entry *audit.AuditLogEntry)
}

// logAuthzUpgradeWarning 把權限模型遷移當下的警示補寫成一列審計。
//
// 遷移在段 1 執行，審計服務尚不存在，所以遷移只暫存事實，這裡在段 2 建好審計服務後取走補記
// （與 kek_topology_env_import 同一手法）。升級不因此擋下；留痕的意義是讓「之後的備份不可還原、
// 該怎麼補救」有地方被日後的稽核者與維運讀到。只記計數與補救代碼，不記帳號名稱。
// 取走即清除：同一行程只補記一次；遷移重跑不再暫存，故同一份資料不會每次啟動都警示。
func logAuthzUpgradeWarning(sink auditLogger) {
	w, ok := database.TakeAuthzUpgradeWarning()
	if !ok {
		return
	}
	body, err := json.Marshal(map[string]any{
		"event":                     "permission_model_upgrade_warning",
		"local_super_admins":        w.LocalSuperAdmins,
		"dangling_assignments":      w.DanglingAssignments,
		"later_backups_restorable":  false,
		"restore_refuses_this_data": true,
		"remedy":                    "grant_local_super_admin_and_fix_assignments_then_back_up_again",
	})
	if err != nil {
		log.Printf("[AuthzModelMigration] 升級警示審計序列化失敗（不阻塞啟動）: %v", err)
		return
	}
	sink.Log(&audit.AuditLogEntry{
		UserID: 0, Username: "system",
		Action: model.ActionExecute, Resource: model.ResourceRole,
		Status: model.StatusFailure, ErrorMsg: "permission_model_upgrade_warning",
		Path: "/startup/permission-model-upgrade", Method: "POST",
		Details: string(body),
	})
}
