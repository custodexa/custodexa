package database

import (
	"log"
	"sync"
)

// authzWarningLogPrefix 升級警示印在後端日誌的固定前綴；管理腳本升級收尾與維運查日誌都以它辨認。
const authzWarningLogPrefix = "[AuthzModelMigration] WARN "

// AuthzUpgradeWarning 權限模型遷移當下資料已不具還原資格的事實。
//
// 遷移不因此停下（升級不擋使用者），但這兩種狀態會讓之後的備份被標為不可用於還原、
// 還原一律拒絕，所以必須在升級當下留痕：日誌一行，加上段 2 審計服務建好後補寫的一列審計。
type AuthzUpgradeWarning struct {
	LocalSuperAdmins    int64
	DanglingAssignments int64
}

var (
	authzWarnMu      sync.Mutex
	authzWarnPending *AuthzUpgradeWarning
)

// authzWarningFor 報告是否需要警示：沒有本地超管，或有指向已刪除／不存在角色的指派。
func authzWarningFor(rep AuthzMigrationReport) (AuthzUpgradeWarning, bool) {
	w := AuthzUpgradeWarning{LocalSuperAdmins: rep.LocalSuperAdmins, DanglingAssignments: rep.DanglingAssignments}
	return w, w.LocalSuperAdmins < 1 || w.DanglingAssignments > 0
}

// announceAuthzWarning 遷移首次寫入報告時呼叫：印日誌並暫存，等審計服務存在後由段 2 取走補記。
// 重跑（報告已存在）不呼叫，所以同一份資料只警示一次。
func announceAuthzWarning(rep AuthzMigrationReport) {
	w, ok := authzWarningFor(rep)
	if !ok {
		return
	}
	log.Printf("%slocal_super_admins=%d dangling_assignments=%d backups_restorable=false",
		authzWarningLogPrefix, w.LocalSuperAdmins, w.DanglingAssignments)
	authzWarnMu.Lock()
	authzWarnPending = &w
	authzWarnMu.Unlock()
}

// TakeAuthzUpgradeWarning 取走（並清除）暫存的升級警示；沒有則 ok 為 false。
func TakeAuthzUpgradeWarning() (AuthzUpgradeWarning, bool) {
	authzWarnMu.Lock()
	defer authzWarnMu.Unlock()
	if authzWarnPending == nil {
		return AuthzUpgradeWarning{}, false
	}
	w := *authzWarnPending
	authzWarnPending = nil
	return w, true
}

// AnnounceAuthzWarningForTest 供其他套件的測試模擬「遷移剛警示過」；正式碼不呼叫。
func AnnounceAuthzWarningForTest(localSuperAdmins, dangling int64) {
	announceAuthzWarning(AuthzMigrationReport{LocalSuperAdmins: localSuperAdmins, DanglingAssignments: dangling})
}
