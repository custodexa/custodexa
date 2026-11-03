package identity

import (
	"log"

	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// historyAuditorFlag 審核歷史唯讀端點以稽核身分放行的判定（與端點守衛同一個函式）。
// 查詢失敗當否、不阻斷組裝（顯示性欄位，端點另有強制），並記一行 log。
func historyAuditorFlag(db *gorm.DB, userID uint) bool {
	ok, err := authz.IsAccessRequestHistoryAuditor(db, userID)
	if err != nil {
		log.Printf("[Auth] 審核歷史讀取資格查詢失敗（本次不顯示入口）: userID=%d err=%v", userID, err)
		return false
	}
	return ok
}
