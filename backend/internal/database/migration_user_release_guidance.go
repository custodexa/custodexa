package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 使用者版本說明關閉狀態增量。
//
// 內容：新表 user_release_guidance，每列是一位使用者對一個說明版本的關閉紀錄；
// （user_id, notice_version）為主鍵，user_id 外鍵隨帳號刪除。不回填：缺列即尚未關閉，
// 升級後的第一次登入會看到說明。
//
// # Down 契約
//
// 不提供回滾：回退只走升級前備份（表內只有個人偏好，丟失的代價是說明再顯示一次）。
func userReleaseGuidanceDDL() []string {
	return []string{
		`CREATE TABLE user_release_guidance (user_id bigint NOT NULL, notice_version character varying(32) NOT NULL, dismissed_at timestamp with time zone NOT NULL, CONSTRAINT user_release_guidance_pkey PRIMARY KEY (user_id, notice_version), CONSTRAINT fk_user_release_guidance_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`,
	}
}

func applyUserReleaseGuidance(db *gorm.DB) error {
	for _, stmt := range userReleaseGuidanceDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 user_release_guidance DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackUserReleaseGuidance 不提供回滾；見檔頭 Down 契約。
func rollbackUserReleaseGuidance(_ *gorm.DB) error {
	return fmt.Errorf("user release guidance has no down migration; restore the pre-upgrade backup instead")
}
