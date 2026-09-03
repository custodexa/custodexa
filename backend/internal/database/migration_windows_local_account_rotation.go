package database

import (
	"fmt"

	"gorm.io/gorm"
)

// Windows 本機帳號改密的資料層增量 migration：assets 加六個改密通道側車欄。
// 純加法，無資料轉換、無回填。沿 migration_db_query_console.go 的紀律：
// DDL 無條件、不用 IF NOT EXISTS——在已套用的庫上重跑必須大聲失敗，而非靜默 no-op。
//
// # Up 做什麼
//
//  1. assets.rotation_channel：改密要怎麼連上這台機器（posix_ssh／windows_winrm／
//     windows_ssh／none）。**預設空字串而非回填實值**：空＝依協定推導
//     （ssh→posix_ssh，其餘→none），故升級後既有列的行為與升級前逐項相同。
//     回填實值會讓「管理者設的」與「當初回填的」在日後永遠分不出來。
//  2. assets.winrm_scheme／winrm_port／winrm_tls_mode／winrm_ca_cert：WinRM 通道的
//     連線方式、埠、憑證驗證模式與信任錨。四欄皆可空——它們只在 winrm 通道下有
//     意義，對其餘資產強制預設值等於宣稱設定過了。
//  3. assets.rotation_ssh_port：以 SSH 走 PowerShell 改密時的目標埠（0＝22）。
//     協定為 ssh 的資產沿用既有 port，本欄對它們不參與推導。
//
// # 為什麼是六個具名欄而不是一個 JSON 設定欄
//
// assets 表既有的 per-protocol 側車（RDP 傳輸安全、DB TLS、VNC SFTP）全是具名欄，
// 值域受控、可在 SQL 層查詢、schema parity 守衛看得見。單一 JSON 欄會讓這批設定
// 脫離全部既有守衛的射程，而它承載的是「憑證要送到哪裡、用不用 TLS」——
// 恰好是最不該只有應用層知道形狀的一組值。
//
// # 為什麼 winrm_ca_cert 不加密
//
// CA 憑證是公開資料（信任錨的公鑰部分），與 assets.db_ca_cert、assets.k8s_ca_cert
// 同性質，沿用同一存放形態。此欄不得出現在列表投影——不是因為機密，而是因為
// PEM 動輒數 KB，讓每一列都扛著它會使資產列表的傳輸量隨憑證大小起伏。
//
// # Down 契約（讀完再用）
//
// **本 Down 有損**：六欄刪除即失去全部改密通道設定，再次 Up 之後所有資產回到
// 「未設定」而由協定推導——rdp 資產從此不再改密且不會有任何提示。
//
// 故本函式只供 parity 守衛與開發環境使用。**生產沒有回滾入口**：
// RollbackMigration 無產品碼呼叫者，回退的唯一手段是部署回舊版映像並還原
// 升級前備份（docs/ops/upgrade-sop.md）。
func windowsLocalAccountRotationDDL() []string {
	return []string{
		`ALTER TABLE assets ADD COLUMN rotation_channel character varying(16) NOT NULL DEFAULT ''`,
		`ALTER TABLE assets ADD COLUMN winrm_scheme character varying(8)`,
		`ALTER TABLE assets ADD COLUMN winrm_port bigint`,
		`ALTER TABLE assets ADD COLUMN winrm_tls_mode character varying(16)`,
		`ALTER TABLE assets ADD COLUMN winrm_ca_cert text`,
		`ALTER TABLE assets ADD COLUMN rotation_ssh_port bigint`,
	}
}

func applyWindowsLocalAccountRotation(db *gorm.DB) error {
	for _, stmt := range windowsLocalAccountRotationDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 windows_local_account_rotation DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackWindowsLocalAccountRotation 反序還原結構。
//
// **有損**：見本檔檔頭的 Down 契約。開發庫限定；生產回退不走這裡。
func rollbackWindowsLocalAccountRotation(db *gorm.DB) error {
	stmts := []string{
		`ALTER TABLE assets DROP COLUMN rotation_ssh_port`,
		`ALTER TABLE assets DROP COLUMN winrm_ca_cert`,
		`ALTER TABLE assets DROP COLUMN winrm_tls_mode`,
		`ALTER TABLE assets DROP COLUMN winrm_port`,
		`ALTER TABLE assets DROP COLUMN winrm_scheme`,
		`ALTER TABLE assets DROP COLUMN rotation_channel`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 windows_local_account_rotation 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
