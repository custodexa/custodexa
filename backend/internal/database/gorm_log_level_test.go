package database

import (
	"os"
	"strings"
	"testing"
)

// TestReleaseModeDoesNotLogSQL 釘住「release 模式的 GORM 日誌等級不得輸出 SQL」。
//
// **為什麼這條需要守衛而不只是註解**：`logger.Info` 會把每一條 SQL 連同參數值寫到
// stdout。在本產品中，那使稽核紀錄（audit_logs／session_commands）與憑證雜湊的內容
// **複寫出保留期與檢查點簽章鏈的保護範圍之外**——那份副本不受完整性控制、不隨保留
// 政策清除。把它改回 Info 只是一行的事，而錯誤不會有任何其他測試轉紅。
//
// 本測試以原始碼為對象（而非啟動一個 release 模式的 DB 連線）：判定的是「分流存在
// 且 release 落在不輸出 SQL 的等級」，那是原始碼層的不變式，不需要真連線就能驗。
func TestReleaseModeDoesNotLogSQL(t *testing.T) {
	src, err := os.ReadFile("database.go")
	if err != nil {
		t.Fatalf("讀取 database.go 失敗: %v", err)
	}
	code := string(src)

	// 1. 必須存在依模式分流的判斷
	if !strings.Contains(code, "cfg.IsReleaseMode()") {
		t.Error("GORM 日誌等級未依部署模式分流：release 模式會輸出完整 SQL 與參數，" +
			"使稽核內容複寫出保留期與簽章鏈的保護範圍之外")
	}

	// 2. release 分支必須落在不輸出 SQL 的等級
	if !strings.Contains(code, "gormLogLevel = logger.Error") &&
		!strings.Contains(code, "gormLogLevel = logger.Silent") {
		t.Error("release 模式的 GORM 日誌等級不是 Error 或 Silent；" +
			"Info/Warn 皆會逐條輸出 SQL 與其參數值")
	}

	// 3. 不得再有無條件的 Info 寫死（本測試存在的原因就是它曾經是寫死的）
	if strings.Contains(code, "logger.Default.LogMode(logger.Info)") {
		t.Error("偵測到無條件的 logger.Info 寫死——那正是本守衛要防的形態")
	}
}
