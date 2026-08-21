//go:build ignore

// retention_smoke.go 保留政策 live 驗證（audit-log-compliance task 2.3）：
// 對真 postgres 造過期資料 → 設保留政策 → PurgeAll → 驗刪除正確與 audit 留痕。
// 用法：docker compose exec -T backend go run scripts/retention_smoke.go
// 結束時還原政策為 0（永久），測試資料自行清除。
package main

import (
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"os"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func main() {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		envOr("DB_HOST", "postgres"), envOr("DB_USER", "postgres"),
		envOr("DB_PASSWORD", "postgres"), envOr("DB_NAME", "custodexa"), envOr("DB_PORT", "5432"))
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		log.Fatalf("連線 DB 失敗: %v", err)
	}

	policy := policy.NewSecurityPolicyService(db)
	retention := audit.NewRetentionService(db, policy, nil, nil)

	// 1. 造 3 筆 400 天前的過期 session_commands（帶識別標記）＋1 筆今日的
	marker := fmt.Sprintf("retention-smoke-%d", time.Now().UnixNano())
	old := time.Now().AddDate(0, 0, -400)
	for i := 0; i < 3; i++ {
		mustExec(db, "INSERT INTO session_commands (session_id, user_id, command, seq, executed_at) VALUES (0, 0, ?, ?, ?)", marker, i+1, old)
	}
	mustExec(db, "INSERT INTO session_commands (session_id, user_id, command, seq, executed_at) VALUES (0, 0, ?, 99, ?)", marker, time.Now())

	// 2. 設保留 365 天 → PurgeAll
	if _, err := policy.Update(policy.PolicyRetentionSessionCommandDays, "365", "retention-smoke"); err != nil {
		log.Fatalf("設政策失敗: %v", err)
	}
	results := retention.PurgeAll()
	fmt.Printf("PurgeAll 結果: %+v\n", results)

	// 3. 驗證：過期 3 筆刪除、今日 1 筆保留
	var remaining int64
	db.Raw("SELECT COUNT(*) FROM session_commands WHERE command = ?", marker).Scan(&remaining)
	pass := true
	if remaining != 1 {
		fmt.Printf("FAIL: 標記列剩 %d 筆, want 1（過期 3 筆應刪、今日 1 筆應留）\n", remaining)
		pass = false
	} else {
		fmt.Println("PASS: 過期 3 筆已刪、今日 1 筆保留")
	}

	// 4. 驗證 audit 留痕：本次 PurgeAll 至少刪了 3 筆 session_commands。
	// 注意 retention 建構時 audit 傳 nil（script 不拉 worker pool），
	// 故此處驗證的是「結果含刪除計數」而 audit 留痕由單測覆蓋；
	// live 排程鏈的留痕在 02:00 排程或對抗驗證段驗
	deletedOK := false
	for _, r := range results {
		if r.Target == "session_commands" && r.Deleted >= 3 && r.Error == "" {
			deletedOK = true
		}
	}
	if !deletedOK {
		fmt.Println("FAIL: PurgeAll 結果未含 session_commands 刪除 >= 3")
		pass = false
	} else {
		fmt.Println("PASS: PurgeAll 回報 session_commands 刪除計數正確")
	}

	// 5. 還原：政策回 0、清掉殘留標記列
	if _, err := policy.Update(policy.PolicyRetentionSessionCommandDays, "0", "retention-smoke"); err != nil {
		log.Fatalf("還原政策失敗: %v", err)
	}
	mustExec(db, "DELETE FROM session_commands WHERE command = ?", marker)
	fmt.Println("已還原政策（0=永久）並清除測試資料")

	if !pass {
		os.Exit(1)
	}
	fmt.Println("retention smoke 全數 PASS")
}

func mustExec(db *gorm.DB, sql string, args ...any) {
	if err := db.Exec(sql, args...).Error; err != nil {
		log.Fatalf("SQL 失敗 (%s): %v", sql, err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var _ = model.MechanismAuditWrite // 保持 model import（識別碼引用文檔一致性）
