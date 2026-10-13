package audit

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 稽核列的由新到舊分批讀取面，供其他模組查「某類事件最近一次發生在何時、結果為何」。
//
// 查詢語句留在 audit 模組內：其他模組只交出條件值（資源、動作、事件碼、details 的
// 預篩樣式），不拿到可任意加條件的查詢句柄，稽核表的欄位與索引用法因此只有一處。
// 精確比對（解析 details 後核對）仍由呼叫端在 visit 內做，預篩只負責縮小讀取量。

// auditScanBatchSize 每批讀取的稽核列數
const auditScanBatchSize = 200

// AuditScanFilter 掃描條件。Resource、Action、DetailsLike 必填；ErrorMsg 空字串表示不限。
type AuditScanFilter struct {
	Resource model.AuditResource
	Action   model.AuditAction
	ErrorMsg string
	// DetailsLike details 欄的 LIKE 樣式，多個之間為 OR
	DetailsLike []string
	// Since 只讀建立時間不早於此時刻的列
	Since time.Time
}

// AuditScanRow 掃描讀出的欄位
type AuditScanRow struct {
	ID        uint
	CreatedAt time.Time
	UserID    uint
	Username  string
	Status    string
	Details   string
}

// ScanAuditBackwards 依 (created_at, id) 由新到舊分批讀取符合 f 的稽核列，
// 逐列交給 visit，visit 回 true 即停。讀完時間窗內全部符合的列也停。
func ScanAuditBackwards(db *gorm.DB, f AuditScanFilter, visit func(AuditScanRow) bool) error {
	if len(f.DetailsLike) == 0 {
		return fmt.Errorf("稽核掃描缺少 details 預篩條件")
	}
	var cursor *AuditScanRow
	for {
		q := scanFilterScope(db.Model(&model.AuditLog{}), f).Where("created_at >= ?", f.Since)
		if cursor != nil {
			// 多帶一個 created_at <= 上界：只有 OR 條件時規劃器無法以時間索引直接定位到
			// 游標處，每一批都從窗的最新端重掃，批數多時成本成平方成長
			q = q.Where("created_at <= ? AND (created_at < ? OR (created_at = ? AND id < ?))",
				cursor.CreatedAt, cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
		}
		var rows []AuditScanRow
		if err := q.Select("id, created_at, user_id, username, status, details").
			Order("created_at DESC").Order("id DESC").
			Limit(auditScanBatchSize).Scan(&rows).Error; err != nil {
			return fmt.Errorf("讀取稽核紀錄失敗: %w", err)
		}
		for _, r := range rows {
			if visit(r) {
				return nil
			}
		}
		if len(rows) < auditScanBatchSize {
			return nil
		}
		last := rows[len(rows)-1]
		cursor = &last
	}
}

// scanFilterScope 把掃描條件轉成 WHERE 子句；details 的多個樣式以括號包成一組 OR
func scanFilterScope(q *gorm.DB, f AuditScanFilter) *gorm.DB {
	q = q.Where("resource = ? AND action = ?", f.Resource, f.Action)
	if f.ErrorMsg != "" {
		q = q.Where("error_msg = ?", f.ErrorMsg)
	}
	clauses := make([]string, len(f.DetailsLike))
	args := make([]any, len(f.DetailsLike))
	for i, p := range f.DetailsLike {
		clauses[i] = "details LIKE ?"
		args[i] = p
	}
	return q.Where("("+strings.Join(clauses, " OR ")+")", args...)
}
