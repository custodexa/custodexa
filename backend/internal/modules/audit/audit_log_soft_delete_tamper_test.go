package audit

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 操作日誌不具軟刪語意：軟刪欄位非空的列仍出現在讀取面，且其所在區間不得判通過。
func TestAuditLogSoftDeleteTamper(t *testing.T) {
	f := setupVerifyFixture(t)
	ids := f.stampedRows(t, 3, time.Now())
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// 前置：封章後內容層驗證通過
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPassed {
		t.Fatalf("前置不成立：封章後狀態 = %s, want %s", got, IntervalStatusPassed)
	}
	f.mustExec(t, "UPDATE audit_logs SET deleted_at = ? WHERE id = ?", time.Now().UTC(), ids[1])

	// 讀取面：列表與單筆都看得到該列
	var one model.AuditLog
	if err := f.db.First(&one, ids[1]).Error; err != nil {
		t.Fatalf("單筆讀取看不到軟刪欄位非空的列: %v", err)
	}
	var count int64
	if err := f.db.Model(&model.AuditLog{}).Where("id IN ?", ids).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != int64(len(ids)) {
		t.Fatalf("列表可見列數 = %d, want %d", count, len(ids))
	}

	// 內容層：不得判通過，回報 rows_hidden 與隱藏筆數
	res := f.statusOf(t, cp.Seq)
	if res.Status != IntervalStatusRowsHidden {
		t.Fatalf("內容層狀態 = %s, want %s", res.Status, IntervalStatusRowsHidden)
	}
	if res.AuditLogs == nil || res.AuditLogs.HiddenRows != 1 {
		t.Errorf("隱藏筆數不符，want 1: %+v", res.AuditLogs)
	}

	// 逐列完整性：該列計為異常
	rep, err := f.integrity.VerifyIDRange(f.db, cp.IDFrom, cp.IDTo)
	if err != nil {
		t.Fatalf("VerifyIDRange: %v", err)
	}
	if rep.Mismatched < 1 {
		t.Errorf("逐列完整性異常數 = %d, want >= 1", rep.Mismatched)
	}
	rep, err = f.integrity.Verify(f.db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Mismatched < 1 {
		t.Errorf("時間範圍逐列完整性異常數 = %d, want >= 1", rep.Mismatched)
	}
}
