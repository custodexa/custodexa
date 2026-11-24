package audit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openBulkReviewPG 在 TEST_PG_DSN 指向的資料庫另開一個臨時 schema，結束時整個刪除
func openBulkReviewPG(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	schema := fmt.Sprintf("alert_bulk_review_%d", time.Now().UnixNano())
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("postgres 連線失敗: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	if err := db.AutoMigrate(&model.AuditLog{}, &model.CommandAlert{}); err != nil {
		t.Fatal(err)
	}
	return db
}

// TestAlertBulkReviewOverlappingBatchesNoDeadlockPG 兩個重疊且順序相反的批次同時送出。
//
// 擋的威脅：逐筆依請求順序取列鎖時，一方由早到晚、另一方由晚到早，兩個交易互相等待成環，
// 資料庫中止其中一方使其得到 500；或兩邊都以為處置成功而同一筆有兩列處置稽核。
// 斷言：沒有錯誤；每一筆恰好一列處置稽核；重疊的每一筆恰有一方回已有審閱結果。
func TestAlertBulkReviewOverlappingBatchesNoDeadlockPG(t *testing.T) {
	db := openBulkReviewPG(t)
	svc := NewCommandAlertService(db)
	// 每次寫稽核前稍等，拉長交易、放大鎖的重疊時間
	svc.SetAuditTxSink(slowTxSink{delay: 2 * time.Millisecond, inner: NewTxSink()})

	for round := 0; round < 10; round++ {
		owners := make([]uint, 100)
		for i := range owners {
			owners[i] = uint(100 + i)
		}
		ids := seedOwnedAlerts(t, db, owners...)
		a := append([]uint(nil), ids[:70]...) // 由早到晚
		b := make([]uint, 0, 70)              // 由晚到早
		for i := len(ids) - 1; i >= 30; i-- {
			b = append(b, ids[i])
		}
		inputs := []AlertBatchReviewInput{bulkInput(a, 0), bulkInput(b, 0)}
		inputs[0].Reviewer = gatewayapi.Actor{UserID: 8, Username: "auditor-8"}
		inputs[1].Reviewer = gatewayapi.Actor{UserID: 9, Username: "auditor-9"}
		inputs[1].BatchID = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"

		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]*AlertBatchReviewResult, 2)
		errs := make([]error, 2)
		for i := range inputs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i], errs[i] = svc.ReviewBatch(inputs[i])
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("第 %d 輪第 %d 批失敗（不得死結或回錯）: %v", round, i, err)
			}
		}
		reviewedBy := map[uint]int{}
		already := map[uint]int{}
		for _, r := range results {
			for _, it := range r.Items {
				switch it.Result {
				case AlertBatchResultReviewed:
					reviewedBy[it.ID]++
				case AlertBatchResultAlreadyReviewed:
					already[it.ID]++
				}
			}
		}
		for _, id := range ids {
			if reviewedBy[id] != 1 {
				t.Fatalf("第 %d 輪告警 %d 被處置 %d 次, want 1", round, id, reviewedBy[id])
			}
			var n int64
			db.Model(&model.AuditLog{}).Where("resource = ? AND resource_id = ?", model.ResourceCommandAlert, id).Count(&n)
			if n != 1 {
				t.Fatalf("第 %d 輪告警 %d 有 %d 列處置稽核, want 1", round, id, n)
			}
		}
		for _, id := range ids[30:70] {
			if already[id] != 1 {
				t.Fatalf("第 %d 輪重疊的告警 %d 回已有審閱結果 %d 次, want 1", round, id, already[id])
			}
		}
	}
}
