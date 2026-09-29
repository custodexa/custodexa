package audit

import (
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestAlertBatchReviewNeverOverwritesReviewed 批次審閱只能處置「送出當下仍未審閱」的告警。
//
// 擋的威脅：兩位審閱者先後處置同一筆，批次那一方把對方已寫下的處置與理由整筆蓋掉，
// 而畫面上兩人都以為自己的判斷成立。單筆路徑的「重新審閱」仍須可用（修正誤判）。
func TestAlertBatchReviewNeverOverwritesReviewed(t *testing.T) {
	svc, db := setupAlertDB(t)
	a := seedAlert(t, db, "rm -rf /tmp/x")
	if err := svc.Review(a.ID, 7, model.AlertDispositionEscalated, "已通報主管"); err != nil {
		t.Fatalf("先行審閱失敗: %v", err)
	}

	err := svc.ReviewInBatch(a.ID, 8, model.AlertDispositionBenign, "批次：例行維運")
	if !errors.Is(err, ErrAlertAlreadyReviewed) {
		t.Fatalf("已審閱的告警走批次應回 ErrAlertAlreadyReviewed，得到 %v", err)
	}
	var got model.CommandAlert
	db.First(&got, a.ID)
	if got.Disposition != model.AlertDispositionEscalated || got.Note != "已通報主管" ||
		got.ReviewedBy == nil || *got.ReviewedBy != 7 {
		t.Fatalf("既有處置被覆蓋: disposition=%s note=%q by=%v", got.Disposition, got.Note, got.ReviewedBy)
	}

	// 未審閱的那一筆照常成立
	b := seedAlert(t, db, "cat /etc/shadow")
	if err := svc.ReviewInBatch(b.ID, 8, model.AlertDispositionBenign, "批次：例行維運"); err != nil {
		t.Fatalf("未審閱告警批次審閱應成功: %v", err)
	}
	var gotB model.CommandAlert
	db.First(&gotB, b.ID)
	if gotB.ReviewedAt == nil || gotB.Disposition != model.AlertDispositionBenign || gotB.Note != "批次：例行維運" {
		t.Fatalf("批次審閱未寫入: %+v", gotB)
	}

	// 單筆重新審閱不受影響
	if err := svc.Review(a.ID, 8, model.AlertDispositionBenign, "複查後改判"); err != nil {
		t.Fatalf("單筆重新審閱應可用: %v", err)
	}
	if err := svc.ReviewInBatch(9999, 8, model.AlertDispositionBenign, "x"); !errors.Is(err, ErrAlertNotFound) {
		t.Fatalf("不存在的告警應回 ErrAlertNotFound，得到 %v", err)
	}
}

// TestAlertBatchReviewRequiresNoteAndOtherUsersAlert 批次審閱的理由必填且有上限，
// 並拒絕審閱者自己連線觸發的告警。
//
// 擋的威脅：以空白或灌量理由一次結案多筆，事後答不出每筆為什麼無害；
// 以及審閱者把自己觸發的告警混進批次一併結案（自己替自己的行為背書）。
func TestAlertBatchReviewRequiresNoteAndOtherUsersAlert(t *testing.T) {
	svc, db := setupAlertDB(t)
	a := seedAlert(t, db, "rm -rf /tmp/x") // seedAlert 的觸發者為 user 1

	for _, note := range []string{"", "   \n\t", strings.Repeat("字", maxAlertBatchNoteRunes+1)} {
		if err := svc.ReviewInBatch(a.ID, 8, model.AlertDispositionBenign, note); !errors.Is(err, ErrAlertBatchNote) {
			t.Fatalf("理由 %d 字應回 ErrAlertBatchNote，得到 %v", len([]rune(note)), err)
		}
	}
	if err := svc.ReviewInBatch(a.ID, 1, model.AlertDispositionBenign, "自己看過了"); !errors.Is(err, ErrAlertSelfTriggered) {
		t.Fatalf("審閱者自己觸發的告警應回 ErrAlertSelfTriggered，得到 %v", err)
	}
	if err := svc.ReviewInBatch(a.ID, 8, "bogus", "理由"); !errors.Is(err, ErrInvalidDisposition) {
		t.Fatalf("非法處置應回 ErrInvalidDisposition，得到 %v", err)
	}
	var got model.CommandAlert
	db.First(&got, a.ID)
	if got.ReviewedAt != nil {
		t.Fatalf("被拒的批次審閱不應留下任何處置: %+v", got)
	}
	// 上限邊界本身可用
	if err := svc.ReviewInBatch(a.ID, 8, model.AlertDispositionBenign, strings.Repeat("字", maxAlertBatchNoteRunes)); err != nil {
		t.Fatalf("恰為上限的理由應可用: %v", err)
	}
	// 自己觸發的告警仍可逐筆審閱（單筆路徑不擋）
	c := seedAlert(t, db, "id")
	if err := svc.Review(c.ID, 1, model.AlertDispositionBenign, "逐筆說明"); err != nil {
		t.Fatalf("單筆路徑不應擋本人觸發的告警: %v", err)
	}

	// 單筆路徑同一字數上限（理由會進稽核列）：超過即拒、不寫入；恰為上限與空理由仍可用
	d := seedAlert(t, db, "whoami")
	if err := svc.Review(d.ID, 8, model.AlertDispositionBenign, strings.Repeat("字", maxAlertBatchNoteRunes+1)); !errors.Is(err, ErrAlertNoteTooLong) {
		t.Fatalf("單筆理由超過上限應回 ErrAlertNoteTooLong，得到 %v", err)
	}
	var gotD model.CommandAlert
	db.First(&gotD, d.ID)
	if gotD.ReviewedAt != nil {
		t.Fatalf("被拒的單筆審閱不應留下處置: %+v", gotD)
	}
	for _, note := range []string{strings.Repeat("字", maxAlertBatchNoteRunes), ""} {
		if err := svc.Review(d.ID, 8, model.AlertDispositionBenign, note); err != nil {
			t.Fatalf("單筆理由 %d 字應可用: %v", len([]rune(note)), err)
		}
	}
}

// TestAlertListFiltersByIDs 以 id 清單查詢告警，供批次中斷後查回每筆的實際處置。
//
// 擋的威脅：回應遺失的那幾筆無從查證，畫面只能猜「成功」或「失敗」。
func TestAlertListFiltersByIDs(t *testing.T) {
	svc, db := setupAlertDB(t)
	a := seedAlert(t, db, "a")
	seedAlert(t, db, "b")
	c := seedAlert(t, db, "c")
	res, err := svc.List(&CommandAlertFilter{IDs: []uint{a.ID, c.ID}, PageSize: 50})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 2 || len(res.Data) != 2 {
		t.Fatalf("ids 篩選應只回 2 筆，得到 total=%d len=%d", res.Total, len(res.Data))
	}
}
