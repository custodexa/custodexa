package api

import (
	"net/url"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
)

// TestAuditLogEndBeforeIsExclusive 擋：抽屜「查看全部」把下一日起點的事件列進來，
// 審閱範圍跨到隔日
func TestAuditLogEndBeforeIsExclusive(t *testing.T) {
	_, db, _ := setupDailyReviewRouter(t)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	taipei, _ := time.LoadLocation("Asia/Taipei")
	windowStart := time.Date(2026, 10, 10, 0, 0, 0, 0, taipei)
	windowEnd := time.Date(2026, 10, 11, 0, 0, 0, 0, taipei)
	for i, at := range []time.Time{windowEnd, windowEnd.Add(-time.Microsecond), windowStart} {
		row := &model.AuditLog{Action: model.ActionLogin, Resource: model.ResourceAuth, Status: model.StatusFailure,
			UserID: uint(i + 1), Username: "u", CreatedAt: at.UTC()}
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	snap, err := audit.NewDailyReviewService(db, policy.NewSecurityPolicyService(db), nil).Snapshot("2026-10-10", windowStart, windowEnd)
	if err != nil {
		t.Fatal(err)
	}

	// 查詢參數以 UTC 帶入：sqlite 以字串比較時間（生產的 pg 比較的是時刻本身）
	q := "?start_time=" + url.QueryEscape(windowStart.UTC().Format(time.RFC3339Nano)) + "&end_before=" + url.QueryEscape(windowEnd.UTC().Format(time.RFC3339Nano))
	code, body := callAuditLogList(t, q)
	if code != 200 {
		t.Fatalf("status = %d", code)
	}
	if body.Total != 2 || len(body.Data) != 2 {
		t.Errorf("total = %d, want 2（恰在下一日起點的那筆不列入）", body.Total)
	}
	if snap.LoginFailures == nil || body.Total != *snap.LoginFailures {
		t.Errorf("操作日誌總數 %d ≠ 該日共用範圍的計數 %v", body.Total, snap.LoginFailures)
	}

	// 與含尾端的 end_time 同時給定：取交集
	q2 := q + "&end_time=" + url.QueryEscape(windowStart.UTC().Format(time.RFC3339Nano))
	if _, body := callAuditLogList(t, q2); body.Total != 1 {
		t.Errorf("end_before＋end_time total = %d, want 1（兩條件都套用）", body.Total)
	}
	// 只用含尾端的 end_time 時，恰在尾端的那筆會被收進來（對照組）
	q3 := "?start_time=" + url.QueryEscape(windowStart.UTC().Format(time.RFC3339Nano)) + "&end_time=" + url.QueryEscape(windowEnd.UTC().Format(time.RFC3339Nano))
	if _, body := callAuditLogList(t, q3); body.Total != 3 {
		t.Errorf("對照組 end_time total = %d, want 3", body.Total)
	}
}
