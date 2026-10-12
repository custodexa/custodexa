package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

func setWatermark(t *testing.T, db *gorm.DB, class model.RetentionClass, through time.Time) {
	t.Helper()
	var existing model.AuditRetentionWatermark
	if db.Where("class = ?", class).First(&existing).Error == nil {
		if err := db.Model(&existing).Updates(map[string]any{"purged_through_at": through.UTC()}).Error; err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := db.Create(&model.AuditRetentionWatermark{Class: class, PurgedThroughAt: through.UTC(), LastPurgeAt: through.UTC(), PolicyDays: 365}).Error; err != nil {
		t.Fatal(err)
	}
}

// TestDailyReviewDayDetailMatchesSnapshot 擋：抽屜寫的筆數與列出的集合不同，
// 稽核者看到的不是他簽的那一份
func TestDailyReviewDayDetailMatchesSnapshot(t *testing.T) {
	svc, db, _ := setupDailyReviewDB(t)
	const tz = "UTC"
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	fixedClock(svc, at(t, tz, "2026-10-11", 9, 0, 0))

	// token 到期 4 筆放在最早，若被誤收必出現在前 20 筆
	expiry := map[uint]bool{}
	for i := 0; i < 4; i++ {
		seedAnonRejection(t, db, model.AuditReasonTokenExpired, at(t, tz, "2026-10-10", 0, i, 0))
		var id uint
		db.Raw("SELECT max(id) FROM audit_logs").Scan(&id)
		expiry[id] = true
	}
	for i := 0; i < 20; i++ {
		seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, at(t, tz, "2026-10-10", 1, i, 0))
	}
	for i := 0; i < 5; i++ {
		seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusDenied, at(t, tz, "2026-10-10", 2, i, 0))
	}
	for i := 0; i < 7; i++ {
		seedAuditLog(t, db, model.ActionDelete, model.ResourceAsset, model.StatusSuccess, at(t, tz, "2026-10-10", 3, i, 0))
	}
	// 隔日的列不得混入
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, at(t, tz, "2026-10-11", 0, 0, 0))

	detail, err := svc.Day("2026-10-10")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Status != DailyReviewDayPending {
		t.Fatalf("狀態 = %s, want pending", detail.Status)
	}
	if detail.LoginFailures.Total != 25 || val(detail.Counts.LoginFailures) != 25 {
		t.Errorf("登入失敗 明細總數 %d／計數 %d, want 25／25", detail.LoginFailures.Total, val(detail.Counts.LoginFailures))
	}
	if detail.HighRiskOps.Total != 7 || val(detail.Counts.HighRiskOps) != 7 || len(detail.HighRiskOps.Items) != 7 {
		t.Errorf("高危操作 明細總數 %d／計數 %d／列 %d, want 7", detail.HighRiskOps.Total, val(detail.Counts.HighRiskOps), len(detail.HighRiskOps.Items))
	}
	if len(detail.LoginFailures.Items) != DailyReviewDetailLimit {
		t.Errorf("登入失敗列 %d, want %d", len(detail.LoginFailures.Items), DailyReviewDetailLimit)
	}
	for _, it := range detail.LoginFailures.Items {
		if expiry[it.ID] {
			t.Errorf("token 到期列 %d 出現在明細", it.ID)
		}
	}

	row, err := svc.Sign(SignRequest{ReviewDate: "2026-10-10", ReviewerID: 5, ReviewerName: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	var snap DailyReviewSnapshot
	if err := json.Unmarshal([]byte(row.SnapshotJSON), &snap); err != nil {
		t.Fatal(err)
	}
	if val(snap.LoginFailures) != detail.LoginFailures.Total || val(snap.HighRiskOps) != detail.HighRiskOps.Total {
		t.Errorf("簽核快照 %+v 與明細總數 %d／%d 不一致", snap, detail.LoginFailures.Total, detail.HighRiskOps.Total)
	}
}

// TestDailyReviewSourcePurgedNotZero 擋：補簽很久以前的日子時，已清除的來源被算成 0
// 而固化為整日零異常
func TestDailyReviewSourcePurgedNotZero(t *testing.T) {
	const tz = "UTC"
	t.Run("水位晚於該日結束：補簽成功且計數為未知", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		enableFrom(t, db, tz, at(t, tz, "2024-07-01", 0, 0, 0))
		fixedClock(svc, at(t, tz, "2026-10-11", 9, 0, 0))
		setWatermark(t, db, model.RetentionClassAuditLog, at(t, tz, "2025-01-01", 0, 0, 0))
		setWatermark(t, db, model.RetentionClassCommandAlert, at(t, tz, "2025-01-01", 0, 0, 0))
		row, err := svc.Sign(SignRequest{ReviewDate: "2024-08-01", DelayReason: "升級前紀錄已清除", ReviewerID: 5, ReviewerName: "auditor"})
		if err != nil {
			t.Fatalf("補簽: %v", err)
		}
		var snap DailyReviewSnapshot
		_ = json.Unmarshal([]byte(row.SnapshotJSON), &snap)
		if snap.LoginFailures != nil || snap.UnreviewedAlerts != nil || snap.HighRiskOps != nil {
			t.Errorf("已清除來源的計數應為 null: %s", row.SnapshotJSON)
		}
		if row.SourceStatus != model.DailyReviewSourcePurged || row.Coverage != model.DailyReviewCoverageFullDay {
			t.Errorf("source_status=%s coverage=%s, want purged／full_day", row.SourceStatus, row.Coverage)
		}
		if !row.Late || row.DelayReason == nil {
			t.Errorf("late=%v delay_reason=%v", row.Late, row.DelayReason)
		}
	})
	t.Run("水位落在該日中間：計數為下限", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		enableFrom(t, db, tz, at(t, tz, "2024-07-01", 0, 0, 0))
		fixedClock(svc, at(t, tz, "2026-10-11", 9, 0, 0))
		seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, at(t, tz, "2024-08-01", 18, 0, 0))
		seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, at(t, tz, "2024-08-01", 19, 0, 0))
		setWatermark(t, db, model.RetentionClassAuditLog, at(t, tz, "2024-08-01", 12, 0, 0))
		detail, err := svc.Day("2024-08-01")
		if err != nil {
			t.Fatal(err)
		}
		if detail.Counts.LoginFailuresSource != model.DailyReviewSourcePartial || val(detail.Counts.LoginFailures) != 2 {
			t.Errorf("login %d source=%s, want 2（下限）／partial", val(detail.Counts.LoginFailures), detail.Counts.LoginFailuresSource)
		}
		if detail.Sources["audit_log"] != model.DailyReviewSourcePartial || detail.Sources["command_alert"] != model.DailyReviewSourceComplete {
			t.Errorf("sources = %v", detail.Sources)
		}
	})
	t.Run("簽後清除：固化計數不變、明細另回目前狀態", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
		fixedClock(svc, at(t, tz, "2026-10-11", 9, 0, 0))
		for i := 0; i < 5; i++ {
			seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, at(t, tz, "2026-10-10", 10, i, 0))
		}
		row, err := svc.Sign(SignRequest{ReviewDate: "2026-10-10", ReviewerID: 5, ReviewerName: "auditor"})
		if err != nil {
			t.Fatal(err)
		}
		// 保留政策清除該日（原生刪除，與清除迴圈同路徑）並推進水位
		if err := db.Exec("DELETE FROM audit_logs").Error; err != nil {
			t.Fatal(err)
		}
		setWatermark(t, db, model.RetentionClassAuditLog, at(t, tz, "2026-10-11", 0, 0, 0))
		detail, err := svc.Day("2026-10-10")
		if err != nil {
			t.Fatal(err)
		}
		var stored model.DailyReviewLog
		db.First(&stored, row.ID)
		if stored.SnapshotJSON != row.SnapshotJSON {
			t.Errorf("簽核列的快照被改動: %s → %s", row.SnapshotJSON, stored.SnapshotJSON)
		}
		if got := detail.SignedSnapshot["login_failures"]; got != float64(5) {
			t.Errorf("固化計數 = %v, want 5", got)
		}
		if detail.LoginFailures.Total != 0 || detail.LoginFailures.SourceStatus != model.DailyReviewSourcePurged {
			t.Errorf("目前可查 %d source=%s, want 0／purged", detail.LoginFailures.Total, detail.LoginFailures.SourceStatus)
		}
	})
}

// TestDailyReviewDetailCarriesReason 擋：沒有路徑的系統紀錄在抽屜原因欄空白；details 鑑識原文外流到簽核回應
func TestDailyReviewDetailCarriesReason(t *testing.T) {
	svc, db, _ := setupDailyReviewDB(t)
	const tz = "UTC"
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	fixedClock(svc, at(t, tz, "2026-10-11", 9, 0, 0))

	uid := uint(41)
	rows := []model.AuditLog{
		{CreatedAt: at(t, tz, "2026-10-10", 3, 0, 0), UserID: uid, Username: "idle", Action: model.ActionUpdate,
			Resource: model.ResourceUser, ResourceID: &uid, Status: model.StatusSuccess, ClientIP: "system",
			ErrorMsg: "auto_disabled_inactive_account", Details: InactiveDisableDetails(90)},
		{CreatedAt: at(t, tz, "2026-10-10", 4, 0, 0), UserID: 1, Username: "admin", Action: model.ActionDelete,
			Resource: model.ResourceAsset, Status: model.StatusSuccess, Method: "DELETE",
			Path: "/api/v1/assets/7", Details: `{"secret_marker":"must-not-leak"}`},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	detail, err := svc.Day("2026-10-10")
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.HighRiskOps.Items) != 2 {
		t.Fatalf("高危明細 %d 列, want 2", len(detail.HighRiskOps.Items))
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		HighRiskOps struct {
			Items []map[string]any `json:"items"`
		} `json:"high_risk_ops"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	idle, del := doc.HighRiskOps.Items[0], doc.HighRiskOps.Items[1]
	if idle["reason_code"] != "auto_disabled_inactive_account" {
		t.Errorf("閒置停用列 reason_code = %v", idle["reason_code"])
	}
	if p, _ := idle["reason_params"].(map[string]any); p["days"] != "90" {
		t.Errorf("閒置停用列 reason_params = %v", idle["reason_params"])
	}
	if _, ok := del["reason_code"]; ok {
		t.Errorf("帶路徑的刪除列不應有 reason_code：%v", del["reason_code"])
	}
	if del["path"] != "/api/v1/assets/7" {
		t.Errorf("帶路徑的刪除列 path = %v", del["path"])
	}
	if strings.Contains(string(raw), `"details"`) || strings.Contains(string(raw), "must-not-leak") {
		t.Errorf("單日明細回應含 details：%s", raw)
	}
}
