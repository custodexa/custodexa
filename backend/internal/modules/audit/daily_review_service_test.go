package audit

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/reviewcal"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupDailyReviewDB 每日簽核的 sqlite 測試環境。command_alerts 生產走原生 SQL
// （timestamptz），glebarez 驅動對 timestamptz 欄 scan 回 time.Time 失敗，故手建
// datetime 等價表；其餘走 AutoMigrate。時刻一律以 UTC 寫入（sqlite 以字串比較時間）
func setupDailyReviewDB(t *testing.T) (*DailyReviewService, *gorm.DB, *fakeAuditLogger) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{}, &model.SecurityPolicyHistory{},
		&model.DailyReviewLog{}, &model.AuditRetentionWatermark{}, &model.User{}, &model.Asset{}, &model.Session{}, &model.UserRole{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE TABLE command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL DEFAULT 'r',
		session_id INTEGER NOT NULL DEFAULT 0, user_id INTEGER NOT NULL DEFAULT 3, asset_id INTEGER,
		command TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'high', triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error; err != nil {
		t.Fatalf("建表: %v", err)
	}
	audit := &fakeAuditLogger{}
	svc := NewDailyReviewService(db, policy.NewSecurityPolicyService(db), audit)
	return svc, db, audit
}

// fixedClock 把服務時鐘固定在 at，回傳改時刻的函式
func fixedClock(svc *DailyReviewService, at time.Time) func(time.Time) {
	now := at
	svc.SetClock(func() time.Time { return now })
	return func(next time.Time) { now = next }
}

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// at 業務時區的當地時刻
func at(t *testing.T, tz string, date string, hh, mm, ss int) time.Time {
	t.Helper()
	d, ok := reviewcal.ParseDate(date)
	if !ok {
		t.Fatalf("日期 %q", date)
	}
	return time.Date(d.Year(), d.Month(), d.Day(), hh, mm, ss, 0, mustLoc(t, tz))
}

// historyRow 直接寫一列政策變更歷史（以真實歷史表＋行事曆建 fixture）
func historyRow(t *testing.T, db *gorm.DB, key, oldV, newV string, changedAt time.Time, source string) {
	t.Helper()
	if err := db.Create(&model.SecurityPolicyHistory{PolicyKey: key, OldValue: oldV, NewValue: newV,
		ChangedAt: changedAt.UTC(), ChangedBy: "admin", Source: source}).Error; err != nil {
		t.Fatalf("歷史列: %v", err)
	}
}

// setPolicyRow 政策現值列（與歷史末值一致）
func setPolicyRow(t *testing.T, db *gorm.DB, key, value string) {
	t.Helper()
	if err := db.Save(&model.SecurityPolicy{Key: key, Value: value, UpdatedBy: "admin", UpdatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("政策列: %v", err)
	}
}

// enableFrom 業務時區 tz（升級初值），自 since 起啟用
func enableFrom(t *testing.T, db *gorm.DB, tz string, since time.Time) {
	t.Helper()
	historyRow(t, db, policy.PolicyDailyReviewTimezone, "", tz, since.Add(-time.Hour), model.PolicyHistorySourceMigrationUpgrade)
	historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", since, model.PolicyHistorySourcePolicyUpdate)
	setPolicyRow(t, db, policy.PolicyDailyReviewTimezone, tz)
	setPolicyRow(t, db, policy.PolicyDailyReviewEnabled, "true")
}

func seedAuditLog(t *testing.T, db *gorm.DB, action model.AuditAction, resource model.AuditResource, status model.AuditStatus, at time.Time) {
	t.Helper()
	if err := db.Exec(
		"INSERT INTO audit_logs (created_at, action, resource, status, user_id, username) VALUES (?, ?, ?, ?, 1, 'u')",
		at.UTC(), action, resource, status).Error; err != nil {
		t.Fatalf("seed audit_log: %v", err)
	}
}

// seedAnonRejection 認證中介層的匿名拒絕列：user_id=0、無 username、
// 原因碼在 details。reason 決定它算不算「登入失敗」
func seedAnonRejection(t *testing.T, db *gorm.DB, reason string, at time.Time) {
	t.Helper()
	if err := db.Exec(
		"INSERT INTO audit_logs (created_at, action, resource, status, user_id, username, details) VALUES (?, ?, ?, ?, 0, '', ?)",
		at.UTC(), model.ActionLogin, model.ResourceAuth, model.StatusFailure,
		`{"event":"auth_rejected","reason":"`+reason+`"}`).Error; err != nil {
		t.Fatalf("seed anon rejection: %v", err)
	}
}

func seedAlertAt(t *testing.T, db *gorm.DB, triggered time.Time, reviewed *time.Time, disposition string) uint {
	t.Helper()
	var reviewedAt any
	if reviewed != nil {
		reviewedAt = reviewed.UTC()
	}
	res := db.Exec("INSERT INTO command_alerts (triggered_at, reviewed_at, disposition) VALUES (?, ?, ?)", triggered.UTC(), reviewedAt, disposition)
	if res.Error != nil {
		t.Fatalf("seed alert: %v", res.Error)
	}
	var id uint
	db.Raw("SELECT max(id) FROM command_alerts").Scan(&id)
	return id
}

// utcDay 今天在 UTC 的起訖（沿用原有快照測試的「今日」語義）
func utcDay(now time.Time) (string, time.Time, time.Time) {
	u := now.UTC()
	start := time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
	return start.Format(reviewcal.DateFormat), start, start.AddDate(0, 0, 1)
}

func val(p *int64) int64 {
	if p == nil {
		return -1
	}
	return *p
}

// TestDailyReviewSnapshot 三計數的白名單與時間邊界
func TestDailyReviewSnapshot(t *testing.T) {
	svc, db, _ := setupDailyReviewDB(t)
	date, start, end := utcDay(time.Now())
	now := start.Add(12 * time.Hour)
	yesterday := start.Add(-time.Hour)

	// 今日：2 登入失敗、1 登入成功（不計）、1 刪除（高危）、1 政策變更（高危）、1 一般讀取（不計）
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, now)
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, now)
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusSuccess, now)
	seedAuditLog(t, db, model.ActionDelete, model.ResourceAsset, model.StatusSuccess, now)
	seedAuditLog(t, db, model.ActionUpdate, model.ResourceSecurityPolicy, model.StatusSuccess, now)
	seedAuditLog(t, db, model.ActionRead, model.ResourceAsset, model.StatusSuccess, now)
	// 昨日的登入失敗不計入今日
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, yesterday)
	// 告警：今日 1 未審閱、1 已審閱（不計）
	seedAlertAt(t, db, now, nil, model.AlertDispositionPending)
	seedAlertAt(t, db, now, &now, model.AlertDispositionBenign)

	snap, err := svc.Snapshot(date, start, end)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if val(snap.LoginFailures) != 2 || val(snap.UnreviewedAlerts) != 1 || val(snap.HighRiskOps) != 2 {
		t.Errorf("snapshot = %+v, want 登入失敗 2/未審閱 1/高危 2", snap)
	}
	if val(snap.AlertsTotal) != 2 || val(snap.AlertsBenign) != 1 || val(snap.AlertsEscalated) != 0 {
		t.Errorf("告警分布 total=%d benign=%d escalated=%d, want 2/1/0", val(snap.AlertsTotal), val(snap.AlertsBenign), val(snap.AlertsEscalated))
	}
}

// TestDailyReviewLoginFailuresCoverBothStatuses 登入失敗計數涵蓋兩種狀態值。
//
// 修正前只數 `status='failure'`，而外部身分提供者的登入拒絕（准入規則不符、
// 外部帳號以本地密碼登入、LDAP 傳輸嚴格拒絕）在本庫一律記 `denied`——**全數漏算**，
// PCI 10.4.1 的每日覆核因而對 SSO 部署形同虛設。
//
// 反向格同樣關鍵：資源授權拒絕（RBAC 403）也是 `denied`，但它不是登入事件。
// 若判準放寬成「所有 denied」，覆核數字會被日常的權限拒絕淹沒而失去意義
func TestDailyReviewLoginFailuresCoverBothStatuses(t *testing.T) {
	svc, db, _ := setupDailyReviewDB(t)
	date, start, end := utcDay(time.Now())
	now := start.Add(12 * time.Hour)

	// 認證類：憑證不成立記 failure
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, now)
	// 認證類：OIDC 准入拒絕記 denied（resource=auth）
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusDenied, now)
	// 認證類：外部帳號以本地密碼登入的嘗試記 denied，但 resource=user
	//（既有實作，見 external_login_attempt_audit.go）——判準以 action 收斂而非
	// resource，正是為了不把這種列排除掉
	seedAuditLog(t, db, model.ActionLogin, model.ResourceUser, model.StatusDenied, now)
	// 認證類：LDAP 傳輸嚴格拒絕記 denied，resource=transmission
	seedAuditLog(t, db, model.ActionLogin, model.ResourceTransmission, model.StatusDenied, now)

	// 非認證類的 denied 一律不得計入
	seedAuditLog(t, db, model.ActionRead, model.ResourceAsset, model.StatusDenied, now)
	seedAuditLog(t, db, model.ActionCreate, model.ResourceAccessRequest, model.StatusDenied, now)
	seedAuditLog(t, db, model.ActionExecute, model.ResourceSession, model.StatusDenied, now)
	// 登入成功亦不得計入
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusSuccess, now)

	snap, err := svc.Snapshot(date, start, end)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if val(snap.LoginFailures) != 4 {
		t.Errorf("登入失敗數 = %d, want 4（failure 1 筆＋認證類 denied 3 筆）", val(snap.LoginFailures))
	}
}

// TestDailyReviewExcludesRoutineTokenExpiry 例行 token 到期不計入登入失敗數。
//
// access token 每 15 分鐘到期一次、前端自動 refresh，每次都在認證中介層留下一筆匿名
// 拒絕列。若照單全收，這個數字會被正常流量淹沒到失去訊號——覆核卡片天天顯示三位數，
// 稽核者學會忽略它，PCI 10.4.1 的價值就歸零了。
//
// **只排除到期這一種**：無憑證與簽章無效是真正的無效存取嘗試（PCI 10.2.1.4），
// 排除它們等於把偵測面關掉。到期與簽章無效在**對外回應上不可區分**（同一則
// AUTH_TOKEN_INVALID），分流只存在於審計 details——否則就開出了憑證存在性探測面。
func TestDailyReviewExcludesRoutineTokenExpiry(t *testing.T) {
	svc, db, _ := setupDailyReviewDB(t)
	date, start, end := utcDay(time.Now())
	now := start.Add(12 * time.Hour)

	// 例行到期 ×3：不計入
	seedAnonRejection(t, db, model.AuditReasonTokenExpired, now)
	seedAnonRejection(t, db, model.AuditReasonTokenExpired, now)
	seedAnonRejection(t, db, model.AuditReasonTokenExpired, now)
	// 無憑證與簽章無效：計入（真正的無效存取嘗試）
	seedAnonRejection(t, db, "AUTH_TOKEN_MISSING", now)
	seedAnonRejection(t, db, "AUTH_TOKEN_INVALID", now)
	// handler 自寫的登入失敗（details 為 NULL）：計入。
	// **這一格釘的是 COALESCE**——少了它，`NOT LIKE` 遇 NULL 得 NULL，
	// 既有的登入失敗列會被靜默排除，數字反而變得比修正前更少
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, now)

	snap, err := svc.Snapshot(date, start, end)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if val(snap.LoginFailures) != 3 {
		t.Errorf("登入失敗數 = %d, want 3（無憑證 1＋簽章無效 1＋handler 自寫 1；例行到期 3 筆不計）",
			val(snap.LoginFailures))
	}
}

// TestDailyReviewSignOncePerDay 簽核留痕含快照；同一所屬日重複簽核被拒並回既有簽核者
func TestDailyReviewSignOncePerDay(t *testing.T) {
	svc, db, audit := setupDailyReviewDB(t)
	const tz = "Asia/Taipei"
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	fixedClock(svc, at(t, tz, "2026-10-11", 9, 0, 0))
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, at(t, tz, "2026-10-10", 12, 0, 0))

	row, err := svc.Sign(SignRequest{ReviewDate: "2026-10-10", Note: "已檢視", ReviewerID: 5, ReviewerName: "auditor-a"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.Contains(row.SnapshotJSON, `"login_failures":1`) || row.ReviewDate != "2026-10-10" {
		t.Errorf("快照未固化或所屬日錯: %s %s", row.ReviewDate, row.SnapshotJSON)
	}
	if len(audit.entries) != 1 || audit.entries[0].Resource != model.ResourceDailyReview {
		t.Errorf("簽核未入審計: %+v", audit.entries)
	}

	_, err = svc.Sign(SignRequest{ReviewDate: "2026-10-10", ReviewerID: 6, ReviewerName: "auditor-b"})
	var signed *AlreadySignedError
	if !errors.As(err, &signed) || signed.Signer != "auditor-a" || signed.Date != "2026-10-10" || !signed.SignedAt.Equal(row.SignedAt) {
		t.Errorf("重複簽核應回 AlreadySignedError 含既有所屬日、簽核者與簽核時刻, got %v", err)
	}
	var n int64
	db.Model(&model.DailyReviewLog{}).Count(&n)
	if n != 1 {
		t.Errorf("簽核列 = %d, want 1", n)
	}
}
