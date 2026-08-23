package audit

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupDailyReviewDB command_alerts 帶 timestamptz tag，sqlite 用原生 SQL 建
// datetime 等價表（Snapshot 只 COUNT 不 scan）；其餘走 AutoMigrate
func setupDailyReviewDB(t *testing.T) (*DailyReviewService, *gorm.DB, *fakeAuditLogger) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{}, &model.DailyReviewLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(
		"CREATE TABLE command_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, triggered_at DATETIME NOT NULL, reviewed_at DATETIME)").Error; err != nil {
		t.Fatalf("建表: %v", err)
	}
	audit := &fakeAuditLogger{}
	svc := NewDailyReviewService(db, policy.NewSecurityPolicyService(db), audit)
	return svc, db, audit
}

func seedAuditLog(t *testing.T, db *gorm.DB, action model.AuditAction, resource model.AuditResource, status model.AuditStatus, at time.Time) {
	t.Helper()
	if err := db.Exec(
		"INSERT INTO audit_logs (created_at, action, resource, status, user_id, username) VALUES (?, ?, ?, ?, 1, 'u')",
		at, action, resource, status).Error; err != nil {
		t.Fatalf("seed audit_log: %v", err)
	}
}

// seedAnonRejection 認證中介層的匿名拒絕列：user_id=0、無 username、
// 原因碼在 details。reason 決定它算不算「登入失敗」
func seedAnonRejection(t *testing.T, db *gorm.DB, reason string, at time.Time) {
	t.Helper()
	if err := db.Exec(
		"INSERT INTO audit_logs (created_at, action, resource, status, user_id, username, details) VALUES (?, ?, ?, ?, 0, '', ?)",
		at, model.ActionLogin, model.ResourceAuth, model.StatusFailure,
		`{"event":"auth_rejected","reason":"`+reason+`"}`).Error; err != nil {
		t.Fatalf("seed anon rejection: %v", err)
	}
}

// TestDailyReviewSnapshot 三計數的白名單與時間邊界
func TestDailyReviewSnapshot(t *testing.T) {
	svc, db, _ := setupDailyReviewDB(t)
	now := time.Now()
	yesterday := now.AddDate(0, 0, -1)

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
	db.Exec("INSERT INTO command_alerts (triggered_at) VALUES (?)", now)
	db.Exec("INSERT INTO command_alerts (triggered_at, reviewed_at) VALUES (?, ?)", now, now)

	snap, err := svc.Snapshot(now)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.LoginFailures != 2 || snap.UnreviewedAlerts != 1 || snap.HighRiskOps != 2 {
		t.Errorf("snapshot = %+v, want 登入失敗 2/未審閱 1/高危 2", snap)
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
	now := time.Now()

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

	snap, err := svc.Snapshot(now)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.LoginFailures != 4 {
		t.Errorf("登入失敗數 = %d, want 4（failure 1 筆＋認證類 denied 3 筆）", snap.LoginFailures)
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
	now := time.Now()

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

	snap, err := svc.Snapshot(now)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.LoginFailures != 3 {
		t.Errorf("登入失敗數 = %d, want 3（無憑證 1＋簽章無效 1＋handler 自寫 1；例行到期 3 筆不計）",
			snap.LoginFailures)
	}
}

// TestDailyReviewSignOncePerDay 簽核留痕含快照；同日重複簽核被拒並回既有簽核者
func TestDailyReviewSignOncePerDay(t *testing.T) {
	svc, db, audit := setupDailyReviewDB(t)
	now := time.Now()
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, now)

	row, err := svc.Sign(now, 5, "auditor-a", "已檢視")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.Contains(row.SnapshotJSON, `"login_failures":1`) {
		t.Errorf("快照未固化: %s", row.SnapshotJSON)
	}
	if len(audit.entries) != 1 || audit.entries[0].Resource != model.ResourceDailyReview {
		t.Errorf("簽核未入審計: %+v", audit.entries)
	}

	_, err = svc.Sign(now, 6, "auditor-b", "")
	if !errors.Is(err, ErrAlreadySigned) || !strings.Contains(err.Error(), "auditor-a") {
		t.Errorf("重複簽核應回 ErrAlreadySigned 含既有簽核者, got %v", err)
	}
}

// TestDailyReviewOverdue 逾期提醒：關閉不查、昨日已簽不發、未簽發
func TestDailyReviewOverdue(t *testing.T) {
	svc, _, _ := setupDailyReviewDB(t)
	now := time.Now()

	if svc.CheckOverdue(now) {
		t.Error("功能關閉時不應發提醒")
	}

	if _, err := svc.policy.Update(policy.PolicyDailyReviewEnabled, "true", "test"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !svc.CheckOverdue(now) {
		t.Error("啟用且昨日未簽應發提醒")
	}

	if _, err := svc.Sign(now.AddDate(0, 0, -1), 5, "auditor-a", ""); err != nil {
		t.Fatalf("sign yesterday: %v", err)
	}
	if svc.CheckOverdue(now) {
		t.Error("昨日已簽不應發提醒")
	}
}
