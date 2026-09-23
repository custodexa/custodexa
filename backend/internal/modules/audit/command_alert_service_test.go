package audit

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupAlertDB(t *testing.T) (*CommandAlertService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// command_alerts 生產走原生 SQL（timestamptz），測試以 sqlite 相容型別（datetime）
	// 原生建表——CommandAlert.TriggeredAt 的 gorm type:timestamptz 經 AutoMigrate 會建
	// timestamptz 欄，glebarez 驅動 scan 回 time.Time 失敗，故此處手建等價 schema
	if err := db.Exec(`CREATE TABLE command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error; err != nil {
		t.Fatalf("create command_alerts: %v", err)
	}
	// users/assets 供 List 的 LEFT JOIN 補 username/asset_name；
	// sessions 供 List 的 LEFT JOIN 帶出建線當下的來源位址（client_ip）
	if err := db.AutoMigrate(&model.User{}, &model.Asset{}, &model.Session{}, &model.UserRole{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewCommandAlertService(db), db
}

func seedAlert(t *testing.T, db *gorm.DB, cmd string) *model.CommandAlert {
	t.Helper()
	ruleID := uint(1)
	a := &model.CommandAlert{
		RuleID: &ruleID, RuleName: "rm -rf 偵測", SessionID: 1, UserID: 1,
		Command: cmd, Severity: "high", TriggeredAt: time.Now(),
		Disposition: model.AlertDispositionPending,
	}
	if err := db.Create(a).Error; err != nil {
		t.Fatalf("create alert: %v", err)
	}
	return a
}

// TestAlertReviewMarksDisposition 審閱處置記複審者/時間/分類/備註，並從未審閱清單移除
func TestAlertReviewMarksDisposition(t *testing.T) {
	svc, db := setupAlertDB(t)
	a := seedAlert(t, db, "rm -rf /")

	if err := svc.Review(a.ID, 7, model.AlertDispositionEscalated, "已通報主管"); err != nil {
		t.Fatalf("Review: %v", err)
	}

	var reloaded model.CommandAlert
	db.First(&reloaded, a.ID)
	if reloaded.ReviewedAt == nil || reloaded.ReviewedBy == nil || *reloaded.ReviewedBy != 7 {
		t.Errorf("審閱後應記複審者與時間, got by=%v at=%v", reloaded.ReviewedBy, reloaded.ReviewedAt)
	}
	if reloaded.Disposition != model.AlertDispositionEscalated || reloaded.Note != "已通報主管" {
		t.Errorf("處置分類/備註未正確記錄, got %s / %q", reloaded.Disposition, reloaded.Note)
	}
}

// TestAlertReviewRejectsInvalidDisposition 只接受 benign/escalated，pending 不可主動設回
func TestAlertReviewRejectsInvalidDisposition(t *testing.T) {
	svc, db := setupAlertDB(t)
	a := seedAlert(t, db, "shutdown now")

	for _, bad := range []string{"pending", "unknown", ""} {
		if err := svc.Review(a.ID, 1, bad, ""); !errors.Is(err, ErrInvalidDisposition) {
			t.Errorf("disposition=%q = %v, want ErrInvalidDisposition", bad, err)
		}
	}
}

// TestAlertReviewNotFound 審閱不存在的告警回 ErrAlertNotFound
func TestAlertReviewNotFound(t *testing.T) {
	svc, _ := setupAlertDB(t)
	if err := svc.Review(999, 1, model.AlertDispositionBenign, ""); !errors.Is(err, ErrAlertNotFound) {
		t.Errorf("不存在告警 = %v, want ErrAlertNotFound", err)
	}
}

// TestAlertUnreviewedFilter 未審閱篩選僅列 reviewed_at IS NULL
func TestAlertUnreviewedFilter(t *testing.T) {
	svc, db := setupAlertDB(t)
	a1 := seedAlert(t, db, "cmd1")
	seedAlert(t, db, "cmd2") // 保持未審閱
	svc.Review(a1.ID, 1, model.AlertDispositionBenign, "誤報")

	// 全部：2 筆
	all, err := svc.List(&CommandAlertFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if all.Total != 2 {
		t.Fatalf("全部 = %d, want 2", all.Total)
	}
	// 僅未審閱：1 筆（cmd2）
	un, err := svc.List(&CommandAlertFilter{Unreviewed: true})
	if err != nil {
		t.Fatalf("List unreviewed: %v", err)
	}
	if un.Total != 1 {
		t.Errorf("未審閱 = %d, want 1", un.Total)
	}
}

// TestAlertReviewIdempotentCorrection 重覆審閱視為更新（可修正誤判）
func TestAlertReviewIdempotentCorrection(t *testing.T) {
	svc, db := setupAlertDB(t)
	a := seedAlert(t, db, "risky")
	svc.Review(a.ID, 1, model.AlertDispositionBenign, "初判無害")
	if err := svc.Review(a.ID, 2, model.AlertDispositionEscalated, "複查後升級"); err != nil {
		t.Fatalf("再審: %v", err)
	}
	var reloaded model.CommandAlert
	db.First(&reloaded, a.ID)
	if reloaded.Disposition != model.AlertDispositionEscalated || *reloaded.ReviewedBy != 2 {
		t.Error("重覆審閱應更新為最新處置與複審者")
	}
}

// TestAlertListFiltersQualifyJoinedColumns 主體與資產過濾在三表 JOIN 下不得歧義：
// sessions 也有 user_id／asset_id，未加表名前綴的 WHERE 會在 SQL 層直接報錯，
// 稽核按主體查告警即得 500。先確認過濾真的以告警列為準。
func TestAlertListFiltersQualifyJoinedColumns(t *testing.T) {
	svc, db := setupAlertDB(t)
	sessAsset := uint(9)
	if err := db.Create(&model.Session{ID: 1, UserID: 9, AssetID: &sessAsset, ClientIP: "10.0.0.1"}).Error; err != nil {
		t.Fatalf("create session: %v", err)
	}
	a := seedAlert(t, db, "ssh 127.0.0.1") // user_id=1，會話列 user_id=9
	asset := uint(5)
	db.Model(a).Update("asset_id", asset)

	uid := uint(1)
	byUser, err := svc.List(&CommandAlertFilter{UserID: &uid})
	if err != nil {
		t.Fatalf("List by user: %v", err)
	}
	if byUser.Total != 1 || len(byUser.Data) != 1 || byUser.Data[0].ClientIP != "10.0.0.1" {
		t.Fatalf("by user = total %d, rows %d", byUser.Total, len(byUser.Data))
	}
	other := uint(9)
	if r, err := svc.List(&CommandAlertFilter{UserID: &other}); err != nil || r.Total != 0 {
		t.Fatalf("session 的 user_id 不得當成告警主體：total=%d err=%v", r.Total, err)
	}
	byAsset, err := svc.List(&CommandAlertFilter{AssetID: &asset, Severity: "high", Unreviewed: true})
	if err != nil || byAsset.Total != 1 {
		t.Fatalf("List by asset: total=%d err=%v", byAsset.Total, err)
	}
}

func TestCommandAlertSessionBlockedFilters(t *testing.T) {
	svc, db := setupAlertDB(t)
	first := seedAlert(t, db, "ssh 10.0.0.9")
	if err := db.Model(first).Update("blocked", true).Error; err != nil {
		t.Fatal(err)
	}
	second := seedAlert(t, db, "echo safe")
	third := seedAlert(t, db, "blocked elsewhere")
	if err := db.Model(third).Updates(map[string]any{"session_id": 2, "blocked": true}).Error; err != nil {
		t.Fatal(err)
	}
	sessionID := uint(1)
	blocked := true
	result, err := svc.List(&CommandAlertFilter{SessionID: &sessionID, Blocked: &blocked})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(result.Data) != 1 || result.Data[0].ID != first.ID {
		t.Fatalf("session AND blocked = %+v", result)
	}
	row := result.Data[0]
	if row.SessionID != 1 || !row.Blocked || row.RuleName == "" || row.Command != "ssh 10.0.0.9" || row.TriggeredAt.IsZero() {
		t.Fatalf("alert projection = %+v", row)
	}
	blocked = false
	result, err = svc.List(&CommandAlertFilter{SessionID: &sessionID, Blocked: &blocked})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || result.Data[0].ID != second.ID {
		t.Fatalf("blocked=false = %+v", result)
	}
}
