package identity

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// 特權登入時的角色指派比對（role-assignment-integrity task 3.4，第三個比對時機）。
//
// 兩件事要同時成立，缺一即為缺陷：
//   - admin／auditor 登入時比對**確實發生**，且**權杖照發**（不阻斷）。
//   - 一般使用者登入**完全不比對**——不是「比對了但很快」，是登入路徑
//     一次額外查詢都沒有。以查詢計數斷言，因為「有沒有多查」用眼睛看不出來。

// countingProbe 記錄比對次數的替身
type countingProbe struct{ calls int }

func (p *countingProbe) ReconcileOnPrivilegedLogin(ctx context.Context) { p.calls++ }

// queryCounter 掛在 gorm 上的查詢計數器
type queryCounter struct{ n int }

func (q *queryCounter) attach(t *testing.T, db *gorm.DB) {
	t.Helper()
	inc := func(tx *gorm.DB) { q.n++ }
	if err := db.Callback().Query().After("gorm:query").Register("rolestate:count", inc); err != nil {
		t.Fatalf("掛查詢計數器: %v", err)
	}
	if err := db.Callback().Row().After("gorm:row").Register("rolestate:count_row", inc); err != nil {
		t.Fatalf("掛列計數器: %v", err)
	}
}

// seedLoginUser 建立可登入的帳號並配角色
func seedLoginUser(t *testing.T, db *gorm.DB, username, roleName string) *model.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("right-pass-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	u := &model.User{Username: username, Password: string(hash), Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建帳號: %v", err)
	}
	var role model.Role
	if err := db.Where("name = ?", roleName).First(&role).Error; err != nil {
		role = model.Role{Name: roleName}
		if err := db.Create(&role).Error; err != nil {
			t.Fatalf("建角色: %v", err)
		}
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		return model.AssignUserRole(tx, u.ID, role.ID, model.RoleOriginRegister)
	}); err != nil {
		t.Fatalf("配角色: %v", err)
	}
	return u
}

// TestLoginRoleStateCheckedForPrivilegedRoles admin 與 auditor 登入即比對，
// 且權杖照發
func TestLoginRoleStateCheckedForPrivilegedRoles(t *testing.T) {
	for _, roleName := range []string{model.RoleAdmin, model.RoleAuditor} {
		t.Run(roleName, func(t *testing.T) {
			db := setupRoleAuditDB(t)
			auth := NewAuthService("secret", 15*time.Minute)
			probe := &countingProbe{}
			auth.SetRoleStateProbe(probe)
			seedLoginUser(t, db, "priv-"+roleName, roleName)

			resp, err := auth.Login(&LoginRequest{Username: "priv-" + roleName, Password: "right-pass-1"})
			if err != nil {
				t.Fatalf("登入: %v", err)
			}
			if probe.calls != 1 {
				t.Fatalf("比對次數 = %d, want 1", probe.calls)
			}
			if resp.Token == "" {
				t.Fatal("權杖未發出：比對不得阻斷登入——擋掉管理者的代價是" +
					"正在發生提權時沒有人進得來處理")
			}
		})
	}
}

// TestLoginRoleStateSkippedForOrdinaryUser 一般使用者登入不比對、不多查一次
func TestLoginRoleStateSkippedForOrdinaryUser(t *testing.T) {
	db := setupRoleAuditDB(t)
	seedLoginUser(t, db, "plain", model.RoleUser)
	counter := &queryCounter{}
	counter.attach(t, db)

	// 基準：未接比對面的登入查詢次數
	baseAuth := NewAuthService("secret", 15*time.Minute)
	if _, err := baseAuth.Login(&LoginRequest{Username: "plain", Password: "right-pass-1"}); err != nil {
		t.Fatalf("基準登入: %v", err)
	}
	baseline := counter.n
	if baseline == 0 {
		t.Fatal("基準查詢次數為 0：計數器沒掛上，本測試的綠燈沒有意義")
	}

	// 接上比對面之後，同一條路徑的查詢次數必須逐次相同
	counter.n = 0
	auth := NewAuthService("secret", 15*time.Minute)
	probe := &countingProbe{}
	auth.SetRoleStateProbe(probe)
	if _, err := auth.Login(&LoginRequest{Username: "plain", Password: "right-pass-1"}); err != nil {
		t.Fatalf("登入: %v", err)
	}
	if probe.calls != 0 {
		t.Fatalf("一般使用者登入執行了 %d 次比對, want 0", probe.calls)
	}
	if counter.n != baseline {
		t.Fatalf("查詢次數 = %d, 基準 = %d：一般使用者的登入路徑不得多任何一次查詢",
			counter.n, baseline)
	}
}

// TestLoginRoleStateOpensMismatchEventWithRealReconciler 特權登入時的比對
// **以真對帳器**跑完整條路徑：直寫提權 → 登入 → `audit_failure_events` 真的
// 多一筆 role_state_mismatch，且其起點與該次登入的審計列對得上時間；權杖照發。
//
// # 為什麼假 probe 不夠
//
// 上面兩支以 `countingProbe` 斷言「比對發生了幾次」，那是登入路徑這一端的事實。
// 「比對真的會開出事件」則落在對帳器那一端的測試裡。兩段之間靠「產品組裝時
// probe 就是對帳器」這個**裝配事實**連接，而裝配事實沒有測試釘住：介面換一個
// 只會計數不會開單的實作、或注入被拿掉，兩端的測試都照樣綠，稽核面卻再也不會
// 在提權者登入的當下看到任何東西。
//
// 時間對得上是 spec 的一半：稽核者要能把「這個帳號在這一刻登入」與
// 「這一刻開出的角色指派不符」放在同一條時間線上讀
func TestLoginRoleStateOpensMismatchEventWithRealReconciler(t *testing.T) {
	db := setupRoleAuditDB(t)
	if err := db.AutoMigrate(&model.AuditCheckpoint{}, &model.AuditFailureEvent{},
		&model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	admin := seedLoginUser(t, db, "admin-real", model.RoleAdmin)
	seedRoleStateBaseline(t, db)

	failures := audit.InitAuditFailure(db, policy.NewSecurityPolicyService(db))
	rec := audit.NewRoleStateReconciler(db, failures)
	auth := NewAuthService("secret", 15*time.Minute)
	auth.SetRoleStateProbe(rec)

	// 前置：直寫之前對帳是相符的（少了它，一個恆回不符的對帳器也會讓本測試綠）
	if report, err := rec.Reconcile(context.Background()); err != nil {
		t.Fatalf("前置對帳: %v", err)
	} else if report.State != "match" {
		t.Fatalf("直寫前對帳 = %s, want match（missing=%v extra=%v）",
			report.State, report.Missing, report.Extra)
	}
	if n := failureEventCount(t, db); n != 0 {
		t.Fatalf("前置失效事件筆數 = %d, want 0", n)
	}

	// 原生 SQL 直寫提權：把管理者角色掛到一個從未經過應用程式的帳號上
	var adminRole model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
		t.Fatalf("讀管理者角色: %v", err)
	}
	if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
		4242, adminRole.ID).Error; err != nil {
		t.Fatalf("直寫提權: %v", err)
	}

	beforeLogin := time.Now()
	resp, err := auth.Login(&LoginRequest{Username: admin.Username, Password: "right-pass-1"})
	if err != nil {
		t.Fatalf("登入: %v", err)
	}
	// 登入的審計列由 API 層在 Login 回來之後落下；本測試在同一時點以同樣形狀補一列
	loginRow := &model.AuditLog{
		Action: model.ActionLogin, Resource: model.ResourceAuth, Status: model.StatusSuccess,
		UserID: admin.ID, Username: admin.Username,
	}
	if err := db.Create(loginRow).Error; err != nil {
		t.Fatalf("落登入審計列: %v", err)
	}
	afterLogin := time.Now()

	if resp.Token == "" {
		t.Fatal("權杖未發出：比對不得阻斷登入")
	}

	var events []model.AuditFailureEvent
	if err := db.Order("id ASC").Find(&events).Error; err != nil {
		t.Fatalf("讀失效事件: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("失效事件筆數 = %d, want 1：登入時的比對必須真的開單，"+
			"不是只呼叫一個計數器", len(events))
	}
	ev := events[0]
	if ev.Mechanism != model.MechanismRoleStateIntegrity ||
		ev.CauseCode != model.CauseRoleStateMismatch {
		t.Fatalf("事件 = %s/%s, want %s/%s", ev.Mechanism, ev.CauseCode,
			model.MechanismRoleStateIntegrity, model.CauseRoleStateMismatch)
	}
	if !strings.Contains(ev.CauseParams, "4242/") {
		t.Errorf("cause_params = %q，未帶直寫進來的那一筆差集", ev.CauseParams)
	}

	// 時間對得上：事件起點落在本次登入的區間內，且與登入審計列相差不到一秒
	if ev.StartedAt.Before(beforeLogin.Add(-time.Second)) || ev.StartedAt.After(afterLogin.Add(time.Second)) {
		t.Fatalf("事件起點 %s 不在本次登入區間 [%s, %s] 內",
			ev.StartedAt, beforeLogin, afterLogin)
	}
	if d := ev.StartedAt.Sub(loginRow.CreatedAt); d > time.Second || d < -time.Second {
		t.Fatalf("事件起點與登入審計列相差 %s, want ≤1s：稽核者要能把兩者"+
			"放在同一條時間線上讀", d)
	}
}

// seedRoleStateBaseline 落一個對帳可用的基準檢查點（快照＝現行 user_roles、
// 封章當下對帳相符）
func seedRoleStateBaseline(t *testing.T, db *gorm.DB) {
	t.Helper()
	snap, err := audit.SnapshotUserRoles(context.Background(), db)
	if err != nil {
		t.Fatalf("取快照: %v", err)
	}
	var maxID uint
	if err := db.Raw("SELECT COALESCE(MAX(id), 0) FROM audit_logs").Scan(&maxID).Error; err != nil {
		t.Fatalf("取審計列上界: %v", err)
	}
	body := `{"user_roles":` + string(snap.Body) + `}`
	reconciled := true
	cp := model.AuditCheckpoint{
		Seq: 1, IDFrom: 1, IDTo: maxID, RowCount: int64(maxID),
		AggHash: "baseline", AggScheme: model.AggSchemeV2, PrevCheckpointHash: "genesis",
		SealedAt: time.Now(), SigningKeyVersion: 1, Signature: "test",
		AnchorStatus:      model.AnchorStatusEnqueued,
		RoleStateSnapshot: &body, RoleStateHash: &snap.Hash, RoleStateCount: &snap.Count,
		RoleStateReconciled: &reconciled,
	}
	if err := db.Create(&cp).Error; err != nil {
		t.Fatalf("落基準檢查點: %v", err)
	}
}

// failureEventCount 目前的失效事件筆數
func failureEventCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AuditFailureEvent{}).Count(&n).Error; err != nil {
		t.Fatalf("計數失效事件: %v", err)
	}
	return n
}
