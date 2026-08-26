package identity

import (
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sourceip"
)

// 服務層的來源限定：refresh 的零寫入路徑，與政策不可用的降級／恢復。
//
// # 為何 refresh 要單獨一組
//
// 其餘十七個判定點的形狀是「拒絕並回 403」；refresh 的形狀是
// 「拒絕、回統一 401、**而且一個位元組都不寫**」。後者的價值不在拒絕本身，
// 在於「憑證沒有被消耗」——判定若落在輪替之後，持竊憑證者自清單外打一次
// refresh 就能讓受害者下次刷新命中 reuse detection、整個家族被撤，
// 等於攻擊者拿到一個免費的登出原語。那條缺陷用「有沒有被拒絕」測不出來。

const (
	srcPolicyInside  = "203.0.113.0/24"
	srcPolicyOutside = "10.0.0.0/8"
	srcPolicyIP      = "203.0.113.5"
	srcPolicyCorrupt = "10.0.0.0/8,not-a-cidr"
)

// resetSourcePolicyState 還原包級失效旗標與失效服務單例。
//
// 包級狀態跨測試殘留會讓「單獨跑綠、整包跑紅」重演，且方向不可預測
// ——旗標為真時恢復謂詞會多掃一次全表，為假時 Resolve 直接 no-op。
func resetSourcePolicyState(t *testing.T) {
	t.Helper()
	sourcePolicyDegraded.Store(false)
	t.Cleanup(func() {
		sourcePolicyDegraded.Store(false)
		audit.ResetAuditFailureSingleton()
	})
}

// setSourcePolicyRaw 直寫使用者的允許來源網段（損壞態按定義造不出於 service 層）
func setSourcePolicyRaw(t *testing.T, db *gorm.DB, userID uint, raw string) {
	t.Helper()
	if err := db.Model(&model.User{}).Where("id = ?", userID).
		Update("allowed_cidrs", raw).Error; err != nil {
		t.Fatalf("set allowed_cidrs=%q: %v", raw, err)
	}
}

// refreshRow 讀回目前唯一未撤銷的 refresh 列（斷言「未被消耗」的依據）
func refreshRows(t *testing.T, db *gorm.DB) []model.RefreshToken {
	t.Helper()
	var rows []model.RefreshToken
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("load refresh rows: %v", err)
	}
	return rows
}

// TestRefreshSourceDeniedDoesNotConsumeToken 盤點表 #9：清單外刷新被拒後，
// **同一枚憑證**自清單內刷新照常成功。
//
// 斷言四件事，缺一都讓那條缺陷得以存活：
//
//	(a) 拒絕時 refresh_tokens 的列數不變（沒插新列＝沒有孤兒憑證）
//	(b) 舊列的 revoked_at 仍為 null（沒撤舊＝憑證未被消耗）
//	(c) 舊列的 last_used_at 未變（連時間戳都沒動）
//	(d) 隨後自清單內刷新成功，且**不觸發家族撤銷**
func TestRefreshSourceDeniedDoesNotConsumeToken(t *testing.T) {
	resetSourcePolicyState(t)
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	first := loginForRefresh(t, auth, "bob", "right-pass-1")

	setSourcePolicyRaw(t, db, user.ID, srcPolicyOutside)
	before := refreshRows(t, db)
	if len(before) != 1 {
		t.Fatalf("前提不成立：登入後應恰有 1 枚 refresh 憑證，實得 %d", len(before))
	}

	_, err := auth.RefreshSession(first.RefreshToken, srcPolicyIP)
	var denied *RefreshSourceDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("清單外刷新 = %v, want RefreshSourceDeniedError", err)
	}
	if denied.UserID != user.ID || denied.Username != user.Username {
		t.Errorf("拒絕錯誤的主體 = (%d,%q), want (%d,%q)（審計列指不出是誰被擋）",
			denied.UserID, denied.Username, user.ID, user.Username)
	}
	if denied.Verdict.Reason != sourceip.ReasonSourceNotAllowed {
		t.Errorf("拒絕原因 = %q, want %q", denied.Verdict.Reason, sourceip.ReasonSourceNotAllowed)
	}
	if note := denied.AuditNote(); note == "" ||
		!containsAll(note, "refresh_source_not_allowed", srcPolicyIP, "10.0.0.0/8") {
		t.Errorf("審計註記未含原因碼／位址／清單快照：%q", note)
	}

	after := refreshRows(t, db)
	if len(after) != len(before) {
		t.Fatalf("(a) 拒絕路徑寫了新列：before=%d after=%d（孤兒憑證）", len(before), len(after))
	}
	if after[0].RevokedAt != nil {
		t.Fatalf("(b) 拒絕路徑撤了舊憑證——持竊憑證者因此得以消耗受害者的 token："+
			"revoked_reason=%q", after[0].RevokedReason)
	}
	if !after[0].LastUsedAt.Equal(before[0].LastUsedAt) {
		t.Errorf("(c) 拒絕路徑改了 last_used_at：before=%v after=%v",
			before[0].LastUsedAt, after[0].LastUsedAt)
	}

	// (d) 同一枚憑證自清單內刷新照常成功，且不觸發家族撤銷
	setSourcePolicyRaw(t, db, user.ID, srcPolicyInside)
	rotated, err := auth.RefreshSession(first.RefreshToken, srcPolicyIP)
	if err != nil {
		t.Fatalf("(d) 清單內刷新 = %v, want nil（前一次拒絕不得消耗憑證）", err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == first.RefreshToken {
		t.Fatalf("(d) 刷新未換發新憑證：%+v", rotated)
	}
	var reuse *RefreshReuseError
	if _, err := auth.RefreshSession(rotated.RefreshToken, srcPolicyIP); errors.As(err, &reuse) {
		t.Fatal("(d) 新憑證立刻被判為重放——前一次拒絕污染了家族狀態")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// TestRefreshCorruptPolicyDeniesWithoutConsuming 政策不可用處置：政策損壞於 refresh 點
// 同樣**不消耗**憑證，且原因碼是「政策不可讀」而非「來源不對」。
func TestRefreshCorruptPolicyDeniesWithoutConsuming(t *testing.T) {
	resetSourcePolicyState(t)
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	first := loginForRefresh(t, auth, "bob", "right-pass-1")

	setSourcePolicyRaw(t, db, user.ID, srcPolicyCorrupt)
	before := refreshRows(t, db)

	_, err := auth.RefreshSession(first.RefreshToken, srcPolicyIP)
	var denied *RefreshSourceDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("政策損壞的刷新 = %v, want RefreshSourceDeniedError", err)
	}
	if denied.Verdict.Reason != sourceip.ReasonPolicyUnreadable {
		t.Fatalf("原因碼 = %q, want %q（稽核要分得出「政策壞了」與「來源不對」）",
			denied.Verdict.Reason, sourceip.ReasonPolicyUnreadable)
	}
	if denied.Verdict.Cause != sourceip.CauseParseError {
		t.Errorf("成因 = %q, want %q", denied.Verdict.Cause, sourceip.CauseParseError)
	}
	after := refreshRows(t, db)
	if len(after) != len(before) || after[0].RevokedAt != nil {
		t.Fatal("政策損壞的拒絕路徑動了憑證狀態（應與來源拒絕同樣零寫入）")
	}
}

// TestSourcePolicyDegradationReportsAndResolves 政策不可用的降級訊號與恢復謂詞。
//
//	損壞 → audit_failure_events 出現 source_policy 的未結案列（cause 為解析失敗）
//	修好後重評估 → 該列結案
func TestSourcePolicyDegradationReportsAndResolves(t *testing.T) {
	resetSourcePolicyState(t)
	auth, policies, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	if err := db.AutoMigrate(&model.AuditFailureEvent{}); err != nil {
		t.Fatalf("migrate failure events: %v", err)
	}
	audit.InitAuditFailure(db, policies)

	setSourcePolicyRaw(t, db, user.ID, srcPolicyCorrupt)
	if _, err := auth.ReadSourcePolicy(user.ID); err != nil {
		t.Fatalf("讀取本身不應失敗（損壞的是內容，不是讀取）：%v", err)
	}

	open := sourcePolicyOpenEvent(t, db)
	if open == nil {
		t.Fatal("政策損壞未在失效面留下未結案列——降級沒有任何可見訊號")
	}
	if open.CauseCode != model.CauseSourcePolicyCorrupt {
		t.Errorf("cause_code = %q, want %q", open.CauseCode, model.CauseSourcePolicyCorrupt)
	}
	if open.Cause == "" {
		t.Error("cause 文案為空（notifycat 詞條缺失時失效面只剩一個碼）")
	}

	// 修好清單並重評估：列應結案
	setSourcePolicyRaw(t, db, user.ID, srcPolicyInside)
	EvaluateSourcePolicyHealth(db)
	if still := sourcePolicyOpenEvent(t, db); still != nil {
		t.Fatalf("清單修好後失效列仍未結案（started_at=%v）", still.StartedAt)
	}
}

// TestSourcePolicyReadErrorFailsClosed DB 讀取失敗 → 拒絕，**不出現放行路徑**。
//
// 注入方式是把 users 表改名：後續讀取必然回錯，而「注入點確實被走到」由
// 讀取回錯這件事本身證明（測試先斷言 err != nil，再斷言判定方向）。
func TestSourcePolicyReadErrorFailsClosed(t *testing.T) {
	resetSourcePolicyState(t)
	auth, policies, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	if err := db.AutoMigrate(&model.AuditFailureEvent{}); err != nil {
		t.Fatalf("migrate failure events: %v", err)
	}
	audit.InitAuditFailure(db, policies)

	if err := db.Exec("ALTER TABLE users RENAME TO users_hidden").Error; err != nil {
		t.Fatalf("注入讀取失敗: %v", err)
	}
	raw, err := auth.ReadSourcePolicy(user.ID)
	if err == nil {
		t.Fatal("注入點未生效：讀取仍成功，本測試對 fail-close 沒有任何證明力")
	}
	// **fail-close 的方向**：讀不到 ≠ 空清單放行
	v := sourceip.Evaluate(raw, err, srcPolicyIP)
	if v.Allowed {
		t.Fatal("讀取失敗被判為放行——限制設了等於沒設，而且沒有訊號")
	}
	if v.Reason != sourceip.ReasonPolicyUnreadable || v.Cause != sourceip.CauseReadError {
		t.Fatalf("判定 = (%q,%q), want (%q,%q)",
			v.Reason, v.Cause, sourceip.ReasonPolicyUnreadable, sourceip.CauseReadError)
	}
	open := sourcePolicyOpenEvent(t, db)
	if open == nil || open.CauseCode != model.CauseSourcePolicyUnreadable {
		t.Fatalf("讀取失敗未上報為 %q：%+v", model.CauseSourcePolicyUnreadable, open)
	}

	// 還原後恢復謂詞應結案（證明降級不是單向閂）
	if err := db.Exec("ALTER TABLE users_hidden RENAME TO users").Error; err != nil {
		t.Fatalf("還原: %v", err)
	}
	EvaluateSourcePolicyHealth(db)
	if still := sourcePolicyOpenEvent(t, db); still != nil {
		t.Fatalf("讀取恢復後失效列仍未結案（started_at=%v）", still.StartedAt)
	}
}

// TestSourcePolicyStartupScanOpensEventForCorruptRow 啟動掃描是**雙向**的：
// 啟動時就已存在損壞列 → 立刻開失效，不必等到有人登入。
func TestSourcePolicyStartupScanOpensEventForCorruptRow(t *testing.T) {
	resetSourcePolicyState(t)
	_, policies, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	if err := db.AutoMigrate(&model.AuditFailureEvent{}); err != nil {
		t.Fatalf("migrate failure events: %v", err)
	}
	audit.InitAuditFailure(db, policies)
	setSourcePolicyRaw(t, db, user.ID, srcPolicyCorrupt)

	EvaluateSourcePolicyHealth(db)
	if open := sourcePolicyOpenEvent(t, db); open == nil {
		t.Fatal("啟動掃描對既存的損壞列沒有任何訊號——那正是最需要被看見的時刻")
	}
}

// TestSourcePolicyEmptyListIsNotDegradation 空字串是「不限」，不是「不可用」。
//
// 反向斷言：把空當成損壞會讓**全部未設限的帳號**在啟動掃描時被判為政策失效，
// 失效面因此永遠亮著紅燈而沒有人再看它。
func TestSourcePolicyEmptyListIsNotDegradation(t *testing.T) {
	resetSourcePolicyState(t)
	_, policies, db := setupLockoutEnv(t)
	seedLockoutUser(t, db, "right-pass-1")
	if err := db.AutoMigrate(&model.AuditFailureEvent{}); err != nil {
		t.Fatalf("migrate failure events: %v", err)
	}
	audit.InitAuditFailure(db, policies)

	EvaluateSourcePolicyHealth(db)
	if open := sourcePolicyOpenEvent(t, db); open != nil {
		t.Fatalf("未設限的帳號被判為政策失效：%+v", open)
	}
	if !SourcePolicyParsable("") {
		t.Fatal("空字串應可解析（＝不限）")
	}
}

// TestUserServiceWriteReevaluatesSourcePolicy 清單成功寫入後重評估：
// 管理者修好損壞的那一列之後，失效事件自己結案，不必等重啟。
func TestUserServiceWriteReevaluatesSourcePolicy(t *testing.T) {
	resetSourcePolicyState(t)
	_, policies, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	if err := db.AutoMigrate(&model.AuditFailureEvent{}); err != nil {
		t.Fatalf("migrate failure events: %v", err)
	}
	audit.InitAuditFailure(db, policies)

	setSourcePolicyRaw(t, db, user.ID, srcPolicyCorrupt)
	EvaluateSourcePolicyHealth(db)
	if sourcePolicyOpenEvent(t, db) == nil {
		t.Fatal("前提不成立：損壞列應先開出失效")
	}

	users := NewUserService(db, nil)
	users.SetSecurityPolicies(policies)
	fixed := []string{srcPolicyInside}
	if _, _, err := users.Update(user.ID, &UpdateUserRequest{AllowedCIDRs: &fixed}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if still := sourcePolicyOpenEvent(t, db); still != nil {
		t.Fatalf("清單成功寫入後失效列未結案（started_at=%v）", still.StartedAt)
	}
}

// sourcePolicyOpenEvent 取 source_policy 機制目前未結案的失效列；無則 nil
func sourcePolicyOpenEvent(t *testing.T, db *gorm.DB) *model.AuditFailureEvent {
	t.Helper()
	var ev model.AuditFailureEvent
	err := db.Where("mechanism = ? AND ended_at IS NULL", model.MechanismSourcePolicy).
		First(&ev).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		t.Fatalf("query failure event: %v", err)
	}
	return &ev
}
