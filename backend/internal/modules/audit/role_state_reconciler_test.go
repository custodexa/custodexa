package audit

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 角色指派對帳（role-assignment-integrity task 3.2）。
//
// 每個情境都以**原生 SQL 直寫**製造竄改：威脅模型明載對手可直寫資料庫，
// 經 ORM 造出來的竄改只證明守衛擋得住守衛擋得住的東西。
// 合法變更則一律走 `model.AssignUserRole`／`RevokeUserRole`——測試若自己
// 手寫審計列，就等於在測「我寫的假事件能不能被我自己重放」，而不是
// 「產品的留痕路徑推不推得回現況」。

// fakeFailure 記錄開單與結案，供冪等與「不開單」的斷言
type fakeFailure struct {
	reports  []map[string]string
	causes   []string
	resolved int
}

func (f *fakeFailure) ReportWithCounts(mechanism, causeCode string,
	params map[string]string, _ map[string]int) {
	f.causes = append(f.causes, mechanism+"/"+causeCode)
	f.reports = append(f.reports, params)
}

func (f *fakeFailure) Resolve(mechanism string) { f.resolved++ }

// NotifyOngoing 對帳器不用（進行中提醒是鏈驗證編排者的路徑）；
// 被呼叫即代表出口的用法變了，讓測試立刻說出來而不是靜默通過
func (f *fakeFailure) NotifyOngoing(notifycat.Event, map[string]string) {
	panic("角色指派對帳器不應呼叫 NotifyOngoing")
}

// roleFixture 對帳測試的裝配：一條真的鏈（genesis 已封）＋對帳器
type roleFixture struct {
	*verifyFixture
	failure *fakeFailure
	rec     *RoleStateReconciler
}

func setupRoleFixture(t *testing.T) *roleFixture {
	t.Helper()
	f := setupVerifyFixture(t)
	failure := &fakeFailure{}
	return &roleFixture{verifyFixture: f, failure: failure,
		rec: NewRoleStateReconciler(f.db, failure)}
}

// sealWithRoles 以現行 user_roles 封一個含快照的檢查點，回傳其 seq
func (f *roleFixture) sealWithRoles(t *testing.T) uint {
	t.Helper()
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("封章: %v", err)
	}
	if cp.RoleStateSnapshot == nil {
		t.Fatalf("封出的檢查點 seq=%d 無狀態快照：對帳的前提不成立", cp.Seq)
	}
	return cp.Seq
}

// legalAssign／legalRevoke 走產品的唯一寫入面（同交易留痕）
func (f *roleFixture) legalAssign(t *testing.T, userID, roleID uint) {
	t.Helper()
	if err := f.db.Transaction(func(tx *gorm.DB) error {
		return model.AssignUserRole(tx, userID, roleID, model.RoleOriginAPI)
	}); err != nil {
		t.Fatalf("合法指派: %v", err)
	}
}

func (f *roleFixture) legalRevoke(t *testing.T, userID, roleID uint) {
	t.Helper()
	if err := f.db.Transaction(func(tx *gorm.DB) error {
		return model.RevokeUserRole(tx, userID, roleID, model.RoleOriginAPI)
	}); err != nil {
		t.Fatalf("合法移除: %v", err)
	}
}

func (f *roleFixture) reconcile(t *testing.T) *RoleStateReport {
	t.Helper()
	report, err := f.rec.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("對帳: %v", err)
	}
	return report
}

// TestRoleStateReconcileDetectsDirectGrant 直寫提權被指出
func TestRoleStateReconcileDetectsDirectGrant(t *testing.T) {
	f := setupRoleFixture(t)
	f.legalAssign(t, 1, 1)
	seq := f.sealWithRoles(t)

	// 前置：封章當下相符（少了這個斷言，一個恆回不符的對帳器也會讓本測試綠）
	if got := f.reconcile(t); got.State != RoleStateMatch {
		t.Fatalf("竄改前狀態 = %s, want match（差集 missing=%v extra=%v）",
			got.State, got.Missing, got.Extra)
	}

	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 7, 1)
	report := f.reconcile(t)
	if report.State != RoleStateMismatch {
		t.Fatalf("狀態 = %s, want mismatch", report.State)
	}
	if report.SinceSeq != seq {
		t.Errorf("since_seq = %d, want %d", report.SinceSeq, seq)
	}
	if len(report.Extra) != 1 || report.Extra[0] != (RolePair{UserID: 7, RoleID: 1}) {
		t.Fatalf("多出集合 = %v, want [{7 1}]", report.Extra)
	}
	if len(report.Missing) != 0 {
		t.Errorf("缺少集合 = %v, want 空", report.Missing)
	}
	if report.ExpectedHash == report.ActualHash {
		t.Error("預期與現況雜湊相同：差集非空時雜湊必不同")
	}
	if len(f.failure.causes) != 1 ||
		f.failure.causes[0] != model.MechanismRoleStateIntegrity+"/"+model.CauseRoleStateMismatch {
		t.Fatalf("失效事件 = %v, want 一筆 role_state_integrity/role_state_mismatch", f.failure.causes)
	}
	if got := f.failure.reports[0]["extra"]; got != "7/1" {
		t.Errorf("事件 extra 參數 = %q, want \"7/1\"", got)
	}
}

// TestRoleStateReconcileDetectsDirectRevoke 直寫移除被指出
func TestRoleStateReconcileDetectsDirectRevoke(t *testing.T) {
	f := setupRoleFixture(t)
	f.legalAssign(t, 3, 2)
	f.sealWithRoles(t)

	f.mustExec(t, "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", 3, 2)
	report := f.reconcile(t)
	if report.State != RoleStateMismatch {
		t.Fatalf("狀態 = %s, want mismatch", report.State)
	}
	if len(report.Missing) != 1 || report.Missing[0] != (RolePair{UserID: 3, RoleID: 2}) {
		t.Fatalf("缺少集合 = %v, want [{3 2}]", report.Missing)
	}
	if len(f.failure.causes) != 1 {
		t.Fatalf("失效事件筆數 = %d, want 1", len(f.failure.causes))
	}
}

// TestRoleStateReconcileLegalChangesDoNotAlert 合法變更不觸發。
//
// **這是假警報射程的測試**：封章之後經產品路徑指派與移除，對帳必須靠審計列
// 把預期集合推到與現況相同。突變自檢 3.3 拿掉「套用審計列」這一步時本測試轉紅
func TestRoleStateReconcileLegalChangesDoNotAlert(t *testing.T) {
	f := setupRoleFixture(t)
	f.legalAssign(t, 1, 1)
	f.legalAssign(t, 2, 3)
	f.sealWithRoles(t)

	// 封章之後的合法變更：新增兩筆、移除一筆
	f.legalAssign(t, 4, 1)
	f.legalAssign(t, 4, 2)
	f.legalRevoke(t, 2, 3)

	report := f.reconcile(t)
	if report.State != RoleStateMatch {
		t.Fatalf("狀態 = %s, want match（missing=%v extra=%v）",
			report.State, report.Missing, report.Extra)
	}
	if report.ExpectedHash != report.ActualHash {
		t.Errorf("預期雜湊 %s ≠ 現況雜湊 %s：相符時兩者必須逐位元組相同",
			report.ExpectedHash, report.ActualHash)
	}
	if len(f.failure.causes) != 0 {
		t.Fatalf("合法變更開了失效事件 %v：假警報會讓真警報失去意義", f.failure.causes)
	}
}

// TestRoleStateReconcileIdempotentEvent 同一不符只開一筆
func TestRoleStateReconcileIdempotentEvent(t *testing.T) {
	f := setupRoleFixture(t)
	f.legalAssign(t, 1, 1)
	f.sealWithRoles(t)
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 8, 1)

	for i := 0; i < 3; i++ {
		if got := f.reconcile(t); got.State != RoleStateMismatch {
			t.Fatalf("第 %d 次對帳狀態 = %s, want mismatch", i+1, got.State)
		}
	}
	if len(f.failure.causes) != 1 {
		t.Fatalf("失效事件筆數 = %d, want 1：同一 (since_seq, actual_hash) 只開一筆",
			len(f.failure.causes))
	}

	// 第二筆**不同的**不符（現況雜湊變了）必須開新單，
	// 否則第一件事未結案期間發生的第二件事會完全靜默
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 9, 1)
	f.reconcile(t)
	if len(f.failure.causes) != 2 {
		t.Fatalf("第二種不符後事件筆數 = %d, want 2", len(f.failure.causes))
	}

	// 回復到相符即結案
	f.mustExec(t, "DELETE FROM user_roles WHERE user_id IN (8, 9)")
	if got := f.reconcile(t); got.State != RoleStateMatch {
		t.Fatalf("回復後狀態 = %s, want match", got.State)
	}
	if f.failure.resolved == 0 {
		t.Error("回復相符未結案：失效區間的結束端證據會永久破損")
	}
}

// TestRoleStateReconcileNotCoveredBeforeFirstSnapshot 尚未涵蓋不開單
func TestRoleStateReconcileNotCoveredBeforeFirstSnapshot(t *testing.T) {
	f := setupRoleFixture(t)
	// 把鏈上所有檢查點的快照欄清空＝升級後、首個含快照的封章之前
	f.mustExec(t, "UPDATE audit_checkpoints SET role_state_snapshot = NULL")
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 5, 1)

	report := f.reconcile(t)
	if report.Covered {
		t.Error("covered = true, want false")
	}
	if report.State != RoleStateNotCovered {
		t.Fatalf("狀態 = %s, want not_covered", report.State)
	}
	if len(f.failure.causes) != 0 {
		t.Fatalf("尚未涵蓋卻開了事件 %v：沒有基準不等於不符", f.failure.causes)
	}
	if f.failure.resolved != 0 {
		t.Error("尚未涵蓋卻結案：未知不是相符")
	}
}

// TestRoleStateReconcileIgnoresUnrelatedAuditRows 只重放 user_role 資源的列。
//
// 對帳把審計列當狀態機的事件流重放，混進別的資源（帳號建立、改名）
// 就會讀到不是狀態變更的東西
func TestRoleStateReconcileIgnoresUnrelatedAuditRows(t *testing.T) {
	f := setupRoleFixture(t)
	f.legalAssign(t, 1, 1)
	f.sealWithRoles(t)

	details, _ := json.Marshal(model.UserRoleAuditDetails{
		Resource: "user", UserID: 6, RoleID: 1, Origin: model.RoleOriginAPI,
	})
	if err := f.db.Create(&model.AuditLog{
		Action: model.ActionAssign, Resource: model.ResourceUser, Status: model.StatusSuccess,
		UserID: 1, Username: "admin", Details: string(details),
	}).Error; err != nil {
		t.Fatalf("寫入無關列: %v", err)
	}
	if got := f.reconcile(t); got.State != RoleStateMatch {
		t.Fatalf("狀態 = %s, want match：resource=user 的列不是角色指派事件", got.State)
	}
}

// TestSealRecordsRoleStateReconciled 封章記錄對帳結果（三態）
func TestSealRecordsRoleStateReconciled(t *testing.T) {
	f := setupRoleFixture(t)
	f.seal.SetRoleStateReconciler(f.rec)

	// 第一個含快照的檢查點：genesis 已封（無基準），此點對帳得到基準
	f.legalAssign(t, 1, 1)
	first := f.sealWithRoles(t)
	firstRow := f.checkpointBySeq(t, first)
	if firstRow.RoleStateReconciled == nil || !*firstRow.RoleStateReconciled {
		t.Fatalf("seq=%d 的 role_state_reconciled = %v, want true（基準為 genesis 的快照）",
			first, firstRow.RoleStateReconciled)
	}

	// 直寫提權後再封一次：檢查點照現況封章，但結果記 false
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 9, 9)
	second := f.sealWithRoles(t)
	secondRow := f.checkpointBySeq(t, second)
	if secondRow.RoleStateReconciled == nil || *secondRow.RoleStateReconciled {
		t.Fatalf("seq=%d 的 role_state_reconciled = %v, want false", second, secondRow.RoleStateReconciled)
	}
	if len(f.failure.causes) != 1 {
		t.Fatalf("封章時的失效事件筆數 = %d, want 1（不符照開事件）", len(f.failure.causes))
	}
}

// TestVerifyChainReportsRoleState 驗證端點與排程自動驗證共用的路徑帶對帳結果
func TestVerifyChainReportsRoleState(t *testing.T) {
	f := setupRoleFixture(t)
	f.legalAssign(t, 1, 1)
	f.sealWithRoles(t)

	// 未接對帳器：報告不附帶（nil ≠ 相符）
	report, err := f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("驗證: %v", err)
	}
	if report.RoleState != nil {
		t.Fatalf("未接對帳器時 role_state = %+v, want nil", report.RoleState)
	}

	f.verifier.SetRoleStateReconciler(f.rec)
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 6, 2)
	report, err = f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("驗證: %v", err)
	}
	if report.RoleState == nil || report.RoleState.State != RoleStateMismatch {
		t.Fatalf("role_state = %+v, want mismatch", report.RoleState)
	}
	// 鏈本身照樣通過：檢查點一個字都沒被動，不符是由對帳指出的
	if report.Status != IntervalStatusPassed {
		t.Errorf("鏈狀態 = %s, want passed（直寫狀態表不改變已封的簽章）", report.Status)
	}
	if len(f.failure.causes) != 1 {
		t.Fatalf("驗證時的失效事件筆數 = %d, want 1", len(f.failure.causes))
	}
}

// checkpointBySeq 重讀落庫後的檢查點列
func (f *roleFixture) checkpointBySeq(t *testing.T, seq uint) model.AuditCheckpoint {
	t.Helper()
	var cp model.AuditCheckpoint
	if err := f.db.Where("seq = ?", seq).First(&cp).Error; err != nil {
		t.Fatalf("讀檢查點 seq=%d: %v", seq, err)
	}
	return cp
}

// TestAutoVerifyRunsRoleStateReconcile 排程自動驗證也做對帳。
//
// **單獨成測**：兩個比對時機（驗證端點、排程自動驗證）共走 VerifyChain，
// 而「共走」是一個實作事實，不是被測過的承諾——編排者哪天改成自己組報告，
// 排程這一路就會靜默地不再對帳
func TestAutoVerifyRunsRoleStateReconcile(t *testing.T) {
	f := setupChainVerifyFixture(t)
	failure := &fakeFailure{}
	rec := NewRoleStateReconciler(f.db, failure)
	f.verifier.SetRoleStateReconciler(rec)
	f.sealIntervals(t, 1, 2)
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 11, 1)

	if err := f.svc.RunRecentNow(context.Background()); err != nil {
		t.Fatalf("排程近期層: %v", err)
	}
	if len(failure.causes) != 1 ||
		failure.causes[0] != model.MechanismRoleStateIntegrity+"/"+model.CauseRoleStateMismatch {
		t.Fatalf("排程自動驗證未開角色指派失效事件: %v", failure.causes)
	}
}

// TestRoleStateBaselineSkipsUnreconciledCheckpoint 封章時不符的檢查點不得成為基準。
//
// # 這條測試擋的攻擊
//
// 直寫提權之後，攻擊者什麼都不必再做——只要等下一次自動封章。那次封章會把
// **含提權的現況**寫進 role_state_snapshot。若對帳的基準只取「最近一個含快照的
// 檢查點」，下一次對帳就會拿這張含提權的快照當預期集合，於是驗證頁回「相符」，
// 而那筆從未經過應用程式的指派安安穩穩地留在表裡。
//
// 封章當下的對帳結果（role_state_reconciled）正是用來分辨這件事的：false ＝
// 這個點的快照裡有未經留痕的內容，它不能當任何東西的基準。
func TestRoleStateBaselineSkipsUnreconciledCheckpoint(t *testing.T) {
	f := setupRoleFixture(t)
	f.seal.SetRoleStateReconciler(f.rec)

	f.legalAssign(t, 1, 1)
	good := f.sealWithRoles(t)
	goodRow := f.checkpointBySeq(t, good)
	if goodRow.RoleStateReconciled == nil || !*goodRow.RoleStateReconciled {
		t.Fatalf("前置不成立：seq=%d 的 role_state_reconciled = %v, want true",
			good, goodRow.RoleStateReconciled)
	}

	// 直寫提權；此刻對帳應指向 good
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 7, 1)
	if got := f.reconcile(t); got.State != RoleStateMismatch || got.SinceSeq != good {
		t.Fatalf("封章前對帳 = %s（since=%d）, want mismatch（since=%d）",
			got.State, got.SinceSeq, good)
	}

	// 攻擊者什麼也不做，等下一次封章把提權態封進快照
	tainted := f.sealWithRoles(t)
	taintedRow := f.checkpointBySeq(t, tainted)
	if taintedRow.RoleStateReconciled == nil || *taintedRow.RoleStateReconciled {
		t.Fatalf("前置不成立：seq=%d 的 role_state_reconciled = %v, want false",
			tainted, taintedRow.RoleStateReconciled)
	}
	if taintedRow.RoleStateSnapshot == nil {
		t.Fatalf("前置不成立：seq=%d 無快照", tainted)
	}

	after := f.reconcile(t)
	if after.State != RoleStateMismatch {
		t.Fatalf("封章後對帳 = %s, want mismatch：封章時不符的檢查點不得洗白提權",
			after.State)
	}
	if after.SinceSeq != good {
		t.Fatalf("since_seq = %d, want %d（最後一個對帳相符的檢查點）", after.SinceSeq, good)
	}
	if len(after.Extra) != 1 || after.Extra[0] != (RolePair{UserID: 7, RoleID: 1}) {
		t.Fatalf("多出集合 = %v, want [{7 1}]", after.Extra)
	}

	// 移除提權後回到相符，且基準回到最新的相符檢查點（不永久卡在 good）
	f.mustExec(t, "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", 7, 1)
	healed := f.sealWithRoles(t)
	if got := f.reconcile(t); got.State != RoleStateMatch || got.SinceSeq != healed {
		t.Fatalf("修復後對帳 = %s（since=%d）, want match（since=%d）",
			got.State, got.SinceSeq, healed)
	}
}

// TestRoleStateBaselineIgnoresSnapshotAfterTaintedSeal 已知不符之後的
// 「沒做對帳」檢查點同樣不得當基準。
//
// role_state_reconciled 為 nil 表示那次封章沒有做出判讀（對帳讀不到基準或出錯），
// 不是判讀通過。在一個已知不符的區間之後，把「不知道」當成可信基準，
// 效果與把 false 當基準一樣：提權被洗白
func TestRoleStateBaselineIgnoresSnapshotAfterTaintedSeal(t *testing.T) {
	f := setupRoleFixture(t)
	f.seal.SetRoleStateReconciler(f.rec)
	anchor := f.sealWithRoles(t) // 第一個含快照且有對帳器的檢查點（基準為 genesis）

	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 7, 1)
	tainted := f.sealWithRoles(t) // reconciled = false
	if row := f.checkpointBySeq(t, tainted); row.RoleStateReconciled == nil || *row.RoleStateReconciled {
		t.Fatalf("前置不成立：seq=%d 應記 false", tainted)
	}

	// 模擬「對帳未能完成」的封章：快照照落，結果留 nil
	f.seal.SetRoleStateReconciler(nil)
	unknown := f.sealWithRoles(t)
	if row := f.checkpointBySeq(t, unknown); row.RoleStateReconciled != nil {
		t.Fatalf("前置不成立：seq=%d 應記 nil", unknown)
	}

	after := f.reconcile(t)
	if after.State != RoleStateMismatch {
		t.Fatalf("對帳 = %s, want mismatch：不符之後的未判讀檢查點不得當基準", after.State)
	}
	if after.SinceSeq != anchor {
		t.Fatalf("since_seq = %d, want %d", after.SinceSeq, anchor)
	}
}
