package audit

import (
	"encoding/json"
	"sort"
	"testing"

)

// 未登記的狀態表不參與比對（role-assignment-integrity spec「未登記的表不參與比對」）。
//
// # 為什麼要有這一組
//
// 登記清單已有結構守衛（`TestStateTableRegistryGuard`：登記一張表就必須同時有
// 快照測試與竄改矩陣列）。但那守衛盯的是**登記了什麼就得證明什麼**，不是
// **沒登記的東西不會被扯進來**。兩個方向的失敗長得完全不同：後者失敗的樣子是
// 一張沒有留痕路徑的表被拿去比對，而它的每一次合法變更都會變成一筆假警報——
// 假警報淹沒真警報，這條機制就沒有意義了。
//
// 本組以 `asset_authorizations`（下一期才會登記的表，spec 明列為 Non-Goal）
// 為載體，用**原生 SQL 直寫**製造變更，斷言封章指紋、對帳結果、失效事件
// 三處全都當它不存在。

// createUnregisteredTable 建一張未登記的狀態表（形狀比照 asset_authorizations 的樞紐部分）
func (f *roleFixture) createUnregisteredTable(t *testing.T) {
	t.Helper()
	f.mustExec(t, `CREATE TABLE IF NOT EXISTS asset_authorizations (
		id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, asset_id INTEGER NOT NULL)`)
}

// snapshotTables 取某檢查點快照欄內的表名（升冪）
func (f *roleFixture) snapshotTables(t *testing.T, seq uint) []string {
	t.Helper()
	cp := f.checkpointBySeq(t, seq)
	if cp.RoleStateSnapshot == nil {
		t.Fatalf("seq=%d 無快照欄", seq)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(*cp.RoleStateSnapshot), &m); err != nil {
		t.Fatalf("解析 seq=%d 的快照欄: %v", seq, err)
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// TestStateCoverageListsOnlyRegisteredTables 涵蓋清單（登記清單與檢查點快照欄）
// 只列 user_roles
func TestStateCoverageListsOnlyRegisteredTables(t *testing.T) {
	f := setupRoleFixture(t)
	f.createUnregisteredTable(t)
	f.mustExec(t, "INSERT INTO asset_authorizations (id, user_id, asset_id) VALUES (1, 1, 1)")
	f.legalAssign(t, 1, 1)
	seq := f.sealWithRoles(t)

	var registered []string
	for _, st := range StateTableRegistry() {
		registered = append(registered, st.Name)
	}
	if len(registered) != 1 || registered[0] != StateTableUserRoles {
		t.Fatalf("登記清單 = %v, want [%s]：新增登記項必須連同其寫入點的留痕與"+
			"竄改矩陣一起進來，不得只加一行登記", registered, StateTableUserRoles)
	}
	if got := f.snapshotTables(t, seq); len(got) != 1 || got[0] != StateTableUserRoles {
		t.Fatalf("檢查點 seq=%d 的快照欄涵蓋 %v, want [%s]：檢查點不得宣稱涵蓋"+
			"一張沒有留痕路徑的表", seq, got, StateTableUserRoles)
	}
}

// TestUnregisteredTableWriteDoesNotAffectReconcile 直寫未登記的表：
// 對帳、封章指紋、失效事件三處皆不受影響
func TestUnregisteredTableWriteDoesNotAffectReconcile(t *testing.T) {
	f := setupRoleFixture(t)
	f.seal.SetRoleStateReconciler(f.rec)
	f.verifier.SetRoleStateReconciler(f.rec)
	f.createUnregisteredTable(t)
	f.legalAssign(t, 1, 1)
	before := f.sealWithRoles(t)
	beforeRow := f.checkpointBySeq(t, before)
	if beforeRow.RoleStateHash == nil {
		t.Fatalf("前置不成立：seq=%d 無 role_state_hash", before)
	}

	// 前置：直寫之前是相符的（少了這一句，一個恆回相符的對帳器也會讓本測試綠）
	if got := f.reconcile(t); got.State != RoleStateMatch {
		t.Fatalf("直寫前狀態 = %s, want match", got.State)
	}

	// 原生 SQL 直寫一張未登記的表（新增、修改、刪除三種動作都試）
	f.mustExec(t, "INSERT INTO asset_authorizations (id, user_id, asset_id) VALUES (1, 7, 3)")
	f.mustExec(t, "UPDATE asset_authorizations SET asset_id = 99 WHERE id = 1")
	f.mustExec(t, "INSERT INTO asset_authorizations (id, user_id, asset_id) VALUES (2, 8, 4)")
	f.mustExec(t, "DELETE FROM asset_authorizations WHERE id = 2")

	report := f.reconcile(t)
	if report.State != RoleStateMatch {
		t.Fatalf("狀態 = %s, want match（missing=%v extra=%v）：未登記的表不參與比對",
			report.State, report.Missing, report.Extra)
	}
	if len(f.failure.causes) != 0 {
		t.Fatalf("直寫未登記的表開了失效事件 %v：那張表沒有留痕路徑，"+
			"比對它只會產出假警報", f.failure.causes)
	}

	// 驗證端點走的同一條路徑同樣不受影響
	chain, err := f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("驗證: %v", err)
	}
	if chain.RoleState == nil || chain.RoleState.State != RoleStateMatch {
		t.Fatalf("驗證報告 role_state = %+v, want match", chain.RoleState)
	}
	if chain.Status != IntervalStatusPassed {
		t.Errorf("鏈狀態 = %s, want passed", chain.Status)
	}

	// 下一個檢查點的角色指派指紋逐位元組不變，且對帳結果記 true
	after := f.sealWithRoles(t)
	afterRow := f.checkpointBySeq(t, after)
	if afterRow.RoleStateHash == nil || *afterRow.RoleStateHash != *beforeRow.RoleStateHash {
		t.Fatalf("role_state_hash 由 %v 變為 %v：未登記的表不得改變檢查點指紋",
			*beforeRow.RoleStateHash, afterRow.RoleStateHash)
	}
	if afterRow.RoleStateReconciled == nil || !*afterRow.RoleStateReconciled {
		t.Fatalf("seq=%d 的 role_state_reconciled = %v, want true",
			after, afterRow.RoleStateReconciled)
	}
	if got := f.snapshotTables(t, after); len(got) != 1 || got[0] != StateTableUserRoles {
		t.Fatalf("快照欄涵蓋 %v, want [%s]", got, StateTableUserRoles)
	}
}
