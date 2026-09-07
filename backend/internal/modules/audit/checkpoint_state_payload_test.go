package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 狀態快照進簽章載荷（role-assignment-integrity 第 2 組）。
//
// 本檔釘三件事：v2 載荷的位元組、舊版本載荷續驗、以及新版本缺快照時的判定。
// 第三件是本組最容易被做錯的一件——「缺 state 就退回 v1 的形狀去驗」看起來
// 寬容，實際上等於讓攻擊者把 role_state_snapshot 清空就繞過整個機制。

// TestCheckpointCanonicalGoldenV2 v2 簽章載荷的位元組 golden。
//
// 與 v1 的 golden 是同一顆釘子（見 TestCheckpointCanonicalGolden）：
// 欄位順序、鍵名與 null 表示都是離線驗證者照文件手寫重建的對象，
// 動它一個位元組就是讓已封的檢查點全數驗不過
func TestCheckpointCanonicalGoldenV2(t *testing.T) {
	minAt := time.Date(2026, 8, 12, 1, 2, 3, 456789000, time.UTC)
	maxAt := time.Date(2026, 8, 12, 2, 3, 4, 567890000, time.UTC)
	snapshot := `{"user_roles":[[1,1],[2,3]]}`
	hash := "aaaa"
	count := int64(2)
	cp := &model.AuditCheckpoint{
		Seq: 7, IDFrom: 4023, IDTo: 5000, RowCount: 978,
		AggHash:            "1111111111111111111111111111111111111111111111111111111111111111",
		AggScheme:          model.AggSchemeV2,
		PrevCheckpointHash: "2222222222222222222222222222222222222222222222222222222222222222",
		MinCreatedAt:       &minAt, MaxCreatedAt: &maxAt,
		SealedAt:          time.Date(2026, 8, 12, 2, 5, 0, 0, time.UTC),
		SigningKeyVersion: 1,
		Signature:         "c2ln",
		AnchorStatus:      model.AnchorStatusEnqueued,
		// hash 與 count 兩欄刻意填成與快照本體不符的值：載荷取的是**由本體現算**
		// 的摘要，不是這兩欄——否則改寫本體而不動摘要欄即可繞過簽章
		RoleStateHash:     &hash,
		RoleStateCount:    &count,
		RoleStateSnapshot: &snapshot,
	}

	got, err := CheckpointSignBytes(cp)
	if err != nil {
		t.Fatalf("CheckpointSignBytes: %v", err)
	}
	wantStateHash := stateHash([]byte(`[[1,1],[2,3]]`))
	want := `{"seq":7,"id_from":4023,"id_to":5000,"row_count":978,` +
		`"agg_hash":"1111111111111111111111111111111111111111111111111111111111111111",` +
		`"agg_scheme":"cp-agg-v2",` +
		`"prev_checkpoint_hash":"2222222222222222222222222222222222222222222222222222222222222222",` +
		`"min_created_at_us":1786496523456789,` +
		`"state":[{"table":"user_roles","hash":"` + wantStateHash + `","count":2}],` +
		`"role_state_reconciled":null,` +
		`"max_created_at_us":1786500184567890,` +
		`"sealed_at_us":1786500300000000,"signing_key_version":1}`
	if string(got) != want {
		t.Fatalf("v2 簽章 payload 位元組不符 golden\n got: %s\nwant: %s", got, want)
	}
	if strings.Contains(string(got), snapshot) {
		t.Error("快照本體不得整段進簽章載荷：載荷是離線驗證者要逐位元組重建的東西")
	}
	if strings.Contains(string(got), `"hash":"aaaa"`) {
		t.Error("載荷取了 role_state_hash 欄而非由快照本體現算：" +
			"如此則改寫快照本體不會使簽章失效，而快照本體正是對帳的輸入")
	}

	// 對帳結果為真時寫出 true（第 2 波接上對帳後的形態）
	yes := true
	cp.RoleStateReconciled = &yes
	got, err = CheckpointSignBytes(cp)
	if err != nil {
		t.Fatalf("CheckpointSignBytes: %v", err)
	}
	if !strings.Contains(string(got), `"role_state_reconciled":true`) {
		t.Errorf("對帳結果未進載荷: %s", got)
	}
}

// TestSealWritesRoleStateSnapshot 封章寫入四欄且宣告 v2。
//
// 同時釘住 role_state_reconciled 於本波固定為 nil：對帳器尚未接上，
// 以 true 佔位就是簽下一個沒有人做過的主張
func TestSealWritesRoleStateSnapshot(t *testing.T) {
	f := setupVerifyFixture(t)
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 2, 2)
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 1, 1)
	f.stampedRows(t, 2, time.Now())

	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if cp.AggScheme != model.AggSchemeV2 {
		t.Fatalf("agg_scheme = %s, want %s", cp.AggScheme, model.AggSchemeV2)
	}
	if cp.RoleStateSnapshot == nil || *cp.RoleStateSnapshot != `{"user_roles":[[1,1],[2,2]]}` {
		t.Fatalf("快照欄 = %v, want 排序後的兩筆", cp.RoleStateSnapshot)
	}
	if cp.RoleStateCount == nil || *cp.RoleStateCount != 2 {
		t.Fatalf("筆數欄 = %v, want 2", cp.RoleStateCount)
	}
	want, err := SnapshotUserRoles(context.Background(), f.db)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if cp.RoleStateHash == nil || *cp.RoleStateHash != want.Hash {
		t.Fatalf("雜湊欄 = %v, want %s", cp.RoleStateHash, want.Hash)
	}
	if cp.RoleStateReconciled != nil {
		t.Fatalf("對帳結果 = %v, want nil（對帳尚未接上，非 nil 即簽下一個沒做過的主張）",
			*cp.RoleStateReconciled)
	}
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPassed {
		t.Fatalf("剛封的檢查點狀態 = %s, want passed", got)
	}
	// genesis 也帶快照：全新安裝自第一個檢查點起就有涵蓋起點
	var genesis model.AuditCheckpoint
	if err := f.db.Where("seq = ?", 1).First(&genesis).Error; err != nil {
		t.Fatalf("讀 genesis: %v", err)
	}
	if genesis.AggScheme != model.AggSchemeV2 || genesis.RoleStateSnapshot == nil {
		t.Fatalf("genesis scheme=%s snapshot=%v, want v2 且帶快照",
			genesis.AggScheme, genesis.RoleStateSnapshot)
	}
}

// TestCheckpointV1PayloadStillVerifies 舊載荷版本續驗。
//
// 升級後的鏈是混的：v1 的舊點與 v2 的新點在同一條鏈上，而 v1 的點沒有、
// 也不可能有 state 欄（它們封章時本能力還不存在）。要求它們有 state
// 就是升級當天把整條歷史鏈判成竄改
func TestCheckpointV1PayloadStillVerifies(t *testing.T) {
	f := setupVerifyFixture(t)
	f.stampedRows(t, 2, time.Now())
	last, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// 手工續接一個 v1 形態的檢查點（模擬升級前封的點）
	prevHash, err := CheckpointLinkHash(last)
	if err != nil {
		t.Fatalf("link hash: %v", err)
	}
	emptyHash, emptyCount := ComputeAggHash(nil)
	legacy := model.AuditCheckpoint{
		Seq: last.Seq + 1, IDFrom: last.IDTo + 1, IDTo: last.IDTo,
		RowCount: emptyCount, AggHash: emptyHash,
		AggScheme:          model.AggSchemeV1,
		PrevCheckpointHash: prevHash,
		SealedAt:           time.Now().UTC(),
		SigningKeyVersion:  1,
		AnchorStatus:       model.AnchorStatusDisabled,
	}
	payload, err := CheckpointSignBytes(&legacy)
	if err != nil {
		t.Fatalf("v1 載荷建不出來: %v", err)
	}
	if strings.Contains(string(payload), "state") {
		t.Fatalf("v1 載荷含 state 欄：舊檢查點的位元組被改動了\n%s", payload)
	}
	_, legacy.Signature = f.signer.Sign(payload)
	if err := f.db.Create(&legacy).Error; err != nil {
		t.Fatalf("寫入舊形態檢查點: %v", err)
	}

	if got := f.statusOf(t, legacy.Seq).Status; got != IntervalStatusPassed {
		t.Fatalf("舊載荷版本的檢查點狀態 = %s, want passed", got)
	}
	rep, err := f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if rep.Status != "passed" {
		t.Fatalf("混版本鏈的結構層狀態 = %s, want passed（新舊點在同一條鏈上是升級的常態）",
			rep.Status)
	}
}

// TestCheckpointV2MissingStateIsPayloadInvalid v2 但缺快照欄＝payload_invalid。
//
// **不得退回 v1 的形狀去驗**：那等於「把 role_state_snapshot 清成 NULL」
// 就能讓一個宣稱涵蓋角色指派的檢查點照樣驗過，整個機制一句 UPDATE 即可關閉
func TestCheckpointV2MissingStateIsPayloadInvalid(t *testing.T) {
	f := setupVerifyFixture(t)
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 1, 1)
	f.stampedRows(t, 2, time.Now())
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPassed {
		t.Fatalf("竄改前狀態 = %s, want passed", got)
	}

	f.mustExec(t, "UPDATE audit_checkpoints SET role_state_snapshot = NULL WHERE seq = ?", cp.Seq)
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPayloadInvalid {
		t.Fatalf("清空快照欄後狀態 = %s, want %s", got, IntervalStatusPayloadInvalid)
	}

	// 快照欄被改成非陣列的合法 JSON：同樣不得靜默通過
	f.mustExec(t, "UPDATE audit_checkpoints SET role_state_snapshot = ? WHERE seq = ?",
		`{"user_roles":{"1":1}}`, cp.Seq)
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPayloadInvalid {
		t.Fatalf("快照欄形狀被改後狀態 = %s, want %s", got, IntervalStatusPayloadInvalid)
	}

	// 未知的 agg_scheme 同理：不猜版本
	f.mustExec(t, "UPDATE audit_checkpoints SET role_state_snapshot = ?, agg_scheme = ? WHERE seq = ?",
		`{"user_roles":[[1,1]]}`, "cp-agg-v99", cp.Seq)
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPayloadInvalid {
		t.Fatalf("未知 agg_scheme 的狀態 = %s, want %s", got, IntervalStatusPayloadInvalid)
	}
}
