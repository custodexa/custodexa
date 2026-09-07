package audit

import (
	"context"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 竄改情境矩陣（audit-checkpoint-chain）。
//
// 與 `TestCheckpointVerifyStatuses`（八態各造一例）的分工：那組證明「每個
// 狀態都造得出來」，本組反過來問「**每一種攻擊手法**落到哪個狀態」，並且
// 一律以**原生 SQL 直寫**製造——威脅模型明載對手可直寫 DB，經 ORM 造出來
// 的竄改只證明守衛擋得住守衛擋得住的東西。
//
// 每個情境同時斷言「未竄改前是 passed」：少了這個前置斷言，一個恆回
// 竄改狀態的驗證器也會讓整張表全綠。
// tamperScenario 竄改矩陣的一列。
//
// **stateTable 是登記清單守衛的事實源**：非空即宣告「本列覆蓋該狀態表的
// 竄改形態」，`TestStateTableRegistryGuard` 雙向比對它與 StateTableRegistry()。
// 自我宣告的字串清單會在情境被刪掉後繼續宣稱有覆蓋，故守衛讀的是**真的被
// range 過的這張表**
type tamperScenario struct {
	name string
	// stateTable 本列覆蓋的登記狀態表（空＝與狀態表無關的既有情境）
	stateTable string
	// seed 封章前的前置狀態（狀態表列；空＝不需要）
	seed func(t *testing.T, f *verifyFixture)
	// tamper 以原生 SQL 施加竄改；回傳要判定的 seq
	tamper func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint, ids []uint) uint
	want   string
	// verify 狀態以外的額外斷言（差集之類）；nil＝只判狀態
	verify func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint)
	why    string
}

// tamperScenarios 竄改情境矩陣的全部列
func tamperScenarios() []tamperScenario {
	return []tamperScenario{
		{
			name: "抽走中段列",
			tamper: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint, ids []uint) uint {
				f.mustExec(t, "DELETE FROM audit_logs WHERE id = ?", ids[1])
				return cp.Seq
			},
			want: IntervalStatusCountMismatch,
			why:  "列數少於封章主張＝最典型的 DB 直寫抽列",
		},
		{
			name: "改 key_version",
			tamper: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint, ids []uint) uint {
				f.mustExec(t, "UPDATE audit_logs SET key_version = 99 WHERE id = ?", ids[0])
				return cp.Seq
			},
			want: IntervalStatusHashMismatch,
			why:  "列級 HMAC 不含 key_version，鏈的聚合含之（新增覆蓋）",
		},
		{
			name: "刪整個檢查點",
			tamper: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint, ids []uint) uint {
				// 再封一個點，挖掉中段的 cp
				f.stampedRows(t, 2, time.Now())
				next, err := f.seal.SealNow()
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				f.mustExec(t, "DELETE FROM audit_checkpoints WHERE seq = ?", cp.Seq)
				return next.Seq
			},
			want: ChainStatusSeqGap,
			why:  "seq 嚴格連續，挖掉一點即斷洞（空區間照蓋使斷洞無法以「那段沒事」掩飾）",
		},
		{
			name: "改被簽章欄位並重簽",
			tamper: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint, ids []uint) uint {
				f.stampedRows(t, 2, time.Now())
				next, err := f.seal.SealNow()
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				tampered := *cp
				tampered.RowCount = cp.RowCount - 1
				payload, err := CheckpointSignBytes(&tampered)
				if err != nil {
					t.Fatalf("payload: %v", err)
				}
				_, sig := f.signer.Sign(payload)
				f.mustExec(t, "UPDATE audit_checkpoints SET row_count = ?, signature = ? WHERE seq = ?",
					tampered.RowCount, sig, cp.Seq)
				return next.Seq
			},
			want: ChainStatusChainBroken,
			why:  "持鑰者可讓單點自洽，但下一點的 prev hash 對不上——鏈接是持鑰者也繞不過的一層",
		},
		{
			name: "偽造 tombstone",
			tamper: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint, ids []uint) uint {
				// 抽走全部列後補一個「看起來像合法清除」的 tombstone
				f.mustExec(t, "DELETE FROM audit_logs WHERE id >= ? AND id <= ?", cp.IDFrom, cp.IDTo)
				f.mustExec(t, `UPDATE audit_checkpoints
					SET purged_at = ?, purge_signature = ?, purge_signing_key_version = 1, purge_policy_days = 365
					WHERE seq = ?`, time.Now(), "Zm9yZ2Vk", cp.Seq)
				return cp.Seq
			},
			want: IntervalStatusPurgedInvalid,
			why:  "tombstone 是 Ed25519 簽章，無私鑰即偽造不出——這是「合法清除」與「竊取」的分界",
		},
		{
			name: "刪最舊檢查點且無修剪記錄",
			tamper: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint, ids []uint) uint {
				f.mustExec(t, "DELETE FROM audit_checkpoints WHERE seq = 1")
				return cp.Seq
			},
			want: ChainStatusSeqGap,
			why:  "鏈頭必須是 genesis 或有修剪記錄錨定；直接挖掉鏈頭即斷洞",
		},
		{
			name:       "DB 直寫 INSERT user_roles（提權）",
			stateTable: StateTableUserRoles,
			seed:       seedUserRoles(RolePair{UserID: 1, RoleID: 1}, RolePair{UserID: 2, RoleID: 2}),
			tamper: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint, ids []uint) uint {
				f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 9, 1)
				return cp.Seq
			},
			// 檢查點自身未被動，故鏈與區間照樣 passed——**不符是由對帳指出的**。
			// 把它寫成 hash_mismatch 之類會是誇大：鏈證明的是封章當下的狀態，
			// 之後的直寫改不了已封的簽章
			want: IntervalStatusPassed,
			verify: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint) {
				missing, extra := roleStateDiff(t, f, cp.Seq)
				if len(missing) != 0 {
					t.Errorf("缺少集合 = %v, want 空", missing)
				}
				if len(extra) != 1 || extra[0] != (RolePair{UserID: 9, RoleID: 1}) {
					t.Fatalf("多出集合 = %v, want [{9 1}]：直寫提權未被指認", extra)
				}
			},
			why: "封章後直寫掛上角色＝現況多出一筆，對帳回報 extra 並指名是哪一筆",
		},
		{
			name:       "DB 直寫 DELETE user_roles（抹掉稽核者）",
			stateTable: StateTableUserRoles,
			seed:       seedUserRoles(RolePair{UserID: 1, RoleID: 1}, RolePair{UserID: 2, RoleID: 2}),
			tamper: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint, ids []uint) uint {
				f.mustExec(t, "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", 2, 2)
				return cp.Seq
			},
			want: IntervalStatusPassed,
			verify: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint) {
				missing, extra := roleStateDiff(t, f, cp.Seq)
				if len(extra) != 0 {
					t.Errorf("多出集合 = %v, want 空", extra)
				}
				if len(missing) != 1 || missing[0] != (RolePair{UserID: 2, RoleID: 2}) {
					t.Fatalf("缺少集合 = %v, want [{2 2}]：直寫移除未被指認", missing)
				}
			},
			why: "直寫移除指派＝現況少一筆，對帳回報 missing（撤銷也是要留痕的變更）",
		},
		{
			name:       "改 role_state_snapshot 欄",
			stateTable: StateTableUserRoles,
			seed:       seedUserRoles(RolePair{UserID: 1, RoleID: 1}, RolePair{UserID: 2, RoleID: 2}),
			tamper: func(t *testing.T, f *verifyFixture, cp *model.AuditCheckpoint, ids []uint) uint {
				// 直寫把「9 號帳號本來就有 admin」寫進已封的快照——
				// 攻擊者要的不是改現況，是讓現況看起來一直如此
				f.mustExec(t, "UPDATE audit_checkpoints SET role_state_snapshot = ? WHERE seq = ?",
					`{"user_roles":[[1,1],[2,2],[9,1]]}`, cp.Seq)
				return cp.Seq
			},
			want: IntervalStatusSignatureInvalid,
			why:  "快照本體的雜湊是由本體現算後進簽章的，改本體即改簽章輸入——無私鑰改不出通過的檢查點",
		},
	}
}

func TestCheckpointTamperMatrix(t *testing.T) {
	for _, sc := range tamperScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			f := setupVerifyFixture(t)
			if sc.seed != nil {
				sc.seed(t, f)
			}
			ids := f.stampedRows(t, 3, time.Now())
			cp, err := f.seal.SealNow()
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			// 前置：未竄改前必須是 passed（否則整張表可能是恆紅的驗證器）
			if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPassed {
				t.Fatalf("竄改前狀態 = %s, want passed：前提不成立", got)
			}

			seq := sc.tamper(t, f, cp, ids)
			got := f.statusOf(t, seq).Status
			if got != sc.want {
				t.Fatalf("[%s] 狀態 = %s, want %s（%s）", sc.name, got, sc.want, sc.why)
			}
			if sc.verify != nil {
				sc.verify(t, f, cp)
			}
			t.Logf("[%s] → %s（%s）", sc.name, got, sc.why)
		})
	}
}

// seedUserRoles 封章前先把角色指派寫進去（原生 SQL：user_roles 無 model）
func seedUserRoles(pairs ...RolePair) func(t *testing.T, f *verifyFixture) {
	return func(t *testing.T, f *verifyFixture) {
		t.Helper()
		for _, p := range pairs {
			f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
				p.UserID, p.RoleID)
		}
	}
}

// roleStateDiff 以檢查點內的快照為預期、現況為實際，算出差集。
//
// **這不是完整的對帳**（對帳還要套用期間內的 `user_role` 審計列，見下一波）：
// 本矩陣的情境刻意不經任何合法路徑改動角色，故「快照 vs 現況」就是預期與現況
func roleStateDiff(t *testing.T, f *verifyFixture, seq uint) (missing, extra []RolePair) {
	t.Helper()
	var fresh model.AuditCheckpoint
	if err := f.db.Where("seq = ?", seq).First(&fresh).Error; err != nil {
		t.Fatalf("讀檢查點 seq=%d: %v", seq, err)
	}
	if fresh.RoleStateSnapshot == nil {
		t.Fatalf("檢查點 seq=%d 無狀態快照：本列的前提不成立", seq)
	}
	tables, err := DecodeStateSnapshotColumn(*fresh.RoleStateSnapshot)
	if err != nil {
		t.Fatalf("解析快照欄: %v", err)
	}
	expected, err := DecodeRolePairs(tables[StateTableUserRoles])
	if err != nil {
		t.Fatalf("解析 user_roles 快照: %v", err)
	}
	now, err := SnapshotUserRoles(context.Background(), f.db)
	if err != nil {
		t.Fatalf("現況快照: %v", err)
	}
	actual, err := DecodeRolePairs(now.Body)
	if err != nil {
		t.Fatalf("解析現況快照: %v", err)
	}
	return DiffRolePairs(expected, actual)
}

// TestCheckpointTamperContentColumnIsRowLayer 第七個情境：**改內容欄**。
//
// 單獨成測是因為它的答案與其他六個不同，而那個不同正是本機制最容易被
// 誇大的地方：改 `username`／`details` 之類的內容欄**不會**改動聚合輸入
//（三元組只含 id、key_version、integrity_hmac），故檢查點內容層回報
// `passed`——鏈證明的是「序列沒少沒多」，不是「每列內容沒被改」。
// 內容真偽由列級 HMAC 承擔（不重複覆蓋的理由），本測同時
// 斷言列級驗證確實抓得到，否則這條分工就只是說法而非事實。
func TestCheckpointTamperContentColumnIsRowLayer(t *testing.T) {
	f := setupVerifyFixture(t)
	ids := f.stampedRows(t, 3, time.Now())
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPassed {
		t.Fatalf("竄改前狀態 = %s, want passed", got)
	}

	f.mustExec(t, "UPDATE audit_logs SET username = ? WHERE id = ?", "forged", ids[1])

	// 鏈：仍 passed（誠實邊界 R6，不是缺陷）
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPassed {
		t.Fatalf("改內容欄後鏈狀態 = %s, want passed（鏈不覆蓋內容欄，超出宣稱即是誇大）", got)
	}
	// 列級：必須抓到，且指名該列
	rep, err := f.integrity.VerifyIDRange(f.db, cp.IDFrom, cp.IDTo)
	if err != nil {
		t.Fatalf("VerifyIDRange: %v", err)
	}
	if rep.Mismatched != 1 {
		t.Fatalf("列級驗證抓到 %d 列不符, want 1：分工的另一半沒接住，改內容欄就成了無人偵測的攻擊",
			rep.Mismatched)
	}
	if len(rep.MismatchedIDs) != 1 || rep.MismatchedIDs[0] != ids[1] {
		t.Errorf("不符列 id = %v, want [%d]", rep.MismatchedIDs, ids[1])
	}
	t.Logf("改內容欄：鏈 passed（R6）＋列級抓到 id=%d", ids[1])
}
