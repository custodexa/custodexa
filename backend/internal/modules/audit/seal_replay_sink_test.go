package audit

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sealjournal"
)

// 封印期 journal 回灌落地端的驗收。

// newReplayAuditService 建一個同步寫入的審計服務（回灌經它落地）。
func newReplayAuditService(t *testing.T) *AuditLogService {
	t.Helper()
	s := NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	return s
}

// newReplaySink 建一個接好審計服務的回灌落地端。
func newReplaySink(t *testing.T, db *gorm.DB) *SealJournalSink {
	t.Helper()
	return NewSealJournalSinkWithDB(db, newReplayAuditService(t))
}

func newReplaySinkDB(t *testing.T) *gorm.DB {
	t.Helper()
	// **檔案型而非 :memory:**：共享快取的記憶體 DB 會被同行程的其他測試看見，
	// 且其連線池語義曾在本專案造成「單獨跑綠、整包跑紅」的假訊號。
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "replay.db")),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("開啟測試 DB 失敗: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("建表失敗: %v", err)
	}
	return db
}

// writeSealJournalEvents 寫入一組真實的封印期事件並回傳 journal。
func writeSealJournalEvents(t *testing.T) *sealjournal.Journal {
	t.Helper()
	j, err := sealjournal.Open(t.TempDir(), sealjournal.WithCapacity(16, 16),
		sealjournal.WithMinAdmissionInterval(0))
	if err != nil {
		t.Fatalf("開啟 journal 失敗: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })

	ctx := context.Background()
	seq, err := j.WriteReceived(ctx, 1, strings.Repeat("ab", 16))
	if err != nil {
		t.Fatalf("寫入 received 失敗: %v", err)
	}
	if err := j.WriteOutcome(ctx, 1, seq, "material_failure"); err != nil {
		t.Fatalf("寫入 outcome 失敗: %v", err)
	}
	j.RecordRejected("cooldown")
	return j
}

func countAuditRows(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AuditLog{}).Count(&n).Error; err != nil {
		t.Fatalf("計數審計列失敗: %v", err)
	}
	return n
}

// TestSealReplaySinkWritesEventsAndAggregate 回灌寫出事件列＋合成聚合列。
func TestSealReplaySinkWritesEventsAndAggregate(t *testing.T) {
	db := newReplaySinkDB(t)
	j := writeSealJournalEvents(t)

	res, err := j.Replay(context.Background(), newReplaySink(t, db))
	if err != nil {
		t.Fatalf("回灌失敗: %v", err)
	}
	if res.Events == 0 {
		t.Fatal("回灌了 0 筆事件——本測試的前提不成立")
	}

	var rows []model.AuditLog
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀取審計列失敗: %v", err)
	}
	if int64(len(rows)) != int64(res.Events)+1 {
		t.Fatalf("寫出 %d 列，期望 %d 筆事件列＋1 筆聚合列", len(rows), res.Events)
	}

	aggregates, events := 0, 0
	for _, r := range rows {
		// 冪等鍵必須逐列存在：缺了它，重跑就會產生重複列。
		if r.IdempotencyUUID == nil || *r.IdempotencyUUID == "" {
			t.Fatalf("回灌列缺冪等鍵：%+v", r)
		}
		// 內容白名單：不得含請求體、KEK 材料或憑證。
		if strings.Contains(r.Details, "password") || strings.Contains(r.Details, "kek\"") {
			t.Fatalf("回灌列含不該出現的欄位：%s", r.Details)
		}
		switch {
		case strings.Contains(r.Details, `"seal_journal_aggregate"`):
			aggregates++
		case strings.Contains(r.Details, `"seal_journal"`):
			events++
		}
	}
	if aggregates != 1 {
		t.Fatalf("聚合列有 %d 筆，期望恰 1 筆（洪水期的總量與時間範圍必須進入蓋章鏈）", aggregates)
	}
	if events != res.Events {
		t.Fatalf("事件列有 %d 筆，期望 %d 筆", events, res.Events)
	}
}

// TestSealReplaySinkIsIdempotent 重複回灌不產生重複列。
//
// checkpoint 未落盤而重跑是 at-least-once 的正常情形；去重完全由 DB 唯一鍵
// 承擔——事件列靠確定性事件 ID，聚合列靠 (journal_uuid, 起訖 seq) 導出的 ID。
// 缺聚合列那一半時，重跑會讓同一區間的總量被重複記入審計。
func TestSealReplaySinkIsIdempotent(t *testing.T) {
	db := newReplaySinkDB(t)
	j := writeSealJournalEvents(t)
	sink := newReplaySink(t, db)

	// 直接對 Sink 送兩次同一批（等同「Commit 成功但 checkpoint 未落盤」後重跑）。
	batch := captureBatch(t, j)
	if err := sink.Commit(context.Background(), batch); err != nil {
		t.Fatalf("首次 Commit 失敗: %v", err)
	}
	first := countAuditRows(t, db)
	if first == 0 {
		t.Fatal("首次 Commit 未寫出任何列")
	}
	if err := sink.Commit(context.Background(), batch); err != nil {
		t.Fatalf("重跑 Commit 失敗（重複回灌不該回錯）: %v", err)
	}
	if second := countAuditRows(t, db); second != first {
		t.Fatalf("重複回灌後列數由 %d 變為 %d——冪等鍵未生效", first, second)
	}
}

// TestSealReplaySinkDerivesOwnAggregateID 聚合列的冪等鍵由 sink 自行導出。
//
// 冪等鍵同時是 DB 唯一鍵。若沿用上游交出的 DeterministicID，「兩批算不算同一批」
// 的判定權就在呼叫端手上：上游對**不同區間**交出同一個 ID 時，第二批會被
// ON CONFLICT 靜默吞掉——留痕消失且不回任何錯誤。
func TestSealReplaySinkDerivesOwnAggregateID(t *testing.T) {
	db := newReplaySinkDB(t)
	sink := newReplaySink(t, db)
	ctx := context.Background()

	const journalUUID = "11111111-2222-3333-4444-555555555555"
	// 兩個不同區間，但上游宣稱的 ID 相同（模擬上游導出邏輯失效或被竄改）。
	collide := "ffffffff-ffff-ffff-ffff-ffffffffffff"
	first := sealjournal.ReplayBatch{
		JournalUUID: journalUUID,
		Aggregate: sealjournal.AggregateRow{
			DeterministicID: collide, JournalUUID: journalUUID,
			StartSeq: 1, EndSeq: 10, ReceivedDelta: 3,
		},
	}
	second := first
	second.Aggregate.StartSeq, second.Aggregate.EndSeq = 11, 20

	if err := sink.Commit(ctx, first); err != nil {
		t.Fatalf("第一批 Commit 失敗: %v", err)
	}
	if err := sink.Commit(ctx, second); err != nil {
		t.Fatalf("第二批 Commit 失敗: %v", err)
	}
	if n := countAuditRows(t, db); n != 2 {
		t.Fatalf("兩個不同區間寫出 %d 列，期望 2 列——上游的碰撞 ID 使第二批被靜默吞掉", n)
	}

	// 同一區間重送仍須去重（自行導出的鍵本身要是確定性的）。
	if err := sink.Commit(ctx, second); err != nil {
		t.Fatalf("重送 Commit 失敗: %v", err)
	}
	if n := countAuditRows(t, db); n != 2 {
		t.Fatalf("重送同一區間後列數變為 %d，期望仍為 2——自行導出的鍵不具確定性", n)
	}
}

// TestSealReplaySinkRejectsInconsistentBatch 自我矛盾的批次一律拒絕。
func TestSealReplaySinkRejectsInconsistentBatch(t *testing.T) {
	db := newReplaySinkDB(t)
	sink := newReplaySink(t, db)
	const journalUUID = "11111111-2222-3333-4444-555555555555"

	cases := map[string]sealjournal.ReplayBatch{
		"批次缺 journal_uuid": {
			Aggregate: sealjournal.AggregateRow{StartSeq: 1, EndSeq: 2},
		},
		"聚合列的 journal 與批次不符": {
			JournalUUID: journalUUID,
			Aggregate: sealjournal.AggregateRow{
				JournalUUID: "99999999-9999-9999-9999-999999999999", StartSeq: 1, EndSeq: 2},
		},
		"序號區間反向": {
			JournalUUID: journalUUID,
			Aggregate:   sealjournal.AggregateRow{JournalUUID: journalUUID, StartSeq: 10, EndSeq: 2},
		},
		"事件落在聚合區間之外": {
			JournalUUID: journalUUID,
			Events:      []sealjournal.ReplayEvent{{Seq: 99, Kind: "received"}},
			Aggregate:   sealjournal.AggregateRow{JournalUUID: journalUUID, StartSeq: 1, EndSeq: 10},
		},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if err := sink.Commit(context.Background(), b); err == nil {
				t.Fatalf("%s 竟被接受——冪等鍵的導出依據已不可信", name)
			}
		})
	}
	if n := countAuditRows(t, db); n != 0 {
		t.Fatalf("被拒的批次竟寫出 %d 列", n)
	}
}

// TestSealReplaySinkRequiresAuditWriter 回灌必須經審計服務入口。
//
// 自行 tx.Create 會讓回灌成為第二條無人維護的審計寫入路徑：繞過
// FEATURE_AUDIT_LOG_ENABLED、繞過寫入失敗上報。此處以「審計停用時回錯而非
// 靜默寫入」證明回灌確實經過那個入口。
func TestSealReplaySinkRequiresAuditWriter(t *testing.T) {
	db := newReplaySinkDB(t)
	j := writeSealJournalEvents(t)
	batch := captureBatch(t, j)

	t.Run("未接線審計服務即回錯", func(t *testing.T) {
		sink := NewSealJournalSinkWithDB(db, nil)
		if err := sink.Commit(context.Background(), batch); err == nil {
			t.Fatal("未接線審計服務的回灌竟成功——回灌並未經過審計寫入入口")
		}
		if n := countAuditRows(t, db); n != 0 {
			t.Fatalf("未接線審計服務卻寫出 %d 列", n)
		}
	})

	t.Run("審計停用時不落地且不推進", func(t *testing.T) {
		disabled := NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: false})
		t.Cleanup(func() { _ = disabled.Shutdown(context.Background()) })
		sink := NewSealJournalSinkWithDB(db, disabled)
		if err := sink.Commit(context.Background(), batch); err == nil {
			t.Fatal("審計停用時回灌竟回 nil——checkpoint 會推進而留痕直接消失")
		}
		if n := countAuditRows(t, db); n != 0 {
			t.Fatalf("審計停用時卻寫出 %d 列", n)
		}
	})
}

// captureBatch 以一次性 Sink 擷取 Replay 交出的批次內容。
type capturingSink struct{ batch sealjournal.ReplayBatch }

func (s *capturingSink) Commit(_ context.Context, b sealjournal.ReplayBatch) error {
	s.batch = b
	return nil
}

func captureBatch(t *testing.T, j *sealjournal.Journal) sealjournal.ReplayBatch {
	t.Helper()
	cs := &capturingSink{}
	if _, err := j.Replay(context.Background(), cs); err != nil {
		t.Fatalf("擷取回灌批次失敗: %v", err)
	}
	if len(cs.batch.Events) == 0 {
		t.Fatal("擷取到的批次為空——本測試的前提不成立")
	}
	return cs.batch
}

// TestSealReplayFailCloseOnAuditWriteFailure AP-56／AP-57 的 runtime backstop。
//
// 封印期 journal 回灌是 audit 模組**自己的**落地入口（manifest 標「不進 sink」），
// 它的 fail-close 語義是：任一列寫不進去 ⇒ 整批回滾 ⇒ 回 error ⇒
// **checkpoint 不推進、事件仍留在 journal**（下次啟動重試）。
// 本測試以 GORM callback 注入寫入故障，斷言「一列都沒有落地」——
// 半批落地會讓 checkpoint 推進與否都錯：推進即遺失，不推進即重複。
func TestSealReplayFailCloseOnAuditWriteFailure(t *testing.T) {
	db := newReplaySinkDB(t)
	j := writeSealJournalEvents(t)

	// 通用防呆：計數證明「注入器真的被觸發過」。
	// 下方兩條斷言（回 error／一列都沒落地）在「回灌根本沒跑到寫入」時也會成立
	// ——例如 journal 擷取為空、sink 前置檢查早退。計數停在 0 即該格為假綠。
	// 與 internal/service 的 assertFaultInjectorFired 同一道保護，跨包故各自實作。
	fired := 0
	const cb = "w4_backstop:seal_replay_fail"
	if err := db.Callback().Create().Before("gorm:create").Register(cb, func(tx *gorm.DB) {
		fired++
		_ = tx.AddError(errors.New("注入故障：回灌審計列寫入失敗"))
	}); err != nil {
		t.Fatalf("註冊注入器: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Create().Remove(cb) })
	t.Cleanup(func() {
		if fired == 0 {
			t.Errorf("[backstop 防呆] 故障注入器在本測試中一次都沒有觸發——" +
				"回灌未走到審計寫入路徑，兩條斷言全因『什麼都沒發生』而成立，本格為假綠。")
		}
	})

	if _, err := j.Replay(context.Background(), newReplaySink(t, db)); err == nil {
		t.Fatal("AP-56／57：回灌寫入失敗時竟然成功——checkpoint 會推進而封印期留痕永久遺失")
	}
	if n := countAuditRows(t, db); n != 0 {
		t.Fatalf("AP-56／57：回灌交易未回滾，留下 %d 筆半批列", n)
	}
}
