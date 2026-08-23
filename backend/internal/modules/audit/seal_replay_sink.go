package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sealjournal"
)

// 封印期 journal 的回灌落地端。
//
// **走既有審計寫入路徑（同一服務入口），不另開直寫**：本 Sink 建立 model.AuditLog
// 之後，交由 AuditLogService 的回灌入口寫入，因此與一般審計共用同一個服務物件、
// 同一組建立 hook（逐列完整性 HMAC 與 syslog tee）與同一套失效上報。
//
// **誠實界定**：本專案的完整性蓋章是**逐列 HMAC、非鏈式**（見 AuditIntegrityService.StampOne），
// 故不存在「鏈尾」可被競爭；同源要解決的問題是另一組——自行 tx.Create 會讓回灌
// 繞過 FEATURE_AUDIT_LOG_ENABLED、繞過寫入失敗上報，並成為第二條無人維護的
// 審計寫入路徑。
//
// **順序硬性：先提交 DB 交易、再持久化 checkpoint**。本 Sink 只負責前半段——
// Commit 回 nil 即代表交易已提交；checkpoint 的推進由 sealjournal 在 Commit
// 成功之後才做，反向順序在該套件的結構上不存在。

// SealJournalSink 把封印期事件回灌進 audit_logs。
type SealJournalSink struct {
	db    *gorm.DB
	audit *AuditLogService
}

// NewSealJournalSink 以全域 DB 與段 2 的審計服務建立回灌落地端。
func NewSealJournalSink(audit *AuditLogService) *SealJournalSink {
	return &SealJournalSink{db: database.DB, audit: audit}
}

// NewSealJournalSinkWithDB 以指定 DB 建立回灌落地端（測試用）。
func NewSealJournalSinkWithDB(db *gorm.DB, audit *AuditLogService) *SealJournalSink {
	return &SealJournalSink{db: db, audit: audit}
}

var _ sealjournal.Sink = (*SealJournalSink)(nil)

// sealJournalAuditPath 是回灌列的 Path 欄位值：使回灌事件在審計 UI 上可被
// 一眼歸戶到解封端點，而不是散落在無 path 的系統列裡。
const sealJournalAuditPath = "/api/v1/seal/unseal"

// 回灌列冪等鍵的命名空間（本 sink 自有）。
//
// **不沿用上游交出的 ID**：ID 同時是 DB 唯一鍵，等於把「兩批算不算同一批」
// 的判定權交給呼叫端。上游若因任何原因對不同區間交出相同 ID，第二批會被
// ON CONFLICT 靜默吞掉——留痕就這樣消失且不留錯誤。故此處由
// (journal_uuid, 起訖 seq)／(journal_uuid, seq, kind, slot) 自行導出，
// 冪等性只依賴我們自己算得出來的東西。
var (
	sealAggregateNamespace = uuid.MustParse("3f7d5c21-9b64-4c8a-8f2e-1d6a0b4e7c93")
	sealEventNamespace     = uuid.MustParse("3f7d5c21-9b64-4c8a-8f2e-1d6a0b4e7c94")
)

// sealAggregateID 由 (journal_uuid, 起始 seq, 結束 seq) 確定性導出。
func sealAggregateID(journalUUID string, startSeq, endSeq uint64) string {
	key := fmt.Sprintf("%s|%d|%d", journalUUID, startSeq, endSeq)
	return uuid.NewSHA1(sealAggregateNamespace, []byte(key)).String()
}

// sealEventID 由 (journal_uuid, seq, kind, slot_index) 確定性導出。
func sealEventID(journalUUID string, e sealjournal.ReplayEvent) string {
	key := fmt.Sprintf("%s|%d|%s|%d", journalUUID, e.Seq, e.Kind, e.SlotIndex)
	return uuid.NewSHA1(sealEventNamespace, []byte(key)).String()
}

// validateReplayBatch 拒絕自我矛盾的批次。
//
// 冪等鍵改為自行導出之後，導出所依據的欄位就成了信任邊界：若聚合列宣稱的
// journal 與批次的不同、或序號區間反向、或事件落在區間之外，導出的鍵就不再
// 對應「這一批實際涵蓋的範圍」，去重與稽核兩者同時失去意義。
func validateReplayBatch(b sealjournal.ReplayBatch) error {
	if b.JournalUUID == "" {
		return fmt.Errorf("回灌批次缺 journal_uuid")
	}
	if b.Aggregate.JournalUUID != b.JournalUUID {
		return fmt.Errorf("回灌批次的聚合列 journal_uuid（%q）與批次（%q）不一致",
			b.Aggregate.JournalUUID, b.JournalUUID)
	}
	// 無事件但有計數變化時 EndSeq == StartSeq-1 為合法（區間為空）。
	if b.Aggregate.EndSeq+1 < b.Aggregate.StartSeq {
		return fmt.Errorf("回灌批次的序號區間反向：start=%d end=%d",
			b.Aggregate.StartSeq, b.Aggregate.EndSeq)
	}
	for _, e := range b.Events {
		if e.Seq < b.Aggregate.StartSeq || e.Seq > b.Aggregate.EndSeq {
			return fmt.Errorf("回灌事件 seq=%d 落在聚合區間 [%d,%d] 之外",
				e.Seq, b.Aggregate.StartSeq, b.Aggregate.EndSeq)
		}
	}
	return nil
}

// Commit 於**單一 DB 交易**內寫入全部事件列與聚合列，提交成功後才回 nil。
//
// 冪等由唯一鍵承擔：重複回灌（checkpoint 未落盤而重跑）走
// ON CONFLICT DO NOTHING，不產生重複列亦不回錯。
func (s *SealJournalSink) Commit(ctx context.Context, batch sealjournal.ReplayBatch) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("回灌落地端未接線（DB 為 nil）")
	}
	if err := validateReplayBatch(batch); err != nil {
		return err
	}
	rows := make([]*model.AuditLog, 0, len(batch.Events)+1)
	for _, e := range batch.Events {
		row, err := sealEventRow(batch.JournalUUID, e)
		if err != nil {
			return err
		}
		rows = append(rows, row)
	}
	aggRow, err := sealAggregateRow(batch.Aggregate)
	if err != nil {
		return err
	}
	rows = append(rows, aggRow)

	return s.audit.SubmitSealReplayRows(ctx, s.db, rows)
}

// SubmitSealReplayRows 是 AuditLogService 的回灌專用寫入入口。
//
// **為何是 AuditLogService 的方法、卻定義在本檔**：它屬於封印回灌這條路徑的
// 契約（冪等鍵、單一交易、不走非同步佇列），與一般審計的批次寫入語義不同；
// 放在本檔使「回灌的特殊性」與它的唯一使用者同處一地，而不是散進審計服務的
// 通用區。它仍是同一個服務物件上的入口，故旗標、hook 與失效上報全部同源。
//
// 三點與一般審計刻意相同：
//   - 尊重 FEATURE_AUDIT_LOG_ENABLED——審計停用時整個產品沒有審計落點，
//     回灌不得自行例外（回錯而非靜默略過：checkpoint 因此不推進，留痕仍在 journal）。
//   - 逐列 Create 而非 CreateInBatches——批次插入在部分驅動下會跳過 hook 或
//     合併語句，蓋章的逐列性質不能靠驅動行為碰巧維持。
//   - 寫入失敗上報既有的審計失效機制。**成功不呼叫 Resolve**：回灌是低頻旁路，
//     它成功不足以證明主寫入鏈已恢復，代為 Resolve 會抹掉真正的失效狀態。
func (s *AuditLogService) SubmitSealReplayRows(ctx context.Context, db *gorm.DB, rows []*model.AuditLog) error {
	if s == nil {
		return fmt.Errorf("回灌落地端未接線（審計服務為 nil）")
	}
	if s.cfg == nil || !s.cfg.AuditLogEnabled {
		return fmt.Errorf("審計日誌已停用，封印期留痕無處落地（checkpoint 不推進，事件仍留在 journal）")
	}
	if len(rows) == 0 {
		return nil
	}
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, row := range rows {
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "idempotency_uuid"}},
				DoNothing: true,
			}).Create(row).Error; err != nil {
				return fmt.Errorf("回灌審計列失敗: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		if failure := GetAuditFailure(); failure != nil {
			failure.Report(model.MechanismAuditWrite, model.CauseAuditWriteBatchDropped,
				map[string]string{model.CauseParamDetail: err.Error()})
		}
		return err
	}
	return nil
}

// sealEventRow 把單筆封印期事件轉為審計列。
//
// **不含請求體、KEK 材料或其片段、認證憑證或其衍生值**——journal 本身就只
// 存得下十六進位摘要（其內容白名單在建構上成立），此處原樣搬運不擴充欄位。
func sealEventRow(journalUUID string, e sealjournal.ReplayEvent) (*model.AuditLog, error) {
	details := map[string]any{
		"source":        "seal_journal",
		"journal_uuid":  journalUUID,
		"kind":          e.Kind,
		"seq":           e.Seq,
		"generation":    e.Gen,
		"slot_index":    e.SlotIndex,
		"source_digest": e.SourceDigest,
	}
	if e.Outcome != "" {
		details["outcome"] = e.Outcome
	}
	// 「結果未知」＝有 received 無 outcome。據實標示，SHALL NOT 以任何
	// 結果碼頂替——把未知記成已知才是留痕真正的失效。
	if e.UnknownOutcome {
		details["outcome_unknown"] = true
	}
	body, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("序列化封印期事件失敗: %w", err)
	}
	id := sealEventID(journalUUID, e)
	row := &model.AuditLog{
		Action:          model.ActionExecute,
		Resource:        model.ResourceKeyManagement,
		Status:          sealEventStatus(e),
		UserID:          0,
		Username:        "system",
		Method:          http.MethodPost,
		Path:            sealJournalAuditPath,
		Details:         string(body),
		IdempotencyUUID: &id,
	}
	if !e.Timestamp.IsZero() {
		row.CreatedAt = e.Timestamp
	}
	return row, nil
}

// sealEventStatus 依結果碼決定審計狀態。
// 結果未知一律記 failure：把不確定歸為成功，會讓「有 received 無 outcome」
// 這個刻意保留的誠實訊號在審計面被抹平。
func sealEventStatus(e sealjournal.ReplayEvent) model.AuditStatus {
	if e.UnknownOutcome {
		return model.StatusFailure
	}
	switch e.Outcome {
	case "", "success":
		return model.StatusSuccess
	default:
		return model.StatusFailure
	}
}

// sealAggregateRow 產生合成聚合審計列。
//
// 使洪水期的**總量與時間範圍**進入 HMAC 蓋章鏈：個別事件會被定長環繞回覆蓋，
// 但「發生過多少次、涵蓋哪段序號」不該隨之消失。
// 該列以 (journal_uuid, 起始 seq, 結束 seq) 導出的確定性 ID 入唯一鍵——
// 否則 checkpoint 未落盤而重跑時，同一區間的聚合列會重複入審計。
func sealAggregateRow(a sealjournal.AggregateRow) (*model.AuditLog, error) {
	details := map[string]any{
		"source":       "seal_journal_aggregate",
		"journal_uuid": a.JournalUUID,
		"start_seq":    a.StartSeq,
		"end_seq":      a.EndSeq,
		"counters": map[string]uint64{
			"received":             a.ReceivedDelta,
			"published":            a.PublishedDelta,
			"success":              a.SuccessDelta,
			"material_failure":     a.MaterialFailDelta,
			"init_failed":          a.InitFailedDelta,
			"timeout":              a.TimeoutDelta,
			"aborted":              a.AbortedDelta,
			"rejected_cooldown":    a.RejectedCooldownDelta,
			"rejected_backoff":     a.RejectedBackoffDelta,
			"rejected_conflict":    a.RejectedConflictDelta,
			"rejected_observed":    a.RejectedObservedDelta,
			"rejected_durable":     a.RejectedDurableDelta,
			"rejected_overwritten": a.RejectedOverwrittenDelta,
			"critical_overwritten": a.CriticalOverwrittenDelta,
		},
		// 覆蓋不得默默跨過未回灌資料：被覆蓋的序號範圍與遺失明細一併入審計。
		"critical_overwritten_first_seq": a.CriticalOverwrittenFirstSeq,
		"critical_overwritten_last_seq":  a.CriticalOverwrittenLastSeq,
		"missing_seqs":                   a.MissingSeqs,
		"unknown_outcome_seqs":           a.UnknownOutcomeSeqs,
		"corrupt_critical_slots":         a.CorruptCriticalSlots,
		"corrupt_rejected_slots":         a.CorruptRejectedSlots,
	}
	if !a.FirstEventTS.IsZero() {
		details["first_event_ts"] = a.FirstEventTS
	}
	if !a.LastEventTS.IsZero() {
		details["last_event_ts"] = a.LastEventTS
	}
	body, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("序列化封印期聚合列失敗: %w", err)
	}
	id := sealAggregateID(a.JournalUUID, a.StartSeq, a.EndSeq)
	status := model.StatusSuccess
	if a.CriticalOverwrittenDelta > 0 || len(a.MissingSeqs) > 0 ||
		len(a.UnknownOutcomeSeqs) > 0 || a.CorruptCriticalSlots > 0 || a.CorruptRejectedSlots > 0 {
		status = model.StatusFailure
	}
	return &model.AuditLog{
		Action:          model.ActionExecute,
		Resource:        model.ResourceKeyManagement,
		Status:          status,
		UserID:          0,
		Username:        "system",
		Method:          http.MethodPost,
		Path:            sealJournalAuditPath,
		Details:         string(body),
		IdempotencyUUID: &id,
	}, nil
}
