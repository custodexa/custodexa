package sealjournal

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// 兩個固定命名空間，使冪等鍵在跨行程、跨重跑之間完全確定。
var (
	nsEvent     = uuid.MustParse("6f2c1e58-5b8c-4a1f-9a2e-3c7b5d0a1f01")
	nsAggregate = uuid.MustParse("6f2c1e58-5b8c-4a1f-9a2e-3c7b5d0a1f02")
)

// ReplayEvent 為單筆封印期事件的回灌表述。
// IdempotencyUUID 為確定性導出值（journal_uuid × seq × kind × slotIndex），
// 呼叫端 SHALL 將其設為 DB 唯一索引，重複回灌即不產生重複列。
type ReplayEvent struct {
	IdempotencyUUID string
	Kind            string
	Seq             uint64
	Gen             uint64
	SlotIndex       uint64
	Timestamp       time.Time
	SourceDigest    string
	Outcome         string
	// UnknownOutcome 為真代表「有 received 無 outcome」＝結果未知。
	UnknownOutcome bool
}

// AggregateRow 為合成聚合審計列：使洪水期的總量與時間範圍進入 HMAC 蓋章鏈。
// 該列不具個別事件的冪等鍵，故以 (journal_uuid, 起始 seq, 結束 seq) 構成確定性 ID，
// 呼叫端 SHALL 將 DeterministicID 納入 DB 唯一鍵。
type AggregateRow struct {
	DeterministicID string
	JournalUUID     string
	StartSeq        uint64
	EndSeq          uint64
	FirstEventTS    time.Time
	LastEventTS     time.Time

	ReceivedDelta     uint64
	PublishedDelta    uint64
	SuccessDelta      uint64
	MaterialFailDelta uint64
	InitFailedDelta   uint64
	TimeoutDelta      uint64
	AbortedDelta      uint64

	RejectedCooldownDelta    uint64
	RejectedBackoffDelta     uint64
	RejectedConflictDelta    uint64
	RejectedObservedDelta    uint64
	RejectedDurableDelta     uint64
	RejectedOverwrittenDelta uint64

	// CriticalOverwrittenDelta 與 Overwritten*Seq 使「覆蓋不得默默跨過未回灌資料」可稽核。
	CriticalOverwrittenDelta    uint64
	CriticalOverwrittenFirstSeq uint64
	CriticalOverwrittenLastSeq  uint64

	MissingSeqs          []uint64
	UnknownOutcomeSeqs   []uint64
	CorruptCriticalSlots int
	CorruptRejectedSlots int
}

// ReplayBatch 為一次回灌交付給 Sink 的內容。
type ReplayBatch struct {
	JournalUUID string
	StartSeq    uint64
	EndSeq      uint64
	Events      []ReplayEvent
	Aggregate   AggregateRow
}

// Sink 為回灌的落地端。
//
// 契約（D6.5 第 6 點，本套件無法自行保證，SHALL 由呼叫端遵守）：
// Sink 的實作 MUST 走既有審計寫入路徑（同一序列化入口），MUST NOT 另開直寫 DB。
// 否則回灌會與解封後的正常審計並行競爭 HMAC 鏈尾，產生亂序或重複的鏈接點。
//
// Commit MUST 在單一 DB 交易內寫入全部事件列與聚合列，並於交易提交成功後才回 nil。
// 本套件保證：checkpoint 僅在 Commit 回 nil 之後才被持久化（反向順序在架構上不存在）。
type Sink interface {
	Commit(ctx context.Context, batch ReplayBatch) error
}

// ReplayResult 為一次回灌的結果摘要。
type ReplayResult struct {
	Events               int
	StartSeq             uint64
	EndSeq               uint64
	AggregateID          string
	CheckpointAdvancedTo uint64
	Skipped              bool
}

type replaySnapshot struct {
	h    header
	scan scanResult
}

// Replay 執行 at-least-once 回灌。
//
// 順序硬性：先提交 DB 交易（sink.Commit 回 nil），再經 owner 持久化 checkpoint。
// 反向順序（先推進 checkpoint 再提交）會在崩潰時永久遺失該批，故本函式在結構上
// 不提供該路徑：checkpoint 的推進只出現在 Commit 成功之後。
//
// checkpoint 一律經 owner 更新，本函式 SHALL NOT 自行寫 header——
// 兩路獨立讀改寫 header 會使較新 generation 挾帶舊 checkpoint 而使進度回退。
func (j *Journal) Replay(ctx context.Context, sink Sink) (ReplayResult, error) {
	if sink == nil {
		return ReplayResult{}, fmt.Errorf("sealjournal: sink 不得為 nil")
	}
	snap, err := submit(j, ctx, func() (replaySnapshot, error) {
		scan, scanErr := scanRings(j.f, j.hdr)
		return replaySnapshot{h: *j.hdr, scan: scan}, scanErr
	})
	if err != nil {
		return ReplayResult{}, err
	}

	journalUUID := formatUUID(snap.h.JournalUUID)
	checkpoint := snap.h.ReplayCheckpointSeq
	unknown := map[uint64]bool{}
	for _, s := range snap.scan.UnknownOutcomeSeqs {
		unknown[s] = true
	}

	events := make([]ReplayEvent, 0, len(snap.scan.Events))
	endSeq := checkpoint
	for _, e := range snap.scan.Events {
		if e.Seq <= checkpoint {
			continue
		}
		events = append(events, ReplayEvent{
			IdempotencyUUID: eventID(journalUUID, e),
			Kind:            e.Kind,
			Seq:             e.Seq,
			Gen:             e.Gen,
			SlotIndex:       e.SlotIndex,
			Timestamp:       e.TS,
			SourceDigest:    e.SourceDigest,
			Outcome:         e.Outcome,
			UnknownOutcome:  e.Kind == KindReceived && unknown[e.Seq],
		})
		if e.Seq > endSeq {
			endSeq = e.Seq
		}
	}

	delta := snap.h.Live.sub(snap.h.ReplaySnap)
	if len(events) == 0 && delta.isZero() {
		return ReplayResult{Skipped: true, CheckpointAdvancedTo: checkpoint}, nil
	}

	startSeq := checkpoint + 1
	agg := AggregateRow{
		DeterministicID:             aggregateID(journalUUID, startSeq, endSeq),
		JournalUUID:                 journalUUID,
		StartSeq:                    startSeq,
		EndSeq:                      endSeq,
		ReceivedDelta:               delta.Received,
		PublishedDelta:              delta.Published,
		SuccessDelta:                delta.Success,
		MaterialFailDelta:           delta.MaterialFail,
		InitFailedDelta:             delta.InitFail,
		TimeoutDelta:                delta.Timeout,
		AbortedDelta:                delta.Aborted,
		RejectedCooldownDelta:       delta.RejectedCooldown,
		RejectedBackoffDelta:        delta.RejectedBackoff,
		RejectedConflictDelta:       delta.RejectedConflict,
		RejectedObservedDelta:       delta.RejectedObserved,
		RejectedDurableDelta:        delta.RejectedDurable,
		RejectedOverwrittenDelta:    delta.RejectedOverwritten,
		CriticalOverwrittenDelta:    delta.CriticalOverwritten,
		CriticalOverwrittenFirstSeq: snap.h.CriticalOverwrittenFirstSeq,
		CriticalOverwrittenLastSeq:  snap.h.CriticalOverwrittenLastSeq,
		MissingSeqs:                 snap.scan.MissingSeqs,
		UnknownOutcomeSeqs:          snap.scan.UnknownOutcomeSeqs,
		CorruptCriticalSlots:        snap.scan.CorruptCriticalSlots,
		CorruptRejectedSlots:        snap.scan.CorruptRejectedSlots,
	}
	if snap.h.FirstEventTS != 0 {
		agg.FirstEventTS = time.Unix(0, snap.h.FirstEventTS).UTC()
	}
	if snap.h.LastEventTS != 0 {
		agg.LastEventTS = time.Unix(0, snap.h.LastEventTS).UTC()
	}

	batch := ReplayBatch{
		JournalUUID: journalUUID,
		StartSeq:    startSeq,
		EndSeq:      endSeq,
		Events:      events,
		Aggregate:   agg,
	}

	// 先提交 DB 交易。失敗即返回，checkpoint 完全未動（回灌失敗不清 checkpoint）。
	if err := sink.Commit(ctx, batch); err != nil {
		return ReplayResult{}, fmt.Errorf("sealjournal: 回灌交易未提交: %w", err)
	}

	// 交易已提交，才經 owner 持久化 checkpoint 與計數器快照。
	live := snap.h.Live
	n := uint64(len(events))
	if _, err := submit(j, ctx, func() (struct{}, error) {
		nh := *j.hdr
		if endSeq > nh.ReplayCheckpointSeq {
			nh.ReplayCheckpointSeq = endSeq
		}
		nh.ReplaySnap = live
		nh.ReplayedEvents += n
		nh.ReplayedBatches++
		return struct{}{}, j.commitHeader(&nh)
	}); err != nil {
		// checkpoint 未持久化：下次回灌會重跑同一區間，
		// 事件列靠 IdempotencyUUID、聚合列靠 DeterministicID 去重（at-least-once）。
		return ReplayResult{
			Events:      len(events),
			StartSeq:    startSeq,
			EndSeq:      endSeq,
			AggregateID: agg.DeterministicID,
		}, fmt.Errorf("sealjournal: checkpoint 持久化失敗（該批已提交，將於下次重跑去重）: %w", err)
	}

	return ReplayResult{
		Events:               len(events),
		StartSeq:             startSeq,
		EndSeq:               endSeq,
		AggregateID:          agg.DeterministicID,
		CheckpointAdvancedTo: endSeq,
	}, nil
}

// eventID 由 journal_uuid × seq × kind × slotIndex 確定性導出，重跑必然相同。
func eventID(journalUUID string, e scannedEvent) string {
	key := fmt.Sprintf("%s|%d|%s|%d", journalUUID, e.Seq, e.Kind, e.SlotIndex)
	return uuid.NewSHA1(nsEvent, []byte(key)).String()
}

// aggregateID 由 (journal_uuid, 起始 seq, 結束 seq) 確定性導出。
func aggregateID(journalUUID string, startSeq, endSeq uint64) string {
	key := fmt.Sprintf("%s|%d|%d", journalUUID, startSeq, endSeq)
	return uuid.NewSHA1(nsAggregate, []byte(key)).String()
}
