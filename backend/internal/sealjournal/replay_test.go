package sealjournal

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// recordingSink 模擬既有審計寫入路徑：以 DeterministicID／IdempotencyUUID
// 當作 DB 唯一鍵，重複回灌只會覆蓋同一列（不新增列）。
type recordingSink struct {
	mu       sync.Mutex
	batches  []ReplayBatch
	eventIDs map[string]int
	aggIDs   map[string]int
	err      error
	onCommit func(b ReplayBatch)
}

func newSink() *recordingSink {
	return &recordingSink{eventIDs: map[string]int{}, aggIDs: map[string]int{}}
}

func (s *recordingSink) Commit(ctx context.Context, b ReplayBatch) error {
	if s.onCommit != nil {
		s.onCommit(b)
	}
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, b)
	for _, e := range b.Events {
		s.eventIDs[e.IdempotencyUUID]++
	}
	s.aggIDs[b.Aggregate.DeterministicID]++
	return nil
}

// uniqueRows 為 DB 唯一鍵去重後的實際列數。
func (s *recordingSink) uniqueRows() (events int, aggregates int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.eventIDs), len(s.aggIDs)
}

func (s *recordingSink) totalSubmitted() (events int, aggregates int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.eventIDs {
		events += n
	}
	for _, n := range s.aggIDs {
		aggregates += n
	}
	return
}

// TestReplayCommitsDBBeforePersistingCheckpoint 驗收：
// 先提交 DB 交易、再持久化 checkpoint（反向順序禁止）。
// 斷言方式：sink 於交易內回讀 checkpoint，此刻它必須仍是舊值。
func TestReplayCommitsDBBeforePersistingCheckpoint(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)
	ctx := context.Background()
	writeAttempt(t, j, 1, OutcomeSuccess)
	writeAttempt(t, j, 1, OutcomeMaterialFailure)

	var checkpointDuringCommit uint64
	sink := newSink()
	sink.onCommit = func(ReplayBatch) {
		checkpointDuringCommit = mustStatus(t, j).ReplayCheckpointSeq
	}

	res, err := j.Replay(ctx, sink)
	if err != nil {
		t.Fatalf("Replay 失敗: %v", err)
	}
	if checkpointDuringCommit != 0 {
		t.Fatalf("checkpoint 不得先於 DB 提交而推進（交易中讀到 %d）", checkpointDuringCommit)
	}
	st := mustStatus(t, j)
	if st.ReplayCheckpointSeq != res.EndSeq || res.EndSeq != 2 {
		t.Fatalf("提交後 checkpoint 應推進到 %d，得 %d", res.EndSeq, st.ReplayCheckpointSeq)
	}
	if res.Events != 4 {
		t.Fatalf("應回灌 4 筆事件（2 received ＋ 2 outcome），得 %d", res.Events)
	}
}

// TestReplayKeepsCheckpointWhenCommitFails 驗收：
// 交易未提交即不得推進 checkpoint；回灌失敗不清 checkpoint、不阻服務。
func TestReplayKeepsCheckpointWhenCommitFails(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)
	ctx := context.Background()
	writeAttempt(t, j, 1, OutcomeSuccess)

	sink := newSink()
	sink.err = errors.New("模擬 DB 交易失敗")
	if _, err := j.Replay(ctx, sink); err == nil {
		t.Fatal("交易失敗時 Replay 應回錯")
	}
	if st := mustStatus(t, j); st.ReplayCheckpointSeq != 0 {
		t.Fatalf("交易失敗後 checkpoint 必須維持不動，得 %d", st.ReplayCheckpointSeq)
	}

	sink.err = nil
	if _, err := j.Replay(ctx, sink); err != nil {
		t.Fatalf("修復後重跑應成功: %v", err)
	}
	if st := mustStatus(t, j); st.ReplayCheckpointSeq != 1 {
		t.Fatalf("重跑後 checkpoint 應為 1，得 %d", st.ReplayCheckpointSeq)
	}
}

// TestReplayRerunIsIdempotent 驗收：
// at-least-once——checkpoint 未落盤而重跑時，事件列與聚合列都以確定性 ID 去重，
// 不產生重複列。
func TestReplayRerunIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	j, probe := openProbedJournal(t, dir)
	ctx := context.Background()
	writeAttempt(t, j, 1, OutcomeSuccess)
	writeAttempt(t, j, 1, OutcomeTimeout)

	sink := newSink()
	// 交易提交成功，但緊接著的 checkpoint 持久化失敗（模擬崩潰時窗）。
	sink.onCommit = func(ReplayBatch) { probe.setFailWrite(true) }
	if _, err := j.Replay(ctx, sink); err == nil {
		t.Fatal("checkpoint 持久化失敗時 Replay 應回錯")
	}
	probe.setFailWrite(false)
	sink.onCommit = nil
	if st := mustStatus(t, j); st.ReplayCheckpointSeq != 0 {
		t.Fatalf("checkpoint 未落盤，應維持 0，得 %d", st.ReplayCheckpointSeq)
	}

	res2, err := j.Replay(ctx, sink)
	if err != nil {
		t.Fatalf("重跑失敗: %v", err)
	}

	submittedEvents, submittedAggs := sink.totalSubmitted()
	uniqueEvents, uniqueAggs := sink.uniqueRows()
	if submittedEvents != 8 || submittedAggs != 2 {
		t.Fatalf("測試前提：兩次回灌應各送出 4 事件＋1 聚合列，得 %d/%d", submittedEvents, submittedAggs)
	}
	if uniqueEvents != 4 {
		t.Fatalf("重複回灌不得產生重複事件列：唯一鍵去重後應為 4，得 %d", uniqueEvents)
	}
	if uniqueAggs != 1 {
		t.Fatalf("聚合列重跑不得重複入審計：應為 1 列，得 %d", uniqueAggs)
	}
	if res2.AggregateID != sink.batches[0].Aggregate.DeterministicID {
		t.Fatal("聚合列 ID 必須由 (journal_uuid, 起始 seq, 結束 seq) 確定性導出")
	}
}

// TestReplayCheckpointWrittenOnlyByOwner 驗收：
// 回灌不自行寫 header，checkpoint 一律經 owner 序列化。
func TestReplayCheckpointWrittenOnlyByOwner(t *testing.T) {
	dir := t.TempDir()
	j, probe := openProbedJournal(t, dir)
	ctx := context.Background()
	writeAttempt(t, j, 1, OutcomeSuccess)

	probe.reset()
	callerGID := goID()
	if _, err := j.Replay(ctx, newSink()); err != nil {
		t.Fatalf("Replay 失敗: %v", err)
	}

	var headerWrites int
	for _, op := range probe.snapshot() {
		if op.Kind != "write" {
			continue
		}
		if op.GID == callerGID {
			t.Fatal("回灌不得由呼叫端 goroutine 直接寫 journal 檔")
		}
		if op.Off < criticalRingOffset {
			headerWrites++
		}
	}
	if headerWrites == 0 {
		t.Fatal("回灌應經 owner 推進 checkpoint（header 未被寫入）")
	}
}

// TestReplayReportsOverwrittenRangeAndUnknownOutcome 驗收：
// 覆蓋不得默默跨過未回灌資料——聚合列須帶被覆蓋序號範圍、缺口與結果未知明細。
func TestReplayReportsOverwrittenRangeAndUnknownOutcome(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir, WithCapacity(4, 2))
	ctx := context.Background()

	for i := 0; i < 6; i++ {
		writeAttempt(t, j, 1, "") // 只有 received，全部結果未知
	}

	sink := newSink()
	if _, err := j.Replay(ctx, sink); err != nil {
		t.Fatalf("Replay 失敗: %v", err)
	}
	agg := sink.batches[0].Aggregate
	if agg.CriticalOverwrittenDelta != 2 {
		t.Fatalf("應記錄 2 筆覆蓋，得 %d", agg.CriticalOverwrittenDelta)
	}
	if agg.CriticalOverwrittenFirstSeq != 1 || agg.CriticalOverwrittenLastSeq != 2 {
		t.Fatalf("被覆蓋序號範圍應為 1..2，得 %d..%d",
			agg.CriticalOverwrittenFirstSeq, agg.CriticalOverwrittenLastSeq)
	}
	if len(agg.UnknownOutcomeSeqs) != 4 {
		t.Fatalf("環內剩餘 4 筆應全為結果未知，得 %v", agg.UnknownOutcomeSeqs)
	}
	if agg.ReceivedDelta != 6 {
		t.Fatalf("計數器差額應含全部 6 筆 received（含已被覆蓋者），得 %d", agg.ReceivedDelta)
	}
	if agg.JournalUUID == "" || agg.DeterministicID == "" {
		t.Fatal("聚合列必須帶 journal_uuid 與確定性 ID")
	}
}

// TestReplayCarriesRejectedCountersAndSkipsWhenIdle 驗收：
// rejected 計數（含合批遺失明細）進入聚合列；無新資料時不重複產生列。
func TestReplayCarriesRejectedCountersAndSkipsWhenIdle(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir, WithRejectedFlushInterval(5*time.Millisecond))
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		j.RecordRejected(RejectedBackoff)
	}
	time.Sleep(30 * time.Millisecond)

	sink := newSink()
	res, err := j.Replay(ctx, sink)
	if err != nil {
		t.Fatalf("Replay 失敗: %v", err)
	}
	if res.Skipped {
		t.Fatal("有 rejected 計數差額時不應跳過回灌")
	}
	if got := sink.batches[0].Aggregate.RejectedBackoffDelta; got != 30 {
		t.Fatalf("聚合列應帶 30 筆 backoff，得 %d", got)
	}

	res2, err := j.Replay(ctx, sink)
	if err != nil {
		t.Fatalf("Replay 失敗: %v", err)
	}
	if !res2.Skipped {
		t.Fatal("無新資料時應跳過，避免重複產生聚合列")
	}
	if _, aggs := sink.uniqueRows(); aggs != 1 {
		t.Fatalf("應僅一列聚合，得 %d", aggs)
	}
}

// TestReplayEventFieldsCarryOutcomeAndDigest 驗收：回灌事件保有結果碼與來源摘要。
func TestReplayEventFieldsCarryOutcomeAndDigest(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)
	ctx := context.Background()
	seq := writeAttempt(t, j, 9, OutcomeAborted)
	if err := j.WritePublished(ctx, 9, seq); err != nil {
		t.Fatalf("WritePublished 失敗: %v", err)
	}

	sink := newSink()
	if _, err := j.Replay(ctx, sink); err != nil {
		t.Fatalf("Replay 失敗: %v", err)
	}
	kinds := map[string]ReplayEvent{}
	for _, e := range sink.batches[0].Events {
		kinds[e.Kind] = e
	}
	if kinds[KindReceived].SourceDigest != testDigest {
		t.Fatalf("received 應帶來源摘要，得 %q", kinds[KindReceived].SourceDigest)
	}
	if kinds[KindOutcome].Outcome != OutcomeAborted {
		t.Fatalf("outcome 應為 aborted，得 %q", kinds[KindOutcome].Outcome)
	}
	if _, ok := kinds[KindPublished]; !ok {
		t.Fatal("published 標記型別應獨立於 outcome 碼並進入回灌")
	}
	if kinds[KindReceived].Gen != 9 {
		t.Fatalf("事件應保有 generation，得 %d", kinds[KindReceived].Gen)
	}
	if kinds[KindReceived].UnknownOutcome {
		t.Fatal("已有 outcome 者不得標為結果未知")
	}
}
