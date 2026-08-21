package sealjournal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestJournalWritesWithAuditFallbackFlagDisabled 驗收：
// 關閉 FEATURE_AUDIT_FALLBACK_TO_FILE 後，封印期嘗試仍落檔。
// journal 不受任何 feature flag 控制、不可關閉。
func TestJournalWritesWithAuditFallbackFlagDisabled(t *testing.T) {
	t.Setenv("FEATURE_AUDIT_FALLBACK_TO_FILE", "false")
	dir := t.TempDir()
	j := openTestJournal(t, dir)

	before := fileHash(t, journalPath(dir))
	seq := writeAttempt(t, j, 7, OutcomeMaterialFailure)
	after := fileHash(t, journalPath(dir))

	if seq != 1 {
		t.Fatalf("首筆 received 的序號應為 1，得 %d", seq)
	}
	if before == after {
		t.Fatal("旗標關閉時 journal 檔位元未變動＝未落檔（留痕可被 feature flag 關閉）")
	}
	st := mustStatus(t, j)
	if st.ReceivedTotal != 1 || st.MaterialFailureTotal != 1 {
		t.Fatalf("計數器未更新: %+v", st)
	}
}

// TestJournalFileSizeConstantUnderLoad 驗收：檔案大小在任意請求量下恆定
// （B′ 的存在理由——容量攻擊面消失）。
func TestJournalFileSizeConstantUnderLoad(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir, WithRejectedFlushInterval(5*time.Millisecond))
	path := journalPath(dir)

	initial := fileSizeOf(t, path)
	expected := layout{criticalSlots: 64, rejectedSlots: 16}.fileSize()
	if initial != expected {
		t.Fatalf("預配置大小應為 %d，得 %d", expected, initial)
	}

	for i := 0; i < 400; i++ {
		writeAttempt(t, j, uint64(i), OutcomeMaterialFailure)
		for k := 0; k < 10; k++ {
			j.RecordRejected(RejectedConflict)
			j.RecordRejected(RejectedCooldown)
			j.RecordRejected(RejectedBackoff)
		}
		if i%50 == 0 {
			time.Sleep(8 * time.Millisecond) // 讓 rejected 合批確實落地
		}
	}
	time.Sleep(20 * time.Millisecond)

	if got := fileSizeOf(t, path); got != initial {
		t.Fatalf("檔案隨請求量成長（%d → %d）＝B′ 前提被破壞", initial, got)
	}
	st := mustStatus(t, j)
	if st.ReceivedTotal != 400 {
		t.Fatalf("received 計數應為 400，得 %d", st.ReceivedTotal)
	}
	if st.RejectedObservedTotal != 12000 {
		t.Fatalf("rejected observed 應為 12000，得 %d", st.RejectedObservedTotal)
	}
	if st.CriticalOverwrittenTotal == 0 {
		t.Fatal("環容量 64 槽下寫入 800 筆 critical 事件應有覆蓋紀錄")
	}
}

// TestRecordRejectedDoesNotTouchCriticalRingOrFsync 驗收：
// 未取得獨佔者不寫 critical 環、不觸發 fsync。
func TestRecordRejectedDoesNotTouchCriticalRingOrFsync(t *testing.T) {
	dir := t.TempDir()
	j, probe := openProbedJournal(t, dir) // flush 間隔為 1 小時，期間不會合批
	probe.reset()

	for i := 0; i < 500; i++ {
		j.RecordRejected(RejectedCooldown)
		j.RecordRejected(RejectedBackoff)
		j.RecordRejected(RejectedConflict)
	}

	if n := probe.countKind("sync"); n != 0 {
		t.Fatalf("被拒嘗試不得觸發 fdatasync，實際 %d 次", n)
	}
	if n := probe.countKind("write"); n != 0 {
		t.Fatalf("被拒嘗試不得 pwrite，實際 %d 次", n)
	}
	st := mustStatus(t, j)
	if st.CriticalWriteIndex != 0 {
		t.Fatalf("critical 環游標應為 0，得 %d", st.CriticalWriteIndex)
	}
	if st.RejectedPendingTotal != 1500 {
		t.Fatalf("記憶體聚合器應累計 1500 筆，得 %d", st.RejectedPendingTotal)
	}
}

// TestAbortBetweenCASAndPrepareIsNotUnknownOutcome 驗收：
// CAS 到 PREPARE 之間中止不被記為「結果未知」——尚未驗證任何材料。
func TestAbortBetweenCASAndPrepareIsNotUnknownOutcome(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)

	// 模擬：取得 admission（＝CAS 勝出）後即中止，未寫 received。
	ticket, err := j.Admit(context.Background())
	if err != nil {
		t.Fatalf("Admit 失敗: %v", err)
	}
	ticket.Release(false)

	st := mustStatus(t, j)
	if len(st.UnknownOutcomeSeqs) != 0 {
		t.Fatalf("未寫 received 不得產生結果未知，得 %v", st.UnknownOutcomeSeqs)
	}
	if st.SeqNext != 1 || st.ReceivedTotal != 0 {
		t.Fatalf("不得於 CAS 之前／之後未寫 received 就推進計數: %+v", st)
	}
}

// TestReceivedWithoutOutcomeIsUnknown 驗收：有 received 無 outcome 標示為「結果未知」，
// 且該判定在重開檔（崩潰恢復）之後仍成立。
func TestReceivedWithoutOutcomeIsUnknown(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)

	done := writeAttempt(t, j, 1, OutcomeSuccess)
	unknownSeq := writeAttempt(t, j, 1, "") // 只寫 received，模擬崩潰
	if err := j.Close(); err != nil {
		t.Fatalf("Close 失敗: %v", err)
	}

	reopened := openTestJournal(t, dir)
	st := mustStatus(t, reopened)
	if len(st.UnknownOutcomeSeqs) != 1 || st.UnknownOutcomeSeqs[0] != unknownSeq {
		t.Fatalf("應僅 seq=%d 為結果未知，得 %v", unknownSeq, st.UnknownOutcomeSeqs)
	}
	for _, s := range st.UnknownOutcomeSeqs {
		if s == done {
			t.Fatalf("已有 outcome 的 seq=%d 不得標為結果未知", done)
		}
	}
}

// TestWriteReceivedReturnsAfterHeaderDatasync 驗收：驗證未早於 header fdatasync。
// 完整定序＝寫資料槽 → fdatasync → 推進 header → fdatasync，
// WriteReceived 回傳時該定序必已完成（呼叫端在此之後才驗證材料）。
func TestWriteReceivedReturnsAfterHeaderDatasync(t *testing.T) {
	dir := t.TempDir()
	j, probe := openProbedJournal(t, dir)
	probe.reset()

	if _, err := j.WriteReceived(context.Background(), 3, testDigest); err != nil {
		t.Fatalf("WriteReceived 失敗: %v", err)
	}
	// 這一刻即「呼叫端開始驗證材料」的時點。
	ops := probe.snapshot()

	var seq []string
	for _, op := range ops {
		switch {
		case op.Kind == "write" && op.Off >= criticalRingOffset:
			seq = append(seq, "write-body")
		case op.Kind == "write" && op.Off < criticalRingOffset:
			seq = append(seq, "write-header")
		case op.Kind == "sync":
			seq = append(seq, "sync")
		}
	}
	want := []string{"write-body", "sync", "write-header", "sync"}
	if strings.Join(seq, ",") != strings.Join(want, ",") {
		t.Fatalf("I/O 定序不符：want %v，got %v", want, seq)
	}
}

// TestAllWritesComeFromSingleOwnerGoroutine 驗收：單一 writer。
// received／outcome／rejected 合批／回灌 checkpoint 全部收斂到同一 goroutine。
func TestAllWritesComeFromSingleOwnerGoroutine(t *testing.T) {
	dir := t.TempDir()
	j, probe := openProbedJournal(t, dir, WithRejectedFlushInterval(5*time.Millisecond))

	var wg = make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		go func(n int) {
			defer func() { wg <- struct{}{} }()
			ctx := context.Background()
			for k := 0; k < 5; k++ {
				ticket, err := j.Admit(ctx)
				if err != nil {
					return
				}
				seq, err := j.WriteReceived(ctx, uint64(n), testDigest)
				ticket.Release(err == nil)
				if err == nil {
					_ = j.WriteOutcome(ctx, uint64(n), seq, OutcomeTimeout)
				}
				j.RecordRejected(RejectedConflict)
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-wg
	}
	time.Sleep(20 * time.Millisecond)

	if _, err := j.Replay(context.Background(), newSink()); err != nil {
		t.Fatalf("Replay 失敗: %v", err)
	}

	gids := probe.writerGoroutines()
	if len(gids) != 1 {
		t.Fatalf("journal 檔的寫入者必須唯一，實際來自 %d 個 goroutine: %v", len(gids), gids)
	}
	if gids[0] == goID() {
		t.Fatal("寫入不應發生在呼叫端 goroutine（owner 未生效）")
	}
}

// TestIOFaultRejectsNewAttemptsAndAutoRecovers 驗收：
// 運行中 I/O 故障即拒收新嘗試＋Status 標示，修復後自動恢復。
func TestIOFaultRejectsNewAttemptsAndAutoRecovers(t *testing.T) {
	dir := t.TempDir()
	j, probe := openProbedJournal(t, dir, WithRejectedFlushInterval(10*time.Millisecond))

	probe.setFailWrite(true)
	if _, err := j.WriteReceived(context.Background(), 1, testDigest); err == nil {
		t.Fatal("I/O 故障時 WriteReceived 應回錯")
	}
	if !j.Faulted() {
		t.Fatal("I/O 故障應被記錄")
	}
	st := mustStatus(t, j)
	if !st.IOFaulted || st.IOFaultReason == "" {
		t.Fatalf("Status 應標示 I/O 故障: %+v", st)
	}
	if _, err := j.Admit(context.Background()); !errors.Is(err, ErrIOFaulted) {
		t.Fatalf("故障期間 Admit 應拒收新嘗試，得 %v", err)
	}

	probe.setFailWrite(false)
	deadline := time.Now().Add(2 * time.Second)
	for j.Faulted() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if j.Faulted() {
		t.Fatal("修復後應自動恢復")
	}
	ticket, err := j.Admit(context.Background())
	if err != nil {
		t.Fatalf("恢復後 Admit 應成功: %v", err)
	}
	ticket.Release(false)
}

// TestSuccessOutcomeFailureBlocksPublish 驗收：
// SUCCESS 未 durable 時不得回覆解封成功——journal 端以回錯表達，
// 呼叫端據此丟棄服務圖、清除 KEK、維持封印（不得 publish-then-write）。
func TestSuccessOutcomeFailureBlocksPublish(t *testing.T) {
	dir := t.TempDir()
	j, probe := openProbedJournal(t, dir)
	seq := writeAttempt(t, j, 1, "")

	probe.setFailWrite(true)
	err := j.WriteOutcome(context.Background(), 1, seq, OutcomeSuccess)
	if err == nil {
		t.Fatal("SUCCESS 未 durable 時 WriteOutcome 必須回錯（否則呼叫端會誤 publish）")
	}
	if pubErr := j.WritePublished(context.Background(), 1, seq); pubErr == nil {
		t.Fatal("SUCCESS 未 durable 時 published 標記亦不得成功")
	}
	st := mustStatus(t, j)
	if st.SuccessTotal != 0 {
		t.Fatalf("失敗的 SUCCESS 不得計入計數: %+v", st)
	}
	if len(st.UnknownOutcomeSeqs) != 1 || st.UnknownOutcomeSeqs[0] != seq {
		t.Fatalf("SUCCESS 未落地時該 seq 應維持結果未知，得 %v", st.UnknownOutcomeSeqs)
	}
}

// TestWrapAroundRecordsOverwrittenSeqRange 驗收：環繞覆蓋時記錄被覆蓋的序號範圍。
func TestWrapAroundRecordsOverwrittenSeqRange(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir, WithCapacity(4, 2))

	for i := 0; i < 7; i++ {
		writeAttempt(t, j, 1, "")
	}
	st := mustStatus(t, j)
	if st.CriticalOverwrittenTotal != 3 {
		t.Fatalf("4 槽環寫 7 筆應覆蓋 3 筆，得 %d", st.CriticalOverwrittenTotal)
	}
	if st.CriticalOverwrittenFirstSeq != 1 || st.CriticalOverwrittenLastSeq != 3 {
		t.Fatalf("被覆蓋序號範圍應為 1..3，得 %d..%d",
			st.CriticalOverwrittenFirstSeq, st.CriticalOverwrittenLastSeq)
	}
	want := layout{criticalSlots: 4, rejectedSlots: 2}.fileSize()
	if got := fileSizeOf(t, journalPath(dir)); got != want {
		t.Fatalf("環繞後檔案大小仍須恆定：want %d，got %d", want, got)
	}
}

// TestOutcomeAndSeqValidation 驗收：五類結果碼值域，以及不存在的序號一律拒收。
func TestOutcomeAndSeqValidation(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)
	ctx := context.Background()
	seq := writeAttempt(t, j, 1, "")

	for _, o := range []string{OutcomeSuccess, OutcomeMaterialFailure, OutcomeInitFailed, OutcomeTimeout, OutcomeAborted} {
		if err := j.WriteOutcome(ctx, 1, seq, o); err != nil {
			t.Fatalf("結果碼 %q 應被接受: %v", o, err)
		}
	}
	if err := j.WriteOutcome(ctx, 1, seq, "unknown_state"); !errors.Is(err, ErrInvalidOutcome) {
		t.Fatalf("值域外的結果碼應被拒，得 %v", err)
	}
	if err := j.WriteOutcome(ctx, 1, 999, OutcomeSuccess); !errors.Is(err, ErrUnknownSeq) {
		t.Fatalf("不存在的序號應被拒，得 %v", err)
	}
}
