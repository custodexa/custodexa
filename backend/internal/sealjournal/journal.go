package sealjournal

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Recorder 為封印狀態機對 journal 的契約面（跨套件不可改名改簽章）。
type Recorder interface {
	WriteReceived(ctx context.Context, gen uint64, sourceDigest string) (seq uint64, err error)
	WriteOutcome(ctx context.Context, gen uint64, seq uint64, outcome string) error
	WritePublished(ctx context.Context, gen uint64, seq uint64) error
	RecordRejected(kind string)
	Close() error
}

var _ Recorder = (*Journal)(nil)

// Journal 為封印期定長環狀 journal。
//
// 單一 writer：檔案的全部寫入——received／outcome／
// published／rejected 合批／回灌 checkpoint 推進——都收斂到 owner goroutine 並由它
// 序列化。回灌器 SHALL 經該 owner 更新 checkpoint，SHALL NOT 自行寫 header。
// 因此不需要鎖或 compare-and-retry 合併規則：兩路獨立寫 header 在架構上被禁止。
type Journal struct {
	path   string
	opt    Options
	bootID [16]byte

	// 以下欄位僅由 owner goroutine 存取。
	f   fileIO
	hdr *header

	ops       chan func()
	stopOnce  sync.Once
	stopCh    chan struct{}
	closedCh  chan struct{}
	closeErr  error
	closeDone chan struct{}

	// rejected 定長記憶體聚合器：被拒嘗試不逐筆 pwrite，按固定頻率合批。
	aggMu sync.Mutex
	agg   rejectedAgg

	// I/O 故障狀態：運行期故障即拒收新嘗試並於 Status 標示，修復後自動恢復。
	faultMu     sync.Mutex
	faultReason string

	// admission 間隔：固定最小間隔（非配額），單調時鐘，行程內共享、不持久化。
	admitToken chan struct{}
	admitMu    sync.Mutex
	baseline   time.Time
	hasBase    bool

	openScan scanResult
}

// rejectedAgg 為定長聚合器（欄位固定，不隨拒絕次數成長）。
type rejectedAgg struct {
	cooldown uint64
	backoff  uint64
	conflict uint64
	invalid  uint64
	firstTS  int64
	lastTS   int64
}

func (a *rejectedAgg) total() uint64 { return a.cooldown + a.backoff + a.conflict }

func newJournal(path string, f fileIO, h *header, opt Options, scan scanResult) *Journal {
	j := &Journal{
		path:       path,
		opt:        opt,
		bootID:     newBootID(),
		f:          f,
		hdr:        h,
		ops:        make(chan func()),
		stopCh:     make(chan struct{}),
		closedCh:   make(chan struct{}),
		closeDone:  make(chan struct{}),
		admitToken: make(chan struct{}, 1),
		openScan:   scan,
	}
	go j.run()
	return j
}

// run 為單一 writer 的 owner 迴圈。
func (j *Journal) run() {
	ticker := time.NewTicker(j.opt.RejectedFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case op := <-j.ops:
			op()
		case <-ticker.C:
			j.flushRejected()
			j.probeRecovery()
		case <-j.stopCh:
			j.flushRejected()
			j.closeErr = j.f.Close()
			close(j.closeDone)
			return
		}
	}
}

type opResult[T any] struct {
	val T
	err error
}

// submit 把一個操作交給 owner 執行並等待結果。
// 結果以緩衝通道回傳，ctx 逾時後 owner 仍可安全完成而不與呼叫端競爭。
func submit[T any](j *Journal, ctx context.Context, fn func() (T, error)) (T, error) {
	var zero T
	res := make(chan opResult[T], 1)
	op := func() {
		v, err := fn()
		res <- opResult[T]{val: v, err: err}
	}
	select {
	case j.ops <- op:
	case <-j.closedCh:
		return zero, ErrClosed
	case <-ctx.Done():
		return zero, ctx.Err()
	}
	select {
	case r := <-res:
		return r.val, r.err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func (j *Journal) writeCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok || j.opt.WriteTimeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, j.opt.WriteTimeout)
}

// WriteReceived 寫入 received 事件並回傳全域序號。
//
// 定序（崩潰一致性）：寫資料槽 → fdatasync → 推進 header → fdatasync。
// 本方法回傳即代表已完成到 header fdatasync；呼叫端 SHALL 於本方法成功回傳「之後」
// 才開始驗證材料，否則崩潰後可能沒有可辨識的 received，
// 核心不變式「任何被驗證的嘗試必有 durable 個別紀錄」當場破。
// 寫入失敗時呼叫端 SHALL 回滾 CAS 至 sourceState、拒絕該次、不驗證材料。
func (j *Journal) WriteReceived(ctx context.Context, gen uint64, sourceDigest string) (uint64, error) {
	if err := validateSourceDigest(sourceDigest); err != nil {
		return 0, err
	}
	wctx, cancel := j.writeCtx(ctx)
	defer cancel()
	return submit(j, wctx, func() (uint64, error) {
		return j.writeCritical(slotKindReceived, gen, 0, sourceDigest, "")
	})
}

// WriteOutcome 寫入某個 received 的結果碼。
// 「有 received 無 outcome」即為「結果未知」，故本方法失敗不得被吞掉。
func (j *Journal) WriteOutcome(ctx context.Context, gen uint64, seq uint64, outcome string) error {
	if !validOutcome(outcome) {
		return fmt.Errorf("%w: %q", ErrInvalidOutcome, outcome)
	}
	wctx, cancel := j.writeCtx(ctx)
	defer cancel()
	_, err := submit(j, wctx, func() (uint64, error) {
		if seq == 0 || seq >= j.hdr.SeqNext {
			return 0, fmt.Errorf("%w: seq=%d", ErrUnknownSeq, seq)
		}
		return j.writeCritical(slotKindOutcome, gen, seq, "", outcome)
	})
	return err
}

// WritePublished 寫入 published 標記（非 outcome 碼）。
// 呼叫端 SHALL 於 outcome=success 落地之後、publish 之前使用；
// 任一寫入失敗即 SHALL NOT 回覆解封成功。
func (j *Journal) WritePublished(ctx context.Context, gen uint64, seq uint64) error {
	wctx, cancel := j.writeCtx(ctx)
	defer cancel()
	_, err := submit(j, wctx, func() (uint64, error) {
		if seq == 0 || seq >= j.hdr.SeqNext {
			return 0, fmt.Errorf("%w: seq=%d", ErrUnknownSeq, seq)
		}
		return j.writeCritical(slotKindPublished, gen, seq, "", "")
	})
	return err
}

// RecordRejected 記錄未取得獨佔的嘗試（cooldown／backoff／conflict）。
// 只更新定長記憶體聚合器，不寫 critical 環、不觸發 fsync；
// 由 owner 按固定頻率合批落地。
func (j *Journal) RecordRejected(kind string) {
	now := time.Now().UnixNano()
	j.aggMu.Lock()
	defer j.aggMu.Unlock()
	switch kind {
	case RejectedCooldown:
		j.agg.cooldown++
	case RejectedBackoff:
		j.agg.backoff++
	case RejectedConflict:
		j.agg.conflict++
	default:
		j.agg.invalid++
		return
	}
	if j.agg.firstTS == 0 {
		j.agg.firstTS = now
	}
	j.agg.lastTS = now
}

// Close 停止 owner，最後合批一次 rejected 並關閉檔案。
func (j *Journal) Close() error {
	j.stopOnce.Do(func() {
		close(j.closedCh)
		close(j.stopCh)
	})
	<-j.closeDone
	return j.closeErr
}

// ---- owner 專用：實際 I/O ----

// writeCritical 為 critical 環的唯一寫入路徑（owner goroutine 內執行）。
// body-first／commit-last：先寫資料槽並 fdatasync，再推進 header 並 fdatasync。
// 不假設單槽寫入為原子；header 以 generation ＋ CRC32C 雙槽輪替。
func (j *Journal) writeCritical(kind uint8, gen, refSeq uint64, digest, outcome string) (uint64, error) {
	nh := *j.hdr
	seq := refSeq
	if kind == slotKindReceived {
		seq = nh.SeqNext
	}
	idx := nh.CriticalWriteIndex
	now := time.Now().UnixNano()

	// 環繞覆蓋：先讀出即將被覆蓋的槽，記錄被覆蓋的序號範圍
	// （覆蓋不得默默跨過未回灌資料）。
	var overwritten *criticalSlot
	if idx >= nh.CriticalSlotCount {
		old, err := j.readCriticalSlot(nh.layout(), idx-nh.CriticalSlotCount)
		if err == nil {
			overwritten = old
		}
	}

	slot := &criticalSlot{
		Kind:         kind,
		Seq:          seq,
		Gen:          gen,
		SlotIndex:    idx,
		TSUnixNano:   now,
		BootID:       j.bootID,
		SourceDigest: digest,
		Outcome:      outcome,
	}
	if _, err := j.f.WriteAt(encodeCriticalSlot(slot), nh.layout().criticalOffset(idx)); err != nil {
		return 0, j.fault("寫入 critical 槽失敗", err)
	}
	if err := j.f.Datasync(); err != nil {
		return 0, j.fault("同步 critical 槽失敗", err)
	}

	nh.CriticalWriteIndex = idx + 1
	if overwritten != nil {
		nh.Live.CriticalOverwritten++
		if nh.CriticalOverwrittenFirstSeq == 0 {
			nh.CriticalOverwrittenFirstSeq = overwritten.Seq
		}
		nh.CriticalOverwrittenLastSeq = overwritten.Seq
	}
	switch kind {
	case slotKindReceived:
		nh.SeqNext = seq + 1
		nh.Live.Received++
	case slotKindPublished:
		nh.Live.Published++
	case slotKindOutcome:
		switch outcome {
		case OutcomeSuccess:
			nh.Live.Success++
		case OutcomeMaterialFailure:
			nh.Live.MaterialFail++
		case OutcomeInitFailed:
			nh.Live.InitFail++
		case OutcomeTimeout:
			nh.Live.Timeout++
		case OutcomeAborted:
			nh.Live.Aborted++
		}
	}
	if nh.FirstEventTS == 0 {
		nh.FirstEventTS = now
	}
	nh.LastEventTS = now

	if err := j.commitHeader(&nh); err != nil {
		return 0, err
	}
	return seq, nil
}

// commitHeader 推進 header：generation+1 寫入另一個槽，並 fdatasync。
// header 更新本身亦須同步——否則崩潰後恢復程序看不到游標推進，
// 該資料槽即成為無法辨識的孤兒槽。
func (j *Journal) commitHeader(nh *header) error {
	nh.Generation = j.hdr.Generation + 1
	if _, err := j.f.WriteAt(encodeHeader(nh), headerSlotOffset(nh.Generation)); err != nil {
		return j.fault("寫入 header 失敗", err)
	}
	if err := j.f.Datasync(); err != nil {
		return j.fault("同步 header 失敗", err)
	}
	*j.hdr = *nh
	j.clearFault()
	return nil
}

// flushRejected 把記憶體聚合器合批寫入 rejected 環（owner goroutine 內執行）。
func (j *Journal) flushRejected() {
	j.aggMu.Lock()
	snap := j.agg
	j.aggMu.Unlock()
	if snap.total() == 0 {
		return
	}

	nh := *j.hdr
	idx := nh.RejectedWriteIndex
	if idx >= nh.RejectedSlotCount {
		if old, err := j.readRejectedSlot(nh.layout(), idx-nh.RejectedSlotCount); err == nil {
			nh.Live.RejectedOverwritten += old.Cooldown + old.Backoff + old.Conflict
		}
	}
	slot := &rejectedSlot{
		BatchIndex: idx,
		Cooldown:   snap.cooldown,
		Backoff:    snap.backoff,
		Conflict:   snap.conflict,
		FirstTS:    snap.firstTS,
		LastTS:     snap.lastTS,
		BootID:     j.bootID,
	}
	if _, err := j.f.WriteAt(encodeRejectedSlot(slot), nh.layout().rejectedOffset(idx)); err != nil {
		_ = j.fault("寫入 rejected 槽失敗", err)
		return
	}
	if err := j.f.Datasync(); err != nil {
		_ = j.fault("同步 rejected 槽失敗", err)
		return
	}
	nh.RejectedWriteIndex = idx + 1
	nh.Live.RejectedCooldown += snap.cooldown
	nh.Live.RejectedBackoff += snap.backoff
	nh.Live.RejectedConflict += snap.conflict
	nh.Live.RejectedObserved += snap.total()
	nh.Live.RejectedDurable += snap.total()
	if err := j.commitHeader(&nh); err != nil {
		return
	}

	// 只在完整落地後才扣除已合批的量；期間新增的拒絕留待下一批。
	j.aggMu.Lock()
	j.agg.cooldown -= snap.cooldown
	j.agg.backoff -= snap.backoff
	j.agg.conflict -= snap.conflict
	if j.agg.total() == 0 {
		j.agg.firstTS = 0
	}
	j.aggMu.Unlock()
}

// probeRecovery 於 I/O 故障後定期重寫 header 探測；成功即自動恢復。
func (j *Journal) probeRecovery() {
	if !j.Faulted() {
		return
	}
	nh := *j.hdr
	_ = j.commitHeader(&nh)
}

func (j *Journal) readCriticalSlot(lay layout, index uint64) (*criticalSlot, error) {
	buf := make([]byte, criticalSlotSize)
	if _, err := j.f.ReadAt(buf, lay.criticalOffset(index)); err != nil {
		return nil, err
	}
	return decodeCriticalSlot(buf)
}

func (j *Journal) readRejectedSlot(lay layout, index uint64) (*rejectedSlot, error) {
	buf := make([]byte, rejectedSlotSize)
	if _, err := j.f.ReadAt(buf, lay.rejectedOffset(index)); err != nil {
		return nil, err
	}
	return decodeRejectedSlot(buf)
}

// ---- 故障狀態 ----

func (j *Journal) fault(what string, err error) error {
	j.faultMu.Lock()
	j.faultReason = fmt.Sprintf("%s: %v", what, err)
	j.faultMu.Unlock()
	return fmt.Errorf("sealjournal: %s: %w", what, err)
}

func (j *Journal) clearFault() {
	j.faultMu.Lock()
	j.faultReason = ""
	j.faultMu.Unlock()
}

// Faulted 回報 journal 是否處於 I/O 故障狀態。
func (j *Journal) Faulted() bool {
	j.faultMu.Lock()
	defer j.faultMu.Unlock()
	return j.faultReason != ""
}

func (j *Journal) faultReasonText() string {
	j.faultMu.Lock()
	defer j.faultMu.Unlock()
	return j.faultReason
}

// ---- 掃描與狀態 ----

type scannedEvent struct {
	Kind         string
	Seq          uint64
	Gen          uint64
	SlotIndex    uint64
	TS           time.Time
	SourceDigest string
	Outcome      string
}

type scanResult struct {
	Events               []scannedEvent
	CorruptCriticalSlots int
	CorruptRejectedSlots int
	UnknownOutcomeSeqs   []uint64
	MissingSeqs          []uint64
}

// scanRings 完整掃描兩個環。兼作開檔時「可完整讀取」的健全性檢查。
// (ii) 序號缺口與 (iii) 環繞 torn overwrite 於此判定：CRC 不符即計為 corrupt。
func scanRings(f fileIO, h *header) (scanResult, error) {
	lay := h.layout()
	var res scanResult
	received := map[uint64]bool{}
	hasOutcome := map[uint64]bool{}

	for i := 0; i < lay.criticalSlots; i++ {
		buf := make([]byte, criticalSlotSize)
		if _, err := f.ReadAt(buf, criticalRingOffset+int64(i)*criticalSlotSize); err != nil {
			return res, fmt.Errorf("讀取 critical 槽 %d 失敗: %w", i, err)
		}
		s, err := decodeCriticalSlot(buf)
		if err != nil {
			if err == errSlotCorrupt {
				res.CorruptCriticalSlots++
			}
			continue
		}
		kind := KindReceived
		switch s.Kind {
		case slotKindOutcome:
			kind = KindOutcome
			hasOutcome[s.Seq] = true
		case slotKindPublished:
			kind = KindPublished
		default:
			received[s.Seq] = true
		}
		res.Events = append(res.Events, scannedEvent{
			Kind:         kind,
			Seq:          s.Seq,
			Gen:          s.Gen,
			SlotIndex:    s.SlotIndex,
			TS:           time.Unix(0, s.TSUnixNano).UTC(),
			SourceDigest: s.SourceDigest,
			Outcome:      s.Outcome,
		})
	}
	for i := 0; i < lay.rejectedSlots; i++ {
		buf := make([]byte, rejectedSlotSize)
		if _, err := f.ReadAt(buf, lay.rejectedOffset(uint64(i))); err != nil {
			return res, fmt.Errorf("讀取 rejected 槽 %d 失敗: %w", i, err)
		}
		if _, err := decodeRejectedSlot(buf); err == errSlotCorrupt {
			res.CorruptRejectedSlots++
		}
	}

	sort.Slice(res.Events, func(a, b int) bool { return res.Events[a].SlotIndex < res.Events[b].SlotIndex })

	// 「有 received 無 outcome」＝結果未知（唯一判準）。
	for seq := range received {
		if !hasOutcome[seq] {
			res.UnknownOutcomeSeqs = append(res.UnknownOutcomeSeqs, seq)
		}
	}
	sort.Slice(res.UnknownOutcomeSeqs, func(a, b int) bool {
		return res.UnknownOutcomeSeqs[a] < res.UnknownOutcomeSeqs[b]
	})

	// 序號缺口：環內可見的 received 序號區間中缺少的那些（含環繞覆蓋造成者）。
	var minSeq, maxSeq uint64
	for seq := range received {
		if minSeq == 0 || seq < minSeq {
			minSeq = seq
		}
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	for seq := minSeq; seq != 0 && seq <= maxSeq; seq++ {
		if !received[seq] {
			res.MissingSeqs = append(res.MissingSeqs, seq)
		}
	}
	return res, nil
}

// Status 為 /seal/status 的資料來源。
type Status struct {
	Path             string
	JournalUUID      string
	BootID           string
	FileSize         int64
	HeaderGeneration uint64
	SeqNext          uint64

	ReceivedTotal        uint64
	PublishedTotal       uint64
	SuccessTotal         uint64
	MaterialFailureTotal uint64
	InitFailedTotal      uint64
	TimeoutTotal         uint64
	AbortedTotal         uint64

	RejectedCooldownTotal    uint64
	RejectedBackoffTotal     uint64
	RejectedConflictTotal    uint64
	RejectedObservedTotal    uint64
	RejectedDurableTotal     uint64
	RejectedOverwrittenTotal uint64
	// RejectedPendingTotal 為尚未合批落地的量（誠實邊界：崩潰最多遺失一個有上限的時窗）。
	RejectedPendingTotal uint64

	CriticalWriteIndex          uint64
	CriticalOverwrittenTotal    uint64
	CriticalOverwrittenFirstSeq uint64
	CriticalOverwrittenLastSeq  uint64

	ReplayCheckpointSeq uint64
	ReplayedEvents      uint64
	ReplayedBatches     uint64

	UnknownOutcomeSeqs   []uint64
	MissingSeqs          []uint64
	CorruptCriticalSlots int
	CorruptRejectedSlots int

	IOFaulted     bool
	IOFaultReason string

	FirstEventTS         time.Time
	LastEventTS          time.Time
	MinAdmissionInterval time.Duration
}

// Status 回傳當前狀態（含一次完整環掃描）。
func (j *Journal) Status(ctx context.Context) (Status, error) {
	st, err := submit(j, ctx, func() (Status, error) {
		scan, scanErr := scanRings(j.f, j.hdr)
		return j.statusFrom(scan), scanErr
	})
	if err != nil {
		return st, err
	}
	return st, nil
}

func (j *Journal) statusFrom(scan scanResult) Status {
	h := j.hdr
	j.aggMu.Lock()
	pending := j.agg.total()
	j.aggMu.Unlock()
	st := Status{
		Path:                        j.path,
		JournalUUID:                 formatUUID(h.JournalUUID),
		BootID:                      hex.EncodeToString(j.bootID[:]),
		FileSize:                    int64(h.FileSize),
		HeaderGeneration:            h.Generation,
		SeqNext:                     h.SeqNext,
		ReceivedTotal:               h.Live.Received,
		PublishedTotal:              h.Live.Published,
		SuccessTotal:                h.Live.Success,
		MaterialFailureTotal:        h.Live.MaterialFail,
		InitFailedTotal:             h.Live.InitFail,
		TimeoutTotal:                h.Live.Timeout,
		AbortedTotal:                h.Live.Aborted,
		RejectedCooldownTotal:       h.Live.RejectedCooldown,
		RejectedBackoffTotal:        h.Live.RejectedBackoff,
		RejectedConflictTotal:       h.Live.RejectedConflict,
		RejectedObservedTotal:       h.Live.RejectedObserved + pending,
		RejectedDurableTotal:        h.Live.RejectedDurable,
		RejectedOverwrittenTotal:    h.Live.RejectedOverwritten,
		RejectedPendingTotal:        pending,
		CriticalWriteIndex:          h.CriticalWriteIndex,
		CriticalOverwrittenTotal:    h.Live.CriticalOverwritten,
		CriticalOverwrittenFirstSeq: h.CriticalOverwrittenFirstSeq,
		CriticalOverwrittenLastSeq:  h.CriticalOverwrittenLastSeq,
		ReplayCheckpointSeq:         h.ReplayCheckpointSeq,
		ReplayedEvents:              h.ReplayedEvents,
		ReplayedBatches:             h.ReplayedBatches,
		UnknownOutcomeSeqs:          scan.UnknownOutcomeSeqs,
		MissingSeqs:                 scan.MissingSeqs,
		CorruptCriticalSlots:        scan.CorruptCriticalSlots,
		CorruptRejectedSlots:        scan.CorruptRejectedSlots,
		IOFaulted:                   j.Faulted(),
		IOFaultReason:               j.faultReasonText(),
		MinAdmissionInterval:        j.opt.MinAdmissionInterval,
	}
	if h.FirstEventTS != 0 {
		st.FirstEventTS = time.Unix(0, h.FirstEventTS).UTC()
	}
	if h.LastEventTS != 0 {
		st.LastEventTS = time.Unix(0, h.LastEventTS).UTC()
	}
	return st
}

// OpenRecovery 回傳開檔當下的恢復掃描結果摘要（供啟動日誌與 runbook 判讀）。
func (j *Journal) OpenRecovery() (unknownOutcome []uint64, missing []uint64, corruptCritical int) {
	return j.openScan.UnknownOutcomeSeqs, j.openScan.MissingSeqs, j.openScan.CorruptCriticalSlots
}

func formatUUID(b [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// validateSourceDigest 只接受十六進位摘要。
// 這是「內容白名單」的機械保證：原始材料（KEK、憑證、請求體）不可能通過此驗證，
// 因此在建構上無法進入 journal。
func validateSourceDigest(d string) error {
	if len(d) > maxSourceDigestLen {
		return ErrInvalidSourceDigest
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return ErrInvalidSourceDigest
	}
	return nil
}

func validOutcome(o string) bool {
	switch o {
	case OutcomeSuccess, OutcomeMaterialFailure, OutcomeInitFailed, OutcomeTimeout, OutcomeAborted:
		return true
	}
	return false
}
