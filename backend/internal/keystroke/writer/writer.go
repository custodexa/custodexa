// Package writer 把事件加密後落地成鍵盤紀錄檔。
//
// 呼叫端（bridge 的輸入泵）呼叫 Append；Append 只做編碼與入佇列，
// 加密與 I/O 由單一寫入 goroutine 完成。佇列有筆數與位元組雙上限，
// 佇列滿時 Append 在呼叫端同步等待（背壓），事件一筆不丟。
// 等待上限以「寫入端沒有進展」計：連續 StallTimeout 沒有任何一段完成，
// 才判定寫入端停擺並失敗；失敗後 Append 立即返回、不再等待。
//
// 明文事件內容不會出現在任何錯誤訊息或 log。
package writer

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/keystroke"
	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/keystroke/sealer"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
)

// 預設值。
const (
	DefaultSegmentBytes    = 16 << 10
	DefaultSegmentInterval = time.Second
	DefaultMaxQueueEvents  = 4096
	DefaultMaxQueueBytes   = 1 << 20
	// StallTimeout 是常數而非政策鍵：做成政策鍵就成了可調鬆的關閉途徑。
	DefaultStallTimeout = 10 * time.Second
)

// closeGrace 為失敗後 Close 等待寫入 goroutine 收尾的上限。
const closeGrace = 2 * time.Second

var (
	ErrClosed  = errors.New("keystroke writer: closed")
	ErrFailed  = errors.New("keystroke writer: failed")
	ErrStalled = errors.New("keystroke writer: stalled")
)

// OpenError 標示啟動階段的失敗原因碼。
type OpenError struct {
	Cause string
	Err   error
}

func (e *OpenError) Error() string { return fmt.Sprintf("keystroke open (%s): %v", e.Cause, e.Err) }
func (e *OpenError) Unwrap() error { return e.Err }

// File 為落地檔的最小介面，測試可包裝以注入慢速、停住或失敗。
type File interface {
	io.Writer
	Sync() error
	Close() error
}

// Stats 為寫入統計。
type Stats struct {
	Events   int64
	Bytes    int64 // 已寫出的檔案位元組數
	Segments int64
	LastAt   time.Time
}

// Config 為寫入器設定。
type Config struct {
	Root       string
	RecordUUID string // 標準 UUID 字串
	SessionID  uint64
	Protocol   string
	Start      time.Time
	// Key 為 32-byte 檔案金鑰；所有權移交寫入器，Close 或失敗時 Destroy
	Key *material.Secret

	// 以下皆可省略（測試用）
	Mono            func() time.Duration
	SegmentBytes    int
	SegmentInterval time.Duration
	MaxQueueEvents  int
	MaxQueueBytes   int
	StallTimeout    time.Duration
	WrapFile        func(File) File
	// OnFail 於首次失敗時呼叫一次（不在持鎖狀態下）
	OnFail func(cause string, err error)
	// OnSegment 於每段寫出後由寫入 goroutine 呼叫
	OnSegment func(Stats)
}

type queued struct {
	data []byte
}

// Writer 為單一紀錄檔的寫入器。
type Writer struct {
	cfg   Config
	suite *sealer.Suite
	key   *material.Secret
	file  File
	path  string // 相對於根目錄
	start time.Time
	mono  func() time.Duration

	mu        sync.Mutex
	q         []queued
	qBytes    int
	inSeg     int // 已移入段緩衝但尚未封出的事件位元組（計入背壓）
	failed    error
	failCause string
	// stallMarker 停擺失敗後，寫入 goroutine 若仍能執行，把停擺標記與緩衝中的事件封成最後一段（非結束段）
	stallMarker bool
	closed      bool
	lastDelta   time.Duration
	bcast       chan struct{} // 空間釋出或狀態改變時關閉並替換
	progress    time.Time

	wake chan struct{}
	done chan struct{}

	failOnce sync.Once

	stats Stats
	seq   uint32
}

// Open 建立目錄與檔案、寫出標頭並啟動寫入 goroutine。
// 失敗回傳 *OpenError（Cause 為 KEYSTROKE_DIR_UNWRITABLE 或 KEYSTROKE_FILE_CREATE_FAILED）；
// 失敗時 Key 已被 Destroy。
func Open(cfg Config) (*Writer, error) {
	fail := func(cause string, err error) (*Writer, error) {
		cfg.Key.Destroy()
		return nil, &OpenError{Cause: cause, Err: err}
	}
	if cfg.SegmentBytes <= 0 {
		cfg.SegmentBytes = DefaultSegmentBytes
	}
	if cfg.SegmentInterval <= 0 {
		cfg.SegmentInterval = DefaultSegmentInterval
	}
	if cfg.MaxQueueEvents <= 0 {
		cfg.MaxQueueEvents = DefaultMaxQueueEvents
	}
	if cfg.MaxQueueBytes <= 0 {
		cfg.MaxQueueBytes = DefaultMaxQueueBytes
	}
	if cfg.StallTimeout <= 0 {
		cfg.StallTimeout = DefaultStallTimeout
	}

	uid, err := parseUUID(cfg.RecordUUID)
	if err != nil {
		return fail(model.CauseKeystrokeFileCreateFailed, err)
	}
	hdr := format.Header{
		RecordUUID: uid, SessionID: cfg.SessionID, Protocol: cfg.Protocol,
		StartUnixNs: cfg.Start.UTC().UnixNano(), SegmentMax: uint32(cfg.SegmentBytes),
	}
	if _, err := rand.Read(hdr.NoncePrefix[:]); err != nil {
		return fail(model.CauseKeystrokeFileCreateFailed, err)
	}
	hdrBytes, err := hdr.Encode()
	if err != nil {
		return fail(model.CauseKeystrokeFileCreateFailed, err)
	}
	var suite *sealer.Suite
	if err := cfg.Key.Borrow(func(k []byte) error {
		s, e := sealer.NewSuite(k, hdr, hdrBytes)
		suite = s
		return e
	}); err != nil {
		return fail(model.CauseKeystrokeFileCreateFailed, err)
	}

	rel := keystroke.RelPath(cfg.RecordUUID, cfg.Start)
	full := filepath.Join(cfg.Root, rel)
	if err := keystroke.EnsureDir(cfg.Root); err != nil {
		return fail(model.CauseKeystrokeDirUnwritable, err)
	}
	if err := keystroke.EnsureDir(filepath.Dir(full)); err != nil {
		return fail(model.CauseKeystrokeDirUnwritable, err)
	}
	// O_EXCL：同名檔已存在即失敗，絕不附加到既有檔尾
	osf, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, keystroke.FilePerm)
	if err != nil {
		return fail(model.CauseKeystrokeFileCreateFailed, err)
	}
	var f File = osf
	if cfg.WrapFile != nil {
		f = cfg.WrapFile(f)
	}
	if _, err := f.Write(hdrBytes); err != nil {
		_ = f.Close()
		return fail(model.CauseKeystrokeFileCreateFailed, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fail(model.CauseKeystrokeFileCreateFailed, err)
	}

	w := &Writer{
		cfg: cfg, suite: suite, key: cfg.Key, file: f, path: rel, start: cfg.Start,
		bcast: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{}),
		progress: time.Now(),
	}
	w.stats.Bytes = int64(len(hdrBytes))
	if cfg.Mono != nil {
		w.mono = cfg.Mono
	} else {
		t0 := time.Now() // 含單調讀值：delta 不受牆鐘調整影響
		w.mono = func() time.Duration { return time.Since(t0) }
	}
	go w.run()
	return w, nil
}

func parseUUID(s string) ([format.UUIDLen]byte, error) {
	var out [format.UUIDLen]byte
	j := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		if j >= 32 {
			return out, errors.New("bad uuid")
		}
		v, ok := hexVal(s[i])
		if !ok {
			return out, errors.New("bad uuid")
		}
		if j%2 == 0 {
			out[j/2] = v << 4
		} else {
			out[j/2] |= v
		}
		j++
	}
	if j != 32 {
		return out, errors.New("bad uuid")
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// RelPath 回傳檔案相對於根目錄的路徑。
func (w *Writer) RelPath() string { return w.path }

// Append 追加一筆事件。佇列滿時同步等待（背壓）；寫入端停擺時回傳錯誤。
// 失敗或關閉後立即返回錯誤。呼叫端不得因錯誤中斷轉發。
func (w *Writer) Append(kind, flags byte, payload []byte) error {
	if (kind != format.KindBytes && kind != format.KindKeysymRaw) || len(payload) <= MaxEventPayload {
		return w.appendOne(kind, flags, payload, nil)
	}
	// 單筆過大的位元組事件切成多筆連續事件（同時間戳、同旗標、順序不變），
	// 讓任何一段都遠低於讀取端的單段長度上限。
	var ts *time.Duration
	for len(payload) > 0 {
		n := len(payload)
		if n > MaxEventPayload {
			n = MaxEventPayload
		}
		if err := w.appendOne(kind, flags, payload[:n], &ts); err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

// MaxEventPayload 是單筆 bytes／原始圖形事件的 payload 上限；超過者由 Append 切分。
const MaxEventPayload = 64 << 10

// appendOne 追加單筆事件。ts 非 nil 時，同一次 Append 的各片共用第一片的時間戳。
func (w *Writer) appendOne(kind, flags byte, payload []byte, ts **time.Duration) error {
	size := len(payload) + 12
	var timer *time.Timer
	var waitStart time.Time // 本次 Append 開始等待的時間；閒置後才灌入大量輸入不算停擺
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return ErrClosed
		}
		if w.failed != nil {
			w.mu.Unlock()
			return ErrFailed
		}
		total := w.qBytes + w.inSeg
		if (len(w.q) == 0 && total == 0) ||
			(len(w.q) < w.cfg.MaxQueueEvents && total+size <= w.cfg.MaxQueueBytes) {
			d := w.mono()
			if ts != nil && *ts != nil {
				d = **ts
			}
			if d < w.lastDelta {
				d = w.lastDelta // 回撥時保持非遞減
			}
			w.lastDelta = d
			if ts != nil && *ts == nil {
				dd := d
				*ts = &dd
			}
			enc := format.AppendEvent(make([]byte, 0, size), uint64(d/time.Millisecond), kind, flags, payload)
			w.q = append(w.q, queued{data: enc})
			w.qBytes += len(enc)
			w.mu.Unlock()
			w.poke()
			return nil
		}
		ch := w.bcast
		base := w.progress
		w.mu.Unlock()
		if waitStart.IsZero() {
			waitStart = time.Now()
		}
		if waitStart.After(base) {
			base = waitStart
		}
		wait := w.cfg.StallTimeout - time.Since(base)
		if wait <= 0 {
			w.fail(model.CauseKeystrokeWriterStalled, ErrStalled)
			return ErrStalled
		}
		if timer == nil {
			timer = time.NewTimer(wait)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(wait)
		}
		select {
		case <-ch:
		case <-timer.C:
		}
	}
}

func (w *Writer) poke() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// broadcast 通知等待中的 Append；呼叫時須持有 w.mu。
func (w *Writer) broadcastLocked() {
	close(w.bcast)
	w.bcast = make(chan struct{})
}

// fail 記錄首次失敗並通知；其後的 Append 立即返回。
func (w *Writer) fail(cause string, err error) {
	w.mu.Lock()
	first := w.failed == nil
	if first {
		w.failed = err
		w.failCause = cause
		w.stallMarker = cause == model.CauseKeystrokeWriterStalled
		w.q = nil
		w.qBytes = 0
		w.inSeg = 0
	}
	w.broadcastLocked()
	w.mu.Unlock()
	if first {
		w.key.Destroy()
		w.poke()
		w.failOnce.Do(func() {
			if w.cfg.OnFail != nil {
				w.cfg.OnFail(cause, err)
			}
		})
	}
}

// run 為單一寫入 goroutine。
func (w *Writer) run() {
	defer close(w.done)
	var segBuf []byte
	var segEvents int64
	var segDeadline time.Time
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	flush := func(final bool) bool {
		frame, err := w.suite.Seal(w.seq, segBuf, final)
		if err != nil {
			w.fail(model.CauseKeystrokeWriteFailed, err)
			return false
		}
		if err := sealer.WriteFrame(w.file, frame); err != nil {
			w.fail(model.CauseKeystrokeWriteFailed, err)
			return false
		}
		w.seq++
		now := time.Now()
		w.mu.Lock()
		w.inSeg -= len(segBuf)
		if w.inSeg < 0 {
			w.inSeg = 0
		}
		w.progress = now
		w.stats.Events += segEvents
		w.stats.Bytes += int64(len(frame))
		w.stats.Segments++
		w.stats.LastAt = now
		st := w.stats
		w.broadcastLocked()
		w.mu.Unlock()
		clear(segBuf)
		segBuf = segBuf[:0]
		segEvents = 0
		if w.cfg.OnSegment != nil {
			w.cfg.OnSegment(st)
		}
		return true
	}

	for {
		w.mu.Lock()
		failed := w.failed != nil
		stallMarker := w.stallMarker
		w.stallMarker = false
		closed := w.closed
		batch := w.q
		w.q = nil
		moved := 0
		for _, e := range batch {
			moved += len(e.data)
		}
		w.qBytes -= moved
		w.inSeg += moved
		w.mu.Unlock()
		if failed {
			if stallMarker {
				// 盡力而為：非結束段，讀取器仍判定為不完整；寫不進去就放棄
				w.mu.Lock()
				d := w.mono()
				if d < w.lastDelta {
					d = w.lastDelta
				}
				w.mu.Unlock()
				segBuf = format.AppendEvent(segBuf, uint64(d/time.Millisecond),
					format.KindMarker, format.FlagPlatform, []byte(keystroke.MarkerWriterStalled))
				segEvents++
				flush(false)
			}
			w.cleanup()
			return
		}
		for _, e := range batch {
			if len(segBuf) == 0 {
				segDeadline = time.Now().Add(w.cfg.SegmentInterval)
			}
			segBuf = append(segBuf, e.data...)
			segEvents++
			clear(e.data)
			if len(segBuf) >= w.cfg.SegmentBytes {
				if !flush(false) {
					w.cleanup()
					return
				}
			}
		}
		if closed {
			w.mu.Lock()
			more := len(w.q) > 0
			w.mu.Unlock()
			if more {
				continue
			}
			if !flush(true) { // 正常結束一律封結束段（可為空）
				w.cleanup()
				return
			}
			w.cleanup()
			return
		}
		var tc <-chan time.Time
		if len(segBuf) > 0 {
			d := time.Until(segDeadline)
			if d <= 0 {
				if !flush(false) {
					w.cleanup()
					return
				}
				continue
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(d)
			tc = timer.C
		}
		select {
		case <-w.wake:
		case <-tc:
		}
	}
}

func (w *Writer) cleanup() {
	if w.file != nil {
		_ = w.file.Close()
	}
	w.key.Destroy()
}

// Close 結束寫入：排空佇列、封結束段、fsync、關檔並清除金鑰。
// 已失敗時回傳失敗錯誤。重複呼叫安全。
func (w *Writer) Close() (Stats, error) {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		w.broadcastLocked()
	}
	w.mu.Unlock()
	w.poke()
	closeStart := time.Now()
	select {
	case <-w.done:
	case <-time.After(closeGrace):
		// 寫入端還沒收尾：只要仍有進展就繼續等；連續 StallTimeout 沒有任何一段完成
		// （含卡在系統呼叫）即判停擺並返回，不再等 done，收尾因此一定在上限內結束。
		// 卡住的 goroutine 日後自行關檔。
		w.waitDoneOrStall(closeStart)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats, w.failed
}

// waitDoneOrStall 等寫入 goroutine 收尾，直到它結束、已失敗或停擺逾時。
func (w *Writer) waitDoneOrStall(closeStart time.Time) {
	for {
		w.mu.Lock()
		failed := w.failed != nil
		base := w.progress
		w.mu.Unlock()
		if failed {
			return
		}
		if closeStart.After(base) {
			base = closeStart
		}
		remaining := w.cfg.StallTimeout - time.Since(base)
		if remaining <= 0 {
			w.fail(model.CauseKeystrokeWriterStalled, ErrStalled)
			return
		}
		select {
		case <-w.done:
			return
		case <-time.After(remaining):
		}
	}
}

// Stats 回傳目前統計。
func (w *Writer) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats
}

// FailCause 回傳失敗原因碼（未失敗為空字串）。
func (w *Writer) FailCause() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.failCause
}
