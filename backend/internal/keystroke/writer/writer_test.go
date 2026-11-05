package writer

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/keystroke"
	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/keystroke/reader"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
)

const testUUID = "0a1b2c3d-4e5f-4061-8283-949596979899"

type testEnv struct {
	root string
	key  []byte
	cfg  Config
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	kc := append([]byte(nil), key...)
	root := filepath.Join(t.TempDir(), "keystrokes")
	return &testEnv{root: root, key: key, cfg: Config{
		Root: root, RecordUUID: testUUID, SessionID: 7, Protocol: "ssh",
		Start: time.Date(2026, 11, 5, 3, 4, 5, 0, time.UTC), Key: material.Adopt(kc),
	}}
}

func (e *testEnv) read(t *testing.T) reader.Result {
	t.Helper()
	return reader.Read(e.root, reader.Record{
		UUID: testUUID, SessionID: 7, Protocol: "ssh",
		FilePath: keystroke.RelPath(testUUID, e.cfg.Start),
	}, e.key, reader.Options{})
}

func TestZeroEventCloseWritesEmptyFinalSegment(t *testing.T) {
	e := newEnv(t)
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	st, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if st.Segments != 1 || st.Events != 0 {
		t.Fatalf("segments=%d events=%d", st.Segments, st.Events)
	}
	r := e.read(t)
	if r.Status != reader.StatusComplete || r.TotalEvents != 0 || r.SegmentsRead != 1 {
		t.Fatalf("status=%s total=%d segs=%d", r.Status, r.TotalEvents, r.SegmentsRead)
	}
}

func TestSegmentsAndFlagsRoundTrip(t *testing.T) {
	e := newEnv(t)
	e.cfg.SegmentBytes = 256
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		fl := byte(0)
		if i%10 == 0 {
			fl = format.FlagBlocked
		}
		if err := w.Append(format.KindBytes, fl, []byte(fmt.Sprintf("ev-%03d", i))); err != nil {
			t.Fatal(err)
		}
	}
	st, err := w.Close()
	if err != nil || st.Events != 100 || st.Segments < 3 {
		t.Fatalf("close err=%v events=%d segments=%d", err, st.Events, st.Segments)
	}
	r := e.read(t)
	if r.Status != reader.StatusComplete || r.TotalEvents != 100 {
		t.Fatalf("status=%s total=%d", r.Status, r.TotalEvents)
	}
	for i, ev := range r.Events {
		if string(ev.Payload) != fmt.Sprintf("ev-%03d", i) {
			t.Fatalf("order mismatch at %d", i)
		}
		if (i%10 == 0) != (ev.Flags&format.FlagBlocked != 0) {
			t.Fatalf("flag mismatch at %d", i)
		}
	}
}

// 慢速寫入端下灌入 8 MiB：背壓使呼叫端變慢，但事件全數落地、不判失敗。
type slowFile struct {
	File
	delay time.Duration
}

func (s *slowFile) Write(p []byte) (int, error) {
	time.Sleep(s.delay)
	return s.File.Write(p)
}

func TestSlowWriterBackpressureLosesNothing(t *testing.T) {
	e := newEnv(t)
	e.cfg.MaxQueueBytes = 64 << 10
	e.cfg.StallTimeout = 5 * time.Second
	e.cfg.WrapFile = func(f File) File { return &slowFile{File: f, delay: time.Millisecond} }
	var failed atomic.Int32
	e.cfg.OnFail = func(string, error) { failed.Add(1) }
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{0xA5}, 1024)
	const total = 8 << 20
	for sent := 0; sent < total; sent += len(chunk) {
		if err := w.Append(format.KindBytes, 0, chunk); err != nil {
			t.Fatalf("append failed after %d bytes: %v", sent, err)
		}
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if failed.Load() != 0 {
		t.Fatal("OnFail must not fire under backpressure")
	}
	r := e.read(t)
	got := 0
	n := 0
	rr := reader.Read(e.root, reader.Record{UUID: testUUID, SessionID: 7, Protocol: "ssh",
		FilePath: keystroke.RelPath(testUUID, e.cfg.Start)}, e.key, reader.Options{Limit: 1 << 30})
	for _, ev := range rr.Events {
		got += len(ev.Payload)
		n++
	}
	if r.Status != reader.StatusComplete || got != total || n != total/len(chunk) {
		t.Fatalf("status=%s bytes=%d events=%d", r.Status, got, n)
	}
}

// 寫入端完全停住：連續 StallTimeout 無進展後失敗，並解除等待。
type stuckFile struct {
	File
	block   chan struct{}
	stuckAt int32
	calls   atomic.Int32
}

func (s *stuckFile) Write(p []byte) (int, error) {
	if s.calls.Add(1) > s.stuckAt {
		<-s.block
	}
	return s.File.Write(p)
}

func TestStuckWriterFailsAfterStallTimeout(t *testing.T) {
	e := newEnv(t)
	e.cfg.MaxQueueBytes = 4 << 10
	e.cfg.SegmentBytes = 512
	e.cfg.StallTimeout = 300 * time.Millisecond
	sf := &stuckFile{block: make(chan struct{}), stuckAt: 2} // 標頭寫出後第 1 段通過，之後停住
	e.cfg.WrapFile = func(f File) File { sf.File = f; return sf }
	var mu sync.Mutex
	var causes []string
	e.cfg.OnFail = func(c string, _ error) { mu.Lock(); causes = append(causes, c); mu.Unlock() }
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{1}, 300)
	start := time.Now()
	var appendErr error
	for i := 0; i < 1000 && appendErr == nil; i++ {
		appendErr = w.Append(format.KindBytes, 0, chunk)
	}
	elapsed := time.Since(start)
	if !errors.Is(appendErr, ErrStalled) {
		t.Fatalf("append err=%v", appendErr)
	}
	if elapsed < 250*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("stall detection took %v", elapsed)
	}
	t0 := time.Now()
	if err := w.Append(format.KindBytes, 0, chunk); err == nil || time.Since(t0) > 100*time.Millisecond {
		t.Fatalf("append after failure must return immediately with error, err=%v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(causes) != 1 || causes[0] != model.CauseKeystrokeWriterStalled {
		t.Fatalf("causes=%v", causes)
	}
	if w.FailCause() != model.CauseKeystrokeWriterStalled {
		t.Fatalf("FailCause=%q", w.FailCause())
	}
	close(sf.block)
	if _, err := w.Close(); err == nil {
		t.Fatal("Close after failure must return the failure")
	}
}

type failFile struct {
	File
	calls atomic.Int32
	after int32
}

func (f *failFile) Write(p []byte) (int, error) {
	if f.calls.Add(1) > f.after {
		return 0, errors.New("injected write error")
	}
	return f.File.Write(p)
}

func TestWriteErrorFailsOnce(t *testing.T) {
	e := newEnv(t)
	e.cfg.SegmentBytes = 64
	ff := &failFile{after: 1}
	e.cfg.WrapFile = func(f File) File { ff.File = f; return ff }
	var n atomic.Int32
	var cause atomic.Value
	e.cfg.OnFail = func(c string, _ error) { n.Add(1); cause.Store(c) }
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		_ = w.Append(format.KindBytes, 0, bytes.Repeat([]byte{2}, 40))
		time.Sleep(time.Millisecond)
	}
	_, cerr := w.Close()
	if cerr == nil {
		t.Fatal("expected failure")
	}
	if n.Load() != 1 || cause.Load() != model.CauseKeystrokeWriteFailed {
		t.Fatalf("OnFail count=%d cause=%v", n.Load(), cause.Load())
	}
}

func TestAppendAfterCloseRejected(t *testing.T) {
	e := newEnv(t)
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(format.KindBytes, 0, []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
	if _, err := w.Close(); err != nil { // 重複 Close 安全
		t.Fatal(err)
	}
}

func TestClockRollbackKeepsDeltaMonotonic(t *testing.T) {
	e := newEnv(t)
	seq := []time.Duration{5 * time.Second, 3 * time.Second, 9 * time.Second, 1 * time.Second}
	var i int
	e.cfg.Mono = func() time.Duration { d := seq[i%len(seq)]; i++; return d }
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for k := 0; k < 4; k++ {
		_ = w.Append(format.KindBytes, 0, []byte{byte(k)})
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := e.read(t)
	var prev uint64
	for _, ev := range r.Events {
		if ev.DeltaMs < prev {
			t.Fatalf("delta went backwards: %d < %d", ev.DeltaMs, prev)
		}
		prev = ev.DeltaMs
	}
	if len(r.Events) != 4 {
		t.Fatalf("events=%d", len(r.Events))
	}
}

func TestPathLayoutAndPerms(t *testing.T) {
	e := newEnv(t)
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Close()
	want := filepath.Join("2026-11-05", testUUID+".cxkr")
	if w.RelPath() != want {
		t.Fatalf("rel=%s", w.RelPath())
	}
	fi, err := os.Stat(filepath.Join(e.root, want))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file perm: %v %v", fi, err)
	}
	for _, d := range []string{e.root, filepath.Join(e.root, "2026-11-05")} {
		di, err := os.Stat(d)
		if err != nil || di.Mode().Perm() != 0o700 {
			t.Fatalf("dir perm %s: %v", d, err)
		}
	}
}

func TestExclusiveCreateRefusesExistingFile(t *testing.T) {
	e := newEnv(t)
	dir := filepath.Join(e.root, "2026-11-05")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pre := filepath.Join(dir, testUUID+".cxkr")
	if err := os.WriteFile(pre, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(e.cfg)
	var oe *OpenError
	if !errors.As(err, &oe) || oe.Cause != model.CauseKeystrokeFileCreateFailed {
		t.Fatalf("err=%v", err)
	}
	b, _ := os.ReadFile(pre)
	if string(b) != "old" {
		t.Fatal("existing file was modified")
	}
}

func TestOpenDirUnwritable(t *testing.T) {
	e := newEnv(t)
	blocker := filepath.Join(t.TempDir(), "afile")
	_ = os.WriteFile(blocker, nil, 0o600)
	e.cfg.Root = filepath.Join(blocker, "keystrokes") // 上層是一般檔，無法建立目錄
	_, err := Open(e.cfg)
	var oe *OpenError
	if !errors.As(err, &oe) || oe.Cause != model.CauseKeystrokeDirUnwritable {
		t.Fatalf("err=%v", err)
	}
}

const marker = "KS-PLAINTEXT-MARKER-7f3a9c"

func TestNoPlaintextOnDisk(t *testing.T) {
	e := newEnv(t)
	e.cfg.SegmentBytes = 128
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		_ = w.Append(format.KindBytes, 0, []byte(marker))
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(e.root, w.RelPath()))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(marker)) || bytes.Contains(raw, []byte(marker[:12])) {
		t.Fatalf("plaintext marker found in file (size=%d)", len(raw))
	}
	if bytes.Contains(raw, e.key) {
		t.Fatal("key bytes found in file")
	}
}

func TestNoPlaintextInLogs(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// 成功路徑與兩種失敗路徑都送入標記字串
	var errTexts []string
	var mu sync.Mutex
	collect := func(_ string, err error) { mu.Lock(); errTexts = append(errTexts, err.Error()); mu.Unlock() }

	e := newEnv(t)
	e.cfg.OnFail = collect
	w, _ := Open(e.cfg)
	_ = w.Append(format.KindBytes, 0, []byte(marker))
	_, _ = w.Close()

	e2 := newEnv(t)
	e2.cfg.SegmentBytes = 32
	ff := &failFile{after: 1}
	e2.cfg.WrapFile = func(f File) File { ff.File = f; return ff }
	e2.cfg.OnFail = collect
	w2, _ := Open(e2.cfg)
	for i := 0; i < 20; i++ {
		_ = w2.Append(format.KindBytes, 0, []byte(marker))
		time.Sleep(time.Millisecond)
	}
	_, _ = w2.Close()

	e3 := newEnv(t)
	e3.cfg.Root = "/proc/definitely/not/writable"
	_, oerr := Open(e3.cfg)
	if oerr != nil {
		errTexts = append(errTexts, oerr.Error())
	}

	out := buf.String() + strings.Join(errTexts, "\n")
	if strings.Contains(out, marker) || strings.Contains(out, marker[:12]) {
		t.Fatalf("plaintext marker leaked into log or error output (len=%d)", len(out))
	}
}

// Close 時寫入端卡住：Close 在停擺上限內返回並回傳失敗，原因為停擺，且不等 goroutine。
func TestCloseReturnsWhenWriterStuck(t *testing.T) {
	e := newEnv(t)
	e.cfg.StallTimeout = 300 * time.Millisecond
	sf := &stuckFile{block: make(chan struct{}), stuckAt: 1} // 標頭之後的第一次寫入即停住
	e.cfg.WrapFile = func(f File) File { sf.File = f; return sf }
	var mu sync.Mutex
	var causes []string
	e.cfg.OnFail = func(c string, _ error) { mu.Lock(); causes = append(causes, c); mu.Unlock() }
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(format.KindBytes, 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() { _, err := w.Close(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Close on stuck writer must return the failure")
		}
	case <-time.After(closeGrace + 5*time.Second):
		t.Fatal("Close blocked on stuck writer")
	}
	if el := time.Since(start); el > closeGrace+2*time.Second {
		t.Fatalf("Close took %v", el)
	}
	if w.FailCause() != model.CauseKeystrokeWriterStalled {
		t.Fatalf("FailCause=%q", w.FailCause())
	}
	mu.Lock()
	n := len(causes)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("OnFail calls=%d", n)
	}
	close(sf.block)
}

// 停擺後寫入端恢復執行：停擺標記與緩衝事件封成最後一段（非結束段），讀取器判不完整並可讀到標記。
func TestStallMarkerWrittenWhenWriterRegainsControl(t *testing.T) {
	e := newEnv(t)
	e.cfg.MaxQueueBytes = 4 << 10
	e.cfg.SegmentBytes = 512
	e.cfg.StallTimeout = 200 * time.Millisecond
	sf := &stuckFile{block: make(chan struct{}), stuckAt: 2}
	e.cfg.WrapFile = func(f File) File { sf.File = f; return sf }
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{1}, 300)
	var appendErr error
	for i := 0; i < 1000 && appendErr == nil; i++ {
		appendErr = w.Append(format.KindBytes, 0, chunk)
	}
	if !errors.Is(appendErr, ErrStalled) {
		t.Fatalf("append err=%v", appendErr)
	}
	close(sf.block)
	select {
	case <-w.done:
	case <-time.After(3 * time.Second):
		t.Fatal("writer goroutine did not finish after unblock")
	}
	res := e.read(t)
	if res.Status != reader.StatusTruncated {
		t.Fatalf("status=%s", res.Status)
	}
	found := false
	for _, ev := range res.Events {
		if ev.Kind == format.KindMarker && string(ev.Payload) == keystroke.MarkerWriterStalled && ev.Flags&format.FlagPlatform != 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("stall marker not found in %d events", len(res.Events))
	}
}

func TestMarkerCodesAreUniqueAndLowerSnake(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range keystroke.MarkerCodes() {
		if c == "" || seen[c] || strings.ToLower(c) != c || strings.ContainsAny(c, " -") {
			t.Fatalf("bad marker code %q", c)
		}
		seen[c] = true
	}
	if len(seen) != 8 {
		t.Fatalf("expected 8 codes, got %d", len(seen))
	}
}

// 標記事件往返：平台旗標、原樣碼字串。
func TestMarkerEventRoundTrip(t *testing.T) {
	e := newEnv(t)
	w, err := Open(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Append(format.KindBytes, 0, []byte("ls\r"))
	_ = w.Append(format.KindMarker, format.FlagPlatform, []byte(keystroke.MarkerEndIdleTimeout))
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	res := e.read(t)
	if res.Status != reader.StatusComplete || len(res.Events) != 2 {
		t.Fatalf("status=%s events=%d", res.Status, len(res.Events))
	}
	m := res.Events[1]
	if m.Kind != format.KindMarker || m.Flags != format.FlagPlatform || string(m.Payload) != keystroke.MarkerEndIdleTimeout {
		t.Fatalf("marker event kind=%x flags=%x", m.Kind, m.Flags)
	}
}

// 單筆超大輸入（一次貼上）切成多筆連續事件，讀回 complete 且位元組逐一相同。
func TestHugeSingleEventIsSplitAndReadsComplete(t *testing.T) {
	for _, size := range []int{5 << 20, 8 << 20} {
		for _, kind := range []byte{format.KindBytes, format.KindKeysymRaw} {
			e := newEnv(t)
			w, err := Open(e.cfg)
			if err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, size)
			if _, err := rand.Read(payload); err != nil {
				t.Fatal(err)
			}
			if err := w.Append(kind, format.FlagBlocked, payload); err != nil {
				t.Fatalf("append: %v", err)
			}
			if _, err := w.Close(); err != nil {
				t.Fatal(err)
			}
			rr := reader.Read(e.root, reader.Record{UUID: testUUID, SessionID: 7, Protocol: "ssh",
				FilePath: keystroke.RelPath(testUUID, e.cfg.Start)}, e.key, reader.Options{Limit: 1 << 30})
			if rr.Status != reader.StatusComplete {
				t.Fatalf("size=%d kind=%d status=%s", size, kind, rr.Status)
			}
			wantEvents := (size + MaxEventPayload - 1) / MaxEventPayload
			if len(rr.Events) != wantEvents {
				t.Fatalf("size=%d events=%d want %d", size, len(rr.Events), wantEvents)
			}
			var got []byte
			for _, ev := range rr.Events {
				if ev.Kind != kind || ev.Flags != format.FlagBlocked || ev.DeltaMs != rr.Events[0].DeltaMs {
					t.Fatalf("chunk attrs differ")
				}
				if len(ev.Payload) > MaxEventPayload {
					t.Fatalf("chunk too large: %d", len(ev.Payload))
				}
				got = append(got, ev.Payload...)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("size=%d payload mismatch", size)
			}
		}
	}
}
