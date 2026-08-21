package sealjournal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

// probeFile 包住真實檔案，記錄每一次 I/O 的種類、偏移與發起 goroutine，
// 並可注入寫入失敗與同步延遲。
// 斷言一律打在真實位元／真實檔案大小上，probe 只負責觀察與注入。
type probeFile struct {
	inner fileIO

	mu        sync.Mutex
	ops       []probeOp
	writeGIDs map[uint64]bool
	failWrite bool
	syncDelay time.Duration
}

type probeOp struct {
	Kind string // "write" / "sync" / "read"
	Off  int64
	GID  uint64
}

func newProbe(inner fileIO) *probeFile {
	return &probeFile{inner: inner, writeGIDs: map[uint64]bool{}}
}

func (p *probeFile) WriteAt(b []byte, off int64) (int, error) {
	p.mu.Lock()
	fail := p.failWrite
	p.ops = append(p.ops, probeOp{Kind: "write", Off: off, GID: goID()})
	p.writeGIDs[goID()] = true
	p.mu.Unlock()
	if fail {
		return 0, fs.ErrPermission
	}
	return p.inner.WriteAt(b, off)
}

func (p *probeFile) ReadAt(b []byte, off int64) (int, error) {
	p.mu.Lock()
	p.ops = append(p.ops, probeOp{Kind: "read", Off: off, GID: goID()})
	p.mu.Unlock()
	return p.inner.ReadAt(b, off)
}

func (p *probeFile) Datasync() error {
	p.mu.Lock()
	delay := p.syncDelay
	fail := p.failWrite
	p.ops = append(p.ops, probeOp{Kind: "sync", GID: goID()})
	p.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if fail {
		return fs.ErrPermission
	}
	return p.inner.Datasync()
}

func (p *probeFile) Stat() (fs.FileInfo, error) { return p.inner.Stat() }
func (p *probeFile) Close() error               { return p.inner.Close() }

func (p *probeFile) setFailWrite(v bool) {
	p.mu.Lock()
	p.failWrite = v
	p.mu.Unlock()
}

func (p *probeFile) setSyncDelay(d time.Duration) {
	p.mu.Lock()
	p.syncDelay = d
	p.mu.Unlock()
}

func (p *probeFile) snapshot() []probeOp {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]probeOp, len(p.ops))
	copy(out, p.ops)
	return out
}

func (p *probeFile) reset() {
	p.mu.Lock()
	p.ops = nil
	p.writeGIDs = map[uint64]bool{}
	p.mu.Unlock()
}

func (p *probeFile) countKind(kind string) int {
	n := 0
	for _, op := range p.snapshot() {
		if op.Kind == kind {
			n++
		}
	}
	return n
}

func (p *probeFile) writerGoroutines() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]uint64, 0, len(p.writeGIDs))
	for g := range p.writeGIDs {
		out = append(out, g)
	}
	return out
}

// goID 取當前 goroutine 編號，用於「單一 writer」的機械斷言。
func goID() uint64 {
	buf := make([]byte, 64)
	n := runtime.Stack(buf, false)
	field := bytes.Fields(buf[:n])
	if len(field) < 2 {
		return 0
	}
	id, _ := strconv.ParseUint(string(field[1]), 10, 64)
	return id
}

// ---- 共用測試工具 ----

const testDigest = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

func testOptions(extra ...Option) []Option {
	base := []Option{
		WithCapacity(64, 16),
		WithMinAdmissionInterval(0),
		WithRejectedFlushInterval(time.Hour),
		WithWriteTimeout(5 * time.Second),
	}
	return append(base, extra...)
}

func openTestJournal(t *testing.T, dir string, extra ...Option) *Journal {
	t.Helper()
	j, err := Open(dir, testOptions(extra...)...)
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}

func openProbedJournal(t *testing.T, dir string, extra ...Option) (*Journal, *probeFile) {
	t.Helper()
	var probe *probeFile
	opts := testOptions(extra...)
	opts = append(opts, withWrapFile(func(f fileIO) fileIO {
		probe = newProbe(f)
		return probe
	}))
	j, err := Open(dir, opts...)
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })
	// 開檔期的預配置寫入發生在 Open 的呼叫端（owner 尚未存在），
	// 「單一 writer」的約束對象是開檔後的運行期，故在此重設觀察基準。
	probe.reset()
	return j, probe
}

func journalPath(dir string) string { return filepath.Join(dir, DefaultFileName) }

func fileSizeOf(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 失敗: %v", err)
	}
	return info.Size()
}

func fileHash(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀檔失敗: %v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func mustStatus(t *testing.T, j *Journal) Status {
	t.Helper()
	st, err := j.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 失敗: %v", err)
	}
	return st
}

// writeAttempt 走完整的正常流程：Admit → WriteReceived → （模擬驗證）→ WriteOutcome。
func writeAttempt(t *testing.T, j *Journal, gen uint64, outcome string) uint64 {
	t.Helper()
	ctx := context.Background()
	ticket, err := j.Admit(ctx)
	if err != nil {
		t.Fatalf("Admit 失敗: %v", err)
	}
	seq, err := j.WriteReceived(ctx, gen, testDigest)
	ticket.Release(err == nil)
	if err != nil {
		t.Fatalf("WriteReceived 失敗: %v", err)
	}
	if outcome != "" {
		if err := j.WriteOutcome(ctx, gen, seq, outcome); err != nil {
			t.Fatalf("WriteOutcome 失敗: %v", err)
		}
	}
	return seq
}
