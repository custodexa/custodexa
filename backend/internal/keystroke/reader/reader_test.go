package reader_test

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/keystroke"
	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/keystroke/reader"
	"github.com/custodexa/backend/internal/keystroke/writer"
	"github.com/custodexa/backend/internal/material"
)

const uuid = "11111111-2222-4333-8444-555555555555"

type fixture struct {
	root  string
	key   []byte
	rec   reader.Record
	path  string
	hdrN  int
	raw   []byte
	segs  [][]byte // 各段框架（含長度欄）
	count int
}

func build(t *testing.T) *fixture {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	root := filepath.Join(t.TempDir(), "keystrokes")
	start := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	w, err := writer.Open(writer.Config{
		Root: root, RecordUUID: uuid, SessionID: 9, Protocol: "ssh", Start: start,
		Key: material.Adopt(append([]byte(nil), key...)), SegmentBytes: 48,
	})
	if err != nil {
		t.Fatal(err)
	}
	const n = 12
	for i := 0; i < n; i++ {
		if err := w.Append(format.KindBytes, 0, []byte(fmt.Sprintf("event-number-%02d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rel := keystroke.RelPath(uuid, start)
	path := filepath.Join(root, rel)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, hn, err := format.DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{root: root, key: key, path: path, hdrN: hn, raw: raw, count: n,
		rec: reader.Record{UUID: uuid, SessionID: 9, Protocol: "ssh", FilePath: rel}}
	off := hn
	for off < len(raw) {
		l := int(binary.BigEndian.Uint32(raw[off:off+4]) &^ (1 << 31))
		f.segs = append(f.segs, raw[off:off+4+l])
		off += 4 + l
	}
	if len(f.segs) < 4 {
		t.Fatalf("need several segments, got %d", len(f.segs))
	}
	return f
}

func (f *fixture) rewrite(t *testing.T, b []byte) {
	t.Helper()
	if err := os.WriteFile(f.path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) read() reader.Result {
	return reader.Read(f.root, f.rec, f.key, reader.Options{})
}

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestComplete(t *testing.T) {
	f := build(t)
	r := f.read()
	if r.Status != reader.StatusComplete || r.TotalEvents != f.count {
		t.Fatalf("status=%s total=%d", r.Status, r.TotalEvents)
	}
}

func TestFromEventAndLimit(t *testing.T) {
	f := build(t)
	r := reader.Read(f.root, f.rec, f.key, reader.Options{FromEvent: 3, Limit: 4})
	if len(r.Events) != 4 || r.TotalEvents != f.count || string(r.Events[0].Payload) != "event-number-03" {
		t.Fatalf("window events=%d total=%d", len(r.Events), r.TotalEvents)
	}
}

func TestTruncatedMidSegmentKeepsEarlierSegments(t *testing.T) {
	f := build(t)
	cut := f.hdrN + len(f.segs[0]) + len(f.segs[1]) + len(f.segs[2])/2
	f.rewrite(t, f.raw[:cut])
	r := f.read()
	if r.Status != reader.StatusTruncated || r.SegmentsRead != 2 || r.TotalEvents == 0 {
		t.Fatalf("status=%s segs=%d total=%d", r.Status, r.SegmentsRead, r.TotalEvents)
	}
}

func TestTruncatedAtSegmentBoundary(t *testing.T) {
	f := build(t)
	cut := f.hdrN + len(f.segs[0]) + len(f.segs[1])
	f.rewrite(t, f.raw[:cut])
	r := f.read()
	if r.Status != reader.StatusTruncated || r.SegmentsRead != 2 {
		t.Fatalf("status=%s segs=%d", r.Status, r.SegmentsRead)
	}
}

func TestTruncatedBeforeFinalSegment(t *testing.T) {
	f := build(t)
	last := len(f.segs) - 1
	f.rewrite(t, f.raw[:len(f.raw)-len(f.segs[last])])
	r := f.read()
	if r.Status != reader.StatusTruncated || r.SegmentsRead != last {
		t.Fatalf("status=%s segs=%d", r.Status, r.SegmentsRead)
	}
}

func TestZeroSegmentFile(t *testing.T) {
	f := build(t)
	f.rewrite(t, f.raw[:f.hdrN])
	r := f.read()
	if r.Status != reader.StatusTruncated || r.TotalEvents != 0 || r.SegmentsRead != 0 {
		t.Fatalf("status=%s", r.Status)
	}
}

func TestPartialHeaderIsTruncated(t *testing.T) {
	f := build(t)
	f.rewrite(t, f.raw[:f.hdrN-3])
	if r := f.read(); r.Status != reader.StatusTruncated {
		t.Fatalf("status=%s", r.Status)
	}
}

func TestModifiedByteIsTampered(t *testing.T) {
	f := build(t)
	b := append([]byte(nil), f.raw...)
	off := f.hdrN + len(f.segs[0]) + len(f.segs[1]) + 4 + 2 // 第 3 段密文內
	b[off] ^= 0x01
	f.rewrite(t, b)
	r := f.read()
	if r.Status != reader.StatusTampered || r.FailedSegment != 2 || r.SegmentsRead != 2 || r.TotalEvents == 0 {
		t.Fatalf("status=%s failed=%d segs=%d", r.Status, r.FailedSegment, r.SegmentsRead)
	}
}

func TestSwappedSegmentsAreTampered(t *testing.T) {
	f := build(t)
	b := join(f.raw[:f.hdrN], f.segs[0], f.segs[2], f.segs[1])
	for _, s := range f.segs[3:] {
		b = append(b, s...)
	}
	f.rewrite(t, b)
	r := f.read()
	if r.Status != reader.StatusTampered || r.FailedSegment != 1 {
		t.Fatalf("status=%s failed=%d", r.Status, r.FailedSegment)
	}
}

func TestDeletedMiddleSegmentIsTampered(t *testing.T) {
	f := build(t)
	b := join(f.raw[:f.hdrN], f.segs[0], f.segs[2])
	for _, s := range f.segs[3:] {
		b = append(b, s...)
	}
	f.rewrite(t, b)
	r := f.read()
	if r.Status != reader.StatusTampered || r.FailedSegment != 1 || r.SegmentsRead != 1 {
		t.Fatalf("status=%s failed=%d segs=%d", r.Status, r.FailedSegment, r.SegmentsRead)
	}
}

func TestTrailingDataAfterFinalIsTampered(t *testing.T) {
	f := build(t)
	f.rewrite(t, join(f.raw, f.segs[0]))
	if r := f.read(); r.Status != reader.StatusTampered {
		t.Fatalf("status=%s", r.Status)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	f := build(t)
	secret := filepath.Join(filepath.Dir(f.root), "outside.cxkr")
	_ = os.WriteFile(secret, f.raw, 0o600)
	for _, p := range []string{"../outside.cxkr", "2026-11-05/../../outside.cxkr", f.path, ""} {
		rec := f.rec
		rec.FilePath = p
		r := reader.Read(f.root, rec, f.key, reader.Options{})
		if r.Status != reader.StatusPathRejected {
			t.Fatalf("path %q: status=%s", p, r.Status)
		}
	}
}

func TestSymlinkRejected(t *testing.T) {
	f := build(t)
	outside := filepath.Join(t.TempDir(), "real.cxkr")
	_ = os.WriteFile(outside, f.raw, 0o600)
	link := filepath.Join(f.root, "2026-11-05", "link.cxkr")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	rec := f.rec
	rec.FilePath = filepath.Join("2026-11-05", "link.cxkr")
	if r := reader.Read(f.root, rec, f.key, reader.Options{}); r.Status != reader.StatusPathRejected {
		t.Fatalf("file symlink: status=%s", r.Status)
	}
	// 上層目錄為指向根目錄外的符號連結
	dirLink := filepath.Join(f.root, "linkdir")
	if err := os.Symlink(filepath.Dir(outside), dirLink); err != nil {
		t.Fatal(err)
	}
	rec.FilePath = filepath.Join("linkdir", "real.cxkr")
	if r := reader.Read(f.root, rec, f.key, reader.Options{}); r.Status != reader.StatusPathRejected {
		t.Fatalf("dir symlink: status=%s", r.Status)
	}
}

func TestHeaderMismatch(t *testing.T) {
	f := build(t)
	rec := f.rec
	rec.UUID = "11111111-2222-4333-8444-555555555556"
	if r := reader.Read(f.root, rec, f.key, reader.Options{}); r.Status != reader.StatusHeaderMismatch || r.TotalEvents != 0 {
		t.Fatalf("uuid: status=%s", r.Status)
	}
	rec = f.rec
	rec.SessionID = 10
	if r := reader.Read(f.root, rec, f.key, reader.Options{}); r.Status != reader.StatusHeaderMismatch {
		t.Fatalf("session: status=%s", r.Status)
	}
	rec = f.rec
	rec.Protocol = "k8s"
	if r := reader.Read(f.root, rec, f.key, reader.Options{}); r.Status != reader.StatusHeaderMismatch {
		t.Fatalf("protocol: status=%s", r.Status)
	}
}

func TestFileMissing(t *testing.T) {
	f := build(t)
	_ = os.Remove(f.path)
	if r := f.read(); r.Status != reader.StatusFileMissing {
		t.Fatalf("status=%s", r.Status)
	}
}

func TestWrongKeyIsTampered(t *testing.T) {
	f := build(t)
	bad := make([]byte, 32)
	r := reader.Read(f.root, f.rec, bad, reader.Options{})
	if r.Status != reader.StatusTampered || r.FailedSegment != 0 {
		t.Fatalf("status=%s", r.Status)
	}
}

func TestCompleteRecordMissingFinalSegmentIsTampered(t *testing.T) {
	f := build(t)
	f.rec.ExpectComplete = true
	f.rec.SegmentCount = int64(len(f.segs))
	last := len(f.segs) - 1
	f.rewrite(t, f.raw[:len(f.raw)-len(f.segs[last])])
	if r := f.read(); r.Status != reader.StatusTampered || r.FailedSegment != last {
		t.Fatalf("status=%s failed=%d", r.Status, r.FailedSegment)
	}
}

func TestCompleteRecordTruncatedMidFileIsTampered(t *testing.T) {
	f := build(t)
	f.rec.ExpectComplete = true
	f.rec.SegmentCount = int64(len(f.segs))
	f.rewrite(t, f.raw[:f.hdrN+len(f.segs[0])+len(f.segs[1])/2])
	if r := f.read(); r.Status != reader.StatusTampered {
		t.Fatalf("status=%s", r.Status)
	}
}

func TestCompleteRecordIntactStaysComplete(t *testing.T) {
	f := build(t)
	f.rec.ExpectComplete = true
	f.rec.SegmentCount = int64(len(f.segs))
	if r := f.read(); r.Status != reader.StatusComplete {
		t.Fatalf("status=%s", r.Status)
	}
}

func TestRecordingStatusTruncatedStaysTruncated(t *testing.T) {
	f := build(t)
	f.rec.ExpectComplete = false
	f.rewrite(t, f.raw[:len(f.raw)-len(f.segs[len(f.segs)-1])])
	if r := f.read(); r.Status != reader.StatusTruncated {
		t.Fatalf("status=%s", r.Status)
	}
}

func TestOversizedLengthFieldRejectedBeforeAllocation(t *testing.T) {
	f := build(t)
	var lf [4]byte
	binary.BigEndian.PutUint32(lf[:], 200<<20)
	f.rewrite(t, join(f.raw[:f.hdrN], lf[:], make([]byte, 64)))
	if r := f.read(); r.Status != reader.StatusTampered || r.FailedSegment != 0 {
		t.Fatalf("status=%s failed=%d", r.Status, r.FailedSegment)
	}
}
