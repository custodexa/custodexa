package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"sync/atomic"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/keystroke/reader"
	"github.com/custodexa/backend/internal/keystroke/writer"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
)

// ksFakeCodec 以簡單位元運算代替信封加密；驗證 ref 為登記的 FEK 欄位。
type ksFakeCodec struct {
	failEncrypt bool
	refs        []crypto.CipherRef
}

func (c *ksFakeCodec) EncryptBytesFor(_ context.Context, ref crypto.CipherRef, p []byte) (string, error) {
	c.refs = append(c.refs, ref)
	if c.failEncrypt {
		return "", errors.New("material sealed")
	}
	b := make([]byte, len(p))
	for i := range p {
		b[i] = p[i] ^ 0x5a
	}
	return "enc:" + hex.EncodeToString(b), nil
}

func (c *ksFakeCodec) DecryptBytesFor(_ context.Context, _ crypto.CipherRef, s string) (*material.Secret, error) {
	raw, err := hex.DecodeString(s[len("enc:"):])
	if err != nil {
		return nil, err
	}
	for i := range raw {
		raw[i] ^= 0x5a
	}
	return material.Adopt(raw), nil
}

type ksReporter struct {
	mu       sync.Mutex
	reports  []string
	resolves int
}

func (r *ksReporter) Report(mech, cause string, _ map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, mech+"/"+cause)
}
func (r *ksReporter) ResolveFailure(mech string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mech == model.MechanismKeystrokeRecord {
		r.resolves++
	}
}
func (r *ksReporter) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.reports...)
}

type ksRig struct {
	db    *gorm.DB
	svc   *KeystrokeService
	codec *ksFakeCodec
	rep   *ksReporter
	root  string
}

func newKsRig(t *testing.T) *ksRig {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.KeystrokeRecord{}); err != nil {
		t.Fatal(err)
	}
	codec := &ksFakeCodec{}
	rep := &ksReporter{}
	root := filepath.Join(t.TempDir(), "keystrokes")
	svc := NewKeystrokeService(db, codec, root, rep)
	svc.heartbeat = 20 * time.Millisecond
	return &ksRig{db: db, svc: svc, codec: codec, rep: rep, root: root}
}

func (r *ksRig) row(t *testing.T, sessionID uint) model.KeystrokeRecord {
	t.Helper()
	var row model.KeystrokeRecord
	if err := r.db.Where("session_id = ?", sessionID).First(&row).Error; err != nil {
		t.Fatalf("row for session %d: %v", sessionID, err)
	}
	return row
}

func TestKeystrokeStartAppendCloseRoundTrip(t *testing.T) {
	r := newKsRig(t)
	rec, err := r.svc.Start(&model.Session{ID: 11}, "ssh")
	if err != nil || rec == nil {
		t.Fatalf("start: %v", err)
	}
	rec.AppendInput([]byte("ls\r"))
	rec.AppendBlocked([]byte("rm -rf /\r"))
	rec.AppendPlatform([]byte{0x03})
	rec.Close()

	row := r.row(t, 11)
	if row.Status != model.KeystrokeStatusComplete || row.EventCount != 3 || row.SegmentCount < 1 || row.EndedAt == nil {
		t.Fatalf("row status=%s events=%d segs=%d", row.Status, row.EventCount, row.SegmentCount)
	}
	if row.FileKeyEnc == "" || row.WriterInstance == "" {
		t.Fatal("file key / writer instance missing")
	}
	if len(r.codec.refs) != 1 || r.codec.refs[0] != keyvault.RefKeystrokeFileKey {
		t.Fatalf("FEK must be sealed under RefKeystrokeFileKey, got %v", r.codec.refs)
	}
	fek, err := r.codec.DecryptBytesFor(context.Background(), keyvault.RefKeystrokeFileKey, row.FileKeyEnc)
	if err != nil {
		t.Fatal(err)
	}
	defer fek.Destroy()
	var res reader.Result
	_ = fek.Borrow(func(k []byte) error {
		res = reader.Read(r.root, reader.Record{UUID: row.RecordUUID, SessionID: 11, Protocol: "ssh",
			FilePath: row.FilePath}, k, reader.Options{})
		return nil
	})
	if res.Status != reader.StatusComplete || res.TotalEvents != 3 {
		t.Fatalf("read status=%s events=%d", res.Status, res.TotalEvents)
	}
	if res.Events[0].Flags != 0 || res.Events[1].Flags != format.FlagBlocked || res.Events[2].Flags != format.FlagPlatform {
		t.Fatal("flag sequence mismatch")
	}
	if !bytes.Equal(res.Events[2].Payload, []byte{0x03}) {
		t.Fatal("platform byte mismatch")
	}
	if r.rep.resolves != 1 || len(r.rep.snapshot()) != 0 {
		t.Fatalf("resolves=%d reports=%v", r.rep.resolves, r.rep.snapshot())
	}
}

func TestKeystrokeStartKeySealFailure(t *testing.T) {
	r := newKsRig(t)
	r.codec.failEncrypt = true
	rec, err := r.svc.Start(&model.Session{ID: 21}, "ssh")
	if rec != nil || err == nil {
		t.Fatal("start must fail without a recorder")
	}
	row := r.row(t, 21)
	if row.Status != model.KeystrokeStatusFailed || row.FailureCause != model.CauseKeystrokeKeySealFailed ||
		row.FileKeyEnc != "" || row.FilePath != "" {
		t.Fatalf("row=%+v", row)
	}
	if got := r.rep.snapshot(); len(got) != 1 || got[0] != model.MechanismKeystrokeRecord+"/"+model.CauseKeystrokeKeySealFailed {
		t.Fatalf("reports=%v", got)
	}
	if _, statErr := os.Stat(r.root); statErr == nil {
		ents, _ := os.ReadDir(r.root)
		if len(ents) != 0 {
			t.Fatal("no file may be created when sealing fails")
		}
	}
}

func TestKeystrokeStartOpenFailureClearsKey(t *testing.T) {
	r := newKsRig(t)
	blocker := filepath.Join(t.TempDir(), "afile")
	_ = os.WriteFile(blocker, nil, 0o600)
	r.svc.root = filepath.Join(blocker, "keystrokes")
	rec, err := r.svc.Start(&model.Session{ID: 31}, "ssh")
	if rec != nil || err == nil {
		t.Fatal("start must fail")
	}
	row := r.row(t, 31)
	if row.Status != model.KeystrokeStatusFailed || row.FailureCause != model.CauseKeystrokeDirUnwritable || row.FileKeyEnc != "" {
		t.Fatalf("row=%+v", row)
	}
	if got := r.rep.snapshot(); len(got) != 1 {
		t.Fatalf("reports=%v", got)
	}
}

func TestKeystrokeStartInsertFailureHasNoRowButAlerts(t *testing.T) {
	r := newKsRig(t)
	if err := r.db.Migrator().DropTable(&model.KeystrokeRecord{}); err != nil {
		t.Fatal(err)
	}
	rec, err := r.svc.Start(&model.Session{ID: 41}, "ssh")
	if rec != nil || err == nil {
		t.Fatal("start must fail")
	}
	if got := r.rep.snapshot(); len(got) != 1 {
		t.Fatalf("reports=%v", got)
	}
	ents, _ := os.ReadDir(r.root)
	if len(ents) != 0 {
		t.Fatal("no file may exist without a record row")
	}
}

type ksFailingFile struct {
	writer.File
	n int
}

func (f *ksFailingFile) Write(p []byte) (int, error) {
	f.n++
	if f.n > 1 { // 標頭通過，其後全部失敗
		return 0, errors.New("injected")
	}
	return f.File.Write(p)
}

func TestKeystrokeMidSessionFailureMarksRowAndAlertsOnce(t *testing.T) {
	r := newKsRig(t)
	r.svc.writerHook = func(c *writer.Config) {
		c.SegmentBytes = 16
		c.WrapFile = func(f writer.File) writer.File { return &ksFailingFile{File: f} }
	}
	rec, err := r.svc.Start(&model.Session{ID: 51}, "ssh")
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		rec.AppendInput(bytes.Repeat([]byte{'a'}, 24))
		time.Sleep(2 * time.Millisecond)
	}
	rec.Close()
	row := r.row(t, 51)
	if row.Status != model.KeystrokeStatusFailed || row.FailureCause != model.CauseKeystrokeWriteFailed {
		t.Fatalf("row status=%s cause=%s", row.Status, row.FailureCause)
	}
	if row.FileKeyEnc == "" {
		t.Fatal("failed mid-session record must keep the key so written segments stay readable")
	}
	time.Sleep(50 * time.Millisecond) // 等 persistFailure 的 goroutine
	if got := r.rep.snapshot(); len(got) != 1 {
		t.Fatalf("must alert exactly once, reports=%v", got)
	}
}

func TestKeystrokeNotCoveredRowIsIdempotent(t *testing.T) {
	r := newKsRig(t)
	if err := r.svc.RecordNotCovered(61, "ssh", model.CoverageReasonK8sLogsReadonly); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.RecordNotCovered(61, "ssh", model.CoverageReasonDBConsole); err != nil {
		t.Fatal(err)
	}
	var n int64
	r.db.Model(&model.KeystrokeRecord{}).Where("session_id = ?", 61).Count(&n)
	row := r.row(t, 61)
	if n != 1 || row.Status != model.KeystrokeStatusNotCovered || row.CoverageReason != model.CoverageReasonK8sLogsReadonly ||
		row.FilePath != "" || row.FileKeyEnc != "" {
		t.Fatalf("n=%d row=%+v", n, row)
	}
}

func TestKeystrokeHeartbeatUpdatesLastWriteAt(t *testing.T) {
	r := newKsRig(t)
	rec, err := r.svc.Start(&model.Session{ID: 71}, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if row := r.row(t, 71); row.LastWriteAt != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("heartbeat never wrote last_write_at")
}

func TestKeystrokeReconcileStale(t *testing.T) {
	r := newKsRig(t)
	now := time.Now()
	old := now.Add(-time.Hour)
	recent := now.Add(-time.Minute)
	mk := func(sid uint, started time.Time, last *time.Time) {
		if err := r.db.Create(&model.KeystrokeRecord{
			RecordUUID: "u-" + string(rune('a'+sid)), SessionID: sid, Protocol: "ssh",
			Status: model.KeystrokeStatusRecording, StartedAt: started, LastWriteAt: last,
		}).Error; err != nil {
			t.Fatal(err)
		}
	}
	mk(1, old, nil)       // 無 last_write_at 的舊列：標記
	mk(2, old, &old)      // 心跳過期：標記
	mk(3, old, &recent)   // 另一實例有心跳：不標記
	mk(4, recent, nil)    // 剛開始、尚無心跳：不標記
	n, err := r.svc.ReconcileStale(now)
	if err != nil || n != 2 {
		t.Fatalf("marked=%d err=%v", n, err)
	}
	want := map[uint]string{1: model.KeystrokeStatusIncomplete, 2: model.KeystrokeStatusIncomplete,
		3: model.KeystrokeStatusRecording, 4: model.KeystrokeStatusRecording}
	for sid, st := range want {
		if got := r.row(t, sid).Status; got != st {
			t.Fatalf("session %d status=%s want %s", sid, got, st)
		}
	}
}

func TestKeystrokeReconcileSkipsLocallyActive(t *testing.T) {
	r := newKsRig(t)
	rec, err := r.svc.Start(&model.Session{ID: 81}, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	// 以遠未來的時間對帳：活躍集合內的紀錄不可被標記
	n, err := r.svc.ReconcileStale(time.Now().Add(24 * time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("marked=%d err=%v", n, err)
	}
}

type ksStuckOnWrite struct {
	writer.File
	calls   atomic.Int32
	release chan struct{}
}

func (f *ksStuckOnWrite) Write(p []byte) (int, error) {
	if f.calls.Add(1) > 1 { // 標頭之後的第一次寫入即停住
		<-f.release
	}
	return f.File.Write(p)
}

// 收尾時寫入端卡住：Close 在上限內返回，紀錄列標失敗與停擺原因。
func TestKeystrokeCloseWithStuckWriterReturnsAndMarksFailed(t *testing.T) {
	r := newKsRig(t)
	release := make(chan struct{})
	defer close(release)
	r.svc.SetWriterConfigHook(func(c *writer.Config) {
		c.StallTimeout = 200 * time.Millisecond
		c.WrapFile = func(f writer.File) writer.File { return &ksStuckOnWrite{File: f, release: release} }
	})
	rec, err := r.svc.Start(&model.Session{ID: 61}, "ssh")
	if err != nil || rec == nil {
		t.Fatalf("start: %v", err)
	}
	rec.AppendInput([]byte("ls\r"))
	done := make(chan struct{})
	go func() { rec.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocked on stuck writer")
	}
	row := r.row(t, 61)
	if row.Status != model.KeystrokeStatusFailed || row.FailureCause != model.CauseKeystrokeWriterStalled {
		t.Fatalf("status=%s cause=%s", row.Status, row.FailureCause)
	}
}
