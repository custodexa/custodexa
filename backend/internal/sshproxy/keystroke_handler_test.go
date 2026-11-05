package sshproxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/keystroke"
	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/keystroke/reader"
	"github.com/custodexa/backend/internal/keystroke/writer"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
)

type ksTestCodec struct{ fail bool }

func (c *ksTestCodec) EncryptBytesFor(_ context.Context, _ crypto.CipherRef, p []byte) (string, error) {
	if c.fail {
		return "", errors.New("material sealed")
	}
	b := make([]byte, len(p))
	for i := range p {
		b[i] = p[i] ^ 0x33
	}
	return "e:" + hex.EncodeToString(b), nil
}

func (c *ksTestCodec) DecryptBytesFor(_ context.Context, _ crypto.CipherRef, s string) (*material.Secret, error) {
	raw, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, err
	}
	for i := range raw {
		raw[i] ^= 0x33
	}
	return material.Adopt(raw), nil
}

type ksTestReporter struct {
	mu      sync.Mutex
	reports []string
}

func (r *ksTestReporter) Report(mech, cause string, _ map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, mech+"/"+cause)
}
func (r *ksTestReporter) ResolveFailure(string) {}
func (r *ksTestReporter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reports)
}

type ksHandlerRig struct {
	h     *Handler
	db    *gorm.DB
	codec *ksTestCodec
	rep   *ksTestReporter
	root  string
}

func newKsHandlerRig(t *testing.T, hook func(*writer.Config)) *ksHandlerRig {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.KeystrokeRecord{}))
	codec := &ksTestCodec{}
	rep := &ksTestReporter{}
	root := filepath.Join(t.TempDir(), "keystrokes")
	svc := session.NewKeystrokeService(db, codec, root, rep)
	if hook != nil {
		svc.SetWriterConfigHook(hook)
	}
	return &ksHandlerRig{h: &Handler{KeystrokeService: svc}, db: db, codec: codec, rep: rep, root: root}
}

func (r *ksHandlerRig) row(t *testing.T, sid uint) model.KeystrokeRecord {
	t.Helper()
	var row model.KeystrokeRecord
	require.NoError(t, r.db.Where("session_id = ?", sid).First(&row).Error)
	return row
}

func (r *ksHandlerRig) read(t *testing.T, row model.KeystrokeRecord) reader.Result {
	t.Helper()
	fek, err := r.codec.DecryptBytesFor(context.Background(), crypto.CipherRef{}, row.FileKeyEnc)
	require.NoError(t, err)
	defer fek.Destroy()
	var res reader.Result
	require.NoError(t, fek.Borrow(func(k []byte) error {
		res = reader.Read(r.root, reader.Record{UUID: row.RecordUUID, SessionID: uint64(row.SessionID),
			Protocol: row.Protocol, FilePath: row.FilePath}, k, reader.Options{Limit: 1 << 20})
		return nil
	}))
	return res
}

// 與 runTerminal 相同的接線順序：attach → Run → 結束後 Close。
func runKsBridge(t *testing.T, rig *ksHandlerRig, sess *model.Session, kind keystroke.SessionKind,
	conn TerminalConn, inputs ...string) *session.KeystrokeRecorder {
	t.Helper()
	server, client := NewInProcessTransportPair()
	b := newBridge(server, conn, sess, nil, "", 1, 2)
	rec := rig.h.attachKeystrokeTo(b, sess, string(sess.Protocol), kind)
	done := make(chan struct{})
	go func() { b.Run(); close(done) }()
	for _, in := range inputs {
		raw, err := EncodeMessage(MsgData, in)
		require.NoError(t, err)
		require.NoError(t, client.WriteMessage(1, raw))
	}
	time.Sleep(50 * time.Millisecond)
	b.stop()
	<-done
	return rec
}

func TestKeystrokeHandlerLifecycleRecordsAndCloses(t *testing.T) {
	rig := newKsHandlerRig(t, nil)
	sess := &model.Session{ID: 5, Protocol: model.ProtocolSSH}
	rec := runKsBridge(t, rig, sess, keystroke.KindSSHTerminal, newBlockingConn(nil), "echo hi\r")
	require.NotNil(t, rec)
	rec.Close()
	row := rig.row(t, 5)
	require.Equal(t, model.KeystrokeStatusComplete, row.Status)
	res := rig.read(t, row)
	require.Equal(t, reader.StatusComplete, res.Status)
	require.Equal(t, 1, res.TotalEvents)
	require.Equal(t, "echo hi\r", string(res.Events[0].Payload))
}

// 送出即斷線：輸入送出後立刻結束，結尾段仍封出，紀錄含完整行。
func TestKeystrokeHandlerSendThenDisconnectKeepsLine(t *testing.T) {
	rig := newKsHandlerRig(t, nil)
	sess := &model.Session{ID: 6, Protocol: model.ProtocolSSH}
	server, client := NewInProcessTransportPair()
	b := newBridge(server, newBlockingConn(nil), sess, nil, "", 1, 2)
	rec := rig.h.attachKeystrokeTo(b, sess, "ssh", keystroke.KindSSHTerminal)
	done := make(chan struct{})
	go func() { b.Run(); close(done) }()
	raw, _ := EncodeMessage(MsgData, "reboot\r")
	require.NoError(t, client.WriteMessage(1, raw))
	client.Close() // 緊接著斷線
	<-done
	rec.Close()
	res := rig.read(t, rig.row(t, 6))
	require.Equal(t, reader.StatusComplete, res.Status)
	require.Equal(t, 1, res.TotalEvents)
	require.Equal(t, "reboot\r", string(res.Events[0].Payload))
}

// 錄影啟動失敗不影響鍵盤紀錄。
func TestKeystrokeHandlerRecordingFailureDoesNotAffectKeystroke(t *testing.T) {
	rig := newKsHandlerRig(t, nil)
	blocker := filepath.Join(t.TempDir(), "afile")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	_, recErr := newRecordingTap(filepath.Join(blocker, "rec"), 1, 80, 24)
	require.Error(t, recErr, "recording must fail for this directory")
	sess := &model.Session{ID: 7, Protocol: model.ProtocolSSH}
	rec := runKsBridge(t, rig, sess, keystroke.KindSSHTerminal, newBlockingConn(nil), "ok\r")
	require.NotNil(t, rec)
	rec.Close()
	require.Equal(t, 1, rig.read(t, rig.row(t, 7)).TotalEvents)
}

// 鍵盤紀錄啟動失敗不影響錄影，轉發照常。
func TestKeystrokeHandlerKeystrokeFailureDoesNotAffectRecordingOrForwarding(t *testing.T) {
	rig := newKsHandlerRig(t, nil)
	rig.codec.fail = true
	rt, recErr := newRecordingTap(t.TempDir(), 1, 80, 24)
	require.NoError(t, recErr)
	defer func() { _ = rt.rec.Stop() }()
	conn := newBlockingConn(nil)
	sess := &model.Session{ID: 8, Protocol: model.ProtocolSSH}
	rec := runKsBridge(t, rig, sess, keystroke.KindSSHTerminal, conn, "still forwarded\r")
	require.Nil(t, rec, "no keystroke record when sealing fails")
	require.Contains(t, conn.written(), "still forwarded")
	require.Equal(t, 1, rig.rep.count())
}

// 啟動失敗、中途失敗、寫入端停擺：會話不中斷、標 failed＋原因、只通報一次。
func TestKeystrokeHandlerFailStartDirUnwritable(t *testing.T) {
	rig := newKsHandlerRig(t, nil)
	blocker := filepath.Join(t.TempDir(), "afile")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	rig.h.KeystrokeService.SetRoot(filepath.Join(blocker, "ks"))
	conn := newBlockingConn(nil)
	sess := &model.Session{ID: 9, Protocol: model.ProtocolSSH}
	rec := runKsBridge(t, rig, sess, keystroke.KindSSHTerminal, conn, "line\r")
	require.Nil(t, rec)
	require.Contains(t, conn.written(), "line")
	row := rig.row(t, 9)
	require.Equal(t, model.KeystrokeStatusFailed, row.Status)
	require.Equal(t, model.CauseKeystrokeDirUnwritable, row.FailureCause)
	require.Equal(t, 1, rig.rep.count())
}

type ksFailAfterHeader struct {
	writer.File
	n int
}

func (f *ksFailAfterHeader) Write(p []byte) (int, error) {
	f.n++
	if f.n > 1 {
		return 0, errors.New("injected")
	}
	return f.File.Write(p)
}

func TestKeystrokeHandlerFailMidSessionWriteError(t *testing.T) {
	rig := newKsHandlerRig(t, func(c *writer.Config) {
		c.SegmentBytes = 8
		c.WrapFile = func(f writer.File) writer.File { return &ksFailAfterHeader{File: f} }
	})
	conn := newBlockingConn(nil)
	sess := &model.Session{ID: 10, Protocol: model.ProtocolSSH}
	var inputs []string
	for i := 0; i < 20; i++ {
		inputs = append(inputs, "0123456789abcdef")
	}
	rec := runKsBridge(t, rig, sess, keystroke.KindSSHTerminal, conn, inputs...)
	require.NotNil(t, rec)
	rec.Close()
	require.Contains(t, conn.written(), "0123456789abcdef", "forwarding must continue")
	row := rig.row(t, 10)
	require.Equal(t, model.KeystrokeStatusFailed, row.Status)
	require.Equal(t, model.CauseKeystrokeWriteFailed, row.FailureCause)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, rig.rep.count(), "one alert per record")
}

type ksStuckFile struct {
	writer.File
	n       int
	release chan struct{}
}

func (f *ksStuckFile) Write(p []byte) (int, error) {
	f.n++
	if f.n > 1 {
		<-f.release
	}
	return f.File.Write(p)
}

func TestKeystrokeHandlerFailWriterStalled(t *testing.T) {
	release := make(chan struct{})
	rig := newKsHandlerRig(t, func(c *writer.Config) {
		c.SegmentBytes = 8
		c.MaxQueueBytes = 64
		c.StallTimeout = 200 * time.Millisecond
		c.WrapFile = func(f writer.File) writer.File { return &ksStuckFile{File: f, release: release} }
	})
	defer close(release)
	conn := newBlockingConn(nil)
	sess := &model.Session{ID: 11, Protocol: model.ProtocolSSH}
	server, client := NewInProcessTransportPair()
	b := newBridge(server, conn, sess, nil, "", 1, 2)
	rec := rig.h.attachKeystrokeTo(b, sess, "ssh", keystroke.KindSSHTerminal)
	require.NotNil(t, rec)
	done := make(chan struct{})
	go func() { b.Run(); close(done) }()
	start := time.Now()
	for i := 0; i < 30; i++ {
		raw, _ := EncodeMessage(MsgData, string(bytes.Repeat([]byte{'z'}, 40)))
		require.NoError(t, client.WriteMessage(1, raw))
	}
	require.Eventually(t, func() bool { return rig.rep.count() == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Less(t, time.Since(start), 5*time.Second)
	// 之後的輸入轉送不再等待
	t0 := time.Now()
	raw, _ := EncodeMessage(MsgData, "after\r")
	require.NoError(t, client.WriteMessage(1, raw))
	require.Eventually(t, func() bool { return bytes.Contains([]byte(conn.written()), []byte("after")) },
		time.Second, 5*time.Millisecond)
	require.Less(t, time.Since(t0), time.Second)
	b.stop()
	<-done
	rec.Close()
	row := rig.row(t, 11)
	require.Equal(t, model.KeystrokeStatusFailed, row.Status)
	require.Equal(t, model.CauseKeystrokeWriterStalled, row.FailureCause)
	require.Equal(t, 1, rig.rep.count())
}

func TestKeystrokeNotCoveredK8sLogsAndConsole(t *testing.T) {
	rig := newKsHandlerRig(t, nil)
	require.Nil(t, rig.h.startKeystroke(&model.Session{ID: 20, Protocol: model.ProtocolK8s}, "k8s", keystroke.KindK8sLogs))
	require.Nil(t, rig.h.startKeystroke(&model.Session{ID: 21, Protocol: "mysql"}, "mysql", keystroke.KindDBConsole))
	require.Nil(t, rig.h.startKeystroke(&model.Session{ID: 22, Protocol: "mysql"}, "mysql", keystroke.KindAgentDBConsole))
	require.Nil(t, rig.h.startKeystroke(&model.Session{ID: 23, Protocol: "sftp"}, "sftp", keystroke.KindFileTransfer))
	for sid, reason := range map[uint]string{20: model.CoverageReasonK8sLogsReadonly, 21: model.CoverageReasonDBConsole,
		22: model.CoverageReasonDBConsole, 23: model.CoverageReasonFileTransfer} {
		row := rig.row(t, sid)
		require.Equal(t, model.KeystrokeStatusNotCovered, row.Status)
		require.Equal(t, reason, row.CoverageReason)
		require.Empty(t, row.FilePath)
		require.Empty(t, row.FileKeyEnc)
	}
	ents, _ := os.ReadDir(rig.root)
	require.Empty(t, ents, "not-covered sessions must not create files")
}

// 代理通道開啟的終端（in-process 傳輸、非 console）產生紀錄。
func TestKeystrokeInProcessTerminalProducesRecord(t *testing.T) {
	rig := newKsHandlerRig(t, nil)
	sess := &model.Session{ID: 30, Protocol: model.ProtocolSSH}
	rec := runKsBridge(t, rig, sess, keystroke.KindAgentTerminal, newBlockingConn(nil), "uptime\r")
	require.NotNil(t, rec)
	rec.Close()
	row := rig.row(t, 30)
	require.Equal(t, model.KeystrokeStatusComplete, row.Status)
	require.Equal(t, 1, rig.read(t, row).TotalEvents)
}

func TestKeystrokeCoverageTerminalKindsAreCovered(t *testing.T) {
	for _, k := range []keystroke.SessionKind{keystroke.KindSSHTerminal, keystroke.KindDBCLI,
		keystroke.KindK8sExec, keystroke.KindAgentTerminal} {
		covered, reason := keystroke.Coverage(k)
		require.True(t, covered, string(k))
		require.Empty(t, reason)
	}
}

// 結束原因標記：平台終止、逾時類由平台原因決定；標記帶 platform 旗標，位於最後一筆輸入之後。
func TestKeystrokeEndMarkerPlatformTerminate(t *testing.T) {
	rig := newKsHandlerRig(t, nil)
	sess := &model.Session{ID: 40, Protocol: model.ProtocolSSH}
	server, client := NewInProcessTransportPair()
	b := newBridge(server, newBlockingConn(nil), sess, nil, "", 1, 2)
	rec := rig.h.attachKeystrokeTo(b, sess, "ssh", keystroke.KindSSHTerminal)
	done := make(chan struct{})
	go func() { b.Run(); close(done) }()
	raw, _ := EncodeMessage(MsgData, "id\r")
	require.NoError(t, client.WriteMessage(1, raw))
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, b.terminate())
	<-done
	require.Equal(t, keystroke.MarkerEndTerminated, b.EndMarker())
	rec.AppendMarker(b.EndMarker())
	rec.Close()
	res := rig.read(t, rig.row(t, 40))
	require.Equal(t, reader.StatusComplete, res.Status)
	require.Equal(t, 2, res.TotalEvents)
	last := res.Events[1]
	require.Equal(t, format.KindMarker, last.Kind)
	require.Equal(t, format.FlagPlatform, last.Flags)
	require.Equal(t, keystroke.MarkerEndTerminated, string(last.Payload))
}

func TestKeystrokeEndMarkerMapping(t *testing.T) {
	cases := []struct {
		reason, cause, want string
	}{
		{endReasonIdleTimeout, keystroke.MarkerEndClientLost, keystroke.MarkerEndIdleTimeout},
		{endReasonMaxDuration, keystroke.MarkerEndUserClosed, keystroke.MarkerEndMaxDuration},
		{endReasonBlockClearFailed, keystroke.MarkerEndTargetClosed, keystroke.MarkerEndBlockClearFailed},
		{endReasonNormal, keystroke.MarkerEndTargetClosed, keystroke.MarkerEndTargetClosed},
		{endReasonNormal, keystroke.MarkerEndUserClosed, keystroke.MarkerEndUserClosed},
	}
	for _, c := range cases {
		b := &bridge{endReason: endReasonNormal}
		b.setEndReason(c.reason)
		b.setCloseCause(c.cause)
		b.setCloseCause(keystroke.MarkerEndClientLost) // 第一個觸發者勝出
		require.Equal(t, c.want, b.EndMarker(), c.reason+"/"+c.cause)
	}
	require.Empty(t, (&bridge{endReason: endReasonNormal}).EndMarker())
}
