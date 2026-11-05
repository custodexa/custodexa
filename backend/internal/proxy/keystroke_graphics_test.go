package proxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gorilla/websocket"
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
	"github.com/custodexa/backend/pkg/guacamole"
)

// 以下測試只印事件數與 kind 序列，不印任何 keysym 或原始參數。

type gksCodec struct{}

func (c *gksCodec) EncryptBytesFor(_ context.Context, _ crypto.CipherRef, p []byte) (string, error) {
	b := make([]byte, len(p))
	for i := range p {
		b[i] = p[i] ^ 0x33
	}
	return "e:" + hex.EncodeToString(b), nil
}

func (c *gksCodec) DecryptBytesFor(_ context.Context, _ crypto.CipherRef, s string) (*material.Secret, error) {
	raw, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, err
	}
	for i := range raw {
		raw[i] ^= 0x33
	}
	return material.Adopt(raw), nil
}

type gksReporter struct {
	mu sync.Mutex
	n  int
}

func (r *gksReporter) Report(string, string, map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
}
func (r *gksReporter) ResolveFailure(string) {}
func (r *gksReporter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

type gksRig struct {
	h     *ConnectionHandler
	db    *gorm.DB
	codec *gksCodec
	rep   *gksReporter
	root  string
}

func newGksRig(t *testing.T, hook func(*writer.Config)) *gksRig {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.KeystrokeRecord{}))
	codec := &gksCodec{}
	rep := &gksReporter{}
	root := filepath.Join(t.TempDir(), "keystrokes")
	svc := session.NewKeystrokeService(db, codec, root, rep)
	if hook != nil {
		svc.SetWriterConfigHook(hook)
	}
	return &gksRig{h: &ConnectionHandler{KeystrokeService: svc}, db: db, codec: codec, rep: rep, root: root}
}

func (r *gksRig) row(t *testing.T, sid uint) model.KeystrokeRecord {
	t.Helper()
	var row model.KeystrokeRecord
	require.NoError(t, r.db.Where("session_id = ?", sid).First(&row).Error)
	return row
}

func (r *gksRig) read(t *testing.T, row model.KeystrokeRecord) reader.Result {
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

func kinds(evs []format.Event) []byte {
	out := make([]byte, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func keyInst(args ...string) *guacamole.Instruction {
	return &guacamole.Instruction{Opcode: "key", Args: args}
}

func sendInst(t *testing.T, ws *websocket.Conn, inst *guacamole.Instruction) {
	t.Helper()
	require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte(inst.Encode())))
}

// 圖形會話涵蓋判定與啟動：RDP、VNC 都建立正常紀錄（recording），不再寫 not_covered。
func TestKeystrokeHandlerCoverageGraphicsStartsRecord(t *testing.T) {
	rig := newGksRig(t, nil)
	for sid, proto := range map[uint]string{71: "rdp", 72: "vnc"} {
		rec := rig.h.startKeystroke(&model.Session{ID: sid, Protocol: model.ProtocolType(proto)}, proto)
		require.NotNil(t, rec)
		row := rig.row(t, sid)
		require.Equal(t, model.KeystrokeStatusRecording, row.Status)
		require.Empty(t, row.CoverageReason)
		require.Equal(t, proto, row.Protocol)
		require.NotEmpty(t, row.FilePath)
		rec.Close()
		require.Equal(t, model.KeystrokeStatusComplete, rig.row(t, sid).Status)
	}
	// 未注入服務或沒有會話（既有測試路徑）不 panic、不寫列
	require.Nil(t, (&ConnectionHandler{}).startKeystroke(&model.Session{ID: 73}, "rdp"))
	require.Nil(t, rig.h.startKeystroke(nil, "rdp"))
	var n int64
	rig.db.Model(&model.KeystrokeRecord{}).Where("session_id = ?", 73).Count(&n)
	require.Zero(t, n)
}

// 與 handler 相同的接線：start → SetKeystrokeTap → Start → 結束標記 → Close。
func runGraphicsTunnel(t *testing.T, rig *gksRig, sid uint, drive func(cli *websocket.Conn)) reader.Result {
	t.Helper()
	guacd := newFakeGuacd(t)
	conn := guacd.dial(t)
	guacdSide := guacd.accepted(t)
	go func() { // 排空 guacd 端，避免寫入阻塞
		buf := make([]byte, 4096)
		for {
			if _, err := guacdSide.Read(buf); err != nil {
				return
			}
		}
	}()
	srvWS, cliWS := wsPair(t)
	rec := rig.h.startKeystroke(&model.Session{ID: sid, Protocol: model.ProtocolRDP}, "rdp")
	require.NotNil(t, rec)
	tunnel := NewTunnel(srvWS, conn, nil, nil, nil)
	tunnel.SetKeystrokeTap(NewKeystrokeTap(rec))
	done, _ := startTunnel(t, tunnel)
	drive(cliWS)
	// 正常關閉：等 pump 讀完先前送出的所有訊息
	require.NoError(t, cliWS.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(2*time.Second)))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel did not stop")
	}
	rec.AppendMarker(tunnel.EndMarker())
	rec.Close()
	return rig.read(t, rig.row(t, sid))
}

// 只記 key：滑鼠、剪貼簿、connect 握手都不入紀錄；按放序列正確；以使用者端正常關閉收尾。
func TestKeystrokeTunnelRecordsKeyOnly(t *testing.T) {
	rig := newGksRig(t, nil)
	res := runGraphicsTunnel(t, rig, 81, func(cli *websocket.Conn) {
		sendInst(t, cli, &guacamole.Instruction{Opcode: "connect", Args: []string{"1.5.0", "x", "secret-handshake-value"}})
		sendInst(t, cli, &guacamole.Instruction{Opcode: "mouse", Args: []string{"10", "20", "1"}})
		sendInst(t, cli, keyInst("97", "1"))         // 字母按下
		sendInst(t, cli, keyInst("97", "0"))         // 放開
		sendInst(t, cli, keyInst("65474", "1"))      // F5
		sendInst(t, cli, keyInst("65474", "0"))      //
		sendInst(t, cli, keyInst("65505", "1"))      // 左 Shift
		sendInst(t, cli, keyInst("65505", "0"))      //
		sendInst(t, cli, keyInst("4294967295", "1")) // keysym 上界
		sendInst(t, cli, &guacamole.Instruction{Opcode: "clipboard", Args: []string{"3", "text/plain"}})
		sendInst(t, cli, &guacamole.Instruction{Opcode: "blob", Args: []string{"3", "c2VjcmV0"}})
		sendInst(t, cli, &guacamole.Instruction{Opcode: "argv", Args: []string{"4", "text/plain", "n"}})
	})
	require.Equal(t, reader.StatusComplete, res.Status)
	require.Equal(t, []byte{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x10}, kinds(res.Events),
		"seven key events then one end marker, no other kind")
	want := []struct {
		ks      uint32
		pressed bool
	}{{97, true}, {97, false}, {65474, true}, {65474, false}, {65505, true}, {65505, false}, {0xFFFFFFFF, true}}
	for i, w := range want {
		ks, pressed, err := format.DecodeKeysym(res.Events[i].Payload)
		require.NoError(t, err)
		require.Equal(t, w.ks, ks, "event %d keysym", i)
		require.Equal(t, w.pressed, pressed, "event %d state", i)
		require.Zero(t, res.Events[i].Flags)
	}
	require.Equal(t, keystroke.MarkerEndUserClosed, string(res.Events[7].Payload))
	require.Equal(t, format.FlagPlatform, res.Events[7].Flags)
}

// 無法解析的 key 指令各記一筆 0x03，保留原始參數（含逗號也不歧義），不丟棄。
func TestKeystrokeTunnelMalformedKeyRecordedRaw(t *testing.T) {
	rig := newGksRig(t, nil)
	bad := []*guacamole.Instruction{
		keyInst("97"),                // 參數不足
		keyInst("97", "1", "extra"),  // 參數過多
		keyInst("not-a-number", "1"), // keysym 非十進位
		keyInst("4294967296", "1"),   // 超出 uint32
		keyInst("-1", "1"),           // 負值
		keyInst("97", "2"),           // 按放不是 0／1
		keyInst("9,7", "1"),          // 參數內含逗號
		keyInst(),                    // 沒有參數
	}
	res := runGraphicsTunnel(t, rig, 82, func(cli *websocket.Conn) {
		for _, in := range bad {
			sendInst(t, cli, in)
		}
	})
	require.Equal(t, reader.StatusComplete, res.Status)
	got := kinds(res.Events)
	require.Equal(t, len(bad)+1, len(got))
	for i, in := range bad {
		require.Equal(t, format.KindKeysymRaw, res.Events[i].Kind, "event %d kind", i)
		raw, err := format.DecodeKeysymRaw(res.Events[i].Payload)
		require.NoError(t, err)
		require.Equal(t, rawKeyArgs(in), string(raw), "event %d raw args", i)
	}
	require.Equal(t, byte(format.KindMarker), got[len(got)-1])
}

// 寫入 guacd 失敗的 key 指令不記入（記在成功之後）。
func TestKeystrokeTunnelWriteFailureNotRecorded(t *testing.T) {
	rig := newGksRig(t, nil)
	guacd := newFakeGuacd(t)
	conn := guacd.dial(t)
	guacd.accepted(t)
	srvWS, cliWS := wsPair(t)
	rec := rig.h.startKeystroke(&model.Session{ID: 83, Protocol: model.ProtocolRDP}, "rdp")
	require.NotNil(t, rec)
	tunnel := NewTunnel(srvWS, conn, nil, nil, nil)
	tunnel.SetKeystrokeTap(NewKeystrokeTap(rec))
	require.NoError(t, conn.Close()) // 之後的 WriteInstruction 必失敗
	sendInst(t, cliWS, keyInst("97", "1"))
	errCh := make(chan error, 1)
	go func() { errCh <- tunnel.pumpWebSocketToGuacamole() }()
	select {
	case err := <-errCh:
		require.Error(t, err, "pump must report the failed forward")
	case <-time.After(3 * time.Second):
		t.Fatal("pump did not return")
	}
	rec.Close()
	res := rig.read(t, rig.row(t, 83))
	require.Equal(t, reader.StatusComplete, res.Status)
	require.Zero(t, res.TotalEvents, "failed forward must not be recorded")
}

type gksStuckFile struct {
	writer.File
	n       int
	release chan struct{}
}

func (f *gksStuckFile) Write(p []byte) (int, error) {
	f.n++
	if f.n > 1 {
		<-f.release
	}
	return f.File.Write(p)
}

// 寫入端停擺：背壓期間 pump 同步等待、停擺判定後解除，只通報一次、紀錄標 failed＋停擺原因，
// 其後的 key 不再等待、不影響會話轉發。
func TestKeystrokeTunnelBackpressureStallFail(t *testing.T) {
	release := make(chan struct{})
	rig := newGksRig(t, func(c *writer.Config) {
		c.SegmentBytes = 8
		c.MaxQueueBytes = 64
		c.StallTimeout = 200 * time.Millisecond
		c.WrapFile = func(f writer.File) writer.File { return &gksStuckFile{File: f, release: release} }
	})
	defer close(release)
	rec := rig.h.startKeystroke(&model.Session{ID: 84, Protocol: model.ProtocolRDP}, "rdp")
	require.NotNil(t, rec)
	tap := NewKeystrokeTap(rec)

	start := time.Now()
	for i := 0; i < 200; i++ {
		tap.Observe(keyInst("97", "1"))
	}
	require.Eventually(t, func() bool { return rig.rep.count() == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Less(t, time.Since(start), 8*time.Second, "stall must release the pump")
	// 判失敗之後不再等待
	t0 := time.Now()
	for i := 0; i < 100; i++ {
		tap.Observe(keyInst("97", "0"))
	}
	require.Less(t, time.Since(t0), time.Second)
	rec.Close()
	row := rig.row(t, 84)
	require.Equal(t, model.KeystrokeStatusFailed, row.Status)
	require.Equal(t, model.CauseKeystrokeWriterStalled, row.FailureCause)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, rig.rep.count(), "one alert per record")
}

type gksFailAfterHeader struct {
	writer.File
	n int
}

func (f *gksFailAfterHeader) Write(p []byte) (int, error) {
	f.n++
	if f.n > 1 {
		return 0, errors.New("injected")
	}
	return f.File.Write(p)
}

// 寫入錯誤：紀錄標 failed、通報一次，tap 之後的呼叫立即返回。
func TestKeystrokeTunnelWriteFailureReportsOnce(t *testing.T) {
	rig := newGksRig(t, func(c *writer.Config) {
		c.SegmentBytes = 8
		c.WrapFile = func(f writer.File) writer.File { return &gksFailAfterHeader{File: f} }
	})
	rec := rig.h.startKeystroke(&model.Session{ID: 85, Protocol: model.ProtocolVNC}, "vnc")
	require.NotNil(t, rec)
	tap := NewKeystrokeTap(rec)
	for i := 0; i < 50; i++ {
		tap.Observe(keyInst("97", "1"))
	}
	rec.Close()
	row := rig.row(t, 85)
	require.Equal(t, model.KeystrokeStatusFailed, row.Status)
	require.Equal(t, model.CauseKeystrokeWriteFailed, row.FailureCause)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, rig.rep.count())
}

// 鍵盤紀錄啟動失敗：標 failed＋原因並通報，會話（tunnel）照常轉發。
func TestKeystrokeTunnelStartFailureKeepsForwarding(t *testing.T) {
	rig := newGksRig(t, nil)
	blocker := filepath.Join(t.TempDir(), "afile")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	rig.h.KeystrokeService.SetRoot(filepath.Join(blocker, "ks"))
	require.Nil(t, rig.h.startKeystroke(&model.Session{ID: 86, Protocol: model.ProtocolRDP}, "rdp"))
	row := rig.row(t, 86)
	require.Equal(t, model.KeystrokeStatusFailed, row.Status)
	require.Equal(t, model.CauseKeystrokeDirUnwritable, row.FailureCause)
	require.Equal(t, 1, rig.rep.count())

	// nil tap 的 tunnel 仍可轉發：key 指令到達 guacd
	guacd := newFakeGuacd(t)
	conn := guacd.dial(t)
	guacdSide := guacd.accepted(t)
	srvWS, cliWS := wsPair(t)
	tunnel := NewTunnel(srvWS, conn, nil, nil, nil)
	tunnel.SetKeystrokeTap(NewKeystrokeTap(nil))
	_, _ = startTunnel(t, tunnel)
	sendInst(t, cliWS, keyInst("97", "1"))
	_ = guacdSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := guacdSide.Read(buf)
	require.NoError(t, err)
	require.Equal(t, keyInst("97", "1").Encode(), string(buf[:n]))
}

// 守衛：圖形閘道參數不得讓按鍵寫進錄影檔（不使用 recording-include-keys）。
func TestGuacParamsNeverIncludeKeys(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		require.NoError(t, err)
		scanned++
		require.False(t, bytes.Contains(b, []byte("recording-include-keys")),
			"%s must not enable key capture into the recording file", e.Name())
	}
	require.Greater(t, scanned, 5, "guard must actually scan the package sources")
}
