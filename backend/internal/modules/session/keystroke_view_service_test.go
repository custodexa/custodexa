package session

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
)

// 鍵盤紀錄查看服務：中繼資料各狀態、同步留痕的 fail-close、解封與完整性錯誤。
// 內容標記只做位元組比對，失敗訊息不印內容。

const ksViewMarker = "KS_VIEW_MARKER_91c2"

type ksViewCodec struct {
	inner    *ksFakeCodec
	decrypts atomic.Int64
	err      error
}

func (c *ksViewCodec) EncryptBytesFor(ctx context.Context, ref crypto.CipherRef, p []byte) (string, error) {
	return c.inner.EncryptBytesFor(ctx, ref, p)
}
func (c *ksViewCodec) DecryptBytesFor(ctx context.Context, ref crypto.CipherRef, s string) (*material.Secret, error) {
	c.decrypts.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	return c.inner.DecryptBytesFor(ctx, ref, s)
}

type ksViewRig struct {
	*ksRig
	view  *KeystrokeViewService
	vc    *ksViewCodec
	sink  *countingTxSink
	fails *recordingFailureReporter
}

func newKsViewRig(t *testing.T) *ksViewRig {
	t.Helper()
	r := newKsRig(t)
	if err := r.db.AutoMigrate(&model.Session{}, &model.AuditLog{}, &database.SchemaMigration{}); err != nil {
		t.Fatal(err)
	}
	asset := uint(7)
	for _, id := range []uint{11, 12, 13, 14, 15, 16, 17, 18} {
		s := &model.Session{ID: id, SessionID: "s-" + string(rune('a'+id)), Status: model.SessionStatusClosed,
			Protocol: model.ProtocolSSH, UserID: 1, AssetID: &asset, StartTime: time.Now()}
		if err := r.db.Create(s).Error; err != nil {
			t.Fatal(err)
		}
	}
	vc := &ksViewCodec{inner: r.codec}
	sink := &countingTxSink{}
	fails := &recordingFailureReporter{}
	return &ksViewRig{ksRig: r, view: NewKeystrokeViewService(r.db, vc, r.root, sink, fails), vc: vc, sink: sink, fails: fails}
}

func (r *ksViewRig) record(t *testing.T, id uint, inputs ...string) {
	t.Helper()
	rec, err := r.svc.Start(&model.Session{ID: id}, "ssh")
	if err != nil || rec == nil {
		t.Fatalf("start: %v", err)
	}
	for _, in := range inputs {
		rec.AppendInput([]byte(in))
	}
	rec.Close()
}

func ksOp() KeystrokeViewOperator {
	return KeystrokeViewOperator{UserID: 9, Username: "auditor", ClientIP: "10.0.0.9",
		RequestID: "req-ks", Path: "/api/v1/sessions/11/keystrokes/view"}
}

func (r *ksViewRig) attemptRows(t *testing.T) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := r.db.Where("resource = ?", model.ResourceKeystrokeRecord).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestKeystrokeMetaStates(t *testing.T) {
	r := newKsViewRig(t)
	now := time.Now()
	insert := func(sid uint, status, cov, cause, path, key string) {
		row := &model.KeystrokeRecord{RecordUUID: "u-" + status + cause + cov, SessionID: sid, Protocol: "ssh", Status: status,
			CoverageReason: cov, FailureCause: cause, FilePath: path, FileKeyEnc: key, StartedAt: now}
		if status == model.KeystrokeStatusPurged {
			row.PurgedAt = &now
		}
		if err := r.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name     string
		sid      uint
		status   string
		cov      string
		cause    string
		path     string
		key      string
		state    string
		viewable bool
	}{
		{"not_covered", 11, model.KeystrokeStatusNotCovered, "db_console", "", "", "", "not_covered", false},
		{"failed 無檔案", 12, model.KeystrokeStatusFailed, "", "KEYSTROKE_KEY_SEAL_FAILED", "", "", "failed", false},
		{"failed 有檔案", 13, model.KeystrokeStatusFailed, "", "KEYSTROKE_WRITE_FAILED", "a/b", "enc:00", "failed", true},
		{"purged", 14, model.KeystrokeStatusPurged, "", "", "a/b", "", "purged", false},
		{"recording", 15, model.KeystrokeStatusRecording, "", "", "a/b", "enc:00", "recording", true},
		{"complete", 16, model.KeystrokeStatusComplete, "", "", "a/b", "enc:00", "complete", true},
		{"incomplete", 17, model.KeystrokeStatusIncomplete, "", "", "a/b", "enc:00", "incomplete", true},
	}
	for _, c := range cases {
		insert(c.sid, c.status, c.cov, c.cause, c.path, c.key)
		m, err := r.view.Meta(c.sid)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if m.State != c.state || m.Viewable != c.viewable {
			t.Errorf("%s: state=%s viewable=%v, want %s/%v", c.name, m.State, m.Viewable, c.state, c.viewable)
		}
	}
	if m, _ := r.view.Meta(11); m.CoverageReason != "db_console" {
		t.Errorf("not_covered 應帶 coverage_reason，得 %q", m.CoverageReason)
	}
	if m, _ := r.view.Meta(13); m.FailureCause == "" {
		t.Error("failed 應帶 failure_cause")
	}
	if m, _ := r.view.Meta(14); m.PurgedAt == nil {
		t.Error("purged 應帶 purged_at")
	}
}

func TestKeystrokeMetaNoRowPreFeatureVsMissing(t *testing.T) {
	r := newKsViewRig(t)
	since := time.Now().Add(-time.Hour)
	if err := r.db.Create(&database.SchemaMigration{Version: database.KeystrokeFeatureMigrationVersion, AppliedAt: since}).Error; err != nil {
		t.Fatal(err)
	}
	// 會話 11 開始於上線之前、12 開始於上線之後；兩者都沒有紀錄列
	r.db.Model(&model.Session{}).Where("id = ?", 11).Update("start_time", since.Add(-time.Hour))
	m, err := r.view.Meta(11)
	if err != nil || m.State != KeystrokeStatePreFeature || m.FeatureSince == nil || m.Viewable {
		t.Fatalf("pre_feature: %+v %v", m, err)
	}
	m, err = r.view.Meta(12)
	if err != nil || m.State != KeystrokeStateRecordMissing || m.Viewable {
		t.Fatalf("record_missing: %+v %v", m, err)
	}
	if _, err := r.view.Meta(9999); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("會話不存在應回 ErrSessionNotFound，得 %v", err)
	}
}

func TestKeystrokeViewSuccessLeavesOneAttemptRow(t *testing.T) {
	r := newKsViewRig(t)
	r.record(t, 11, ksViewMarker, "ls\r")
	v, err := r.view.View(context.Background(), 11, KeystrokeViewRequest{Reason: "調查工單 42"}, ksOp())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Events) != 2 || v.Integrity != "complete" || v.NextEvent != nil || v.RecordStatus != "complete" {
		t.Fatalf("events=%d integrity=%s next=%v status=%s", len(v.Events), v.Integrity, v.NextEvent, v.RecordStatus)
	}
	got, _ := base64.StdEncoding.DecodeString(v.Events[0].DataB64)
	if string(got) != ksViewMarker || v.Events[0].Source != "user" || v.Events[0].Blocked {
		t.Fatal("第一筆事件內容或來源不符")
	}
	rows := r.attemptRows(t)
	if len(rows) != 1 || r.sink.calls.Load() != 1 {
		t.Fatalf("應恰一筆嘗試列，得 %d（sink 呼叫 %d）", len(rows), r.sink.calls.Load())
	}
	d := rows[0].Details
	if !strings.Contains(d, `"reason":"調查工單 42"`) || !strings.Contains(d, `"phase":"attempt"`) ||
		!strings.Contains(d, `"session_id":"11"`) || !strings.Contains(d, `"record_status":"complete"`) {
		t.Fatalf("嘗試列欄位不齊（長度 %d）", len(d))
	}
	if strings.Contains(d, ksViewMarker) || strings.Contains(rows[0].RequestBody, ksViewMarker) {
		t.Fatal("審計列含明文按鍵標記")
	}
	// 留痕列在交付前寫入，實際結果以同一請求的中介層列為準（details 標明）
	if !strings.Contains(d, `"outcome":"see_request_row"`) {
		t.Fatalf("留痕列須標明結果以請求列為準（長度 %d）", len(d))
	}
	if rows[0].AssetID == nil || *rows[0].AssetID != 7 || rows[0].RequestID != "req-ks" || rows[0].Action != model.ActionRead {
		t.Fatal("嘗試列的資產、請求識別或動作不符")
	}
}

func TestKeystrokeViewPagingAndPlatformFlags(t *testing.T) {
	r := newKsViewRig(t)
	rec, _ := r.svc.Start(&model.Session{ID: 11}, "ssh")
	rec.AppendInput([]byte("a"))
	rec.AppendBlocked([]byte("b"))
	rec.AppendPlatform([]byte{0x03})
	rec.Append(format.KindMarker, 0, []byte("SESSION_END_NORMAL"))
	rec.AppendInput([]byte("e"))
	rec.Close()
	ctx := context.Background()
	p1, err := r.view.View(ctx, 11, KeystrokeViewRequest{Reason: "x", Limit: 2}, ksOp())
	if err != nil || len(p1.Events) != 2 || p1.NextEvent == nil || *p1.NextEvent != 2 {
		t.Fatalf("p1: %v %+v", err, p1)
	}
	if !p1.Events[1].Blocked {
		t.Fatal("第二筆應為已阻斷")
	}
	p2, err := r.view.View(ctx, 11, KeystrokeViewRequest{Reason: "x", FromEvent: 2, Limit: 2}, ksOp())
	if err != nil || len(p2.Events) != 2 || p2.NextEvent == nil || *p2.NextEvent != 4 {
		t.Fatalf("p2: %v", err)
	}
	if p2.Events[0].Source != "platform" || p2.Events[1].Marker != "SESSION_END_NORMAL" || p2.Events[1].DataB64 != "" {
		t.Fatal("平台來源或標記事件形狀不符")
	}
	p3, err := r.view.View(ctx, 11, KeystrokeViewRequest{Reason: "x", FromEvent: 4, Limit: 2}, ksOp())
	if err != nil || len(p3.Events) != 1 || p3.NextEvent != nil {
		t.Fatalf("p3: %v", err)
	}
	if n := len(r.attemptRows(t)); n != 3 {
		t.Fatalf("三頁應有三筆嘗試列，得 %d", n)
	}
}

func TestKeystrokeViewRecordingStatusReadable(t *testing.T) {
	r := newKsViewRig(t)
	r.record(t, 11, "abc")
	r.db.Model(&model.KeystrokeRecord{}).Where("session_id = ?", 11).Update("status", model.KeystrokeStatusRecording)
	v, err := r.view.View(context.Background(), 11, KeystrokeViewRequest{Reason: "x"}, ksOp())
	if err != nil || v.RecordStatus != "recording" || len(v.Events) != 1 {
		t.Fatalf("recording 狀態應可讀已封出的段: %v", err)
	}
}

// 審計不可用：不交付、不解密、告警鏈通報（fail-close）。拿掉嘗試審計寫入此測試必須轉紅。
func TestKeystrokeViewAuditFailureDeliversNothing(t *testing.T) {
	r := newKsViewRig(t)
	r.record(t, 11, ksViewMarker)
	r.sink.err = errors.New("audit db unavailable (injected)")
	v, err := r.view.View(context.Background(), 11, KeystrokeViewRequest{Reason: "x"}, ksOp())
	if !errors.Is(err, ErrKeystrokeAuditUnavailable) || v != nil {
		t.Fatalf("審計不可用應拒絕交付，err=%v view=%v", err, v)
	}
	if r.sink.calls.Load() != 1 {
		t.Fatalf("sink 必須被呼叫（證明 fail-close 路徑真的走到），得 %d", r.sink.calls.Load())
	}
	if r.vc.decrypts.Load() != 0 {
		t.Fatal("審計失敗時不得解封檔案金鑰")
	}
	if len(r.fails.mechanisms) != 1 || r.fails.mechanisms[0] != model.MechanismAuditWrite {
		t.Fatalf("應以 audit_write 機制通報，得 %v", r.fails.mechanisms)
	}
	if n := len(r.attemptRows(t)); n != 0 {
		t.Fatalf("審計失敗不應有落地列，得 %d", n)
	}
}

func TestKeystrokeViewNilAuditSinkRefuses(t *testing.T) {
	r := newKsViewRig(t)
	r.record(t, 11, "x")
	svc := NewKeystrokeViewService(r.db, r.vc, r.root, nil, r.fails)
	if v, err := svc.View(context.Background(), 11, KeystrokeViewRequest{Reason: "x"}, ksOp()); err == nil || v != nil {
		t.Fatal("未接審計 sink 時必須拒絕交付")
	}
}

func TestKeystrokeViewSealedKeepsAttemptNoDelivery(t *testing.T) {
	r := newKsViewRig(t)
	r.record(t, 11, ksViewMarker)
	r.vc.err = seal.ErrMaterialSealed
	v, err := r.view.View(context.Background(), 11, KeystrokeViewRequest{Reason: "x"}, ksOp())
	if !errors.Is(err, ErrKeystrokeVaultSealed) || v != nil {
		t.Fatalf("err=%v", err)
	}
	if n := len(r.attemptRows(t)); n != 1 {
		t.Fatalf("解封失敗仍應有嘗試列，得 %d", n)
	}
}

func TestKeystrokeViewHeaderMismatchRejected(t *testing.T) {
	r := newKsViewRig(t)
	r.record(t, 11, ksViewMarker)
	r.db.Model(&model.KeystrokeRecord{}).Where("session_id = ?", 11).Update("protocol", "rdp")
	v, err := r.view.View(context.Background(), 11, KeystrokeViewRequest{Reason: "x"}, ksOp())
	if !errors.Is(err, ErrKeystrokeRecordRejected) || v != nil {
		t.Fatalf("標頭不符應拒絕交付任何事件: %v", err)
	}
}

func TestKeystrokeViewPathEscapeRejected(t *testing.T) {
	r := newKsViewRig(t)
	r.record(t, 11, "x")
	r.db.Model(&model.KeystrokeRecord{}).Where("session_id = ?", 11).Update("file_path", "../../etc/passwd")
	if _, err := r.view.View(context.Background(), 11, KeystrokeViewRequest{Reason: "x"}, ksOp()); !errors.Is(err, ErrKeystrokeRecordRejected) {
		t.Fatalf("越界路徑應拒絕: %v", err)
	}
}

func TestKeystrokeViewTamperedAndMissingDeliverState(t *testing.T) {
	r := newKsViewRig(t)
	r.record(t, 11, "first", "second")
	var row model.KeystrokeRecord
	r.db.Where("session_id = ?", 11).First(&row)
	full := filepath.Join(r.root, row.FilePath)
	b, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-3] ^= 0xff
	if err := os.WriteFile(full, b, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := r.view.View(context.Background(), 11, KeystrokeViewRequest{Reason: "x"}, ksOp())
	if err != nil || v.Integrity != "tampered" || v.FailedSegment == nil {
		t.Fatalf("疑似竄改應交付並標示: %v", err)
	}
	if err := os.Remove(full); err != nil {
		t.Fatal(err)
	}
	v, err = r.view.View(context.Background(), 11, KeystrokeViewRequest{Reason: "x"}, ksOp())
	if err != nil || v.Integrity != "file_missing" || len(v.Events) != 0 {
		t.Fatalf("檔案缺失應交付狀態而非空白冒充: %v", err)
	}
}

func TestKeystrokeViewNotViewableWritesNoAttempt(t *testing.T) {
	r := newKsViewRig(t)
	if err := r.db.Create(&model.KeystrokeRecord{RecordUUID: "u1", SessionID: 12, Protocol: "ssh",
		Status: model.KeystrokeStatusNotCovered, CoverageReason: "db_console", StartedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	cases := []uint{11, 12} // 11 無列、12 不產生
	for _, sid := range cases {
		_, err := r.view.View(context.Background(), sid, KeystrokeViewRequest{Reason: "x"}, ksOp())
		var nv *KeystrokeNotViewableError
		if !errors.As(err, &nv) {
			t.Fatalf("會話 %d 應回不可查看: %v", sid, err)
		}
	}
	if r.sink.calls.Load() != 0 || r.vc.decrypts.Load() != 0 {
		t.Fatal("不可查看時不得留嘗試列、不得解密")
	}
	if _, err := r.view.View(context.Background(), 9999, KeystrokeViewRequest{Reason: "x"}, ksOp()); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("會話不存在: %v", err)
	}
}

func TestKeystrokeViewLimitClamped(t *testing.T) {
	r := newKsViewRig(t)
	r.record(t, 11, "a", "b")
	v, err := r.view.View(context.Background(), 11, KeystrokeViewRequest{Reason: "x", Limit: 999999, FromEvent: -5}, ksOp())
	if err != nil || len(v.Events) != 2 {
		t.Fatalf("上限與負起點應被收斂: %v", err)
	}
	_ = gorm.ErrRecordNotFound
}

func TestKeystrokeViewCompleteRecordTruncatedReadsTampered(t *testing.T) {
	r := newKsViewRig(t)
	r.record(t, 11, "first", "second")
	var row model.KeystrokeRecord
	r.db.Where("session_id = ?", 11).First(&row)
	full := filepath.Join(r.root, row.FilePath)
	b, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, b[:len(b)-5], 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := r.view.View(context.Background(), 11, KeystrokeViewRequest{Reason: "x"}, ksOp())
	if err != nil || v.Integrity != "tampered" {
		t.Fatalf("complete 紀錄被截尾應判 tampered: err=%v", err)
	}
	r.record(t, 12, "a")
	var row2 model.KeystrokeRecord
	r.db.Where("session_id = ?", 12).First(&row2)
	r.db.Model(&row2).Update("status", model.KeystrokeStatusRecording)
	b2, _ := os.ReadFile(filepath.Join(r.root, row2.FilePath))
	_ = os.WriteFile(filepath.Join(r.root, row2.FilePath), b2[:len(b2)-5], 0o600)
	v, err = r.view.View(context.Background(), 12, KeystrokeViewRequest{Reason: "x"}, ksOp())
	if err != nil || v.Integrity != "truncated" {
		t.Fatalf("recording 狀態被截應維持 truncated: err=%v", err)
	}
}
