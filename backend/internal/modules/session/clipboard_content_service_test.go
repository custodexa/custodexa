package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 單筆剪貼簿內容調閱的 fail-close 語義（AP-74）。
//
// 四個面：成功調閱＋審計恰一筆含事件識別；審計不可用時拒絕且無明文交付
// （注入以 sink 計數證明走到）；跨會話 eventID 收斂拒絕且不產生歸屬錯誤的
// 審計；缺口紀錄回事實不觸發解密。403 權限面在 handler 測試
// （internal/api/clipboard_event_handler_test.go）以真權限中介層驗。

func setupClipboardContentDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取得 sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1) // sqlite :memory: 連線池陷阱（ff51836 教訓）
	if err := db.AutoMigrate(&model.ClipboardEvent{}, &model.AuditLog{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 資產主體解析用會話列（會話 73→asset 7、會話 88→asset 9）
	asset7, asset9 := uint(7), uint(9)
	for _, s := range []*model.Session{
		{ID: 73, SessionID: "sess-73", Status: model.SessionStatusClosed, Protocol: model.ProtocolRDP, UserID: 1, AssetID: &asset7},
		{ID: 88, SessionID: "sess-88", Status: model.SessionStatusClosed, Protocol: model.ProtocolVNC, UserID: 1, AssetID: &asset9},
	} {
		if err := db.Create(s).Error; err != nil {
			t.Fatalf("seed session %d: %v", s.ID, err)
		}
	}
	return db
}

// stubClipboardCodec 可觀察的 ColumnCodec：密文＝可逆前綴編碼，
// decryptCalls 供「未展開不解密」與「缺口不解密」斷言。
type stubClipboardCodec struct {
	decryptCalls atomic.Int64
	decryptErr   error
}

func (s *stubClipboardCodec) EncryptFor(_ context.Context, _ crypto.CipherRef, plaintext string) (string, error) {
	return "enc:test:" + plaintext, nil
}

func (s *stubClipboardCodec) DecryptFor(_ context.Context, _ crypto.CipherRef, ciphertext string) (string, error) {
	s.decryptCalls.Add(1)
	if s.decryptErr != nil {
		return "", s.decryptErr
	}
	return strings.TrimPrefix(ciphertext, "enc:test:"), nil
}

// countingTxSink 真落地（tx.Create）＋呼叫計數；err 非 nil 時注入失敗。
// 計數是故障注入的證明力來源：拒絕發生時 sink 曾被呼叫＝fail-close 路徑
// 真的走到，而非前置早退。
type countingTxSink struct {
	calls atomic.Int64
	err   error
}

func (s *countingTxSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	s.calls.Add(1)
	if s.err != nil {
		return s.err
	}
	row := &model.AuditLog{
		UserID:     ev.Actor.UserID,
		Username:   ev.Actor.Username,
		Action:     model.AuditAction(ev.Action),
		Resource:   model.AuditResource(ev.Resource),
		ResourceID: ev.ResourceID,
		AssetID:    ev.AssetID,
		Status:     model.AuditStatus(ev.Status),
		Method:     ev.Request.Method,
		Path:       ev.Request.Path,
		ClientIP:   ev.Request.ClientIP,
		RequestID:  ev.Request.RequestID,
		Details:    ev.Details,
	}
	return tx.Create(row).Error
}

// recordingFailureReporter 告警鏈的觀察樁。
type recordingFailureReporter struct {
	mechanisms []string
	causes     []string
}

func (r *recordingFailureReporter) Report(mechanism, causeCode string, _ map[string]string) {
	r.mechanisms = append(r.mechanisms, mechanism)
	r.causes = append(r.causes, causeCode)
}

func seedClipboardEvent(t *testing.T, db *gorm.DB, sessionID uint, status, plaintext string) uint {
	t.Helper()
	ev := &model.ClipboardEvent{
		SessionID:     sessionID,
		Direction:     "send",
		ContentLength: len(plaintext),
		ContentStatus: status,
	}
	if status == model.ClipboardContentAvailable {
		ev.ContentEnc = "enc:test:" + plaintext
	}
	if err := db.Create(ev).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	return ev.ID
}

func testOperator() ClipboardReadOperator {
	return ClipboardReadOperator{
		UserID: 9, Username: "auditor", ClientIP: "10.0.0.9",
		RequestID: "req-1", Path: "/api/v1/sessions/73/clipboard-events/1/content",
	}
}

// TestClipboardContentReadSuccessAuditsOnce 成功調閱：回明文，audit_logs 恰一筆，
// 含操作者、會話與事件識別（details.event_id）
func TestClipboardContentReadSuccessAuditsOnce(t *testing.T) {
	db := setupClipboardContentDB(t)
	codec := &stubClipboardCodec{}
	sink := &countingTxSink{}
	svc := NewClipboardContentService(db, codec, sink, &recordingFailureReporter{})
	evID := seedClipboardEvent(t, db, 73, model.ClipboardContentAvailable, "top-secret-paste")

	view, err := svc.ReadContent(context.Background(), 73, evID, testOperator())
	if err != nil {
		t.Fatalf("ReadContent: %v", err)
	}
	if view.Content != "top-secret-paste" {
		t.Errorf("content = %q", view.Content)
	}
	if view.Event.ContentStatus != model.ClipboardContentAvailable {
		t.Errorf("content_status = %q", view.Event.ContentStatus)
	}

	var rows []model.AuditLog
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("讀 audit_logs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit_logs 應恰一筆（逐筆粒度），得 %d", len(rows))
	}
	row := rows[0]
	if row.UserID != 9 || row.Username != "auditor" {
		t.Errorf("操作者 = (%d, %q)", row.UserID, row.Username)
	}
	if row.Resource != model.ResourceClipboardEvent || row.Action != model.ActionRead {
		t.Errorf("resource/action = %s/%s", row.Resource, row.Action)
	}
	if row.ResourceID == nil || *row.ResourceID != 73 {
		t.Errorf("resource_id = %v, want 73（範圍鍵＝會話 id）", row.ResourceID)
	}
	if row.AssetID == nil || *row.AssetID != 7 {
		t.Errorf("asset_id = %v, want 7（資產主體鍵經所屬會話解析，AP-74 pivotFilled）", row.AssetID)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
		t.Fatalf("details 非 JSON: %q (%v)", row.Details, err)
	}
	if details["event_id"] != fmt.Sprint(evID) || details["session_id"] != "73" {
		t.Errorf("事件識別缺失: details=%s", row.Details)
	}
	if details["content_status"] != model.ClipboardContentAvailable {
		t.Errorf("details.content_status = %q", details["content_status"])
	}
	// 明文不得進審計列
	if strings.Contains(row.Details, "top-secret-paste") {
		t.Errorf("審計 details 殘留明文: %s", row.Details)
	}
}

// TestClipboardContentAuditUnavailableRefusesDelivery fail-close：
// 審計寫入不可用 → 拒絕且無明文交付；注入點走到以 sink 計數為證；
// 失敗經告警鏈（audit_write／audit_write_sync_refused）揭露
func TestClipboardContentAuditUnavailableRefusesDelivery(t *testing.T) {
	db := setupClipboardContentDB(t)
	codec := &stubClipboardCodec{}
	sink := &countingTxSink{err: errors.New("audit db unavailable (injected)")}
	reporter := &recordingFailureReporter{}
	svc := NewClipboardContentService(db, codec, sink, reporter)
	evID := seedClipboardEvent(t, db, 73, model.ClipboardContentAvailable, "must-not-leak")

	view, err := svc.ReadContent(context.Background(), 73, evID, testOperator())
	if err == nil {
		t.Fatalf("審計不可用時 MUST 拒絕，卻回 view=%+v", view)
	}
	if view != nil {
		t.Fatalf("拒絕時不得交付任何內容: %+v", view)
	}
	if sink.calls.Load() == 0 {
		t.Fatal("審計 sink 零呼叫——故障從未觸發（前置早退），本測試失去證明力")
	}
	// 告警鏈：機制失效必須被看見
	if len(reporter.mechanisms) != 1 || reporter.mechanisms[0] != model.MechanismAuditWrite ||
		reporter.causes[0] != model.CauseAuditWriteSyncRefused {
		t.Errorf("告警鏈未走到或參數不符: mechanisms=%v causes=%v", reporter.mechanisms, reporter.causes)
	}
	// 交易回滾：audit_logs 零列（半截審計不得殘留）
	var count int64
	db.Model(&model.AuditLog{}).Count(&count)
	if count != 0 {
		t.Errorf("audit_logs 應零列（回滾），得 %d", count)
	}
}

// TestClipboardContentCrossSessionRefused 跨會話 eventID：單一受權查詢收斂拒絕，
// 不產生歸屬錯誤的審計紀錄，也不觸發解密
func TestClipboardContentCrossSessionRefused(t *testing.T) {
	db := setupClipboardContentDB(t)
	codec := &stubClipboardCodec{}
	sink := &countingTxSink{}
	svc := NewClipboardContentService(db, codec, sink, &recordingFailureReporter{})
	evID := seedClipboardEvent(t, db, 88, model.ClipboardContentAvailable, "other-session-secret")

	// 以會話 73 的路徑帶會話 88 的事件識別
	view, err := svc.ReadContent(context.Background(), 73, evID, testOperator())
	if !errors.Is(err, ErrClipboardEventNotFound) {
		t.Fatalf("跨會話 MUST 收斂拒絕（ErrClipboardEventNotFound），got view=%+v err=%v", view, err)
	}
	if codec.decryptCalls.Load() != 0 {
		t.Error("跨會話拒絕不得觸發解密")
	}
	if sink.calls.Load() != 0 {
		t.Error("跨會話拒絕不得產生審計紀錄（歸屬錯誤的紀錄比沒有更糟）")
	}
	var count int64
	db.Model(&model.AuditLog{}).Count(&count)
	if count != 0 {
		t.Errorf("audit_logs 應零列，得 %d", count)
	}

	// 不存在的 eventID 與跨會話收斂為同一錯誤（不洩存在性細節）
	_, err2 := svc.ReadContent(context.Background(), 73, evID+999, testOperator())
	if !errors.Is(err2, ErrClipboardEventNotFound) {
		t.Fatalf("不存在的 eventID 應收斂為同一錯誤, got %v", err2)
	}
}

// TestClipboardContentGapRecordSkipsDecrypt 缺口紀錄：回事實與失敗標記、
// 不觸發解密、Content 空；仍逐筆留痕（含 content_status=failed）
func TestClipboardContentGapRecordSkipsDecrypt(t *testing.T) {
	db := setupClipboardContentDB(t)
	codec := &stubClipboardCodec{}
	sink := &countingTxSink{}
	svc := NewClipboardContentService(db, codec, sink, &recordingFailureReporter{})
	evID := seedClipboardEvent(t, db, 73, model.ClipboardContentFailed, "")

	view, err := svc.ReadContent(context.Background(), 73, evID, testOperator())
	if err != nil {
		t.Fatalf("缺口紀錄調閱應成功（回事實）: %v", err)
	}
	if view.Event.ContentStatus != model.ClipboardContentFailed || view.Content != "" {
		t.Errorf("缺口紀錄應回失敗標記且無內容: %+v", view)
	}
	if codec.decryptCalls.Load() != 0 {
		t.Error("缺口紀錄不得觸發解密")
	}
	var rows []model.AuditLog
	db.Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("缺口調閱仍應留痕恰一筆，得 %d", len(rows))
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(rows[0].Details), &details); err != nil {
		t.Fatalf("details 非 JSON: %v", err)
	}
	if details["content_status"] != model.ClipboardContentFailed {
		t.Errorf("留痕應標示缺口態: %s", rows[0].Details)
	}
}
