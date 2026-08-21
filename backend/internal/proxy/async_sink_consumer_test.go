package proxy

// AsyncSink 的**消費側**測試（modular-architecture W10.2，DoD-2 補強）
//
// 既有的 `file_tap_test.go` 雖然也是經 `gatewayapi.AsyncSink` 注入，但注入的是
// 生產實作（`audit.NewDirectSink`），驗的是「事件最終落到 audit_logs 表」——
// 那證明的是實作，不是介面。本檔補上缺的那一半：以**替身**注入同一個消費端
// （`FileTap`），證明「只經介面就能完成檔案上傳留痕這件職責」，且替身完全不碰
// audit 模組與資料庫。

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// recordingSink 只依介面契約而生的替身：把投遞到的事件留下來供斷言
type recordingSink struct {
	mu     sync.Mutex
	events []gatewayapi.AuditEvent
}

var _ gatewayapi.AsyncSink = (*recordingSink)(nil)

func (s *recordingSink) Submit(_ context.Context, ev gatewayapi.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}

func (s *recordingSink) waitFor(t *testing.T, n int) []gatewayapi.AuditEvent {
	t.Helper()
	// record 是 fire-and-forget goroutine，與生產路徑同一非同步語義
	for i := 0; i < 200; i++ {
		s.mu.Lock()
		got := len(s.events)
		s.mu.Unlock()
		if got >= n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]gatewayapi.AuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

// TestAsyncSinkConsumerEmitsUploadEventThroughInterface FileTap 只認得
// gatewayapi.AsyncSink：換上替身後，上傳留痕的**事件內容**逐欄成立，
// 且完全不需要任何審計落地實作在場。
func TestAsyncSinkConsumerEmitsUploadEventThroughInterface(t *testing.T) {
	db := setupFileTapDB(t)
	db.Create(&model.User{Username: "alice"}) // id 1
	aid := uint(7)

	sink := &recordingSink{}
	var injected gatewayapi.AsyncSink = sink // 消費端只看得到介面
	tap := NewFileTap(db, injected, 100, 1, &aid, "vnc")

	tap.Observe(inst("put", "0", "s1", "text/plain", "report.txt"))
	tap.Observe(inst("blob", "s1", b64("hello")))
	tap.Observe(inst("blob", "s1", b64("world")))
	tap.Observe(inst("end", "s1"))

	events := sink.waitFor(t, 1)
	if len(events) != 1 {
		t.Fatalf("經介面投遞的事件數 = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Action != string(model.ActionFileUpload) || ev.Resource != string(model.ResourceFile) {
		t.Fatalf("動作／資源不符: action=%q resource=%q", ev.Action, ev.Resource)
	}
	if ev.Request.Path != "report.txt" {
		t.Errorf("檔名未帶入: %q", ev.Request.Path)
	}
	if ev.Actor.UserID != 1 || ev.Actor.Username != "alice" {
		t.Errorf("行為者未帶入: %+v", ev.Actor)
	}
	if ev.ResourceID == nil || *ev.ResourceID != 7 {
		t.Errorf("assetID 未帶入: %v", ev.ResourceID)
	}
	// 只記元資料、不留內容：大小是 hello+world=10
	if !strings.Contains(ev.Details, `"size":10`) || !strings.Contains(ev.Details, `"via":"guac-sftp"`) {
		t.Errorf("元資料不符: %s", ev.Details)
	}
	if strings.Contains(ev.Details, "hello") || strings.Contains(ev.Details, "world") {
		t.Errorf("檔案內容不得進審計: %s", ev.Details)
	}
}
