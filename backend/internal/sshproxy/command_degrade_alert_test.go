package sshproxy

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 降級告警的守衛（command-audit-altscreen-bypass tasks 3.2／3.4）。
//
// 兩件事必須同時成立，缺一都會使這條安全訊號失效：
//   - **每個 span 至少一筆**——沒有告警的降級紀錄只是「可搜尋」，
//     而 spec 明文要求「MUST 本身即為可告警的訊號」。
//   - **每個 span 至多一筆**——真 vim 一次編輯產生數十筆降級列，
//     逐列告警＝告警疲勞，而疲勞的告警等於沒有告警。

// degradeAlertSink 記帳用的假落地面（併發安全：writeLoop 在另一個 goroutine 上呼叫）。
type degradeAlertSink struct {
	mu     sync.Mutex
	alerts []gatewayapi.CommandAlert
}

func (s *degradeAlertSink) RecordAlert(ctx context.Context, a gatewayapi.CommandAlert) error {
	return s.RecordAlerts(ctx, []gatewayapi.CommandAlert{a})
}

func (s *degradeAlertSink) RecordAlerts(_ context.Context, as []gatewayapi.CommandAlert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, as...)
	return nil
}

func (s *degradeAlertSink) snapshot() []gatewayapi.CommandAlert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]gatewayapi.CommandAlert(nil), s.alerts...)
}

// newDegradeAlertStore 檔案型 sqlite（**不用 `:memory:`**——連線池會讓不同連線
// 看到不同的庫，那是本 repo 已知的「單獨跑綠、整包跑紅」來源）＋ 真的 writeLoop。
func newDegradeAlertStore(t *testing.T) (*CommandStore, *degradeAlertSink) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "cmds.db")),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("開啟 sqlite 失敗: %v", err)
	}
	if err := db.AutoMigrate(&model.SessionCommand{}); err != nil {
		t.Fatalf("建表失敗: %v", err)
	}
	aid := uint(3)
	store := NewCommandStore(db, 42, 7, &aid, "ssh")
	sink := &degradeAlertSink{}
	store.SetAlertSink(sink)
	return store, sink
}

// TestDegradeSpanEmitsExactlyOneAlert 一段連續降級只發一筆告警。
//
// 語料是真 vim 的形狀：一條正常指令 → 十筆降級列 → 一條正常指令。
// 逐列發會得到 10 筆，那是告警疲勞的形態。
func TestDegradeSpanEmitsExactlyOneAlert(t *testing.T) {
	store, sink := newDegradeAlertStore(t)
	now := time.Now()

	store.Enqueue("vim notes.txt", now)
	for i := 0; i < 10; i++ {
		store.EnqueueDegraded(model.DegradeQueueDiscarded, now.Add(time.Duration(i)*time.Second))
	}
	store.Enqueue("echo done", now.Add(20*time.Second))
	store.Close()

	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("降級告警數 = %d, want 1（一個 span 一筆；逐列發＝告警疲勞）：%+v", len(got), got)
	}
	a := got[0]
	if a.Kind != model.AlertKindAuditDegraded {
		t.Errorf("kind = %q, want %q", a.Kind, model.AlertKindAuditDegraded)
	}
	if a.ReasonCode != model.AlertReasonDegradedSpan {
		t.Errorf("reason_code = %q, want %q", a.ReasonCode, model.AlertReasonDegradedSpan)
	}
	if a.RuleID != nil {
		t.Errorf("rule_id = %v, want nil：降級告警不得掛在可被 CRUD 停用的規則上", *a.RuleID)
	}
	if a.Command != "" {
		t.Errorf("告警帶了指令文字 %q：降級的定義就是沒有可信的指令文字", a.Command)
	}
	if a.SessionID != 42 || a.Actor.UserID != 7 || a.AssetID == nil || *a.AssetID != 3 {
		t.Errorf("歸因欄有誤: %+v", a)
	}
	if a.Level != "medium" {
		t.Errorf("severity = %q, want medium（本版本不宣稱已分離日常與異常）", a.Level)
	}
	if a.Disposition != model.AlertDispositionPending {
		t.Errorf("disposition = %q, want %q", a.Disposition, model.AlertDispositionPending)
	}
	if a.Blocked {
		t.Error("blocked = true：降級不阻斷任何東西")
	}
}

// TestDegradeSpansAreSeparatedByRealCommands 兩段降級之間夾著可信重組的指令列時，
// 那是**兩個** span，各發一筆——把它們併成一筆會讓第二次降級無聲。
func TestDegradeSpansAreSeparatedByRealCommands(t *testing.T) {
	store, sink := newDegradeAlertStore(t)
	now := time.Now()

	for i := 0; i < 3; i++ {
		store.EnqueueDegraded(model.DegradeAltScreen, now)
	}
	store.Enqueue("echo gap", now.Add(time.Second))
	for i := 0; i < 3; i++ {
		store.EnqueueDegraded(model.DegradeAltScreen, now.Add(2*time.Second))
	}
	store.Enqueue("echo gap2", now.Add(3*time.Second))
	store.Close()

	if got := sink.snapshot(); len(got) != 2 {
		t.Fatalf("降級告警數 = %d, want 2（兩段各一筆）：%+v", len(got), got)
	}
}

// TestDegradeAlertDrainsAtClose 會話在降級中結束（span 未被任何正常指令關閉）時，
// 告警仍必須在 Close 回傳前發出。
//
// **這是最需要留痕的形態**：偽標記注入之後直接斷線，整段會話沒有任何一筆
// 可信重組的指令列。等到「下一批」才發等於永遠不發。
func TestDegradeAlertDrainsAtClose(t *testing.T) {
	store, sink := newDegradeAlertStore(t)
	now := time.Now()

	store.Enqueue("printf poc", now)
	for i := 0; i < 5; i++ {
		store.EnqueueDegraded(model.DegradeAltScreen, now.Add(time.Duration(i)*time.Second))
	}
	store.Close()

	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("會話在降級中結束的告警數 = %d, want 1：%+v", len(got), got)
	}
}

// TestQualifiedTextRowClosesSpanAndRaisesNoAlert 受限定的文字列
//（Degraded=false 且 DegradeReason 非空）**不是**降級列：它有文字。
// 它不得自己觸發降級告警，且應結束當前的 span（design §6.6：兩個值域刻意不合併）。
func TestQualifiedTextRowClosesSpanAndRaisesNoAlert(t *testing.T) {
	store, sink := newDegradeAlertStore(t)
	now := time.Now()

	store.Record("echo a", false, model.QualifyReplayFallback, now)
	store.Record("echo b", false, model.QualifyReplayFallback, now.Add(time.Second))
	store.Close()

	if got := sink.snapshot(); len(got) != 0 {
		t.Fatalf("受限定的文字列觸發了降級告警 %d 筆：%+v", len(got), got)
	}
}

// TestDegradeAlertWithoutSinkIsLoudNotSilent 未注入落地面時 SHALL NOT 靜默 no-op。
//
// 靜默的後果是「告警系統看起來正常但一筆都沒發」——那是本 repo 已經踩過的形態
// （BD-1）。此處以「不 panic 且會話照常結束」為界：錯誤只記 log，不反壓會話。
func TestDegradeAlertWithoutSinkIsLoudNotSilent(t *testing.T) {
	store, _ := newDegradeAlertStore(t)
	store.alerts = nil // 模擬組裝根漏接線
	now := time.Now()

	store.EnqueueDegraded(model.DegradeAltScreen, now)
	store.Close() // 不得 panic、不得卡住
}
