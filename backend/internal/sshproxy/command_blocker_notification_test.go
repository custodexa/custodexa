package sshproxy

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 阻斷路徑（C3）同步只多一次寫入：告警列與通知內容列各一次 INSERT，不讀通道、不加解密。

type stmtRecorder struct {
	mu    sync.Mutex
	stmts []string
}

func (r *stmtRecorder) LogMode(logger.LogLevel) logger.Interface      { return r }
func (r *stmtRecorder) Info(context.Context, string, ...interface{})  {}
func (r *stmtRecorder) Warn(context.Context, string, ...interface{})  {}
func (r *stmtRecorder) Error(context.Context, string, ...interface{}) {}
func (r *stmtRecorder) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, _ := fc()
	r.mu.Lock()
	r.stmts = append(r.stmts, sql)
	r.mu.Unlock()
}

type codecCounter struct{ calls atomic.Int64 }

func (c *codecCounter) EncryptFor(_ context.Context, _ crypto.CipherRef, p string) (string, error) {
	c.calls.Add(1)
	return p, nil
}
func (c *codecCounter) DecryptFor(_ context.Context, _ crypto.CipherRef, s string) (string, error) {
	c.calls.Add(1)
	return s, nil
}

type noBlockMatcher struct{}

func (noBlockMatcher) MatchBlock(string, string) (*model.AlertRule, bool) { return nil, false }

func TestRecordBlockedWritesOnlyAlertAndNotificationRows(t *testing.T) {
	db := setupAlertDB(t)
	if err := db.AutoMigrate(&model.NotificationMessage{}, &model.NotificationChannel{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.NotificationChannel{Name: "ops", Type: "webhook", URL: "https://example.test/h", Enabled: true, Language: "zh-TW"}).Error; err != nil {
		t.Fatal(err)
	}
	rec := &stmtRecorder{}
	quiet := db.Session(&gorm.Session{Logger: rec})
	codec := &codecCounter{}
	n := audit.InitAlertNotifier(quiet, codec)
	t.Cleanup(func() { audit.StopAlertNotifierForRelease(n) })

	c := newCommandBlocker(noBlockMatcher{}, audit.NewAlertRecorder(quiet), 9, 1, 5, "ssh")
	c.recordBlocked(&model.AlertRule{ID: 3, Name: "no-rm", Severity: "high"}, "rm -rf /")

	rec.mu.Lock()
	stmts := append([]string(nil), rec.stmts...)
	rec.mu.Unlock()
	if len(stmts) != 2 {
		t.Fatalf("阻斷路徑應恰為兩句語句，得 %d: %v", len(stmts), stmts)
	}
	if !strings.Contains(stmts[0], "command_alerts") || !strings.Contains(stmts[1], "notification_messages") {
		t.Fatalf("應依序寫告警列與通知內容列: %v", stmts)
	}
	for _, s := range stmts {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s)), "INSERT") || strings.Contains(s, "notification_channels") {
			t.Fatalf("不得有 INSERT 以外的語句或讀通道: %s", s)
		}
	}
	if codec.calls.Load() != 0 {
		t.Fatalf("阻斷路徑不得加解密，得 %d 次", codec.calls.Load())
	}
	var msgs []model.NotificationMessage
	db.Find(&msgs)
	if len(msgs) != 1 || msgs[0].AlertID == nil || msgs[0].Severity != "high" {
		t.Fatalf("內容列不符: %+v", msgs)
	}
}
