package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type recordingReceiver struct {
	mu   sync.Mutex
	srv  *httptest.Server
	auth []string
}

func newRecordingReceiver(t *testing.T, body string) *recordingReceiver {
	t.Helper()
	r := &recordingReceiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.ReadAll(req.Body)
		r.mu.Lock()
		r.auth = append(r.auth, req.Header.Get("Authorization"))
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recordingReceiver) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.auth...)
}

func channelHandlerDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.NotificationChannel{}, &model.NotificationDelivery{}); err != nil {
		t.Fatal(err)
	}
	return db
}

// 測試發送只依路徑上的通道識別碼取已存設定：本文帶網址、秘密或型別都不會被讀取。
func TestNotificationChannelTestUsesStoredSettingsOnly(t *testing.T) {
	db := channelHandlerDB(t)
	a := newRecordingReceiver(t, `{"ok":true}`)
	b := newRecordingReceiver(t, `{"ok":true}`)
	ch := model.NotificationChannel{Name: "app", Type: model.NotificationChannelTypeSlackApp, URL: a.srv.URL,
		Secret: "xoxb-stored-token", Target: "C1", Enabled: true, Language: "zh-TW", MinSeverity: "low"}
	if err := db.Create(&ch).Error; err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewNotificationChannelHandler(audit.NewNotificationChannelService(db, nil))
	r.POST("/api/v1/notification-channels/:id/test", h.Test)

	var outboxBefore int64
	db.Model(&model.NotificationDelivery{}).Count(&outboxBefore)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels/1/test",
		strings.NewReader(`{"shape":"system_event","url":"`+b.srv.URL+`","secret":"xoxb-x","type":"webhook"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if got := a.requests(); len(got) != 1 || got[0] != "Bearer xoxb-stored-token" {
		t.Fatalf("已存網址應收到一次、帶已存 token: %v", got)
	}
	if got := b.requests(); len(got) != 0 {
		t.Fatalf("本文的網址不得收到請求: %v", got)
	}
	var outboxAfter int64
	db.Model(&model.NotificationDelivery{}).Count(&outboxAfter)
	if outboxAfter != outboxBefore {
		t.Fatal("測試發送不得建立待投遞紀錄")
	}

	// 不支援的形狀回 400
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels/1/test", strings.NewReader(`{"shape":"bogus"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("不支援的形狀應回 400，得 %d", w.Code)
	}
	// 省略本文時照舊
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels/1/test", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("省略本文應照舊成功，得 %d", w.Code)
	}
}

// 通道規則錯誤對應 400 與各自的機器碼。
func TestRespondChannelErrorMapsTokenRules(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for err, code := range map[error]string{
		audit.ErrChannelURLChangeNeedsSecret: string(apierror.CodeChannelURLChangeNeedsSecret),
		audit.ErrChannelTypeChangeNeedsURL:   string(apierror.CodeChannelTypeChangeNeedsURL),
		audit.ErrChannelSecretRequired:       string(apierror.CodeChannelSecretRequired),
		audit.ErrInvalidChannelTarget:        string(apierror.CodeInvalidChannelTarget),
		audit.ErrInvalidChannelSecret:        string(apierror.CodeInvalidChannelSecret),
	} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		respondChannelError(c, err)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), code) {
			t.Fatalf("%v: status=%d body=%s", err, w.Code, w.Body.String())
		}
	}
}
