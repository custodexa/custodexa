package audit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openDailyReviewPG(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	schema := fmt.Sprintf("daily_review_conflict_%d", time.Now().UnixNano())
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("postgres 連線失敗: %v", err)
	}
	drop := "DROP SCHEMA IF EXISTS " + schema + " CASCADE"
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.Exec(drop)
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	if err := db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{}, &model.SecurityPolicyHistory{},
		&model.DailyReviewLog{}, &model.AuditRetentionWatermark{}, &model.CommandAlert{}); err != nil {
		t.Fatal(err)
	}
	return db
}

// TestDailyReviewSignConflictReturnsRecord 擋：兩人同時補簽同一天時第二人得到 500
// 或看不到是誰先簽。兩個交易都先通過「查無」才放行寫入，恰一筆成功、另一筆撞唯一
// 索引並轉為 409，回應帶贏家的完整紀錄
func TestDailyReviewSignConflictReturnsRecord(t *testing.T) {
	db := openDailyReviewPG(t)
	taipei, _ := time.LoadLocation("Asia/Taipei")
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, taipei)
	for _, h := range []model.SecurityPolicyHistory{
		{PolicyKey: policy.PolicyDailyReviewTimezone, NewValue: "Asia/Taipei", ChangedAt: since.Add(-time.Hour), ChangedBy: "m", Source: model.PolicyHistorySourceMigrationUpgrade},
		{PolicyKey: policy.PolicyDailyReviewEnabled, OldValue: "false", NewValue: "true", ChangedAt: since, ChangedBy: "admin", Source: model.PolicyHistorySourcePolicyUpdate},
	} {
		h := h
		if err := db.Create(&h).Error; err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range map[string]string{policy.PolicyDailyReviewTimezone: "Asia/Taipei", policy.PolicyDailyReviewEnabled: "true"} {
		if err := db.Create(&model.SecurityPolicy{Key: k, Value: v, UpdatedBy: "admin", UpdatedAt: since}).Error; err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 11, 9, 0, 0, 0, taipei)
	svc := audit.NewDailyReviewService(db, policy.NewSecurityPolicyService(db), nil)
	svc.SetClock(func() time.Time { return now })
	handler := api.NewDailyReviewHandler(svc)

	// barrier：兩個交易都通過「查無」後才一起寫入
	var arrived sync.WaitGroup
	arrived.Add(2)
	release := make(chan struct{})
	audit.SetDailyReviewSignBeforeInsertHook(func() {
		arrived.Done()
		<-release
	})
	t.Cleanup(func() { audit.SetDailyReviewSignBeforeInsertHook(nil) })

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/daily-reviews", func(c *gin.Context) {
		c.Set("userID", uint(5))
		c.Set("username", c.GetHeader("X-Test-User"))
		handler.Sign(c)
	})
	results := make(chan *httptest.ResponseRecorder, 2)
	for _, user := range []string{"auditor-a", "auditor-b"} {
		user := user
		go func() {
			body, _ := json.Marshal(map[string]string{"review_date": "2026-10-10"})
			req := httptest.NewRequest(http.MethodPost, "/daily-reviews", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Test-User", user)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			results <- w
		}()
	}
	arrived.Wait()
	close(release)

	var ok, conflict *httptest.ResponseRecorder
	for i := 0; i < 2; i++ {
		w := <-results
		switch w.Code {
		case http.StatusOK:
			ok = w
		case http.StatusConflict:
			conflict = w
		default:
			t.Fatalf("非預期狀態 %d: %s", w.Code, w.Body.String())
		}
	}
	if ok == nil || conflict == nil {
		t.Fatal("應恰一筆 200、一筆 409")
	}
	var winner model.DailyReviewLog
	if err := db.Where("review_date = ?", "2026-10-10").First(&winner).Error; err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Model(&model.DailyReviewLog{}).Count(&n)
	if n != 1 {
		t.Fatalf("簽核列 %d, want 1", n)
	}
	var env struct {
		Code   string         `json:"code"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(conflict.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Code != "CONFLICT_DAILY_REVIEW_SIGNED" {
		t.Errorf("code = %q", env.Code)
	}
	signedAt, err := time.Parse(time.RFC3339, fmt.Sprint(env.Params["signed_at"]))
	if err != nil || !signedAt.Equal(winner.SignedAt.Truncate(time.Second)) {
		t.Errorf("signed_at = %v（%v）, want 贏家的 %v（RFC3339）", env.Params["signed_at"], err, winner.SignedAt)
	}
	if env.Params["date"] != "2026-10-10" || env.Params["signer"] != winner.ReviewerName || env.Params["timezone"] != "Asia/Taipei" {
		t.Errorf("params = %v, want 贏家 %s 的紀錄", env.Params, winner.ReviewerName)
	}
	t.Logf("贏家 %s；409 params=%v", winner.ReviewerName, env.Params)
}
