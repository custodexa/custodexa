package main

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 通道建立路徑：真處理器、真服務、真交易內審計與系統告警落地面。合法請求不得 500；
// 成功後通道、審計列、告警明細各一筆。表集合取授權基準環境補表用的同一份模型清單，
// 清單漏掉告警相關表時這裡就會紅（基準種子步驟同走這條路徑）。
func TestNotificationChannelCreateRouteLegalRequestNot500(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(append(baselineExtraModels(), &model.AuditLog{})...); err != nil {
		t.Fatal(err)
	}
	svc := audit.NewNotificationChannelService(db, nil)
	svc.SetAuditTxSink(audit.NewTxSink())
	svc.SetSystemAlertSink(audit.NewSystemAlertSink(nil))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "route-test")
	})
	r.POST("/api/v1/notification-channels", api.NewNotificationChannelHandler(svc).Create)

	w := doJSON(r, http.MethodPost, "/api/v1/notification-channels",
		`{"name":"ops","type":"webhook","url":"https://hooks.example.com/abc"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("合法建立應回 201，得 %d: %s", w.Code, w.Body.String())
	}
	var n int64
	for name, m := range map[string]any{
		"通道": &model.NotificationChannel{}, "審計列": &model.AuditLog{}, "告警明細": &model.SystemAlertDetail{},
	} {
		db.Model(m).Count(&n)
		if n != 1 {
			t.Fatalf("%s應恰一筆，得 %d", name, n)
		}
	}
}
