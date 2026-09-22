package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func reportFixture(t *testing.T) (*gorm.DB, *audit.AgentTaskReports, *gin.Engine, *[]map[string]string) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sql, _ := db.DB()
	sql.SetMaxOpenConns(1)
	t.Cleanup(func() { sql.Close() })
	if err = db.AutoMigrate(&model.User{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.AgentTaskReport{}, &model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	owner := uint(1)
	for _, u := range []model.User{{ID: 1, Username: "owner", Kind: model.KindHuman}, {ID: 2, Username: "agent", Kind: model.KindAgent, OwnerUserID: &owner}, {ID: 3, Username: "other", Kind: model.KindAgent, OwnerUserID: &owner}} {
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
	}
	agent := uint(2)
	req := model.AccessRequest{ID: 1, RequesterID: 1, ExecutorUserID: &agent, AssetID: 1, Reason: "task", RequestedDurationMinutes: 30, Status: model.AccessRequestPending, PendingExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Create(&req).Error; err != nil {
		t.Fatal(err)
	}
	events := []map[string]string{}
	svc := audit.NewAgentTaskReports(db, audit.NewTxSink(), authz.ReadAgentTaskForReport, identity.ReadAgentAuditPrincipal, func(owner uint, event notifycat.Event, p map[string]string) {
		if owner != 1 || event != notifycat.EventAgentTaskReport || p["owner_id"] != "1" {
			t.Error(owner, event, p)
		}
		events = append(events, p)
	})
	h := NewAccessRequestHandler(nil, nil, db)
	h.SetAgentTaskReports(svc)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(2))
		c.Set("username", "agent")
		c.Set("role", model.RoleUser)
	})
	r.POST("/tasks/:id/reports", h.SubmitReport)
	r.GET("/tasks/:id/reports", h.ReportVersions)
	return db, svc, r, &events
}
func TestAgentTaskReport(t *testing.T) {
	db, svc, r, events := reportFixture(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/1/reports", strings.NewReader(`{"body":"first"}`)))
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(*events) != 1 {
		t.Fatal(events)
	}
	closed := time.Now().Add(-time.Hour)
	db.Model(&model.AccessRequest{}).Where("id=1").Update("closed_at", closed)
	for _, actor := range []gatewayapi.Actor{{UserID: 1}, {UserID: 3}} {
		if _, err := svc.Submit(context.Background(), 1, actor, "bad"); err == nil {
			t.Fatal("other principal accepted")
		}
	}
	expired := time.Now().Add(-25 * time.Hour)
	db.Model(&model.AccessRequest{}).Where("id=1").Update("closed_at", expired)
	if _, err := svc.Submit(context.Background(), 1, gatewayapi.Actor{UserID: 2}, "expired"); err != audit.ErrAgentReportWindow {
		t.Fatal(err)
	}
	var count int64
	db.Model(&model.AgentTaskReport{}).Count(&count)
	if count != 1 || len(*events) != 1 {
		t.Fatal(count, events)
	}
	// Only closed_at moves the window; terminal parent/item state does not.
	db.Model(&model.AccessRequest{}).Where("id=1").Updates(map[string]any{"status": model.AccessRequestCancelled, "closed_at": closed})
	item := model.AccessRequestItem{RequestID: 1, AssetID: 1, Status: model.AccessRequestPending}
	db.Session(&gorm.Session{SkipHooks: true}).Create(&item)
	if _, err := svc.Submit(context.Background(), 1, gatewayapi.Actor{UserID: 2}, "second"); err != nil {
		t.Fatal(err)
	}
	db.Model(&model.AccessRequestItem{}).Where("request_id=1").Update("status", model.AccessRequestExpired)
	if _, err := svc.Submit(context.Background(), 1, gatewayapi.Actor{UserID: 2}, "third"); err != nil {
		t.Fatal(err)
	}
	var audits int64
	db.Model(&model.AuditLog{}).Where("resource=?", model.ResourceAccessRequest).Count(&audits)
	if audits != 3 || len(*events) != 3 {
		t.Fatal(audits, events)
	}
	if err := db.Model(&model.AgentTaskReport{}).Where("id=1").Update("body", "overwrite").Error; err == nil {
		t.Fatal("immutable report overwritten")
	}
}
func TestAgentTaskReportVersions(t *testing.T) {
	db, svc, r, _ := reportFixture(t)
	if _, err := svc.Submit(context.Background(), 1, gatewayapi.Actor{UserID: 2}, "first"); err != nil {
		t.Fatal(err)
	}
	db.Model(&model.AccessRequest{}).Where("id=1").Update("closed_at", time.Now())
	if _, err := svc.Submit(context.Background(), 1, gatewayapi.Actor{UserID: 2}, "second"); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/tasks/1/reports", nil))
	var got audit.AgentTaskReportVersions
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	if got.Latest.Version != 2 || len(got.Versions) != 2 || got.Versions[1].Body != "first" || got.ClosedAt == nil || got.MissingAtClose == nil || *got.MissingAtClose {
		t.Fatal(fmt.Sprintf("%+v", got))
	}
}
func TestAgentTaskReportMissing(t *testing.T) {
	db, svc, r, _ := reportFixture(t)
	db.Model(&model.AccessRequest{}).Where("id=1").Update("closed_at", time.Now().Add(-time.Minute))
	if _, err := svc.Submit(context.Background(), 1, gatewayapi.Actor{UserID: 2}, "late first"); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/tasks/1/reports", nil))
	var got audit.AgentTaskReportVersions
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	if got.MissingAtClose == nil || !*got.MissingAtClose || len(got.Versions) != 1 || got.Latest.Body != "late first" || got.ClosedAt == nil {
		t.Fatal(got)
	}
}
