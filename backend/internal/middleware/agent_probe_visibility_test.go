package middleware

import (
	"context"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"net/http/httptest"
	"testing"
	"time"
)

type exposureDeniedChecker struct {
	*authz.AssetAuthorizationService
}

func (exposureDeniedChecker) CheckPermission(context.Context, uint, uint, model.PermissionType) (bool, error) {
	return false, nil
}

func TestAssetVisibilityProbeEvent(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sql, _ := db.DB()
	sql.SetMaxOpenConns(1)
	t.Cleanup(func() { sql.Close() })
	if err := db.AutoMigrate(&model.User{}, &model.Asset{}, &model.AgentVisibilityExposure{}, &model.AgentProbeEvent{}, &model.AuditLog{}, &model.CommandAlert{}); err != nil {
		t.Fatal(err)
	}
	owner := uint(1)
	if err := db.Create(&model.User{ID: 2, Username: "agent", Kind: model.KindAgent, OwnerUserID: &owner}).Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint{10, 11, 12} {
		if err := db.Session(&gorm.Session{SkipHooks: true}).Create(&model.Asset{ID: id, Name: fmt.Sprint(id)}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Session(&gorm.Session{SkipHooks: true}).Model(&model.Asset{}).Where("id=12").Update("deleted_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	svc := authz.NewAssetAuthorizationService(db)
	if err := svc.RecordAgentVisibilityExposures(context.Background(), 2, []uint{10, 12}); err != nil {
		t.Fatal(err)
	}
	breaker := audit.NewProbeBreaker(db, audit.NewTxSink(), audit.NewAlertRecorder(db), audit.ProbeBreakerDependencies{
		LockPrincipal: identity.LockProbePrincipal, Classify: authz.ClassifyAgentProbe,
		Trip: func(*gorm.DB, uint, uint, time.Time) (bool, error) { t.Fatal("unexpected trip"); return false, nil }, Finish: func(uint) {}, Limits: func() (int, int) { return 2, 300 }, Notify: func(uint, notifycat.Event, map[string]string) {},
	})
	svc.SetAgentProbeRecorder(func(ctx context.Context, u, k, a uint, e string) error {
		_, err := breaker.RecordDenied(ctx, u, k, a, e)
		return err
	})
	r := gin.New()
	kind := model.KindAgent
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(2))
		c.Set("role", model.RoleUser)
		c.Set("principal_kind", kind)
		c.Set("agent_token_id", uint(3))
	})
	r.GET("/assets/:id", RequireAssetVisible(exposureDeniedChecker{svc}), func(c *gin.Context) { t.Error("denied target reached") })
	var baseline string
	for _, tc := range []struct {
		id    uint
		class string
	}{{10, model.ProbeRevoked}, {12, model.ProbeRetired}, {999, model.ProbeRetired}, {11, model.ProbeNeverVisible}, {11, model.ProbeNeverVisible}} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("/assets/%d", tc.id), nil))
		if baseline == "" {
			baseline = w.Body.String()
		}
		if w.Code != 404 || w.Body.String() != baseline {
			t.Fatal(w.Code, w.Body.String(), baseline)
		}
		var logged model.AuditLog
		if err := db.Last(&logged).Error; err != nil || logged.ResourceID == nil || *logged.ResourceID != tc.id || logged.AssetID == nil || *logged.AssetID != tc.id {
			t.Fatal("audit target", logged, err)
		}
		var event model.AgentProbeEvent
		if err := db.Last(&event).Error; err != nil || event.Class != tc.class || event.AssetRef != tc.id || event.Endpoint != "GET /assets/:id" || event.UserID != 2 || event.AgentTokenID != 3 {
			t.Fatal(event, err)
		}
	}
	kind = model.KindHuman
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/13", nil))
	var n int64
	db.Model(&model.AgentProbeEvent{}).Count(&n)
	if n != 5 || w.Code != 404 || w.Body.String() != baseline {
		t.Fatal("human", n, w.Code, w.Body.String())
	}
	db.Model(&model.AuditLog{}).Where("resource=? AND status=?", model.ResourceAsset, model.StatusFailure).Count(&n)
	if n != 5 {
		t.Fatal("audit events", n)
	}
}
