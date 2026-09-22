package api

import (
	"context"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/mock"
	"net/http/httptest"
	"testing"
)

type exposurePageAuthorization struct {
	*MockAssetAuthorizationService
	record func(context.Context, uint, []uint) error
}

func (s exposurePageAuthorization) RecordAgentVisibilityExposures(ctx context.Context, u uint, ids []uint) error {
	return s.record(ctx, u, ids)
}

func TestAgentVisibilityExposureReturnedPageOnly(t *testing.T) {
	db, _, _, agent := principalAPIEnv(t)
	if err := db.AutoMigrate(&model.AgentVisibilityExposure{}); err != nil {
		t.Fatal(err)
	}
	mockAuth := new(MockAssetAuthorizationService)
	mockAuth.On("GetAuthorizedAssets", mock.Anything, agent.ID, model.PermissionView).Return([]*authz.AuthorizedAssetDTO{{Asset: model.Asset{ID: 1, Name: "hidden"}}, {Asset: model.Asset{ID: 2, Name: "shown"}}, {Asset: model.Asset{ID: 3, Name: "shown"}}}, nil)
	service := authz.NewAssetAuthorizationService(db)
	h := NewAssetHandler(nil, exposurePageAuthorization{mockAuth, service.RecordAgentVisibilityExposures}, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", agent.ID)
		c.Set("role", model.RoleUser)
		c.Set("principal_kind", model.KindAgent)
	})
	r.GET("/assets", h.List)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets?search=shown&page=2&page_size=1", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rows []model.AgentVisibilityExposure
	if err := db.Find(&rows).Error; err != nil || len(rows) != 1 || rows[0].AssetID != 3 || rows[0].UserID != agent.ID {
		t.Fatal(rows, err)
	}
	// Unrecordable disclosure must not return the page.
	if err := db.Migrator().DropTable(&model.AgentVisibilityExposure{}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets", nil))
	if w.Code != 500 {
		t.Fatal(w.Code, w.Body.String())
	}
}
