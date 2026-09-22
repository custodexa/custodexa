package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"net/http/httptest"
	"testing"
)

func principalAPIEnv(t *testing.T) (*gorm.DB, *UserHandler, *model.User, *model.User) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}, &model.AuditLog{}, &model.OIDCProvider{}, &model.UserExternalIdentity{}, &model.ApproverScope{}); err != nil {
		t.Fatal(err)
	}
	owner := &model.User{Username: "human", Password: "!", Kind: model.KindHuman, Active: true}
	if err := db.Create(owner).Error; err != nil {
		t.Fatal(err)
	}
	agent := &model.User{Username: "agent", Password: "!", Kind: model.KindAgent, OwnerUserID: &owner.ID, Active: true}
	if err := db.Create(agent).Error; err != nil {
		t.Fatal(err)
	}
	return db, NewUserHandler(identity.NewUserService(db, nil)), owner, agent
}
func TestUserListExcludesAgentsByDefault(t *testing.T) {
	_, h, _, _ := principalAPIEnv(t)
	router := gin.New()
	router.GET("/users", h.List)
	for _, tc := range []struct {
		query string
		count int
	}{{"", 1}, {"?include_agents=true", 2}} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/users"+tc.query, nil))
		var res identity.UserListResponse
		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if res.Total != int64(tc.count) || len(res.Data) != tc.count {
			t.Fatalf("list=%s", w.Body)
		}
	}
}
func TestApproverCandidatesExcludeAgents(t *testing.T) {
	// Both UI candidate consumers use GET /users without include_agents.
	for _, consumer := range []string{"approver selection", "group members"} {
		t.Run(consumer, func(t *testing.T) {
			service := &MockUserService{}
			service.On("List", mock.MatchedBy(func(req *identity.ListUsersRequest) bool { return !req.IncludeAgents })).Return(&identity.UserListResponse{}, nil).Once()
			router := gin.New()
			router.GET("/users", NewUserHandler(service).List)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", "/users?page=1&page_size=1000", nil))
			if w.Code != 200 {
				t.Fatalf("status=%d", w.Code)
			}
			service.AssertExpectations(t)
		})
	}
}
func TestApproverScopeRejectsAgent(t *testing.T) {
	db, _, owner, agent := principalAPIEnv(t)
	role := model.Role{Name: model.RoleApprover}
	if err := db.Create(&role).Error; err != nil {
		t.Fatal(err)
	}
	// Even an illicit pre-existing approver role must not bypass the principal check.
	if err := db.Create(&model.UserRole{UserID: agent.ID, RoleID: role.ID, Source: model.RoleSourceManual}).Error; err != nil {
		t.Fatal(err)
	}
	h := NewAccessRequestHandler(nil, authz.NewApproverScopeService(db), nil)
	router := gin.New()
	router.POST("/approver-scopes", func(c *gin.Context) {
		c.Set("userID", owner.ID)
		c.Set("username", owner.Username)
		c.Set("role", model.RoleAdmin)
		h.CreateScope(c)
	})
	before := []model.ApproverScope{}
	if err := db.Find(&before).Error; err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/approver-scopes", bytes.NewBufferString(fmt.Sprintf(`{"approver_id":%d,"subject_user_id":%d}`, agent.ID, owner.ID)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	var after []model.ApproverScope
	if err := db.Find(&after).Error; err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatal("rejected scope wrote record")
	}
}
func TestPrincipalKindImmutableAPI(t *testing.T) {
	_, h, owner, agent := principalAPIEnv(t)
	router := gin.New()
	router.PUT("/users/:id", h.Update)
	for _, u := range []*model.User{owner, agent} {
		kind := model.KindAgent
		if u.Kind == model.KindAgent {
			kind = model.KindHuman
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("PUT", fmt.Sprintf("/users/%d", u.ID), bytes.NewBufferString(fmt.Sprintf(`{"kind":%q}`, kind)))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body)
		}
	}
}
func TestDeleteOwnerWithAgentsRejectedAPI(t *testing.T) {
	_, h, owner, agent := principalAPIEnv(t)
	router := gin.New()
	router.DELETE("/users/:id", h.Delete)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("DELETE", fmt.Sprintf("/users/%d", owner.ID), nil))
	var body struct {
		AgentIDs []uint `json:"agent_ids"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != 409 || len(body.AgentIDs) != 1 || body.AgentIDs[0] != agent.ID {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
}

func TestCreateAgentPrincipalAPI(t *testing.T) {
	db, h, owner, _ := principalAPIEnv(t)
	router := gin.New()
	router.POST("/users", h.Create)
	for i, password := range []string{`,"password":"Password123"`, `,"password":""`, ""} {
		body := fmt.Sprintf(`{"username":"new-agent-%d","email":"agent%d@example.test","kind":"agent","owner_user_id":%d%s}`, i, i, owner.ID, password)
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/users", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		want := 400
		if password == "" {
			want = 201
		}
		if w.Code != want {
			t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body)
		}
	}
	var count int64
	if err := db.Model(&model.User{}).Where("username LIKE ?", "new-agent-%").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("created=%d", count)
	}
}
