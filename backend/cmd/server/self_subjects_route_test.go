package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// GET /api/v1/authorizations/self-subjects：本人範圍唯讀端點，
// 資料與授權規則守衛同一函式（authz.SelfSubjectsOf）。
//
// 突變自檢：把 SelfSubjectsOf 的群組或 agent 查詢拿掉，「只含本人資料」格轉紅。

func selfSubjectsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}); err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.UserGroupMember{}); err != nil {
		t.Fatal(err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	// user 1 一般使用者、user 2 授權規則管理者、user 3 超管；
	// group 1：1、2 為成員；group 2：3 為成員；agent 4 owner=2、agent 5 owner=1（停用）、agent 6 owner=3
	for _, u := range []model.User{
		{Username: "plain", Active: true, Kind: model.KindHuman},
		{Username: "authz-admin", Active: true, Kind: model.KindHuman},
		{Username: "root", Active: true, Kind: model.KindHuman},
	} {
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
	}
	one, two, three := uint(1), uint(2), uint(3)
	for _, a := range []model.User{
		{Username: "bot-a", Active: true, Kind: model.KindAgent, OwnerUserID: &two},
		{Username: "bot-b", Active: false, Kind: model.KindAgent, OwnerUserID: &one},
		{Username: "bot-c", Active: true, Kind: model.KindAgent, OwnerUserID: &three},
	} {
		if err := db.Create(&a).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range []string{"g1", "g2"} {
		if err := db.Create(&model.UserGroup{Name: g}).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []model.UserGroupMember{{UserGroupID: 1, UserID: 1, Manual: true}, {UserGroupID: 1, UserID: 2, Manual: false}, {UserGroupID: 2, UserID: 3, Manual: true}} {
		if err := db.Create(&m).Error; err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func selfSubjectsCall(t *testing.T, h *api.AuthorizationHandler, userID uint, p *authz.Principal) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		middleware.SetPrincipal(c, p)
	})
	r.GET("/api/v1/authorizations/self-subjects", middleware.EnforceRegistry(), h.SelfSubjects)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/authorizations/self-subjects", nil))
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

func uintList(v any) []uint {
	out := []uint{}
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			if f, ok := x.(float64); ok {
				out = append(out, uint(f))
			}
		}
	}
	return out
}

func TestSelfSubjectsRoute(t *testing.T) {
	t.Run("路由在登錄表與路由清冊都有、類別為 self；agent 由路由允許清單拒絕", func(t *testing.T) {
		e, ok := authz.LookupRoute("GET", "/api/v1/authorizations/self-subjects")
		if !ok || e.Base != authz.BaseSelf {
			t.Fatalf("登錄應為 self: %+v ok=%v", e, ok)
		}
		routes, _ := buildRouter(t, gin.ReleaseMode, true)
		if _, ok := routes[[2]string{"GET", "/api/v1/authorizations/self-subjects"}]; !ok {
			t.Fatal("實際 router 未註冊 GET /api/v1/authorizations/self-subjects")
		}
		if allowed, registered := middleware.AgentRouteDecision("GET", "/api/v1/authorizations/self-subjects"); allowed || !registered {
			t.Fatalf("agent 應被既有路由拒絕: allowed=%v registered=%v", allowed, registered)
		}
	})

	t.Run("一般使用者、授權規則管理者、超管各一案：只含本人資料，超管 applies=false", func(t *testing.T) {
		selfSubjectsDB(t)
		h := api.NewAuthorizationHandler(nil, nil)
		h.SetSelfSubjectsReader(authz.SelfGrantGuard{})
		cases := []struct {
			name    string
			userID  uint
			p       *authz.Principal
			applies bool
			groups  []uint
			agents  []uint
		}{
			{"一般使用者", 1, principalWith(model.BuiltinUser, model.RoleUser), true, []uint{1}, []uint{5}},
			{"授權規則管理者", 2, customRolePrincipal("authz-admin", authz.PermAuthorizationManage), true, []uint{1}, []uint{4}},
			{"超管", 3, principalWith(model.BuiltinSuperAdmin, model.RoleAdmin), false, []uint{2}, []uint{6}},
		}
		for _, c := range cases {
			st, body := selfSubjectsCall(t, h, c.userID, c.p)
			if st != http.StatusOK {
				t.Fatalf("%s：status=%d body=%v", c.name, st, body)
			}
			if body["applies"] != c.applies || uint(body["user_id"].(float64)) != c.userID {
				t.Errorf("%s：applies/user_id 不符: %v", c.name, body)
			}
			if got := uintList(body["user_group_ids"]); !equalUints(got, c.groups) {
				t.Errorf("%s：user_group_ids=%v want %v", c.name, got, c.groups)
			}
			if got := uintList(body["agent_ids"]); !equalUints(got, c.agents) {
				t.Errorf("%s：agent_ids=%v want %v", c.name, got, c.agents)
			}
			if len(body) != 4 {
				t.Errorf("%s：回應只含 applies／user_id／user_group_ids／agent_ids: %v", c.name, body)
			}
		}
	})

	t.Run("未注入讀取面時 fail-close", func(t *testing.T) {
		selfSubjectsDB(t)
		h := api.NewAuthorizationHandler(nil, nil)
		st, _ := selfSubjectsCall(t, h, 1, principalWith(model.BuiltinUser, model.RoleUser))
		if st != http.StatusInternalServerError {
			t.Fatalf("status=%d", st)
		}
	})

	t.Run("既有授權列表與使用者列表回應形狀不變", func(t *testing.T) {
		// 本段不改 serializeAuthorization 與使用者列表：以登錄項釘住兩條既有路由仍走原權限點，
		// 回應形狀由各自既有測試守（authorization_handler_test、user_handler_test）
		list, _ := authz.LookupRoute("GET", "/api/v1/authorizations")
		users, _ := authz.LookupRoute("GET", "/api/v1/users")
		if list.Perm != authz.PermAuthorizationManage || users.Base != authz.BasePerm {
			t.Fatalf("既有列表路由登錄不得被本段改動: list=%+v users=%+v", list, users)
		}
	})
}

func equalUints(a, b []uint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
