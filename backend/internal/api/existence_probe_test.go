package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestExistenceProbeRequestResponses(t *testing.T) {
	request := func(h *AccessRequestHandler, method, path, body string, user uint, role string) *httptest.ResponseRecorder {
		r := gin.New()
		r.Use(func(c *gin.Context) { c.Set("userID", user); c.Set("username", "requester"); c.Set("role", role) })
		r.POST("/access-requests", h.Create)
		r.GET("/access-requests/:id/reports", h.ReportVersions)
		r.POST("/access-requests/:id/reports", h.SubmitReport)
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		q.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		return w
	}
	pair := func(t *testing.T, missing, denied *httptest.ResponseRecorder) {
		t.Helper()
		require.Equal(t, 404, missing.Code, missing.Body.String())
		require.Equal(t, missing.Code, denied.Code, "paired status: %s", denied.Body.String())
		require.JSONEq(t, `{"code":"NOTFOUND_ACCESS_REQUEST","error":"申請單不存在"}`, missing.Body.String())
		require.Equal(t, missing.Body.String(), denied.Body.String(), "paired complete body")
		require.Equal(t, missing.Result().Header, denied.Result().Header, "paired complete headers")
	}
	t.Run("executor", func(t *testing.T) {
		db, _, owner, agent := principalAPIEnv(t)
		require.NoError(t, db.AutoMigrate(&model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.AccessRequestApproval{}, &model.AgentVisibilityExposure{}, &model.SecurityPolicy{}, &model.NotificationChannel{}))
		previousDB := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = previousDB })
		requester := model.User{ID: 3, Username: "requester", Kind: model.KindHuman, Active: true}
		inactive := model.User{ID: 4, Username: "inactive", Kind: model.KindAgent, OwnerUserID: &owner.ID, Active: true}
		unshared := model.User{ID: 5, Username: "unshared", Kind: model.KindAgent, OwnerUserID: &owner.ID, Active: true}
		for _, u := range []*model.User{&requester, &inactive, &unshared} {
			require.NoError(t, db.Create(u).Error)
		}
		require.NoError(t, db.Model(&inactive).Update("active", false).Error)
		approval := model.AccessPolicyApproval
		for id := uint(1); id <= 3; id++ {
			require.NoError(t, db.Create(&model.Asset{ID: id, Name: fmt.Sprintf("asset-%d", id), Protocol: "ssh", Host: "fixture", Port: 22, CreatedBy: owner.ID, AccessPolicy: &approval}).Error)
		}
		for _, grant := range []struct{ user, asset uint }{{requester.ID, 1}, {requester.ID, 2}, {agent.ID, 1}} {
			u, a := grant.user, grant.asset
			require.NoError(t, db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &a, Permission: model.PermissionView, GrantedBy: owner.ID}).Error)
		}
		policies := policy.NewSecurityPolicyService(db)
		svc := authz.NewAccessRequestService(db, policies, policy.NewAccessPolicyService(db, policies, authz.NewAssetAuthorizationService(db)), nil, nil)
		svc.SetAccountPresenceSource(func(_ *gorm.DB, _ uint, name string) (bool, error) { return name == "app", nil })
		h := NewAccessRequestHandler(svc, nil, db)
		body := func(asset uint, executor any) string {
			b, err := json.Marshal(map[string]any{"asset_id": asset, "executor_user_id": executor, "accounts": []string{"app"}, "reason": "maintenance", "duration_minutes": 30})
			require.NoError(t, err)
			return string(b)
		}
		missing := request(h, "POST", "/access-requests", body(99999, agent.ID), requester.ID, model.RoleUser)
		for _, asset := range []uint{1, 3} {
			for _, candidate := range []uint{99999, inactive.ID, requester.ID, unshared.ID} {
				t.Run(fmt.Sprintf("asset=%d/candidate=%d", asset, candidate), func(t *testing.T) {
					pair(t, missing, request(h, "POST", "/access-requests", body(asset, candidate), requester.ID, model.RoleUser))
				})
			}
		}
		pair(t, missing, request(h, "POST", "/access-requests", body(3, agent.ID), requester.ID, model.RoleUser))
		for _, items := range []string{`[{"asset_id":1,"accounts":["absent"]},{"asset_id":2,"accounts":["app"]}]`, `[{"asset_id":2,"accounts":["app"]},{"asset_id":1,"accounts":["absent"]}]`} {
			t.Run("item_order", func(t *testing.T) {
				for _, candidate := range []uint{agent.ID, 99999} {
					b := fmt.Sprintf(`{"items":%s,"executor_user_id":%d,"reason":"maintenance","duration_minutes":30}`, items, candidate)
					pair(t, missing, request(h, "POST", "/access-requests", b, requester.ID, model.RoleUser))
				}
			})
		}
		for _, candidate := range []any{0, -1, "2", 1.5} {
			t.Run(fmt.Sprintf("shape_%v", candidate), func(t *testing.T) {
				for _, asset := range []uint{1, 99999} {
					w := request(h, "POST", "/access-requests", body(asset, candidate), requester.ID, model.RoleUser)
					require.Equal(t, 400, w.Code, w.Body.String())
					code := "VALIDATION_ACCESS_REQUEST_FIELDS"
					if candidate == 0 {
						code = "VALIDATION_BAD_PARAMS"
					}
					require.Contains(t, w.Body.String(), code)
				}
			})
		}
		for _, items := range []string{`[]`, `[{"asset_id":1},{"asset_id":1}]`, `[{"asset_id":0}]`} {
			w := request(h, "POST", "/access-requests", fmt.Sprintf(`{"items":%s,"executor_user_id":99999,"reason":"maintenance","duration_minutes":30}`, items), requester.ID, model.RoleUser)
			require.Equal(t, 400, w.Code, w.Body.String())
		}
		for _, table := range []any{&model.AccessRequest{}, &model.AccessRequestItem{}} {
			var n int64
			require.NoError(t, db.Model(table).Count(&n).Error)
			require.Zero(t, n, "rejected requests must not write partial requests/items")
		}
		var tickets int64
		require.NoError(t, db.Model(&model.AssetAuthorization{}).Where("source=?", model.AuthorizationSourceTicket).Count(&tickets).Error)
		require.Zero(t, tickets)
		require.NoError(t, db.Callback().Query().Before("gorm:query").Register("existence_executor_error", func(tx *gorm.DB) {
			if tx.Statement.Table == "users" {
				tx.AddError(errors.New("executor query unavailable"))
			}
		}))
		w := request(h, "POST", "/access-requests", body(1, agent.ID), requester.ID, model.RoleUser)
		require.Equal(t, 500, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), "INTERNAL_ACCESS_REQUEST_CREATE")
		require.NoError(t, db.Callback().Query().Remove("existence_executor_error"))
		// The requester is deliberately not the agent's owner.
		require.NotEqual(t, requester.ID, *agent.OwnerUserID)
		w = request(h, "POST", "/access-requests", body(1, agent.ID), requester.ID, model.RoleUser)
		require.Equal(t, 201, w.Code, w.Body.String())
		var created map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
		require.Equal(t, float64(agent.ID), created["executor_user_id"])
		for _, actor := range []uint{requester.ID, agent.ID} {
			for _, executorField := range []string{"", `,"executor_user_id":null`} {
				w = request(h, "POST", "/access-requests", `{"asset_id":1,"accounts":["app"],"reason":"self","duration_minutes":30`+executorField+`}`, actor, model.RoleUser)
				require.Equal(t, 201, w.Code, w.Body.String())
			}
		}
	})

	t.Run("reports", func(t *testing.T) {
		db, reports, _, _ := reportFixture(t)
		h := NewAccessRequestHandler(nil, nil, db)
		h.SetAgentTaskReports(reports)
		for _, u := range []model.User{{ID: 4, Username: "requester", Kind: model.KindHuman}, {ID: 5, Username: "admin", Kind: model.KindHuman}, {ID: 6, Username: "auditor", Kind: model.KindHuman}} {
			require.NoError(t, db.Create(&u).Error)
		}
		require.NoError(t, db.Model(&model.AccessRequest{}).Where("id=1").Update("requester_id", 4).Error)
		missing := request(h, "GET", "/access-requests/99999/reports", "", 3, model.RoleUser)
		for _, versioned := range []bool{false, true} {
			t.Run(fmt.Sprintf("versions=%v", versioned), func(t *testing.T) {
				pair(t, missing, request(h, "GET", "/access-requests/1/reports", "", 3, model.RoleUser))
			})
			for _, actor := range []struct {
				id   uint
				role string
			}{{1, model.RoleUser}, {2, model.RoleUser}, {4, model.RoleUser}, {5, model.RoleAdmin}, {6, model.RoleAuditor}} {
				w := request(h, "GET", "/access-requests/1/reports", "", actor.id, actor.role)
				require.Equal(t, 200, w.Code, w.Body.String())
				var value struct {
					Versions []json.RawMessage `json:"versions"`
				}
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &value))
				if versioned {
					require.Len(t, value.Versions, 2)
				} else {
					require.Empty(t, value.Versions)
				}
			}
			if !versioned {
				w := request(h, "POST", "/access-requests/1/reports", `{"body":"first"}`, 2, model.RoleUser)
				require.Equal(t, 201, w.Code, w.Body.String())
				require.NoError(t, db.Model(&model.AccessRequest{}).Where("id=1").Update("closed_at", time.Now().Add(-time.Hour)).Error)
				w = request(h, "POST", "/access-requests/1/reports", `{"body":"second"}`, 2, model.RoleUser)
				require.Equal(t, 201, w.Code, w.Body.String())
			}
		}
		for _, actor := range []struct {
			id   uint
			role string
		}{{1, model.RoleUser}, {3, model.RoleUser}, {4, model.RoleUser}, {5, model.RoleAdmin}, {6, model.RoleAuditor}} {
			w := request(h, "POST", "/access-requests/1/reports", `{"body":"not mine"}`, actor.id, actor.role)
			require.Equal(t, 403, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), "AUTH_AGENT_FORBIDDEN_ROUTE")
		}
		w := request(h, "POST", "/access-requests/1/reports", `{"body":""}`, 2, model.RoleUser)
		require.Equal(t, 400, w.Code, w.Body.String())
		require.NoError(t, db.Model(&model.AccessRequest{}).Where("id=1").Update("closed_at", time.Now().Add(-25*time.Hour)).Error)
		w = request(h, "POST", "/access-requests/1/reports", `{"body":"late"}`, 2, model.RoleUser)
		require.Equal(t, 409, w.Code, w.Body.String())
		var n int64
		require.NoError(t, db.Model(&model.AgentTaskReport{}).Count(&n).Error)
		require.EqualValues(t, 2, n)
		require.NoError(t, db.Callback().Query().Before("gorm:query").Register("existence_report_error", func(tx *gorm.DB) {
			if tx.Statement.Table == "agent_task_reports" {
				tx.AddError(errors.New("report query unavailable"))
			}
		}))
		defer db.Callback().Query().Remove("existence_report_error")
		w = request(h, "GET", "/access-requests/1/reports", "", 2, model.RoleUser)
		require.Equal(t, 500, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), "INTERNAL_ACCESS_REQUEST_MINE_QUERY")
	})
}
