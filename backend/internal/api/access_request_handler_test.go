package api

import (
	"bytes"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/authz"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAccessRequestService - AccessRequestServiceInterface 的 mock
type MockAccessRequestService struct {
	mock.Mock
}

func (m *MockAccessRequestService) Submit(requesterID uint, username, role string, input authz.SubmitAccessRequestInput) (*model.AccessRequest, error) {
	args := m.Called(requesterID, username, role, input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessRequest), args.Error(1)
}

func (m *MockAccessRequestService) Cancel(requesterID uint, requestID uint) (*model.AccessRequest, error) {
	args := m.Called(requesterID, requestID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessRequest), args.Error(1)
}

func (m *MockAccessRequestService) Approve(actorID uint, isAdmin bool, requestID uint, input authz.DecideInput) (*model.AccessRequest, error) {
	args := m.Called(actorID, isAdmin, requestID, input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessRequest), args.Error(1)
}

func (m *MockAccessRequestService) Reject(actorID uint, isAdmin bool, requestID uint, note string) (*model.AccessRequest, error) {
	args := m.Called(actorID, isAdmin, requestID, note)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessRequest), args.Error(1)
}

func (m *MockAccessRequestService) ListMine(requesterID uint) ([]*model.AccessRequest, error) {
	args := m.Called(requesterID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AccessRequest), args.Error(1)
}

func (m *MockAccessRequestService) MyActiveTickets(requesterID uint, now time.Time) ([]*model.AssetAuthorization, error) {
	args := m.Called(requesterID, mock.Anything)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AssetAuthorization), args.Error(1)
}

func (m *MockAccessRequestService) ListPending(actorID uint, isAdmin bool, now time.Time) ([]*model.AccessRequest, error) {
	args := m.Called(actorID, isAdmin, mock.Anything)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AccessRequest), args.Error(1)
}

func (m *MockAccessRequestService) ListHistory(actorID uint, isAdmin bool, page, pageSize int) ([]*model.AccessRequest, int64, error) {
	args := m.Called(actorID, isAdmin, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*model.AccessRequest), args.Get(1).(int64), args.Error(2)
}

func (m *MockAccessRequestService) ActiveTickets(actorID uint, isAdmin bool, now time.Time) ([]*model.AssetAuthorization, error) {
	args := m.Called(actorID, isAdmin, mock.Anything)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AssetAuthorization), args.Error(1)
}

func (m *MockAccessRequestService) PendingCount(actorID uint, isAdmin bool, now time.Time) (int64, error) {
	args := m.Called(actorID, isAdmin, mock.Anything)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAccessRequestService) ExpireOverdue(now time.Time) (int, error) {
	args := m.Called(mock.Anything)
	return args.Int(0), args.Error(1)
}

func (m *MockAccessRequestService) BreakGlass(requesterID uint, username, role string, assetID uint, reason string) (*model.AccessRequest, error) {
	args := m.Called(requesterID, username, role, assetID, reason)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessRequest), args.Error(1)
}

func (m *MockAccessRequestService) Revoke(actorID uint, isAdmin bool, username string, requestID uint, note string) (*model.AccessRequest, error) {
	args := m.Called(actorID, isAdmin, username, requestID, note)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessRequest), args.Error(1)
}

func (m *MockAccessRequestService) Review(actorID uint, isAdmin bool, requestID uint, disposition, note string) (*model.AccessRequest, error) {
	args := m.Called(actorID, isAdmin, requestID, disposition, note)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessRequest), args.Error(1)
}

func (m *MockAccessRequestService) ListPendingReview(actorID uint, isAdmin bool) ([]*model.AccessRequest, error) {
	args := m.Called(actorID, isAdmin)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AccessRequest), args.Error(1)
}

func (m *MockAccessRequestService) PendingReviewCount(actorID uint, isAdmin bool) (int64, error) {
	args := m.Called(actorID, isAdmin)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAccessRequestService) NotifyOverdueReviews(now time.Time) (int, error) {
	args := m.Called(mock.Anything)
	return args.Int(0), args.Error(1)
}

// MockApproverScopeService - ApproverScopeServiceInterface 的 mock
type MockApproverScopeService struct {
	mock.Mock
}

func (m *MockApproverScopeService) List() ([]*model.ApproverScope, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.ApproverScope), args.Error(1)
}

func (m *MockApproverScopeService) Create(spec authz.ApproverScopeSpec) (*model.ApproverScope, error) {
	args := m.Called(spec)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.ApproverScope), args.Error(1)
}

func (m *MockApproverScopeService) Delete(id uint) error {
	return m.Called(id).Error(0)
}

// newAccessRequestRouter 掛 handler 的測試路由；identity 以 wrapper 注入。
//
// **W7b 8.3**：`isRevokeAdmin` 只注入撤銷端點的 admin 旗標（`RevokeAdminKey`）——
// D-12 收斂後審核端點不存在 admin 兜底身分，`ApproverAdminKey` 已刪除
func newAccessRequestRouter(reqSvc *MockAccessRequestService, scopeSvc *MockApproverScopeService,
	userID uint, role string, isRevokeAdmin *bool) (*gin.Engine, *AccessRequestHandler) {
	gin.SetMode(gin.TestMode)
	h := NewAccessRequestHandler(reqSvc, scopeSvc, nil)
	r := gin.New()
	inject := func(c *gin.Context) {
		if userID != 0 {
			c.Set("userID", userID)
			c.Set("username", "tester")
			c.Set("role", role)
		}
		if isRevokeAdmin != nil {
			c.Set(middleware.RevokeAdminKey, *isRevokeAdmin)
		}
	}
	r.POST("/access-requests", func(c *gin.Context) { inject(c); h.Create(c) })
	r.GET("/access-requests/mine", func(c *gin.Context) { inject(c); h.ListMine(c) })
	r.GET("/access-requests/mine/tickets", func(c *gin.Context) { inject(c); h.MyTickets(c) })
	r.POST("/access-requests/:id/cancel", func(c *gin.Context) { inject(c); h.Cancel(c) })
	r.GET("/access-requests/pending", func(c *gin.Context) { inject(c); h.ListPending(c) })
	r.GET("/access-requests/pending/count", func(c *gin.Context) { inject(c); h.PendingCount(c) })
	r.GET("/access-requests/history", func(c *gin.Context) { inject(c); h.ListHistory(c) })
	r.GET("/access-requests/tickets", func(c *gin.Context) { inject(c); h.ActiveTickets(c) })
	r.POST("/access-requests/:id/approve", func(c *gin.Context) { inject(c); h.Approve(c) })
	r.POST("/access-requests/:id/reject", func(c *gin.Context) { inject(c); h.Reject(c) })
	r.POST("/access-requests/break-glass", func(c *gin.Context) { inject(c); h.BreakGlass(c) })
	r.POST("/access-requests/:id/revoke", func(c *gin.Context) { inject(c); h.Revoke(c) })
	r.POST("/access-requests/:id/review", func(c *gin.Context) { inject(c); h.Review(c) })
	r.GET("/access-requests/reviews/pending", func(c *gin.Context) { inject(c); h.ListPendingReview(c) })
	r.GET("/approver-scopes", func(c *gin.Context) { inject(c); h.ListScopes(c) })
	r.POST("/approver-scopes", func(c *gin.Context) { inject(c); h.CreateScope(c) })
	r.DELETE("/approver-scopes/:id", func(c *gin.Context) { inject(c); h.DeleteScope(c) })
	return r, h
}

func doJSON(r *gin.Engine, method, path string, payload interface{}) *httptest.ResponseRecorder {
	var body *bytes.Buffer
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewBuffer(b)
	} else {
		body = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAccessRequestHandler_Create(t *testing.T) {
	t.Run("成功建單 201", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("Submit", uint(5), "tester", "user", mock.MatchedBy(func(in authz.SubmitAccessRequestInput) bool {
			return in.AssetID == 3 && in.Reason == "維護" && in.DurationMinutes == 60
		})).Return(&model.AccessRequest{ID: 9, Status: model.AccessRequestPending}, nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 5, "user", nil)

		w := doJSON(r, "POST", "/access-requests", map[string]interface{}{
			"asset_id": 3, "reason": "維護", "duration_minutes": 60,
		})
		assert.Equal(t, http.StatusCreated, w.Code)
		reqSvc.AssertExpectations(t)
	})

	t.Run("缺事由 400 不觸 service", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		r, _ := newAccessRequestRouter(reqSvc, nil, 5, "user", nil)

		w := doJSON(r, "POST", "/access-requests", map[string]interface{}{
			"asset_id": 3, "duration_minutes": 60,
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		reqSvc.AssertNotCalled(t, "Submit")
	})

	t.Run("錯誤映射：409/400/403/404", func(t *testing.T) {
		cases := []struct {
			err  error
			code int
		}{
			{authz.ErrDuplicatePendingRequest, http.StatusConflict},
			{&authz.DurationExceedsPolicyError{MaxMinutes: 1440}, http.StatusBadRequest},
			{authz.ErrPolicyOpenNoRequest, http.StatusBadRequest},
			{authz.ErrRequesterExempt, http.StatusForbidden},
			{authz.ErrAccessRequestNotFound, http.StatusNotFound},
		}
		for _, tc := range cases {
			reqSvc := new(MockAccessRequestService)
			reqSvc.On("Submit", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(nil, tc.err)
			r, _ := newAccessRequestRouter(reqSvc, nil, 5, "user", nil)

			w := doJSON(r, "POST", "/access-requests", map[string]interface{}{
				"asset_id": 3, "reason": "r", "duration_minutes": 60,
			})
			assert.Equal(t, tc.code, w.Code, "err=%v", tc.err)
		}
	})

	t.Run("未認證 401", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		r, _ := newAccessRequestRouter(reqSvc, nil, 0, "", nil)

		w := doJSON(r, "POST", "/access-requests", map[string]interface{}{
			"asset_id": 3, "reason": "r", "duration_minutes": 60,
		})
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestAccessRequestHandler_MineAndCancel(t *testing.T) {
	t.Run("mine 以 JWT 身分過濾", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("ListMine", uint(7)).Return([]*model.AccessRequest{{ID: 1}}, nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 7, "user", nil)

		// 附帶他人識別參數應被忽略（owner-scoped）
		w := doJSON(r, "GET", "/access-requests/mine?user_id=999", nil)
		assert.Equal(t, http.StatusOK, w.Code)
		reqSvc.AssertCalled(t, "ListMine", uint(7))
	})

	t.Run("mine tickets", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("MyActiveTickets", uint(7), mock.Anything).
			Return([]*model.AssetAuthorization{{ID: 2}}, nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 7, "user", nil)

		w := doJSON(r, "GET", "/access-requests/mine/tickets", nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("撤回 CAS 衝突 409", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("Cancel", uint(7), uint(3)).Return(nil, authz.ErrAccessRequestConflict)
		r, _ := newAccessRequestRouter(reqSvc, nil, 7, "user", nil)

		w := doJSON(r, "POST", "/access-requests/3/cancel", nil)
		assert.Equal(t, http.StatusConflict, w.Code)
	})
}

func TestAccessRequestHandler_Review(t *testing.T) {
	admin := true
	notAdmin := false

	t.Run("待審列表一律依審核範圍（D-12 後無 admin 兜底）", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("ListPending", uint(2), false, mock.Anything).
			Return([]*model.AccessRequest{}, nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 2, "user", &notAdmin)

		w := doJSON(r, "GET", "/access-requests/pending", nil)
		assert.Equal(t, http.StatusOK, w.Code)
		reqSvc.AssertCalled(t, "ListPending", uint(2), false, mock.Anything)
	})

	t.Run("核准帶下修值", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		short := 30
		reqSvc.On("Approve", uint(3), false, uint(9), mock.MatchedBy(func(in authz.DecideInput) bool {
			return in.DurationMinutes != nil && *in.DurationMinutes == 30 && in.Note == "縮短"
		})).Return(&model.AccessRequest{ID: 9, Status: model.AccessRequestApproved}, nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 3, "admin", &admin)

		w := doJSON(r, "POST", "/access-requests/9/approve", map[string]interface{}{
			"duration_minutes": short, "note": "縮短",
		})
		assert.Equal(t, http.StatusOK, w.Code)
		reqSvc.AssertExpectations(t)
	})

	t.Run("核准空 body 合法（照申請值）", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("Approve", uint(3), false, uint(9), mock.Anything).
			Return(&model.AccessRequest{ID: 9}, nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 3, "admin", &admin)

		w := doJSON(r, "POST", "/access-requests/9/approve", nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("自核 403", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("Approve", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil, authz.ErrSelfApproval)
		r, _ := newAccessRequestRouter(reqSvc, nil, 2, "user", &notAdmin)

		w := doJSON(r, "POST", "/access-requests/9/approve", nil)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("範圍外 403、上調 400、終態 409", func(t *testing.T) {
		cases := []struct {
			err  error
			code int
		}{
			{authz.ErrNotEligibleApprover, http.StatusForbidden},
			{authz.ErrDecisionIncrease, http.StatusBadRequest},
			{authz.ErrAccessRequestConflict, http.StatusConflict},
		}
		for _, tc := range cases {
			reqSvc := new(MockAccessRequestService)
			reqSvc.On("Approve", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(nil, tc.err)
			r, _ := newAccessRequestRouter(reqSvc, nil, 2, "user", &notAdmin)

			w := doJSON(r, "POST", "/access-requests/9/approve", nil)
			assert.Equal(t, tc.code, w.Code, "err=%v", tc.err)
		}
	})

	t.Run("拒絕缺事由 400 不觸 service", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		r, _ := newAccessRequestRouter(reqSvc, nil, 3, "admin", &admin)

		w := doJSON(r, "POST", "/access-requests/9/reject", map[string]interface{}{})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		reqSvc.AssertNotCalled(t, "Reject")
	})

	t.Run("拒絕成功", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("Reject", uint(3), false, uint(9), "不符變更窗").
			Return(&model.AccessRequest{ID: 9, Status: model.AccessRequestRejected}, nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 3, "admin", &admin)

		w := doJSON(r, "POST", "/access-requests/9/reject", map[string]interface{}{"note": "不符變更窗"})
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("badge 計數（含待補審，break-glass-revocation D7）", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("PendingCount", uint(2), false, mock.Anything).Return(int64(4), nil)
		reqSvc.On("PendingReviewCount", uint(2), false).Return(int64(1), nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 2, "user", &notAdmin)

		w := doJSON(r, "GET", "/access-requests/pending/count", nil)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"count":4`)
		assert.Contains(t, w.Body.String(), `"review_count":1`)
	})

	t.Run("歷史分頁", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("ListHistory", uint(2), false, 2, 10).
			Return([]*model.AccessRequest{}, int64(0), nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 2, "user", &notAdmin)

		w := doJSON(r, "GET", "/access-requests/history?page=2&page_size=10", nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestAccessRequestHandler_Scopes(t *testing.T) {
	t.Run("建立範圍（客體轉指標）", func(t *testing.T) {
		scopeSvc := new(MockApproverScopeService)
		scopeSvc.On("Create", mock.MatchedBy(func(spec authz.ApproverScopeSpec) bool {
			return spec.ApproverID != nil && *spec.ApproverID == 8 &&
				spec.ApproverGroupID == nil &&
				spec.AssetID != nil && *spec.AssetID == 3 &&
				spec.AssetGroupID == nil && spec.GrantedBy == 1
		})).Return(&model.ApproverScope{ID: 1}, nil)
		r, _ := newAccessRequestRouter(new(MockAccessRequestService), scopeSvc, 1, "admin", nil)

		w := doJSON(r, "POST", "/approver-scopes", map[string]interface{}{
			"approver_id": 8, "asset_id": 3,
		})
		assert.Equal(t, http.StatusCreated, w.Code)
		scopeSvc.AssertExpectations(t)
	})

	t.Run("錯誤映射：XOR 400、非 approver 400、重複 409、刪除不存在 404", func(t *testing.T) {
		scopeSvc := new(MockApproverScopeService)
		scopeSvc.On("Create", mock.Anything).Return(nil, authz.ErrScopeTargetInvalid).Once()
		scopeSvc.On("Create", mock.Anything).Return(nil, authz.ErrNotApproverRole).Once()
		scopeSvc.On("Create", mock.Anything).Return(nil, authz.ErrScopeExists).Once()
		scopeSvc.On("Delete", uint(99)).Return(authz.ErrScopeNotFound)
		r, _ := newAccessRequestRouter(new(MockAccessRequestService), scopeSvc, 1, "admin", nil)

		body := map[string]interface{}{"approver_id": 8, "asset_id": 3}
		assert.Equal(t, http.StatusBadRequest, doJSON(r, "POST", "/approver-scopes", body).Code)
		assert.Equal(t, http.StatusBadRequest, doJSON(r, "POST", "/approver-scopes", body).Code)
		assert.Equal(t, http.StatusConflict, doJSON(r, "POST", "/approver-scopes", body).Code)
		assert.Equal(t, http.StatusNotFound, doJSON(r, "DELETE", "/approver-scopes/99", nil).Code)
	})

	t.Run("範圍清單", func(t *testing.T) {
		scopeSvc := new(MockApproverScopeService)
		scopeSvc.On("List").Return([]*model.ApproverScope{{ID: 1}, {ID: 2}}, nil)
		r, _ := newAccessRequestRouter(new(MockAccessRequestService), scopeSvc, 1, "admin", nil)

		w := doJSON(r, "GET", "/approver-scopes", nil)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"total":2`)
	})
}

// TestAccessRequestHandler_BreakGlassRevocation 破窗/撤銷/補審端點（break-glass-revocation）
func TestAccessRequestHandler_BreakGlassRevocation(t *testing.T) {
	notAdmin := false

	t.Run("破窗成功 201（不收時長欄位）", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("BreakGlass", uint(5), "tester", "user", uint(1), "半夜事故").
			Return(&model.AccessRequest{ID: 20, Status: model.AccessRequestApproved,
				Kind: model.AccessRequestKindBreakGlass}, nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 5, "user", nil)

		// duration_minutes 傳入即忽略（binding 不宣告該欄）
		w := doJSON(r, "POST", "/access-requests/break-glass", map[string]interface{}{
			"asset_id": 1, "reason": "半夜事故", "duration_minutes": 1440,
		})
		assert.Equal(t, http.StatusCreated, w.Code)
		reqSvc.AssertExpectations(t)
	})

	t.Run("破窗缺事由 400 不觸 service", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		r, _ := newAccessRequestRouter(reqSvc, nil, 5, "user", nil)
		w := doJSON(r, "POST", "/access-requests/break-glass", map[string]interface{}{"asset_id": 1})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		reqSvc.AssertNotCalled(t, "BreakGlass")
	})

	t.Run("開關關閉 403 帶機器可辨 code", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("BreakGlass", uint(5), "tester", "user", uint(1), "急").
			Return(nil, authz.ErrBreakGlassDisabled)
		r, _ := newAccessRequestRouter(reqSvc, nil, 5, "user", nil)
		w := doJSON(r, "POST", "/access-requests/break-glass", map[string]interface{}{
			"asset_id": 1, "reason": "急",
		})
		assert.Equal(t, http.StatusForbidden, w.Code)
		// 機器碼收口 apierror registry（backend-i18n-unification A1）：
		// 原 legacy 小寫碼 break_glass_disabled → RULE_BREAK_GLASS_DISABLED，
		// 語義不變（開關關閉＝封 API，前端據此隱藏入口自癒）
		assert.Contains(t, w.Body.String(), `"code":"RULE_BREAK_GLASS_DISABLED"`)
	})

	t.Run("無資格 403", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("BreakGlass", uint(5), "tester", "user", uint(1), "急").
			Return(nil, authz.ErrBreakGlassNotEligible)
		r, _ := newAccessRequestRouter(reqSvc, nil, 5, "user", nil)
		w := doJSON(r, "POST", "/access-requests/break-glass", map[string]interface{}{
			"asset_id": 1, "reason": "急",
		})
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("重複破窗 409", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("BreakGlass", uint(5), "tester", "user", uint(1), "急").
			Return(nil, authz.ErrDuplicateBreakGlass)
		r, _ := newAccessRequestRouter(reqSvc, nil, 5, "user", nil)
		w := doJSON(r, "POST", "/access-requests/break-glass", map[string]interface{}{
			"asset_id": 1, "reason": "急",
		})
		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("撤銷成功＋事由必填", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("Revoke", uint(2), false, "tester", uint(7), "核錯人").
			Return(&model.AccessRequest{ID: 7, Status: model.AccessRequestApproved}, nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 2, "user", &notAdmin)

		w := doJSON(r, "POST", "/access-requests/7/revoke", map[string]interface{}{"note": "核錯人"})
		assert.Equal(t, http.StatusOK, w.Code)

		w = doJSON(r, "POST", "/access-requests/7/revoke", map[string]interface{}{})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		reqSvc.AssertNumberOfCalls(t, "Revoke", 1)
	})

	t.Run("撤銷資格不足 403、已撤/到期 409", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("Revoke", uint(2), false, "tester", uint(7), "越權").
			Return(nil, authz.ErrNotRevokeEligible)
		reqSvc.On("Revoke", uint(2), false, "tester", uint(8), "太遲").
			Return(nil, authz.ErrTicketNotActive)
		r, _ := newAccessRequestRouter(reqSvc, nil, 2, "user", &notAdmin)

		w := doJSON(r, "POST", "/access-requests/7/revoke", map[string]interface{}{"note": "越權"})
		assert.Equal(t, http.StatusForbidden, w.Code)
		w = doJSON(r, "POST", "/access-requests/8/revoke", map[string]interface{}{"note": "太遲"})
		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("補審成功與錯誤映射", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("Review", uint(2), false, uint(20), "confirmed", "正當維運").
			Return(&model.AccessRequest{ID: 20, ReviewStatus: model.BreakGlassReviewReviewed}, nil)
		reqSvc.On("Review", uint(2), false, uint(21), "maybe", "").
			Return(nil, authz.ErrInvalidReviewDisposition)
		reqSvc.On("Review", uint(2), false, uint(22), "confirmed", "").
			Return(nil, authz.ErrSelfReview)
		reqSvc.On("Review", uint(2), false, uint(23), "confirmed", "").
			Return(nil, authz.ErrAlreadyReviewed)
		r, _ := newAccessRequestRouter(reqSvc, nil, 2, "user", &notAdmin)

		w := doJSON(r, "POST", "/access-requests/20/review", map[string]interface{}{
			"disposition": "confirmed", "note": "正當維運",
		})
		assert.Equal(t, http.StatusOK, w.Code)
		w = doJSON(r, "POST", "/access-requests/21/review", map[string]interface{}{"disposition": "maybe"})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		w = doJSON(r, "POST", "/access-requests/22/review", map[string]interface{}{"disposition": "confirmed"})
		assert.Equal(t, http.StatusForbidden, w.Code)
		w = doJSON(r, "POST", "/access-requests/23/review", map[string]interface{}{"disposition": "confirmed"})
		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("待補審列表", func(t *testing.T) {
		reqSvc := new(MockAccessRequestService)
		reqSvc.On("ListPendingReview", uint(2), false).
			Return([]*model.AccessRequest{{ID: 20, Kind: model.AccessRequestKindBreakGlass}}, nil)
		r, _ := newAccessRequestRouter(reqSvc, nil, 2, "user", &notAdmin)

		w := doJSON(r, "GET", "/access-requests/reviews/pending", nil)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"total":1`)
	})
}
