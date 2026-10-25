package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
)

// guardedUsersSpy 帶操作者入口的替身：記錄每次收到的指派選項，帶範圍欄位時照服務的
// 行為回拒絕碼。範圍判定在服務關卡，替身只驗 handler 有沒有把請求原文的事實交下去。
type guardedUsersSpy struct {
	*MockUserService
	calls  int
	scoped []bool
}

func (s *guardedUsersSpy) record(opts []identity.DirectAssignOptions) error {
	s.calls++
	scoped := false
	for _, o := range opts {
		scoped = scoped || o.ScopeRequested
	}
	s.scoped = append(s.scoped, scoped)
	if scoped {
		return identity.ErrRoleBindingScopeUnsupported
	}
	return nil
}

func (s *guardedUsersSpy) CreateBy(_ identity.Operator, _ *identity.CreateUserRequest, opts ...identity.DirectAssignOptions) (*model.User, error) {
	if err := s.record(opts); err != nil {
		return nil, err
	}
	return &model.User{ID: 9, Username: "n1"}, nil
}

func (s *guardedUsersSpy) AddRoleBy(_ identity.Operator, _ uint, _ string, opts ...identity.DirectAssignOptions) error {
	return s.record(opts)
}

func (s *guardedUsersSpy) AssignRolesBy(_ identity.Operator, _ uint, _ []string, opts ...identity.DirectAssignOptions) (*identity.RoleAssignResult, error) {
	if err := s.record(opts); err != nil {
		return nil, err
	}
	return &identity.RoleAssignResult{}, nil
}

func (s *guardedUsersSpy) PinMappedRoleBy(_ identity.Operator, _ uint, _ string) (*identity.RoleSets, error) {
	s.calls++
	s.scoped = append(s.scoped, false)
	return &identity.RoleSets{}, nil
}

type scopeFieldCase struct {
	name   string
	method string
	path   string
	body   map[string]any // nil 表示不帶 body
	okCode int
	pin    bool // 釘住入口沒有帶選項的版本：handler 自己拒絕，服務不被呼叫
}

func directAssignCases(withScope bool) []scopeFieldCase {
	extra := func(m map[string]any, k string, v any) map[string]any {
		out := map[string]any{}
		for kk, vv := range m {
			out[kk] = vv
		}
		if withScope {
			out[k] = v
		}
		return out
	}
	createBody := map[string]any{"username": "newuser", "password": "Passw0rd!xyz", "email": "newuser@example.com", "roles": []string{"auditor"}}
	cases := []scopeFieldCase{
		{name: "替換", method: "PUT", path: "/users/1/roles",
			body: extra(map[string]any{"manual_roles": []string{"auditor"}}, "node_ids", []int{3}), okCode: http.StatusOK},
		{name: "替換（範圍種類）", method: "PUT", path: "/users/1/roles",
			body: extra(map[string]any{"manual_roles": []string{"auditor"}}, "Scope_Kind", "nodes"), okCode: http.StatusOK},
		{name: "建帳號帶角色", method: "POST", path: "/users",
			body: extra(createBody, "scope", map[string]any{"kind": "nodes", "node_ids": []int{}}), okCode: http.StatusCreated},
		{name: "追加", method: "POST", path: "/users/1/roles/auditor",
			body: extra(map[string]any{}, "node_ids", []int{}), okCode: http.StatusOK},
		{name: "釘住", method: "POST", path: "/users/1/roles/pin", pin: true,
			body: extra(map[string]any{"role": "auditor"}, "role_nodes", map[string]any{"auditor": []int{3}}), okCode: http.StatusOK},
	}
	if !withScope {
		// 追加端點本來就不收 body：完全不帶 body 的請求照常放行
		cases = append(cases, scopeFieldCase{name: "追加（無 body）", method: "POST", path: "/users/1/roles/auditor", okCode: http.StatusOK})
	}
	return cases
}

func serveDirectAssign(t *testing.T, svc UserServiceInterface, tc scopeFieldCase) *httptest.ResponseRecorder {
	t.Helper()
	h := newTestUserHandler(svc)
	router := setupTestRouter()
	router.POST("/users", h.Create)
	router.PUT("/users/:id/roles", h.AssignRoles)
	router.POST("/users/:id/roles/pin", h.PinRole)
	router.POST("/users/:id/roles/:role", h.AddRole)
	var buf *bytes.Buffer
	if tc.body != nil {
		raw, err := json.Marshal(tc.body)
		require.NoError(t, err)
		buf = bytes.NewBuffer(raw)
	} else {
		buf = &bytes.Buffer{}
	}
	req := httptest.NewRequest(tc.method, tc.path, buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func scopeRespCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), w.Body.String())
	code, _ := resp["code"].(string)
	return code
}

// TestDirectRoleAssignmentScopeFields 擋：直接指派三條路徑（替換、建帳號帶角色、追加）的請求帶任何範圍
// 或節點欄位時整筆拒絕，不得因 JSON 綁定忽略未知鍵而改存為全域；不帶時照常交給服務。
//
// 兩種服務都要測：帶操作者入口的服務由關卡拒絕，handler 必須把「帶了範圍欄位」交下去；
// 沒有帶操作者入口的替身，handler 自己拒絕且服務一次都不得被呼叫。
func TestDirectRoleAssignmentScopeFields(t *testing.T) {
	for _, tc := range directAssignCases(true) {
		t.Run(tc.name+"：帶範圍欄位，關卡收到事實並整筆拒絕", func(t *testing.T) {
			spy := &guardedUsersSpy{MockUserService: new(MockUserService)}
			w := serveDirectAssign(t, spy, tc)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, string(apierror.CodeValidationRoleBindingScopeUnsupported), scopeRespCode(t, w))
			if tc.pin {
				assert.Equal(t, 0, spy.calls, "釘住入口由 handler 拒絕，服務不被呼叫")
				return
			}
			require.Equal(t, 1, spy.calls)
			assert.Equal(t, []bool{true}, spy.scoped)
		})
		t.Run(tc.name+"：帶範圍欄位，無關卡入口的服務不被呼叫", func(t *testing.T) {
			m := new(MockUserService)
			// 備妥成功回應：若 handler 漏擋，請求會被當成全域寫入成功，由下方斷言抓出
			m.On("Create", mock.Anything).Return(&model.User{ID: 9}, nil).Maybe()
			m.On("AssignRoles", mock.Anything, mock.Anything).Return(&identity.RoleAssignResult{}, nil).Maybe()
			m.On("AddRole", mock.Anything, mock.Anything).Return(nil).Maybe()
			m.On("PinMappedRole", mock.Anything, mock.Anything).Return(&identity.RoleSets{}, nil).Maybe()
			w := serveDirectAssign(t, m, tc)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, string(apierror.CodeValidationRoleBindingScopeUnsupported), scopeRespCode(t, w))
			m.AssertNotCalled(t, "Create")
			m.AssertNotCalled(t, "AssignRoles")
			m.AssertNotCalled(t, "AddRole")
			m.AssertNotCalled(t, "PinMappedRole")
		})
	}
	for _, tc := range directAssignCases(false) {
		t.Run(tc.name+"：不帶範圍欄位照常寫入", func(t *testing.T) {
			spy := &guardedUsersSpy{MockUserService: new(MockUserService)}
			w := serveDirectAssign(t, spy, tc)
			assert.Equal(t, tc.okCode, w.Code, w.Body.String())
			require.Equal(t, 1, spy.calls)
			assert.Equal(t, []bool{false}, spy.scoped)
		})
	}
	// role_nodes 在替換入口有自己的語義：形狀錯誤與鍵不在 manual_roles 由 handler 整筆拒絕，服務不被呼叫
	for name, roleNodes := range map[string]any{
		"形狀錯誤（不是物件）":       "x",
		"值不是整數陣列":          map[string]any{"auditor": "y"},
		"鍵不在 manual_roles": map[string]any{"viewer": []int{3}},
	} {
		t.Run("替換：role_nodes "+name+" 回 VALIDATION_BAD_PARAMS", func(t *testing.T) {
			spy := &guardedUsersSpy{MockUserService: new(MockUserService)}
			w := serveDirectAssign(t, spy, scopeFieldCase{method: "PUT", path: "/users/1/roles",
				body: map[string]any{"manual_roles": []string{"auditor"}, "role_nodes": roleNodes}})
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, string(apierror.CodeBadParams), scopeRespCode(t, w))
			assert.Equal(t, 0, spy.calls)
		})
	}
}
