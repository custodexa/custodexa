package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// 跨會話搜尋的結果事實篩選。
//
// 兩件事各自要釘：**參數確實抵達 filter**（少接一個等於該條件靜默不生效，
// 回傳的是超集而稽核以為已篩），以及**值域外的狀態被擋在 400**
// （照樣查詢會回空集，那與「範圍內真的沒有」看起來一模一樣）。

// searchWithQuery 跑一次 Search 並回傳服務收到的 filter；服務未被呼叫時回 nil
func searchWithQuery(t *testing.T, query string) (*audit.SessionCommandFilter, int) {
	t.Helper()
	var got *audit.SessionCommandFilter
	mockService := new(MockSessionCommandService)
	mockService.On("Search", mock.MatchedBy(func(f *audit.SessionCommandFilter) bool {
		got = f
		return true
	})).Return(&audit.SessionCommandListResponse{Page: 1, PageSize: 20}, nil).Maybe()

	handler := NewSessionCommandHandler(mockService)
	router := setupTestRouter()
	router.GET("/commands", handler.Search)

	req := httptest.NewRequest("GET", "/commands"+query, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return got, w.Code
}

// TestSearchResultFactFiltersReachService 四參數各自與組合
func TestSearchResultFactFiltersReachService(t *testing.T) {
	cases := []struct {
		name  string
		query string
		check func(t *testing.T, f *audit.SessionCommandFilter)
	}{
		{"未帶任何結果條件", "?keyword=rm", func(t *testing.T, f *audit.SessionCommandFilter) {
			assert.Equal(t, "", f.Source)
			assert.Empty(t, f.ResultStatuses)
			assert.Equal(t, "", f.TargetDatabase)
			assert.Equal(t, "", f.ErrorCode)
		}},
		{"source=console", "?source=console", func(t *testing.T, f *audit.SessionCommandFilter) {
			assert.Equal(t, audit.SourceConsole, f.Source)
		}},
		{"source=cli", "?source=cli", func(t *testing.T, f *audit.SessionCommandFilter) {
			assert.Equal(t, audit.SourceCLI, f.Source)
		}},
		{"target_database", "?target_database=payments", func(t *testing.T, f *audit.SessionCommandFilter) {
			assert.Equal(t, "payments", f.TargetDatabase)
		}},
		{"result_status 單值", "?result_status=partial", func(t *testing.T, f *audit.SessionCommandFilter) {
			assert.Equal(t, []string{model.ResultStatusPartial}, f.ResultStatuses)
		}},
		{"result_status 可重複帶（聯集）",
			"?result_status=partial&result_status=effect_unknown",
			func(t *testing.T, f *audit.SessionCommandFilter) {
				assert.Equal(t, []string{model.ResultStatusPartial, model.ResultStatusEffectUnknown},
					f.ResultStatuses)
			}},
		{"error_code", "?error_code=42601", func(t *testing.T, f *audit.SessionCommandFilter) {
			assert.Equal(t, "42601", f.ErrorCode)
		}},
		{"四者組合",
			"?source=console&target_database=app&result_status=blocked&error_code=1064",
			func(t *testing.T, f *audit.SessionCommandFilter) {
				assert.Equal(t, audit.SourceConsole, f.Source)
				assert.Equal(t, "app", f.TargetDatabase)
				assert.Equal(t, []string{model.ResultStatusBlocked}, f.ResultStatuses)
				assert.Equal(t, "1064", f.ErrorCode)
			}},
		{"與既有條件並存不互相覆寫",
			"?keyword=drop&user_id=7&degraded=true&source=console",
			func(t *testing.T, f *audit.SessionCommandFilter) {
				assert.Equal(t, "drop", f.Keyword)
				assert.NotNil(t, f.UserID)
				assert.NotNil(t, f.Degraded)
				assert.Equal(t, audit.SourceConsole, f.Source)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, code := searchWithQuery(t, tc.query)
			assert.Equal(t, http.StatusOK, code)
			if assert.NotNil(t, got, "服務未被呼叫") {
				tc.check(t, got)
			}
		})
	}
}

// TestSearchRejectsOutOfDomainValues 值域外的狀態與來源一律 400，
// **且查詢不得送到服務**——送過去會回空集，而空集看起來就像「沒有這種列」
func TestSearchRejectsOutOfDomainValues(t *testing.T) {
	cases := []string{
		"?result_status=succeeded",
		"?result_status=ok&result_status=succeeded",
		// 空字串是「非主控台列」的標記，不是一個狀態值
		"?result_status=",
		"?source=CONSOLE",
		"?source=terminal",
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			got, code := searchWithQuery(t, query)
			assert.Equal(t, http.StatusBadRequest, code)
			assert.Nil(t, got, "被拒的查詢不得抵達服務")
		})
	}
}

// TestSearchRejectionUsesMachineCode 拒絕走機器碼（前端據碼查譯，不吃散文）
func TestSearchRejectionUsesMachineCode(t *testing.T) {
	mockService := new(MockSessionCommandService)
	handler := NewSessionCommandHandler(mockService)
	router := setupTestRouter()
	router.GET("/commands", handler.Search)

	req := httptest.NewRequest("GET", "/commands?result_status=succeeded", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), string(apierror.CodeBadParams))
}

// TestSearchFilterKeepsAuditViewGate 新參數不改變守門：
// 跨會話搜尋仍掛 audit:view，未認證仍 401
func TestSearchFilterKeepsAuditViewGate(t *testing.T) {
	r, mgr := setupSessionGateEnv(t)
	const path = "/api/v1/commands?source=console&result_status=partial"

	userToken, err := mgr.GenerateToken(2, "normaluser", "u@example.com", "user", crypto.AuthContext{})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, getWithToken(t, r, path, userToken).Code,
		"user 對跨會話搜尋應 403")

	for _, role := range []string{"auditor", "admin"} {
		token, err := mgr.GenerateToken(1, role, role+"@example.com", role, crypto.AuthContext{})
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, getWithToken(t, r, path, token).Code,
			"%s 對跨會話搜尋應 200", role)
	}

	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "無 token 應 401")
}
