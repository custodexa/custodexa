package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/asset"
)

type stubExecutorCheck struct {
	runErr   error
	stateErr error
	res      *asset.ExecutorLoginCheckResult
	st       *asset.ExecutorLoginCheckState
}

func (s *stubExecutorCheck) Run(context.Context, uint, asset.InventoryActor) (*asset.ExecutorLoginCheckResult, error) {
	return s.res, s.runErr
}
func (s *stubExecutorCheck) State(uint) (*asset.ExecutorLoginCheckState, error) {
	return s.st, s.stateErr
}

func TestExecutorLoginCheckHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	call := func(stub *stubExecutorCheck, method string) *httptest.ResponseRecorder {
		h := &ExecutorLoginCheckHandler{svc: stub}
		r := gin.New()
		r.POST("/assets/:id/executor/login-check", h.Run)
		r.GET("/assets/:id/executor/login-check", h.Get)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(method, "/assets/3/executor/login-check", nil))
		return rec
	}
	cases := []struct {
		name   string
		err    error
		status int
		code   apierror.ErrCode
	}{
		{"沒有專用帳號", asset.ErrAssetExecutorNotFound, http.StatusNotFound, apierror.CodeAssetExecutorNotFound},
		{"資產不存在同形", asset.ErrExecutorCheckAssetNotFound, http.StatusNotFound, apierror.CodeAssetExecutorNotFound},
		{"掛載已變更", asset.ErrExecutorStateChanged, http.StatusConflict, apierror.CodeExecutorStateChanged},
		{"帳號忙碌", asset.ErrExecutorCheckBusy, http.StatusConflict, apierror.CodeExecutorCheckBusy},
		{"平台不支援", asset.ErrExecutorCheckPlatformUnsupported, http.StatusUnprocessableEntity, apierror.CodeExecutorCheckPlatformUnsupported},
		{"限流", asset.ErrExecutorCheckRateLimited, http.StatusTooManyRequests, apierror.CodeExecutorCheckRateLimited},
		{"內部錯誤", asset.ErrExecutorCheckInternal, http.StatusInternalServerError, apierror.CodeInternalExecutorCheck},
		{"未預期錯誤一律內部錯誤", errors.New("boom"), http.StatusInternalServerError, apierror.CodeInternalExecutorCheck},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := call(&stubExecutorCheck{runErr: c.err}, http.MethodPost)
			assert.Equal(t, c.status, rec.Code)
			assert.Contains(t, rec.Body.String(), string(c.code))
			assert.Empty(t, rec.Header().Get("Retry-After"))
			assert.NotContains(t, rec.Body.String(), "boom", "不回內部錯誤文字")
			if c.status == http.StatusTooManyRequests {
				assert.False(t, strings.ContainsAny(rec.Body.String(), "0123456789"), "429 回應不含數字參數: %s", rec.Body.String())
			}
		})
	}
	t.Run("GET 同一套對照", func(t *testing.T) {
		rec := call(&stubExecutorCheck{stateErr: asset.ErrAssetExecutorNotFound}, http.MethodGet)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
	t.Run("成功回 200 與結果", func(t *testing.T) {
		rec := call(&stubExecutorCheck{res: &asset.ExecutorLoginCheckResult{Success: true, Method: "executor_root"}}, http.MethodPost)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"success":true`)
	})
}
