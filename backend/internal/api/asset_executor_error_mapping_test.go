package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 堡壘機專用帳號的哨兵到 HTTP 狀態與機器碼的對照：每個新哨兵在其出口各對一次。

func runErrorOutlet(t *testing.T, outlet func(c *gin.Context, err error), err error) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/assets/1/executor", nil)
	outlet(c, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	return rec.Code, body
}

func TestAssetExecutorErrorMapping(t *testing.T) {
	executor := func(c *gin.Context, err error) { respondExecutorError(c, apierror.CodeInternalAssetExecutorWrite, err) }
	account := func(c *gin.Context, err error) { respondAccountError(c, apierror.CodeInternalAssetAccountUpdate, err) }
	credential := func(c *gin.Context, err error) { respondCredentialError(c, apierror.CodeInternalCredentialUpdate, err) }

	cases := []struct {
		name   string
		outlet func(c *gin.Context, err error)
		err    error
		status int
		code   apierror.ErrCode
	}{
		{"executor/source_invalid", executor, asset.ErrExecutorSourceInvalid, http.StatusBadRequest, apierror.CodeExecutorSourceInvalid},
		{"executor/protocol_unsupported", executor, asset.ErrExecutorProtocolUnsupported, http.StatusUnprocessableEntity, apierror.CodeExecutorProtocolUnsupported},
		{"executor/secret_type_unsupported", executor, asset.ErrExecutorSecretTypeUnsupported, http.StatusUnprocessableEntity, apierror.CodeExecutorSecretTypeUnsupported},
		{"executor/shared_host_count", executor, &asset.ExecutorSharedHostCountError{Count: 7}, http.StatusConflict, apierror.CodeExecutorSharedHostCount},
		{"executor/state_changed", executor, asset.ErrExecutorStateChanged, http.StatusConflict, apierror.CodeExecutorStateChanged},
		{"executor/convert_candidate_pending", executor, asset.ErrExecutorConvertCandidatePending, http.StatusConflict, apierror.CodeExecutorConvertCandidatePending},
		{"executor/not_found", executor, asset.ErrAssetExecutorNotFound, http.StatusNotFound, apierror.CodeAssetExecutorNotFound},
		{"executor/public_key_not_found", executor, asset.ErrAssetExecutorPublicKeyNotFound, http.StatusNotFound, apierror.CodeAssetExecutorPublicKeyNotFound},
		{"executor/purpose_mismatch", executor, asset.ErrCredentialPurposeMismatch, http.StatusConflict, apierror.CodeCredentialPurposeMismatch},
		{"executor/internal_write", executor, errors.New("db down"), http.StatusInternalServerError, apierror.CodeInternalAssetExecutorWrite},
		{"executor/internal_read", func(c *gin.Context, err error) {
			respondExecutorError(c, apierror.CodeInternalAssetExecutorRead, err)
		}, errors.New("db down"), http.StatusInternalServerError, apierror.CodeInternalAssetExecutorRead},
		{"account/executor_managed", account, asset.ErrAssetAccountExecutorManaged, http.StatusConflict, apierror.CodeAccountExecutorManaged},
		{"account/purpose_mismatch", account, asset.ErrCredentialPurposeMismatch, http.StatusConflict, apierror.CodeCredentialPurposeMismatch},
		{"credential/executor_managed", credential, asset.ErrAssetAccountExecutorManaged, http.StatusConflict, apierror.CodeAccountExecutorManaged},
		{"credential/purpose_mismatch", credential, asset.ErrCredentialPurposeMismatch, http.StatusConflict, apierror.CodeCredentialPurposeMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := fmt.Errorf("context: %w", tc.err)
			status, body := runErrorOutlet(t, tc.outlet, wrapped)
			assert.Equal(t, tc.status, status)
			assert.Equal(t, string(tc.code), body["code"])
		})
	}

	t.Run("executor/shared_host_count_params", func(t *testing.T) {
		_, body := runErrorOutlet(t, executor, &asset.ExecutorSharedHostCountError{Count: 7})
		assert.Equal(t, map[string]any{"count": float64(7)}, body["params"], "參數只有台數")
	})
}
