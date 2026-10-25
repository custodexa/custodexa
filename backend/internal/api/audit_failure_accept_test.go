package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/stretchr/testify/require"
)

type fakeAcceptor struct {
	calls  int
	reason string
	actor  uint
	err    error
}

func (f *fakeAcceptor) Accept(_ context.Context, who audit.PermissionAcceptActor, reason string) (*audit.PermissionAcceptResult, error) {
	f.calls++
	f.reason, f.actor = reason, who.Actor.UserID
	if f.err != nil {
		return nil, f.err
	}
	return &audit.PermissionAcceptResult{OpID: "op", EventSeq: 9, ExtraCount: 1}, nil
}

// 確認端點是超管保留能力（admin only）；其他角色與未登入被擋、不觸及服務；
// 失敗形狀固定。經完整 RegisterRoutes（真 AuthMiddleware＋真 JWT）。
func TestPermissionStateAcceptRoute(t *testing.T) {
	r, mgr, _, _ := setupCheckpointAPIEnv(t)
	fake := &fakeAcceptor{}
	h := NewAuditFailureHandler(nil)
	h.SetPermissionAccept(fake)
	h.RegisterRoutes(r.Group("/api/v1"), identity.NewAuthService("checkpoint-api-secret", time.Minute))
	const path = "/api/v1/audit-failures/permission-state/accept"
	body := `{"reason":"已查明"}`
	code := func(w interface{ Bytes() []byte }) string {
		var b map[string]any
		_ = json.Unmarshal(w.Bytes(), &b)
		s, _ := b["code"].(string)
		return s
	}

	t.Run("非超管被拒（稽核員、一般使用者、未登入），服務不被呼叫", func(t *testing.T) {
		for name, tok := range map[string]string{
			"auditor": tokenFor(t, mgr, 3, "auditor1", model.RoleAuditor),
			"user":    tokenFor(t, mgr, 2, "normaluser", model.RoleUser),
		} {
			w := cpReq(t, r, http.MethodPost, path, tok, body)
			require.Equal(t, http.StatusForbidden, w.Code, name)
			require.Equal(t, "AUTH_PERMISSION_DENIED", code(w.Body), name)
			require.NotContains(t, w.Body.String(), "params", name)
			require.NotContains(t, w.Body.String(), "admin", name)
		}
		w := cpReq(t, r, http.MethodPost, path, "", body)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Zero(t, fake.calls)
	})

	admin := tokenFor(t, mgr, 1, "admin", model.RoleAdmin)
	t.Run("超管成功：原因與確認人傳到服務", func(t *testing.T) {
		w := cpReq(t, r, http.MethodPost, path, admin, body)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Equal(t, 1, fake.calls)
		require.Equal(t, "已查明", fake.reason)
		require.EqualValues(t, 1, fake.actor)
	})
	t.Run("錯誤形狀固定", func(t *testing.T) {
		require.Equal(t, http.StatusBadRequest, cpReq(t, r, http.MethodPost, path, admin, `not json`).Code)
		fake.err = audit.ErrPermissionAcceptReason
		w := cpReq(t, r, http.MethodPost, path, admin, `{"reason":""}`)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, "VALIDATION_PERMISSION_STATE_ACCEPT_REASON", code(w.Body))
		fake.err = &audit.PermissionNotAcceptableError{State: "match"}
		w = cpReq(t, r, http.MethodPost, path, admin, body)
		require.Equal(t, http.StatusConflict, w.Code)
		require.Equal(t, "CONFLICT_PERMISSION_STATE_NOT_ACCEPTABLE", code(w.Body))
		require.NotContains(t, w.Body.String(), "match", "不洩漏對帳狀態細節")
		fake.err = context.DeadlineExceeded
		w = cpReq(t, r, http.MethodPost, path, admin, body)
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Equal(t, "INTERNAL_PERMISSION_STATE_ACCEPT", code(w.Body))
	})
}
