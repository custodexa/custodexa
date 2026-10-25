package main

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// soRevokeOnFirstCall 時序包裝：第一次判定時先執行撤權，再委派內層。請求已通過路由閘與讀取裁決、
// 資料已讀出，撤權正好落在讀出與投影之間。
type soRevokeOnFirstCall struct {
	inner asset.CredentialOutputScopeSource
	hook  func()
	calls int
}

func (w *soRevokeOnFirstCall) CredentialOutputScope(ctx context.Context) (asset.CredentialOutputScope, error) {
	w.calls++
	if w.calls == 1 {
		w.hook()
	}
	return w.inner.CredentialOutputScope(ctx)
}

// soRevokeAccountProjection 帳號列投影的同型包裝。
type soRevokeAccountProjection struct {
	inner *authz.CredentialScopeReader
	hook  func()
	calls int
}

func (w *soRevokeAccountProjection) AccountCredentialProjection(ctx context.Context, ids []uint) (authz.AccountCredentialShape, map[uint]bool, error) {
	w.calls++
	if w.calls == 1 {
		w.hook()
	}
	return w.inner.AccountCredentialProjection(ctx, ids)
}

// soLegacyJudgment 反例判定：重現舊的「不是範圍化檢視者即全量」。
type soLegacyJudgment struct{ r *authz.CredentialScopeReader }

func (l soLegacyJudgment) CredentialOutputScope(ctx context.Context) (asset.CredentialOutputScope, error) {
	v, err := l.r.CredentialScopeView(ctx)
	if err != nil {
		return nil, err
	}
	return &soLegacyScope{ctx: ctx, r: l.r, v: v}, nil
}

type soLegacyScope struct {
	ctx context.Context
	r   *authz.CredentialScopeReader
	v   asset.CredentialScopeView
}

func soAllIn(ids []uint) map[uint]bool {
	out := make(map[uint]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

func (s *soLegacyScope) Full() bool { return s.v == nil }

func (s *soLegacyScope) AssetsInView(ids []uint) (map[uint]bool, error) {
	if s.v == nil {
		return soAllIn(ids), nil
	}
	return s.v.AssetsInView(ids)
}

func (s *soLegacyScope) CredentialsInView(ids []uint) (map[uint]bool, error) {
	if s.v == nil {
		return soAllIn(ids), nil
	}
	m, scoped, err := s.r.CredentialsInView(s.ctx, ids)
	if err != nil {
		return nil, err
	}
	if !scoped {
		return soAllIn(ids), nil
	}
	return m, nil
}

// soDropNodeAssignments 移除使用者全部節點範圍指派（指派列與節點綁定）。
func (e *outEnv) soDropNodeAssignments(userID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Where("user_id = ? AND scope_kind = ?", userID, model.ScopeKindNodes).Delete(&model.UserRole{}).Error)
	require.NoError(e.t, e.db.Where("subject_kind = ? AND subject_id = ?", model.BindingSubjectUser, userID).Delete(&model.RoleBindingNode{}).Error)
}

// soStartRotation 以 mgr 發起一輪輪替，回進度路徑與該輪成員。
func (e *outEnv) soStartRotation(t *testing.T) (string, []model.CredentialRotationMember) {
	t.Helper()
	e.soBumpRotationIDs()
	credBase := credPath(e.rotCred)
	r := e.soRotationRouter(e.mgr)
	code, raw := soServe(r, http.MethodPost, credBase+"/impact-confirmations", `{"operation":"rotate"}`)
	soAssertOK(t, code, raw, http.StatusOK, []string{"confirmation_id"})
	confirmID, _ := soDecode(t, raw)["confirmation_id"].(string)
	code, raw = soServe(r, http.MethodPost, credBase+"/rotations",
		fmt.Sprintf(`{"mode":"group","impact_confirmation_id":%q}`, confirmID))
	soAssertOK(t, code, raw, http.StatusAccepted, []string{"data"})
	rid := uint(soDecode(t, raw)["data"].(map[string]any)["id"].(float64))
	var members []model.CredentialRotationMember
	require.NoError(t, e.db.Where("rotation_id = ?", rid).Order("id asc").Find(&members).Error)
	if len(members) != 5 {
		t.Fatalf("PRECONDITION: 該輪成員列應為 5 筆，實際 %d", len(members))
	}
	return fmt.Sprintf("%s/rotations/%d", credBase, rid), members
}

// soRevokedVariants 兩個變體共用的流程：計數必為 1；counterexample 必須外洩，real 不得外洩。
func soRevokedVariants(t *testing.T, build func(inner func(e *outEnv) asset.CredentialOutputScopeSource) (raw string, calls int, leaks []soToken, check func(t *testing.T, raw string))) {
	t.Helper()
	t.Run("counterexample", func(t *testing.T) {
		raw, calls, leaks, _ := build(func(e *outEnv) asset.CredentialOutputScopeSource {
			return soLegacyJudgment{r: authz.NewCredentialScopeReader(e.eval, e.db)}
		})
		if calls != 1 {
			t.Fatalf("PRECONDITION: revoke hook not fired（包裝計數 %d）", calls)
		}
		hits := soFindLeaks(raw, leaks)
		if len(hits) < 1 {
			t.Fatalf("PRECONDITION: 反例判定在撤權時序下沒有外洩，測試測不到撤權時序\n本文: %s", raw)
		}
		t.Logf("LEAK-DETECTED: %v (包裝計數 %d)", hits, calls)
	})
	t.Run("real", func(t *testing.T) {
		raw, calls, leaks, check := build(func(e *outEnv) asset.CredentialOutputScopeSource {
			return authz.NewCredentialScopeReader(e.eval, e.db)
		})
		if calls != 1 {
			t.Fatalf("PRECONDITION: revoke hook not fired（包裝計數 %d）", calls)
		}
		t.Logf("包裝計數 %d", calls)
		soAssertNoLeak(t, raw, leaks, nil)
		check(t, raw)
	})
}

func soRowsAllMasked(t *testing.T, rows []map[string]any) {
	t.Helper()
	require.NotEmpty(t, rows)
	for _, r := range rows {
		if v, _ := r["credential_out_of_scope"].(bool); !v {
			t.Fatalf("ASSERT: 帶憑證的列應帶 credential_out_of_scope:true\n列: %v", r)
		}
	}
}

func TestScopedOutputRevokedMidResponse(t *testing.T) {
	csForbidden := func(e *outEnv) []soToken {
		return []soToken{soName("zz-so-out-gcred"), soName("zz-so-in-cred"),
			soNum("credential_id", e.gcred), soNum("credential_id", e.inCred),
			soNum("target_version_id", soVerG), soNum("target_version_id", soVerI)}
	}

	t.Run("rotation_get", func(t *testing.T) {
		soRevokedVariants(t, func(inner func(e *outEnv) asset.CredentialOutputScopeSource) (string, int, []soToken, func(*testing.T, string)) {
			e := newOutEnv(t, soWithRotation())
			path, members := e.soStartRotation(t)
			w := &soRevokeOnFirstCall{inner: inner(e), hook: func() { e.soDropNodeAssignments(e.mgr) }}
			e.rot.WithOutputScope(w)
			code, raw := soServe(e.soRotationRouter(e.mgr), http.MethodGet, path, "")
			soAssertOK(t, code, raw, http.StatusOK, []string{"data"})
			forbidden := []soToken{soName("zz-so-out-asset-0"), soName("zz-so-out-asset-1"), soName("zz-so-out-asset-2"),
				soName("zz-so-asset-in-0"), soName("zz-so-asset-in-1"), soName(`"asset_id"`), soName(`"account_id"`)}
			for _, m := range members {
				forbidden = append(forbidden, soNum("id", m.ID))
			}
			return raw, w.calls, forbidden, func(t *testing.T, raw string) {
				soAssertNoLeak(t, raw, nil, []string{`"members":[]`, `"out_of_scope_asset_count":5`})
			}
		})
	})

	type csRoute struct {
		name string
		path func(d *soCSData) string
		rows []string
	}
	for _, rt := range []csRoute{
		{"batch_targets", func(*soCSData) string { return "/api/v1/change-secret-batches/targets?username=zz-so-g" }, []string{"data"}},
		{"batch_detail", func(d *soCSData) string { return fmt.Sprintf("/api/v1/change-secret-batches/%d", d.batchID) }, []string{"data", "records"}},
		{"plan_records", func(d *soCSData) string { return fmt.Sprintf("/api/v1/change-secret-plans/%d/records", d.inPlan.ID) }, []string{"data"}},
	} {
		t.Run(rt.name, func(t *testing.T) {
			soRevokedVariants(t, func(inner func(e *outEnv) asset.CredentialOutputScopeSource) (string, int, []soToken, func(*testing.T, string)) {
				e := newOutEnv(t, soWithChangeSecret())
				d := e.soBuildCS()
				w := &soRevokeOnFirstCall{inner: inner(e), hook: func() { e.soDropNodeAssignments(e.mgr) }}
				code, raw := soServe(e.soChangeSecretRouterWith(e.mgr, w), http.MethodGet, rt.path(d), "")
				soAssertOK(t, code, raw, http.StatusOK, []string{"data"})
				return raw, w.calls, csForbidden(e), func(t *testing.T, raw string) {
					soRowsAllMasked(t, soJSONRows(t, raw, rt.rows...))
				}
			})
		})
	}

	t.Run("account_update", func(t *testing.T) {
		e := newOutEnv(t, soWithAccounts())
		w := &soRevokeAccountProjection{inner: authz.NewCredentialScopeReader(e.eval, e.db),
			hook: func() { e.soDropNodeAssignments(e.mgr) }}
		path := fmt.Sprintf("/api/v1/assets/%d/accounts/%d", e.assetU, e.gcredAcc)
		code, raw := soServe(e.soAccountRouterWith(e.mgr, w), http.MethodPut, path, `{"note":"zz-so-note"}`)
		soAssertOK(t, code, raw, http.StatusOK, []string{"id", "username"})
		if w.calls != 1 {
			t.Fatalf("PRECONDITION: revoke hook not fired（包裝計數 %d）", w.calls)
		}
		t.Logf("包裝計數 %d", w.calls)
		soAssertNoLeak(t, raw, []soToken{soName("zz-so-out-gcred")}, nil)
		require.Equal(t, soSlimKeys(t), soTopKeys(t, raw), raw)
	})
}
