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

// soWithdrawnCompat 反例判定：重現已撤除的規則。真實判定為受限時，若資料表顯示該使用者已沒有任何含
// 憑證檢視能力的指派、且有一筆含改密管理能力的全域指派，就回全量。
type soWithdrawnCompat struct {
	userID uint
	real   *authz.CredentialScopeReader
	count  func(sql string, args ...any) int64
}

func (c soWithdrawnCompat) CredentialOutputScope(ctx context.Context) (asset.CredentialOutputScope, error) {
	scope, err := c.real.CredentialOutputScope(ctx)
	if err != nil || scope.Full() {
		return scope, err
	}
	viewRows := c.count(`SELECT COUNT(*) FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id
		WHERE ur.user_id = ? AND rp.permission_key = ?`, c.userID, string(authz.PermCredentialView))
	globalManage := c.count(`SELECT COUNT(*) FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id
		WHERE ur.user_id = ? AND ur.scope_kind = ? AND rp.permission_key = ?`,
		c.userID, model.ScopeKindGlobal, string(authz.PermChangeSecretManage))
	if viewRows == 0 && globalManage >= 1 {
		return &soFullScope{}, nil
	}
	return scope, nil
}

type soFullScope struct{}

func (soFullScope) Full() bool                                          { return true }
func (soFullScope) AssetsInView(ids []uint) (map[uint]bool, error)      { return soAllIn(ids), nil }
func (soFullScope) CredentialsInView(ids []uint) (map[uint]bool, error) { return soAllIn(ids), nil }

// soDropRoleAssignment 只刪一筆節點指派（指派列與其節點綁定），其餘指派不動。
func (e *outEnv) soDropRoleAssignment(userID, roleID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Where("user_id = ? AND role_id = ?", userID, roleID).Delete(&model.UserRole{}).Error)
	require.NoError(e.t, e.db.Where("subject_kind = ? AND subject_id = ? AND role_id = ?",
		model.BindingSubjectUser, userID, roleID).Delete(&model.RoleBindingNode{}).Error)
}

// TestScopedOutputViewRevokedKeepsEntry 只撤憑證檢視指派、保留全域改密入口與資產改密指派：
// 判定必須轉為受限，憑證識別不因改密入口而回到全量。
func TestScopedOutputViewRevokedKeepsEntry(t *testing.T) {
	type fx struct {
		e      *outEnv
		d      *soCSData
		uid    uint
		viewRL uint
	}
	build := func(t *testing.T) *fx {
		e := newOutEnv(t, soWithChangeSecret())
		d := e.soBuildCS()
		uid := e.user("zz-so-viewdrop")
		e.grantGlobal(uid, e.role(authz.PermChangeSecretManage))
		e.grantNodes(uid, e.role(authz.PermAssetView, authz.PermAccountRotate), soNodeIn)
		viewRL := e.role(authz.PermCredentialView)
		e.grantNodes(uid, viewRL, soNodeIn)
		return &fx{e: e, d: d, uid: uid, viewRL: viewRL}
	}
	count := func(e *outEnv) func(string, ...any) int64 {
		return func(sql string, args ...any) int64 {
			var n int64
			require.NoError(e.t, e.db.Raw(sql, args...).Scan(&n).Error)
			return n
		}
	}
	routes := []struct {
		name string
		path func(d *soCSData) string
		rows []string
	}{
		{"batch_targets", func(*soCSData) string { return "/api/v1/change-secret-batches/targets?username=zz-so-g" }, []string{"data"}},
		{"batch_detail", func(d *soCSData) string { return fmt.Sprintf("/api/v1/change-secret-batches/%d", d.batchID) }, []string{"data", "records"}},
		{"plan_records", func(d *soCSData) string { return fmt.Sprintf("/api/v1/change-secret-plans/%d/records", d.inPlan.ID) }, []string{"data"}},
	}
	forbidden := func(e *outEnv) []soToken {
		return []soToken{soName("zz-so-out-gcred"), soName("zz-so-in-cred"),
			soNum("credential_id", e.gcred), soNum("credential_id", e.inCred),
			soNum("target_version_id", soVerG), soNum("target_version_id", soVerI)}
	}

	t.Run("precondition", func(t *testing.T) {
		f := build(t)
		code, raw := soServe(f.e.soChangeSecretRouter(f.uid), http.MethodGet,
			"/api/v1/change-secret-batches/targets?username=zz-so-g", "")
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		soAssertNoLeak(t, raw, []soToken{soName("zz-so-out-gcred")}, []string{`"credential_name":"zz-so-in-cred"`})
		rows := soJSONRows(t, raw, "data")
		if v, _ := soJSONRowBy(t, rows, "account_id", f.e.gcredAcc)["credential_out_of_scope"].(bool); !v {
			t.Fatalf("PRECONDITION: 全域憑證的列應帶標記\n本文: %s", raw)
		}
	})

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			run := func(t *testing.T, mk func(f *fx) asset.CredentialOutputScopeSource) (string, int, *fx) {
				f := build(t)
				w := &soRevokeOnFirstCall{inner: mk(f), hook: func() { f.e.soDropRoleAssignment(f.uid, f.viewRL) }}
				code, raw := soServe(f.e.soChangeSecretRouterWith(f.uid, w), http.MethodGet, rt.path(f.d), "")
				soAssertOK(t, code, raw, http.StatusOK, []string{"data"})
				return raw, w.calls, f
			}
			t.Run("counterexample", func(t *testing.T) {
				raw, calls, _ := run(t, func(f *fx) asset.CredentialOutputScopeSource {
					return soWithdrawnCompat{userID: f.uid, real: authz.NewCredentialScopeReader(f.e.eval, f.e.db), count: count(f.e)}
				})
				if calls != 1 {
					t.Fatalf("PRECONDITION: revoke hook not fired（包裝計數 %d）", calls)
				}
				hits := soFindLeaks(raw, []soToken{soName("zz-so-out-gcred")})
				if len(hits) < 1 {
					t.Fatalf("PRECONDITION: 已撤除的相容規則沒有外洩，測試測不到\n本文: %s", raw)
				}
				t.Logf("LEAK-DETECTED: %v (包裝計數 %d)", hits, calls)
			})
			t.Run("real", func(t *testing.T) {
				raw, calls, f := run(t, func(f *fx) asset.CredentialOutputScopeSource {
					return authz.NewCredentialScopeReader(f.e.eval, f.e.db)
				})
				if calls != 1 {
					t.Fatalf("PRECONDITION: revoke hook not fired（包裝計數 %d）", calls)
				}
				t.Logf("包裝計數 %d", calls)
				must := `"account_username":"zz-so-g"`
				if rt.name == "batch_targets" {
					must = `"username":"zz-so-g"`
				}
				soAssertNoLeak(t, raw, forbidden(f.e), []string{must})
				if rt.name == "batch_targets" {
					soAssertNoLeak(t, raw, nil, []string{"zz-so-asset-in-0"})
				}
				soRowsAllMasked(t, soJSONRows(t, raw, rt.rows...))
			})
		})
	}
}
