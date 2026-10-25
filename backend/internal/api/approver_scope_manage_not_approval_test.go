package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
)

// 管理審核規則與實際審核能力分開：審核範圍管理（含申請人型管理）不構成審核資格。
//
// 經完整 RegisterRoutes（真認證中介層＋真 JWT＋真申請服務），持全域審核範圍管理＋申請人型管理、
// 或持節點範圍審核範圍管理、但不具 approver 角色者，對審核中心入口、待審計數、待審與待補審列表、
// 核准、拒絕、補審一律被拒；同時持審核範圍管理且已具 approver 角色、範圍命中者照常核准他人申請，
// 對自己的申請仍回自核禁止。SQLite；設 TEST_PG_DSN 時改在 PostgreSQL。

const manageNotApprovalSecret = "manage-not-approval-secret"

type manageNotApprovalEnv struct {
	*apsEnv
	r   *gin.Engine
	jwt *crypto.JWTManager
}

func newManageNotApprovalEnv(t *testing.T) *manageNotApprovalEnv {
	t.Helper()
	base := apsEnvFor(t, "aps_not_approval")
	require.NoError(t, migrateWithAuthz(base.db, &model.AccessRequest{}, &model.AccessRequestItem{},
		&model.AccessRequestApproval{}, &model.SecurityPolicy{}))
	policies := policy.NewSecurityPolicyService(base.db)
	requests := authz.NewAccessRequestService(base.db, policies,
		policy.NewAccessPolicyService(base.db, policies, authz.NewAssetAuthorizationService(base.db)), nil, nil)

	auth := identity.NewAuthService(manageNotApprovalSecret, time.Minute)
	r := gin.New()
	NewAccessRequestHandler(requests, base.svc, base.db).RegisterRoutes(r.Group("/api/v1"), auth)
	ah := NewAuthHandler(auth, nil)
	ah.SetSourcePolicyReader(unrestrictedSourcePolicy())
	ah.SetScopeNodePathReader(asset.NewScopeTopologyReader()) // 與組裝根同：節點範圍主體的摘要需要節點路徑
	ah.RegisterRoutes(r.Group("/api/v1"), auth)
	return &manageNotApprovalEnv{apsEnv: base, r: r, jwt: crypto.NewJWTManager(manageNotApprovalSecret, time.Minute)}
}

func (e *manageNotApprovalEnv) send(uid uint, method, path string, body any) apsResp {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(e.t, json.NewEncoder(&buf).Encode(body))
	}
	tok, err := e.jwt.GenerateToken(uid, fmt.Sprintf("u%d", uid), "", "user", crypto.AuthContext{})
	require.NoError(e.t, err)
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return apsResp{code: w.Code, raw: w.Body.String()}
}

// pending 直接寫表建一張待審申請單（一項，資產 assetID）。
func (e *manageNotApprovalEnv) pending(requester, assetID uint) uint {
	e.t.Helper()
	r := &model.AccessRequest{RequesterID: requester, AssetID: assetID, Reason: "r", RequestedDurationMinutes: 30,
		Status: model.AccessRequestPending, PendingExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}
	require.NoError(e.t, e.db.Create(r).Error)
	require.NoError(e.t, e.db.Create(&model.AccessRequestItem{RequestID: r.ID, RequesterID: requester,
		AssetID: assetID, Status: model.AccessRequestPending}).Error)
	return r.ID
}

func (e *manageNotApprovalEnv) status(id uint) string {
	e.t.Helper()
	var r model.AccessRequest
	require.NoError(e.t, e.db.First(&r, id).Error)
	return string(r.Status)
}

func (e *manageNotApprovalEnv) approvals() int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.AccessRequestApproval{}).Count(&n).Error)
	return n
}

func (e *manageNotApprovalEnv) mePermissions(uid uint) []string {
	e.t.Helper()
	got := e.send(uid, http.MethodGet, "/api/v1/auth/me", nil)
	require.Equal(e.t, http.StatusOK, got.code, got.raw)
	var me struct {
		Permissions []string `json:"permissions"`
	}
	require.NoError(e.t, json.Unmarshal([]byte(got.raw), &me), got.raw)
	return me.Permissions
}

func TestApproverScopeManageIsNotApproval(t *testing.T) {
	e := newManageNotApprovalEnv(t)
	srv := e.hostAsset("srv", "10.9.9.9", "prod/db")
	requester := e.user("requester")

	globalManager := e.user("manager-global")
	e.grantGlobal(globalManager, e.role(authz.PermApproverScopeManage, authz.PermApproverScopeApplicantManage))
	nodeManager := e.user("manager-node")
	e.grantNodes(nodeManager, e.role(authz.PermApproverScopeManage), "prod")
	approver := e.approver("approver-manager")
	e.grantGlobal(approver, e.role(authz.PermApproverScopeManage))
	e.seedScope(model.ApproverScope{ApproverID: ptrU(approver), AssetID: ptrU(srv)})

	target := e.pending(requester, srv)
	before := e.approvals()

	for name, uid := range map[string]uint{"global_manage_and_applicant": globalManager, "node_manage": nodeManager} {
		uid := uid
		t.Run(name, func(t *testing.T) {
			// 兩者確實持有審核範圍管理（範圍管理路由放行），否則下面的拒絕不證明分離
			list := e.send(uid, http.MethodGet, "/api/v1/approver-scopes", nil)
			require.Equal(t, http.StatusOK, list.code, list.raw)

			for _, path := range []string{
				"/api/v1/access-requests/pending",
				"/api/v1/access-requests/pending/count",
				"/api/v1/access-requests/reviews/pending",
			} {
				got := e.send(uid, http.MethodGet, path, nil)
				bodyOnlyCodeError(t, got)
			}
			for _, action := range []string{"approve", "reject", "review"} {
				got := e.send(uid, http.MethodPost, fmt.Sprintf("/api/v1/access-requests/%d/%s", target, action),
					map[string]string{"note": "x", "disposition": "confirmed"})
				bodyOnlyCodeError(t, got)
			}
			require.Equal(t, string(model.AccessRequestPending), e.status(target))
			require.Equal(t, before, e.approvals())
			require.NotContains(t, e.mePermissions(uid), authz.UIApprovals)
		})
	}

	t.Run("approver_with_manage", func(t *testing.T) {
		require.Contains(t, e.mePermissions(approver), authz.UIApprovals)
		got := e.send(approver, http.MethodPost, fmt.Sprintf("/api/v1/access-requests/%d/approve", target), nil)
		require.Equal(t, http.StatusOK, got.code, got.raw)
		require.Equal(t, before+1, e.approvals())

		own := e.pending(approver, srv)
		got = e.send(approver, http.MethodPost, fmt.Sprintf("/api/v1/access-requests/%d/approve", own), nil)
		require.Equal(t, http.StatusForbidden, got.code, got.raw)
		require.Contains(t, got.raw, `"RULE_ACCESS_REQUEST_SELF_APPROVAL"`)
		require.Equal(t, string(model.AccessRequestPending), e.status(own))
	})
}
