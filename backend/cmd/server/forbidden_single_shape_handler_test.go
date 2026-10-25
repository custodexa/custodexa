package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/session"
)

// 服務層能力拒絕的其餘 handler 寫出點：儀表板逐卡資料（卡片能力、審核資格）與主機身分確認
// （憑證管理關卡拒絕）。由 TestForbiddenSingleShape 呼叫，與登錄閘拒絕的本文逐位元比對，
// 並斷言依據存入脈絡；被拒的請求不得讀任何資料來源。

// cardSourceStub 儀表板卡片的資料來源替身：任何呼叫都記一次，供斷言「拒絕前未讀資料」。
type cardSourceStub struct{ hits *int }

func (s cardSourceStub) List(*session.SessionFilter) (*session.SessionListResponse, error) {
	*s.hits++
	return &session.SessionListResponse{}, nil
}

func (s cardSourceStub) GetActiveSessions() ([]model.Session, error) {
	*s.hits++
	return nil, nil
}

func (s cardSourceStub) ListMyConnections(uint, int, int) (*session.MyConnectionListResponse, error) {
	*s.hits++
	return &session.MyConnectionListResponse{}, nil
}

func (s cardSourceStub) GetRecordingStats() (*session.RecordingStats, error) {
	*s.hits++
	return &session.RecordingStats{}, nil
}

func (s cardSourceStub) LastReviewDaysAgo() (int, error) {
	*s.hits++
	return 0, nil
}

func (s cardSourceStub) CountMinePending(uint) (int64, error) {
	*s.hits++
	return 0, nil
}

func (s cardSourceStub) PendingCount(uint, bool, time.Time) (int64, error) {
	*s.hits++
	return 0, nil
}

func (s cardSourceStub) PendingReviewCount(uint, bool) (int64, error) {
	*s.hits++
	return 0, nil
}

func (s cardSourceStub) CountAssets(context.Context, *authz.Principal, uint) (int64, error) {
	*s.hits++
	return 0, nil
}

// cardAlertSourceStub 告警來源與連線來源同名方法分開。
type cardAlertSourceStub struct{ hits *int }

func (s cardAlertSourceStub) List(*audit.CommandAlertFilter) (*audit.CommandAlertListResponse, error) {
	*s.hits++
	return &audit.CommandAlertListResponse{}, nil
}

const handlerShapeConfirmBody = `{"confirm_host_identity":{"transport":"ssh","record_id":7,"algorithm":"ssh-ed25519",` +
	`"fingerprint":"SHA256:abc","generation":3,"accept_different_key":false}}`

func handlerCapabilitySubcases(t *testing.T, sample string, assertShape shapeAsserter) {
	require.NotEmpty(t, sample)
	plain := principalOf(model.BuiltinUser, "")

	// 儀表板卡片：審核資格現查讀 DB（users 1–5，無審核方群組）。
	env := newOwnerTransferEnv(t)
	hits := 0
	src := cardSourceStub{hits: &hits}
	cards, err := api.NewDashboardCardHandler(api.DashboardCardDeps{
		Assets: src, Sessions: src, MyConnections: src, Alerts: cardAlertSourceStub{hits: &hits},
		Recordings: src, Reviews: src, Requests: src, DB: env.db,
	})
	require.NoError(t, err)
	cardRoutes := func(r gin.IRoutes) {
		r.GET("/api/v1/dashboard/cards/:key", middleware.EnforceRegistry(), cards.GetCard)
	}

	// 主機身分確認：候選重試帶明示確認，經正式承接服務與憑證管理關卡判定。
	confirmRoutes := func(t *testing.T) (func(r gin.IRoutes), *markerEnv, uint) {
		m := newMarkerEnv(t, "")
		candidates, err := asset.NewChangeSecretCandidateService(m.db, m.codec, m.assets, audit.NewTxSink())
		require.NoError(t, err)
		cand := model.ChangeSecretCandidate{AccountID: m.seed.accountID, AssetID: m.seed.assetID, SecretType: "password"}
		require.NoError(t, m.db.Create(&cand).Error)
		h := api.NewChangeSecretHandler(nil, nil, candidates, nil, nil, nil)
		h.SetHostIdentityTakeover(asset.NewHostIdentityTakeoverService(m.db, m.auth))
		return func(r gin.IRoutes) {
			r.POST("/api/v1/change-secret-candidates/:id/retry", middleware.EnforceRegistry(), h.RetryCandidate)
		}, m, cand.ID
	}

	reservedSet := map[string]bool{
		authz.ReservedSuperAdmin: true, authz.ReservedSuperAdminOrAuditor: true,
		authz.ReservedApproverEligibility: true, authz.ReservedRevokeEligibility: true,
	}
	check := func(t *testing.T, name, method, path string, pr shapeProbe, basis authz.DenialBasis, required []string) {
		t.Helper()
		assertShape(t, name, authz.RouteEntry{Method: method, Path: path}, pr, basis)
		assert.Equal(t, sample, pr.raw, "%s：須與登錄閘的能力拒絕逐位元相同", name)
		require.True(t, pr.hasDeny, "%s：拒絕依據未存入脈絡", name)
		assert.Equal(t, required, pr.denial.Required, "%s：拒絕依據所列鍵", name)
		if basis == authz.DenialReserved {
			for _, v := range pr.denial.Required {
				assert.True(t, reservedSet[v], "%s：保留條件值 %q 不在受控清單", name, v)
			}
		}
	}

	t.Run("儀表板卡片：缺該卡能力", func(t *testing.T) {
		hits = 0
		path := "/api/v1/dashboard/cards/recording-storage"
		pr, _ := outletProbe(otUserU, customPrincipal(authz.PermSessionView), "GET", path, "", cardRoutes)
		check(t, "儀表板卡片：缺該卡能力", "GET", path, pr, authz.DenialAllOf, []string{string(authz.PermAuditView)})
		assert.Zero(t, hits, "被拒前不得讀資料來源")
	})
	t.Run("儀表板卡片：待審卡非有效審核者", func(t *testing.T) {
		hits = 0
		path := "/api/v1/dashboard/cards/pending-approvals"
		pr, _ := outletProbe(otUserU, plain, "GET", path, "", cardRoutes)
		check(t, "儀表板卡片：待審卡非有效審核者", "GET", path, pr, authz.DenialReserved, []string{authz.ReservedApproverEligibility})
		assert.Zero(t, hits, "被拒前不得讀資料來源")
	})

	// 補標記列：回應外形與改為單一寫出函式之前的寫法逐位元相同，依據入脈絡。
	legacy := legacyPermissionDeniedBody(t)
	require.Equal(t, sample, legacy, "基準：改前寫法與登錄閘能力拒絕須逐位元相同")
	t.Run("主機身分確認：確認者缺帳號改密能力", func(t *testing.T) {
		mount, m, id := confirmRoutes(t)
		path := fmt.Sprintf("/api/v1/change-secret-candidates/%d/retry", id)
		m.current = customPrincipal(authz.PermChangeSecretManage)
		defer func() { m.current = nil }()
		pr := markerServe(m.current, 7, "POST", path, handlerShapeConfirmBody, mount)
		check(t, "主機身分確認：確認者缺帳號改密能力", "POST", path, pr, authz.DenialAllOf, []string{string(authz.PermAccountRotate)})
		assert.Equal(t, legacy, pr.raw)
	})
	t.Run("主機身分確認：空主體記路由要求", func(t *testing.T) {
		mount, m, id := confirmRoutes(t)
		path := fmt.Sprintf("/api/v1/change-secret-candidates/%d/retry", id)
		m.current = customPrincipal(authz.PermChangeSecretManage, authz.PermAccountRotate)
		defer func() { m.current = nil }()
		pr := markerServe(m.current, 0, "POST", path, handlerShapeConfirmBody, mount)
		check(t, "主機身分確認：空主體記路由要求", "POST", path, pr, authz.DenialAllOf, []string{string(authz.PermChangeSecretManage)})
		assert.Equal(t, legacy, pr.raw)
	})
}
