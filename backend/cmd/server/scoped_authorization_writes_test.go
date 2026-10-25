package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 授權規則寫入的範圍化 HTTP 夾具：注入目錄把授權規則管理標為範圍生效，服務注入真實的交易內範圍判定。
// 節點、資產名稱以 zz-aw- 起頭。

type awEnv struct {
	*saEnv
	cat authz.Catalogue
	svc *authz.AssetAuthorizationService
	// aeval 與服務同一份判定器，供範圍化讀取的解析器共用
	aeval *authz.ScopeEvaluator
}

// newAWEnv 的 extra 為另外標為範圍生效的權限點（其節點範圍指派才會被物化）。
func newAWEnv(t *testing.T, extra ...authz.Permission) *awEnv {
	t.Helper()
	base := newSAEnv(t)
	cat, err := authz.CatalogueWithScopedEnforcedForTest(append([]authz.Permission{authz.PermAuthorizationManage}, extra...)...)
	require.NoError(t, err)
	svc := authz.NewAssetAuthorizationService(base.db)
	aeval := authz.NewAuthorizationScopeEvaluator(cat, asset.NewScopeTopologyReader())
	svc.SetWriteScope(authz.NewAuthorizationWriteScope(aeval))
	require.NoError(t, svc.RequireWriteScope())
	return &awEnv{saEnv: base, cat: cat, svc: svc, aeval: aeval}
}

func (e *awEnv) do2(uid uint, method, path, body string) (int, string) {
	e.t.Helper()
	return e.serve(false, uid, method, path, body)
}

// doAudited 同 do2，但最外層掛真的審計中介層（同步寫入），供讀回該請求的審計列。
func (e *awEnv) doAudited(uid uint, method, path, body string) (int, string) {
	e.t.Helper()
	return e.serve(true, uid, method, path, body)
}

// lastAudit 最新一列審計列。
func (e *awEnv) lastAudit() model.AuditLog {
	e.t.Helper()
	var row model.AuditLog
	require.NoError(e.t, e.db.Unscoped().Order("id desc").First(&row).Error)
	return row
}

func (e *awEnv) serve(audited bool, uid uint, method, path, body string) (int, string) {
	e.t.Helper()
	r := gin.New()
	if audited {
		r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	}
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	h := api.NewAuthorizationHandler(e.svc, authz.NewEffectiveAccessResolver(e.db).WithScope(e.aeval))
	h.EnableScopedWrites(nil, authz.NewAuthorizationSelectors(e.db, e.aeval))
	g := r.Group("/api/v1/authorizations")
	g.POST("", h.Create)
	g.POST("/batch", h.BatchCreate)
	g.PUT("/:id/accounts", h.UpdateAccounts)
	g.DELETE("/:id", h.Delete)
	g.GET("", h.List)
	g.GET("/effective-assets", h.EffectiveAssets)
	g.GET("/effective-users", h.EffectiveUsers)
	g.GET("/subject-options", h.SubjectOptions)
	g.GET("/target-options", h.TargetOptions)
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (e *awEnv) ruleCount() int64 {
	var n int64
	require.NoError(e.t, e.db.Model(&model.AssetAuthorization{}).Count(&n).Error)
	return n
}

// 規則由超級管理者建立（granted_by＝super），客體為資產 assetID。
func (e *awEnv) seedRule(subject, assetID uint) uint {
	e.t.Helper()
	a := model.AssetAuthorization{UserID: &subject, AssetID: &assetID, Permission: model.PermissionConnect,
		GrantedBy: e.super, Accounts: model.AccountScope{model.AccountScopeAll}}
	require.NoError(e.t, e.db.Create(&a).Error)
	return a.ID
}

func TestScopedAuthorizationWrites(t *testing.T) {
	e := newAWEnv(t)
	e.node("zz-aw-a", "")
	e.node("zz-aw-b", "zz-aw-a")
	e.node("zz-aw-c", "")
	x := e.asset("zz-aw-x", "zz-aw-b")
	y := e.asset("zz-aw-y", "zz-aw-c")
	op := e.user("zz-aw-op")
	e.grantNodes(op, e.role(authz.PermAuthorizationManage), "zz-aw-a")
	sub := e.user("zz-aw-sub")
	nobody := e.user("zz-aw-nobody")
	const missing = 999907

	create := func(uid uint, assetID, nodeID uint) (int, string) {
		if nodeID != 0 {
			return e.do2(uid, "POST", "/api/v1/authorizations", fmt.Sprintf(`{"user_id":%d,"asset_group_id":%d,"permission":"view"}`, sub, nodeID))
		}
		return e.do2(uid, "POST", "/api/v1/authorizations", fmt.Sprintf(`{"user_id":%d,"asset_id":%d,"permission":"view"}`, sub, assetID))
	}

	t.Run("create in scope asset and node succeed", func(t *testing.T) {
		code, body := create(op, x, 0)
		require.Equal(t, http.StatusOK, code, body)
		code, body = create(op, 0, e.nodes["zz-aw-b"])
		require.Equal(t, http.StatusOK, code, body)
	})
	t.Run("create out of scope equals nonexistent", func(t *testing.T) {
		before := e.ruleCount()
		c1, b1 := create(op, y, 0)
		c2, b2 := create(op, missing, 0)
		require.Equal(t, http.StatusNotFound, c1, b1)
		require.Equal(t, c2, c1)
		require.Equal(t, b2, b1)
		n1c, n1 := create(op, 0, e.nodes["zz-aw-c"])
		n2c, n2 := create(op, 0, missing)
		require.Equal(t, http.StatusNotFound, n1c, n1)
		require.Equal(t, n2c, n1c)
		require.Equal(t, n2, n1)
		require.Equal(t, before, e.ruleCount())
		require.NotContains(t, b1+n1, "zz-aw-")
	})
	t.Run("operator without capability gets single forbidden", func(t *testing.T) {
		code, _ := create(nobody, x, 0)
		require.Equal(t, http.StatusForbidden, code)
	})
	t.Run("batch counts unavailable objects and writes nothing", func(t *testing.T) {
		before := e.ruleCount()
		code, body := e.do2(op, "POST", "/api/v1/authorizations/batch",
			fmt.Sprintf(`{"user_ids":[%d],"asset_ids":[%d,%d,%d],"permission":"connect"}`, sub, x, y, missing))
		require.Equal(t, http.StatusNotFound, code, body)
		require.Contains(t, body, "NOTFOUND_BATCH_ITEMS_UNAVAILABLE")
		require.Contains(t, body, `"count":2`)
		require.NotContains(t, body, "zz-aw-")
		require.Equal(t, before, e.ruleCount())
		code, body = e.do2(op, "POST", "/api/v1/authorizations/batch",
			fmt.Sprintf(`{"user_ids":[%d],"asset_ids":[%d],"permission":"connect"}`, sub, x))
		require.Equal(t, http.StatusOK, code, body)
	})
	t.Run("batch with zero ids equals nonexistent ids", func(t *testing.T) {
		globalHolder := e.user("zz-aw-global-holder")
		e.grantGlobal(globalHolder, e.role(authz.PermAuthorizationManage))
		batch := func(uid uint, field string, ids string) (int, string) {
			return e.do2(uid, "POST", "/api/v1/authorizations/batch",
				fmt.Sprintf(`{"user_ids":[%d],"%s":[%s],"permission":"view"}`, sub, field, ids))
		}
		for _, field := range []string{"asset_ids", "asset_group_ids"} {
			before := e.ruleCount()
			c0, b0 := batch(op, field, "0")
			cm, bm := batch(op, field, strconv.Itoa(missing))
			require.Equal(t, http.StatusNotFound, c0, b0)
			require.Equal(t, cm, c0, field)
			require.Equal(t, bm, b0, field)
			require.Contains(t, b0, "NOTFOUND_BATCH_ITEMS_UNAVAILABLE")
			require.Contains(t, b0, `"count":1`)
			require.Equal(t, before, e.ruleCount())
			// 全域持有者的既有回應不變
			gc, gb := batch(globalHolder, field, "0")
			require.Equal(t, http.StatusNotFound, gc, gb)
			require.Contains(t, gb, "NOTFOUND_BATCH_GRANT_REFERENCE")
			require.Equal(t, before, e.ruleCount())
		}
		// 混在範圍內客體之間的 0 同樣計入，且整批不寫入
		before := e.ruleCount()
		c0, b0 := e.do2(op, "POST", "/api/v1/authorizations/batch",
			fmt.Sprintf(`{"user_ids":[%d],"asset_ids":[%d,0],"permission":"view"}`, sub, x))
		cm, bm := e.do2(op, "POST", "/api/v1/authorizations/batch",
			fmt.Sprintf(`{"user_ids":[%d],"asset_ids":[%d,%d],"permission":"view"}`, sub, x, missing))
		require.Equal(t, http.StatusNotFound, c0, b0)
		require.Equal(t, cm, c0)
		require.Equal(t, bm, b0)
		require.Equal(t, before, e.ruleCount())
	})
	t.Run("update accounts and delete", func(t *testing.T) {
		// 另立主體：前一子測試的批次已替 sub 在 x 上建了 connect 規則，同主體同客體同權限受唯一索引約束
		seeded := e.user("zz-aw-seeded")
		inRule := e.seedRule(seeded, x)
		outRule := e.seedRule(seeded, y)
		upd := func(id uint) (int, string) {
			return e.do2(op, "PUT", fmt.Sprintf("/api/v1/authorizations/%d/accounts", id), `{"accounts":["root"]}`)
		}
		c1, b1 := upd(outRule)
		c2, b2 := upd(missing)
		require.Equal(t, http.StatusNotFound, c1, b1)
		require.Equal(t, c2, c1)
		require.Equal(t, b2, b1)
		code, body := upd(inRule)
		require.Equal(t, http.StatusOK, code, body)
		// 非建立者擴大仍被窄化守衛拒絕
		code, _ = e.do2(op, "PUT", fmt.Sprintf("/api/v1/authorizations/%d/accounts", inRule), `{"accounts":["@ALL"]}`)
		require.Equal(t, http.StatusForbidden, code)

		d1, db1 := e.do2(op, "DELETE", fmt.Sprintf("/api/v1/authorizations/%d", outRule), "")
		d2, db2 := e.do2(op, "DELETE", fmt.Sprintf("/api/v1/authorizations/%d", missing), "")
		require.Equal(t, http.StatusNotFound, d1, db1)
		require.Equal(t, d2, d1)
		require.Equal(t, db2, db1)
		var n int64
		require.NoError(t, e.db.Model(&model.AssetAuthorization{}).Where("id = ?", outRule).Count(&n).Error)
		require.EqualValues(t, 1, n)
		code, body = e.do2(op, "DELETE", fmt.Sprintf("/api/v1/authorizations/%d", inRule), "")
		require.Equal(t, http.StatusOK, code, body)
	})
	t.Run("temporary grant out of scope is not found before conflict", func(t *testing.T) {
		require.NoError(t, e.db.AutoMigrate(&model.AccessRequest{}))
		holder := e.user("zz-aw-ticket-holder")
		// 有關聯申請單的臨時授權：範圍內的裸刪與帳號範圍調整回 409，範圍外須先回與不存在同形的 404
		ticket := func(assetID uint) uint {
			now := time.Now()
			start, expire := now.Add(-time.Minute), now.Add(time.Hour)
			a := model.AssetAuthorization{UserID: &holder, AssetID: &assetID, Permission: model.PermissionConnect,
				GrantedBy: e.super, Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &expire,
				Accounts: model.AccountScope{model.AccountScopeAll}}
			require.NoError(t, e.db.Create(&a).Error)
			req := model.AccessRequest{RequesterID: holder, AssetID: assetID, Reason: "zz-aw-ticket", Kind: "normal",
				RequestedDurationMinutes: 60, Status: model.AccessRequestPending, PendingExpiresAt: now.Add(time.Hour)}
			require.NoError(t, e.db.Create(&req).Error)
			require.NoError(t, e.db.Model(&req).Updates(map[string]any{
				"status": model.AccessRequestApproved, "authorization_id": a.ID}).Error)
			return a.ID
		}
		inTicket, outTicket := ticket(x), ticket(y)
		alive := func(id uint) {
			t.Helper()
			var a model.AssetAuthorization
			require.NoError(t, e.db.First(&a, id).Error)
			require.Equal(t, model.AccountScope{model.AccountScopeAll}, a.Accounts)
		}
		for _, c := range []struct {
			name, method, path, body string
			conflict                 string
		}{
			{"update accounts", "PUT", "/api/v1/authorizations/%d/accounts", `{"accounts":["root"]}`, string(apierror.CodeTicketAccountScopeImmutable)},
			{"delete", "DELETE", "/api/v1/authorizations/%d", "", string(apierror.CodeTicketRevocationRequired)},
		} {
			t.Run(c.name, func(t *testing.T) {
				co, bo := e.do2(op, c.method, fmt.Sprintf(c.path, outTicket), c.body)
				cm, bm := e.do2(op, c.method, fmt.Sprintf(c.path, missing), c.body)
				require.Equal(t, http.StatusNotFound, co, bo)
				require.Equal(t, cm, co)
				require.Equal(t, bm, bo)
				require.NotContains(t, bo, "CONFLICT_")
				ci, bi := e.do2(op, c.method, fmt.Sprintf(c.path, inTicket), c.body)
				require.Equal(t, http.StatusConflict, ci, bi)
				require.Contains(t, bi, c.conflict)
				alive(inTicket)
				alive(outTicket)
			})
		}
	})
	t.Run("soft deleted rule and rule with deleted object equal nonexistent", func(t *testing.T) {
		upd := func(id uint) (int, string) {
			return e.do2(op, "PUT", fmt.Sprintf("/api/v1/authorizations/%d/accounts", id), `{"accounts":["root"]}`)
		}
		del := func(id uint) (int, string) {
			return e.do2(op, "DELETE", fmt.Sprintf("/api/v1/authorizations/%d", id), "")
		}
		softDeleted := e.seedRule(e.user("zz-aw-soft-sub"), x)
		goneAsset := e.asset("zz-aw-gone", "zz-aw-b")
		goneAssetRule := e.seedRule(e.user("zz-aw-gone-sub"), goneAsset)
		goneNode := e.node("zz-aw-gone-node", "zz-aw-a")
		nodeSub := e.user("zz-aw-gone-node-sub")
		nodeRule := model.AssetAuthorization{UserID: &nodeSub, AssetGroupID: &goneNode, Permission: model.PermissionView,
			GrantedBy: e.super, Accounts: model.AccountScope{model.AccountScopeAll}}
		require.NoError(t, e.db.Create(&nodeRule).Error)
		// 刪除前三筆皆在範圍內：之後的拒絕只來自刪除
		for _, id := range []uint{softDeleted, goneAssetRule, nodeRule.ID} {
			code, body := upd(id)
			require.Equal(t, http.StatusOK, code, body)
		}
		require.NoError(t, e.db.Delete(&model.AssetAuthorization{}, softDeleted).Error)
		require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", goneAsset).Update("deleted_at", time.Now()).Error)
		require.NoError(t, e.db.Model(&model.AssetGroup{}).Where("id = ?", goneNode).Update("deleted_at", time.Now()).Error)
		cu, bu := upd(missing)
		cd, bd := del(missing)
		require.Equal(t, http.StatusNotFound, cu, bu)
		require.Equal(t, http.StatusNotFound, cd, bd)
		for name, id := range map[string]uint{"soft deleted rule": softDeleted, "deleted asset": goneAssetRule, "deleted node": nodeRule.ID} {
			c1, b1 := upd(id)
			require.Equal(t, cu, c1, name)
			require.Equal(t, bu, b1, name)
			c2, b2 := del(id)
			require.Equal(t, cd, c2, name)
			require.Equal(t, bd, b2, name)
		}
		var n int64
		require.NoError(t, e.db.Model(&model.AssetAuthorization{}).Where("id IN ?", []uint{goneAssetRule, nodeRule.ID}).Count(&n).Error)
		require.EqualValues(t, 2, n, "客體已刪除的規則不得被刪除")
	})
	t.Run("scope denial audit details carry only the scope shape", func(t *testing.T) {
		ensureDenialAuditTable(t, e.db)
		outRule := e.seedRule(e.user("zz-aw-audit-sub"), y)
		for _, c := range []struct {
			name, method, path, body string
			ids                      []uint
		}{
			{"create asset object", "POST", "/api/v1/authorizations", fmt.Sprintf(`{"user_id":%d,"asset_id":%d,"permission":"view"}`, sub, y), []uint{y}},
			{"create node object", "POST", "/api/v1/authorizations", fmt.Sprintf(`{"user_id":%d,"asset_group_id":%d,"permission":"view"}`, sub, e.nodes["zz-aw-c"]), []uint{e.nodes["zz-aw-c"]}},
			{"update accounts of rule", "PUT", fmt.Sprintf("/api/v1/authorizations/%d/accounts", outRule), `{"accounts":["root"]}`, []uint{outRule, y}},
			{"delete rule", "DELETE", fmt.Sprintf("/api/v1/authorizations/%d", outRule), "", []uint{outRule, y}},
		} {
			t.Run(c.name, func(t *testing.T) {
				before := countAuditRows(t, e.db)
				code, body := e.doAudited(op, c.method, c.path, c.body)
				require.Equal(t, http.StatusNotFound, code, body)
				require.Equal(t, before+1, countAuditRows(t, e.db))
				row := e.lastAudit()
				require.Equal(t, model.StatusDenied, row.Status)
				require.Equal(t, http.StatusNotFound, row.StatusCode)
				gotNew, gotExisting := splitDenialDetails(t, row.Details)
				require.Equal(t, scopeDetails(string(authz.ScopeReasonOutOfScope), ""), gotNew, row.Details)
				require.Empty(t, gotExisting, row.Details)
				require.NotContains(t, row.Details, "zz-aw-")
				for _, id := range c.ids {
					for k, v := range gotNew {
						require.NotEqual(t, strconv.FormatUint(uint64(id), 10), v, k)
					}
				}
			})
		}
	})
}
