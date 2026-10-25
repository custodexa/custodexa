package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 授權規則寫入與「真的」拓撲變更的交錯（PostgreSQL，接在 TestAuthorizationScopeLockOrder 之後）：
//   - 搬移：正式資產更新入口把客體資產改掛到操作者範圍外的節點；
//   - 撤除：操作者的節點範圍指派以測試內直接寫入撤除，該寫入在交易開頭取正式拓撲序列化函式。
//
// 每組兩種先後：先行者停在「已取拓撲鎖、尚未執行下一個語句」（installTopologyStop），後行者在拓撲鎖上等待，
// 等待一律以 pwloProveWait 的嚴格等待證明確認後才放行。寫入一律經 HTTP 入口（範圍化操作者、登錄目錄），
// 結果與「不存在的目標」同一入口的回應逐欄比較。

const alsMissingID = 999931

type alsIL struct {
	e      *pwloEnv
	w      *pwloActor
	mover  *pwloActor
	kit    pwloAssetKit
	cat    authz.Catalogue
	authH  *api.AuthorizationHandler
	reqSvc *authz.AccessRequestService
	seq    int
}

func newALSInterleave(t *testing.T, e *pwloEnv) *alsIL {
	t.Helper()
	cat, err := authz.CatalogueWithScopedEnforcedForTest(authz.PermAuthorizationManage)
	require.NoError(t, err)
	kit := e.assetKit(t, "mover")
	e.installTopologyStop(t)
	w := e.actor("writer")
	aeval := authz.NewAuthorizationScopeEvaluator(cat, asset.NewScopeTopologyReader())
	svc := authz.NewAssetAuthorizationService(w.db)
	svc.SetWriteScope(authz.NewAuthorizationWriteScope(aeval))
	require.NoError(t, svc.RequireWriteScope())
	h := api.NewAuthorizationHandler(svc, authz.NewEffectiveAccessResolver(w.db).WithScope(aeval))
	h.EnableScopedWrites(nil, authz.NewAuthorizationSelectors(w.db, aeval))
	reqSvc := authz.NewAccessRequestService(w.db, policy.NewSecurityPolicyService(w.db), nil, nil, nil)
	reqSvc.SetRevokeScope(authz.NewAuthorizationWriteScope(aeval))
	reqSvc.SetAuditTxSink(audit.NewTxSink())
	require.NoError(t, reqSvc.RequireRevokeWiring())
	return &alsIL{e: e, w: w, mover: e.actor("mover"), kit: kit, cat: cat, authH: h, reqSvc: reqSvc}
}

type alsResp struct {
	code int
	body string
}

// http 以 uid 為主體送一個請求（主體在請求開始時解出，與正式中介層同形；交易內另行重解）。
func (il *alsIL) http(t *testing.T, uid uint, method, path, body string) alsResp {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(il.e.fix, il.cat, uid, authz.TokenFacts{})
		if err != nil {
			c.AbortWithStatus(599)
			return
		}
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	g := r.Group("/api/v1/authorizations")
	g.POST("", il.authH.Create)
	g.PUT("/:id/accounts", il.authH.UpdateAccounts)
	g.DELETE("/:id", il.authH.Delete)
	r.POST("/api/v1/access-requests/:id/revoke", middleware.RequireRevokeEligibilityOn(il.e.fix, il.cat),
		api.NewAccessRequestHandler(il.reqSvc, nil, il.e.fix).Revoke)
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rw := httptest.NewRecorder()
	r.ServeHTTP(rw, req)
	return alsResp{code: rw.Code, body: rw.Body.String()}
}

// fixture 一組資料：範圍節點 in（操作者以 role 持授權規則管理）、範圍外節點 out、in 下的資產與主體。
type alsFx struct {
	op, role, subject, in, out, asset, rule uint
	reqID, itemID, ticket                   uint
}

func (il *alsIL) fixture(t *testing.T, tag string) alsFx {
	t.Helper()
	e := il.e
	il.seq++
	fx := alsFx{in: e.newNode(t, fmt.Sprintf("il-in-%s-%d", tag, il.seq)), out: e.newNode(t, fmt.Sprintf("il-out-%s-%d", tag, il.seq))}
	fx.op = e.human(t, fmt.Sprintf("il-op-%s-%d", tag, il.seq))
	fx.subject = e.human(t, fmt.Sprintf("il-sub-%s-%d", tag, il.seq))
	r := model.Role{Name: fmt.Sprintf("il-role-%s-%d", tag, il.seq), DefinitionVersion: 1}
	require.NoError(t, e.fix.Create(&r).Error)
	require.NoError(t, e.fix.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(authz.PermAuthorizationManage)}).Error)
	fx.role = r.ID
	require.NoError(t, e.fix.Create(&model.UserRole{UserID: fx.op, RoleID: r.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	require.NoError(t, e.fix.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: fx.op, RoleID: r.ID, NodeID: fx.in}).Error)
	a := model.Asset{Name: fmt.Sprintf("il-asset-%s-%d", tag, il.seq), Host: fmt.Sprintf("10.9.9.%d", il.seq), Port: 22,
		Protocol: model.ProtocolSSH, Active: true, CreatedBy: e.root}
	require.NoError(t, e.fix.Create(&a).Error)
	require.NoError(t, e.fix.Create(&model.AssetNode{AssetID: a.ID, NodeID: fx.in}).Error)
	fx.asset = a.ID
	return fx
}

func (il *alsIL) seedRule(t *testing.T, fx *alsFx) {
	t.Helper()
	r := model.AssetAuthorization{UserID: &fx.subject, AssetID: &fx.asset, Permission: model.PermissionConnect,
		GrantedBy: il.e.root, Accounts: model.AccountScope{model.AccountScopeAll}}
	require.NoError(t, il.e.fix.Create(&r).Error)
	fx.rule = r.ID
}

// seedTicket 他人核准的臨時授權單（操作者不是原核准人，資格只能來自授權規則管理範圍）。
func (il *alsIL) seedTicket(t *testing.T, fx *alsFx) {
	t.Helper()
	e := il.e
	now := time.Now()
	dur := 60
	start, expire := now.Add(-time.Minute), now.Add(time.Hour)
	approver := e.human(t, fmt.Sprintf("il-approver-%d", il.seq))
	a := model.AssetAuthorization{UserID: &fx.subject, AssetID: &fx.asset, Permission: model.PermissionConnect, GrantedBy: e.root,
		Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &expire, Accounts: model.AccountScope{model.AccountScopeAll}}
	require.NoError(t, e.fix.Create(&a).Error)
	req := model.AccessRequest{RequesterID: fx.subject, AssetID: fx.asset, Reason: "il", Kind: "normal", RequestedDurationMinutes: dur,
		Status: model.AccessRequestPending, ApproverID: &approver, PendingExpiresAt: now.Add(time.Hour)}
	require.NoError(t, e.fix.Create(&req).Error)
	require.NoError(t, e.fix.Model(&req).Update("status", model.AccessRequestApproved).Error)
	item := model.AccessRequestItem{RequestID: req.ID, RequesterID: fx.subject, AssetID: fx.asset, Accounts: model.AccountScope{model.AccountScopeAll},
		Status: model.AccessRequestPending, ApprovedDurationMinutes: &dur, ApprovedDateStart: &start, DecidedBy: &approver,
		AuthorizationID: &a.ID, PolicySnapshot: "{}"}
	require.NoError(t, e.fix.Create(&item).Error)
	require.NoError(t, e.fix.Model(&item).Update("status", model.AccessRequestApproved).Error)
	fx.reqID, fx.itemID, fx.ticket = req.ID, item.ID, a.ID
}

// keepOther 操作者另一筆不被撤除的節點範圍指派（另一節點、另一角色）：撤除 in 的指派後操作者仍持授權規則管理能力，
// 客體因此是「範圍外」而不是「無能力」，後行寫入的結果應與不存在的客體同形。
func (il *alsIL) keepOther(t *testing.T, fx *alsFx) {
	t.Helper()
	e := il.e
	keep := e.newNode(t, fmt.Sprintf("il-keep-%d", il.seq))
	r := model.Role{Name: fmt.Sprintf("il-role-keep-%d", il.seq), DefinitionVersion: 1}
	require.NoError(t, e.fix.Create(&r).Error)
	require.NoError(t, e.fix.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(authz.PermAuthorizationManage)}).Error)
	require.NoError(t, e.fix.Create(&model.UserRole{UserID: fx.op, RoleID: r.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	require.NoError(t, e.fix.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: fx.op, RoleID: r.ID, NodeID: keep}).Error)
}

// moveOut 正式資產更新入口：客體資產改掛到範圍外節點 out。
func (il *alsIL) moveOut(fx alsFx) func() error {
	return func() error {
		ids := []uint{fx.out}
		_, err := il.kit.assets.Update(asset.WithSystemCaller(il.e.rootCtx()), fx.asset, &asset.UpdateAssetRequest{NodeIDs: &ids})
		return err
	}
}

// unassign 撤除操作者在 in 上的節點範圍指派：交易開頭取正式拓撲序列化函式，再刪節點綁定與指派列。
func (il *alsIL) unassign(fx alsFx) func() error {
	return func() error {
		return il.mover.db.Transaction(func(tx *gorm.DB) error {
			if err := authz.LockScopeTopologyTx(tx); err != nil {
				return err
			}
			if err := tx.Where("subject_kind = ? AND subject_id = ? AND role_id = ?", model.BindingSubjectUser, fx.op, fx.role).
				Delete(&model.RoleBindingNode{}).Error; err != nil {
				return err
			}
			return tx.Where("user_id = ? AND role_id = ?", fx.op, fx.role).Delete(&model.UserRole{}).Error
		})
	}
}

type alsSide struct {
	name  string
	actor *pwloActor
	run   func() error
}

// interleave 先行者停在拓撲鎖取得後；後行者以嚴格等待證明確認停在拓撲鎖上之後才放行先行者。
func (il *alsIL) interleave(t *testing.T, subcase string, lead, follow alsSide) {
	t.Helper()
	e := il.e
	lead.actor.pool.reset()
	follow.actor.pool.reset()
	st := e.stops.arm(pwloSiteTopology)
	defer e.stops.disarm()
	defer st.open()
	leadRun := pwloGo(lead.run)
	var leadPID int64
	select {
	case leadPID = <-st.reached:
	case <-leadRun.done:
		t.Fatalf("%s：%s 未走到拓撲鎖停點就結束（err=%v）", subcase, lead.name, leadRun.err)
	case <-time.After(pwloDeadline):
		t.Fatalf("%s：%s 未在期限內走到拓撲鎖停點", subcase, lead.name)
	}
	require.NotEqual(t, int64(-1), leadPID)
	require.EqualValues(t, 1, pwloAdvisoryHeld(t, e.obs, leadPID, authz.TopologySerializationLockClass, 1), "%s 停在停點時應已持拓撲鎖", lead.name)
	followRun := pwloGo(follow.run)
	followPID := e.awaitBegin(t, follow.actor, followRun, follow.name, 0)
	proof, ok, why := pwloProveWait(t, e.obs, followPID, leadPID, pwloAdvisory(authz.TopologySerializationLockClass, 1), pwloProofBound, followRun)
	require.True(t, ok, "%s：%s 未被證明停在拓撲鎖上：%s", subcase, follow.name, why)
	require.Zero(t, pwloAdvisoryHeld(t, e.obs, followPID, authz.TopologySerializationLockClass, 1), "%s 等待時不得已持拓撲鎖", follow.name)
	require.False(t, followRun.finished(), "%s 在先行者放行前就已完成", follow.name)
	st.open()
	requirePWLOClean(t, lead.name, leadRun.wait(t, lead.name))
	requirePWLOClean(t, follow.name, followRun.wait(t, follow.name))
	fmt.Printf("ALS-INTERLEAVE subcase=%s lead=%s lead_pid=%d follow=%s follow_pid=%d confirmed=%v proof=%s\n",
		subcase, lead.name, leadPID, follow.name, followPID, ok, proof)
	fmt.Printf("EVIDENCE dialect=%s subcase=%s pids=lead:%d;follow:%d\n", follow.actor.db.Dialector.Name(), subcase, leadPID, followPID)
}

func (il *alsIL) count(t *testing.T, q string, args ...any) int64 { return il.e.scalar(t, q, args...) }

// runAuthorizationScopeInterleave (ii)、(iii)、2.4 帳號範圍調整與刪除、2.5 撤銷，各兩種先後。
func runAuthorizationScopeInterleave(t *testing.T, e *pwloEnv) {
	il := newALSInterleave(t, e)
	type pair struct {
		name     string
		prep     func(t *testing.T, fx *alsFx)
		topology func(fx alsFx) func() error
		write    func(fx alsFx) func() alsResp
		missing  func(fx alsFx) alsResp
		// unchanged 拓撲先提交時（寫入被判範圍外）資料不變；applied 寫入先提交時寫入結果已落地
		unchanged, applied func(t *testing.T, fx alsFx)
		denyCode           int
		denyHas            string
	}
	ruleCount := func(t *testing.T, fx alsFx) int64 {
		return il.count(t, "SELECT count(*) FROM asset_authorizations WHERE user_id = ? AND asset_id = ? AND deleted_at IS NULL", fx.subject, fx.asset)
	}
	grant := func(fx alsFx) func() alsResp {
		return func() alsResp {
			return il.http(t, fx.op, "POST", "/api/v1/authorizations", fmt.Sprintf(`{"user_id":%d,"asset_id":%d,"permission":"view"}`, fx.subject, fx.asset))
		}
	}
	grantMissing := func(fx alsFx) alsResp {
		return il.http(t, fx.op, "POST", "/api/v1/authorizations", fmt.Sprintf(`{"user_id":%d,"asset_id":%d,"permission":"view"}`, fx.subject, alsMissingID))
	}
	accountsOf := func(t *testing.T, id uint) string {
		var r model.AssetAuthorization
		require.NoError(t, e.fix.First(&r, id).Error)
		return strings.Join(r.Accounts, ",")
	}
	pairs := []pair{
		{name: "grant_vs_move_out", topology: il.moveOut, write: grant, missing: grantMissing, denyCode: http.StatusNotFound,
			unchanged: func(t *testing.T, fx alsFx) { require.Zero(t, ruleCount(t, fx)) },
			applied:   func(t *testing.T, fx alsFx) { require.EqualValues(t, 1, ruleCount(t, fx)) }},
		{name: "grant_vs_unassign_node_scope", prep: il.keepOther, topology: il.unassign, write: grant, missing: grantMissing, denyCode: http.StatusNotFound,
			unchanged: func(t *testing.T, fx alsFx) { require.Zero(t, ruleCount(t, fx)) },
			applied:   func(t *testing.T, fx alsFx) { require.EqualValues(t, 1, ruleCount(t, fx)) }},
		{name: "update_accounts_vs_move_out", prep: il.seedRule, topology: il.moveOut, denyCode: http.StatusNotFound,
			write: func(fx alsFx) func() alsResp {
				return func() alsResp {
					return il.http(t, fx.op, "PUT", fmt.Sprintf("/api/v1/authorizations/%d/accounts", fx.rule), `{"accounts":["root"]}`)
				}
			},
			missing: func(fx alsFx) alsResp {
				return il.http(t, fx.op, "PUT", fmt.Sprintf("/api/v1/authorizations/%d/accounts", alsMissingID), `{"accounts":["root"]}`)
			},
			unchanged: func(t *testing.T, fx alsFx) { require.Equal(t, model.AccountScopeAll, accountsOf(t, fx.rule)) },
			applied:   func(t *testing.T, fx alsFx) { require.Equal(t, "root", accountsOf(t, fx.rule)) }},
		{name: "delete_vs_move_out", prep: il.seedRule, topology: il.moveOut, denyCode: http.StatusNotFound,
			write: func(fx alsFx) func() alsResp {
				return func() alsResp {
					return il.http(t, fx.op, "DELETE", fmt.Sprintf("/api/v1/authorizations/%d", fx.rule), "")
				}
			},
			missing: func(fx alsFx) alsResp {
				return il.http(t, fx.op, "DELETE", fmt.Sprintf("/api/v1/authorizations/%d", alsMissingID), "")
			},
			unchanged: func(t *testing.T, fx alsFx) { require.EqualValues(t, 1, ruleCount(t, fx)) },
			applied:   func(t *testing.T, fx alsFx) { require.Zero(t, ruleCount(t, fx)) }},
		{name: "revoke_vs_move_out", prep: il.seedTicket, topology: il.moveOut, denyCode: http.StatusForbidden, denyHas: "RULE_ACCESS_TICKET_NOT_REVOKE_ELIGIBLE",
			write: func(fx alsFx) func() alsResp {
				return func() alsResp {
					return il.http(t, fx.op, "POST", fmt.Sprintf("/api/v1/access-requests/%d/revoke", fx.reqID), `{"note":"il-note"}`)
				}
			},
			unchanged: func(t *testing.T, fx alsFx) {
				require.EqualValues(t, 1, il.count(t, "SELECT count(*) FROM asset_authorizations WHERE id = ? AND deleted_at IS NULL", fx.ticket))
				require.EqualValues(t, 1, il.count(t, "SELECT count(*) FROM access_request_items WHERE id = ? AND status = ?", fx.itemID, model.AccessRequestApproved))
			},
			applied: func(t *testing.T, fx alsFx) {
				require.Zero(t, il.count(t, "SELECT count(*) FROM asset_authorizations WHERE id = ? AND deleted_at IS NULL", fx.ticket))
				require.EqualValues(t, 1, il.count(t, "SELECT count(*) FROM access_request_items WHERE id = ? AND status = ?", fx.itemID, model.AccessRequestItemRevoked))
			}},
	}
	topoDone := func(t *testing.T, p pair, fx alsFx) {
		if p.name == "grant_vs_unassign_node_scope" {
			require.Zero(t, il.count(t, "SELECT count(*) FROM role_binding_nodes WHERE subject_id = ? AND role_id = ?", fx.op, fx.role), "撤除應已完成")
			return
		}
		require.EqualValues(t, 1, il.count(t, "SELECT count(*) FROM asset_nodes WHERE asset_id = ? AND node_id = ?", fx.asset, fx.out), "搬移應已完成")
		require.EqualValues(t, 1, il.count(t, "SELECT count(*) FROM asset_nodes WHERE asset_id = ?", fx.asset), "搬移後只掛範圍外節點")
	}
	for _, p := range pairs {
		p := p
		t.Run("interleave_"+p.name+"/topology_first", func(t *testing.T) {
			fx := il.fixture(t, "t")
			if p.prep != nil {
				p.prep(t, &fx)
			}
			var got alsResp
			write := p.write(fx)
			il.interleave(t, "authorization_scope_interleave_"+p.name+"_topology_first",
				alsSide{name: "topology", actor: il.mover, run: p.topology(fx)},
				alsSide{name: "write", actor: il.w, run: func() error { got = write(); return nil }})
			require.Equal(t, p.denyCode, got.code, got.body)
			if p.denyHas != "" {
				require.Contains(t, got.body, p.denyHas)
			}
			if p.missing != nil {
				want := p.missing(fx)
				require.Equal(t, want.code, got.code, "依新狀態的拒絕須與不存在同形")
				require.Equal(t, want.body, got.body, "依新狀態的拒絕須與不存在同形")
			}
			require.NotContains(t, got.body, "il-")
			p.unchanged(t, fx)
			topoDone(t, p, fx)
			fmt.Printf("ALS-RESULT subcase=%s order=topology_first code=%d\n", p.name, got.code)
		})
		t.Run("interleave_"+p.name+"/write_first", func(t *testing.T) {
			fx := il.fixture(t, "w")
			if p.prep != nil {
				p.prep(t, &fx)
			}
			var got alsResp
			write := p.write(fx)
			il.interleave(t, "authorization_scope_interleave_"+p.name+"_write_first",
				alsSide{name: "write", actor: il.w, run: func() error { got = write(); return nil }},
				alsSide{name: "topology", actor: il.mover, run: p.topology(fx)})
			require.Equal(t, http.StatusOK, got.code, got.body)
			p.applied(t, fx)
			topoDone(t, p, fx)
			fmt.Printf("ALS-RESULT subcase=%s order=write_first code=%d\n", p.name, got.code)
		})
	}
}
