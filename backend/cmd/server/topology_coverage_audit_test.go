package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 拓撲變更的涵蓋差異審計與只改描述留痕：正式接線的節點樹服務（拓撲鎖、範圍判定、引用查詢、涵蓋快照），
// 審計落地面可切換為失敗以驗回滾。

var errTcaAuditInjected = errors.New("tca: injected audit failure")

// tcaSink 正式交易內審計落地面；fail 為真時回錯誤。
type tcaSink struct {
	inner port.TxSink
	fail  *atomic.Bool
}

func (s tcaSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	if s.fail.Load() {
		return errTcaAuditInjected
	}
	return s.inner.WriteInTx(tx, ev)
}

type tcaEnv struct {
	t     *testing.T
	db    *gorm.DB
	svc   *asset.AssetGroupService
	fail  *atomic.Bool
	super uint
	seq   int
}

func newTcaEnv(t *testing.T, injectCoverage bool) *tcaEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // :memory: 每條連線各自一個庫
	require.NoError(t, db.AutoMigrate(&model.AssetGroup{}, &model.AssetNode{}, &model.Asset{}, &model.AuditLog{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.User{}, &model.Role{}, &model.RolePermission{},
		&model.AuthzState{}, &model.PermissionStateEvent{}, &model.UserGroup{}))
	require.NoError(t, db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{},
		&model.Credential{})) // 節點刪除承接歸屬該節點的共用憑證
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)

	fail := &atomic.Bool{}
	topo := asset.NewScopeTopologyReader()
	svc := asset.NewAssetGroupService(db, tcaSink{inner: audit.NewTxSink(), fail: fail}, authz.NewAssetAuthorizationService(db))
	svc.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	svc.SetNodeWriteScopePort(authz.NewNodeWriteScope(authz.NewScopeEvaluator(authz.ProductCatalogue(), topo)))
	svc.SetNodeScopeReferencePort(authz.NewNodeScopeReferenceReader())
	if injectCoverage {
		svc.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(topo))
	}
	e := &tcaEnv{t: t, db: db, svc: svc, fail: fail}
	e.super = e.user("tca-super")
	var role model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&role).Error; err != nil {
		role = model.Role{Name: model.RoleAdmin}
		require.NoError(t, db.Create(&role).Error)
	}
	require.NoError(t, db.Create(&model.UserRole{UserID: e.super, RoleID: role.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	return e
}

func (e *tcaEnv) user(name string) uint {
	e.t.Helper()
	u := model.User{Username: name, Password: "x", Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

func (e *tcaEnv) group(name string) uint {
	e.t.Helper()
	g := model.UserGroup{Name: name}
	require.NoError(e.t, e.db.Create(&g).Error)
	return g.ID
}

func (e *tcaEnv) node(name string, parent *uint) uint {
	e.t.Helper()
	g := model.AssetGroup{Name: name, ParentID: parent}
	require.NoError(e.t, e.db.Create(&g).Error)
	return g.ID
}

// asset 建資產並掛到 nodes。
func (e *tcaEnv) asset(nodes ...uint) uint {
	e.t.Helper()
	e.seq++
	a := model.Asset{Name: fmt.Sprintf("tca-asset-%d", e.seq), Protocol: model.ProtocolSSH,
		Host: fmt.Sprintf("10.66.%d.%d", e.seq/250, e.seq%250+1), Port: 22, CreatedBy: e.super, Active: true}
	require.NoError(e.t, e.db.Create(&a).Error)
	for _, n := range nodes {
		require.NoError(e.t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: n}).Error)
	}
	return a.ID
}

func (e *tcaEnv) nodeGrant(userID, nodeID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.AssetAuthorization{UserID: &userID, AssetGroupID: &nodeID,
		Permission: model.PermissionConnect, GrantedBy: e.super}).Error)
}

func (e *tcaEnv) assetGrant(userID, assetID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.AssetAuthorization{UserID: &userID, AssetID: &assetID,
		Permission: model.PermissionConnect, GrantedBy: e.super}).Error)
}

func (e *tcaEnv) groupApproverOn(groupID, nodeID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.ApproverScope{ApproverGroupID: &groupID, AssetGroupID: &nodeID,
		GrantedBy: e.super}).Error)
}

func (e *tcaEnv) ctx() context.Context {
	return authz.ContextWithPrincipal(context.Background(), &authz.Principal{UserID: e.super})
}

func (e *tcaEnv) move(id uint, parent *uint) error {
	_, err := e.svc.Move(e.ctx(), id, parent, e.super, "tca-super", "127.0.0.1")
	return err
}

func (e *tcaEnv) update(id uint, name, desc string) error {
	_, err := e.svc.Update(e.ctx(), id, &asset.AssetGroupRequest{Name: name, Description: desc}, e.super, "tca-super", "127.0.0.1")
	return err
}

// serviceAudits 節點服務寫入的成功審計列（resource＝asset、resource_id＝節點）。
func (e *tcaEnv) serviceAudits(nodeID uint) []model.AuditLog {
	e.t.Helper()
	var rows []model.AuditLog
	require.NoError(e.t, e.db.Where("resource = ? AND resource_id = ? AND status = ?",
		model.ResourceAsset, nodeID, model.StatusSuccess).Order("id").Find(&rows).Error)
	return rows
}

func (e *tcaEnv) parentOf(id uint) *uint {
	e.t.Helper()
	var g model.AssetGroup
	require.NoError(e.t, e.db.First(&g, id).Error)
	return g.ParentID
}

func (e *tcaEnv) version() int64 {
	e.t.Helper()
	v, err := authz.CurrentVersion(e.db)
	require.NoError(e.t, err)
	return v
}

// tcaCoverage 審計 details 的 topology_coverage。
type tcaCoverage struct {
	Assets    asset.CoverageDelta[uint]                  `json:"assets"`
	Grants    asset.CoverageDelta[asset.CoverageGrant]   `json:"grants"`
	Approvers asset.CoverageDelta[asset.CoverageSubject] `json:"approvers"`
	Managers  asset.CoverageDelta[asset.CoverageManager] `json:"managers"`
}

// lastMoveCoverage 節點最後一筆服務審計的 topology_coverage（必須存在）。
func (e *tcaEnv) lastMoveCoverage(nodeID uint) tcaCoverage {
	e.t.Helper()
	rows := e.serviceAudits(nodeID)
	require.NotEmpty(e.t, rows)
	var details map[string]json.RawMessage
	require.NoError(e.t, json.Unmarshal([]byte(rows[len(rows)-1].Details), &details))
	raw, ok := details["topology_coverage"]
	require.True(e.t, ok, "搬移審計須附 topology_coverage：%s", rows[len(rows)-1].Details)
	var c tcaCoverage
	require.NoError(e.t, json.Unmarshal(raw, &c))
	return c
}

func ptrU(v uint) *uint { return &v }

func TestTopologyCoverageAudit(t *testing.T) {
	t.Run("snapshot_grants_match_node_grant_query", func(t *testing.T) {
		e := newTcaEnv(t, true)
		root := e.node("cov-root", nil)
		child := e.node("cov-child", ptrU(root))
		other := e.node("cov-other", nil)
		a1, a2, a3 := e.asset(child), e.asset(root), e.asset(other)
		u1, u2, direct := e.user("cov-u1"), e.user("cov-u2"), e.user("cov-direct")
		e.nodeGrant(u1, root)
		e.nodeGrant(u2, child)
		e.assetGrant(direct, a3)
		snap, err := authz.NewTopologyCoverageReader(asset.NewScopeTopologyReader()).CoverageSnapshot(e.db, []uint{a1, a2, a3})
		require.NoError(t, err)
		acl := authz.NewAssetAuthorizationService(e.db)
		for _, a := range []uint{a1, a2, a3} {
			for _, u := range []uint{u1, u2} {
				want, err := acl.CheckPermission(context.Background(), u, a, model.PermissionConnect)
				require.NoError(t, err)
				got := false
				for _, g := range snap.Assets[a].Grants {
					if g.Kind == model.BindingSubjectUser && g.ID == u && g.Level == string(model.PermissionConnect) {
						got = true
					}
				}
				assert.Equal(t, want, got, "資產 %d 使用者 %d：快照與既有節點授權查詢須一致", a, u)
			}
		}
		// 直接授予資產的授權：既有查詢可及，但不出現在快照
		viaACL, err := acl.CheckPermission(context.Background(), direct, a3, model.PermissionConnect)
		require.NoError(t, err)
		require.True(t, viaACL)
		for _, a := range []uint{a1, a2, a3} {
			for _, g := range snap.Assets[a].Grants {
				assert.NotEqual(t, direct, g.ID, "直接授予資產的授權不得出現在快照（資產 %d）", a)
			}
		}
	})

	t.Run("move_without_snapshot_fails_closed", func(t *testing.T) {
		e := newTcaEnv(t, false)
		src := e.node("nc-src", nil)
		dst := e.node("nc-dst", nil)
		e.asset(src)
		// 夾具建資產本身可能留下同資源類別、同 ID 的審計列：只驗搬移前後沒有多出任何一列
		before := e.serviceAudits(src)
		err := e.move(src, ptrU(dst))
		require.ErrorIs(t, err, asset.ErrCoverageSnapshotPortMissing)
		assert.Nil(t, e.parentOf(src), "未注入涵蓋快照時樹不得改變")
		assert.Equal(t, before, e.serviceAudits(src), "未注入涵蓋快照時搬移不得留下任何服務審計列")
	})

	t.Run("build_coverage_input_order_independent", func(t *testing.T) {
		before := asset.CoverageSnapshot{Assets: map[uint]asset.AssetCoverage{
			3: {Grants: []asset.CoverageGrant{{Kind: "user", ID: 9, Level: "connect"}, {Kind: "user", ID: 2, Level: "connect"}},
				Approvers: []asset.CoverageSubject{{Kind: "user_group", ID: 4}, {Kind: "user", ID: 1}}},
			1: {Managers: []asset.CoverageManager{{Kind: "user", ID: 5, RoleID: 7}, {Kind: "user_group", ID: 2, RoleID: 3}}},
		}}
		after := asset.CoverageSnapshot{Assets: map[uint]asset.AssetCoverage{
			3: {Grants: []asset.CoverageGrant{{Kind: "user", ID: 2, Level: "connect"}, {Kind: "user_group", ID: 8, Level: "connect"}}},
			1: {Managers: []asset.CoverageManager{{Kind: "user_group", ID: 2, RoleID: 3}},
				Approvers: []asset.CoverageSubject{{Kind: "user", ID: 6}}},
			2: {Grants: []asset.CoverageGrant{{Kind: "user", ID: 11, Level: "connect"}}},
		}}
		reverse := func(s asset.CoverageSnapshot) asset.CoverageSnapshot {
			out := asset.CoverageSnapshot{Assets: map[uint]asset.AssetCoverage{}}
			for _, id := range []uint{2, 1, 3} {
				c, ok := s.Assets[id]
				if !ok {
					continue
				}
				r := asset.AssetCoverage{}
				for i := len(c.Grants) - 1; i >= 0; i-- {
					r.Grants = append(r.Grants, c.Grants[i])
				}
				for i := len(c.Approvers) - 1; i >= 0; i-- {
					r.Approvers = append(r.Approvers, c.Approvers[i])
				}
				for i := len(c.Managers) - 1; i >= 0; i-- {
					r.Managers = append(r.Managers, c.Managers[i])
				}
				out.Assets[id] = r
			}
			return out
		}
		first, err := asset.MarshalTopologyCoverage(asset.BuildTopologyCoverage(before, after))
		require.NoError(t, err)
		second, err := asset.MarshalTopologyCoverage(asset.BuildTopologyCoverage(reverse(before), reverse(after)))
		require.NoError(t, err)
		assert.Equal(t, first, second, "不同輸入順序的序列化結果須逐位元組相同")
	})

	t.Run("move_records_gains_and_losses", func(t *testing.T) {
		e := newTcaEnv(t, true)
		u := e.user("gain-u")
		dst := e.node("gain-dst", nil)
		e.nodeGrant(u, dst)
		mover := e.node("gain-mover", nil)
		a, b := e.asset(mover), e.asset(mover)
		require.NoError(t, e.move(mover, ptrU(dst)))
		c := e.lastMoveCoverage(mover)
		assert.Equal(t, []uint{a, b}, c.Assets.Gained.Items, "搬入有連線授權的節點：A、B 列為得到")
		assert.Contains(t, c.Grants.Gained.Items, asset.CoverageGrant{Kind: model.BindingSubjectUser, ID: u, Level: string(model.PermissionConnect)})

		g := e.group("loss-g")
		scope := e.node("loss-scope", nil)
		e.groupApproverOn(g, scope)
		leaving := e.node("loss-leaving", ptrU(scope))
		lost := e.asset(leaving)
		multi := e.asset(leaving, scope) // 另一歸屬仍在審核範圍內
		require.NoError(t, e.move(leaving, nil))
		c = e.lastMoveCoverage(leaving)
		assert.Equal(t, []uint{lost}, c.Assets.Lost.Items, "搬出審核範圍節點：C 列為失去，多歸屬仍受涵蓋者不列")
		assert.NotContains(t, c.Assets.Lost.Items, multi)
		assert.Contains(t, c.Approvers.Lost.Items, asset.CoverageSubject{Kind: model.BindingSubjectUserGroup, ID: g})
	})

	t.Run("operator_widening_own_scope_is_recorded", func(t *testing.T) {
		e := newTcaEnv(t, true)
		mine := e.node("self-mine", nil)
		e.nodeGrant(e.super, mine)
		mover := e.node("self-mover", nil)
		e.asset(mover)
		require.NoError(t, e.move(mover, ptrU(mine)), "涵蓋擴大不得拒絕")
		c := e.lastMoveCoverage(mover)
		assert.Contains(t, c.Grants.Gained.Items, asset.CoverageGrant{Kind: model.BindingSubjectUser, ID: e.super, Level: string(model.PermissionConnect)},
			"操作者為自己擴大連線範圍時本人列為得到者")
	})

	t.Run("empty_delta_still_attached", func(t *testing.T) {
		e := newTcaEnv(t, true)
		x := e.node("empty-x", nil)
		y := e.node("empty-y", nil)
		e.asset(x)
		require.NoError(t, e.move(x, ptrU(y)))
		c := e.lastMoveCoverage(x)
		for name, total := range map[string]int{
			"assets.gained": c.Assets.Gained.Total, "assets.lost": c.Assets.Lost.Total,
			"grants.gained": c.Grants.Gained.Total, "grants.lost": c.Grants.Lost.Total,
			"approvers.gained": c.Approvers.Gained.Total, "approvers.lost": c.Approvers.Lost.Total,
			"managers.gained": c.Managers.Gained.Total, "managers.lost": c.Managers.Lost.Total,
		} {
			assert.Zero(t, total, name)
		}
	})

	t.Run("over_limit_truncates_to_smallest_ids", func(t *testing.T) {
		e := newTcaEnv(t, true)
		u := e.user("big-u")
		dst := e.node("big-dst", nil)
		e.nodeGrant(u, dst)
		big := e.node("big-mover", nil)
		var ids []uint
		for i := 0; i < asset.CoverageListLimit+5; i++ {
			ids = append(ids, e.asset(big))
		}
		require.NoError(t, e.move(big, ptrU(dst)))
		c := e.lastMoveCoverage(big)
		assert.Equal(t, len(ids), c.Assets.Gained.Total)
		assert.Len(t, c.Assets.Gained.Items, asset.CoverageListLimit)
		assert.Equal(t, ids[:asset.CoverageListLimit], c.Assets.Gained.Items, "清單為最小的 100 個識別碼")
		assert.True(t, c.Assets.Gained.Truncated)
	})

	t.Run("one_service_row_and_rollback_on_audit_failure", func(t *testing.T) {
		e := newTcaEnv(t, true)
		u := e.user("rb-u")
		dst := e.node("rb-dst", nil)
		e.nodeGrant(u, dst)
		mover := e.node("rb-mover", nil)
		e.asset(mover)
		require.NoError(t, e.move(mover, ptrU(dst)))
		assert.Len(t, e.serviceAudits(mover), 1, "搬移只寫一筆服務審計列")

		other := e.node("rb-other", nil)
		v0 := e.version()
		e.fail.Store(true)
		err := e.move(mover, ptrU(other))
		e.fail.Store(false)
		require.ErrorIs(t, err, errTcaAuditInjected)
		assert.Equal(t, dst, *e.parentOf(mover), "審計寫入失敗：樹回滾")
		assert.Equal(t, v0, e.version(), "審計寫入失敗：權限版本回滾")
		assert.Len(t, e.serviceAudits(mover), 1)
	})

	t.Run("response_body_omits_coverage", func(t *testing.T) {
		e := newTcaEnv(t, true)
		u := e.user("resp-u")
		dst := e.node("resp-dst", nil)
		e.nodeGrant(u, dst)
		mover := e.node("resp-mover", nil)
		e.asset(mover)
		h := api.NewAssetGroupHandler(e.svc, nil, nil)
		r := gin.New()
		r.Use(func(c *gin.Context) {
			p, err := authz.ResolveUserOnWithCatalogue(e.db, authz.ProductCatalogue(), e.super, authz.TokenFacts{})
			require.NoError(t, err)
			middleware.SetPrincipal(c, p)
			c.Set("userID", e.super)
			c.Set("username", "tca-super")
			c.Next()
		})
		r.PUT("/asset-groups/:id/move", h.Move)
		body, _ := json.Marshal(map[string]any{"parent_id": dst})
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/asset-groups/%d/move", mover), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.NotContains(t, w.Body.String(), "topology_coverage")
		e.lastMoveCoverage(mover) // 審計列上仍附
	})

	t.Run("describe_only_update_is_audited", func(t *testing.T) {
		e := newTcaEnv(t, true)
		n := e.node("desc-node", nil)
		require.NoError(t, e.update(n, "desc-node", "first"))
		rows := e.serviceAudits(n)
		require.Len(t, rows, 1, "只改描述多一筆服務審計")
		var d map[string]map[string]string
		require.NoError(t, json.Unmarshal([]byte(rows[0].Details), &d))
		assert.Equal(t, map[string]string{"old": "", "new": "first"}, d["asset_node_describe"])
		assert.NotContains(t, d, "asset_node_rename")
		assert.Equal(t, string(model.ActionUpdate), string(rows[0].Action))

		e.fail.Store(true)
		err := e.update(n, "desc-node", "second")
		e.fail.Store(false)
		require.ErrorIs(t, err, errTcaAuditInjected)
		var g model.AssetGroup
		require.NoError(t, e.db.First(&g, n).Error)
		assert.Equal(t, "first", g.Description, "審計失敗時描述維持原值")

		require.NoError(t, e.update(n, "desc-renamed", "third"))
		rows = e.serviceAudits(n)
		require.Len(t, rows, 2, "同時改名與改描述只多一筆")
		require.NoError(t, json.Unmarshal([]byte(rows[1].Details), &d))
		assert.Equal(t, map[string]string{"old": "desc-node", "new": "desc-renamed"}, d["asset_node_rename"])
		assert.Equal(t, map[string]string{"old": "first", "new": "third"}, d["asset_node_describe"])

		require.NoError(t, e.update(n, "desc-renamed", "third"))
		assert.Len(t, e.serviceAudits(n), 2, "名稱與描述皆不變不多審計列")
		assert.False(t, strings.Contains(rows[1].Details, "topology_coverage"))
	})
}
