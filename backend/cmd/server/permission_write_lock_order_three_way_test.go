package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TestPermissionWriteLockOrder 子案例 (e) three_way_group_delete（三方交錯）：
// 群組 G 含成員 m；T拓撲＝刪除節點 N（G 在 N 上有節點授權，RevokeByAssetGroup）或刪除資產 A
// （G 對 A 有資產授權，RevokeByAsset），都持拓撲鎖去軟刪 G 的那一列 asset_authorizations；
// T群組＝真 UserGroupService 刪除 G（成員預取在群組列鎖之後、Begin 之前）；
// T授權＝持 m 的使用者鎖後取拓撲鎖、寫一筆以 m 為主體、指向另一未刪節點 M 的授權列
// （最小替身寫法：WithUserCredentialLock(m) 內呼叫序列化函式後 INSERT，granted_by 為 root）。
// 兩種排列（偶數輪甲、奇數輪乙，各 10 輪）：
//   - 甲：T拓撲停在「已取拓撲鎖、尚未級聯」；T授權持 m 的使用者鎖等拓撲鎖；T群組在預取 m 時等 T授權。
//   - 乙：T群組停在 afterCascadeRevoke（已預取、已軟刪該列、尚未推進版本）；T拓撲等該列、T授權等 m 的使用者鎖。

// pwloGate 不帶交易的停點（群組刪除掛點）：走到時通知、等放行。
type pwloGate struct {
	reached chan struct{}
	release chan struct{}
	fired   sync.Once
	rel     sync.Once
}

func (g *pwloGate) open() { g.rel.Do(func() { close(g.release) }) }

// pwloGroupHooks 群組刪除兩個停點的計數與（乙排列的）閘門。
type pwloGroupHooks struct {
	prefetched atomic.Int32
	cascaded   atomic.Int32
	mu         sync.Mutex
	gate       *pwloGate
}

func (h *pwloGroupHooks) arm() *pwloGate {
	g := &pwloGate{reached: make(chan struct{}), release: make(chan struct{})}
	h.mu.Lock()
	h.gate = g
	h.mu.Unlock()
	return g
}

func (h *pwloGroupHooks) disarm() {
	h.mu.Lock()
	h.gate = nil
	h.mu.Unlock()
}

func (h *pwloGroupHooks) afterCascade() {
	h.cascaded.Add(1)
	h.mu.Lock()
	g := h.gate
	h.mu.Unlock()
	if g == nil {
		return
	}
	first := false
	g.fired.Do(func() { first = true })
	if !first {
		return
	}
	close(g.reached)
	select {
	case <-g.release:
	case <-time.After(pwloDeadline):
	}
}

type pwloThreeWay struct {
	e      *pwloEnv
	leaf   string
	hooks  *pwloGroupHooks
	topo   pwloParty
	group  pwloParty
	grant  pwloParty
	setup  func(t *testing.T, tag string) *pwloFixture
	topoDB string // snap：T拓撲刪除的表
}

func runThreeWayGroupDelete(t *testing.T, leaf string) {
	subcase := "three_way_group_delete/" + leaf
	e := newPWLOEnv(t, subcase, true, "topo", "group", "grant")
	e.installTopologyStop(t)
	h := &pwloGroupHooks{}
	t.Cleanup(identity.SetGroupDeleteLockHooksForTest(func() { h.prefetched.Add(1) }, h.afterCascade))
	c := e.threeWayCase(t, leaf, h)

	e.attested = e.checkAttestation(t)
	legal := map[string]string{}
	perms := [][3]pwloParty{
		{c.topo, c.group, c.grant}, {c.topo, c.grant, c.group}, {c.group, c.topo, c.grant},
		{c.group, c.grant, c.topo}, {c.grant, c.topo, c.group}, {c.grant, c.group, c.topo},
	}
	for i, order := range perms {
		fx := c.setup(t, fmt.Sprintf("seq%d", i))
		require.Equal(t, e.attested, e.checkAttestation(t), "附證狀態在子案例內改變")
		label := ""
		for _, p := range order {
			requirePWLOClean(t, p.name, p.run(fx))
			if label != "" {
				label += "->"
			}
			label += p.name
		}
		key := pwloSnapKey(c.snap(t, fx))
		if legal[key] != "" {
			legal[key] += "|"
		}
		legal[key] += label
		fmt.Printf("SEQUENTIAL subcase=%s order=%s result=%s\n", subcase, label, key)
	}
	confirmed := [2]int{}
	for r := 0; r < pwloRounds; r++ {
		perm := r % 2
		fx := c.setup(t, fmt.Sprintf("r%02d", r))
		require.Equal(t, e.attested, e.checkAttestation(t), "附證狀態在子案例內改變")
		if c.round(t, fx, perm, r, legal) {
			confirmed[perm]++
		}
	}
	fmt.Printf("SUMMARY subcase=%s rounds=%d confirmed_jia=%d confirmed_yi=%d\n", subcase, pwloRounds, confirmed[0], confirmed[1])
	require.GreaterOrEqual(t, confirmed[0], 1, "甲排列沒有任何一輪確認重疊")
	require.GreaterOrEqual(t, confirmed[1], 1, "乙排列沒有任何一輪確認重疊")
	fmt.Printf("EVIDENCE dialect=%s subcase=%s pids=%s attested=%v\n", e.fix.Dialector.Name(), subcase, e.pidSummary(), e.attested)
}

func (e *pwloEnv) threeWayCase(t *testing.T, leaf string, h *pwloGroupHooks) *pwloThreeWay {
	t.Helper()
	// groupDeleteParty 綁的是 e.actor("group")（真 UserGroupService，級聯撤銷走真 RevokeByUserGroup）
	c := &pwloThreeWay{e: e, leaf: leaf, hooks: h, group: e.groupDeleteParty()}
	switch leaf {
	case "node_delete":
		kit := e.assetKit(t, "topo")
		c.topo = pwloParty{name: "node_delete", actor: "topo", run: func(fx *pwloFixture) error {
			_, err := kit.groups.Delete(e.nodeCtx(), fx.node, e.root, "pwlo-root", pwloClientIP)
			return err
		}}
		c.topoDB = "asset_groups"
	case "asset_delete":
		kit := e.assetKit(t, "topo")
		c.topo = pwloParty{name: "asset_delete", actor: "topo", run: func(fx *pwloFixture) error {
			return kit.assets.Delete(asset.WithSystemCaller(context.Background()), fx.asset)
		}}
		c.topoDB = "assets"
	default:
		t.Fatalf("未知葉子 %s", leaf)
	}
	c.topo.stopSite = pwloSiteTopology
	c.grant = pwloParty{name: "grant_write", actor: "grant", run: func(fx *pwloFixture) error {
		return identity.WithUserCredentialLock(e.actor("grant").db, fx.user, func(tx *gorm.DB) error {
			if err := authz.LockScopeTopologyTx(tx); err != nil {
				return err
			}
			m, other := fx.user, fx.other
			return tx.Create(&model.AssetAuthorization{UserID: &m, AssetGroupID: &other, Permission: model.PermissionConnect,
				Source: "manual", GrantedBy: e.root}).Error
		})
	}}
	c.setup = func(t *testing.T, tag string) *pwloFixture {
		fx := &pwloFixture{user: e.human(t, "pwlo-e-m-"+tag), group: e.newGroup(t, "e-"+tag), other: e.newNode(t, "e-M-"+tag)}
		require.NoError(t, e.fix.Create(&model.UserGroupMember{UserGroupID: fx.group, UserID: fx.user, Manual: true}).Error)
		g := fx.group
		a := model.AssetAuthorization{UserGroupID: &g, Permission: model.PermissionConnect, Source: "manual", GrantedBy: e.root}
		if leaf == "node_delete" {
			fx.node = e.newNode(t, "e-N-"+tag)
			n := fx.node
			a.AssetGroupID = &n
		} else {
			fx.node = e.newNode(t, "e-X-"+tag)
			as := model.Asset{Name: "pwlo-e-asset-" + tag, Host: "10.9.5.1", Port: 5901, Protocol: model.ProtocolVNC, Active: true}
			require.NoError(t, e.fix.Create(&as).Error)
			fx.asset = as.ID
			require.NoError(t, e.fix.Create(&model.AssetNode{AssetID: as.ID, NodeID: fx.node}).Error)
			id := as.ID
			a.AssetID = &id
		}
		require.NoError(t, e.fix.Create(&a).Error)
		fx.authz = a.ID
		fx.version = e.version(t)
		return fx
	}
	return c
}

func (c *pwloThreeWay) snap(t *testing.T, fx *pwloFixture) map[string]int64 {
	e := c.e
	target := fx.node
	if c.leaf == "asset_delete" {
		target = fx.asset
	}
	return map[string]int64{
		"group_deleted":   e.deleted(t, "user_groups", fx.group),
		"members":         e.scalar(t, "SELECT count(*) FROM user_group_members WHERE user_group_id = ?", fx.group),
		"topo_deleted":    e.deleted(t, c.topoDB, target),
		"g_authz_deleted": e.deleted(t, "asset_authorizations", fx.authz),
		"g_authz_live":    e.scalar(t, "SELECT count(*) FROM asset_authorizations WHERE user_group_id = ? AND deleted_at IS NULL", fx.group),
		"m_grant_live":    e.scalar(t, "SELECT count(*) FROM asset_authorizations WHERE user_id = ? AND asset_group_id = ? AND deleted_at IS NULL", fx.user, fx.other),
		"other_live":      e.scalar(t, "SELECT count(*) FROM asset_groups WHERE id = ? AND deleted_at IS NULL", fx.other),
		"version_delta":   e.version(t) - fx.version,
	}
}

// round 一輪三方交錯；回傳本輪兩個嚴格等待證明是否都成立。
func (c *pwloThreeWay) round(t *testing.T, fx *pwloFixture, perm, round int, legal map[string]string) bool {
	t.Helper()
	e := c.e
	topoA, groupA, grantA := e.actor("topo"), e.actor("group"), e.actor("grant")
	topoA.pool.reset()
	groupA.pool.reset()
	grantA.pool.reset()
	c.hooks.prefetched.Store(0)
	c.hooks.cascaded.Store(0)
	topoClass := authz.TopologySerializationLockClass
	userLock := pwloUserLock(fx.user)

	var topoRun, groupRun, grantRun *pwloRun
	var topoPID, groupPID, grantPID int64
	var p1, p2 pwloProof
	var ok1, ok2 bool
	var why1, why2, label string
	var release func()

	if perm == 0 {
		label = "jia"
		st := e.stops.arm(pwloSiteTopology)
		defer e.stops.disarm()
		defer st.open()
		release = st.open
		topoRun = pwloGo(func() error { return c.topo.run(fx) })
		select {
		case topoPID = <-st.reached:
		case <-topoRun.done:
			t.Fatalf("round %d：%s 未走到拓撲鎖停點就結束（err=%v）", round, c.topo.name, topoRun.err)
		case <-time.After(pwloDeadline):
			t.Fatalf("round %d：%s 未在期限內走到拓撲鎖停點", round, c.topo.name)
		}
		began := topoA.pool.began()
		require.Len(t, began, 1, "%s 在停點前應只開了一筆交易", c.topo.name)
		require.Equal(t, began[0], topoPID, "停點的 pid 應等於 %s 交易開始時取得的 pid", c.topo.name)
		require.EqualValues(t, 1, pwloAdvisoryHeld(t, e.obs, topoPID, topoClass, 1), "%s 停在停點時應已持有拓撲鎖", c.topo.name)
		e.requireRowsFree(t, c.topo.name+" 停在「已取拓撲鎖、尚未級聯」", pwloRowRef{"asset_authorizations", fx.authz})

		grantRun = pwloGo(func() error { return c.grant.run(fx) })
		grantPID = e.awaitBegin(t, grantA, grantRun, c.grant.name, round)
		p1, ok1, why1 = pwloProveWait(t, e.obs, grantPID, topoPID, pwloAdvisory(topoClass, 1), pwloProofBound, grantRun)
		if ok1 {
			require.EqualValues(t, 1, pwloAdvisoryHeld(t, e.obs, grantPID, pwloUserCredentialLockClass, int64(uint32(fx.user))),
				"round %d：%s 在拓撲鎖上等待時應已持有 m 的使用者憑證鎖", round, c.grant.name)
		}
		groupRun = pwloGo(func() error { return c.group.run(fx) })
		groupPID = e.awaitBegin(t, groupA, groupRun, c.group.name, round)
		p2, ok2, why2 = pwloProveWait(t, e.obs, groupPID, grantPID, userLock, pwloProofBound, groupRun)
		if ok2 {
			// 預取在權限列之前：T群組在 m 的使用者鎖上等待時，級聯撤銷（與預取完成）的停點都尚未觸發
			require.Zero(t, c.hooks.cascaded.Load(), "round %d：T群組在預取 m 時等待，afterCascadeRevoke 不得已觸發", round)
			require.Zero(t, c.hooks.prefetched.Load(), "round %d：T群組在預取 m 時等待，afterPrefetch 不得已觸發", round)
		}
	} else {
		label = "yi"
		gate := c.hooks.arm()
		defer c.hooks.disarm()
		defer gate.open()
		release = gate.open
		groupRun = pwloGo(func() error { return c.group.run(fx) })
		select {
		case <-gate.reached:
		case <-groupRun.done:
			t.Fatalf("round %d：%s 未走到 afterCascadeRevoke 就結束（err=%v）", round, c.group.name, groupRun.err)
		case <-time.After(pwloDeadline):
			t.Fatalf("round %d：%s 未在期限內走到 afterCascadeRevoke", round, c.group.name)
		}
		began := groupA.pool.began()
		require.Len(t, began, 1, "%s 在停點前應只開了一筆交易", c.group.name)
		groupPID = began[0]
		require.EqualValues(t, 1, c.hooks.prefetched.Load(), "afterCascadeRevoke 之前應已完成成員預取")
		require.EqualValues(t, 1, pwloAdvisoryHeld(t, e.obs, groupPID, pwloUserCredentialLockClass, int64(uint32(fx.user))),
			"%s 停在 afterCascadeRevoke 時應已持有 m 的使用者憑證鎖", c.group.name)

		topoRun = pwloGo(func() error { return c.topo.run(fx) })
		topoPID = e.awaitBegin(t, topoA, topoRun, c.topo.name, round)
		p1, ok1, why1 = pwloProveWait(t, e.obs, topoPID, groupPID, pwloRowLock(), pwloProofBound, topoRun)
		if ok1 {
			require.EqualValues(t, 1, pwloAdvisoryHeld(t, e.obs, topoPID, topoClass, 1),
				"round %d：%s 在權限列上等待時應已持有拓撲鎖", round, c.topo.name)
		}
		grantRun = pwloGo(func() error { return c.grant.run(fx) })
		grantPID = e.awaitBegin(t, grantA, grantRun, c.grant.name, round)
		p2, ok2, why2 = pwloProveWait(t, e.obs, grantPID, groupPID, userLock, pwloProofBound, grantRun)
	}

	release()
	errTopo := topoRun.wait(t, c.topo.name)
	errGroup := groupRun.wait(t, c.group.name)
	errGrant := grantRun.wait(t, c.grant.name)
	e.notePIDs(c.topo.name, topoPID)
	e.notePIDs(c.group.name, groupPID)
	e.notePIDs(c.grant.name, grantPID)
	ok := ok1 && ok2
	fmt.Printf("ROUND subcase=%s round=%02d perm=%s topo_pid=%d group_pid=%d grant_pid=%d confirmed=%v proof1=%s proof2=%s topo_sqlstate=%s group_sqlstate=%s grant_sqlstate=%s topo_err=%q group_err=%q grant_err=%q reason1=%q reason2=%q\n",
		e.subcase, round, label, topoPID, groupPID, grantPID, ok, p1, p2,
		pwloStateLabel(errTopo), pwloStateLabel(errGroup), pwloStateLabel(errGrant),
		pwloErrText(errTopo), pwloErrText(errGroup), pwloErrText(errGrant), why1, why2)
	requirePWLOClean(t, c.topo.name, errTopo)
	requirePWLOClean(t, c.group.name, errGroup)
	requirePWLOClean(t, c.grant.name, errGrant)

	key := pwloSnapKey(c.snap(t, fx))
	order, legalOK := legal[key]
	require.True(t, legalOK, "round %d：最終資料 %s 不等於任何一種依序執行的結果 %v", round, key, legal)
	fmt.Printf("ROUND-DATA subcase=%s round=%02d result=%s matches=%s\n", e.subcase, round, key, order)
	return ok
}
