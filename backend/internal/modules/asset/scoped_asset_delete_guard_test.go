package asset_test

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 刪除與停用的歸屬規則、移出後的範圍、未分組資產與兩交易競態；PG 跑法另驗序列化鎖先於列鎖。
//
//	go test ./internal/modules/asset/ -run '^TestScopedAssetDeleteDisableGuard$' -count=1 -v
//	TEST_PG_DSN=... REQUIRE_INTEGRATION=1 go test ./internal/modules/asset/ -run '^TestScopedAssetDeleteDisableGuard$' -count=1 -v

func requireOutOfScopeNodes(t *testing.T, err error, count int, msg string) {
	t.Helper()
	var oos *asset.AssetOutOfScopeNodesError
	require.True(t, errors.As(err, &oos), "%s：應為範圍外歸屬錯誤，得到 %v", msg, err)
	assert.Equal(t, count, oos.Count, "%s：count＝範圍外歸屬數", msg)
}

func requireScopeDenied(t *testing.T, err error, msg string) {
	t.Helper()
	var denied *authz.ErrScopeDenied
	require.True(t, errors.As(err, &denied), "%s：應為與不存在同形的範圍拒絕，得到 %v", msg, err)
}

func (e *swEnv) connGrantCount(assetID uint) int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.AssetAuthorization{}).Where("asset_id = ?", assetID).Count(&n).Error)
	return n
}

// assertGuardedDecisions 受限主體每筆刪停裁決：成功者裁決當下不得有範圍外歸屬。
func assertGuardedDecisions(t *testing.T, e *swEnv, op asset.AssetWriteOp) {
	t.Helper()
	ds := e.rec.decisions(e.manager, op)
	require.Len(t, ds, 1, "受限主體恰有一次 %s 裁決", op)
	for _, d := range ds {
		t.Logf("decision actor=manager op=%s current=%v err=%v", op, e.names(d.current), d.err)
		if d.err == nil {
			assert.Equal(t, []string{"sw-a"}, e.names(d.current), "裁決成功時歸屬只有範圍內的 sw-a")
		} else {
			assert.Contains(t, e.names(d.current), "sw-b", "拒絕只應發生在已有範圍外歸屬時")
		}
	}
}

func TestScopedAssetDeleteDisableGuard(t *testing.T) {
	t.Run("multi_attribution_rejected", func(t *testing.T) {
		e := newSwEnv(t)
		id := e.asset("sw-multi", "sw-a", "sw-c", "sw-far")
		uid := e.super
		aid := id
		require.NoError(t, e.db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &aid,
			Permission: model.PermissionConnect, GrantedBy: e.super}).Error)
		grants := e.connGrantCount(id)
		v0, err := authz.CurrentVersion(e.db)
		require.NoError(t, err)

		requireOutOfScopeNodes(t, e.del(e.manager, id)(), 2, "刪除")
		requireOutOfScopeNodes(t, e.disable(e.manager, id)(), 2, "停用")
		exists, active := e.live(id)
		assert.True(t, exists && active, "資產仍在且啟用")
		assert.Equal(t, []string{"sw-a", "sw-c", "sw-far"}, e.mounted(id), "歸屬不變")
		assert.Equal(t, grants, e.connGrantCount(id), "授權不變")
		assert.Zero(t, e.term.calls.Load(), "進行中連線未收線")
		v1, err := authz.CurrentVersion(e.db)
		require.NoError(t, err)
		assert.Equal(t, v0, v1, "權限版本不變")
	})

	t.Run("move_out_then_out_of_scope", func(t *testing.T) {
		e := newSwEnv(t)
		id := e.asset("sw-leaving", "sw-a", "sw-c")
		require.NoError(t, e.setNodes(e.manager, id)(), "把範圍內節點全部移出是一次成功的更新")
		assert.Equal(t, []string{"sw-c"}, e.mounted(id))
		requireScopeDenied(t, e.del(e.manager, id)(), "移出後刪除")
		requireScopeDenied(t, e.disable(e.manager, id)(), "移出後停用")
		exists, active := e.live(id)
		assert.True(t, exists && active)
		require.ErrorIs(t, e.svc.Delete(e.ctx(e.manager), 987651), asset.ErrAssetNotFound,
			"不存在的資產（handler 以同一個 404 寫出兩者）")
	})

	t.Run("ungrouped", func(t *testing.T) {
		e := newSwEnv(t)
		holder := e.user("sw-global-holder")
		e.grantGlobal(holder, e.role(authz.PermAssetView, authz.PermAssetUpdate, authz.PermAssetDelete))
		a1 := e.asset("sw-ungrouped-1")
		a2 := e.asset("sw-ungrouped-2")
		requireScopeDenied(t, e.del(e.manager, a1)(), "只持節點範圍者刪除未分組資產")
		requireScopeDenied(t, e.disable(e.manager, a1)(), "只持節點範圍者停用未分組資產")
		require.NoError(t, e.disable(holder, a1)(), "持全域指派的非超管照現行可停用")
		_, active := e.live(a1)
		assert.False(t, active)
		require.NoError(t, e.del(holder, a2)(), "持全域指派的非超管照現行可刪除")
		exists, _ := e.live(a2)
		assert.False(t, exists)
	})

	t.Run("race_delete_vs_superadmin_mount", func(t *testing.T) {
		t.Run("mount_commits_first", func(t *testing.T) {
			e := newSwEnv(t)
			id := e.asset("sw-race-del-1", "sw-a")
			errMount, errDel := runOrdered(t, e.setNodes(e.super, id, "sw-a", "sw-b"), e.del(e.manager, id))
			require.NoError(t, errMount)
			requireOutOfScopeNodes(t, errDel, 1, "加掛先提交：刪除看到範圍外歸屬")
			exists, _ := e.live(id)
			assert.True(t, exists, "資產仍在")
			assert.Equal(t, []string{"sw-a", "sw-b"}, e.mounted(id))
			assertGuardedDecisions(t, e, asset.AssetWriteDelete)
		})
		t.Run("delete_commits_first", func(t *testing.T) {
			e := newSwEnv(t)
			id := e.asset("sw-race-del-2", "sw-a")
			errDel, errMount := runOrdered(t, e.del(e.manager, id), e.setNodes(e.super, id, "sw-a", "sw-b"))
			require.NoError(t, errDel, "刪除先提交：裁決時只有範圍內歸屬")
			require.Error(t, errMount, "資產已不存在，後到的加掛失敗")
			exists, _ := e.live(id)
			assert.False(t, exists)
			assertGuardedDecisions(t, e, asset.AssetWriteDelete)
		})
	})

	t.Run("race_disable_vs_superadmin_mount", func(t *testing.T) {
		t.Run("mount_commits_first", func(t *testing.T) {
			e := newSwEnv(t)
			id := e.asset("sw-race-off-1", "sw-a")
			errMount, errOff := runOrdered(t, e.setNodes(e.super, id, "sw-a", "sw-b"), e.disable(e.manager, id))
			require.NoError(t, errMount)
			requireOutOfScopeNodes(t, errOff, 1, "加掛先提交：停用看到範圍外歸屬")
			_, active := e.live(id)
			assert.True(t, active, "資產維持啟用")
			assert.Zero(t, e.term.calls.Load(), "被拒的停用不收線")
			assertGuardedDecisions(t, e, asset.AssetWriteDisable)
		})
		t.Run("disable_commits_first", func(t *testing.T) {
			e := newSwEnv(t)
			id := e.asset("sw-race-off-2", "sw-a")
			errOff, errMount := runOrdered(t, e.disable(e.manager, id), e.setNodes(e.super, id, "sw-a", "sw-b"))
			require.NoError(t, errOff, "停用先提交：停用合法完成")
			require.NoError(t, errMount, "其後加掛已停用的資產同樣合法")
			_, active := e.live(id)
			assert.False(t, active)
			assert.Equal(t, []string{"sw-a", "sw-b"}, e.mounted(id), "終態停用且掛 A＋B 為合法終態")
			assertGuardedDecisions(t, e, asset.AssetWriteDisable)
		})
	})

	t.Run("lock_before_row_locks", func(t *testing.T) {
		if os.Getenv(testgate.EnvPGDSN) == "" {
			t.Skip("SQLite 沒有列鎖與 advisory 鎖：本子案例只在 PostgreSQL 跑法執行")
		}
		runLockBeforeRowLocks(t)
	})

	if !t.Failed() && os.Getenv(testgate.EnvPGDSN) != "" {
		fmt.Println("EVIDENCE dialect=postgres")
		t.Log("EVIDENCE dialect=postgres")
	}
}
