package asset

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// --- 夾具：沿用專用帳號的 sqlite 夾具（真取密、真憑證表），加上盤點表與可計數的來源 ---

type countingFetcher struct {
	inner inventoryCredentialFetcher
	calls atomic.Int32
}

func (f *countingFetcher) GetWithCredentialsForAccount(assetID, accountID uint) (*AssetCredentials, error) {
	f.calls.Add(1)
	return f.inner.GetWithCredentialsForAccount(assetID, accountID)
}

type countingResolver struct {
	inner inventoryExecutorResolver
	calls atomic.Int32
}

func (r *countingResolver) ResolveExecutorCredentials(ctx context.Context, assetID uint, pin ExecutorPin) (*ExecutorCredentials, error) {
	r.calls.Add(1)
	return r.inner.ResolveExecutorCredentials(ctx, assetID, pin)
}

type execInvEnv struct {
	*delegEnv
	svc      *HostAccountInventoryService
	fetch    *countingFetcher
	resolve  *countingResolver
	limiter  *executorCheckLimiter
	executor bool
}

func newExecInvEnv(t *testing.T, withExecutor bool) *execInvEnv {
	t.Helper()
	if os.Getenv(envChangeSecretFixturePG) == "" {
		t.Skip("需要 PostgreSQL 夾具（盤點的發起交易內會經全域連線取預設帳號密文，單連線的記憶體資料庫會互鎖）")
	}
	d := newDelegEnv(t)
	sqlDB, err := d.db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(8)
	require.NoError(t, d.db.AutoMigrate(&model.HostAccountScan{}, &model.HostAccountFinding{}))
	e := &execInvEnv{delegEnv: d, fetch: &countingFetcher{inner: d.assets}}
	e.resolve = &countingResolver{inner: d.assets}
	e.limiter = newExecutorCheckLimiter()
	e.svc = NewHostAccountInventoryService(d.db, e.fetch, nil, invPolicies{}, audit.NewTxSink(), &invAlertSink{})
	e.svc.UseExecutorIdentity(e.resolve, e.limiter)
	e.svc.hostKeyFor = func(HostKeyDialContext) ssh.HostKeyCallback { return ssh.InsecureIgnoreHostKey() }
	e.svc.collect = func(context.Context, uint, string, *AssetCredentials, ssh.HostKeyCallback, string) (*invScanResult, *inventoryError) {
		return nil, &inventoryError{Reason: model.InventoryLoginFailed}
	}
	if withExecutor {
		d.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
		d.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		e.executor = true
	}
	return e
}

func (e *execInvEnv) scanCount(t *testing.T, assetID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.HostAccountScan{}).Where("asset_id = ?", assetID).Count(&n).Error)
	return n
}

func (e *execInvEnv) initiateCount(t *testing.T, assetID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.AuditLog{}).Where("action = ? AND asset_id = ?", model.ActionInventoryScan, assetID).Count(&n).Error)
	return n
}

func (e *execInvEnv) mount(t *testing.T) model.AssetAccount {
	t.Helper()
	var m model.AssetAccount
	require.NoError(t, e.db.Where("asset_id = ? AND purpose = ?", e.assetID, model.AccountPurposeExecutor).First(&m).Error)
	return m
}

// executorQueryInjector 只對「讀專用帳號掛載」那一種查詢注入錯誤，並計數；其他查詢照常。
type executorQueryInjector struct {
	armed      atomic.Bool
	matched    atomic.Int32
	fired      atomic.Int32
	assetReads atomic.Int32
	assetErrs  atomic.Int32
	failOnNth  int32
}

func installExecutorInjector(t *testing.T, db *gorm.DB, failOnNth int32) *executorQueryInjector {
	t.Helper()
	inj := &executorQueryInjector{failOnNth: failOnNth}
	name := "test:inject_executor_mount_" + t.Name()
	require.NoError(t, db.Callback().Query().After("gorm:query").Register(name, func(tx *gorm.DB) {
		if !inj.armed.Load() {
			return
		}
		sql := tx.Statement.SQL.String()
		if strings.Contains(sql, "FROM `assets`") || strings.Contains(sql, `FROM "assets"`) {
			inj.assetReads.Add(1)
			if tx.Error != nil {
				inj.assetErrs.Add(1)
			}
			return
		}
		if !strings.Contains(sql, "asset_accounts") || !strings.Contains(sql, "purpose") {
			return
		}
		hasExecutorArg := false
		for _, v := range tx.Statement.Vars {
			if s, ok := v.(string); ok && s == model.AccountPurposeExecutor {
				hasExecutorArg = true
			}
		}
		if !hasExecutorArg {
			return
		}
		n := inj.matched.Add(1)
		if n == inj.failOnNth {
			inj.fired.Add(1)
			_ = tx.AddError(errors.New("injected: executor mount read failed"))
		}
	}))
	t.Cleanup(func() { _ = db.Callback().Query().Remove(name) })
	return inj
}

func TestInventoryExecutorIdentity(t *testing.T) {
	t.Run("同時有預設與專用帳號時用專用帳號", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		s, err := e.svc.Initiate(e.assetID, invAdmin)
		require.NoError(t, err)
		e.svc.Wait()
		assert.Equal(t, model.HostAccountIdentityExecutor, s.IdentityMode)
		assert.Equal(t, e.mount(t).ID, s.IdentityAccountID)
		assert.Zero(t, e.fetch.calls.Load(), "發起路徑不取預設帳號密文")
	})
	t.Run("只有預設帳號時為預設帳號身分", func(t *testing.T) {
		e := newExecInvEnv(t, false)
		s, err := e.svc.Initiate(e.assetID, invAdmin)
		require.NoError(t, err)
		e.svc.Wait()
		assert.Equal(t, model.HostAccountIdentityDefault, s.IdentityMode)
		assert.Zero(t, e.resolve.calls.Load(), "沒有專用帳號不碰專用帳號取密")
	})
	t.Run("專用帳號沒有就位版本", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", e.mount(t).ID).Update("effective_version_id", nil).Error)
		_, err := e.svc.Initiate(e.assetID, invAdmin)
		assert.ErrorIs(t, err, ErrInventoryExecutorUnavailable)
		assert.Zero(t, e.scanCount(t, e.assetID))
		assert.Zero(t, e.fetch.calls.Load(), "不退回預設帳號")
		assert.Zero(t, e.resolve.calls.Load(), "發起路徑不解封")
	})
	t.Run("憑證整組輪替中", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", e.mount(t).CredentialID).Update("active_rotation_id", 7).Error)
		_, err := e.svc.Initiate(e.assetID, invAdmin)
		assert.ErrorIs(t, err, ErrInventoryExecutorBusy)
		assert.Zero(t, e.scanCount(t, e.assetID))
		assert.Zero(t, e.fetch.calls.Load())
		assert.Zero(t, e.resolve.calls.Load())
	})
	t.Run("有未驗證候選", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		require.NoError(t, e.db.Create(&model.ChangeSecretCandidate{
			AccountID: e.mount(t).ID, AssetID: e.assetID, SecretType: model.ChangeSecretTypePassword,
		}).Error)
		_, err := e.svc.Initiate(e.assetID, invAdmin)
		assert.ErrorIs(t, err, ErrInventoryExecutorBusy)
		assert.Zero(t, e.scanCount(t, e.assetID))
		assert.Zero(t, e.resolve.calls.Load())
	})
	t.Run("讀專用帳號掛載出錯時失敗關閉", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		inj := installExecutorInjector(t, e.db, 1)
		inj.armed.Store(true)
		_, err := e.svc.Initiate(e.assetID, invAdmin)
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrInventoryNoAccount) || errors.Is(err, ErrInventoryExecutorUnavailable) || errors.Is(err, ErrInventoryExecutorBusy))
		assert.EqualValues(t, 1, inj.matched.Load(), "相符查詢恰一次")
		assert.EqualValues(t, 1, inj.fired.Load(), "注入恰觸發一次")
		assert.GreaterOrEqual(t, inj.assetReads.Load(), int32(1), "讀資產的查詢已執行")
		assert.Zero(t, inj.assetErrs.Load(), "讀資產沒有被注入")
		inj.armed.Store(false)
		assert.Zero(t, e.scanCount(t, e.assetID))
		assert.Zero(t, e.initiateCount(t, e.assetID))
		assert.Zero(t, e.fetch.calls.Load(), "不退回預設帳號")
	})
	t.Run("目標身分桶封頂並與測試登入共用", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		e.limiter.target = newTokenBucketTable(3, time.Hour, 16)
		// 第二筆資產指向同一撥號位址，專用帳號名相同
		var a1 model.Asset
		require.NoError(t, e.db.First(&a1, e.assetID).Error)
		a2 := model.Asset{Name: "second", Host: a1.Host, Port: a1.Port, Protocol: model.ProtocolSSH, RotationChannel: model.RotationChannelPosixSSH}
		require.NoError(t, e.db.Create(&a2).Error)
		m := e.mount(t)
		m2 := model.AssetAccount{AssetID: a2.ID, CredentialID: m.CredentialID, Username: m.Username,
			Purpose: model.AccountPurposeExecutor, EffectiveVersionID: m.EffectiveVersionID}
		require.NoError(t, e.db.Create(&m2).Error)
		ids := []uint{e.assetID, a2.ID, e.assetID}
		for _, id := range ids {
			_, err := e.svc.Initiate(id, invAdmin)
			require.NoError(t, err)
			e.svc.Wait()
		}
		_, err := e.svc.Initiate(a2.ID, invAdmin)
		assert.ErrorIs(t, err, ErrInventoryExecutorRateLimited)
		assert.EqualValues(t, 1, e.scanCount(t, a2.ID), "第 4 筆不建列")
		assert.EqualValues(t, 1, e.initiateCount(t, a2.ID), "第 4 筆不寫發起審計")

		// 測試登入先用盡同一個桶，盤點同樣被擋
		e.limiter.target = newTokenBucketTable(3, time.Hour, 16)
		key := executorTargetKey(a1.Host, a1.Port, m.Username)
		for range 3 {
			require.True(t, e.limiter.allowTarget(key))
		}
		_, err = e.svc.Initiate(e.assetID, invAdmin)
		assert.ErrorIs(t, err, ErrInventoryExecutorRateLimited)
	})
	t.Run("預設帳號模式連發不受目標身分桶限制", func(t *testing.T) {
		e := newExecInvEnv(t, false)
		e.limiter.target = newTokenBucketTable(1, time.Hour, 16)
		for range 5 {
			_, err := e.svc.Initiate(e.assetID, invAdmin)
			require.NoError(t, err)
			e.svc.Wait()
		}
	})
}

func TestExecutorPrecheckMatchesResolve(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, e *execInvEnv)
		want   error
	}{
		{"正常", func(*testing.T, *execInvEnv) {}, nil},
		{"沒有就位版本", func(t *testing.T, e *execInvEnv) {
			require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", e.mount(t).ID).Update("effective_version_id", nil).Error)
		}, ErrInventoryExecutorUnavailable},
		{"輪替中", func(t *testing.T, e *execInvEnv) {
			require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", e.mount(t).CredentialID).Update("active_rotation_id", 9).Error)
		}, ErrInventoryExecutorBusy},
		{"有候選", func(t *testing.T, e *execInvEnv) {
			require.NoError(t, e.db.Create(&model.ChangeSecretCandidate{AccountID: e.mount(t).ID, AssetID: e.assetID, SecretType: model.ChangeSecretTypePassword}).Error)
		}, ErrInventoryExecutorBusy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newExecInvEnv(t, true)
			pin, err := readExecutorPin(e.db, e.assetID)
			require.NoError(t, err)
			c.mutate(t, e)
			m := e.mount(t)
			got := executorPrecheck(e.db, &m)
			ec, rerr := e.assets.ResolveExecutorCredentials(context.Background(), e.assetID, *pin)
			if ec != nil {
				ec.Destroy()
			}
			if c.want == nil {
				assert.NoError(t, got)
				return
			}
			assert.ErrorIs(t, got, c.want)
			switch {
			case errors.Is(got, ErrInventoryExecutorBusy):
				assert.ErrorIs(t, rerr, ErrExecutorBusy, "取密與前置檢查分類相同")
			default:
				assert.True(t, errors.Is(rerr, ErrExecutorUnavailable) || errors.Is(rerr, ErrExecutorChanged), "取密：%v", rerr)
			}
		})
	}
}

func TestInventoryReadIdentityFields(t *testing.T) {
	seedScan := func(t *testing.T, e *execInvEnv, mode string, accountID uint) {
		t.Helper()
		now := time.Now()
		require.NoError(t, e.db.Create(&model.HostAccountScan{AssetID: e.assetID, Platform: "posix", IdentityMode: mode,
			IdentityAccountID: accountID, InitiatedBy: 1, Status: model.HostAccountScanSucceeded, PrivilegedGroups: "root",
			Coverage: "[]", StartedAt: &now, FinishedAt: &now}).Error)
	}
	t.Run("專用帳號列不含帳號名且結果清單的同名帳號照常出現", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		seedScan(t, e, model.HostAccountIdentityExecutor, e.mount(t).ID)
		require.NoError(t, e.db.Create(&model.HostAccountFinding{AssetID: e.assetID, Username: delegExecutorUser, Present: true,
			Status: model.HostAccountFindingOpen, FirstSeenScanID: 1, LastSeenScanID: 1, FirstSeenAt: time.Now(), LastSeenAt: time.Now()}).Error)
		view, err := e.svc.GetAssetInventory(e.assetID, InventoryFindingQuery{})
		require.NoError(t, err)
		require.NotNil(t, view.Scan)
		assert.Empty(t, view.Scan.IdentityUsername)
		require.NotNil(t, view.NextIdentity)
		assert.Equal(t, InventoryNextIdentity{Mode: "executor"}, *view.NextIdentity)
		require.Len(t, view.Findings, 1)
		assert.Equal(t, delegExecutorUser, view.Findings[0].Username)
		// 登入身分欄位不含專用帳號名：把 scan 與 next_identity 序列化後檢查
		b, err := json.Marshal(map[string]any{"scan": view.Scan, "next_identity": view.NextIdentity})
		require.NoError(t, err)
		assert.NotContains(t, string(b), delegExecutorUser)
	})
	t.Run("預設帳號列在帳號被刪除後仍回名稱", func(t *testing.T) {
		e := newExecInvEnv(t, false)
		var def model.AssetAccount
		require.NoError(t, e.db.Where("asset_id = ? AND is_default = ?", e.assetID, true).First(&def).Error)
		seedScan(t, e, model.HostAccountIdentityDefault, def.ID)
		require.NoError(t, e.db.Delete(&def).Error)
		view, err := e.svc.GetAssetInventory(e.assetID, InventoryFindingQuery{})
		require.NoError(t, err)
		assert.Equal(t, def.Username, view.Scan.IdentityUsername)
		assert.Nil(t, view.NextIdentity, "預設帳號已刪除、也沒有專用帳號")
	})
	t.Run("next_identity 在清除專用帳號前後各一種", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		var def model.AssetAccount
		require.NoError(t, e.db.Where("asset_id = ? AND is_default = ?", e.assetID, true).First(&def).Error)
		view, err := e.svc.GetAssetInventory(e.assetID, InventoryFindingQuery{})
		require.NoError(t, err)
		assert.Equal(t, &InventoryNextIdentity{Mode: "executor", Username: ""}, view.NextIdentity)
		require.NoError(t, e.db.Delete(&model.AssetAccount{}, e.mount(t).ID).Error)
		view, err = e.svc.GetAssetInventory(e.assetID, InventoryFindingQuery{})
		require.NoError(t, err)
		assert.Equal(t, &InventoryNextIdentity{Mode: "default_account", Username: def.Username}, view.NextIdentity)
	})
	t.Run("讀專用帳號掛載出錯時回錯而不是預設帳號", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		inj := installExecutorInjector(t, e.db, 1)
		inj.armed.Store(true)
		view, err := e.svc.GetAssetInventory(e.assetID, InventoryFindingQuery{})
		require.Error(t, err)
		assert.Nil(t, view)
		assert.EqualValues(t, 1, inj.matched.Load())
		assert.EqualValues(t, 1, inj.fired.Load())
		assert.GreaterOrEqual(t, inj.assetReads.Load(), int32(1))
		assert.Zero(t, inj.assetErrs.Load())
	})
	t.Run("RDP 資產為 null", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", e.assetID).Updates(map[string]any{"protocol": model.ProtocolRDP}).Error)
		view, err := e.svc.GetAssetInventory(e.assetID, InventoryFindingQuery{})
		require.NoError(t, err)
		assert.Nil(t, view.NextIdentity)
	})
}
