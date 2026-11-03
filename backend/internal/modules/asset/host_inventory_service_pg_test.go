package asset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/testgate"
)

// --- 測試環境：自建 schema 的 PostgreSQL、可注入失敗的審計與告警落地面、可換密文的取密來源 ---

type invPolicies map[string]string

func (p invPolicies) Get(k string) string { return p[k] }

type invSecrets struct {
	mu  sync.Mutex
	pws map[uint]string
}

func (f *invSecrets) set(accountID uint, pw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pws[accountID] = pw
}

func (f *invSecrets) GetWithCredentialsForAccount(assetID, accountID uint) (*AssetCredentials, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pw, ok := f.pws[accountID]
	if !ok {
		return nil, ErrAssetAccountNotFound
	}
	var acc model.AssetAccount
	c := &AssetCredentials{AccountID: accountID, Username: "ops"}
	if database := invCurrentDB; database != nil && database.Unscoped().First(&acc, accountID).Error == nil {
		c.Username = acc.Username
	}
	if pw != "" {
		c.Password = material.Adopt([]byte(pw))
	}
	return c, nil
}

var invCurrentDB *gorm.DB

type invAuditSink struct {
	mu   sync.Mutex
	real port.TxSink
	fail string // 此 action 寫入時失敗
}

func (s *invAuditSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail != "" && ev.Action == fail {
		return errors.New("audit write injected failure")
	}
	return s.real.WriteInTx(tx, ev)
}

type invAlertSink struct {
	mu     sync.Mutex
	events []port.SystemAlertEvent
	fail   bool
}

func (s *invAlertSink) RaiseInTx(tx *gorm.DB, ev port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return port.SystemAlertReceipt{}, errors.New("alert write injected failure")
	}
	s.events = append(s.events, ev)
	return port.SystemAlertReceipt{AlertID: uint(len(s.events))}, nil
}

func (s *invAlertSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

type invEnv struct {
	t       *testing.T
	db      *gorm.DB
	svc     *HostAccountInventoryService
	secrets *invSecrets
	audits  *invAuditSink
	alerts  *invAlertSink
	tg      *invTarget
}

func openInventoryPG(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	schema := fmt.Sprintf("inv_%d", time.Now().UnixNano())
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{
		Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	require.NoError(t, db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.AuditLog{},
		&model.HostAccountScan{}, &model.HostAccountFinding{}))
	// 部分索引只存在於 migration DDL（與正式 migration 同句）
	require.NoError(t, db.Exec(`CREATE UNIQUE INDEX uniq_host_account_scans_active ON host_account_scans USING btree (asset_id) WHERE status IN ('queued','running')`).Error)
	require.NoError(t, db.Exec(`CREATE INDEX idx_host_account_findings_open_privileged ON host_account_findings USING btree (asset_id) WHERE status = 'open' AND privileged AND present`).Error)
	return db
}

func newInvEnv(t *testing.T) *invEnv {
	t.Helper()
	db := openInventoryPG(t)
	invCurrentDB = db
	t.Cleanup(func() { invCurrentDB = nil })
	e := &invEnv{t: t, db: db, secrets: &invSecrets{pws: map[uint]string{}},
		audits: &invAuditSink{real: audit.NewTxSink()}, alerts: &invAlertSink{}}
	e.tg = newInvTarget(t, "pw")
	e.tg.setStandard("0\n", stdPasswd, stdGroup, sudoFrames(false, nil, "absent"))
	e.svc = NewHostAccountInventoryService(db, e.secrets, nil, invPolicies{"host_privileged_groups_posix": "root,sudo,wheel,admin"}, e.audits, e.alerts)
	e.svc.hostKeyFor = func(HostKeyDialContext) ssh.HostKeyCallback { return e.tg.hostKeyCallback() }
	return e
}

// asset 建一台指向行程內靶機的 SSH 資產與其預設帳號（用戶名 root）。
func (e *invEnv) asset(name string) (uint, uint) {
	e.t.Helper()
	host, port := splitHostPortT(e.t, e.tg.addr())
	a := model.Asset{Name: name, Host: host, Port: port, Protocol: model.ProtocolSSH}
	require.NoError(e.t, e.db.Create(&a).Error)
	acc := model.AssetAccount{AssetID: a.ID, CredentialID: 1, Username: "root", IsDefault: true}
	require.NoError(e.t, e.db.Create(&acc).Error)
	e.secrets.set(acc.ID, "pw")
	return a.ID, acc.ID
}

func splitHostPortT(t *testing.T, addr string) (string, int) {
	i := strings.LastIndex(addr, ":")
	var p int
	_, err := fmt.Sscanf(addr[i+1:], "%d", &p)
	require.NoError(t, err)
	return addr[:i], p
}

func (e *invEnv) scan(id uint) model.HostAccountScan {
	e.t.Helper()
	var s model.HostAccountScan
	require.NoError(e.t, e.db.First(&s, id).Error)
	return s
}

func (e *invEnv) findings(assetID uint) []model.HostAccountFinding {
	e.t.Helper()
	var fs []model.HostAccountFinding
	require.NoError(e.t, e.db.Where("asset_id = ?", assetID).Order("username").Find(&fs).Error)
	return fs
}

func (e *invEnv) finding(assetID uint, user string) model.HostAccountFinding {
	e.t.Helper()
	var f model.HostAccountFinding
	require.NoError(e.t, e.db.Where("asset_id = ? AND username = ?", assetID, user).Take(&f).Error)
	return f
}

func (e *invEnv) auditCount(action model.AuditAction, scanID uint) int64 {
	var n int64
	require.NoError(e.t, e.db.Model(&model.AuditLog{}).Where("action = ? AND resource_id = ?", action, scanID).Count(&n).Error)
	return n
}

// runScan 發起並等它結束。
func (e *invEnv) runScan(assetID uint) model.HostAccountScan {
	e.t.Helper()
	s, err := e.svc.Initiate(assetID, InventoryActor{UserID: 1, Username: "admin"})
	require.NoError(e.t, err)
	e.svc.Wait()
	return e.scan(s.ID)
}

var invAdmin = InventoryActor{UserID: 1, Username: "admin"}

// blockingCollector 擋到 release 關閉為止，然後交回預設行為。
func (e *invEnv) blockingCollector() (started chan struct{}, release chan struct{}) {
	started, release = make(chan struct{}, 8), make(chan struct{})
	e.svc.collect = func(ctx context.Context, scanID uint, addr string, creds *AssetCredentials, hk ssh.HostKeyCallback, pg string) (*invScanResult, *inventoryError) {
		started <- struct{}{}
		<-release
		return defaultInventoryCollector(ctx, scanID, addr, creds, hk, pg)
	}
	return started, release
}

func TestInventoryInitiate(t *testing.T) {
	t.Run("兩個併發發起只成功一個", func(t *testing.T) {
		e := newInvEnv(t)
		assetID, _ := e.asset("i1")
		_, release := e.blockingCollector()
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = e.svc.Initiate(assetID, invAdmin)
			}(i)
		}
		wg.Wait()
		ok, conflict := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrInventoryScanRunning):
				conflict++
			default:
				t.Fatalf("非預期錯誤：%v", err)
			}
		}
		close(release)
		e.svc.Wait()
		assert.Equal(t, 1, ok)
		assert.Equal(t, 1, conflict)
		var n int64
		e.db.Model(&model.HostAccountScan{}).Where("asset_id = ?", assetID).Count(&n)
		assert.EqualValues(t, 1, n)
	})
	t.Run("不在登記表的running列收為中斷後新發起成功", func(t *testing.T) {
		e := newInvEnv(t)
		assetID, accID := e.asset("i2")
		now := time.Now()
		orphan := model.HostAccountScan{AssetID: assetID, Platform: "posix", IdentityMode: "default_account",
			IdentityAccountID: accID, InitiatedBy: 1, Status: model.HostAccountScanRunning, PrivilegedGroups: "root", StartedAt: &now}
		require.NoError(t, e.db.Create(&orphan).Error)
		s := e.runScan(assetID)
		assert.Equal(t, model.HostAccountScanSucceeded, s.Status)
		o := e.scan(orphan.ID)
		assert.Equal(t, model.HostAccountScanInterrupted, o.Status)
		assert.Equal(t, model.InventoryInterrupted, o.FailureReason)
		assert.EqualValues(t, 1, e.auditCount(model.ActionInventoryScanDone, orphan.ID), "殘留收尾寫結束審計")
	})
	t.Run("仍在登記表的回衝突", func(t *testing.T) {
		e := newInvEnv(t)
		assetID, _ := e.asset("i3")
		started, release := e.blockingCollector()
		first, err := e.svc.Initiate(assetID, invAdmin)
		require.NoError(t, err)
		<-started
		_, err = e.svc.Initiate(assetID, invAdmin)
		assert.ErrorIs(t, err, ErrInventoryScanRunning)
		close(release)
		e.svc.Wait()
		assert.Equal(t, model.HostAccountScanSucceeded, e.scan(first.ID).Status)
		assert.EqualValues(t, 1, e.auditCount(model.ActionInventoryScan, first.ID))
	})
}

func TestInventoryWorker(t *testing.T) {
	t.Run("工作panic後該筆中斷且下一筆照常", func(t *testing.T) {
		e := newInvEnv(t)
		assetID, _ := e.asset("w1")
		e.svc.collect = func(context.Context, uint, string, *AssetCredentials, ssh.HostKeyCallback, string) (*invScanResult, *inventoryError) {
			panic("boom")
		}
		s := e.runScan(assetID)
		assert.Equal(t, model.HostAccountScanInterrupted, s.Status)
		assert.Equal(t, model.InventoryInterrupted, s.FailureReason)
		assert.EqualValues(t, 1, e.auditCount(model.ActionInventoryScanDone, s.ID))
		e.svc.collect = defaultInventoryCollector
		s2 := e.runScan(assetID)
		assert.Equal(t, model.HostAccountScanSucceeded, s2.Status)
	})
	recheck := func(t *testing.T, mutate func(e *invEnv, assetID, accID uint), want string) {
		e := newInvEnv(t)
		assetID, accID := e.asset("w2")
		for range inventoryWorkerSlots {
			e.svc.slots <- struct{}{}
		}
		s, err := e.svc.Initiate(assetID, invAdmin)
		require.NoError(t, err)
		mutate(e, assetID, accID)
		for range inventoryWorkerSlots {
			<-e.svc.slots
		}
		e.svc.Wait()
		got := e.scan(s.ID)
		assert.Equal(t, model.HostAccountScanFailed, got.Status)
		assert.Equal(t, want, got.FailureReason)
		e.tg.mu.Lock()
		hs := e.tg.handshakes
		e.tg.mu.Unlock()
		assert.Zero(t, hs, "靶機零連線")
	}
	t.Run("等待期間預設帳號換掉", func(t *testing.T) {
		recheck(t, func(e *invEnv, assetID, accID uint) {
			require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", accID).Update("is_default", false).Error)
			other := model.AssetAccount{AssetID: assetID, CredentialID: 1, Username: "ops", IsDefault: true}
			require.NoError(t, e.db.Create(&other).Error)
			e.secrets.set(other.ID, "pw")
		}, model.InventoryNoAccount)
	})
	t.Run("資產刪除", func(t *testing.T) {
		recheck(t, func(e *invEnv, assetID, _ uint) {
			require.NoError(t, e.db.Delete(&model.Asset{}, assetID).Error)
		}, model.InventoryAssetChanged)
	})
	t.Run("密文清空", func(t *testing.T) {
		recheck(t, func(e *invEnv, _, accID uint) { e.secrets.set(accID, "") }, model.InventoryNoSecret)
	})
	t.Run("失敗不動既有結果", func(t *testing.T) {
		e := newInvEnv(t)
		assetID, _ := e.asset("w3")
		require.Equal(t, model.HostAccountScanSucceeded, e.runScan(assetID).Status)
		before := e.findings(assetID)
		require.NotEmpty(t, before)
		e.tg.set(2, invResponse{Out: "", Exit: 2})
		s := e.runScan(assetID)
		require.Equal(t, model.HostAccountScanFailed, s.Status)
		assert.Equal(t, before, e.findings(assetID))
	})
	t.Run("十萬列合成輸出寫入", func(t *testing.T) {
		e := newInvEnv(t)
		assetID, accID := e.asset("w4")
		now := time.Now()
		scan := model.HostAccountScan{AssetID: assetID, Platform: "posix", IdentityMode: "default_account",
			IdentityAccountID: accID, InitiatedBy: 1, InitiatedByName: "admin", Status: model.HostAccountScanRunning,
			PrivilegedGroups: "root", StartedAt: &now}
		require.NoError(t, e.db.Create(&scan).Error)
		res := &invScanResult{Status: model.HostAccountScanSucceeded}
		for i := range 100000 {
			res.Findings = append(res.Findings, invFindingResult{Username: fmt.Sprintf("u%06d", i), UID: fmt.Sprint(10000 + i), LoginCapable: true})
		}
		start := time.Now()
		require.NoError(t, e.svc.finishSucceeded(&scan, res))
		elapsed := time.Since(start)
		fmt.Printf("EVIDENCE inventory_100k_rows_persist=%s\n", elapsed.Round(time.Millisecond))
		var n int64
		e.db.Model(&model.HostAccountFinding{}).Where("asset_id = ?", assetID).Count(&n)
		assert.EqualValues(t, 100000, n)
		assert.Equal(t, 100000, e.scan(scan.ID).AccountsTotal)
	})
}

func TestInventoryStartupRecovery(t *testing.T) {
	e := newInvEnv(t)
	a1, acc1 := e.asset("r1")
	a2, acc2 := e.asset("r2")
	now := time.Now()
	q := model.HostAccountScan{AssetID: a1, Platform: "posix", IdentityMode: "default_account", IdentityAccountID: acc1,
		InitiatedBy: 1, Status: model.HostAccountScanQueued, PrivilegedGroups: "root"}
	r := model.HostAccountScan{AssetID: a2, Platform: "posix", IdentityMode: "default_account", IdentityAccountID: acc2,
		InitiatedBy: 1, Status: model.HostAccountScanRunning, PrivilegedGroups: "root", StartedAt: &now}
	require.NoError(t, e.db.Create(&q).Error)
	require.NoError(t, e.db.Create(&r).Error)
	n, err := e.svc.RecoverInterrupted()
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	for _, id := range []uint{q.ID, r.ID} {
		s := e.scan(id)
		assert.Equal(t, model.HostAccountScanInterrupted, s.Status)
		assert.Equal(t, model.InventoryInterrupted, s.FailureReason)
		assert.EqualValues(t, 1, e.auditCount(model.ActionInventoryScanDone, id), "有結束審計")
	}
}
