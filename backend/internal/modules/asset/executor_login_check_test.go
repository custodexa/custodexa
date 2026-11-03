package asset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
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
	"github.com/custodexa/backend/internal/modules/audit/port"
)

var checkActor = InventoryActor{UserID: 7, Username: "alice", ClientIP: "10.0.0.9"}

type execCheckEnv struct {
	*delegEnv
	svc *ExecutorLoginCheckService
}

func newExecCheckEnv(t *testing.T) *execCheckEnv {
	t.Helper()
	if os.Getenv(envChangeSecretFixturePG) == "" {
		t.Skip("需要 PostgreSQL 夾具（單連線的記憶體資料庫會在取密時互鎖）")
	}
	d := newDelegEnv(t)
	sqlDB, err := d.db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(8)
	require.NoError(t, d.db.AutoMigrate(&model.ExecutorLoginCheck{}))
	e := &execCheckEnv{delegEnv: d}
	e.svc = NewExecutorLoginCheckService(d.db, d.assets, nil, audit.NewTxSink(), nil)
	e.svc.hostKeyFor = func(HostKeyDialContext) ssh.HostKeyCallback { return ssh.InsecureIgnoreHostKey() }
	return e
}

// withExecutor 靶機加一個專用帳號並設為資產的專用帳號（密碼型；key 為 true 時為金鑰型）。
func (e *execCheckEnv) withExecutor(t *testing.T, user, sudo string, key, sudoersRead bool) {
	t.Helper()
	if key {
		private, line := testKeyPair(t, "exec")
		acct := e.srv.addAccount(user, "", sudo)
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		require.NoError(t, err)
		acct.key, acct.sudoersRead = pub, sudoersRead
		e.setExecutor(t, user, "", private)
		return
	}
	e.srv.addAccount(user, delegExecutorSecret, sudo).sudoersRead = sudoersRead
	e.setExecutor(t, user, delegExecutorSecret, "")
}

func (e *execCheckEnv) run(ctx context.Context) (*ExecutorLoginCheckResult, error) {
	return e.svc.Run(ctx, e.assetID, checkActor)
}

func (e *execCheckEnv) audits(t *testing.T, action model.AuditAction) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, e.db.Where("action = ? AND asset_id = ?", action, e.assetID).Order("id").Find(&rows).Error)
	return rows
}

func (e *execCheckEnv) assertPaired(t *testing.T) {
	t.Helper()
	assert.Equal(t, len(e.audits(t, model.ActionExecutorLoginCheck)), len(e.audits(t, model.ActionExecutorLoginCheckDone)), "開始審計數須等於結束審計數")
}

func (e *execCheckEnv) rows(t *testing.T) []model.ExecutorLoginCheck {
	t.Helper()
	var rows []model.ExecutorLoginCheck
	require.NoError(t, e.db.Find(&rows).Error)
	return rows
}

func (e *execCheckEnv) mountRow(t *testing.T) model.AssetAccount {
	t.Helper()
	var m model.AssetAccount
	require.NoError(t, e.db.Where("asset_id = ? AND purpose = ?", e.assetID, model.AccountPurposeExecutor).First(&m).Error)
	return m
}

func TestExecutorLoginCheckOutcomes(t *testing.T) {
	cases := []struct {
		name        string
		user, sudo  string
		key, read   bool
		wantCode    string
		wantMethod  string
		wantInvRead string
		sessions    int
	}{
		{"root 成功", "root", fakeSudoNone, false, false, "", model.ExecutorCheckMethodRoot, model.ExecutorCheckInventoryNotNeeded, 1},
		{"免密碼 sudo 且可讀規則", delegExecutorUser, fakeSudoNopasswd, false, true, "", model.ExecutorCheckMethodSudoNopasswd, model.ExecutorCheckInventoryOK, 2},
		{"免密碼 sudo 讀不到規則", delegExecutorUser, fakeSudoNopasswd, false, false, "", model.ExecutorCheckMethodSudoNopasswd, model.ExecutorCheckInventoryDenied, 2},
		{"密碼型 sudo 第二段成功", delegExecutorUser, fakeSudoPassword, false, false, "", model.ExecutorCheckMethodSudoPassword, model.ExecutorCheckInventoryDenied, 3},
		{"金鑰型沒有免密碼規則", delegExecutorUser, fakeSudoNone, true, false, model.ExecCheckEscalationNeedsNopass, "", "", 1},
		{"金鑰型有密碼型規則", delegExecutorUser, fakeSudoPassword, true, false, model.ExecCheckEscalationNeedsNopass, "", "", 1},
		{"密碼型沒有規則", delegExecutorUser, fakeSudoNone, false, false, model.ExecCheckEscalationDenied, "", "", 2},
		{"sudo 非預期失敗", delegExecutorUser, fakeSudoBroken, false, false, model.ExecCheckEscalationDenied, "", "", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newExecCheckEnv(t)
			e.withExecutor(t, c.user, c.sudo, c.key, c.read)
			res, err := e.run(context.Background())
			require.NoError(t, err)
			assert.Equal(t, c.wantCode == "", res.Success)
			assert.Equal(t, c.wantCode, res.Code)
			assert.Equal(t, c.wantMethod, res.Method)
			if c.wantCode == "" {
				assert.Equal(t, c.wantInvRead, res.InventoryRead)
			} else {
				assert.Equal(t, model.ExecutorCheckInventoryNotChecked, res.InventoryRead)
			}
			assert.Len(t, e.srv.execSessions(), c.sessions)
			assert.Equal(t, 0, e.srv.attemptsAs(delegTargetUser, ""), "不得以目標帳號登入")
			require.Len(t, e.rows(t), 1)
			assert.Equal(t, c.wantCode, e.rows(t)[0].Result)
			e.assertPaired(t)
			st, err := e.svc.State(e.assetID)
			require.NoError(t, err)
			assert.True(t, st.Tested)
		})
	}

	t.Run("專用帳號登入被拒", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		e.srv.accounts[delegExecutorUser].password = "changed-on-host"
		res, err := e.run(context.Background())
		require.NoError(t, err)
		assert.Equal(t, model.ExecCheckLoginFailed, res.Code)
		assert.Empty(t, e.srv.execSessions())
		e.assertPaired(t)
	})
	t.Run("連不到主機", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		require.NoError(t, e.srv.listener.Close())
		res, err := e.run(context.Background())
		require.NoError(t, err)
		assert.Equal(t, model.ExecCheckConnectionFailed, res.Code)
		e.assertPaired(t)
	})
	t.Run("沒有可用秘密", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", e.mountRow(t).ID).Update("effective_version_id", nil).Error)
		res, err := e.run(context.Background())
		require.NoError(t, err)
		assert.Equal(t, model.ExecCheckUnavailable, res.Code)
		assert.Empty(t, e.srv.authAttempts())
		e.assertPaired(t)
	})
	t.Run("憑證整組輪替中", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", e.mountRow(t).CredentialID).Update("active_rotation_id", 7).Error)
		res, err := e.run(context.Background())
		require.NoError(t, err)
		assert.Equal(t, model.ExecCheckRotationPending, res.Code)
		assert.Empty(t, e.srv.authAttempts())
		e.assertPaired(t)
	})
	t.Run("非 ssh 通道的資產", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", e.assetID).Update("rotation_channel", model.RotationChannelNone).Error)
		_, err := e.run(context.Background())
		assert.ErrorIs(t, err, ErrExecutorCheckPlatformUnsupported)
		assert.Empty(t, e.audits(t, model.ActionExecutorLoginCheck), "平台不支援不寫審計")
	})
	t.Run("沒有專用帳號", func(t *testing.T) {
		e := newExecCheckEnv(t)
		_, err := e.run(context.Background())
		assert.ErrorIs(t, err, ErrAssetExecutorNotFound)
		assert.Empty(t, e.audits(t, model.ActionExecutorLoginCheck))
	})
}

func TestExecutorLoginCheckNoAccountLine(t *testing.T) {
	for _, c := range []struct {
		name, user, sudo string
	}{{"root", "root", fakeSudoNone}, {"免密碼", delegExecutorUser, fakeSudoNopasswd}, {"密碼型第二段", delegExecutorUser, fakeSudoPassword}} {
		t.Run(c.name, func(t *testing.T) {
			e := newExecCheckEnv(t)
			e.withExecutor(t, c.user, c.sudo, false, false)
			before := e.srv.passwordOf(delegTargetUser)
			res, err := e.run(context.Background())
			require.NoError(t, err)
			require.True(t, res.Success)
			for _, s := range e.srv.execSessions() {
				switch s.cmd {
				case elevatedCmdSudoPass:
					assert.Equal(t, delegExecutorSecret+"\n", s.stdin, "第二段 stdin 恰為密碼一列")
				case elevatedCmdRoot, elevatedCmdSudoNoPass:
					assert.Empty(t, s.stdin)
				}
				if s.cmd != elevatedCmdSudoPass {
					assert.NotContains(t, s.stdin, ":")
				}
			}
			assert.Equal(t, before, e.srv.passwordOf(delegTargetUser), "不改任何密碼")
		})
	}
}

func TestExecutorLoginCheckHostKeyRefused(t *testing.T) {
	e := newExecCheckEnv(t)
	e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
	var got HostKeyDialContext
	e.svc.hostKeyFor = func(dc HostKeyDialContext) ssh.HostKeyCallback {
		got = dc
		return func(string, net.Addr, ssh.PublicKey) error { return ErrHostKeyChanged }
	}
	res, err := e.run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, model.ExecCheckHostKeyMismatch, res.Code)
	assert.Empty(t, e.srv.authAttempts(), "不符時零認證嘗試")
	assert.Equal(t, HostKeyPathExecutorLoginCheck, got.Path)
	assert.False(t, got.Path.Interactive())
	assert.True(t, strings.HasPrefix(got.ConnectionRef, "executor-check:"))
	e.assertPaired(t)
	// 查核失敗另一碼
	e.svc.hostKeyFor = func(HostKeyDialContext) ssh.HostKeyCallback {
		return func(string, net.Addr, ssh.PublicKey) error { return ErrHostKeyCheckFailed }
	}
	res, err = e.run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, model.ExecCheckHostKeyCheckFailed, res.Code)
	assert.Empty(t, e.srv.authAttempts())
}

type failingSink struct {
	inner   port.TxSink
	failOn  string
	failNth int32
	seen    atomic.Int32
}

func (f *failingSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	if ev.Action == f.failOn && f.seen.Add(1) == f.failNth {
		return errors.New("injected audit failure")
	}
	return f.inner.WriteInTx(tx, ev)
}

func TestExecutorLoginCheckAuditFailClosed(t *testing.T) {
	t.Run("開始審計寫入失敗", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		e.svc.auditTx = &failingSink{inner: audit.NewTxSink(), failOn: string(model.ActionExecutorLoginCheck), failNth: 1}
		_, err := e.run(context.Background())
		assert.ErrorIs(t, err, ErrExecutorCheckInternal)
		assert.Empty(t, e.srv.authAttempts())
		assert.Empty(t, e.rows(t))
	})
	t.Run("結果交易失敗", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		e.svc.auditTx = &failingSink{inner: audit.NewTxSink(), failOn: string(model.ActionExecutorLoginCheckDone), failNth: 1}
		_, err := e.run(context.Background())
		assert.ErrorIs(t, err, ErrExecutorCheckInternal)
		assert.Empty(t, e.rows(t), "結果表不變")
		e.assertPaired(t)
		assert.Contains(t, e.audits(t, model.ActionExecutorLoginCheckDone)[0].Details, model.ExecutorCheckEndPersistFailed)
	})
	t.Run("取鎖後掛載已更換", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		e.svc.afterPrecheck = func() { require.NoError(t, e.db.Delete(&model.AssetAccount{}, e.mountRow(t).ID).Error) }
		_, err := e.run(context.Background())
		assert.ErrorIs(t, err, ErrExecutorStateChanged)
		assert.Empty(t, e.srv.authAttempts())
		assert.Empty(t, e.rows(t))
		e.assertPaired(t)
		assert.Contains(t, e.audits(t, model.ActionExecutorLoginCheckDone)[0].Details, model.ExecutorCheckEndStateChanged)
	})
	t.Run("鎖逾時", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		e.svc.lockWait = 100 * time.Millisecond
		unlock, ok := tryLockRotationAccount(e.mountRow(t).ID)
		require.True(t, ok)
		defer unlock()
		_, err := e.run(context.Background())
		assert.ErrorIs(t, err, ErrExecutorCheckBusy)
		e.assertPaired(t)
		assert.Contains(t, e.audits(t, model.ActionExecutorLoginCheckDone)[0].Details, model.ExecutorCheckEndBusy)
	})
	t.Run("panic 後行程存活", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		e.svc.beforeResult = func() { panic("boom") }
		_, err := e.run(context.Background())
		assert.ErrorIs(t, err, ErrExecutorCheckInternal)
		assert.Empty(t, e.rows(t))
		e.assertPaired(t)
		assert.Contains(t, e.audits(t, model.ActionExecutorLoginCheckDone)[0].Details, model.ExecutorCheckEndInterrupted)
	})
	t.Run("用戶端斷線不影響結果", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		ctx, cancel := context.WithCancel(context.Background())
		e.svc.beforeResult = cancel
		res, err := e.run(ctx)
		require.NoError(t, err)
		assert.True(t, res.Success)
		assert.Len(t, e.rows(t), 1)
		e.assertPaired(t)
	})
}

func TestExecutorLoginCheckNoSecretLeak(t *testing.T) {
	e := newExecCheckEnv(t)
	e.withExecutor(t, delegExecutorUser, fakeSudoPassword, false, false)
	e.srv.echoLoginPassword, e.srv.echoStdin = true, true
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	res, err := e.run(context.Background())
	require.NoError(t, err)
	body, _ := json.Marshal(res)
	all := string(body) + logs.String()
	for _, a := range e.audits(t, model.ActionExecutorLoginCheck) {
		all += a.Details
	}
	for _, a := range e.audits(t, model.ActionExecutorLoginCheckDone) {
		all += a.Details
	}
	raw, _ := json.Marshal(e.rows(t))
	all += string(raw)
	assert.NotContains(t, all, delegExecutorSecret)
	assert.NotContains(t, all, "rejected by pam")
}

func TestExecutorLoginCheckLockAndPin(t *testing.T) {
	t.Run("鎖被佔用時逾時且靶機零連線", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		e.svc.lockWait = 300 * time.Millisecond
		e.svc.limiter = newExecutorCheckLimiter()
		unlock, ok := tryLockRotationAccount(e.mountRow(t).ID)
		require.True(t, ok)
		start := time.Now()
		_, err := e.run(context.Background())
		assert.ErrorIs(t, err, ErrExecutorCheckBusy)
		assert.Less(t, time.Since(start), 1300*time.Millisecond)
		assert.Empty(t, e.srv.authAttempts())
		unlock()
		// 全域同時名額已歸還
		res, err := e.run(context.Background())
		require.NoError(t, err)
		assert.True(t, res.Success)
	})
	t.Run("第 3 步後插入輪替：整組已結束則用新版本", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		var newVer uint
		e.svc.afterPrecheck = func() {
			m := e.mountRow(t)
			var v model.CredentialSecretVersion
			require.NoError(t, e.db.First(&v, *m.EffectiveVersionID).Error)
			v.ID, v.VersionNo = 0, v.VersionNo+100
			require.NoError(t, e.db.Create(&v).Error)
			newVer = v.ID
			require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", m.ID).Update("effective_version_id", v.ID).Error)
		}
		res, err := e.run(context.Background())
		require.NoError(t, err)
		assert.True(t, res.Success)
		require.Len(t, e.rows(t), 1)
		assert.Equal(t, newVer, e.rows(t)[0].CredentialVersionID)
		assert.Zero(t, e.srv.attemptsAs(delegExecutorUser, "wrong"))
	})
	t.Run("第 3 步後插入輪替：整組尚未結束則不登入", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		e.svc.afterPrecheck = func() {
			require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", e.mountRow(t).CredentialID).Update("active_rotation_id", 7).Error)
		}
		res, err := e.run(context.Background())
		require.NoError(t, err)
		assert.Equal(t, model.ExecCheckRotationPending, res.Code)
		assert.Empty(t, e.srv.authAttempts())
		e.assertPaired(t)
	})
	t.Run("讀專用帳號掛載出錯：第 3 步", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		var calls, injected atomic.Int32
		e.svc.readPin = func(db *gorm.DB, id uint) (*ExecutorPin, error) {
			if calls.Add(1) == 1 {
				injected.Add(1)
				return nil, errors.New("injected")
			}
			return readExecutorPin(db, id)
		}
		_, err := e.run(context.Background())
		assert.ErrorIs(t, err, ErrExecutorCheckInternal)
		assert.EqualValues(t, 1, injected.Load())
		assert.Empty(t, e.srv.authAttempts())
		assert.Empty(t, e.audits(t, model.ActionExecutorLoginCheck), "尚無開始審計")
	})
	t.Run("讀專用帳號掛載出錯：第 4 步鎖內重讀", func(t *testing.T) {
		e := newExecCheckEnv(t)
		e.withExecutor(t, delegExecutorUser, fakeSudoNopasswd, false, false)
		var calls, injected atomic.Int32
		e.svc.readPin = func(db *gorm.DB, id uint) (*ExecutorPin, error) {
			if calls.Add(1) == 2 {
				injected.Add(1)
				return nil, errors.New("injected")
			}
			return readExecutorPin(db, id)
		}
		_, err := e.run(context.Background())
		assert.ErrorIs(t, err, ErrExecutorCheckInternal)
		assert.EqualValues(t, 2, calls.Load())
		assert.EqualValues(t, 1, injected.Load())
		assert.Empty(t, e.srv.authAttempts())
		assert.Empty(t, e.rows(t))
		e.assertPaired(t)
		assert.Contains(t, e.audits(t, model.ActionExecutorLoginCheckDone)[0].Details, model.ExecutorCheckEndInterrupted)
	})
}
