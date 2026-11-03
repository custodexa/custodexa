package asset

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 改密記錄的執行方式四欄：代改不論成敗都記下是哪一個專用帳號；自改與選路前跳過的記錄為零值。
// 另斷言秘密不出現在記錄、候選、告警與伺服器日誌四處，以及依帳號、依憑證兩條查詢帶出四欄。

var executorRecordKeys = []string{"execution_method", "executor_account_id", "executor_username", "executor_credential_id"}

func (e *delegEnv) executorMount(t *testing.T) model.AssetAccount {
	t.Helper()
	var mount model.AssetAccount
	require.NoError(t, e.db.Where("asset_id = ? AND purpose = ?", e.assetID, model.AccountPurposeExecutor).
		First(&mount).Error)
	return mount
}

// assertExecutorFields 代改目標的記錄四欄指向掛載的專用帳號，方式不是自改。
func assertExecutorFields(t *testing.T, rec model.ChangeSecretRecord, mount model.AssetAccount, wantMethod string) {
	t.Helper()
	assert.NotEqual(t, model.ChangeSecretExecutionSelf, rec.ExecutionMethod, "代改目標不得記為自改")
	if wantMethod != "" {
		assert.Equal(t, wantMethod, rec.ExecutionMethod)
	}
	assert.Equal(t, mount.ID, rec.ExecutorAccountID)
	assert.Equal(t, delegExecutorUser, rec.ExecutorUsername)
	require.NotZero(t, mount.CredentialID)
	assert.Equal(t, mount.CredentialID, rec.ExecutorCredentialID)
}

func assertSelfFields(t *testing.T, rec model.ChangeSecretRecord) {
	t.Helper()
	assert.Equal(t, model.ChangeSecretExecutionSelf, rec.ExecutionMethod)
	assert.Zero(t, rec.ExecutorAccountID)
	assert.Empty(t, rec.ExecutorUsername)
	assert.Zero(t, rec.ExecutorCredentialID)
}

func TestDelegatedRotationRecordExecutorFields(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoPassword)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		rec := e.runOne(t)
		require.Equal(t, model.ChangeSecretSuccess, rec.Status)
		assertExecutorFields(t, rec, e.executorMount(t), model.ChangeSecretExecutionExecutorSudoPassword)
	})
	failures := []struct {
		name   string
		code   string
		status string
		setup  func(t *testing.T, e *delegEnv)
	}{
		{"login_failed", model.ChangeSecretReasonExecutorLoginFailed, model.ChangeSecretFailed, func(t *testing.T, e *delegEnv) {
			e.srv.addAccount(delegExecutorUser, "changed-on-host", fakeSudoNopasswd)
			e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		}},
		{"command_rejected", model.ChangeSecretReasonExecutorCommandRejected, model.ChangeSecretFailed, func(t *testing.T, e *delegEnv) {
			e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoBroken)
			e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		}},
		{"unavailable", model.ChangeSecretReasonExecutorUnavailable, model.ChangeSecretFailed, func(t *testing.T, e *delegEnv) {
			e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
			e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
			require.NoError(t, e.db.Model(&model.AssetAccount{}).
				Where("asset_id = ? AND purpose = ?", e.assetID, model.AccountPurposeExecutor).
				Update("effective_version_id", nil).Error)
		}},
		{"rotation_pending", model.ChangeSecretReasonExecutorRotationPending, model.ChangeSecretSkipped, func(t *testing.T, e *delegEnv) {
			e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
			e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
			mount := e.executorMount(t)
			require.NoError(t, e.db.Create(&model.ChangeSecretCandidate{
				AccountID: mount.ID, AssetID: e.assetID, SecretType: model.ChangeSecretTypePassword,
			}).Error)
		}},
	}
	for _, c := range failures {
		t.Run(c.name, func(t *testing.T) {
			e := newDelegEnv(t)
			c.setup(t, e)
			mount := e.executorMount(t)
			rec := e.runOne(t)
			assert.Equal(t, c.status, rec.Status)
			assert.Equal(t, c.code, rec.Error)
			assertExecutorFields(t, rec, mount, "")
		})
	}
	t.Run("changed", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		mount := e.executorMount(t)
		job := jobFromPlan(e.plan(t, nil))
		job.initiatorID, job.initiatorName = 1, "tester"
		targets, skip := e.runner.resolveTargets(job, e.assetID)
		require.Nil(t, skip)
		require.Len(t, targets, 1)
		require.NotNil(t, targets[0].executorPin)
		require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", mount.ID).
			Update("effective_version_id", targets[0].executorPin.EffectiveVersionID+100).Error)
		rec, _ := e.runner.runTarget(job, targets[0])
		assert.Equal(t, model.ChangeSecretSkipped, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonExecutorChanged, rec.Error)
		assertExecutorFields(t, rec, mount, "")
	})

	// 自改三種：沒有專用帳號、選路前整台跳過（未設定通道）、Windows 通道有專用帳號
	t.Run("self_no_executor", func(t *testing.T) {
		e := newDelegEnv(t)
		assertSelfFields(t, e.runOne(t))
	})
	t.Run("self_skipped_before_routing", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", e.assetID).
			Update("rotation_channel", model.RotationChannelNone).Error)
		rec := e.runOne(t)
		assert.Equal(t, model.ChangeSecretSkipped, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonChannelNotConfigured, rec.Error)
		assertSelfFields(t, rec)
	})
	t.Run("self_windows_channel_with_executor", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", e.assetID).
			Update("rotation_channel", model.RotationChannelWindowsSSH).Error)
		rec := e.runOne(t)
		assertSelfFields(t, rec)
		assert.Zero(t, e.srv.attemptsAs(delegExecutorUser, delegExecutorSecret), "Windows 通道不以專用帳號登入")
	})
}

// syncBuffer 讓背景告警 worker 與測試主執行緒共用的日誌擷取。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// 靶機把 stdin 回吐到 stderr 時，新密碼與專用帳號秘密不出現在：記錄列、候選列、告警實際送出的內容、伺服器日誌。
// 一次成功（產生新密碼、候選落庫與提交）、一次改密指令非零且 stderr 回吐含新密碼的 stdin（告警、伺服器日誌）。
func TestDelegatedRotationSecretsStayOutOfAllSinks(t *testing.T) {
	logs := &syncBuffer{}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(io.MultiWriter(logs, prevOut))
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	var mu sync.Mutex
	var bodies []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	run := func(t *testing.T, sudo string, dropTarget bool) (*delegEnv, model.ChangeSecretRecord) {
		e := newDelegEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.NotificationChannel{}))
		require.NoError(t, e.db.Create(&model.NotificationChannel{
			Name: "ops", Type: "webhook", URL: hook.URL, Enabled: true, Language: "zh-TW",
		}).Error)
		notifier := audit.NewAlertNotifier(e.db, nil)
		require.NoError(t, notifier.LoadChannels())
		notifier.Start()
		e.runner = NewChangeSecretRunner(e.db, e.assets, e.candidates, e.hostKeys, notifier).
			WithOwnershipScope(globalOwnershipScopeForTest{}).WithManagementAuthorizer(newAllowAllAuthorizer())
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, sudo)
		e.srv.echoStdin = true
		if dropTarget {
			// 目標帳號不在主機上：chpasswd 以非零結束，stderr 帶回吐的 stdin（含新密碼）
			e.srv.mu.Lock()
			delete(e.srv.accounts, delegTargetUser)
			e.srv.mu.Unlock()
		}
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		return e, e.runOne(t)
	}

	okEnv, okRec := run(t, fakeSudoPassword, false)
	require.Equal(t, model.ChangeSecretSuccess, okRec.Status)
	newPW := okEnv.srv.passwordOf(delegTargetUser)
	require.NotEqual(t, delegServerOldPW, newPW, "成功案應已換上新密碼")
	require.NotEmpty(t, targetSecretsSent(okEnv.srv), "靶機未收到含目標帳號的 stdin：本測試不成立")

	badEnv, badRec := run(t, fakeSudoNopasswd, true)
	require.Equal(t, model.ChangeSecretFailed, badRec.Status)
	require.Equal(t, model.ChangeSecretReasonExecutorCommandRejected, badRec.Error)
	badSecrets := targetSecretsSent(badEnv.srv)
	require.NotEmpty(t, badSecrets, "失敗案靶機應收到含新密碼的 stdin：本測試不成立")

	deadline := time.Now().Add(5 * time.Second)
	var alerts []string
	for time.Now().Before(deadline) {
		mu.Lock()
		alerts = append([]string(nil), bodies...)
		mu.Unlock()
		if len(alerts) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotEmpty(t, alerts, "告警未送達：本測試不成立")
	require.Contains(t, logs.String(), "rejected by pam", "回吐的 stderr 未進入伺服器日誌路徑：本測試不成立")

	secrets := append([]string{newPW, delegExecutorSecret}, badSecrets...)
	sinks := map[string]string{"alert": strings.Join(alerts, "\n"), "log": logs.String()}
	for name, env := range map[string]*delegEnv{"ok": okEnv, "bad": badEnv} {
		var recs []model.ChangeSecretRecord
		require.NoError(t, env.db.Find(&recs).Error)
		raw, err := json.Marshal(recs)
		require.NoError(t, err)
		sinks["records_"+name] = string(raw)
		var cands []model.ChangeSecretCandidate
		require.NoError(t, env.db.Find(&cands).Error)
		var lastErrs []string
		for _, c := range cands {
			lastErrs = append(lastErrs, c.LastError)
		}
		sinks["candidates_last_error_"+name] = strings.Join(lastErrs, "\n")
	}
	require.Contains(t, sinks["alert"], model.ChangeSecretReasonExecutorCommandRejected, "告警帶原因碼")
	for name, text := range sinks {
		for _, s := range secrets {
			assert.False(t, strings.Contains(text, s), "%s 含秘密", name)
		}
	}
}

// targetSecretsSent 靶機各 session 收到的 stdin 中「目標帳號:密碼」列的密碼部分（回吐到 stderr 的就是這些）。
func targetSecretsSent(srv *execSSHServer) []string {
	var out []string
	for _, s := range srv.execSessions() {
		for _, line := range strings.Split(s.stdin, "\n") {
			if pw, ok := strings.CutPrefix(line, delegTargetUser+":"); ok && pw != "" {
				out = append(out, pw)
			}
		}
	}
	return out
}

// 依帳號、依憑證兩條記錄查詢回傳的記錄帶執行方式四欄（JSON 鍵與值）。
// 兩條查詢目前沒有直接對外的路由：依帳號只供輪替證據報告取材，報告列型別不含專用帳號識別，
// 因此不存在需要另行遮蔽的出口（由本測試的型別斷言守住）。
func TestRecordQueriesCarryExecutorFields(t *testing.T) {
	e := newDelegEnv(t)
	e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
	e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
	mount := e.executorMount(t)
	rec := e.runOne(t)
	require.Equal(t, model.ChangeSecretSuccess, rec.Status)
	plans := NewChangeSecretPlanService(e.db)

	byAccount, err := plans.RecordsByAccounts([]uint{rec.AccountID}, nil, nil, "")
	require.NoError(t, err)
	byCredential, err := plans.RecordsByCredential(rec.CredentialID, 0)
	require.NoError(t, err)
	for name, rows := range map[string][]model.ChangeSecretRecord{"by_account": byAccount, "by_credential": byCredential} {
		t.Run(name, func(t *testing.T) {
			require.Len(t, rows, 1)
			raw, err := json.Marshal(rows)
			require.NoError(t, err)
			var got []map[string]any
			require.NoError(t, json.Unmarshal(raw, &got))
			for _, k := range executorRecordKeys {
				assert.Contains(t, got[0], k, "回應鍵含 %s", k)
			}
			assert.Equal(t, model.ChangeSecretExecutionExecutorSudoNopasswd, got[0]["execution_method"])
			assert.EqualValues(t, mount.ID, got[0]["executor_account_id"])
			assert.Equal(t, delegExecutorUser, got[0]["executor_username"])
			assert.EqualValues(t, mount.CredentialID, got[0]["executor_credential_id"])
		})
	}

	t.Run("report_row_has_no_executor_identity", func(t *testing.T) {
		rt := reflect.TypeOf(RecordRow{})
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			assert.NotContains(t, strings.ToLower(f.Name), "executor", "報告列不帶專用帳號識別")
			assert.NotContains(t, f.Tag.Get("json"), "executor", "報告列不帶專用帳號識別")
		}
	})
}
