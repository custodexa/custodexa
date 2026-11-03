package asset

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 代改的專用帳號一側失敗：金鑰型登入被拒、root 改密指令非零、五種失敗的告警分流，
// 以及每一段 stderr 同時遮新密碼與登入者密碼。

// 金鑰型專用帳號以不被接受的金鑰登入：專用帳號登入失敗碼，目標帳號零認證、舊密碼不變。
func TestDelegatedRotationKeyExecutorWrongKeyLoginFailed(t *testing.T) {
	e := newDelegEnv(t)
	_, acceptedLine := testKeyPair(t, "exec-accepted")
	offered, _ := testKeyPair(t, "exec-offered")
	acct := e.srv.addAccount(delegExecutorUser, "", fakeSudoNopasswd)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(acceptedLine))
	require.NoError(t, err)
	acct.key = pub
	e.setExecutor(t, delegExecutorUser, "", offered)

	rec := e.runOne(t)
	assert.Equal(t, model.ChangeSecretFailed, rec.Status)
	assert.Equal(t, model.ChangeSecretReasonExecutorLoginFailed, rec.Error)
	assert.Equal(t, model.ChangeSecretExecutionExecutorSudoNopasswd, rec.ExecutionMethod, "未送指令：記依設定預期的方式")
	require.NotZero(t, e.srv.attemptsAs(delegExecutorUser, ""), "靶機未收到專用帳號的認證：本測試不成立")
	for _, a := range e.srv.authAttempts() {
		if a.user == delegExecutorUser {
			assert.False(t, a.ok, "專用帳號認證不得成功")
		}
	}
	assert.Zero(t, e.srv.attemptsAs(delegTargetUser, ""), "以目標帳號認證次數為 0")
	assert.Empty(t, e.srv.execSessions(), "登入失敗：不送任何指令")
	assert.Equal(t, delegServerOldPW, e.srv.passwordOf(delegTargetUser), "目標舊密碼不變")
	assert.Equal(t, delegStoredOldPW, e.storedPassword(t), "憑證庫仍是舊密碼")
	assert.EqualValues(t, 0, e.candidateCount(t))
}

// root 模式改密指令非零：指令被拒碼，目標帳號零認證、舊密碼不變。
// 走靶機 chpasswd 分支中 root 登入、套用失敗的路徑（目標不在主機上，或 PAM 拒絕套用）。
func TestDelegatedRotationRootCommandRejected(t *testing.T) {
	cases := []struct {
		name       string
		dropTarget bool
	}{
		{"target_missing_on_host", true},
		{"chpasswd_rejects", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newDelegEnv(t)
			e.srv.addAccount("root", delegExecutorSecret, fakeSudoNone)
			if c.dropTarget {
				e.srv.mu.Lock()
				delete(e.srv.accounts, delegTargetUser)
				e.srv.mu.Unlock()
			} else {
				e.srv.rejectApply = true
			}
			e.setExecutor(t, "root", delegExecutorSecret, "")

			rec := e.runOne(t)
			assert.Equal(t, model.ChangeSecretFailed, rec.Status)
			assert.Equal(t, model.ChangeSecretReasonExecutorCommandRejected, rec.Error)
			assert.Equal(t, model.ChangeSecretExecutionExecutorRoot, rec.ExecutionMethod)
			sessions := e.srv.execSessions()
			require.Len(t, sessions, 1, "root 只有一段")
			assert.Equal(t, "root", sessions[0].user)
			assert.Equal(t, elevatedCmdRoot, sessions[0].cmd)
			assert.Zero(t, e.srv.attemptsAs(delegTargetUser, ""), "以目標帳號認證次數為 0")
			e.assertSelfNeverTried(t)
			if !c.dropTarget {
				assert.Equal(t, delegServerOldPW, e.srv.passwordOf(delegTargetUser), "目標舊密碼不變")
			}
			assert.Equal(t, delegStoredOldPW, e.storedPassword(t), "憑證庫仍是舊密碼")
			assert.EqualValues(t, 0, e.candidateCount(t))
		})
	}
}

// 五種專用帳號一側失敗經完整執行路徑（含告警判定）：failed 三碼各一則告警、skipped 兩碼零則告警；
// 每案目標帳號零認證。
func TestDelegatedRotationFailureAlerts(t *testing.T) {
	cases := []struct {
		name   string
		code   string
		status string
		alerts int
		setup  func(t *testing.T, e *delegEnv)
		run    func(t *testing.T, e *delegEnv) model.ChangeSecretRecord
	}{
		{"login_failed", model.ChangeSecretReasonExecutorLoginFailed, model.ChangeSecretFailed, 1, func(t *testing.T, e *delegEnv) {
			e.srv.addAccount(delegExecutorUser, "changed-on-host", fakeSudoNopasswd)
			e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		}, nil},
		{"command_rejected", model.ChangeSecretReasonExecutorCommandRejected, model.ChangeSecretFailed, 1, func(t *testing.T, e *delegEnv) {
			e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoBroken)
			e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		}, nil},
		{"unavailable", model.ChangeSecretReasonExecutorUnavailable, model.ChangeSecretFailed, 1, func(t *testing.T, e *delegEnv) {
			e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
			e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
			require.NoError(t, e.db.Model(&model.AssetAccount{}).
				Where("asset_id = ? AND purpose = ?", e.assetID, model.AccountPurposeExecutor).
				Update("effective_version_id", nil).Error)
		}, nil},
		{"rotation_pending", model.ChangeSecretReasonExecutorRotationPending, model.ChangeSecretSkipped, 0, func(t *testing.T, e *delegEnv) {
			e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
			e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
			require.NoError(t, e.db.Create(&model.ChangeSecretCandidate{
				AccountID: e.executorMount(t).ID, AssetID: e.assetID, SecretType: model.ChangeSecretTypePassword,
			}).Error)
		}, nil},
		{"changed", model.ChangeSecretReasonExecutorChanged, model.ChangeSecretSkipped, 0, func(t *testing.T, e *delegEnv) {
			e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
			e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		}, runWithExecutorAdvancedAfterExpansion},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newDelegEnv(t)
			alerts := attachAlertHook(t, e)
			c.setup(t, e)
			candidatesBefore := e.candidateCount(t)
			var rec model.ChangeSecretRecord
			if c.run != nil {
				rec = c.run(t, e)
			} else {
				rec = e.runOne(t)
			}
			assert.Equal(t, c.status, rec.Status)
			assert.Equal(t, c.code, rec.Error)
			e.assertSelfNeverTried(t)
			assert.Zero(t, e.srv.attemptsAs(delegTargetUser, ""), "以目標帳號認證次數為 0")
			assert.Equal(t, candidatesBefore, e.candidateCount(t), "不新增候選")

			got := alerts()
			assert.Len(t, got, c.alerts, "告警則數")
			for _, body := range got {
				assert.Contains(t, body, c.code, "告警帶原因碼")
			}
		})
	}
}

// runWithExecutorAdvancedAfterExpansion 經完整執行路徑跑出 CHANGE_SECRET_EXECUTOR_CHANGED：
// 先持專用帳號掛載的鎖，讓執行在展開目標（讀釘住值）之後停在取專用帳號秘密之前；
// 期間推進專用帳號的就位版本，再放開鎖。
func runWithExecutorAdvancedAfterExpansion(t *testing.T, e *delegEnv) model.ChangeSecretRecord {
	t.Helper()
	pin, err := readExecutorPin(e.db, e.assetID)
	require.NoError(t, err)
	require.NotNil(t, pin)
	release := lockRotationAccount(pin.AccountID)
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	plan := e.plan(t, nil)
	done := make(chan []model.ChangeSecretRecord, 1)
	go func() { done <- e.runner.RunPlan(plan) }()
	select {
	case <-done:
		t.Fatal("ASSERT: 專用帳號的鎖被持有時，執行不得結束")
	case <-time.After(1500 * time.Millisecond):
	}
	require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", pin.AccountID).
		Update("effective_version_id", pin.EffectiveVersionID+100).Error)
	release()
	released = true
	select {
	case records := <-done:
		require.Len(t, records, 1)
		return records[0]
	case <-time.After(30 * time.Second):
		t.Fatal("ASSERT: 放開鎖後執行應結束")
	}
	return model.ChangeSecretRecord{}
}

// attachAlertHook 把 e.runner 換成接上 webhook 告警替身的版本；回傳的函式等佇列清空後回傳實際送出的告警本文。
// 告警在執行路徑上同步入列，所以執行返回後佇列清空即代表這次執行的告警已全數送達。
func attachAlertHook(t *testing.T, e *delegEnv) func() []string {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(hook.Close)
	require.NoError(t, e.db.AutoMigrate(&model.NotificationChannel{}))
	require.NoError(t, e.db.Create(&model.NotificationChannel{
		Name: "ops", Type: "webhook", URL: hook.URL, Enabled: true, Language: "zh-TW",
	}).Error)
	notifier := audit.NewAlertNotifier(e.db, nil)
	require.NoError(t, notifier.LoadChannels())
	notifier.Start()
	e.runner = NewChangeSecretRunner(e.db, e.assets, e.candidates, e.hostKeys, notifier).
		WithOwnershipScope(globalOwnershipScopeForTest{}).WithManagementAuthorizer(newAllowAllAuthorizer())
	return func() []string {
		deadline := time.Now().Add(10 * time.Second)
		for notifier.PendingNotifications() > 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		require.Zero(t, notifier.PendingNotifications(), "告警佇列未清空")
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

// 每一段改密指令的 stderr 都同時遮新密碼與登入者密碼（惡意目標機把兩者回吐到 stderr）。
func TestDelegatedElevatedStderrRedactsBothSecrets(t *testing.T) {
	const newPW = "New-Pw-7xq"
	cases := []struct {
		name  string
		login string
		sudo  string
		setup func(srv *execSSHServer)
	}{
		// root 段：目標不在主機上，chpasswd 非零
		{"root_stage", "root", fakeSudoNone, func(srv *execSSHServer) {
			srv.mu.Lock()
			delete(srv.accounts, delegTargetUser)
			srv.mu.Unlock()
		}},
		// 第一段：sudo -n 非零且不含需要密碼
		{"first_stage", delegExecutorUser, fakeSudoBroken, func(*execSSHServer) {}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newExecSSHServer(t)
			srv.addAccount(delegTargetUser, delegServerOldPW, fakeSudoNone)
			srv.addAccount(c.login, delegExecutorSecret, c.sudo)
			srv.echoStdin = true
			srv.echoLoginPassword = true
			c.setup(srv)
			rt := directRotationTarget(t, srv, delegTargetUser, false)
			_, err := posixSSHExecutor{}.RotateDelegated(context.Background(), rt,
				rotationLogin{username: c.login, password: []byte(delegExecutorSecret)}, []byte(newPW))
			require.Error(t, err)
			require.Len(t, srv.execSessions(), 1, "只跑了一段")
			msg := err.Error()
			require.Contains(t, msg, "login-secret="+redactedMarker, "登入者密碼的回吐未進入錯誤訊息路徑：本測試不成立")
			assert.False(t, strings.Contains(msg, newPW), "錯誤訊息不得含新密碼：%s", msg)
			assert.False(t, strings.Contains(msg, delegExecutorSecret), "錯誤訊息不得含專用帳號密碼：%s", msg)
		})
	}
}
