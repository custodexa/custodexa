package asset

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// change-secret-ssh-deepening 的可靠性語義守衛。
//
// 覆蓋 design D2（候選先於遠端落庫）、D3（遠端失敗的兩種可知性）、
// D4（unverified 保留＋重試＋放棄）、D6（金鑰三段式與零鎖死）、
// D8（同帳號不疊加候選）。全部以行程內 SSH 靶機實跑真連線，不 mock 傳輸層。

type csFixture struct {
	db         *gorm.DB
	assets     *AssetService
	candidates *ChangeSecretCandidateService
	runner     *ChangeSecretRunner
	retry      *ChangeSecretRetryRunner
	hostKeys   *HostKeyService
	server     *testSSHServer
	assetID    uint
	accountID  uint
	username   string
}

func setupChangeSecretFixture(t *testing.T, username, password string) *csFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&model.Asset{}, &model.AssetAccount{}, &model.AuditLog{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetHostKey{},
		&model.ChangeSecretPlan{}, &model.ChangeSecretRecord{}, &model.ChangeSecretCandidate{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	srv := newTestSSHServer(t, username, password)
	host, portStr, err := net.SplitHostPort(srv.addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	key := make([]byte, 32)
	codec := aesColumnCodec(t, key)
	assets, err := NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "target", Protocol: model.ProtocolSSH, Host: host, Port: port,
		Username: username, Password: password, CreatedBy: 1,
	})
	require.NoError(t, err)

	var acct model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&acct).Error)

	candidates, err := NewChangeSecretCandidateService(db, codec, assets, audit.NewTxSink())
	require.NoError(t, err)
	// host key 走既有 TOFU：首次連線自動記錄，其後比對
	hostKeys := NewHostKeyService(db)

	runner := NewChangeSecretRunner(db, assets, candidates, hostKeys, nil)
	retry := NewChangeSecretRetryRunner(db, candidates, assets, hostKeys, nil)
	return &csFixture{
		db: db, assets: assets, candidates: candidates, runner: runner, retry: retry,
		hostKeys: hostKeys, server: srv, assetID: asset.ID, accountID: acct.ID, username: username,
	}
}

func (f *csFixture) plan(t *testing.T, mut func(*model.ChangeSecretPlan)) *model.ChangeSecretPlan {
	t.Helper()
	accounts, err := json.Marshal([]string{model.AccountScopeAll})
	require.NoError(t, err)
	ids, err := json.Marshal([]uint{f.assetID})
	require.NoError(t, err)
	p := &model.ChangeSecretPlan{
		Name:     "t" + strconv.FormatInt(time.Now().UnixNano(), 36),
		AssetIDs: string(ids), Accounts: string(accounts), Enabled: true,
		SecretType: model.ChangeSecretTypePassword, KeyStrategy: model.KeyStrategyAppendReplace,
		PasswordLength: 16, PasswordIncludeSymbol: true, PasswordExcludeAmbiguous: true,
	}
	if mut != nil {
		mut(p)
	}
	require.NoError(t, f.db.Create(p).Error)
	return p
}

func (f *csFixture) candidateCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Count(&n).Error)
	return n
}

func (f *csFixture) storedPassword(t *testing.T) string {
	t.Helper()
	creds, err := f.assets.GetWithCredentialsForAccount(f.assetID, f.accountID)
	require.NoError(t, err)
	return creds.Password
}

func (f *csFixture) storedPrivateKey(t *testing.T) string {
	t.Helper()
	creds, err := f.assets.GetWithCredentialsForAccount(f.assetID, f.accountID)
	require.NoError(t, err)
	return creds.PrivateKey
}

// --- D2／成功路徑 ---

func TestChangeSecretRunnerPasswordSuccessClearsCandidate(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	plan := f.plan(t, nil)

	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
	assert.Equal(t, f.accountID, records[0].AccountID, "記錄須帶 account_id")
	assert.Equal(t, "root", records[0].AccountUsername, "記錄須帶 username 快照")

	assert.EqualValues(t, 0, f.candidateCount(t), "驗證成功後候選 SHALL 立即刪除")
	assert.Equal(t, f.server.currentPassword(), f.storedPassword(t),
		"本地憑證應等於遠端現值")
	assert.NotEqual(t, "oldpass123", f.storedPassword(t))
}

// TestChangeSecretCredentialsNeverEnterArgv 憑證投遞面的機械守衛：
// 新密碼與 sudo 密碼只走 stdin，命令列不得出現任何憑證。
func TestChangeSecretCredentialsNeverEnterArgv(t *testing.T) {
	f := setupChangeSecretFixture(t, "deploy", "oldpass123") // 非 root ⇒ 走 sudo -S 路徑
	plan := f.plan(t, nil)

	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)

	cmd, _ := f.server.lastExecCommand.Load().(string)
	stdin, _ := f.server.lastChpasswdStdin.Load().(string)
	require.NotEmpty(t, cmd, "靶機未收到 exec 指令：本測試的斷言將由空值假綠")
	require.NotEmpty(t, stdin, "靶機未收到 stdin：憑證投遞路徑未被實際走過")

	newPassword := f.server.currentPassword()
	assert.NotContains(t, cmd, newPassword, "新密碼出現在命令列（目標機 ps 可見）")
	assert.NotContains(t, cmd, "oldpass123", "sudo 密碼出現在命令列")
	assert.Contains(t, stdin, newPassword, "新密碼未經 stdin 投遞：投遞路徑已改變")
	assert.Contains(t, stdin, "oldpass123", "sudo 密碼未經 stdin 投遞")
}

// --- D3：遠端失敗的兩種可知性 ---

func TestChangeSecretExitErrorClearsCandidateAndKeepsCredential(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.server.chpasswdExitCode = 1 // 指令跑完但非零退出＝遠端確定未變更
	plan := f.plan(t, nil)

	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretFailed, records[0].Status)
	assert.EqualValues(t, 0, f.candidateCount(t), "遠端確定未變更 ⇒ 候選 SHALL 清除")
	assert.Equal(t, "oldpass123", f.storedPassword(t), "帳號憑證 SHALL 維持原值")

	require.Positive(t, f.server.chpasswdExitFired.Load(),
		"故障注入器未觸發：本測試的斷言由未受測路徑成立（假綠）")
}

func TestChangeSecretTransportFailureKeepsCandidate(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.server.chpasswdDropConn = true // 指令已送出、回應永遠不到＝遠端狀態不可知
	plan := f.plan(t, nil)

	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	assert.EqualValues(t, 1, f.candidateCount(t), "遠端狀態不可知 ⇒ 候選 SHALL 保留")
	assert.Equal(t, "oldpass123", f.storedPassword(t), "SHALL NOT 硬提交未驗證的新密")

	require.Positive(t, f.server.chpasswdDropFired.Load(), "斷線注入器未觸發：假綠")
}

// --- D4：驗證失敗保留 unverified，重試轉正 ---

func TestChangeSecretVerifyFailureThenRetryPromotes(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.server.rejectVerifyLogin = true // 改密會成功，但驗證登入被拒
	plan := f.plan(t, nil)

	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretUnverified, records[0].Status, "錯誤: %s", records[0].Error)
	assert.EqualValues(t, 1, f.candidateCount(t), "候選 SHALL 保留待重試")
	assert.Equal(t, "oldpass123", f.storedPassword(t), "本地憑證 SHALL NOT 被硬提交")
	require.Positive(t, f.server.verifyRejectFired.Load(), "驗證失敗注入器未觸發：假綠")

	// 目標機恢復 ⇒ 重試以候選登入成功 ⇒ 轉正並清候選
	f.server.mu.Lock()
	f.server.rejectVerifyLogin = false
	f.server.mu.Unlock()
	// 退避使 next_attempt_at 落在未來，手動觸發走的是同一條 RetryOne 路徑
	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.First(&cand).Error)
	assert.True(t, cand.Applied, "遠端指令已成功回報 ⇒ applied 應為 true")

	promoted := f.retry.RetryOne(&cand)
	assert.True(t, promoted, "重試應轉正")
	assert.EqualValues(t, 0, f.candidateCount(t), "轉正後候選 SHALL 刪除")
	assert.Equal(t, f.server.currentPassword(), f.storedPassword(t))

	var successCount int64
	require.NoError(t, f.db.Model(&model.ChangeSecretRecord{}).
		Where("status = ?", model.ChangeSecretSuccess).Count(&successCount).Error)
	assert.EqualValues(t, 1, successCount, "轉正 SHALL 補一筆成功記錄，否則使用者只看得到當初的 unverified")
}

func TestChangeSecretRetryBackoffAndAbandon(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	cand, err := f.candidates.Create(context.Background(), CandidateInput{
		AssetID: f.assetID, AccountID: f.accountID, AccountUsername: "root",
		SecretType: model.ChangeSecretTypePassword, Password: "never-valid",
	})
	require.NoError(t, err)

	// 第一次失敗：退避為 base，未放棄
	abandoned, err := f.candidates.RecordFailure(cand, "boom")
	require.NoError(t, err)
	assert.False(t, abandoned)
	var after model.ChangeSecretCandidate
	require.NoError(t, f.db.First(&after, cand.ID).Error)
	assert.EqualValues(t, 1, after.AttemptCount)
	assert.False(t, after.Abandoned)
	assert.WithinDuration(t, time.Now().Add(candidateRetryBase), after.NextAttemptAt, 30*time.Second)

	// 退避單調遞增且受上限封頂
	assert.Equal(t, candidateRetryBase, candidateBackoff(1))
	assert.Equal(t, 2*candidateRetryBase, candidateBackoff(2))
	assert.Equal(t, candidateRetryMax, candidateBackoff(20), "退避 SHALL 受上限封頂")

	// 逾期 ⇒ 標放棄、停止重試、候選列仍在
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
		Update("created_at", time.Now().Add(-candidateRetryDeadline-time.Hour)).Error)
	require.NoError(t, f.db.First(&after, cand.ID).Error)
	abandoned, err = f.candidates.RecordFailure(&after, "still failing")
	require.NoError(t, err)
	assert.True(t, abandoned, "逾期 SHALL 轉為已放棄")

	require.NoError(t, f.db.First(&after, cand.ID).Error)
	assert.True(t, after.Abandoned)
	assert.EqualValues(t, 1, f.candidateCount(t),
		"已放棄的候選 SHALL NOT 被系統自動刪除——它是那把可能已生效的秘密的唯一副本")

	due, err := f.candidates.DueForRetry(50)
	require.NoError(t, err)
	assert.Empty(t, due, "已放棄者 SHALL NOT 再被排入重試")
}

// --- D8：同帳號不疊加候選 ---

func TestChangeSecretSkipsAccountWithPendingCandidate(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	_, err := f.candidates.Create(context.Background(), CandidateInput{
		AssetID: f.assetID, AccountID: f.accountID, AccountUsername: "root",
		SecretType: model.ChangeSecretTypePassword, Password: "pending",
	})
	require.NoError(t, err)

	before := f.server.chpasswdCalls.Load()
	records := f.runner.RunPlan(f.plan(t, nil))
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretSkipped, records[0].Status)
	assert.Equal(t, before, f.server.chpasswdCalls.Load(), "SHALL NOT 觸碰遠端")
	assert.EqualValues(t, 1, f.candidateCount(t), "SHALL NOT 疊加第二筆候選")
}

func TestChangeSecretCandidateUniquePerAccount(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	in := CandidateInput{
		AssetID: f.assetID, AccountID: f.accountID, AccountUsername: "root",
		SecretType: model.ChangeSecretTypePassword, Password: "a",
	}
	_, err := f.candidates.Create(context.Background(), in)
	require.NoError(t, err)
	_, err = f.candidates.Create(context.Background(), in)
	assert.ErrorIs(t, err, ErrCandidateExists, "DB 唯一索引 SHALL 為最終防線")
}

// --- 帳號範圍解析（account 級改密）---

func TestChangeSecretAccountScopeResolution(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	// 加第二個帳號（不同 username）
	require.NoError(t, f.db.Create(&model.AssetAccount{
		AssetID: f.assetID, Username: "deploy", PasswordEnc: "", IsDefault: false,
	}).Error)

	all := f.plan(t, func(p *model.ChangeSecretPlan) {
		p.Accounts = `["@ALL"]`
	})
	records := f.runner.RunPlan(all)
	assert.Len(t, records, 2, "@ALL SHALL 展開為該資產全部帳號")

	// 清掉第一輪產生的候選，讓第二輪不被 D8 擋下
	require.NoError(t, f.db.Where("1 = 1").Delete(&model.ChangeSecretCandidate{}).Error)

	named := f.plan(t, func(p *model.ChangeSecretPlan) {
		p.Accounts = `["deploy"]`
	})
	records = f.runner.RunPlan(named)
	require.Len(t, records, 1, "明列帳號 SHALL 只涵蓋該帳號")
	assert.Equal(t, "deploy", records[0].AccountUsername)
}

func TestChangeSecretPlanAccountScopeDefaultsToAll(t *testing.T) {
	// 空欄位一律讀成 @ALL（回歸安全方向）
	scope := PlanAccountScope(&model.ChangeSecretPlan{})
	assert.True(t, scope.IsAll(), "空帳號範圍 SHALL 讀成 @ALL，否則計劃靜默什麼都不做")
	scope = PlanAccountScope(&model.ChangeSecretPlan{Accounts: `["root"]`})
	assert.False(t, scope.IsAll())
	assert.True(t, scope.Contains("root"))
	assert.False(t, scope.Contains("deploy"))
}

// --- D6：SSH 金鑰輪替三段式 ---

func TestChangeSecretKeyRotationThreeStage(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	oldPriv, oldLine := testKeyPair(t, "old-system-key")
	userLine := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP0000000000000000000000000000000000000000 user-own-key"
	f.server.seedAuthorizedKeys(oldLine + "\n" + userLine + "\n")
	// 帳號改以舊私鑰認證
	require.NoError(t, f.assets.UpdatePrivateKey(f.assetID, f.accountID, "root", oldPriv))

	plan := f.plan(t, func(p *model.ChangeSecretPlan) {
		p.SecretType = model.ChangeSecretTypeSSHKey
	})
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)

	final := f.server.readAuthorizedKeys()
	assert.NotContains(t, final, keyMaterial(oldLine), "驗證成功後 SHALL 刪除本系統先前推送的鑰")
	assert.Contains(t, final, keyMaterial(userLine), "SHALL NOT 動使用者自放的鑰")

	newPriv := f.storedPrivateKey(t)
	assert.NotEqual(t, oldPriv, newPriv, "本地私鑰 SHALL 更新為新鑰")
	newLine, err := PublicLineFromPrivateKey(newPriv)
	require.NoError(t, err)
	assert.Contains(t, final, keyMaterial(newLine), "新公鑰 SHALL 在 authorized_keys 中")
	assert.NotContains(t, final, "PRIVATE KEY", "私鑰 SHALL NOT 出現在目標機")
	assert.EqualValues(t, 0, f.candidateCount(t))
	require.Positive(t, f.server.publicKeyAuthOK.Load(), "公鑰驗證未實際發生：三段式的「驗新」未被走過")
	assertReasonsAreCodes(t, f)
}

func TestChangeSecretKeyRotationVerifyFailureRestores(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	oldPriv, oldLine := testKeyPair(t, "old-system-key")
	original := oldLine + "\n"
	f.server.seedAuthorizedKeys(original)
	require.NoError(t, f.assets.UpdatePrivateKey(f.assetID, f.accountID, "root", oldPriv))

	// 讓「以新私鑰登入」必失敗：靶機的公鑰認證只認 authorized_keys，
	// 故改以 sftp 寫入後把檔案內容還原成舊值來模擬「該檔未被 sshd 採用」
	f.server.mu.Lock()
	f.server.authorizedKeys = func() string { return original }
	f.server.mu.Unlock()

	plan := f.plan(t, func(p *model.ChangeSecretPlan) {
		p.SecretType = model.ChangeSecretTypeSSHKey
	})
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretFailed, records[0].Status,
		"驗證失敗且還原成功 SHALL 記為 failed（零鎖死），實得 %s: %s", records[0].Status, records[0].Error)
	assert.EqualValues(t, 0, f.candidateCount(t), "還原成功後候選 SHALL 清除")
	assert.Equal(t, oldPriv, f.storedPrivateKey(t), "本地私鑰 SHALL 維持舊鑰")

	// 檔案內容回到原狀（剛加入的那一行被移除）
	onDisk := readAuthorizedKeysFile(t, f.server)
	assert.Equal(t, keyMaterial(oldLine), keyMaterial(strings.TrimSpace(onDisk)),
		"authorized_keys SHALL 還原為原內容，實得 %q", onDisk)
	assertReasonsAreCodes(t, f)
}

func TestChangeSecretKeyRotationSFTPUnavailable(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.server.sftpDisabled = true

	plan := f.plan(t, func(p *model.ChangeSecretPlan) {
		p.SecretType = model.ChangeSecretTypeSSHKey
	})
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretFailed, records[0].Status)
	assert.Contains(t, records[0].Error, "SFTP", "SHALL 記錄可讀原因")
	assert.EqualValues(t, 0, f.candidateCount(t))
	require.Positive(t, f.server.sftpRejectFired.Load(), "SFTP 停用注入器未觸發：假綠")
	assertReasonsAreCodes(t, f)
}

func TestChangeSecretKeyRotationExclusiveStrategy(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	userLine := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP1111111111111111111111111111111111111111 stranger"
	f.server.seedAuthorizedKeys(userLine + "\n")

	plan := f.plan(t, func(p *model.ChangeSecretPlan) {
		p.SecretType = model.ChangeSecretTypeSSHKey
		p.KeyStrategy = model.KeyStrategyExclusive
	})
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)

	final := readAuthorizedKeysFile(t, f.server)
	assert.NotContains(t, final, keyMaterial(userLine),
		"exclusive 策略 SHALL 清除來路不明的鑰")
	newLine, err := PublicLineFromPrivateKey(f.storedPrivateKey(t))
	require.NoError(t, err)
	assert.Contains(t, final, keyMaterial(newLine))
	assertReasonsAreCodes(t, f)
}

// --- authorized_keys 行操作的純函式性質 ---

func TestAuthorizedKeysLineOps(t *testing.T) {
	a := "ssh-ed25519 AAAAaaa comment-a"
	b := "ssh-ed25519 AAAAbbb comment-b"

	content := AppendKeyLine("", a)
	assert.Equal(t, a+"\n", content)
	// 冪等：同金鑰材料不重複加入
	assert.Equal(t, content, AppendKeyLine(content, a))
	// comment 不同但材料相同者視為同一把
	assert.Equal(t, content, AppendKeyLine(content, "ssh-ed25519 AAAAaaa other-comment"))

	content = AppendKeyLine(content, b)
	assert.Contains(t, content, "AAAAbbb")

	// 移除以材料比對，忽略 comment 差異
	pruned := RemoveKeyLine(content, "ssh-ed25519 AAAAaaa totally-different-comment")
	assert.NotContains(t, pruned, "AAAAaaa")
	assert.Contains(t, pruned, "AAAAbbb")

	// 移除不存在者為 no-op；空 target 不得清空全檔
	assert.Equal(t, content, RemoveKeyLine(content, ""))
	assert.Equal(t, content, RemoveKeyLine(content, "not-a-key-line"))
}

// --- 顯式清除留痕 ---

func TestChangeSecretCandidateDiscardByAdminIsAudited(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	cand, err := f.candidates.Create(context.Background(), CandidateInput{
		AssetID: f.assetID, AccountID: f.accountID, AccountUsername: "root",
		SecretType: model.ChangeSecretTypePassword, Password: "s3cret-candidate",
	})
	require.NoError(t, err)

	require.NoError(t, f.candidates.DiscardByAdmin(cand.ID, 7, "admin"))
	assert.EqualValues(t, 0, f.candidateCount(t))

	var logs []model.AuditLog
	require.NoError(t, f.db.Find(&logs).Error)
	require.NotEmpty(t, logs, "顯式清除 SHALL 留痕")
	var found bool
	for _, l := range logs {
		if strings.Contains(l.Details, model.AccountOpDiscardCandidate) {
			found = true
			assert.NotContains(t, l.Details, "s3cret-candidate", "審計 SHALL NOT 含秘密材料")
		}
	}
	assert.True(t, found, "SHALL 有一筆 discard_candidate 審計")
}

// readAuthorizedKeysFile 直接讀靶機 home 的實體檔（繞過可能被測試改寫的
// authorizedKeys 讀取器，確保斷言看的是 SFTP 真的寫進去的內容）
func readAuthorizedKeysFile(t *testing.T, s *testSSHServer) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(s.homeDir, ".ssh", "authorized_keys"))
	if err != nil {
		return ""
	}
	return string(data)
}
