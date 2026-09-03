package asset

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 執行器選路：狀態機依資產的改密通道取執行器，通道不可用時的跳過與失敗分流。
//
// 選路與三態處理是狀態機的責任，遠端協定不是——故本檔以 fake executor 注入，
// 不連任何目標機。POSIX 路徑的真連線行為由 change_secret_reliability_test.go 承擔。

// fakeExecutor 記下被呼叫的目標，並依設定回傳指定錯誤。
type fakeExecutor struct {
	mu          sync.Mutex
	rotateCalls []rotationTarget
	verifyCalls []rotationTarget
	rotateErr   error
	verifyErr   error
}

func (f *fakeExecutor) Rotate(_ context.Context, t rotationTarget, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rotateCalls = append(f.rotateCalls, t)
	return f.rotateErr
}

func (f *fakeExecutor) Verify(_ context.Context, t rotationTarget, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifyCalls = append(f.verifyCalls, t)
	return f.verifyErr
}

// channelRecorder 包住工廠，記下每次被要求的通道值。
type channelRecorder struct {
	mu        sync.Mutex
	requested []string
	inner     func(string) rotationExecutor
}

func (c *channelRecorder) factory(channel string) rotationExecutor {
	c.mu.Lock()
	c.requested = append(c.requested, channel)
	c.mu.Unlock()
	return c.inner(channel)
}

func (c *channelRecorder) sawChannel(channel string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, v := range c.requested {
		if v == channel {
			return true
		}
	}
	return false
}

// addRotationAsset 在既有 fixture 的庫內另建一台資產（含預設帳號憑證）。
func (f *csFixture) addRotationAsset(t *testing.T, req *CreateAssetRequest) uint {
	t.Helper()
	req.CreatedBy = 1
	asset, err := f.assets.Create(req)
	require.NoError(t, err)
	var acct model.AssetAccount
	require.NoError(t, f.db.Where("asset_id = ?", asset.ID).First(&acct).Error)
	return asset.ID
}

// planForAssets 建一份涵蓋指定資產的計劃。
func (f *csFixture) planForAssets(t *testing.T, ids []uint, mut func(*model.ChangeSecretPlan)) *model.ChangeSecretPlan {
	t.Helper()
	return f.plan(t, func(p *model.ChangeSecretPlan) {
		raw, err := json.Marshal(ids)
		require.NoError(t, err)
		p.AssetIDs = string(raw)
		if mut != nil {
			mut(p)
		}
	})
}

func recordByAsset(records []model.ChangeSecretRecord, assetID uint) *model.ChangeSecretRecord {
	for i := range records {
		if records[i].AssetID == assetID {
			return &records[i]
		}
	}
	return nil
}

// TestRotationExecutorSelectedByChannel 同一份計劃涵蓋 ssh 與 rdp+WinRM 兩台資產時，
// 各自取到自己的執行器，且各產生一筆記錄。
func TestRotationExecutorSelectedByChannel(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")

	winrmID := f.addRotationAsset(t, &CreateAssetRequest{
		Name: "win-rdp", Protocol: model.ProtocolRDP, Host: "10.9.9.9", Port: 3389,
		Username: "Administrator", Password: "winoldpass",
		RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP,
	})

	fake := &fakeExecutor{}
	rec := &channelRecorder{inner: func(string) rotationExecutor { return fake }}
	f.runner.executors = rec.factory

	plan := f.planForAssets(t, []uint{f.assetID, winrmID}, nil)
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 2)

	assert.True(t, rec.sawChannel(model.RotationChannelPosixSSH),
		"ssh 資產須以 posix_ssh 通道取執行器")
	assert.True(t, rec.sawChannel(model.RotationChannelWindowsWinRM),
		"設為 WinRM 的 rdp 資產須以 windows_winrm 通道取執行器")

	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, "錯誤: %s", r.Error)
	}

	// 目標描述須帶得動執行器需要的東西：資產本體、通道、帳號名與秘密型別
	fake.mu.Lock()
	defer fake.mu.Unlock()
	require.Len(t, fake.rotateCalls, 2)
	require.Len(t, fake.verifyCalls, 2, "驗證步驟同樣經介面")
	channels := map[string]rotationTarget{}
	for _, c := range fake.rotateCalls {
		require.NotNil(t, c.asset, "目標須帶資產本體（WinRM 執行器要讀通道設定）")
		assert.Equal(t, model.ChangeSecretTypePassword, c.secretType)
		assert.NotEmpty(t, c.username)
		channels[c.channel] = c
	}
	require.Contains(t, channels, model.RotationChannelPosixSSH)
	require.Contains(t, channels, model.RotationChannelWindowsWinRM)
	assert.Equal(t, "10.9.9.9:3389", channels[model.RotationChannelWindowsWinRM].addr,
		"SSH 家族位址沿資產埠；WinRM 執行器自資產另行推導自己的埠")
}

// TestRotationExecutorPosixSelectedByDefault 未注入 fake 時，ssh 資產取到的是
// POSIX 執行器——選路的預設值本身也要有守衛，否則上一支測試只證明了工廠可換。
func TestRotationExecutorPosixSelectedByDefault(t *testing.T) {
	assert.IsType(t, posixSSHExecutor{}, rotationExecutorFor(model.RotationChannelPosixSSH))
	assert.IsType(t, windowsWinRMExecutor{}, rotationExecutorFor(model.RotationChannelWindowsWinRM))
	assert.IsType(t, windowsSSHExecutor{}, rotationExecutorFor(model.RotationChannelWindowsSSH))
	assert.IsType(t, notWiredExecutor{}, rotationExecutorFor(model.RotationChannelNone))
}

// TestResolveTargetsSkipsByChannel 通道決定跳過與否，且兩種跳過分碼。
func TestResolveTargetsSkipsByChannel(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")

	noChannelID := f.addRotationAsset(t, &CreateAssetRequest{
		Name: "rdp-plain", Protocol: model.ProtocolRDP, Host: "10.9.9.10", Port: 3389,
		Username: "Administrator", Password: "p",
	})
	dbID := f.addRotationAsset(t, &CreateAssetRequest{
		Name: "mysql-plain", Protocol: model.ProtocolMySQL, Host: "10.9.9.11", Port: 3306,
		Username: "app", Password: "p",
	})
	sshNoneID := f.addRotationAsset(t, &CreateAssetRequest{
		Name: "ssh-opted-out", Protocol: model.ProtocolSSH, Host: "10.9.9.12", Port: 22,
		Username: "root", Password: "p", RotationChannel: model.RotationChannelNone,
	})

	f.runner.executors = func(string) rotationExecutor { return &fakeExecutor{} }

	plan := f.planForAssets(t, []uint{noChannelID, dbID, sshNoneID}, nil)
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 3)

	noChannel := recordByAsset(records, noChannelID)
	require.NotNil(t, noChannel)
	assert.Equal(t, model.ChangeSecretSkipped, noChannel.Status)
	assert.Equal(t, model.ChangeSecretReasonChannelNotConfigured, noChannel.Error,
		"改得了密但沒設通道的資產，原因碼須指出是設定缺口而非協定不支援")

	dbRec := recordByAsset(records, dbID)
	require.NotNil(t, dbRec)
	assert.Equal(t, model.ChangeSecretSkipped, dbRec.Status)
	assert.Equal(t, model.ChangeSecretReasonProtocolUnsupported, dbRec.Error,
		"沒有作業系統帳號可換的協定維持既有原因碼")

	optedOut := recordByAsset(records, sshNoneID)
	require.NotNil(t, optedOut)
	assert.Equal(t, model.ChangeSecretSkipped, optedOut.Status)
	assert.Equal(t, model.ChangeSecretReasonChannelNotConfigured, optedOut.Error,
		"顯式關閉改密的 ssh 資產須跳過而非照舊改密")
}

// TestResolveTargetsSkipsWindowsKeyRotation Windows 通道不支援 SSH 金鑰輪替：
// 誠實跳過，不得以密碼路徑冒充成功。
func TestResolveTargetsSkipsWindowsKeyRotation(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")

	winrmID := f.addRotationAsset(t, &CreateAssetRequest{
		Name: "win-key", Protocol: model.ProtocolRDP, Host: "10.9.9.13", Port: 3389,
		Username: "Administrator", Password: "p",
		RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP,
	})

	fake := &fakeExecutor{}
	f.runner.executors = func(string) rotationExecutor { return fake }

	plan := f.planForAssets(t, []uint{winrmID}, func(p *model.ChangeSecretPlan) {
		p.SecretType = model.ChangeSecretTypeSSHKey
	})
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretSkipped, records[0].Status)
	assert.Equal(t, model.ChangeSecretReasonSecretTypeUnsupported, records[0].Error)

	fake.mu.Lock()
	defer fake.mu.Unlock()
	assert.Empty(t, fake.rotateCalls, "跳過的資產不得觸碰執行器")
}

// TestNotWiredExecutorIsCleanFailure 選路落到沒有執行器的分支：記為 failed、
// 帶「未設定改密通道」、候選清乾淨且本地憑證不動。
//
// Windows 執行器接線後，正常選路已走不到這裡（`none` 在 resolveTargets 先跳過），
// 故以注入的工廠強制取到 notWiredExecutor。它必須是**乾淨失敗**而非 unverified，
// 否則候選會卡住該帳號後續全部改密。
func TestNotWiredExecutorIsCleanFailure(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")

	winrmID := f.addRotationAsset(t, &CreateAssetRequest{
		Name: "win-unwired", Protocol: model.ProtocolRDP, Host: "10.9.9.14", Port: 3389,
		Username: "Administrator", Password: "winoldpass",
		RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP,
	})
	f.runner.executors = func(string) rotationExecutor { return notWiredExecutor{} }

	plan := f.planForAssets(t, []uint{winrmID}, nil)
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretFailed, records[0].Status)
	assert.Equal(t, model.ChangeSecretReasonChannelNotConfigured, records[0].Error)
	assert.EqualValues(t, 0, f.candidateCount(t), "未觸碰遠端 ⇒ 候選 SHALL 清除")

	// 哨兵可被 errors.Is 認出：2.x 換上真執行器時，這條分支要能被找出來刪掉
	err := notWiredExecutor{}.Rotate(context.Background(), rotationTarget{}, "old", "new")
	require.ErrorIs(t, err, errExecutorNotWired)
	var localErr *localPreconditionError
	require.True(t, errors.As(err, &localErr), "未接線須走本地前置失敗分支")
	assert.Equal(t, model.ChangeSecretReasonChannelNotConfigured, localErr.reason)
}

// TestRemoteRejectedErrorCarriesReason 分流型別的形狀守衛：
// reason 落記錄、cause 只進 log（遠端原文是攻擊者可控輸入）。
func TestRemoteRejectedErrorCarriesReason(t *testing.T) {
	cause := errors.New("root:S3cret! rejected by pam")
	err := error(&remoteRejectedError{
		reason: model.ChangeSecretReasonRemoteRejected, cause: cause,
	})

	var rejected *remoteRejectedError
	require.True(t, errors.As(err, &rejected))
	assert.Equal(t, model.ChangeSecretReasonRemoteRejected, rejected.reason)
	require.ErrorIs(t, err, cause, "底層原因須可被 errors.Is 追出（供日誌與診斷）")
	assert.True(t, model.IsChangeSecretReason(rejected.reason),
		"落記錄的 reason 必須在原因碼封閉集內")
}

// TestRetryRunnerVerifiesThroughExecutor 重試走的是同一條驗證路徑——
// 兩邊分岔即會出現「手動能過、自動不能」的行為差異。
func TestRetryRunnerVerifiesThroughExecutor(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.server.rejectVerifyLogin = true

	plan := f.plan(t, nil)
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	require.EqualValues(t, 1, f.candidateCount(t))

	fake := &fakeExecutor{}
	rec := &channelRecorder{inner: func(string) rotationExecutor { return fake }}
	f.retry.executors = rec.factory

	// 退避使 next_attempt_at 落在未來，手動觸發走的是同一條 RetryOne 路徑
	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.First(&cand).Error)
	assert.True(t, f.retry.RetryOne(&cand), "重試應轉正")

	fake.mu.Lock()
	defer fake.mu.Unlock()
	require.Len(t, fake.verifyCalls, 1, "重試須經介面驗證，不得自行撥號")
	assert.Empty(t, fake.rotateCalls, "重試只驗證，不重新改密")
	assert.True(t, rec.sawChannel(model.RotationChannelPosixSSH))
}
