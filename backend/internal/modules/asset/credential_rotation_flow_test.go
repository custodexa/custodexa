package asset

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 整組改密的流程行為：部分成功與逐台就位、全部就位才提升現行版本、
// 重試與補跑重用同一個待生效版本、放棄不回滾、期間鎖定、金鑰型別整組換。

// errRemoteDropped 遠端結果不明（連線中斷）的注入值：沿分流契約落在
// 「不可知」那一類——候選保留、成員停在已下達未驗證
var errRemoteDropped = errors.New("connection dropped")

// --- 4.4 部分成功與收斂 ---

// 部分成功：甲用新版、乙用起始版，兩台各只一次登入嘗試，聚合態 partial
func TestCredentialRotationPartialSuccessKeepsPerHostVersions(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用甲", "ops", "old-shared", "10.11.0.1", "10.11.0.2")
	accA, accB := accounts[0], accounts[1]
	before := f.credential(t, credID)
	f.remote.setVerifyErr("10.11.0.2", errRemoteDropped)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	memberA := f.memberFor(t, rot.ID, accA)
	memberB := f.memberFor(t, rot.ID, accB)
	assert.Equal(t, model.CredentialMemberApplied, memberA.State)
	assert.Equal(t, model.CredentialMemberChangedUnverified, memberB.State,
		"遠端結果不明的成員停在已下達未驗證")

	pushed, rotateCalls, verifyCalls := f.remote.snapshot()
	newSecret := pushed["10.11.0.1"]
	require.NotEmpty(t, newSecret)
	assert.Equal(t, newSecret, pushed["10.11.0.2"], "整組換的是同一組秘密")
	assert.Equal(t, newSecret, f.secretOfBinding(t, accA), "甲以新版連線")
	assert.Equal(t, "old-shared", f.secretOfBinding(t, accB), "乙仍以起始版連線")
	assert.Equal(t, 1, rotateCalls["10.11.0.1"])
	assert.Equal(t, 1, verifyCalls["10.11.0.1"], "甲只發生一次登入嘗試")
	assert.Equal(t, 1, rotateCalls["10.11.0.2"])
	assert.Equal(t, 1, verifyCalls["10.11.0.2"], "乙只發生一次登入嘗試")

	assert.EqualValues(t, 1, f.candidateCountFor(t, accA)*0+f.candidateCountFor(t, accB),
		"結果不明者保留候選")
	assert.EqualValues(t, 0, f.candidateCountFor(t, accA), "已就位者的候選同交易清除")

	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.Equal(t, CredentialAggregatePartial, state)

	after := f.credential(t, credID)
	require.NotNil(t, after.CurrentVersionID)
	assert.Equal(t, *before.CurrentVersionID, *after.CurrentVersionID,
		"未全部就位前不得提升現行版本")
	require.NotNil(t, after.PendingVersionID)
	require.NotNil(t, after.ActiveRotationID)
}

// 全部就位：同交易提升現行版本、清空待生效與進行中指標，聚合態回 idle
func TestCredentialRotationPromotesPendingWhenAllApplied(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用乙", "ops", "old-shared", "10.11.1.1", "10.11.1.2")

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	pendingID := *rot.TargetVersionID
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	for _, accountID := range accounts {
		m := f.memberFor(t, rot.ID, accountID)
		assert.Equal(t, model.CredentialMemberApplied, m.State)
		assert.NotNil(t, m.AppliedAt)
		acc := f.binding(t, accountID)
		require.NotNil(t, acc.EffectiveVersionID)
		assert.Equal(t, pendingID, *acc.EffectiveVersionID)
		assert.EqualValues(t, 0, f.candidateCountFor(t, accountID))
	}

	after := f.credential(t, credID)
	require.NotNil(t, after.CurrentVersionID)
	assert.Equal(t, pendingID, *after.CurrentVersionID, "待生效版本提升為現行版本")
	assert.Nil(t, after.PendingVersionID, "待生效指標清空")
	assert.Nil(t, after.ActiveRotationID, "進行中指標清空")

	done, err := loadRotation(f.db, rot.ID)
	require.NoError(t, err)
	assert.Equal(t, model.CredentialRotationCompleted, done.Status)
	assert.NotNil(t, done.FinishedAt)

	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.Equal(t, CredentialAggregateIdle, state)
	assert.EqualValues(t, 2, f.versionCount(t, credID), "整輪只產生一個新版本")
}

// --- 4.5 重試與逐台補跑 ---

// 補跑重用同一個待生效版本，不產生第二個秘密
func TestCredentialRotationRetryReusesPendingVersion(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用丙", "ops", "old-shared", "10.11.2.1", "10.11.2.2")
	accB := accounts[1]
	f.remote.setVerifyErr("10.11.2.2", errRemoteDropped)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	pendingID := *rot.TargetVersionID
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	firstPush, _, _ := f.remote.snapshot()

	// 遠端恢復後補跑：不得再產生一組新秘密
	f.remote.setVerifyErr("10.11.2.2", nil)
	memberB := f.memberFor(t, rot.ID, accB)
	require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, memberB.ID))

	afterPush, rotateCalls, verifyCalls := f.remote.snapshot()
	assert.Equal(t, firstPush["10.11.2.2"], afterPush["10.11.2.2"], "補跑推的是同一組秘密")
	assert.Equal(t, 1, rotateCalls["10.11.2.2"], "補跑不重下改密指令，只重新驗證")
	assert.Equal(t, 2, verifyCalls["10.11.2.2"], "補跑再驗一次")

	assert.EqualValues(t, 2, f.versionCount(t, credID), "重試不得產生第二個待生效版本")
	memberB = f.memberFor(t, rot.ID, accB)
	assert.Equal(t, model.CredentialMemberApplied, memberB.State)
	acc := f.binding(t, accB)
	require.NotNil(t, acc.EffectiveVersionID)
	assert.Equal(t, pendingID, *acc.EffectiveVersionID)

	after := f.credential(t, credID)
	require.NotNil(t, after.CurrentVersionID)
	assert.Equal(t, pendingID, *after.CurrentVersionID, "補跑收斂後提升現行版本")
	assert.Nil(t, after.PendingVersionID)
}

// 逐台補跑只操作指定成員：其餘成員的狀態、就位版本與遠端往返皆不變
func TestCredentialRotationMemberRetryTouchesOnlyThatMember(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用丁", "ops", "old-shared",
		"10.11.3.1", "10.11.3.2", "10.11.3.3")
	accA, accB, accC := accounts[0], accounts[1], accounts[2]
	f.remote.setVerifyErr("10.11.3.2", errRemoteDropped)
	f.remote.setVerifyErr("10.11.3.3", errRemoteDropped)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	beforeC := f.memberFor(t, rot.ID, accC)
	beforeA := f.memberFor(t, rot.ID, accA)
	effCBefore := f.binding(t, accC).EffectiveVersionID
	_, rotateBefore, verifyBefore := f.remote.snapshot()

	f.remote.setVerifyErr("10.11.3.2", nil)
	memberB := f.memberFor(t, rot.ID, accB)
	require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, memberB.ID))

	assert.Equal(t, model.CredentialMemberApplied,
		f.memberFor(t, rot.ID, accB).State, "被指定的成員推進")

	afterC := f.memberFor(t, rot.ID, accC)
	assert.Equal(t, beforeC.State, afterC.State, "未被指定的成員狀態不變")
	assert.Equal(t, beforeC.AttemptCount, afterC.AttemptCount, "未被指定的成員不累計嘗試")
	assert.Equal(t, effCBefore, f.binding(t, accC).EffectiveVersionID, "未被指定的成員就位版本不變")
	assert.Equal(t, beforeA.State, f.memberFor(t, rot.ID, accA).State)

	_, rotateAfter, verifyAfter := f.remote.snapshot()
	assert.Equal(t, rotateBefore["10.11.3.3"], rotateAfter["10.11.3.3"], "未被指定的主機零額外操作")
	assert.Equal(t, verifyBefore["10.11.3.3"], verifyAfter["10.11.3.3"])
	assert.Equal(t, rotateBefore["10.11.3.1"], rotateAfter["10.11.3.1"])
	assert.Equal(t, verifyBefore["10.11.3.1"], verifyAfter["10.11.3.1"])

	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.Equal(t, CredentialAggregatePartial, state, "尚有成員未就位，聚合態仍為 partial")
}

// --- 4.6 放棄不回滾 ---

// 放棄：已就位者不改回舊密、候選不刪、遠端零額外操作，憑證終態 out_of_sync
func TestCredentialRotationAbandonDoesNotRollBack(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用戊", "ops", "old-shared", "10.11.4.1", "10.11.4.2")
	accA, accB := accounts[0], accounts[1]
	f.remote.setVerifyErr("10.11.4.2", errRemoteDropped)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	pendingID := *rot.TargetVersionID
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	effABefore := f.binding(t, accA).EffectiveVersionID
	pushed, rotateBefore, verifyBefore := f.remote.snapshot()

	require.NoError(t, f.rotations.Abandon(adminCtx(), rot.ID))

	assert.Equal(t, pendingID, *f.binding(t, accA).EffectiveVersionID, "已就位者不改回舊密")
	assert.Equal(t, effABefore, f.binding(t, accA).EffectiveVersionID)
	assert.Equal(t, pushed["10.11.4.1"], f.secretOfBinding(t, accA))
	assert.Equal(t, "old-shared", f.secretOfBinding(t, accB), "未就位者維持起始版")
	assert.EqualValues(t, 1, f.candidateCountFor(t, accB), "放棄不刪候選")

	_, rotateAfter, verifyAfter := f.remote.snapshot()
	assert.Equal(t, rotateBefore, rotateAfter, "放棄時遠端零額外操作")
	assert.Equal(t, verifyBefore, verifyAfter, "放棄時遠端零額外操作")

	assert.Equal(t, model.CredentialMemberApplied, f.memberFor(t, rot.ID, accA).State)
	assert.Equal(t, model.CredentialMemberChangedUnverified, f.memberFor(t, rot.ID, accB).State,
		"結果不明的成員保留證據")

	done, err := loadRotation(f.db, rot.ID)
	require.NoError(t, err)
	assert.Equal(t, model.CredentialRotationAbandoned, done.Status)

	after := f.credential(t, credID)
	assert.Nil(t, after.ActiveRotationID, "放棄後不再鎖住憑證")
	require.NotNil(t, after.PendingVersionID)
	assert.Equal(t, pendingID, *after.PendingVersionID, "待生效版本保留供逐台補跑")
	assert.NotEqual(t, pendingID, *after.CurrentVersionID, "放棄不強制提升待生效版本")

	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.Equal(t, CredentialAggregateOutOfSync, state)
}

// 放棄時無任何成員動過遠端：待生效版本丟棄，憑證回到 idle
func TestCredentialRotationAbandonBeforeAnyRemoteContactReturnsIdle(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用己", "ops", "old-shared", "10.11.5.1", "10.11.5.2")

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Abandon(adminCtx(), rot.ID))

	for _, accountID := range accounts {
		assert.Equal(t, model.CredentialMemberAbandoned, f.memberFor(t, rot.ID, accountID).State)
		assert.Equal(t, "old-shared", f.secretOfBinding(t, accountID))
	}
	_, rotateCalls, verifyCalls := f.remote.snapshot()
	assert.Empty(t, rotateCalls, "沒有任何遠端被觸碰")
	assert.Empty(t, verifyCalls)

	after := f.credential(t, credID)
	assert.Nil(t, after.ActiveRotationID)
	assert.Nil(t, after.PendingVersionID, "這一輪等於沒發生過")

	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.Equal(t, CredentialAggregateIdle, state)

	// 回到 idle 即可再次發起
	_, err = f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	assert.NoError(t, err)
}

// 未收斂前禁止新一輪
func TestCredentialRotationOutOfSyncBlocksNewRound(t *testing.T) {
	f := setupRotationFixture(t)
	credID, _ := f.sharedOn(t, "共用庚", "ops", "old-shared", "10.11.6.1", "10.11.6.2")
	f.remote.setVerifyErr("10.11.6.2", errRemoteDropped)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	require.NoError(t, f.rotations.Abandon(adminCtx(), rot.ID))

	_, err = f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	assert.ErrorIs(t, err, ErrCredentialOutOfSync)
	_, err = f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
	assert.ErrorIs(t, err, ErrCredentialOutOfSync, "拆分同樣要先收斂")
}

// --- 4.7 輪替期間的憑證列鎖 ---

// 輪替進行中：掛載、卸載、直接改密文、改綁、範圍轉換、刪除、再輪替一律拒絕
func TestCredentialRotationActiveBlocksConflictingOps(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用辛", "ops", "old-shared", "10.11.7.1", "10.11.7.2")
	spare := newSSHAsset(t, f.assets, "10.11.7.9", "10.11.7.9")
	other, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "另一筆共用", Username: "ops", ProtocolFamily: model.ProtocolFamilySSH,
		Password: "other-pw",
	})
	require.NoError(t, err)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NotNil(t, rot)

	_, err = f.creds.Bind(adminCtx(), credID, &BindCredentialRequest{AssetID: spare.ID})
	assert.ErrorIs(t, err, ErrCredentialRotationActive, "掛載被拒")

	err = f.creds.Unbind(adminCtx(), credID, accounts[0])
	assert.ErrorIs(t, err, ErrCredentialRotationActive, "卸載被拒")

	_, err = f.creds.SetSecret(adminCtx(), credID, &SetCredentialSecretRequest{Password: "declared"})
	assert.ErrorIs(t, err, ErrCredentialRotationActive, "直接寫入密文被拒")

	acc := f.binding(t, accounts[0])
	_, err = f.creds.Rebind(adminCtx(), acc.AssetID, acc.ID, other.ID)
	assert.ErrorIs(t, err, ErrCredentialRotationActive, "更換掛載所引用的憑證被拒")

	_, err = f.creds.ConvertScope(adminCtx(), credID, &ConvertCredentialScopeRequest{
		Scope: model.CredentialScopeDedicated,
	})
	assert.ErrorIs(t, err, ErrCredentialRotationActive, "範圍轉換被拒")

	err = f.creds.Delete(adminCtx(), credID)
	assert.ErrorIs(t, err, ErrCredentialRotationActive, "刪除被拒")

	_, err = f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	assert.ErrorIs(t, err, ErrCredentialRotationActive, "再輪替被拒")

	// 被拒的操作不得改動成員快照與收斂判斷
	members, err := f.rotations.Members(rot.ID)
	require.NoError(t, err)
	require.Len(t, members, 2)
	for i := range members {
		assert.Equal(t, model.CredentialMemberQueued, members[i].State)
	}
	for _, accountID := range accounts {
		assert.Equal(t, "old-shared", f.secretOfBinding(t, accountID))
	}
}

// --- 4.8 金鑰型別整組換 ---

// 金鑰型別：同一把新金鑰推到全部成員，逐台驗證後各自就位
func TestCredentialRotationKeyTypeGroupChange(t *testing.T) {
	f := setupRotationFixture(t)
	oldPrivate, _, err := GenerateSSHKeyPair("seed-key")
	require.NoError(t, err)
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "共用金鑰", Username: "ops", ProtocolFamily: model.ProtocolFamilySSH,
		SecretType: model.ChangeSecretTypeSSHKey, PrivateKey: oldPrivate,
	})
	require.NoError(t, err)
	var accounts []uint
	for _, host := range []string{"10.11.8.1", "10.11.8.2"} {
		asset := newSSHAsset(t, f.assets, host, host)
		binding, berr := f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: asset.ID})
		require.NoError(t, berr)
		accounts = append(accounts, binding.ID)
	}

	rot, err := f.rotations.Start(adminCtx(), cred.ID, StartRotationRequest{})
	require.NoError(t, err)
	pendingID := *rot.TargetVersionID
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	f.remote.mu.Lock()
	first := f.remote.keyDelivered["10.11.8.1"]
	second := f.remote.keyDelivered["10.11.8.2"]
	f.remote.mu.Unlock()
	require.NotEmpty(t, first)
	assert.Equal(t, first, second, "同一把新金鑰推到全部成員")
	assert.NotEqual(t, oldPrivate, first, "推的是新產生的金鑰")

	for _, accountID := range accounts {
		m := f.memberFor(t, rot.ID, accountID)
		assert.Equal(t, model.CredentialMemberApplied, m.State)
		acc := f.binding(t, accountID)
		require.NotNil(t, acc.EffectiveVersionID)
		assert.Equal(t, pendingID, *acc.EffectiveVersionID)
	}
	resolved, err := f.assets.resolver.ResolveVersion(adminCtx(), cred.ID, pendingID)
	require.NoError(t, err)
	assert.Equal(t, first, resolved.PrivateKey, "就位的正是推到遠端的那一把")
	assert.Equal(t, model.ChangeSecretTypeSSHKey, resolved.SecretType)

	after := f.credential(t, cred.ID)
	require.NotNil(t, after.CurrentVersionID)
	assert.Equal(t, pendingID, *after.CurrentVersionID)
	assert.Nil(t, after.PendingVersionID)
	assert.EqualValues(t, 2, f.versionCount(t, cred.ID))
}
