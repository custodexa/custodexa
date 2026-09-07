package asset

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 每台各自隨機的拆分與單台脫離共用：逐台成功即改綁、失敗者留在原憑證、
// 剩一掛載自動轉專用、放棄後成功者不回掛，以及脫離的驗證前提與自訂新密。

// errRemoteRejected 遠端確定未變更的注入值（登入被拒／指令非零退出的那一類）
var errRemoteRejected = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}

// --- 4.9 拆分 saga ---

// 逐台成功即改綁專用：三個掛載識別維持不變，原共用憑證零掛載後被刪除
func TestCredentialSplitRotationRebindsPerHost(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "待拆共用", "ops", "old-shared",
		"10.12.0.1", "10.12.0.2", "10.12.0.3")

	rot, err := f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	assert.Equal(t, model.CredentialRotationModeSplit, rot.Mode)
	assert.Nil(t, rot.TargetVersionID, "拆分沒有整組的目標版本")
	for _, accountID := range accounts {
		assert.EqualValues(t, 1, f.candidateCountFor(t, accountID), "起始交易為每台備妥候選")
		assert.Equal(t, credID, f.binding(t, accountID).CredentialID, "起始不先解除關聯")
	}

	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	seen := map[string]bool{}
	credIDs := map[uint]bool{}
	for _, accountID := range accounts {
		m := f.memberFor(t, rot.ID, accountID)
		assert.Equal(t, model.CredentialMemberApplied, m.State)

		acc := f.binding(t, accountID)
		assert.Equal(t, accountID, acc.ID, "掛載識別在改綁前後不變")
		assert.NotEqual(t, credID, acc.CredentialID, "已改綁到自己的專用憑證")
		credIDs[acc.CredentialID] = true

		dedicated := f.credential(t, acc.CredentialID)
		assert.Equal(t, model.CredentialScopeDedicated, dedicated.Scope)
		assert.Nil(t, dedicated.Name, "專用憑證沒有名稱")
		assert.Equal(t, "ops", dedicated.Username)

		secret := f.secretOfBinding(t, accountID)
		assert.NotEqual(t, "old-shared", secret, "各台已改為新秘密")
		assert.False(t, seen[secret], "各台的新秘密互不相同")
		seen[secret] = true
		assert.EqualValues(t, 0, f.candidateCountFor(t, accountID), "就位後候選同交易清除")
	}
	assert.Len(t, credIDs, len(accounts), "每台各得一筆專用憑證")

	_, err = loadCredential(f.db, credID)
	assert.ErrorIs(t, err, ErrCredentialNotFound, "原共用憑證零掛載後被刪除")

	done, err := loadRotation(f.db, rot.ID)
	require.NoError(t, err)
	assert.Equal(t, model.CredentialRotationCompleted, done.Status)
}

// 失敗者留在原憑證上且其秘密未變
func TestCredentialSplitRotationFailureStaysOnShared(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "半拆共用", "ops", "old-shared",
		"10.12.1.1", "10.12.1.2", "10.12.1.3")
	accC := accounts[2]
	f.remote.setRotateErr("10.12.1.3", errRemoteRejected)

	rot, err := f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	for _, accountID := range accounts[:2] {
		assert.Equal(t, model.CredentialMemberApplied, f.memberFor(t, rot.ID, accountID).State)
		assert.NotEqual(t, credID, f.binding(t, accountID).CredentialID)
	}
	accCRow := f.binding(t, accC)
	assert.Equal(t, credID, accCRow.CredentialID, "失敗者仍掛在原憑證上")
	assert.Equal(t, "old-shared", f.secretOfBinding(t, accC), "失敗者的秘密未變")
	assert.NotEqual(t, model.CredentialMemberApplied, f.memberFor(t, rot.ID, accC).State)

	_, rotateCalls, verifyCalls := f.remote.snapshot()
	assert.Equal(t, 1, rotateCalls["10.12.1.3"], "失敗者只被下達一次")
	assert.Equal(t, 0, verifyCalls["10.12.1.3"], "下達即被拒，不進驗證")
}

// 三台中兩台成功拆離：原憑證剩一掛載即轉為專用並清空名稱
func TestCredentialSplitRotationLastBindingBecomesDedicated(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "剩一共用", "ops", "old-shared",
		"10.12.2.1", "10.12.2.2", "10.12.2.3")
	accC := accounts[2]
	effBefore := f.binding(t, accC).EffectiveVersionID
	f.remote.setRotateErr("10.12.2.3", errRemoteRejected)

	rot, err := f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	source := f.credential(t, credID)
	assert.Equal(t, model.CredentialScopeDedicated, source.Scope, "剩一掛載即轉為專用")
	assert.Nil(t, source.Name, "轉專用同交易清空名稱")
	assert.Equal(t, effBefore, f.binding(t, accC).EffectiveVersionID, "剩下那台的就位版本不變")
	assert.Equal(t, "old-shared", f.secretOfBinding(t, accC), "剩下那台的遠端秘密不變")
}

// 放棄後已拆離者維持在自己的專用憑證上，不重新掛回
func TestCredentialSplitRotationAbandonKeepsDetached(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "放棄共用", "ops", "old-shared",
		"10.12.3.1", "10.12.3.2", "10.12.3.3")
	accA := accounts[0]
	f.remote.setVerifyErr("10.12.3.2", errRemoteDropped)
	f.remote.setVerifyErr("10.12.3.3", errRemoteDropped)

	rot, err := f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	detachedCred := f.binding(t, accA).CredentialID
	require.NotEqual(t, credID, detachedCred)
	detachedSecret := f.secretOfBinding(t, accA)

	require.NoError(t, f.rotations.Abandon(adminCtx(), rot.ID))

	assert.Equal(t, detachedCred, f.binding(t, accA).CredentialID, "放棄後不得重新掛回原憑證")
	assert.Equal(t, detachedSecret, f.secretOfBinding(t, accA))
	assert.Equal(t, model.CredentialMemberApplied, f.memberFor(t, rot.ID, accA).State)

	done, err := loadRotation(f.db, rot.ID)
	require.NoError(t, err)
	assert.Equal(t, model.CredentialRotationAbandoned, done.Status)
	after := f.credential(t, credID)
	assert.Nil(t, after.ActiveRotationID)
}

// --- 4.10 單台脫離共用 ---

// 驗證通過才脫離：其餘掛載不受影響，原憑證剩一掛載依收斂規則轉為專用
func TestCredentialDetachVerifiedBeforeRebind(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "脫離共用", "ops", "old-shared", "10.13.0.1", "10.13.0.2")
	accA, accB := accounts[0], accounts[1]
	effABefore := f.binding(t, accA).EffectiveVersionID

	rot, err := f.rotations.Detach(adminCtx(), credID, accB, DetachCredentialRequest{
		Source: DetachSourceRandom,
	})
	require.NoError(t, err)
	require.NotNil(t, rot)

	accBRow := f.binding(t, accB)
	assert.Equal(t, accB, accBRow.ID, "掛載識別不變")
	assert.NotEqual(t, credID, accBRow.CredentialID, "改綁一筆新的專用憑證")
	dedicated := f.credential(t, accBRow.CredentialID)
	assert.Equal(t, model.CredentialScopeDedicated, dedicated.Scope)
	assert.Nil(t, dedicated.Name)
	assert.NotEqual(t, "old-shared", f.secretOfBinding(t, accB), "遠端與本地皆換成新秘密")

	assert.Equal(t, credID, f.binding(t, accA).CredentialID, "其餘掛載不受影響")
	assert.Equal(t, effABefore, f.binding(t, accA).EffectiveVersionID)
	assert.Equal(t, "old-shared", f.secretOfBinding(t, accA), "其餘掛載的秘密未變")

	source := f.credential(t, credID)
	assert.Equal(t, model.CredentialScopeDedicated, source.Scope, "剩一掛載依收斂規則轉專用")
	assert.Nil(t, source.Name)

	// 遠端的順序：先以就位版本下達、再以新秘密驗證，各一次
	_, rotateCalls, verifyCalls := f.remote.snapshot()
	assert.Equal(t, 1, rotateCalls["10.13.0.2"])
	assert.Equal(t, 1, verifyCalls["10.13.0.2"])
	assert.Equal(t, 0, rotateCalls["10.13.0.1"], "未脫離的主機零操作")
}

// 遠端確定拒絕：維持共用關係、就位版本不變，並以機器可讀原因碼回報
func TestCredentialDetachFailureKeepsShared(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "脫離失敗", "ops", "old-shared", "10.13.1.1", "10.13.1.2")
	accA, accB := accounts[0], accounts[1]
	effBBefore := f.binding(t, accB).EffectiveVersionID
	f.remote.setRotateErr("10.13.1.2", errRemoteRejected)

	_, err := f.rotations.Detach(adminCtx(), credID, accB, DetachCredentialRequest{
		Source: DetachSourceRandom,
	})
	require.Error(t, err)
	var failed *CredentialDetachFailedError
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, model.ChangeSecretReasonRemoteRejected, failed.Reason, "回報機器可讀原因碼")

	accBRow := f.binding(t, accB)
	assert.Equal(t, credID, accBRow.CredentialID, "仍掛在原共用憑證")
	assert.Equal(t, effBBefore, accBRow.EffectiveVersionID, "就位版本不變")
	assert.Equal(t, "old-shared", f.secretOfBinding(t, accB))

	source := f.credential(t, credID)
	assert.Equal(t, model.CredentialScopeShared, source.Scope, "原憑證維持共用")
	assert.Equal(t, credID, f.binding(t, accA).CredentialID, "其他掛載不受影響")
	assert.Equal(t, "old-shared", f.secretOfBinding(t, accA))
}

// 自訂新密：驗證通過後成為該台專用憑證的密文版本；回應、審計與記錄皆不含該秘密
func TestCredentialDetachCustomSecret(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "自訂脫離", "ops", "old-shared", "10.13.2.1", "10.13.2.2")
	accB := accounts[1]
	const custom = "Custom-Detach-Secret-9137"

	rot, err := f.rotations.Detach(adminCtx(), credID, accB, DetachCredentialRequest{
		Source: DetachSourceCustom, Password: custom,
	})
	require.NoError(t, err)

	assert.Equal(t, custom, f.secretOfBinding(t, accB), "自訂新密成為該台專用憑證的密文版本")
	f.remote.mu.Lock()
	pushed := f.remote.rotated["10.13.2.2"]
	f.remote.mu.Unlock()
	assert.Equal(t, custom, pushed, "推到遠端的就是操作者給的值")

	raw, err := json.Marshal(rot)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), custom, "回應不含新秘密")

	var logs []model.AuditLog
	require.NoError(t, f.db.Find(&logs).Error)
	require.NotEmpty(t, logs, "脫離必須入審計")
	logsRaw, err := json.Marshal(logs)
	require.NoError(t, err)
	assert.NotContains(t, string(logsRaw), custom, "審計不含新秘密")
	assert.True(t, strings.Contains(string(logsRaw), credentialOpDetach), "審計記下脫離操作")

	var records []model.ChangeSecretRecord
	require.NoError(t, f.db.Find(&records).Error)
	recordsRaw, err := json.Marshal(records)
	require.NoError(t, err)
	assert.NotContains(t, string(recordsRaw), custom, "改密記錄不含新秘密")

	var versions []model.CredentialSecretVersion
	require.NoError(t, f.db.Find(&versions).Error)
	versionsRaw, err := json.Marshal(versions)
	require.NoError(t, err)
	assert.NotContains(t, string(versionsRaw), custom, "版本列的序列化結果不含明文秘密")
}

// 新秘密來源值域外一律拒絕
func TestCredentialDetachRejectsUnknownSource(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "來源檢核", "ops", "old-shared", "10.13.3.1", "10.13.3.2")

	_, err := f.rotations.Detach(adminCtx(), credID, accounts[1], DetachCredentialRequest{
		Source: "inherit",
	})
	assert.ErrorIs(t, err, ErrCredentialDetachSourceInvalid)

	_, err = f.rotations.Detach(adminCtx(), credID, accounts[1], DetachCredentialRequest{
		Source: DetachSourceCustom,
	})
	assert.ErrorIs(t, err, ErrCredentialSecretRequired, "自訂來源必須提供新秘密")

	assert.Equal(t, credID, f.binding(t, accounts[1]).CredentialID, "被拒的請求不動掛載")
}
