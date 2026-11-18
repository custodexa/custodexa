package asset

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
)

// 系統產生金鑰的三條路徑（整組輪替、拆分輪替與單台脫離、改密候選轉正）在建立版本時保存公鑰，
// 以及升級前建立、沒有公鑰的候選在升級後轉正。

// keySharedOn 建一筆以私鑰為秘密的共用憑證並掛到指定的幾台 SSH 資產上。
func (f *rotationFixture) keySharedOn(t *testing.T, name string, k fpKey, hosts ...string) (uint, []uint) {
	t.Helper()
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: name, Username: "ops",
		ProtocolFamily: model.ProtocolFamilySSH, PrivateKey: k.pem})
	require.NoError(t, err)
	ids := make([]uint, 0, len(hosts))
	for _, host := range hosts {
		a := newSSHAsset(t, f.assets, host, host)
		b, err := f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: a.ID})
		require.NoError(t, err)
		ids = append(ids, b.ID)
	}
	return cred.ID, ids
}

func (f *rotationFixture) effectiveVersion(t *testing.T, accountID uint) model.CredentialSecretVersion {
	t.Helper()
	return effectiveVersionRow(t, f.db, accountID)
}

// 共用憑證整組輪替：產生的新鑰其公鑰與私鑰同列保存，各台就位後讀到同一把
func TestFingerprintRotationGroupKeepsGeneratedPublicKey(t *testing.T) {
	f := setupRotationFixture(t)
	old := newFPKey(t)
	credID, accounts := f.keySharedOn(t, "fp-group", old, "10.42.0.1", "10.42.0.2")

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NotNil(t, rot.TargetVersionID)
	target := effectiveVersionRowByID(t, f, *rot.TargetVersionID)
	assertVersionKey(t, f.assets, target, "")
	assert.NotEqual(t, old.line, target.PublicKey, "新鑰的公鑰，不是舊鑰的")

	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	for _, id := range accounts {
		v := f.effectiveVersion(t, id)
		assert.Equal(t, target.ID, v.ID, "PRECONDITION: 各台已就位到本輪版本")
		assertVersionKey(t, f.assets, v, target.PublicKey)
	}
}

func effectiveVersionRowByID(t *testing.T, f *rotationFixture, id uint) model.CredentialSecretVersion {
	t.Helper()
	var v model.CredentialSecretVersion
	require.NoError(t, f.db.First(&v, id).Error)
	return v
}

// 拆分輪替：每台的專用憑證 v1 保存該台新鑰的公鑰（候選列本身沒有公鑰，由轉正時持有的明文取得）
func TestFingerprintRotationSplitDerivesFromCandidatePlaintext(t *testing.T) {
	f := setupRotationFixture(t)
	old := newFPKey(t)
	credID, accounts := f.keySharedOn(t, "fp-split", old, "10.42.1.1", "10.42.1.2")

	rot, err := f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	for _, id := range accounts {
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", id).First(&cand).Error)
		require.Empty(t, cand.PublicKey, "PRECONDITION: 拆分候選沒有保存公鑰（與升級前建立的候選同形）")
	}
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	seen := map[string]bool{}
	for _, id := range accounts {
		acc := f.binding(t, id)
		require.NotEqual(t, credID, acc.CredentialID, "PRECONDITION: 已改綁專用憑證")
		v := f.effectiveVersion(t, id)
		assertVersionKey(t, f.assets, v, "")
		assert.NotEqual(t, old.line, v.PublicKey, "不沿用來源版本的公鑰")
		assert.False(t, seen[v.PublicKey], "各台各自一把")
		seen[v.PublicKey] = true
	}
}

// 升級前的候選在升級後轉正，候選的私鑰無法解析：新版本的公鑰留空，絕不沿用來源版本的公鑰。
//
// 完整流程走不到這裡：派送金鑰前會由私鑰推導要寫入目標機的公鑰行，解析失敗即在遠端動作前失敗
// （下方 RunStopsBeforeCommit 子測試確認）。轉正時的處置因此以轉正所用的兩個函式直接驗證：
// 加密時取公鑰（拆分與改密候選各一）與沿用規則。
func TestFingerprintRotationSplitUnparsableCandidateLeavesUnknown(t *testing.T) {
	f := setupRotationFixture(t)
	old := newFPKey(t)
	credID, accounts := f.keySharedOn(t, "fp-split-bad", old, "10.42.2.1", "10.42.2.2")
	source := f.effectiveVersion(t, accounts[0])
	require.Equal(t, old.line, source.PublicKey, "PRECONDITION: 來源版本有公鑰")

	t.Run("SplitCommitEncrypt", func(t *testing.T) {
		mc := &memberContext{secretType: model.ChangeSecretTypeSSHKey,
			newPrivateKey: material.Adopt([]byte("zz-not-a-private-key"))}
		got, err := f.rotations.encryptRotationSecret(context.Background(), mc)
		require.NoError(t, err)
		require.NotEmpty(t, got.PrivateKeyEnc)
		assert.Empty(t, got.PublicKey, "取不到公鑰時留空")
		next, err := carryOverVersionSecret(f.db, credID, source.ID, got)
		require.NoError(t, err)
		assert.Equal(t, got.PrivateKeyEnc, next.PrivateKeyEnc, "私鑰是新的，不自來源搬")
		assert.Empty(t, next.PublicKey, "不沿用來源版本的公鑰")
	})
	t.Run("SplitCommitEncryptValid", func(t *testing.T) {
		k := newFPKey(t)
		mc := &memberContext{secretType: model.ChangeSecretTypeSSHKey, newPrivateKey: material.Adopt([]byte(k.pem))}
		got, err := f.rotations.encryptRotationSecret(context.Background(), mc)
		require.NoError(t, err)
		assert.Equal(t, k.line, got.PublicKey, "候選沒有公鑰時由轉正持有的明文取得")
	})
	t.Run("ChangeSecretPromoteEncrypt", func(t *testing.T) {
		got, err := f.assets.encryptOwnedPrivateKey(material.Adopt([]byte("zz-not-a-private-key")))
		require.NoError(t, err)
		require.NotEmpty(t, got.PrivateKeyEnc)
		assert.Empty(t, got.PublicKey)
		k := newFPKey(t)
		got, err = f.assets.encryptOwnedPrivateKey(material.Adopt([]byte(k.pem)))
		require.NoError(t, err)
		assert.Equal(t, k.line, got.PublicKey)
	})
	t.Run("RunStopsBeforeCommit", func(t *testing.T) {
		rot, err := f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		target := accounts[1]
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", target).First(&cand).Error)
		require.NoError(t, f.db.Delete(&model.ChangeSecretCandidate{}, cand.ID).Error)
		_, err = f.candidates.CreateInTx(context.Background(), f.db, CandidateInput{
			AssetID: cand.AssetID, AccountID: cand.AccountID, AccountUsername: cand.AccountUsername,
			SecretType: cand.SecretType, CredentialID: cand.CredentialID, PrivateKey: "zz-not-a-private-key",
		})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		assert.Equal(t, credID, f.binding(t, target).CredentialID, "無法解析的候選不會轉正")
		assert.Equal(t, source.PublicKey, f.effectiveVersion(t, target).PublicKey, "該台仍在原版本")
	})
}

// 單台脫離（自訂私鑰）：新專用憑證的公鑰是操作者給的那一把，不是原共用憑證的
func TestFingerprintRotationDetachCustomKey(t *testing.T) {
	f := setupRotationFixture(t)
	old := newFPKey(t)
	credID, accounts := f.keySharedOn(t, "fp-detach", old, "10.42.3.1", "10.42.3.2")
	custom := newFPKey(t)
	_, err := f.rotations.Detach(adminCtx(), credID, accounts[1], DetachCredentialRequest{
		Source: DetachSourceCustom, PrivateKey: custom.pem})
	require.NoError(t, err)
	require.NotEqual(t, credID, f.binding(t, accounts[1]).CredentialID, "PRECONDITION: 已脫離")
	assertVersionKey(t, f.assets, f.effectiveVersion(t, accounts[1]), custom.line)
	assertVersionKey(t, f.assets, f.effectiveVersion(t, accounts[0]), old.line)
}

// 單台脫離（隨機）：同上，公鑰由新產生的鑰取得
func TestFingerprintRotationDetachRandomKey(t *testing.T) {
	f := setupRotationFixture(t)
	old := newFPKey(t)
	credID, accounts := f.keySharedOn(t, "fp-detach-rand", old, "10.42.4.1", "10.42.4.2")
	_, err := f.rotations.Detach(adminCtx(), credID, accounts[0], DetachCredentialRequest{Source: DetachSourceRandom})
	require.NoError(t, err)
	v := f.effectiveVersion(t, accounts[0])
	assertVersionKey(t, f.assets, v, "")
	assert.NotEqual(t, old.line, v.PublicKey)
}

// 改密計劃的金鑰輪替：候選轉正後的版本保存新鑰的公鑰
func TestFingerprintChangeSecretKeyPlanPromotion(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	before := effectiveVersionRow(t, f.db, f.accountID)
	plan := f.plan(t, func(p *model.ChangeSecretPlan) {
		p.SecretType = model.ChangeSecretTypeSSHKey
		p.KeyStrategy = model.KeyStrategyExclusive
	})
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
	after := effectiveVersionRow(t, f.db, f.accountID)
	require.NotEqual(t, before.ID, after.ID, "PRECONDITION: 轉正建立了新版本")
	assertVersionKey(t, f.assets, after, "")
	newLine, err := PublicLineFromPrivateKey(f.storedPrivateKey(t))
	require.NoError(t, err)
	assert.Equal(t, newLine, after.PublicKey, "版本的公鑰即本地保存的新私鑰的公鑰")
}
