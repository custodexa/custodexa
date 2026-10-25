package asset

import (
	"context"
	"encoding/pem"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// unparsablePrivateKeys 寫入路徑必須擋下的兩類私鑰：格式錯誤與受 passphrase 保護。
func unparsablePrivateKeys(t *testing.T) map[string]string {
	t.Helper()
	valid, _ := testKeyPair(t, "write-path")
	return map[string]string{
		"Malformed":  valid[:len(valid)/2],
		"Passphrase": encryptedEd25519PEM(t),
	}
}

func encryptedEd25519PEM(t *testing.T) string {
	t.Helper()
	_, priv := genEd25519OpenSSHPEM(t)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte("secret-phrase"))
	require.NoError(t, err)
	return string(pem.EncodeToMemory(block))
}

// writeRowCounts 寫入路徑會碰到的資料表筆數快照（被拒的請求前後必須相同）。
type writeRowCounts struct {
	assets, accounts, credentials, versions int64
}

func countWriteRows(t *testing.T, db *gorm.DB) writeRowCounts {
	t.Helper()
	var c writeRowCounts
	require.NoError(t, db.Model(&model.Asset{}).Count(&c.assets).Error)
	require.NoError(t, db.Model(&model.AssetAccount{}).Count(&c.accounts).Error)
	require.NoError(t, db.Model(&model.Credential{}).Count(&c.credentials).Error)
	require.NoError(t, db.Model(&model.CredentialSecretVersion{}).Count(&c.versions).Error)
	return c
}

// seedUnparsablePrivateKey 直寫密文：把指定版本列的私鑰換成一把無法解析的內容。
//
// **繞過寫入驗證是刻意的**：要驗的是「只改密碼時不重驗庫內既有私鑰」，而那個
// 狀態按定義走不到驗證後的寫入路徑（只可能來自驗證上線前的舊資料）。fixture 若是
// 好鑰，實作錯誤地重驗舊鑰也照樣綠，測試就不算數。回傳寫入的密文供逐位元比對。
func seedUnparsablePrivateKey(t *testing.T, db *gorm.DB, svc *AssetService, versionID uint) string {
	t.Helper()
	enc, err := svc.crypto.EncryptFor(context.Background(), keyvault.RefCredentialVersionPrivateKey, "-----BEGIN OPENSSH PRIVATE KEY-----\nbroken\n")
	require.NoError(t, err)
	require.NoError(t, db.Model(&model.CredentialSecretVersion{}).Where("id = ?", versionID).
		Update("private_key_enc", enc).Error)
	return enc
}

func effectiveVersionRow(t *testing.T, db *gorm.DB, accountID uint) model.CredentialSecretVersion {
	t.Helper()
	var account model.AssetAccount
	require.NoError(t, db.First(&account, accountID).Error)
	require.NotNil(t, account.EffectiveVersionID)
	var v model.CredentialSecretVersion
	require.NoError(t, db.First(&v, *account.EffectiveVersionID).Error)
	return v
}

func defaultAccountOf(t *testing.T, db *gorm.DB, assetID uint) model.AssetAccount {
	t.Helper()
	var account model.AssetAccount
	require.NoError(t, db.Where("asset_id = ? AND is_default = ?", assetID, true).First(&account).Error)
	return account
}

func pkStrPtr(s string) *string { return &s }

// --- 2.1 資產建立與更新 ---

func TestPrivateKeyWriteAssetCreateRejectsUnparsable(t *testing.T) {
	for name, bad := range unparsablePrivateKeys(t) {
		t.Run(name+"/TopLevel", func(t *testing.T) {
			db := setupAccountDB(t)
			assets, _ := newAccountServices(t)
			before := countWriteRows(t, db)
			_, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
				Name: "pk-top", Protocol: model.ProtocolSSH, Host: "10.31.0.1", Port: 22,
				Username: "root", PrivateKey: bad, CreatedBy: 1,
			})
			require.ErrorIs(t, err, ErrPrivateKeyInvalid)
			assert.Equal(t, before, countWriteRows(t, db), "被拒的請求不得寫入任何資料列")
		})
		t.Run(name+"/Inline", func(t *testing.T) {
			db := setupAccountDB(t)
			assets, _ := newAccountServices(t)
			before := countWriteRows(t, db)
			_, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
				Name: "pk-inline", Protocol: model.ProtocolSSH, Host: "10.31.0.2", Port: 22,
				Credential: &InlineCredential{Username: "root", PrivateKey: bad}, CreatedBy: 1,
			})
			require.ErrorIs(t, err, ErrPrivateKeyInvalid)
			assert.Equal(t, before, countWriteRows(t, db), "被拒的請求不得寫入任何資料列")
		})
	}
}

func TestPrivateKeyWriteAssetUpdate(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)
	good, _ := testKeyPair(t, "asset-update")
	row, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: "pk-update", Protocol: model.ProtocolSSH, Host: "10.31.0.3", Port: 22,
		Username: "root", Password: "old-pw", PrivateKey: good, CreatedBy: 1,
	})
	require.NoError(t, err)
	account := defaultAccountOf(t, db, row.ID)

	t.Run("RejectsUnparsableKey", func(t *testing.T) {
		before := countWriteRows(t, db)
		_, err := assets.Update(WithSystemCaller(adminCtx()), row.ID, &UpdateAssetRequest{PrivateKey: pkStrPtr(encryptedEd25519PEM(t))})
		require.ErrorIs(t, err, ErrPrivateKeyInvalid)
		assert.Equal(t, before, countWriteRows(t, db))
	})

	stored := seedUnparsablePrivateKey(t, db, assets, effectiveVersionRow(t, db, account.ID).ID)
	t.Run("PasswordOnlyKeyOmitted", func(t *testing.T) {
		_, err := assets.Update(WithSystemCaller(adminCtx()), row.ID, &UpdateAssetRequest{Password: pkStrPtr("new-pw-1")})
		require.NoError(t, err, "只改密碼不得重驗庫內既有私鑰")
		assert.Equal(t, stored, effectiveVersionRow(t, db, account.ID).PrivateKeyEnc, "既有私鑰密文須原樣保留")
	})
	t.Run("PasswordOnlyKeyEmpty", func(t *testing.T) {
		_, err := assets.Update(WithSystemCaller(adminCtx()), row.ID, &UpdateAssetRequest{Password: pkStrPtr("new-pw-2"), PrivateKey: pkStrPtr("")})
		require.NoError(t, err, "私鑰空字串＝沿用現行私鑰")
		assert.Equal(t, stored, effectiveVersionRow(t, db, account.ID).PrivateKeyEnc, "既有私鑰密文須原樣保留")
	})
}

// --- 2.2 資產帳號新增與更新 ---

func TestPrivateKeyWriteAccountCreateRejectsUnparsable(t *testing.T) {
	for name, bad := range unparsablePrivateKeys(t) {
		for _, form := range []string{"TopLevel", "Inline"} {
			t.Run(name+"/"+form, func(t *testing.T) {
				db := setupAccountDB(t)
				assets, accounts := newAccountServices(t)
				row := newSSHAsset(t, assets, "pk-acct-"+form, "10.31.1.1")
				req := &CreateAssetAccountRequest{Username: "deploy", PrivateKey: bad}
				if form == "Inline" {
					req = &CreateAssetAccountRequest{Credential: &InlineCredential{Username: "deploy", PrivateKey: bad}}
				}
				before := countWriteRows(t, db)
				_, err := accounts.Create(WithSystemCaller(adminCtx()), row.ID, req)
				require.ErrorIs(t, err, ErrPrivateKeyInvalid)
				assert.Equal(t, before, countWriteRows(t, db), "被拒的請求不得寫入任何資料列")
			})
		}
	}
}

func TestPrivateKeyWriteAccountUpdate(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)
	row := newSSHAsset(t, assets, "pk-acct-update", "10.31.1.2")
	good, _ := testKeyPair(t, "account-update")
	dto, err := accounts.Create(WithSystemCaller(adminCtx()), row.ID, &CreateAssetAccountRequest{
		Username: "deploy", Password: "old-pw", PrivateKey: good,
	})
	require.NoError(t, err)

	t.Run("RejectsUnparsableKey", func(t *testing.T) {
		before := countWriteRows(t, db)
		_, err := accounts.Update(adminCtx(), row.ID, dto.ID, &UpdateAssetAccountRequest{PrivateKey: pkStrPtr("not a key")})
		require.ErrorIs(t, err, ErrPrivateKeyInvalid)
		assert.Equal(t, before, countWriteRows(t, db))
	})

	stored := seedUnparsablePrivateKey(t, db, assets, effectiveVersionRow(t, db, dto.ID).ID)
	t.Run("PasswordOnlyKeyOmitted", func(t *testing.T) {
		_, err := accounts.Update(adminCtx(), row.ID, dto.ID, &UpdateAssetAccountRequest{Password: pkStrPtr("new-pw-1")})
		require.NoError(t, err, "只改密碼不得重驗庫內既有私鑰")
		assert.Equal(t, stored, effectiveVersionRow(t, db, dto.ID).PrivateKeyEnc, "既有私鑰密文須原樣保留")
	})
	t.Run("PasswordOnlyKeyEmpty", func(t *testing.T) {
		_, err := accounts.Update(adminCtx(), row.ID, dto.ID, &UpdateAssetAccountRequest{Password: pkStrPtr("new-pw-2"), PrivateKey: pkStrPtr("")})
		require.NoError(t, err, "私鑰空字串＝沿用現行私鑰")
		assert.Equal(t, stored, effectiveVersionRow(t, db, dto.ID).PrivateKeyEnc, "既有私鑰密文須原樣保留")
	})
}

// --- 2.3 憑證庫 ---

func TestPrivateKeyWriteCredentialCreateRejectsUnparsable(t *testing.T) {
	for name, bad := range unparsablePrivateKeys(t) {
		t.Run(name, func(t *testing.T) {
			db := setupCredentialDB(t)
			_, _, creds := newCredentialServices(t)
			before := countWriteRows(t, db)
			_, err := creds.Create(adminCtx(), &CreateCredentialRequest{
				Name: "pk-shared-" + name, Username: "ops", ProtocolFamily: model.ProtocolFamilySSH, PrivateKey: bad,
			})
			require.ErrorIs(t, err, ErrPrivateKeyInvalid)
			assert.Equal(t, before, countWriteRows(t, db), "被拒的請求不得寫入任何資料列")
		})
	}
}

func TestPrivateKeyWriteCredentialSetSecret(t *testing.T) {
	db := setupCredentialDB(t)
	assets, _, creds := newCredentialServices(t)
	good, _ := testKeyPair(t, "set-secret")
	cred, err := creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "pk-set-secret", Username: "ops", ProtocolFamily: model.ProtocolFamilySSH,
		Password: "old-pw", PrivateKey: good,
	})
	require.NoError(t, err)
	host := newSSHAsset(t, assets, "pk-set-secret-host", "10.31.2.1")
	binding, err := creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: host.ID})
	require.NoError(t, err)

	loadCred := func() model.Credential {
		var c model.Credential
		require.NoError(t, db.First(&c, cred.ID).Error)
		return c
	}

	t.Run("RejectsUnparsableKey", func(t *testing.T) {
		before := countWriteRows(t, db)
		credBefore := loadCred()
		effBefore := effectiveVersionRow(t, db, binding.ID).ID
		_, err := creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{PrivateKey: encryptedEd25519PEM(t)})
		require.ErrorIs(t, err, ErrPrivateKeyInvalid)
		assert.Equal(t, before, countWriteRows(t, db))
		assert.Equal(t, credBefore.CurrentVersionID, loadCred().CurrentVersionID, "現行版本指標不變")
		assert.Equal(t, effBefore, effectiveVersionRow(t, db, binding.ID).ID, "就位版本指標不變")
	})

	current := loadCred()
	require.NotNil(t, current.CurrentVersionID)
	stored := seedUnparsablePrivateKey(t, db, assets, *current.CurrentVersionID)
	t.Run("PasswordOnlyCarriesExistingKey", func(t *testing.T) {
		_, err := creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{Password: "new-pw", PrivateKey: ""})
		require.NoError(t, err, "只帶新密碼不得重驗庫內既有私鑰")
		after := loadCred()
		require.NotNil(t, after.CurrentVersionID)
		assert.NotEqual(t, *current.CurrentVersionID, *after.CurrentVersionID, "寫入密文＝新版本")
		var v model.CredentialSecretVersion
		require.NoError(t, db.First(&v, *after.CurrentVersionID).Error)
		assert.Equal(t, stored, v.PrivateKeyEnc, "新版本的私鑰密文自現行版本原樣帶過")
	})
}

func TestPrivateKeyWriteDetachCustomRejectsUnparsable(t *testing.T) {
	f := setupRotationFixture(t)
	good, _ := testKeyPair(t, "detach-shared")
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "pk-detach", Username: "ops", ProtocolFamily: model.ProtocolFamilySSH, PrivateKey: good,
	})
	require.NoError(t, err)
	var accountIDs []uint
	for _, host := range []string{"10.31.3.1", "10.31.3.2"} {
		a := newSSHAsset(t, f.assets, host, host)
		b, berr := f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: a.ID})
		require.NoError(t, berr)
		accountIDs = append(accountIDs, b.ID)
	}
	credBefore := f.credential(t, cred.ID)
	require.Equal(t, model.ChangeSecretTypeSSHKey, credBefore.SecretType)

	for name, bad := range unparsablePrivateKeys(t) {
		t.Run(name, func(t *testing.T) {
			before := countWriteRows(t, f.db)
			effBefore := effectiveVersionRow(t, f.db, accountIDs[1]).ID
			_, err := f.rotations.Detach(adminCtx(), cred.ID, accountIDs[1], DetachCredentialRequest{
				Source: DetachSourceCustom, PrivateKey: bad,
			})
			require.ErrorIs(t, err, ErrPrivateKeyInvalid)
			assert.Equal(t, before, countWriteRows(t, f.db))

			after := f.credential(t, cred.ID)
			assert.Equal(t, credBefore.Scope, after.Scope, "原憑證維持共用")
			assert.Equal(t, credBefore.CurrentVersionID, after.CurrentVersionID, "現行版本指標不變")
			assert.Equal(t, cred.ID, f.binding(t, accountIDs[1]).CredentialID, "掛載不改綁")
			assert.Equal(t, effBefore, effectiveVersionRow(t, f.db, accountIDs[1]).ID, "就位版本指標不變")

			var rotations, candidates int64
			require.NoError(t, f.db.Model(&model.CredentialRotation{}).Count(&rotations).Error)
			require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Count(&candidates).Error)
			assert.Zero(t, rotations, "被拒的脫離不得建立改密工作")
			assert.Zero(t, candidates, "被拒的脫離不得留下候選秘密")
		})
	}
}
