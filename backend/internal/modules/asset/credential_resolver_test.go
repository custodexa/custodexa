package asset

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// 憑證解析器的行為鎖定。
//
// **守衛 1（連線只取就位版本）**即 TestCredentialResolverUsesEffectiveVersionOnly：
// 裝配一筆 pending 與 current 都不等於 effective 的憑證，斷言連線路徑取回的是
// effective 對應的那一版。突變自證＝把解析器改成讀 current 即轉紅。
//
// 為什麼這件事要有守衛：共用憑證在整組改密的中途必然出現「甲台已就位新版、
// 乙台仍是舊版」，此時憑證上的 current／pending 對乙台都是錯的答案。
// 用錯版本的代價不是報錯，是一次失敗的登入嘗試——有鎖定策略的目標系統會因此鎖帳。

// seedCredentialWithVersions 建一筆專用憑證與三個版本，並回傳
// (憑證, 舊版=就位版, 現行版, 待生效版) 的識別。三者刻意互不相同。
func seedCredentialWithVersions(t *testing.T, db *gorm.DB, svc *AssetService,
	username, effectivePlain, currentPlain, pendingPlain string) (uint, uint, uint, uint) {
	t.Helper()
	ctx := context.Background()

	cred := model.Credential{
		Scope: model.CredentialScopeDedicated, Username: username,
		SecretType: model.ChangeSecretTypePassword, AuthMethod: AuthMethodSQL,
		ProtocolFamily: model.ProtocolFamilySSH,
	}
	require.NoError(t, db.Create(&cred).Error)

	mk := func(no int, plain, reason string) uint {
		enc, err := svc.crypto.EncryptFor(ctx, keyvault.RefCredentialVersionPassword, plain)
		require.NoError(t, err)
		v := model.CredentialSecretVersion{
			CredentialID: cred.ID, VersionNo: no,
			SecretType:  model.ChangeSecretTypePassword,
			PasswordEnc: enc, CreatedReason: reason,
		}
		require.NoError(t, db.Create(&v).Error)
		return v.ID
	}
	effectiveID := mk(1, effectivePlain, model.CredentialVersionReasonManual)
	currentID := mk(2, currentPlain, model.CredentialVersionReasonRotation)
	pendingID := mk(3, pendingPlain, model.CredentialVersionReasonRotation)

	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", cred.ID).
		Updates(map[string]interface{}{
			"current_version_id": currentID,
			"pending_version_id": pendingID,
		}).Error)
	return cred.ID, effectiveID, currentID, pendingID
}

// 守衛 1：連線只取掛載的就位版本，不退回 current、不試 pending。
func TestCredentialResolverUsesEffectiveVersionOnly(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "eff-1", Protocol: model.ProtocolVNC, Host: "10.0.9.1", Port: 5901,
		CreatedBy: 1,
	})
	require.NoError(t, err)

	credID, effectiveID, currentID, pendingID := seedCredentialWithVersions(t, db, assets,
		"root", "effective-pw", "current-pw", "pending-pw")
	require.NotEqual(t, effectiveID, currentID)
	require.NotEqual(t, effectiveID, pendingID)

	account := model.AssetAccount{
		AssetID: asset.ID, Username: "root", IsDefault: true,
		CredentialID: credID, EffectiveVersionID: &effectiveID,
	}
	require.NoError(t, db.Create(&account).Error)

	resolved, err := assets.resolver.ResolveForBinding(context.Background(), asset.ID, account.ID)
	require.NoError(t, err)
	assert.Equal(t, effectiveID, resolved.VersionID,
		"取回的必須是掛載的就位版本；退回 current 或試 pending 都會在改密中途用錯版本")
	assert.Equal(t, "effective-pw", resolved.Password)

	// 連線路徑（薄殼）與解析器必須給出同一個答案——守衛盯的是實際建線用的那個值
	creds, err := assets.GetWithCredentialsForAccount(asset.ID, account.ID)
	require.NoError(t, err)
	assert.Equal(t, "effective-pw", creds.Password,
		"連線取密必須是就位版本；讀 current 即為本守衛的突變態")
	assert.NotEqual(t, "current-pw", creds.Password)
	assert.NotEqual(t, "pending-pw", creds.Password)
}

// 就位版本為空＝該掛載尚未取得任何密文：回既有的「無可用帳號憑證」語義，
// 不退回憑證的現行版本猜一個來試。
func TestCredentialResolverNilEffectiveIsUnusable(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "eff-2", Protocol: model.ProtocolVNC, Host: "10.0.9.2", Port: 5901,
		CreatedBy: 1,
	})
	require.NoError(t, err)

	credID, _, currentID, _ := seedCredentialWithVersions(t, db, assets,
		"root", "effective-pw", "current-pw", "pending-pw")
	require.NotZero(t, currentID)

	account := model.AssetAccount{
		AssetID: asset.ID, Username: "root", IsDefault: true,
		CredentialID: credID, EffectiveVersionID: nil,
	}
	require.NoError(t, db.Create(&account).Error)

	_, err = assets.resolver.ResolveForBinding(context.Background(), asset.ID, account.ID)
	assert.ErrorIs(t, err, ErrAssetNoUsableAccount,
		"憑證有現行版本也不得拿來頂替：那是猜測，猜錯就是一次失敗登入")

	// 連線路徑維持既有語義：帳號在、但沒有可用秘密（零帳號閘由各入口自己判）
	creds, err := assets.GetWithCredentialsForAccount(asset.ID, account.ID)
	require.NoError(t, err)
	assert.Equal(t, account.ID, creds.AccountID)
	assert.Empty(t, creds.Password)
	assert.Empty(t, creds.PrivateKey)
}

// 跨資產的掛載識別 fail-close：不得靜默退回預設帳號，也不得解出別台的秘密。
// 版本識別同理——指定不屬於該憑證的版本一律回錯。
func TestCredentialResolverRejectsForeignBinding(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)

	a1, err := assets.Create(&CreateAssetRequest{
		Name: "eff-3a", Protocol: model.ProtocolSSH, Host: "10.0.9.3", Port: 22,
		Username: "root", Password: "pw-a1", CreatedBy: 1,
	})
	require.NoError(t, err)
	a2, err := assets.Create(&CreateAssetRequest{
		Name: "eff-3b", Protocol: model.ProtocolSSH, Host: "10.0.9.4", Port: 22,
		Username: "root", Password: "pw-a2", CreatedBy: 1,
	})
	require.NoError(t, err)

	var foreign model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", a2.ID).First(&foreign).Error)

	_, err = assets.resolver.ResolveForBinding(context.Background(), a1.ID, foreign.ID)
	assert.ErrorIs(t, err, ErrAssetAccountNotFound,
		"跨資產帳號識別注入不得拿到目標資產的憑證，也不得退回預設帳號")

	// 版本歸屬：拿別的憑證的版本識別來要秘密，一律回錯
	var own model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", a1.ID).First(&own).Error)
	require.NotNil(t, foreign.EffectiveVersionID)
	_, err = assets.resolver.ResolveVersion(context.Background(), own.CredentialID, *foreign.EffectiveVersionID)
	assert.ErrorIs(t, err, ErrCredentialVersionNotFound,
		"版本必須屬於該憑證；查完再比的寫法一旦漏掉就是任意密文解封路徑")

	// 反面控制：自己的版本取得回原文（證明上面的紅不是「解析器根本不會成功」）
	require.NotNil(t, own.EffectiveVersionID)
	resolved, err := assets.resolver.ResolveVersion(context.Background(), own.CredentialID, *own.EffectiveVersionID)
	require.NoError(t, err)
	assert.Equal(t, "pw-a1", resolved.Password)
}

// 系統路徑寫入面：新增版本而非就地覆寫，且就位版本同交易改指新版。
func TestUpdateSecretAppendsVersionNotOverwrite(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "append-1", Protocol: model.ProtocolSSH, Host: "10.0.9.5", Port: 22,
		Username: "root", Password: "old-pw", CreatedBy: 1,
	})
	require.NoError(t, err)

	var before model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&before).Error)
	require.NotNil(t, before.EffectiveVersionID)
	oldVersionID := *before.EffectiveVersionID

	var oldRow model.CredentialSecretVersion
	require.NoError(t, db.First(&oldRow, oldVersionID).Error)
	oldCipher := oldRow.PasswordEnc
	require.NotEmpty(t, oldCipher)

	require.NoError(t, assets.UpdatePassword(asset.ID, before.ID, "root", "new-pw"))

	// 舊版本列的密文未被就地覆寫——尚未就位新版的主機仍要能取到它在用的那一版
	var oldAfter model.CredentialSecretVersion
	require.NoError(t, db.First(&oldAfter, oldVersionID).Error)
	assert.Equal(t, oldCipher, oldAfter.PasswordEnc, "既有版本列的密文不得被就地覆寫")
	assert.Equal(t, 1, oldAfter.VersionNo)

	var count int64
	require.NoError(t, db.Model(&model.CredentialSecretVersion{}).
		Where("credential_id = ?", before.CredentialID).Count(&count).Error)
	assert.EqualValues(t, 2, count, "一次改密＝追加一筆版本")

	var after model.AssetAccount
	require.NoError(t, db.First(&after, before.ID).Error)
	require.NotNil(t, after.EffectiveVersionID)
	assert.NotEqual(t, oldVersionID, *after.EffectiveVersionID, "就位版本必須改指新版")

	creds, err := assets.GetWithCredentialsForAccount(asset.ID, before.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-pw", creds.Password)

	// 憑證的現行版本同步推進（系統路徑於驗證通過後才呼叫寫入面）
	var cred model.Credential
	require.NoError(t, db.First(&cred, before.CredentialID).Error)
	require.NotNil(t, cred.CurrentVersionID)
	assert.Equal(t, *after.EffectiveVersionID, *cred.CurrentVersionID)
}

// 金鑰輪替只換私鑰：新版本必須把原本的密碼原樣帶過來。
// 清掉它會讓原本密碼可登入的帳號在金鑰失效時失去唯一的備援入口。
func TestUpdatePrivateKeyKeepsExistingPassword(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "append-2", Protocol: model.ProtocolSSH, Host: "10.0.9.6", Port: 22,
		Username: "root", Password: "keep-me", CreatedBy: 1,
	})
	require.NoError(t, err)

	var account model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&account).Error)

	require.NoError(t, assets.UpdatePrivateKey(asset.ID, account.ID, "root", "PRIVATE-KEY-BODY"))

	creds, err := assets.GetWithCredentialsForAccount(asset.ID, account.ID)
	require.NoError(t, err)
	assert.Equal(t, "PRIVATE-KEY-BODY", creds.PrivateKey)
	assert.Equal(t, "keep-me", creds.Password, "金鑰輪替不得順手清掉密碼備援入口")
}

// effectiveSecretPlain 取某掛載**就位版本**的明文（測試輔助）。
//
// 憑證庫化之後秘密不在掛載列上，既有測試「解 account.PasswordEnc 得到某明文」的
// 斷言一律改讀這裡——斷的還是同一件事（這個掛載當下用的秘密是什麼），只是落點搬了。
func effectiveSecretPlain(t *testing.T, db *gorm.DB, svc *AssetService, accountID uint) (string, string) {
	t.Helper()
	var account model.AssetAccount
	require.NoError(t, db.First(&account, accountID).Error)
	require.NotNil(t, account.EffectiveVersionID, "掛載沒有就位版本＝取不到秘密")
	resolved, err := svc.resolver.ResolveVersion(context.Background(),
		account.CredentialID, *account.EffectiveVersionID)
	require.NoError(t, err)
	return resolved.Password, resolved.PrivateKey
}

// effectiveCipher 取某掛載就位版本的密碼密文（測試輔助；斷言「密文不進審計」用）。
func effectiveCipher(t *testing.T, db *gorm.DB, accountID uint) string {
	t.Helper()
	var account model.AssetAccount
	require.NoError(t, db.First(&account, accountID).Error)
	require.NotNil(t, account.EffectiveVersionID)
	var version model.CredentialSecretVersion
	require.NoError(t, db.First(&version, *account.EffectiveVersionID).Error)
	return version.PasswordEnc
}
