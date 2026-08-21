package asset

import (
	"context"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"

	"github.com/custodexa/backend/internal/modules/audit"
)

// asset-multi-account 階段 2 的服務層行為鎖定：帳號是 username 與憑證的權威來源。

func setupAccountDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫，連線池會讓「寫在 A 連線、
	// 讀在 B 連線」偶發查無資料（本專案既有 flaky 真因，ff51836）
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&model.Asset{}, &model.AssetAccount{}, &model.AuditLog{},
		&model.AssetGroup{}, &model.AssetNode{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

func newAccountServices(t *testing.T) (*AssetService, *AssetAccountService) {
	t.Helper()
	key := make([]byte, 32)
	codec := aesColumnCodec(t, key)
	assets, err := NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	return assets, NewAssetAccountService(assets, codec, audit.NewTxSink())
}

func adminCtx() context.Context {
	ctx := context.WithValue(context.Background(), "userID", uint(1)) //nolint:staticcheck // 沿用既有審計 context 慣例
	return context.WithValue(ctx, "username", "admin")                //nolint:staticcheck
}

// 建立資產：憑證只落 default 帳號，assets 內嵌憑證欄位凍結不再寫入（D1）
func TestCreateAssetWritesDefaultAccountOnly(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "srv-1", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22,
		Username: "root", Password: "s3cret", CreatedBy: 1,
	})
	require.NoError(t, err)

	var stored model.Asset
	require.NoError(t, db.First(&stored, asset.ID).Error)
	assert.Empty(t, stored.PasswordEnc, "內嵌憑證欄位自階段 2 起凍結不再寫入")
	assert.True(t, stored.HasPassword, "顯示旗標仍須同步，否則既有畫面說謊")

	var account model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&account).Error)
	assert.True(t, account.IsDefault)
	assert.Equal(t, "root", account.Username)
	require.NotEmpty(t, account.PasswordEnc)
	plain, err := assets.crypto.DecryptFor(context.Background(), keyvault.RefAccountPassword, account.PasswordEnc)
	require.NoError(t, err)
	assert.Equal(t, "s3cret", plain)

	// 連線路徑取到的 username／憑證同出一帳號
	creds, err := assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)
	assert.Equal(t, account.ID, creds.AccountID)
	assert.Equal(t, "root", creds.Username)
	assert.Equal(t, "s3cret", creds.Password)
}

// 零憑證資產（三欄全空）不建帳號，且連線解析回空憑證束而非錯誤
func TestCreateAssetWithoutCredentialsHasNoAccount(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "vnc-1", Protocol: model.ProtocolVNC, Host: "10.0.0.2", Port: 5901, CreatedBy: 1,
	})
	require.NoError(t, err)

	var count int64
	require.NoError(t, db.Model(&model.AssetAccount{}).Where("asset_id = ?", asset.ID).Count(&count).Error)
	assert.Zero(t, count)

	creds, err := assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)
	assert.Zero(t, creds.AccountID)
	assert.Empty(t, creds.Username)
}

// PUT /assets/:id 憑證欄位透明轉寫 default 帳號（D9）
func TestUpdateAssetWritesThroughToDefaultAccount(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "srv-2", Protocol: model.ProtocolSSH, Host: "10.0.0.3", Port: 22,
		Username: "root", Password: "old", CreatedBy: 1,
	})
	require.NoError(t, err)

	newUser, newPass := "deploy", "rotated"
	_, err = assets.Update(adminCtx(), asset.ID, &UpdateAssetRequest{
		Username: &newUser, Password: &newPass,
	})
	require.NoError(t, err)

	creds, err := assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)
	assert.Equal(t, "deploy", creds.Username)
	assert.Equal(t, "rotated", creds.Password)

	var stored model.Asset
	require.NoError(t, db.First(&stored, asset.ID).Error)
	assert.Empty(t, stored.PasswordEnc, "內嵌憑證仍不得被寫入")
}

// 資產原本零帳號時，PUT 帶憑證會就地建出 default 帳號（否則連線端什麼都拿不到）
func TestUpdateAssetCreatesDefaultAccountWhenMissing(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "vnc-2", Protocol: model.ProtocolVNC, Host: "10.0.0.4", Port: 5901, CreatedBy: 1,
	})
	require.NoError(t, err)

	pw := "vncpass"
	_, err = assets.Update(adminCtx(), asset.ID, &UpdateAssetRequest{Password: &pw})
	require.NoError(t, err)

	var account model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&account).Error)
	assert.True(t, account.IsDefault)
	creds, err := assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)
	assert.Equal(t, "vncpass", creds.Password)
}

// 帳號 CRUD ＋ default 交易式切換 ＋ 禁刪最後 default（D8）
func TestAccountCRUDAndDefaultInvariants(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "srv-3", Protocol: model.ProtocolSSH, Host: "10.0.0.5", Port: 22,
		Username: "root", Password: "rootpw", CreatedBy: 1,
	})
	require.NoError(t, err)

	// 第二個帳號（非 default）
	app, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
		Username: "app", Password: "apppw", Privileged: false, Note: "服務帳號",
	})
	require.NoError(t, err)
	assert.False(t, app.IsDefault)
	assert.True(t, app.HasPassword)

	// 同名帳號衝突
	_, err = accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{Username: "app"})
	assert.ErrorIs(t, err, ErrAssetAccountUsernameExists)

	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.True(t, list[0].IsDefault, "預設帳號排首")

	// 禁刪最後一個 default（資產仍有其他帳號）
	defaultID := list[0].ID
	err = accounts.Delete(adminCtx(), asset.ID, defaultID)
	assert.ErrorIs(t, err, ErrAssetAccountDefaultRequired)

	// 切換 default：交易式，至多一個 default（DB partial index 亦強制）
	_, err = accounts.SetDefault(adminCtx(), asset.ID, app.ID)
	require.NoError(t, err)
	var defaults int64
	require.NoError(t, db.Model(&model.AssetAccount{}).
		Where("asset_id = ? AND is_default = ?", asset.ID, true).Count(&defaults).Error)
	assert.EqualValues(t, 1, defaults)

	creds, err := assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)
	assert.Equal(t, "app", creds.Username)
	assert.Equal(t, "apppw", creds.Password)

	// assets 顯示欄隨 default 鏡射
	var stored model.Asset
	require.NoError(t, db.First(&stored, asset.ID).Error)
	assert.Equal(t, "app", stored.Username)

	// 舊 default 已非 default，可刪
	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, defaultID))

	// 剩最後一個帳號（且是 default）＝允許刪，資產回到零帳號合法狀態
	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, app.ID))
	creds, err = assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)
	assert.Zero(t, creds.AccountID)
}

// 從其他資產的帳號複製建號（D10）：密文原樣搬，複製後可正常解密
func TestCreateAccountCopyFromOtherAsset(t *testing.T) {
	_ = setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	src, err := assets.Create(&CreateAssetRequest{
		Name: "src", Protocol: model.ProtocolSSH, Host: "10.0.0.6", Port: 22,
		Username: "ops", Password: "shared-pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	dst, err := assets.Create(&CreateAssetRequest{
		Name: "dst", Protocol: model.ProtocolSSH, Host: "10.0.0.7", Port: 22,
		Username: "root", Password: "rootpw", CreatedBy: 1,
	})
	require.NoError(t, err)

	srcList, err := accounts.List(src.ID)
	require.NoError(t, err)
	require.Len(t, srcList, 1)

	copied, err := accounts.Create(adminCtx(), dst.ID, &CreateAssetAccountRequest{
		CopyFromAccountID: srcList[0].ID,
	})
	require.NoError(t, err)
	assert.Equal(t, "ops", copied.Username)
	assert.True(t, copied.HasPassword)

	creds, err := assets.GetWithCredentialsForAccount(dst.ID, copied.ID)
	require.NoError(t, err)
	assert.Equal(t, "ops", creds.Username)
	assert.Equal(t, "shared-pw", creds.Password)

	// 來源不存在＝明確錯誤
	_, err = accounts.Create(adminCtx(), dst.ID, &CreateAssetAccountRequest{CopyFromAccountID: 9999})
	assert.ErrorIs(t, err, ErrAssetAccountSourceNotFound)
}

// 跨資產 account id 注入 fail-close：不得靜默退回 default（D3）
func TestGetCredentialsRejectsForeignAccount(t *testing.T) {
	_ = setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	a1, err := assets.Create(&CreateAssetRequest{
		Name: "a1", Protocol: model.ProtocolSSH, Host: "10.0.0.8", Port: 22,
		Username: "root", Password: "pw1", CreatedBy: 1,
	})
	require.NoError(t, err)
	a2, err := assets.Create(&CreateAssetRequest{
		Name: "a2", Protocol: model.ProtocolSSH, Host: "10.0.0.9", Port: 22,
		Username: "root", Password: "pw2", CreatedBy: 1,
	})
	require.NoError(t, err)

	foreign, err := accounts.List(a2.ID)
	require.NoError(t, err)
	require.Len(t, foreign, 1)

	creds, err := assets.GetWithCredentialsForAccount(a1.ID, foreign[0].ID)
	assert.Nil(t, creds)
	assert.ErrorIs(t, err, ErrAssetAccountNotFound)

	// 已軟刪帳號同樣 fail-close
	own, err := accounts.List(a1.ID)
	require.NoError(t, err)
	require.NoError(t, accounts.Delete(adminCtx(), a1.ID, own[0].ID))
	creds, err = assets.GetWithCredentialsForAccount(a1.ID, own[0].ID)
	assert.Nil(t, creds)
	assert.ErrorIs(t, err, ErrAssetAccountNotFound)
}

// 帳號名稱注入防線：換行／冒號會在 chpasswd 的 stdin 條目拆出額外行
func TestAccountUsernameValidation(t *testing.T) {
	_ = setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "srv-4", Protocol: model.ProtocolSSH, Host: "10.0.0.10", Port: 22,
		Username: "root", Password: "pw", CreatedBy: 1,
	})
	require.NoError(t, err)

	_, err = accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{Username: "evil\nroot"})
	assert.ErrorIs(t, err, ErrAssetAccountUsernameInvalid)
	_, err = accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{Username: "a:b"})
	assert.ErrorIs(t, err, ErrAssetAccountUsernameInvalid)
	_, err = accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
		Username: strings.Repeat("x", 101),
	})
	assert.ErrorIs(t, err, ErrAssetAccountUsernameTooLong)
}

// D7a：帳號操作留痕，且審計內容絕不含密文或明文憑證
func TestAccountAuditNeverContainsSecrets(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "srv-5", Protocol: model.ProtocolSSH, Host: "10.0.0.11", Port: 22,
		Username: "root", Password: "plain-secret", CreatedBy: 1,
	})
	require.NoError(t, err)

	created, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
		Username: "svc", Password: "another-secret",
	})
	require.NoError(t, err)
	newPw := "rotated-secret"
	_, err = accounts.Update(adminCtx(), asset.ID, created.ID, &UpdateAssetAccountRequest{Password: &newPw})
	require.NoError(t, err)
	_, err = accounts.SetDefault(adminCtx(), asset.ID, created.ID)
	require.NoError(t, err)

	var logs []model.AuditLog
	require.NoError(t, db.Where("resource = ?", model.ResourceAsset).Find(&logs).Error)
	require.NotEmpty(t, logs)

	var accountEvents int
	for _, l := range logs {
		if strings.Contains(l.Details, "asset_account") {
			accountEvents++
		}
		for _, secret := range []string{"plain-secret", "another-secret", "rotated-secret"} {
			assert.NotContains(t, l.Details, secret, "審計不得含明文憑證")
		}
	}
	assert.GreaterOrEqual(t, accountEvents, 3, "建立／更新／切換預設各應留痕")

	// 密文亦不得出現在審計
	var account model.AssetAccount
	require.NoError(t, db.First(&account, created.ID).Error)
	require.NotEmpty(t, account.PasswordEnc)
	for _, l := range logs {
		assert.NotContains(t, l.Details, account.PasswordEnc, "審計不得含密文")
	}
}

// D9 回歸：改密 runner 釘住的 AccountID 貫穿讀寫——執行中切 default 不影響寫回目標。
//
// 模擬 runAsset 的實際時序：開頭解析 default（釘住 A）→ 期間管理員把 default
// 切到 B → 以釘住的 A 提交新密。舊行為（結尾以 assetID 重解析 default）會把新密
// 寫進 B：本測試對 B 的斷言即是那個 bug 的偵測器。
func TestUpdatePasswordPinsAccountAcrossDefaultSwitch(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "srv-6", Protocol: model.ProtocolSSH, Host: "10.0.0.12", Port: 22,
		Username: "root", Password: "old-root-pw", CreatedBy: 1,
	})
	require.NoError(t, err)

	// runner 開頭：解析 default 並釘住 AccountID
	pinned, err := assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)
	pinnedID := pinned.AccountID
	require.NotZero(t, pinnedID)

	// 執行期間：管理員新增帳號並切換 default
	other, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
		Username: "backup", Password: "backup-pw",
	})
	require.NoError(t, err)
	_, err = accounts.SetDefault(adminCtx(), asset.ID, other.ID)
	require.NoError(t, err)

	// runner 結尾：以釘住的 AccountID 寫回
	require.NoError(t, assets.UpdatePassword(asset.ID, pinnedID, pinned.Username, "new-root-pw"))

	var pinnedAccount, otherAccount model.AssetAccount
	require.NoError(t, db.First(&pinnedAccount, pinnedID).Error)
	require.NoError(t, db.First(&otherAccount, other.ID).Error)

	pinnedPlain, err := assets.crypto.DecryptFor(context.Background(), keyvault.RefAccountPassword, pinnedAccount.PasswordEnc)
	require.NoError(t, err)
	assert.Equal(t, "new-root-pw", pinnedPlain, "新密必須寫回釘住的帳號")

	otherPlain, err := assets.crypto.DecryptFor(context.Background(), keyvault.RefAccountPassword, otherAccount.PasswordEnc)
	require.NoError(t, err)
	assert.Equal(t, "backup-pw", otherPlain, "執行中被切為 default 的帳號憑證不得受影響")

	// 釘住的帳號已非 default，UpdatePassword 仍須寫得進去（不重解析 default）
	assert.False(t, pinnedAccount.IsDefault)
}

// UpdatePassword 對不屬該資產的帳號 fail-close（改密不得跨資產寫入）
func TestUpdatePasswordRejectsForeignAccount(t *testing.T) {
	_ = setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	a1, err := assets.Create(&CreateAssetRequest{
		Name: "p1", Protocol: model.ProtocolSSH, Host: "10.0.0.13", Port: 22,
		Username: "root", Password: "pw1", CreatedBy: 1,
	})
	require.NoError(t, err)
	a2, err := assets.Create(&CreateAssetRequest{
		Name: "p2", Protocol: model.ProtocolSSH, Host: "10.0.0.14", Port: 22,
		Username: "root", Password: "pw2", CreatedBy: 1,
	})
	require.NoError(t, err)

	foreign, err := accounts.List(a2.ID)
	require.NoError(t, err)
	assert.ErrorIs(t, assets.UpdatePassword(a1.ID, foreign[0].ID, "root", "x"), ErrAssetAccountNotFound)
	assert.ErrorIs(t, assets.UpdatePassword(a1.ID, 0, "root", "x"), ErrAssetAccountNotFound)
}
