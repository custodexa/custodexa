package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// mssql 資產與其餘協議一樣支援多帳號。
//
// 資料庫協議的資產常有「應用帳號 vs 維運帳號」兩組身分，若第二個帳號建不起來、
// 或取密路徑只回得了預設帳號的秘密，使用者就只能為同一台機器建兩筆資產——
// 而那會讓授權、稽核與改密全部各自分裂成兩份。
func TestMSSQLAssetSupportsMultipleAccounts(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	a, err := assets.Create(&CreateAssetRequest{
		Name: "mssql-multi", Protocol: model.ProtocolMSSQL, Host: "10.8.0.1", Port: 1433,
		Username: "sa", Password: "sa-pw", CreatedBy: 1, CreatedByName: "admin",
	})
	require.NoError(t, err)

	var defaultAccount model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", a.ID).First(&defaultAccount).Error)

	// 第二個帳號：這台專用的另一組憑證
	second, err := accounts.Create(adminCtx(), a.ID, &CreateAssetAccountRequest{
		Username: "app_reader", Password: "reader-pw",
	})
	require.NoError(t, err)
	assert.False(t, second.IsDefault, "後建的帳號不搶預設")

	var count int64
	require.NoError(t, db.Model(&model.AssetAccount{}).
		Where("asset_id = ?", a.ID).Count(&count).Error)
	assert.EqualValues(t, 2, count, "mssql 資產須容得下第二個帳號")

	// 取密路徑指定帳號：拿到的是該掛載自己那筆憑證的秘密，不是預設帳號的
	got, err := assets.GetWithCredentialsForAccount(a.ID, second.ID)
	require.NoError(t, err)
	assert.Equal(t, second.ID, got.AccountID)
	assert.Equal(t, "app_reader", got.Username)
	assert.Equal(t, "reader-pw", got.Password)

	def, err := assets.GetWithCredentialsDefault(a.ID)
	require.NoError(t, err)
	assert.Equal(t, defaultAccount.ID, def.AccountID)
	assert.Equal(t, "sa-pw", def.Password, "指定帳號取密不得污染預設帳號那一條路")

	// 第三個帳號改掛共用憑證：共用關係在 mssql 上同樣成立
	shared, err := creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "dba-shared", Username: "dba", Password: "dba-pw",
		ProtocolFamily: model.ProtocolFamilyDatabase,
	})
	require.NoError(t, err)
	third, err := accounts.Create(adminCtx(), a.ID, &CreateAssetAccountRequest{
		CredentialID: shared.ID,
	})
	require.NoError(t, err)

	gotShared, err := assets.GetWithCredentialsForAccount(a.ID, third.ID)
	require.NoError(t, err)
	assert.Equal(t, "dba", gotShared.Username)
	assert.Equal(t, "dba-pw", gotShared.Password, "取密須解出該掛載所引用共用憑證的秘密")
}
