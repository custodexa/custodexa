package asset

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 修改帳號的寫入回應要回報這次修改後的修改時間，與隨後讀取相同。
// 先把列的修改時間推回過去，讓「回報交易前的舊值」必然與讀取不同，不依賴兩次請求是否落在同一秒。
func TestUpdateAccountResponseCarriesNewUpdatedAt(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: "srv-time", Protocol: model.ProtocolSSH, Host: "10.0.0.9", Port: 22,
		Username: "root", Password: "s3cret", CreatedBy: 1,
	})
	require.NoError(t, err)
	var account model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&account).Error)

	past := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, db.Model(&model.AssetAccount{}).Where("id = ?", account.ID).
		UpdateColumn("updated_at", past).Error)

	note := "updated"
	written, err := accounts.Update(adminCtx(), asset.ID, account.ID, &UpdateAssetAccountRequest{Note: &note})
	require.NoError(t, err)
	read, err := accounts.Get(asset.ID, account.ID)
	require.NoError(t, err)

	require.NotEqual(t, past.Format(time.RFC3339), written.UpdatedAt, "寫入回應不得回報交易前的修改時間")
	require.Equal(t, read.UpdatedAt, written.UpdatedAt, "寫入回應的修改時間要與隨後讀取相同")
}
