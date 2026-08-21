package session

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// TestSFTPConnectRejectsZeroAccountAsset 零帳號資產不得以空憑證連 SFTP。
//
// **來源（W6 6.6 搬檔）**：本斷言原本住在 asset 側
// `asset_account_review_test.go` 的 `TestZeroAccountAssetFailsClosedEverywhere`
// 末三行。`SFTPService` 屬 session 模組、且斷言要呼叫它的**未匯出** `connect`，
// asset 搬包後跨包取不到。故等值搬到 session 側——同一個入口、同一個哨兵
// （`asset.ErrAssetNoUsableAccount`），**未放寬**。
//
// 為何非有不可：零帳號資產若在 SFTP 路徑上以空密碼「試連」，等於用一條側門
// 繞過「無可用帳號即 fail-close」這條連線紅線。
func TestSFTPConnectRejectsZeroAccountAsset(t *testing.T) {
	setupAccountDB(t)
	assets, _ := newAccountServices(t)

	vnc, err := assets.Create(&asset.CreateAssetRequest{
		Name: "vnc-zero-sftp", Protocol: model.ProtocolVNC, Host: "10.0.1.4", Port: 5901, CreatedBy: 1,
	})
	require.NoError(t, err)

	sftp := NewSFTPService(assets, nil)
	_, _, err = sftp.connect(vnc.ID, 0)
	assert.ErrorIs(t, err, asset.ErrAssetNoUsableAccount)
}
