package session

import (
	"context"
	"sync"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 會話帳號雙快照的不可變性（asset-accounts spec
// 「會話審計雙快照」）：只存 FK 不足以保證不可否認性——帳號改名或刪除後，
// 靠 JOIN 還原的「當時用哪個帳號連的」會跟著變。故 sessions 同時釘住
// AccountID 與連線當下的 username，寫入後永不隨帳號變動更新。

func TestSessionAccountSnapshotImmutable(t *testing.T) {
	db := setupAccountDB(t)
	require.NoError(t, db.AutoMigrate(&model.Session{}))
	assets, accounts := newAccountServices(t)

	assetRow, err := assets.Create(asset.WithSystemCaller(context.Background()), &asset.CreateAssetRequest{
		Name: "srv-snap", Protocol: model.ProtocolSSH, Host: "10.0.0.9", Port: 22,
		Username: "root", Password: "s3cret", CreatedBy: 1,
	})
	require.NoError(t, err)

	app, err := accounts.Create(asset.WithSystemCaller(adminCtx()), assetRow.ID, &asset.CreateAssetAccountRequest{
		Username: "app", Password: "apppw",
	})
	require.NoError(t, err)

	// 連線建立點寫入的快照（兩個 handler 皆以 creds.AccountID／creds.Username 帶入）
	assetID := assetRow.ID
	sess := model.Session{
		SessionID: "sess-snap-1", Status: model.SessionStatusActive, Protocol: model.ProtocolSSH,
		UserID: 1, AssetID: &assetID,
		AccountID: app.ID, AccountUsername: app.Username,
	}
	require.NoError(t, db.Create(&sess).Error)

	// 帳號改名 → 快照不得跟著變
	renamed := "app-renamed"
	_, err = accounts.Update(asset.WithSystemCaller(adminCtx()), assetRow.ID, app.ID, &asset.UpdateAssetAccountRequest{Username: &renamed})
	require.NoError(t, err)

	var after model.Session
	require.NoError(t, db.First(&after, sess.ID).Error)
	require.Equal(t, app.ID, after.AccountID, "改名後 session.account_id 不得變動")
	require.Equal(t, "app", after.AccountUsername, "改名後 session 的 username 快照必須是連線當下的值")

	// 帳號刪除 → 快照兩欄仍在（審計不可被刪帳號洗掉）
	require.NoError(t, accounts.Delete(adminCtx(), assetRow.ID, app.ID))

	var afterDelete model.Session
	require.NoError(t, db.First(&afterDelete, sess.ID).Error)
	require.Equal(t, app.ID, afterDelete.AccountID, "刪帳號後 session.account_id 不得被清空")
	require.Equal(t, "app", afterDelete.AccountUsername, "刪帳號後 username 快照不得被清空")
}

// TestSFTPAccountForSession 自會話沿用帳號的 fail-close：檔案分頁由某會話
// 進入時沿用該會話的帳號；非本人或非本資產的 session_id 一律拒絕——若退回預設
// 帳號，session_id 就成了「換一組（通常更高權）憑證傳檔」的旁路
func TestSFTPAccountForSession(t *testing.T) {
	db := setupAccountDB(t)
	require.NoError(t, db.AutoMigrate(&model.Session{}))
	assets, _ := newAccountServices(t)
	sftp := NewSFTPService(assets, nil)

	assetID, otherAsset := uint(1), uint(2)
	require.NoError(t, db.Create(&model.Session{
		SessionID: "s1", Status: model.SessionStatusActive, Protocol: model.ProtocolSSH,
		UserID: 1, AssetID: &assetID, AccountID: 7, AccountUsername: "app",
	}).Error)

	got, err := sftp.AccountForSession(1, assetID, 1)
	require.NoError(t, err)
	require.Equal(t, uint(7), got, "本人本資產的會話應沿用其帳號")

	_, err = sftp.AccountForSession(2, assetID, 1)
	require.ErrorIs(t, err, ErrSessionAccountNotFound, "他人的會話不得沿用")

	_, err = sftp.AccountForSession(1, otherAsset, 1)
	require.ErrorIs(t, err, ErrSessionAccountNotFound, "他資產的會話不得沿用")

	_, err = sftp.AccountForSession(1, assetID, 999)
	require.ErrorIs(t, err, ErrSessionAccountNotFound, "不存在的會話不得沿用")
}

// asset 夾具的 session 側複本。
//
// **為何是複本**：原件隨 `asset_account_service_test.go` 遷入
// `internal/modules/asset`，而該包的**包內**測試 SHALL NOT 被 `internal/service`
// 取用（跨包看不見未匯出識別字）。本檔驗的是 session 側的帳號快照行為，
// 需要同一組前置資料，故逐行複製一份、只呼叫 asset 的匯出面。
func setupAccountDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&model.Asset{}, &model.AssetAccount{}, &model.Credential{}, &model.CredentialSecretVersion{}, &model.AuditLog{},
		&model.AssetGroup{}, &model.AssetNode{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

func newAccountServices(t *testing.T) (*asset.AssetService, *asset.AssetAccountService) {
	t.Helper()
	key := make([]byte, 32)
	codec := aesColumnCodec(t, key)
	assets, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	assets.SetTopologyPermissionPort(noopTopologyPort{})
	require.NoError(t, err)
	// 與原件同步：表單內嵌的密碼／私鑰宣告是 SetSecret 的同義入口，判定器與告警落地面
	// 皆 fail closed（未注入即拒絕），生產由組裝根注入（cmd/server/stage2.go）。
	auth := allowAllCredentialAuthorizer{}
	alerts := &discardAlertSink{}
	assets.WithManagementAuthorizer(auth).WithSystemAlertSink(alerts)
	return assets, asset.NewAssetAccountService(assets, codec, audit.NewTxSink()).
		WithManagementAuthorizer(auth).WithSystemAlertSink(alerts).WithAccountWriteScope(allowAllAccountWriteScope{})
}

// allowAllCredentialAuthorizer 一律放行的憑證管理判定器（session 側只驗帳號快照，不驗授權）。
type allowAllCredentialAuthorizer struct{}

func (allowAllCredentialAuthorizer) AuthorizeCredentialManagement(_ context.Context, _ *gorm.DB,
	_ asset.CredentialManagementActor, _ asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	return asset.CredentialManagementDecision{Allowed: true, AuthzVersion: 1}, nil
}

// discardAlertSink 收下告警但不落地的系統告警落地面。
type discardAlertSink struct {
	mu     sync.Mutex
	raised int
}

func (d *discardAlertSink) RaiseInTx(_ *gorm.DB, _ port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.raised++
	return port.SystemAlertReceipt{AlertID: uint(d.raised)}, nil
}

// adminCtx 審計操作者 context（原件隨 asset_account_service_test.go 遷入 asset 包）。
func adminCtx() context.Context {
	ctx := context.WithValue(context.Background(), "userID", uint(1)) //nolint:staticcheck // 沿用既有審計 context 慣例
	return context.WithValue(ctx, "username", "admin")                //nolint:staticcheck
}
