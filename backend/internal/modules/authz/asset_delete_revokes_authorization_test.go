package authz

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/crypto"
)

// 刪除資產即失效其授權（塊 2）。
//
// 本測試放在 authz 而非 asset：權限查詢與其姊妹查詢住在這裡，且 authz 已 import
// asset，反向 import 會循環。
//
// **核心不是「Delete 有沒有下那道 SQL」，而是「權限查詢還命不命中」**——
// 前者是實作細節，後者才是缺陷本體（已刪資產的授權仍於權限判定中有效）。

// deleteRevokeCodec 本測試用的最小 ColumnCodec。
//
// 本測試完全不碰憑證欄位（只建資產、授權、刪除），但 NewAssetService 的簽名
// 要求一個 codec——**刻意不寫成 no-op 明文直寫**：明文 codec 一旦被別的測試
// 借用就成了繞過 AAD 綁定的捷徑。這裡走真的 AES＋AAD，與生產同源
type deleteRevokeCodec struct{ c *crypto.AESCrypto }

func (d deleteRevokeCodec) EncryptFor(_ context.Context, ref crypto.CipherRef, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	raw, err := d.c.EncryptBytesAAD([]byte(plaintext), ref.AAD())
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func (d deleteRevokeCodec) DecryptFor(_ context.Context, ref crypto.CipherRef, ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", crypto.ErrInvalidCiphertext
	}
	plain, err := d.c.DecryptBytesAAD(data, ref.AAD())
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func setupDeleteRevokeDB(t *testing.T) (*gorm.DB, *asset.AssetService) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{},
		&model.AssetNode{}, &model.AssetAuthorization{}, &model.ApproverScope{},
		&model.AuditLog{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	key := make([]byte, 32)
	aesCrypto, err := crypto.NewAESCrypto(key)
	require.NoError(t, err)
	svc, err := asset.NewAssetService(
		deleteRevokeCodec{c: aesCrypto}, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	// 資產刪除的級聯撤銷經 tx-taking 窄 port 交由 authz 寫入：
	// asset 不直接碰他模組的表。未注入即 fail-close，故此處注入真實的 authz 服務
	svc.SetAuthorizationRevoker(NewAssetAuthorizationService(db))
	return db, svc
}

func mkDeleteRevokeAsset(t *testing.T, db *gorm.DB, name string) *model.Asset {
	t.Helper()
	a := &model.Asset{
		Name: name, Protocol: model.ProtocolSSH, Host: "10.0.0.9", Port: 22,
		Username: "root", Active: true,
	}
	require.NoError(t, db.Create(a).Error)
	return a
}

func mkDeleteRevokeAuth(t *testing.T, db *gorm.DB, userID, assetID uint, perm model.PermissionType) {
	t.Helper()
	uid, aid := userID, assetID
	future := time.Now().Add(24 * time.Hour)
	require.NoError(t, db.Create(&model.AssetAuthorization{
		UserID:      &uid,
		AssetID:     &aid,
		Permission:  perm,
		Source:      model.AuthorizationSourceManual,
		DateExpired: &future,
	}).Error)
}

func TestDeleteAsset_AuthorizationsStopMatchingPermissionQueries(t *testing.T) {
	db, svc := setupDeleteRevokeDB(t)
	repo := newAssetAuthorizationRepository(db)

	a := mkDeleteRevokeAsset(t, db, "to-delete")
	const userID uint = 42
	mkDeleteRevokeAuth(t, db, userID, a.ID, model.PermissionConnect)
	mkDeleteRevokeAuth(t, db, userID, a.ID, model.PermissionView)

	// 前置條件：刪除前確實命中。缺了這一步，後面的「不命中」可能只是
	// 測試資料本身沒設對，斷言就證明不了任何事
	ok, err := repo.CheckPermission(userID, a.ID, []model.PermissionType{model.PermissionConnect})
	require.NoError(t, err)
	require.True(t, ok, "前置條件：刪除前授權須命中")

	// 姊妹查詢的前置條件同樣要驗——否則刪除後的 Empty 斷言可能只是「本來就空」
	// 的恆真式（守衛假綠的典型形態）
	scopesBefore, err := repo.AccountScopesFor(userID, a.ID,
		[]model.PermissionType{model.PermissionConnect}, time.Now())
	require.NoError(t, err)
	require.NotEmpty(t, scopesBefore, "前置條件：刪除前 AccountScopesFor 須有命中")

	require.NoError(t, svc.Delete(a.ID))

	// ① 權限檢查不再命中（缺陷本體）
	ok, err = repo.CheckPermission(userID, a.ID, []model.PermissionType{model.PermissionConnect})
	require.NoError(t, err)
	require.False(t, ok, "已刪資產的授權不得再於權限檢查中命中")

	// ② 姊妹查詢一併失效——**實測而非推論**。軟刪作用於記錄本身，
	//    故同語義查詢自動繼承；若 GORM 對某查詢未套用軟刪範圍即為缺陷，
	//    而那正是「只改 CheckPermission 會留下的旁路」
	sources, err := repo.ResolveConnectSources(userID, a.ID, time.Now())
	require.NoError(t, err)
	require.False(t, sources.Standing, "ResolveConnectSources 不得命中已刪資產的授權")
	require.False(t, sources.Ticket)

	scopes, err := repo.AccountScopesFor(userID, a.ID,
		[]model.PermissionType{model.PermissionConnect}, time.Now())
	require.NoError(t, err)
	require.Empty(t, scopes, "AccountScopesFor 不得命中已刪資產的授權")

	// ③ 記錄仍在（稽核軌跡保留，非實體移除）
	var count int64
	require.NoError(t, db.Unscoped().Model(&model.AssetAuthorization{}).
		Where("asset_id = ?", a.ID).Count(&count).Error)
	require.Equal(t, int64(2), count, "授權記錄須以軟刪保留，供稽核查詢曾授權給誰")
}

func TestDeleteAsset_DoesNotAffectOtherAssets(t *testing.T) {
	db, svc := setupDeleteRevokeDB(t)
	repo := newAssetAuthorizationRepository(db)

	target := mkDeleteRevokeAsset(t, db, "target")
	other := mkDeleteRevokeAsset(t, db, "other")
	const userID uint = 7
	mkDeleteRevokeAuth(t, db, userID, target.ID, model.PermissionConnect)
	mkDeleteRevokeAuth(t, db, userID, other.ID, model.PermissionConnect)

	require.NoError(t, svc.Delete(target.ID))

	ok, err := repo.CheckPermission(userID, other.ID, []model.PermissionType{model.PermissionConnect})
	require.NoError(t, err)
	require.True(t, ok, "刪除一個資產不得使其他資產的授權失效")
}
