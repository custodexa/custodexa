package asset

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 帳號操作審計必須指認「這次動的是哪一筆憑證、什麼範圍」。
//
// 少了這兩欄，稽核只看得到「某台的某個帳號被改了」，回答不了「那組秘密同時在
// 哪些主機上生效」——而共用憑證正是這個問題的來源。範圍（shared／dedicated）
// 與識別一併記：識別在憑證被回收之後查不回範圍，而範圍決定了影響面有多大。

// accountAuditDetails 取某帳號的帳號類審計列（依 id 升冪）的 Details 解析結果。
func accountAuditDetails(t *testing.T, db *gorm.DB, assetID uint) []model.AssetAccountAuditDetails {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, db.Where("resource = ? AND resource_id = ?",
		string(model.ResourceAsset), assetID).Order("id ASC").Find(&rows).Error)
	out := make([]model.AssetAccountAuditDetails, 0, len(rows))
	for _, row := range rows {
		var d model.AssetAccountAuditDetails
		if err := json.Unmarshal([]byte(row.Details), &d); err != nil {
			continue
		}
		if d.Resource != "asset_account" {
			continue
		}
		out = append(out, d)
	}
	return out
}

// findAccountAudit 取指定操作類型的第一筆帳號審計明細。
func findAccountAudit(t *testing.T, db *gorm.DB, assetID uint, op string) model.AssetAccountAuditDetails {
	t.Helper()
	for _, d := range accountAuditDetails(t, db, assetID) {
		if d.Operation == op {
			return d
		}
	}
	require.FailNowf(t, "查無帳號審計列", "operation=%s asset=%d", op, assetID)
	return model.AssetAccountAuditDetails{}
}

// 建立／更新／切換預設／刪除四事件都要帶憑證識別與範圍。
func TestAccountAuditCarriesCredentialRef(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)
	_ = creds

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "audit-cred", Protocol: model.ProtocolSSH, Host: "10.7.0.1", Port: 22,
		Username: "root", Password: "pw0", CreatedBy: 1, CreatedByName: "admin",
	})
	require.NoError(t, err)

	var first model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&first).Error)
	require.NotZero(t, first.CredentialID)

	create := findAccountAudit(t, db, asset.ID, model.AccountOpCreate)
	assert.Equal(t, first.CredentialID, create.CredentialID, "建立事件須指認掛上的憑證")
	assert.Equal(t, model.CredentialScopeDedicated, create.CredentialScope)

	// 更新（換密碼）
	newPW := "pw1"
	_, err = accounts.Update(adminCtx(), asset.ID, first.ID,
		&UpdateAssetAccountRequest{Password: &newPW})
	require.NoError(t, err)
	update := findAccountAudit(t, db, asset.ID, model.AccountOpUpdate)
	assert.Equal(t, first.CredentialID, update.CredentialID, "更新事件須指認憑證")
	assert.Equal(t, model.CredentialScopeDedicated, update.CredentialScope)

	// 第二個帳號 → 切換預設
	second, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
		Username: "deploy", Password: "pw2",
	})
	require.NoError(t, err)
	_, err = accounts.SetDefault(adminCtx(), asset.ID, second.ID)
	require.NoError(t, err)
	setDefault := findAccountAudit(t, db, asset.ID, model.AccountOpSetDefault)
	var secondRow model.AssetAccount
	require.NoError(t, db.First(&secondRow, second.ID).Error)
	assert.Equal(t, secondRow.CredentialID, setDefault.CredentialID, "切換預設須指認憑證")
	assert.Equal(t, model.CredentialScopeDedicated, setDefault.CredentialScope)

	// 刪除（專用憑證同交易回收，審計仍須留下它的識別與範圍）
	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, first.ID))
	del := findAccountAudit(t, db, asset.ID, model.AccountOpDelete)
	assert.Equal(t, first.CredentialID, del.CredentialID, "刪除事件須指認被解除的憑證")
	assert.Equal(t, model.CredentialScopeDedicated, del.CredentialScope,
		"憑證已隨掛載回收，範圍仍須查得回來")

	// 安全紅線：審計不得含任何秘密材料
	for _, plain := range []string{"pw0", "pw1", "pw2"} {
		var rows []model.AuditLog
		require.NoError(t, db.Find(&rows).Error)
		for _, row := range rows {
			assert.NotContains(t, row.Details, plain, "審計不得含明文憑證")
		}
	}
}

// 掛既有共用憑證的帳號，審計要記 shared。
func TestAccountAuditCredentialScopeShared(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)
	_ = creds

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "audit-shared", Protocol: model.ProtocolSSH, Host: "10.7.0.2", Port: 22,
		Username: "root", Password: "pw0", CreatedBy: 1, CreatedByName: "admin",
	})
	require.NoError(t, err)

	shared := newSharedCredential(t, creds, "ops-shared", "shareduser", "shared-pw")
	acc, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
		CredentialID: shared.ID,
	})
	require.NoError(t, err)

	var stored model.AssetAccount
	require.NoError(t, db.First(&stored, acc.ID).Error)
	assert.Equal(t, shared.ID, stored.CredentialID)

	var got model.AssetAccountAuditDetails
	for _, d := range accountAuditDetails(t, db, asset.ID) {
		if d.Operation == model.AccountOpCreate && d.AccountID == acc.ID {
			got = d
		}
	}
	assert.Equal(t, shared.ID, got.CredentialID, "掛共用憑證的建立事件須指認該憑證")
	assert.Equal(t, model.CredentialScopeShared, got.CredentialScope)
}

// #6 私鑰輪替留痕：審計 details 的欄位名清單須含 private_key（只記名稱、不記值）。
func TestAccountAuditRecordsPrivateKeyFieldName(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)
	_ = creds

	const key = "test-private-key-material-rotated"

	// (a) 建立事件：資產建立時直接帶私鑰
	asset, err := assets.Create(&CreateAssetRequest{
		Name: "pk-audit", Protocol: model.ProtocolSSH, Host: "10.7.0.3", Port: 22,
		Username: "root", PrivateKey: key, CreatedBy: 1, CreatedByName: "admin",
	})
	require.NoError(t, err)
	create := findAccountAudit(t, db, asset.ID, model.AccountOpCreate)
	assert.Contains(t, create.Fields, "private_key", "建立事件須留下私鑰欄位名")

	// (b) 帳號更新事件（asset_account_service.go 的 Update 寫入點）
	var account model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&account).Error)
	rotated := key + "\n"
	_, err = accounts.Update(adminCtx(), asset.ID, account.ID,
		&UpdateAssetAccountRequest{PrivateKey: &rotated})
	require.NoError(t, err)
	update := findAccountAudit(t, db, asset.ID, model.AccountOpUpdate)
	assert.Contains(t, update.Fields, "private_key", "私鑰輪替須留下欄位名")

	// (c) 資產表單透明轉寫（syncDefaultAccountFromAsset 寫入點）
	viaAsset := key + "\n\n"
	_, err = assets.Update(adminCtx(), asset.ID, &UpdateAssetRequest{PrivateKey: &viaAsset})
	require.NoError(t, err)

	var withPK int
	for _, d := range accountAuditDetails(t, db, asset.ID) {
		for _, f := range d.Fields {
			if f == "private_key" {
				withPK++
			}
		}
	}
	assert.GreaterOrEqual(t, withPK, 3, "三個寫入點各留一次私鑰欄位名")

	// 欄位名之外絕不含金鑰本體
	var rows []model.AuditLog
	require.NoError(t, db.Find(&rows).Error)
	for _, row := range rows {
		assert.NotContains(t, row.Details, key, "審計不得含私鑰內容")
	}
}
