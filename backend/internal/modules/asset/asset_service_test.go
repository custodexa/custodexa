package asset

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/audit"
)

// MockAESCrypto 模擬的 AES 加密器
type MockAESCrypto struct {
	encryptFunc func(plaintext string) (string, error)
	decryptFunc func(ciphertext string) (string, error)
}

func (m *MockAESCrypto) Encrypt(plaintext string) (string, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(plaintext)
	}
	// 簡單模擬：返回 "encrypted_" + plaintext
	return "encrypted_" + plaintext, nil
}

func (m *MockAESCrypto) Decrypt(ciphertext string) (string, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(ciphertext)
	}
	// 簡單模擬：移除 "encrypted_" 前綴
	if len(ciphertext) > 10 && ciphertext[:10] == "encrypted_" {
		return ciphertext[10:], nil
	}
	return ciphertext, nil
}

// setupAssetMockDB 建立測試用的 mock 資料庫
func setupAssetMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *gorm.DB) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}

	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to create gorm DB: %v", err)
	}

	// 保存原始的 DB
	oldDB := database.DB
	database.DB = gormDB

	// 清理函數會在測試結束時還原
	t.Cleanup(func() {
		database.DB = oldDB
		db.Close()
	})

	return db, mock, gormDB
}

// TestNewAssetService 測試創建 AssetService
func TestNewAssetService(t *testing.T) {
	// 三職拆解後，建構子改收 codec 必要參數：
	// 建構期**不再讀任何 env 金鑰材料**，故金鑰長度驗證改由 codec 自身的建構負責
	// （見 crypto.NewAESCrypto）；此處驗的是「codec 為必要參數」。
	// AAD cutover 後型別收斂為 crypto.ColumnCodec——**建構上**不可能寫出
	// 無 AAD 密文（該介面無 Encrypt(plaintext)）。
	valid := aesColumnCodec(t, make([]byte, 32))
	tests := []struct {
		name       string
		codec      crypto.ColumnCodec
		wantErr    bool
		errMessage string
	}{
		{"注入合法 codec", valid, false, ""},
		{"codec 為 nil 即拒絕建構", nil, true, "codec 為必要參數"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewAssetService(tt.codec, "localhost", 4822, audit.NewTxSink())

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMessage)
				assert.Nil(t, service)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, service)
				assert.NotNil(t, service.crypto)
			}
		})
	}
}

// TestCreate 測試創建資產
func TestCreate(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	// 創建 service（使用 32 字節密鑰）
	key := make([]byte, 32)
	service, err := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())
	assert.NoError(t, err)

	req := &CreateAssetRequest{
		Name:        "test-server",
		Protocol:    model.ProtocolSSH,
		Host:        "192.168.1.100",
		Port:        22,
		Username:    "admin",
		Password:    "secret123",
		Description: "Test server",
		CreatedBy:   1,
	}

	// 檢查名稱是否重複
	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE name`).
		WillReturnError(gorm.ErrRecordNotFound)

	// 插入資產
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "assets"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	// AfterCreate hook 會在新的 session 中插入 audit log
	mock.ExpectQuery(`INSERT INTO "audit_logs"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	// 資產多帳號階段 2：憑證與 username 同交易寫入 default 帳號，
	// 並留帳號建立審計
	mock.ExpectQuery(`INSERT INTO "asset_accounts"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectQuery(`INSERT INTO "audit_logs"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(2))
	mock.ExpectCommit()

	asset, err := service.Create(req)
	assert.NoError(t, err)
	assert.NotNil(t, asset)
	assert.Equal(t, req.Name, asset.Name)
	assert.True(t, asset.HasPassword)
	// 階段 2：密文只落 default 帳號，assets 內嵌憑證欄位凍結（上方 asset_accounts
	// INSERT 期望已驗證帳號確有寫入）
	assert.Empty(t, asset.PasswordEnc, "內嵌憑證欄位不再寫入")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCreate_PasswordEncrypted 測試密碼已加密
func TestCreate_PasswordEncrypted(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

	password := "mySecretPassword123!"
	req := &CreateAssetRequest{
		Name:      "secure-server",
		Protocol:  model.ProtocolSSH,
		Host:      "10.0.0.1",
		Port:      22,
		Username:  "root",
		Password:  password,
		CreatedBy: 1,
	}

	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE name`).
		WillReturnError(gorm.ErrRecordNotFound)

	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "assets"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	// AfterCreate hook 會插入 audit log (使用 RETURNING)
	mock.ExpectQuery(`INSERT INTO "audit_logs"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	// default 帳號 INSERT ＋ 帳號審計
	mock.ExpectQuery(`INSERT INTO "asset_accounts"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectQuery(`INSERT INTO "audit_logs"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(2))
	mock.ExpectCommit()

	asset, err := service.Create(req)
	assert.NoError(t, err)

	// 核心驗證：密文改落 default 帳號（見 asset_accounts INSERT 期望），
	// assets 內嵌憑證欄位凍結；明文絕不落任一處
	assert.Empty(t, asset.PasswordEnc, "內嵌憑證欄位不再寫入")
	assert.True(t, asset.HasPassword)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCreate_WithPrivateKey 測試創建含私鑰的 SSH 資產
func TestCreate_WithPrivateKey(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

	privateKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
	req := &CreateAssetRequest{
		Name:       "ssh-server",
		Protocol:   model.ProtocolSSH,
		Host:       "server.example.com",
		Port:       22,
		Username:   "deploy",
		PrivateKey: privateKey,
		CreatedBy:  1,
	}

	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE name`).
		WillReturnError(gorm.ErrRecordNotFound)

	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "assets"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	// AfterCreate hook 會插入 audit log (使用 RETURNING)
	mock.ExpectQuery(`INSERT INTO "audit_logs"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	// default 帳號 INSERT ＋ 帳號審計
	mock.ExpectQuery(`INSERT INTO "asset_accounts"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectQuery(`INSERT INTO "audit_logs"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(2))
	mock.ExpectCommit()

	asset, err := service.Create(req)
	assert.NoError(t, err)
	assert.True(t, asset.HasPrivateKey)
	assert.Empty(t, asset.PrivateKeyEnc, "內嵌私鑰欄位不再寫入（密文落 default 帳號）")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCreate_DuplicateName 測試創建重複名稱的資產
func TestCreate_DuplicateName(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

	req := &CreateAssetRequest{
		Name:      "existing-server",
		Protocol:  model.ProtocolSSH,
		Host:      "server.com",
		Port:      22,
		Username:  "admin",
		CreatedBy: 1,
	}

	// 模擬名稱已存在
	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE name`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(99))

	asset, err := service.Create(req)
	assert.Error(t, err)
	assert.Equal(t, ErrAssetNameExists, err)
	assert.Nil(t, asset)
}

// TestCreate_InvalidProtocol 測試無效協議
func TestCreate_InvalidProtocol(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

	req := &CreateAssetRequest{
		Name:      "test-server",
		Protocol:  "ftp", // 無效協議
		Host:      "server.com",
		Port:      21,
		Username:  "admin",
		CreatedBy: 1,
	}

	asset, err := service.Create(req)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidProtocol, err)
	assert.Nil(t, asset)

	// 應該沒有任何 DB 操作
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAsset_GetByID 測試根據 ID 查詢資產
func TestAsset_GetByID(t *testing.T) {
	tests := []struct {
		name      string
		id        uint
		setupMock func(sqlmock.Sqlmock)
		wantErr   error
		wantName  string
	}{
		{
			name: "Asset exists",
			id:   1,
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "protocol", "host", "port", "username", "group_id"}).
					AddRow(1, "my-server", model.ProtocolSSH, "192.168.1.1", 22, "admin", nil)
				mock.ExpectQuery(`SELECT .+ FROM "assets"`).
					WillReturnRows(rows)

					// fillAssetNodeInfo：成員空集即早退不查路徑
				mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
					WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))
			},
			wantErr:  nil,
			wantName: "my-server",
		},
		{
			name: "Asset not found",
			id:   999,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT .+ FROM "assets"`).
					WillReturnError(gorm.ErrRecordNotFound)
			},
			wantErr:  ErrAssetNotFound,
			wantName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mock, _ := setupAssetMockDB(t)
			key := make([]byte, 32)
			service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

			tt.setupMock(mock)

			asset, err := service.GetByID(tt.id)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
			} else {
				assert.NoError(t, err)
				if assert.NotNil(t, asset) {
					assert.Equal(t, tt.wantName, asset.Name)
				}
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestGetWithCredentialsDefault 測試取得資產＋預設帳號並解密憑證
// （階段 2：憑證與 username 一律自帳號表取得，內嵌欄位不再讀）
func TestGetWithCredentialsDefault(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

	// 先加密密碼和私鑰（密文須以落點欄位的列身分綁定 AAD，否則讀端解不開）
	password := "myPassword123"
	privateKey := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
	encryptedPassword, _ := service.crypto.EncryptFor(context.Background(), keyvault.RefAccountPassword, password)
	encryptedPrivateKey, _ := service.crypto.EncryptFor(context.Background(), keyvault.RefAccountPrivateKey, privateKey)

	// Mock 查詢：資產本體不再帶憑證（內嵌欄位凍結）
	rows := sqlmock.NewRows([]string{"id", "name", "username"}).
		AddRow(1, "secure-server", "legacy-embedded")
	mock.ExpectQuery(`SELECT .+ FROM "assets"`).
		WillReturnRows(rows)

	// fillAssetNodeInfo：成員空集即早退不查路徑
	mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))

	// 預設帳號：憑證與 username 的權威來源
	mock.ExpectQuery(`SELECT .+ FROM "asset_accounts"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "username", "password_enc", "private_key_enc", "is_default"}).
			AddRow(7, 1, "svc-account", encryptedPassword, encryptedPrivateKey, true))

	creds, err := service.GetWithCredentialsDefault(1)
	assert.NoError(t, err)
	assert.NotNil(t, creds)

	// 核心驗證：密碼和私鑰已解密為明文，且 username 取自帳號而非 assets 內嵌欄位
	assert.Equal(t, uint(7), creds.AccountID)
	assert.Equal(t, "svc-account", creds.Username, "username 應取自帳號")
	assert.Equal(t, password, creds.Password, "密碼應該被解密為明文")
	assert.Equal(t, privateKey, creds.PrivateKey, "私鑰應該被解密為明文")
	assert.NotEqual(t, encryptedPassword, creds.Password, "解密後不應等於密文")
}

// TestGetWithCredentialsForAccount_CrossAssetRejected 跨資產 account id 注入
// 必須 fail-close：帳號不屬該資產時回錯，**不得靜默退回預設帳號**
func TestGetWithCredentialsForAccount_CrossAssetRejected(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

	mock.ExpectQuery(`SELECT .+ FROM "assets"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(1, "target"))
	mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))
	// (id, asset_id) 複合條件查不到＝別的資產的帳號
	mock.ExpectQuery(`SELECT .+ FROM "asset_accounts"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	creds, err := service.GetWithCredentialsForAccount(1, 99)
	assert.Nil(t, creds)
	assert.ErrorIs(t, err, ErrAssetAccountNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUpdate 測試更新資產
func TestUpdate(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

	// GetByID - First query for asset
	rows := sqlmock.NewRows([]string{"id", "name", "protocol", "host", "port", "username", "group_id"}).
		AddRow(1, "old-name", model.ProtocolSSH, "192.168.1.1", 22, "admin", nil)
	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(rows)

	// fillAssetNodeInfo：成員空集即早退不查路徑
	mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))

	// 更新
	newName := "new-name"
	req := &UpdateAssetRequest{
		Name: &newName,
	}

	// 檢查新名稱是否重複（排除自己）
	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE .*name.* AND .*id`).
		WillReturnError(gorm.ErrRecordNotFound)

	// Save
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "assets" SET`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	// AfterUpdate hook 在交易內插入 audit_log（GORM/Postgres 用 RETURNING，走 Query）
	mock.ExpectQuery(`INSERT INTO "audit_logs"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectCommit()

	asset, err := service.Update(context.Background(), 1, req)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())

	if assert.NotNil(t, asset) {
		assert.Equal(t, newName, asset.Name)
	}
}

// TestUpdate_PasswordReEncrypted 測試更新密碼時重新加密
func TestUpdate_PasswordReEncrypted(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

	oldPassword := "oldPassword"
	// assets.password_enc 自資產多帳號階段 2 起凍結不再寫入，
	// 此處僅作為「內嵌欄位不被覆寫」的比對基準，故綁該欄位的列身分
	oldEncryptedPassword, _ := service.crypto.EncryptFor(context.Background(), keyvault.RefAssetsPassword, oldPassword)

	// GetByID - SELECT asset
	rows := sqlmock.NewRows([]string{"id", "name", "password_enc", "has_password", "group_id"}).
		AddRow(1, "server", oldEncryptedPassword, true, nil)
	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(rows)

	// fillAssetNodeInfo：成員空集即早退不查路徑
	mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))

	newPassword := "newPassword123"
	req := &UpdateAssetRequest{
		Password: &newPassword,
	}

	// Update operation
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "assets" SET`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	// AfterUpdate hook 在交易內插入 audit_log（GORM/Postgres 用 RETURNING，走 Query）
	mock.ExpectQuery(`INSERT INTO "audit_logs"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	// 透明轉寫：鎖資產列（與帳號 CRUD 同一互斥點）→ 查 default 帳號 →
	// 更新密文 → 帳號審計
	mock.ExpectQuery(`SELECT id FROM assets WHERE id = .+ FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectQuery(`SELECT .+ FROM "asset_accounts"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "username", "is_default"}).
			AddRow(5, 1, "", true))
	mock.ExpectExec(`UPDATE "asset_accounts" SET`).
		WillReturnResult(sqlmock.NewResult(5, 1))
	mock.ExpectQuery(`INSERT INTO "audit_logs"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(2))
	mock.ExpectCommit()

	asset, err := service.Update(context.Background(), 1, req)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())

	if assert.NotNil(t, asset) {
		// 階段 2：新密文透明轉寫進 default 帳號（見上方 asset_accounts UPDATE 期望），
		// assets 內嵌欄位維持舊值不再被覆寫
		assert.Equal(t, oldEncryptedPassword, asset.PasswordEnc, "內嵌憑證欄位凍結，不再被更新")
		assert.True(t, asset.HasPassword)
	}
}

// TestDelete 測試刪除資產
func TestDelete(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())
	// 資產刪除須連動撤銷 authz 的授權與審核範圍（塊 2）。
	// 未注入即 fail-close，故此處注入替身；替身不下 SQL，無須額外 mock 期望
	revoker := &fakeAuthzRevoker{}
	service.SetAuthorizationRevoker(revoker)

	// GetByID - SELECT asset
	rows := sqlmock.NewRows([]string{"id", "name", "group_id"}).
		AddRow(1, "to-delete", nil)
	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(rows)

	// fillAssetNodeInfo：成員空集即早退不查路徑
	mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))

	// 軟刪除（節點成員先於資產清除）
	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM "asset_nodes"`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE "assets" SET "deleted_at"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	// AfterDelete hook 在交易內插入 audit_log（GORM/Postgres 用 RETURNING，走 Query）
	mock.ExpectQuery(`INSERT INTO "audit_logs"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectCommit()

	err := service.Delete(1)
	assert.NoError(t, err)
	assert.Equal(t, []uint{1}, revoker.calls,
		"刪除資產必須連動撤銷其授權與審核範圍")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestDelete_NotExists 測試刪除不存在的資產
func TestDelete_NotExists(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

	mock.ExpectQuery(`SELECT .+ FROM "assets"`).
		WillReturnError(gorm.ErrRecordNotFound)

	err := service.Delete(999)
	assert.Error(t, err)
	assert.Equal(t, ErrAssetNotFound, err)
}

// TestAsset_List 測試列表查詢
func TestAsset_List(t *testing.T) {
	tests := []struct {
		name      string
		filter    *AssetFilter
		setupMock func(sqlmock.Sqlmock)
		wantTotal int64
		wantSize  int
	}{
		{
			name: "Default pagination",
			filter: &AssetFilter{
				Page:     1,
				PageSize: 20,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT count\(\*\) FROM "assets"`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

				// Include group_id column with nil values
				rows := sqlmock.NewRows([]string{"id", "name", "group_id"}).
					AddRow(1, "server1", nil).
					AddRow(2, "server2", nil)
				mock.ExpectQuery(`SELECT .+ FROM "assets" .+ ORDER BY created_at DESC`).
					WillReturnRows(rows)

					// fillAssetNodeInfo：成員空集即早退不查路徑
				mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
					WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))
			},
			wantTotal: 5,
			wantSize:  20,
		},
		{
			name: "Filter by protocol",
			filter: &AssetFilter{
				Protocol: model.ProtocolRDP,
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT count\(\*\) FROM "assets" WHERE protocol`).
					WithArgs(model.ProtocolRDP).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

				// Include group_id column with nil value
				rows := sqlmock.NewRows([]string{"id", "protocol", "group_id"}).
					AddRow(1, model.ProtocolRDP, nil)
				mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE protocol`).
					WillReturnRows(rows)

					// fillAssetNodeInfo：成員空集即早退不查路徑
				mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
					WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))
			},
			wantTotal: 3,
			wantSize:  10,
		},
		{
			name: "Search by name",
			filter: &AssetFilter{
				Search:   "prod",
				Page:     1,
				PageSize: 20,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT count\(\*\) FROM "assets" WHERE .+ LIKE .+ OR .+ LIKE`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

				// Include group_id column with nil value
				rows := sqlmock.NewRows([]string{"id", "name", "group_id"}).
					AddRow(1, "prod-server", nil)
				mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE .+ LIKE .+ OR .+ LIKE`).
					WillReturnRows(rows)

					// fillAssetNodeInfo：成員空集即早退不查路徑
				mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
					WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))
			},
			wantTotal: 2,
			wantSize:  20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mock, _ := setupAssetMockDB(t)
			key := make([]byte, 32)
			service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

			tt.setupMock(mock)

			result, err := service.List(tt.filter)
			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantTotal, result.Total)
			assert.Equal(t, tt.wantSize, result.PageSize)

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestValidateProtocol 測試協議驗證
func TestValidateProtocol(t *testing.T) {
	key := make([]byte, 32)
	service, _ := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())

	tests := []struct {
		name     string
		protocol model.ProtocolType
		wantErr  bool
	}{
		{"Valid SSH", model.ProtocolSSH, false},
		{"Valid RDP", model.ProtocolRDP, false},
		{"Valid VNC", model.ProtocolVNC, false},
		{"Invalid FTP", "ftp", true},
		{"Invalid Empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateProtocol(tt.protocol)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidProtocol, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestEncryptionDecryption_Integration 測試加密解密整合（一律帶列身分 AAD——
// 無 AAD 的加解密入口已在過渡格式收尾時自原語層刪除）
func TestEncryptionDecryption_Integration(t *testing.T) {
	key := make([]byte, 32)
	crypto1, _ := crypto.NewAESCrypto(key)

	plaintext := "mySecretPassword123!"
	aad := refAssetPassword.AAD()

	// 加密
	ciphertext, err := crypto1.EncryptBytesAAD([]byte(plaintext), aad)
	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, []byte(plaintext), ciphertext)

	// 解密
	decrypted, err := crypto1.DecryptBytesAAD(ciphertext, aad)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, string(decrypted))

	// 兩次加密同一明文應該產生不同密文（因為 nonce 隨機）
	ciphertext2, err := crypto1.EncryptBytesAAD([]byte(plaintext), aad)
	assert.NoError(t, err)
	assert.NotEqual(t, ciphertext, ciphertext2)

	// 但都能解密為相同明文
	decrypted2, err := crypto1.DecryptBytesAAD(ciphertext2, aad)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, string(decrypted2))

	// 空 AAD 於兩端一律被拒（建構保證，非呼叫端自律）
	_, err = crypto1.EncryptBytesAAD([]byte(plaintext), nil)
	assert.ErrorIs(t, err, crypto.ErrAADRequired)
	_, err = crypto1.DecryptBytesAAD(ciphertext, nil)
	assert.ErrorIs(t, err, crypto.ErrAADRequired)
}

// TestValidateDBTLSMode 白名單不寬容：大小寫、前後空白、未知檔位一律拒絕，
// 否則髒值進 dbproxy 不加 TLS 旗標（postgres 落 prefer、redis 落明文）且騙過風險判定
func TestValidateDBTLSMode(t *testing.T) {
	valid := []string{"", "disable", "require", "verify-ca", "verify-full"}
	for _, v := range valid {
		assert.NoError(t, validateDBTLSMode(v), "合法值 %q 應通過", v)
	}

	invalid := []string{"prefer", "allow", "DISABLE", "Require", "VERIFY-CA", " require", "require ", "verify_full", "true"}
	for _, v := range invalid {
		assert.ErrorIs(t, validateDBTLSMode(v), ErrInvalidDBTLSMode, "非法值 %q 應被拒", v)
	}
}

// TestCreateRejectsInvalidDBTLSMode Create 入口擋非法 db_tls_mode（service 層驗證，
// 使繞 HTTP binding 的內部呼叫同受約束；驗證在查重之前，不需 mock 查詢）
func TestCreateRejectsInvalidDBTLSMode(t *testing.T) {
	setupAssetMockDB(t)

	key := make([]byte, 32)
	service, err := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())
	assert.NoError(t, err)

	_, err = service.Create(&CreateAssetRequest{
		Name:      "bad-tls-mode",
		Protocol:  model.ProtocolPostgres,
		Host:      "db.example.com",
		Port:      5432,
		Username:  "postgres",
		DBTLSMode: "prefer",
		CreatedBy: 1,
	})
	assert.ErrorIs(t, err, ErrInvalidDBTLSMode)
}

// TestUpdateRejectsInvalidDBTLSMode Update 入口擋非法 db_tls_mode
func TestUpdateRejectsInvalidDBTLSMode(t *testing.T) {
	_, mock, _ := setupAssetMockDB(t)

	mock.ExpectQuery(`SELECT .+ FROM "assets"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "protocol", "host", "port", "username"}).
			AddRow(1, "pg-asset", "postgres", "db.example.com", 5432, "postgres"))
	mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))

	key := make([]byte, 32)
	service, err := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())
	assert.NoError(t, err)

	bad := "PREFER"
	_, err = service.Update(context.Background(), 1, &UpdateAssetRequest{DBTLSMode: &bad})
	assert.ErrorIs(t, err, ErrInvalidDBTLSMode)
}
