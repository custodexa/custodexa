package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"database/sql"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/modules/audit"
)

// 整合測試對 docker-compose 的 ssh-test 容器執行：
// 以 mock DB 提供資產記錄（host=ssh-test:2222, testuser/testpass123），
// 實際 SFTP 操作走真連線。容器不可達時跳過。
func newSFTPServiceForTest(t *testing.T) *SFTPService {
	t.Helper()

	_, mock, _ := setupAssetMockDB(t)
	key := make([]byte, 32)
	codec := aesColumnCodec(t, key)
	assetService, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)

	// 密文落點為 asset_accounts.password_enc，AAD 須綁該欄位身分（D5）。
	// **W6 6.6**：原本走 `assetService.crypto`（asset 的未匯出欄），搬包後跨包取不到；
	// 改用**同一個** codec 實例——加密結果逐位元組相同，非放寬。
	encrypted, _ := codec.EncryptFor(context.Background(), keyvault.RefAccountPassword, "testpass123")

	// 每次 GetWithCredentialsDefault 查一次資產＋一次 default 帳號
	//（asset-multi-account 階段 2：username 與憑證皆自帳號取得）；
	// 預期足夠多次供整連串操作使用
	for i := 0; i < 12; i++ {
		rows := mock.NewRows([]string{"id", "name", "protocol", "host", "port", "username"}).
			AddRow(1, "ssh-test", model.ProtocolSSH, "ssh-test", 2222, "testuser")
		mock.ExpectQuery(`SELECT .+ FROM "assets"`).WillReturnRows(rows)
		// fillAssetNodeInfo（asset-node-tree）：成員空集即早退不查路徑
		mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
			WillReturnRows(mock.NewRows([]string{"id", "asset_id", "node_id"}))
		mock.ExpectQuery(`SELECT .+ FROM "asset_accounts"`).
			WillReturnRows(mock.NewRows([]string{"id", "asset_id", "username", "password_enc", "is_default"}).
				AddRow(1, 1, "testuser", encrypted, true))
	}

	return NewSFTPService(assetService, asset.NewHostKeyService(setupHostKeyDB(t)))
}

func skipIfUnreachable(t *testing.T, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), "SSH 連線失敗")) {
		t.Skipf("ssh-test 容器不可達，跳過: %v", err)
	}
}

func TestSFTPValidateRemotePath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"絕對路徑通過", "/tmp/dir", "/tmp/dir", false},
		{"清理重複斜線", "/tmp//dir/", "/tmp/dir", false},
		{"相對路徑拒絕", "tmp/dir", "", true},
		{"含 .. 拒絕", "/tmp/../etc/passwd", "", true},
		{"純 .. 拒絕", "/..", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateRemotePath(tt.input)
			if tt.wantErr {
				assert.True(t, errors.Is(err, ErrInvalidRemotePath))
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSFTPRoundTrip(t *testing.T) {
	// Arrange
	svc := newSFTPServiceForTest(t)
	remoteDir := fmt.Sprintf("/tmp/sftp-it-%d", time.Now().UnixNano())
	remoteFile := remoteDir + "/hello.txt"
	content := []byte("sftp-round-trip-content-42\n")

	// Act + Assert: mkdir
	err := svc.Mkdir(1, 0, remoteDir)
	skipIfUnreachable(t, err)
	require.NoError(t, err)

	// upload
	written, err := svc.Upload(1, 0, remoteFile, bytes.NewReader(content))
	require.NoError(t, err)
	assert.Equal(t, int64(len(content)), written)

	// list：目錄含上傳的檔案
	entries, err := svc.List(1, 0, remoteDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "hello.txt", entries[0].Name)
	assert.Equal(t, int64(len(content)), entries[0].Size)
	assert.False(t, entries[0].IsDir)

	// download round-trip
	reader, size, closeFn, err := svc.Download(1, 0, remoteFile)
	require.NoError(t, err)
	downloaded, err := io.ReadAll(reader)
	reader.Close()
	closeFn()
	require.NoError(t, err)
	assert.Equal(t, int64(len(content)), size)
	assert.Equal(t, content, downloaded)

	// delete 檔案後目錄可刪
	require.NoError(t, svc.Delete(1, 0, remoteFile))
	require.NoError(t, svc.Delete(1, 0, remoteDir))

	// 刪除後 list 應失敗
	_, err = svc.List(1, 0, remoteDir)
	assert.Error(t, err)
}

func TestSFTPInvalidPathShortCircuits(t *testing.T) {
	// Arrange：路徑驗證在連線前，不需 DB 期望
	svc := NewSFTPService(nil, nil)

	// Act + Assert
	_, err := svc.List(1, 0, "relative/path")
	assert.True(t, errors.Is(err, ErrInvalidRemotePath))

	_, err = svc.Upload(1, 0, "/tmp/../etc/x", bytes.NewReader(nil))
	assert.True(t, errors.Is(err, ErrInvalidRemotePath))
}

// setupAssetMockDB 的 session 側複本（W6 6.6）：原件隨 asset_service_test.go
// 遷入 asset 包，跨包取不到未匯出的測試 helper。逐行複製。
func setupAssetMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *gorm.DB) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	gormDB, err := gorm.Open(postgres.New(postgres.Config{Conn: db}), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to create gorm DB: %v", err)
	}
	oldDB := database.DB
	database.DB = gormDB
	t.Cleanup(func() {
		database.DB = oldDB
		db.Close()
	})
	return db, mock, gormDB
}

// setupHostKeyDB 的 session 側複本（W6 6.6，原件隨 hostkey_service_test.go 遷入 asset 包）。
func setupHostKeyDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AssetHostKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}
