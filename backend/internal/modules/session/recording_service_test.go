package session

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// setupTestRecordingService 創建測試用的 RecordingService with sqlmock
func setupTestRecordingService(t *testing.T) (*RecordingService, string, *sql.DB, sqlmock.Sqlmock, func()) {
	// 創建臨時目錄
	tmpDir, err := os.MkdirTemp("", "recording-test-*")
	require.NoError(t, err)

	// 創建 sqlmock
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	// 創建 GORM DB
	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})
	require.NoError(t, err)

	// 保存原始 DB
	oldDB := database.DB
	database.DB = gormDB

	// 創建服務
	service := NewRecordingService(tmpDir)

	// 返回清理函數
	cleanup := func() {
		os.RemoveAll(tmpDir)
		database.DB = oldDB
		db.Close()
	}

	return service, tmpDir, db, mock, cleanup
}

// sessionIDCounter 用於生成唯一的 session ID
var sessionIDCounter int = 0

// createTestRecordingFile 創建測試用的錄製檔案
func createTestRecordingFile(t *testing.T, basePath string, sessionID uint, date string) string {
	// 創建日期目錄
	dateDir := filepath.Join(basePath, date)
	err := os.MkdirAll(dateDir, 0755)
	require.NoError(t, err)

	// 創建錄製檔案
	fileName := fmt.Sprintf("session-%d.cast", sessionID)
	filePath := filepath.Join(dateDir, fileName)

	// 寫入測試內容
	content := `{"version":2,"width":80,"height":24,"timestamp":1234567890}
[0.1,"o","test output"]
[0.2,"o","more output"]
`
	err = os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(t, err)

	return filePath
}

func TestRecordingService_GetRecordingBySessionID(t *testing.T) {
	service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
	defer cleanup()

	t.Run("成功獲取錄製檔案路徑", func(t *testing.T) {
		// 創建測試檔案
		filePath := createTestRecordingFile(t, tmpDir, 1, "2025-10-20")

		// Mock database query
		rows := sqlmock.NewRows([]string{"id", "recording_path", "has_recording"}).
			AddRow(1, filePath, true)

		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(1, sqlmock.AnyArg()).
			WillReturnRows(rows)

		// 獲取錄製檔案
		resultPath, err := service.GetRecordingBySessionID(1)
		assert.NoError(t, err)
		assert.Equal(t, filePath, resultPath)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Session 不存在", func(t *testing.T) {
		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(9999, sqlmock.AnyArg()).
			WillReturnError(gorm.ErrRecordNotFound)

		_, err := service.GetRecordingBySessionID(9999)
		assert.ErrorIs(t, err, ErrSessionNotFound)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Session 沒有錄製檔案", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "recording_path", "has_recording"}).
			AddRow(2, "", false)

		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(2, sqlmock.AnyArg()).
			WillReturnRows(rows)

		_, err := service.GetRecordingBySessionID(2)
		assert.ErrorIs(t, err, ErrSessionHasNoRecording)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("錄製檔案不存在", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "recording_path", "has_recording"}).
			AddRow(3, "/nonexistent/path.cast", true)

		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(3, sqlmock.AnyArg()).
			WillReturnRows(rows)

		_, err := service.GetRecordingBySessionID(3)
		assert.ErrorIs(t, err, ErrRecordingNotFound)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRecordingService_GetRecordingStream(t *testing.T) {
	service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
	defer cleanup()

	t.Run("成功獲取錄製串流", func(t *testing.T) {
		// 創建測試檔案
		filePath := createTestRecordingFile(t, tmpDir, 2, "2025-10-20")

		rows := sqlmock.NewRows([]string{"id", "recording_path", "has_recording"}).
			AddRow(2, filePath, true)

		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(2, sqlmock.AnyArg()).
			WillReturnRows(rows)

		// 獲取串流
		stream, err := service.GetRecordingStream(2)
		assert.NoError(t, err)
		assert.NotNil(t, stream)
		defer stream.Close()

		// 讀取內容
		buf := make([]byte, 100)
		n, err := stream.Read(buf)
		assert.NoError(t, err)
		assert.Greater(t, n, 0)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("檔案不存在時失敗", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "recording_path", "has_recording"}).
			AddRow(3, "/nonexistent/path.cast", true)

		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(3, sqlmock.AnyArg()).
			WillReturnRows(rows)

		stream, err := service.GetRecordingStream(3)
		assert.Error(t, err)
		assert.Nil(t, stream)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRecordingService_GetRecordingStats(t *testing.T) {
	service, tmpDir, _, _, cleanup := setupTestRecordingService(t)
	defer cleanup()

	t.Run("空目錄統計", func(t *testing.T) {
		stats, err := service.GetRecordingStats()
		assert.NoError(t, err)
		assert.Equal(t, int64(0), stats.TotalSize)
		assert.Equal(t, 0, stats.Count)
		assert.Empty(t, stats.OldestDate)
		assert.Empty(t, stats.NewestDate)
	})

	t.Run("統計多個錄製檔案", func(t *testing.T) {
		// 創建多個測試檔案
		file1 := createTestRecordingFile(t, tmpDir, 10, "2025-10-18")
		file2 := createTestRecordingFile(t, tmpDir, 11, "2025-10-19")
		file3 := createTestRecordingFile(t, tmpDir, 12, "2025-10-20")

		// 獲取統計
		stats, err := service.GetRecordingStats()
		assert.NoError(t, err)
		assert.Equal(t, 3, stats.Count)
		assert.Greater(t, stats.TotalSize, int64(0))
		assert.Equal(t, "2025-10-18", stats.OldestDate)
		assert.Equal(t, "2025-10-20", stats.NewestDate)

		// 驗證總大小
		info1, _ := os.Stat(file1)
		info2, _ := os.Stat(file2)
		info3, _ := os.Stat(file3)
		expectedSize := info1.Size() + info2.Size() + info3.Size()
		assert.Equal(t, expectedSize, stats.TotalSize)
	})

	t.Run("目錄不存在時返回空統計", func(t *testing.T) {
		service := NewRecordingService("/nonexistent/path")
		stats, err := service.GetRecordingStats()
		assert.NoError(t, err)
		assert.Equal(t, 0, stats.Count)
	})
}

// TestRecordingService_GetRecordingStats_CoversGraphicalRecordings 守衛「統計只認 .cast」
// 的回歸。圖形協議（RDP/VNC）錄影由 guacd 直接寫在 basePath 根層、副檔名為 .guac，
// 舊實作以 filepath.Ext(path) == ".cast" 過濾，整批漏算——實測 dev 環境單一
// session-33.guac 就有 188KB，而全部 .cast 合計僅 44KB，
// custodexa_recording_storage_bytes 與 `GET /recordings/stats` 因此系統性低報。
func TestRecordingService_GetRecordingStats_CoversGraphicalRecordings(t *testing.T) {
	service, tmpDir, _, _, cleanup := setupTestRecordingService(t)
	defer cleanup()

	// 文字錄影：basePath/YYYY-MM-DD/session-N.cast
	castPath := createTestRecordingFile(t, tmpDir, 10, "2025-10-18")

	// 圖形錄影：根層、.guac，體積刻意大於文字錄影（實測差兩個數量級）
	guacPath := filepath.Join(tmpDir, "session-33.guac")
	require.NoError(t, os.WriteFile(guacPath, make([]byte, 4096), 0600))

	// ---- 前置條件：不先釘死這些，下面的斷言可能是恆真式 ----
	castInfo, err := os.Stat(castPath)
	require.NoError(t, err)
	require.Greater(t, castInfo.Size(), int64(0), "前置條件：文字錄影須非空")
	guacInfo, err := os.Stat(guacPath)
	require.NoError(t, err)
	require.Greater(t, guacInfo.Size(), int64(0),
		"前置條件：圖形錄影須非空，否則『已計入』與『仍漏算』的總量無法區分")
	// 確認這個檔真的落在舊判準之外（副檔名不是 .cast）
	require.NotEqual(t, ".cast", filepath.Ext(guacPath),
		"前置條件：測試檔必須是舊白名單擋掉的副檔名")
	// 也確認它不在日期子目錄下——這是第二個漏洞（日期推導）成立的前提
	_, dateErr := time.Parse("2006-01-02", filepath.Base(filepath.Dir(guacPath)))
	require.Error(t, dateErr,
		"前置條件：圖形錄影須位於非日期目錄，否則測不到日期推導的漏洞")

	stats, err := service.GetRecordingStats()
	require.NoError(t, err)

	assert.Equal(t, 2, stats.Count)
	assert.Equal(t, castInfo.Size()+guacInfo.Size(), stats.TotalSize)
	// 明確釘住「差額正是圖形錄影」：舊實作在此只會累到 castInfo.Size()
	assert.Equal(t, guacInfo.Size(), stats.TotalSize-castInfo.Size(),
		"圖形錄影未被計入儲存統計")

	// 日期涵蓋：.guac 無日期目錄可依，須退回 mtime 而非被整個跳過
	assert.Equal(t, "2025-10-18", stats.OldestDate)
	assert.Equal(t, guacInfo.ModTime().Format("2006-01-02"), stats.NewestDate,
		"圖形錄影未進入日期區間，Oldest/NewestDate 只描述了文字錄影")
}

// TestRecordingService_GetRecordingStats_InProgressAndProbeFiles 涵蓋副檔名白名單
// 必然漏掉的兩種檔：進行中的圖形錄影（尚無副檔名）要計入，探測殘留檔要排除。
func TestRecordingService_GetRecordingStats_InProgressAndProbeFiles(t *testing.T) {
	service, tmpDir, _, _, cleanup := setupTestRecordingService(t)
	defer cleanup()

	// 會話進行中的圖形錄影：guacd 寫的是 basePath/<protocol>-<nanos>，完全沒有副檔名，
	// 會話結束才更名為 session-N.guac（見 internal/proxy/handler.go）
	inProgress := filepath.Join(tmpDir, "rdp-1755123456789000000")
	require.NoError(t, os.WriteFile(inProgress, make([]byte, 2048), 0600))
	require.Empty(t, filepath.Ext(inProgress),
		"前置條件：進行中錄影必須無副檔名，否則測不到副檔名白名單的盲區")

	// recorder.ProbeWritable 殘留的探測檔不是錄影，不得計入
	probePath := filepath.Join(tmpDir, ".probe-abc123")
	require.NoError(t, os.WriteFile(probePath, []byte("ok"), 0600))
	probeInfo, err := os.Stat(probePath)
	require.NoError(t, err)
	require.Greater(t, probeInfo.Size(), int64(0),
		"前置條件：探測檔須非空，否則『排除』與『計入 0 bytes』無法區分")

	stats, err := service.GetRecordingStats()
	require.NoError(t, err)

	assert.Equal(t, 1, stats.Count, "進行中錄影應計入、探測檔應排除")
	assert.Equal(t, int64(2048), stats.TotalSize)
}

func TestRecordingService_DeleteRecording(t *testing.T) {
	service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
	defer cleanup()

	t.Run("成功刪除錄製檔案", func(t *testing.T) {
		// 創建測試檔案
		filePath := createTestRecordingFile(t, tmpDir, 20, "2025-10-20")

		// Mock SELECT query
		rows := sqlmock.NewRows([]string{"id", "recording_path", "has_recording", "recording_size"}).
			AddRow(20, filePath, true, 1024)

		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(20, sqlmock.AnyArg()).
			WillReturnRows(rows)

		// Mock UPDATE query：GORM map update 字母序為 has_recording, recording_path, recording_size, updated_at
		// WHERE id = 20（不含 deleted_at，實際 5 個參數）
		mock.ExpectBegin()
		mock.ExpectExec(`UPDATE "sessions"`).
			WithArgs(false, "", int64(0), sqlmock.AnyArg(), 20).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		// 驗證檔案存在
		_, err := os.Stat(filePath)
		assert.NoError(t, err)

		// 刪除錄製
		err = service.DeleteRecording(20)
		assert.NoError(t, err)

		// 驗證檔案已刪除
		_, err = os.Stat(filePath)
		assert.True(t, os.IsNotExist(err))

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Session 不存在", func(t *testing.T) {
		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(9999, sqlmock.AnyArg()).
			WillReturnError(gorm.ErrRecordNotFound)

		err := service.DeleteRecording(9999)
		assert.ErrorIs(t, err, ErrSessionNotFound)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Session 沒有錄製檔案", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "recording_path", "has_recording"}).
			AddRow(21, "", false)

		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(21, sqlmock.AnyArg()).
			WillReturnRows(rows)

		err := service.DeleteRecording(21)
		assert.ErrorIs(t, err, ErrSessionHasNoRecording)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRecordingService_CleanupOldRecordings(t *testing.T) {
	service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
	defer cleanup()

	t.Run("清理超過保留期的檔案", func(t *testing.T) {
		// 創建新檔案（應保留）
		newFile := createTestRecordingFile(t, tmpDir, 30, "2025-10-20")

		// 創建舊檔案（應刪除）- 修改檔案時間
		oldFile := createTestRecordingFile(t, tmpDir, 31, "2025-10-01")

		// 修改舊檔案的時間戳為 100 天前
		oldTime := time.Now().AddDate(0, 0, -100)
		os.Chtimes(oldFile, oldTime, oldTime)

		// Mock UPDATE for old session（clearRecordingInDB 用 Where(recording_path) + Updates map）
		// GORM map update 字母序：has_recording, recording_path, recording_size, updated_at
		// WHERE recording_path = oldFile（實際 5 個參數，無 deleted_at）
		mock.ExpectBegin()
		mock.ExpectExec(`UPDATE "sessions"`).
			WithArgs(false, "", int64(0), sqlmock.AnyArg(), oldFile).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// 清理 90 天前的檔案
		deletedCount, err := service.CleanupOldRecordings(90)
		assert.NoError(t, err)
		assert.Equal(t, 1, deletedCount)

		// 驗證新檔案仍存在
		_, err = os.Stat(newFile)
		assert.NoError(t, err)

		// 驗證舊檔案已刪除
		_, err = os.Stat(oldFile)
		assert.True(t, os.IsNotExist(err))

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("保留天數必須大於 0", func(t *testing.T) {
		_, err := service.CleanupOldRecordings(0)
		assert.Error(t, err)

		_, err = service.CleanupOldRecordings(-1)
		assert.Error(t, err)
	})

	t.Run("沒有舊檔案時返回 0", func(t *testing.T) {
		// 創建新檔案（不會被刪除）
		createTestRecordingFile(t, tmpDir, 40, "2025-10-20")

		deletedCount, err := service.CleanupOldRecordings(90)
		assert.NoError(t, err)
		assert.Equal(t, 0, deletedCount)
		// 沒有 mock 期望因為沒有檔案被刪除
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// writeRecordingFileWithAge 在 path 寫入 size bytes 並把 mtime 釘在 age 之前，
// 回傳釘好的 mtime。用於構造「過期／未過期」兩態。
func writeRecordingFileWithAge(t *testing.T, path string, size int, age time.Duration) time.Time {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, make([]byte, size), 0600))
	stamp := time.Now().Add(-age)
	require.NoError(t, os.Chtimes(path, stamp, stamp))
	return stamp
}

// requireExpired 前置條件：檔案確實存在，且 mtime 確實早於 retentionDays 的截止日。
// 不釘死這兩點，下面「被刪掉了」的斷言可能只是因為檔案根本沒建起來（恆真式假綠）。
func requireExpired(t *testing.T, path string, retentionDays int) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err, "前置條件：待清理的檔案必須存在")
	require.True(t, info.ModTime().Before(time.Now().AddDate(0, 0, -retentionDays)),
		"前置條件：%s 的 mtime 必須早於截止日，否則測不到清理路徑", path)
}

// requireNotExpired 前置條件：檔案存在且 mtime 未過期——「不該被刪」的斷言若少了
// 這一條，就分不清是判準保護了它，還是它本來就在截止日之後。
func requireNotExpired(t *testing.T, path string, retentionDays int) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err, "前置條件：檔案必須存在")
	require.False(t, info.ModTime().Before(time.Now().AddDate(0, 0, -retentionDays)),
		"前置條件：%s 的 mtime 不得早於截止日", path)
}

// expectClearRecordingUpdate 掛上 clearRecordingInDB 對應的 UPDATE 期望。
// WHERE 條件用**精確路徑**比對，正是本測試要釘的東西：清理孤兒檔時這道 UPDATE
// 只能命中 recording_path 等於該孤兒路徑的列（實際為 0 列），不會波及其他 session。
func expectClearRecordingUpdate(mock sqlmock.Sqlmock, path string, rowsAffected int64) {
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "sessions"`).
		WithArgs(false, "", int64(0), sqlmock.AnyArg(), path).
		WillReturnResult(sqlmock.NewResult(0, rowsAffected))
	mock.ExpectCommit()
}

// TestRecordingService_CleanupOldRecordings_CoversAllRecordingKinds 守衛「保留期清理
// 只刪 .cast」的回歸。
//
// 舊實作以 filepath.Ext(path) != ".cast" 過濾，兩類檔案因此永不被清理：
//   - 圖形協議的 .guac（basePath 根層，實測單檔 188KB vs 文字錄影 1KB 級）——
//     90 天保留政策（PCI 10.5.1）對圖形錄影形同沒設，磁碟只增不減。
//   - 會話中斷留下的無副檔名孤兒檔（guacd 寫 rdp-<nanos>，後端在會話結束才更名為
//     session-N.guac；崩潰／更名失敗就永遠停在無副檔名狀態，產品端再也讀不到）。
//
// 判準改為與統計端同一條「排除隱藏檔與非常規檔」，安全性全數由 mtime 承擔。
func TestRecordingService_CleanupOldRecordings_CoversAllRecordingKinds(t *testing.T) {
	const retentionDays = 90

	t.Run("過期的圖形錄影會被刪除且 DB 欄位被清空", func(t *testing.T) {
		service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
		defer cleanup()

		// 圖形錄影落在 basePath 根層、無日期子目錄（見 internal/proxy/handler.go）
		guacPath := filepath.Join(tmpDir, "session-33.guac")
		writeRecordingFileWithAge(t, guacPath, 4096, 100*24*time.Hour)
		requireExpired(t, guacPath, retentionDays)
		require.NotEqual(t, ".cast", filepath.Ext(guacPath),
			"前置條件：本檔必須落在舊白名單之外，否則測不到缺陷")

		// clearRecordingInDB 以完整路徑比對——.guac 路徑同樣是 DB 內存的那一串
		// （handler 以 basePath + "/session-N.guac" 寫入 recording_path）
		expectClearRecordingUpdate(mock, guacPath, 1)

		deleted, err := service.CleanupOldRecordings(retentionDays)
		require.NoError(t, err)
		assert.Equal(t, 1, deleted)

		_, statErr := os.Stat(guacPath)
		assert.True(t, os.IsNotExist(statErr), "過期的圖形錄影未被刪除")
		assert.NoError(t, mock.ExpectationsWereMet(), "DB 的錄影欄位未被清空")
	})

	t.Run("過期的文字錄影仍會被刪除（既有行為不回歸）", func(t *testing.T) {
		service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
		defer cleanup()

		castPath := filepath.Join(tmpDir, "2025-10-01", "session-31.cast")
		writeRecordingFileWithAge(t, castPath, 512, 100*24*time.Hour)
		requireExpired(t, castPath, retentionDays)

		expectClearRecordingUpdate(mock, castPath, 1)

		deleted, err := service.CleanupOldRecordings(retentionDays)
		require.NoError(t, err)
		assert.Equal(t, 1, deleted)

		_, statErr := os.Stat(castPath)
		assert.True(t, os.IsNotExist(statErr), "過期的文字錄影未被刪除")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("中斷留下的孤兒檔會被清理且不誤動其他 session", func(t *testing.T) {
		service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
		defer cleanup()

		// guacd 進行中的檔名形態：<protocol>-<nanos>，無副檔名。後端崩潰／更名失敗
		// 就停在這個狀態；DB 記的是更名後的路徑，故產品端讀不到它，純粹佔磁碟。
		orphanPath := filepath.Join(tmpDir, "rdp-1755123456789000000")
		writeRecordingFileWithAge(t, orphanPath, 8192, 100*24*time.Hour)
		requireExpired(t, orphanPath, retentionDays)
		require.Empty(t, filepath.Ext(orphanPath),
			"前置條件：孤兒檔必須無副檔名，否則測不到白名單的漏洞")

		// 孤兒檔沒有對應的 recording_path，UPDATE 命中 0 列（rowsAffected=0）——
		// 期望的 WHERE 參數即孤兒路徑本身，證明它不可能命中別的 session 的列
		expectClearRecordingUpdate(mock, orphanPath, 0)

		deleted, err := service.CleanupOldRecordings(retentionDays)
		require.NoError(t, err)
		assert.Equal(t, 1, deleted)

		_, statErr := os.Stat(orphanPath)
		assert.True(t, os.IsNotExist(statErr), "孤兒檔未被清理，空間洩漏仍在")
		assert.NoError(t, mock.ExpectationsWereMet(),
			"清理孤兒檔時發出的 UPDATE 不是以該孤兒路徑為 WHERE 條件")
	})

	t.Run("進行中的錄影（mtime 未過期）不刪", func(t *testing.T) {
		service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
		defer cleanup()

		// 判準改為排除法之後，**mtime 是進行中錄影的唯一防線**：檔案每次寫入都會
		// 刷新 mtime，故進行中者恆不早於截止日。這條測試守的就是那道防線——若有人
		// 把時間判準改寬（例如改用 ctime、或把 Before 寫成 After），此處立刻轉紅。
		inProgress := filepath.Join(tmpDir, "rdp-1755999999999000000")
		writeRecordingFileWithAge(t, inProgress, 2048, time.Hour)
		requireNotExpired(t, inProgress, retentionDays)
		require.Empty(t, filepath.Ext(inProgress))

		deleted, err := service.CleanupOldRecordings(retentionDays)
		require.NoError(t, err)
		assert.Equal(t, 0, deleted)

		_, statErr := os.Stat(inProgress)
		assert.NoError(t, statErr, "進行中的錄影被刪除了")
		assert.NoError(t, mock.ExpectationsWereMet(), "不該有任何 DB 寫入")
	})

	t.Run("未過期的錄影一律不刪", func(t *testing.T) {
		service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
		defer cleanup()

		castPath := filepath.Join(tmpDir, "2025-10-20", "session-30.cast")
		writeRecordingFileWithAge(t, castPath, 512, 24*time.Hour)
		guacPath := filepath.Join(tmpDir, "session-34.guac")
		writeRecordingFileWithAge(t, guacPath, 4096, 24*time.Hour)
		requireNotExpired(t, castPath, retentionDays)
		requireNotExpired(t, guacPath, retentionDays)

		deleted, err := service.CleanupOldRecordings(retentionDays)
		require.NoError(t, err)
		assert.Equal(t, 0, deleted)

		_, err = os.Stat(castPath)
		assert.NoError(t, err, "未過期的文字錄影被刪除了")
		_, err = os.Stat(guacPath)
		assert.NoError(t, err, "未過期的圖形錄影被刪除了")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("探測檔即使過期也不刪", func(t *testing.T) {
		service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
		defer cleanup()

		// recorder.ProbeWritable 在當日子目錄建 `.probe-*`（正常即刻刪除，行程被砍
		// 時可能殘留）。它不是錄影，隱藏檔規則把它擋在刪除集合之外。
		probePath := filepath.Join(tmpDir, "2025-10-01", ".probe-abc123")
		writeRecordingFileWithAge(t, probePath, 2, 100*24*time.Hour)
		requireExpired(t, probePath, retentionDays)

		deleted, err := service.CleanupOldRecordings(retentionDays)
		require.NoError(t, err)
		assert.Equal(t, 0, deleted)

		_, statErr := os.Stat(probePath)
		assert.NoError(t, statErr, "探測檔被當成錄影刪掉了")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRecordingService_GetRecordingMetadata(t *testing.T) {
	service, tmpDir, _, mock, cleanup := setupTestRecordingService(t)
	defer cleanup()

	t.Run("成功獲取元數據", func(t *testing.T) {
		// 創建測試檔案
		filePath := createTestRecordingFile(t, tmpDir, 50, "2025-10-20")

		// Mock session query with preloads
		sessionRows := sqlmock.NewRows([]string{
			"id", "session_id", "protocol", "user_id", "asset_id", "client_ip",
			"start_time", "duration", "recording_path", "recording_size", "has_recording",
		}).AddRow(
			50, "test-session-50", model.ProtocolSSH, sql.NullInt64{}, sql.NullInt64{}, "127.0.0.1",
			time.Now().Add(-1*time.Hour), 3600, filePath, 1024, true,
		)

		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(50, sqlmock.AnyArg()).
			WillReturnRows(sessionRows)

		// 獲取元數據（不測試 User 和 Asset 關聯，因為設為 NULL）
		metadata, err := service.GetRecordingMetadata(50)
		assert.NoError(t, err)
		assert.NotNil(t, metadata)
		assert.Equal(t, uint(50), metadata.SessionID)
		assert.Equal(t, filePath, metadata.FilePath)
		assert.Greater(t, metadata.FileSize, int64(0))
		assert.Equal(t, 3600, metadata.Duration)
		assert.Equal(t, "ssh", metadata.Protocol)

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Session 不存在", func(t *testing.T) {
		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(9999, sqlmock.AnyArg()).
			WillReturnError(gorm.ErrRecordNotFound)

		_, err := service.GetRecordingMetadata(9999)
		assert.ErrorIs(t, err, ErrSessionNotFound)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Session 沒有錄製檔案", func(t *testing.T) {
		sessionRows := sqlmock.NewRows([]string{"id", "recording_path", "has_recording"}).
			AddRow(51, "", false)

		mock.ExpectQuery(`SELECT \* FROM "sessions"`).
			WithArgs(51, sqlmock.AnyArg()).
			WillReturnRows(sessionRows)

		_, err := service.GetRecordingMetadata(51)
		assert.ErrorIs(t, err, ErrSessionHasNoRecording)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRecordingService_ConcurrentAccess(t *testing.T) {
	service, tmpDir, _, _, cleanup := setupTestRecordingService(t)
	defer cleanup()

	// 創建多個測試檔案
	for i := 70; i < 75; i++ {
		createTestRecordingFile(t, tmpDir, uint(i), "2025-10-20")
	}

	t.Run("並發讀取統計", func(t *testing.T) {
		done := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func() {
				stats, err := service.GetRecordingStats()
				assert.NoError(t, err)
				assert.Equal(t, 5, stats.Count)
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}
