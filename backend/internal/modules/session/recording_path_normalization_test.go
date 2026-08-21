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
	"github.com/custodexa/backend/internal/recorder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// setupRecordingServiceWithBase 與 setupTestRecordingService 同構，但由呼叫端指定
// basePath（本檔要餵的正是「未正規化」的形態），且不代建臨時目錄。
func setupRecordingServiceWithBase(t *testing.T, basePath string) (*RecordingService, *sql.DB, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	gormDB, err := gorm.Open(postgres.New(postgres.Config{Conn: db}), &gorm.Config{})
	require.NoError(t, err)

	oldDB := database.DB
	database.DB = gormDB

	service := NewRecordingService(basePath)

	cleanup := func() {
		database.DB = oldDB
		db.Close()
	}
	return service, db, mock, cleanup
}

// walkedFiles 回傳 CleanupOldRecordings 實際會拿去比對 DB 的那組路徑：
// 同一個 filepath.Walk、同一個根，而不是在測試裡再算一次 Join。
func walkedFiles(t *testing.T, root string) []string {
	t.Helper()
	var got []string
	require.NoError(t, filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if !info.IsDir() {
			got = append(got, p)
		}
		return nil
	}))
	return got
}

// TestRecordingPath_TrailingSlashBaseKeepsDBAndWalkInSync 釘住路徑正規化不一致造成的
// 「產品顯示與實際狀態不一致」。
//
// 缺陷形態：圖形協議錄影的落檔路徑原本以字串拼接組出，見 internal/proxy/handler.go 的
// `fmt.Sprintf("%s/session-%d.guac", basePath, id)`——
// 運維只要把 RECORDING_PATH 設成帶尾斜線的目錄，存進 sessions.recording_path 的就是
// 帶雙斜線的字串；而保留期清理走 filepath.Walk，產出的是 clean 路徑。於是
//   - 檔案刪得掉（Walk 那條路）；
//   - clearRecordingInDB 的 `WHERE recording_path = ?` 精確比對命不中，DB 欄位清不掉；
//   - 該會話在 UI 上仍顯示「可回放」，點下去檔案早已不存在，且沒有任何錯誤訊號。
//
// 兩個注入點都要守：讀 RECORDING_PATH 的那條（生產路徑）與建構子直接注入的那條。
func TestRecordingPath_TrailingSlashBaseKeepsDBAndWalkInSync(t *testing.T) {
	t.Run("RECORDING_PATH 帶尾斜線（env 讀取點）", func(t *testing.T) {
		tmpDir := t.TempDir()
		rawBase := tmpDir + "/"
		t.Setenv("RECORDING_PATH", rawBase)

		service, _, mock, cleanup := setupRecordingServiceWithBase(t, "")
		defer cleanup()

		assertGraphicsCleanupClearsDB(t, service, mock, rawBase)
	})

	t.Run("建構子注入帶尾斜線的 basePath", func(t *testing.T) {
		tmpDir := t.TempDir()
		rawBase := tmpDir + "/"
		// env 刻意指向別處，證明走的是注入值
		t.Setenv("RECORDING_PATH", t.TempDir())

		service, _, mock, cleanup := setupRecordingServiceWithBase(t, rawBase)
		defer cleanup()

		assertGraphicsCleanupClearsDB(t, service, mock, rawBase)
	})
}

func assertGraphicsCleanupClearsDB(t *testing.T, service *RecordingService, mock sqlmock.Sqlmock, rawBase string) {
	t.Helper()
	const retentionDays = 90
	const sessionID = uint(77)

	// 前置條件只用標準庫描述**夾具**：這個 rawBase 下拼接與正規化必然分歧。
	// 刻意不拿受測程式的輸出當前置條件——那會讓「改回拼接」在前置條件處就中止，
	// 底下真正的斷言反而永遠跑不到。
	naive := fmt.Sprintf("%s/session-%d.guac", rawBase, sessionID)
	want := filepath.Join(filepath.Clean(rawBase), fmt.Sprintf("session-%d.guac", sessionID))
	require.NotEqual(t, naive, want,
		"前置條件：rawBase 必須是會讓拼接與 Join 分歧的形態，否則測不到缺陷")

	// dbPath＝寫入端（internal/proxy/handler.go 會後更名）存進 recording_path 的字串
	dbPath := recorder.GraphicsRecordingPath(rawBase, sessionID)
	require.Equal(t, want, dbPath, "寫入端組出的路徑未正規化")

	writeRecordingFileWithAge(t, dbPath, 4096, 100*24*time.Hour)
	requireExpired(t, dbPath, retentionDays)

	// 前置條件 2：清理端 Walk（以服務自己的根遍歷）看到的路徑必須與寫入端逐字相同。
	// 這一條就是缺陷本體；同時反證拼接版本對不上 Walk。
	walked := walkedFiles(t, service.basePath)
	require.Equal(t, []string{dbPath}, walked,
		"寫入 DB 的路徑與 filepath.Walk 產出不一致——clearRecordingInDB 將永遠命不中")
	require.NotEqual(t, naive, walked[0],
		"夾具失效：拼接版本若也對得上 Walk，本測試證明不了任何事")

	// clearRecordingInDB 只能以那一串精確路徑為 WHERE 條件，且必須命中該列
	expectClearRecordingUpdate(mock, dbPath, 1)

	deleted, err := service.CleanupOldRecordings(retentionDays)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)

	_, statErr := os.Stat(dbPath)
	assert.True(t, os.IsNotExist(statErr), "過期的圖形錄影未被刪除")
	assert.NoError(t, mock.ExpectationsWereMet(),
		"DB 的 recording_path 未被清空——UI 會留下『可回放』但檔案已不存在的死列")
}
