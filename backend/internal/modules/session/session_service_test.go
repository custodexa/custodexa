package session

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// MockConnectionRegistry 模擬的 ConnectionRegistry
type MockConnectionRegistry struct {
	closeFunc func(sessionID uint) error
	callCount int
}

func (m *MockConnectionRegistry) Close(sessionID uint) error {
	m.callCount++
	if m.closeFunc != nil {
		return m.closeFunc(sessionID)
	}
	return nil
}

// setupMockDB 建立測試用的 mock 資料庫
func setupMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *gorm.DB) {
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

// TestNewSessionService 測試創建 SessionService
func TestNewSessionService(t *testing.T) {
	tests := []struct {
		name     string
		registry ConnectionRegistry
	}{
		{"With registry", &MockConnectionRegistry{}},
		{"Without registry", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewSessionService(tt.registry)
			assert.NotNil(t, service)
			assert.Equal(t, tt.registry, service.registry)
		})
	}
}

// TestCreateSession 測試創建 Session
func TestCreateSession(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	now := time.Now()
	session := &model.Session{
		UserID:    1,
		Protocol:  model.ProtocolSSH,
		ClientIP:  "192.168.1.100",
		StartTime: now,
	}

	// 模擬資料庫插入
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "sessions"`).
		WithArgs(
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
			sqlmock.AnyArg(), // deleted_at
			sqlmock.AnyArg(), // session_id
			model.SessionStatusActive,
			model.ProtocolSSH,
			uint(1),
			sqlmock.AnyArg(), // asset_id
			"192.168.1.100",
			now,
			sqlmock.AnyArg(), // end_time
			0,                // duration
			"normal",         // end_reason
			"",               // recording_path
			int64(0),         // recording_size
			false,            // has_recording
			"",               // recording_error
			sqlmock.AnyArg(), // recording_started_at（workbench-exits-and-export D2 回放時間原點；建檔時為 NULL）
			uint(0),          // account_id（asset-multi-account D7 帳號雙快照）
			"",               // account_username
			sqlmock.AnyArg(), // auth_provider_id（idp-oidc-integration 1.9 認證溯源；本地登入為 NULL）
			0,                // auth_epoch
			"",               // k8s_namespace
			"",               // k8s_pod
			"",               // k8s_pod_uid
			"",               // k8s_container
			"",               // k8s_image
			"",               // k8s_node
		).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectCommit()

	err := service.Create(session)
	assert.NoError(t, err)
	assert.NotEmpty(t, session.SessionID)
	assert.Equal(t, model.SessionStatusActive, session.Status)

	// 驗證所有期望都已滿足
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCreateSession_AutoGenerateSessionID 測試自動生成 SessionID
func TestCreateSession_AutoGenerateSessionID(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	session := &model.Session{
		UserID:   1,
		Protocol: model.ProtocolSSH,
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "sessions"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectCommit()

	err := service.Create(session)
	assert.NoError(t, err)
	assert.NotEmpty(t, session.SessionID)
	assert.Contains(t, session.SessionID, "sess_")
}

// TestCreateSession_AutoSetStatus 測試自動設定狀態
func TestCreateSession_AutoSetStatus(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	session := &model.Session{
		UserID:   1,
		Protocol: model.ProtocolRDP,
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "sessions"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectCommit()

	err := service.Create(session)
	assert.NoError(t, err)
	assert.Equal(t, model.SessionStatusActive, session.Status)
	assert.False(t, session.StartTime.IsZero())
}

// TestGetByID 測試根據 ID 查詢 Session
func TestGetByID(t *testing.T) {
	tests := []struct {
		name      string
		id        uint
		setupMock func(sqlmock.Sqlmock)
		wantErr   error
		wantID    uint
	}{
		{
			name: "Session exists",
			id:   1,
			setupMock: func(mock sqlmock.Sqlmock) {
				assetID := uint(10)
				rows := sqlmock.NewRows([]string{"id", "session_id", "status", "protocol", "user_id", "asset_id", "client_ip"}).
					AddRow(1, "sess_123", model.SessionStatusActive, model.ProtocolSSH, 1, assetID, "192.168.1.1")
				// GORM First 會添加 LIMIT，不指定 WithArgs
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnRows(rows)

				// GORM Preload 順序依關聯欄位值決定：asset_id(10) 先查，user_id(1) 後查
				// Preload Asset（asset_id 有值，先執行）
				assetRows := sqlmock.NewRows([]string{"id", "name"}).
					AddRow(assetID, "test-asset")
				mock.ExpectQuery(`SELECT .+ FROM "assets"`).
					WillReturnRows(assetRows)

				// Preload User（user_id 有值，後執行）
				userRows := sqlmock.NewRows([]string{"id", "username"}).
					AddRow(1, "testuser")
				mock.ExpectQuery(`SELECT .+ FROM "users"`).
					WillReturnRows(userRows)
			},
			wantErr: nil,
			wantID:  1,
		},
		{
			name: "Session not found",
			id:   999,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnError(gorm.ErrRecordNotFound)
			},
			wantErr: ErrSessionNotFound,
			wantID:  0,
		},
		{
			name: "Database error",
			id:   1,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnError(errors.New("db error"))
			},
			wantErr: errors.New("db error"),
			wantID:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mock, _ := setupMockDB(t)
			service := NewSessionService(nil)

			tt.setupMock(mock)

			session, err := service.GetByID(tt.id)

			if tt.wantErr != nil {
				assert.Error(t, err)
				if tt.wantErr == ErrSessionNotFound {
					assert.Equal(t, ErrSessionNotFound, err)
				}
			} else {
				assert.NoError(t, err)
				if assert.NotNil(t, session) {
					assert.Equal(t, tt.wantID, session.ID)
				}
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestGetBySessionID 測試根據 SessionID 查詢
func TestGetBySessionID(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	sessionID := "sess_123"

	rows := sqlmock.NewRows([]string{"id", "session_id", "status", "protocol", "user_id"}).
		AddRow(1, sessionID, model.SessionStatusActive, model.ProtocolSSH, 1)
	// GORM 的 First 會添加 LIMIT 1
	mock.ExpectQuery(`SELECT .+ FROM "sessions" WHERE session_id`).
		WillReturnRows(rows)

	// Preload
	mock.ExpectQuery(`SELECT .+ FROM "users"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT .+ FROM "assets"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))

	session, err := service.GetBySessionID(sessionID)
	assert.NoError(t, err)
	if assert.NotNil(t, session) {
		assert.Equal(t, sessionID, session.SessionID)
	}
}

// TestList 測試列表查詢
func TestList(t *testing.T) {
	tests := []struct {
		name      string
		filter    *SessionFilter
		setupMock func(sqlmock.Sqlmock)
		wantTotal int64
		wantPage  int
		wantSize  int
		wantErr   bool
	}{
		{
			name: "Default pagination",
			filter: &SessionFilter{
				Page:     1,
				PageSize: 20,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Count query
				mock.ExpectQuery(`SELECT count\(\*\) FROM "sessions"`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

				// Data query - mock 列的 user_id/asset_id 為零值，GORM 跳過 Preload
				rows := sqlmock.NewRows([]string{"id", "session_id", "status", "protocol", "user_id"}).
					AddRow(1, "sess_1", model.SessionStatusActive, model.ProtocolSSH, 1).
					AddRow(2, "sess_2", model.SessionStatusClosed, model.ProtocolRDP, 1)
				mock.ExpectQuery(`SELECT .+ FROM "sessions" .+ ORDER BY start_time DESC LIMIT`).
					WillReturnRows(rows)

				// user_id=1（非零值）會觸發 Preload users，但 asset_id 零值跳過 Preload assets
				mock.ExpectQuery(`SELECT .+ FROM "users"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
			},
			wantTotal: 5,
			wantPage:  1,
			wantSize:  20,
			wantErr:   false,
		},
		{
			name: "Filter by protocol",
			filter: &SessionFilter{
				Protocol: model.ProtocolSSH,
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT count\(\*\) FROM "sessions" WHERE protocol`).
					WithArgs(model.ProtocolSSH).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

				// mock 列不含 user_id/asset_id，GORM 跳過所有 Preload
				rows := sqlmock.NewRows([]string{"id", "protocol"}).
					AddRow(1, model.ProtocolSSH)
				mock.ExpectQuery(`SELECT .+ FROM "sessions" WHERE protocol .+ LIMIT`).
					WillReturnRows(rows)
			},
			wantTotal: 3,
			wantPage:  1,
			wantSize:  10,
			wantErr:   false,
		},
		{
			name: "Filter by status",
			filter: &SessionFilter{
				Status:   model.SessionStatusActive,
				Page:     1,
				PageSize: 20,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT count\(\*\) FROM "sessions" WHERE status`).
					WithArgs(model.SessionStatusActive).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

				// mock 列不含 user_id/asset_id，GORM 跳過所有 Preload
				rows := sqlmock.NewRows([]string{"id", "status"}).
					AddRow(1, model.SessionStatusActive)
				mock.ExpectQuery(`SELECT .+ FROM "sessions" WHERE status .+ LIMIT`).
					WillReturnRows(rows)
			},
			wantTotal: 2,
			wantPage:  1,
			wantSize:  20,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mock, _ := setupMockDB(t)
			service := NewSessionService(nil)

			tt.setupMock(mock)

			result, err := service.List(tt.filter)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.wantTotal, result.Total)
				assert.Equal(t, tt.wantPage, result.Page)
				assert.Equal(t, tt.wantSize, result.PageSize)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestList_FilterByUserID 測試按使用者過濾
func TestList_FilterByUserID(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	userID := uint(5)
	filter := &SessionFilter{
		UserID:   &userID,
		Page:     1,
		PageSize: 20,
	}

	mock.ExpectQuery(`SELECT count\(\*\) FROM "sessions" WHERE user_id`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	rows := sqlmock.NewRows([]string{"id", "user_id"}).
		AddRow(1, userID)
	mock.ExpectQuery(`SELECT .+ FROM "sessions" WHERE user_id`).
		WillReturnRows(rows)

	mock.ExpectQuery(`SELECT .+ FROM "users"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT .+ FROM "assets"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))

	result, err := service.List(filter)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
}

// TestList_FilterByTimeRange 測試按時間範圍過濾
func TestList_FilterByTimeRange(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	startTime := time.Now().Add(-24 * time.Hour)
	endTime := time.Now()
	filter := &SessionFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
		Page:      1,
		PageSize:  20,
	}

	mock.ExpectQuery(`SELECT count\(\*\) FROM "sessions" WHERE start_time >= .+ AND start_time <=`).
		WithArgs(startTime, endTime).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	rows := sqlmock.NewRows([]string{"id"}).AddRow(1)
	mock.ExpectQuery(`SELECT .+ FROM "sessions" WHERE start_time`).
		WillReturnRows(rows)

	mock.ExpectQuery(`SELECT .+ FROM "users"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT .+ FROM "assets"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))

	result, err := service.List(filter)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), result.Total)
}

// TestGetActiveSessions 測試查詢活動 Session
func TestGetActiveSessions(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	rows := sqlmock.NewRows([]string{"id", "status"}).
		AddRow(1, model.SessionStatusActive).
		AddRow(2, model.SessionStatusActive)

	// GORM 會為 deleted_at 添加額外的參數
	mock.ExpectQuery(`SELECT .+ FROM "sessions" WHERE status`).
		WithArgs(model.SessionStatusActive).
		WillReturnRows(rows)

	// Preload
	mock.ExpectQuery(`SELECT .+ FROM "users"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT .+ FROM "assets"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))

	sessions, err := service.GetActiveSessions()
	assert.NoError(t, err)
	assert.Len(t, sessions, 2)
}

// TestClose 測試關閉 Session
func TestClose(t *testing.T) {
	tests := []struct {
		name      string
		sessionID uint
		setupMock func(sqlmock.Sqlmock)
		wantErr   error
	}{
		{
			name:      "Close active session",
			sessionID: 1,
			setupMock: func(mock sqlmock.Sqlmock) {
				// GetByID：GORM First(id) 傳 id + limit 兩個參數，不指定 WithArgs
				rows := sqlmock.NewRows([]string{"id", "status", "start_time"}).
					AddRow(1, model.SessionStatusActive, time.Now().Add(-1*time.Hour))
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnRows(rows)
				// mock 列不含 user_id/asset_id（零值），GORM 跳過 Preload

				// Update：GORM 對 struct 欄位依字母序排列：duration, end_time, status, updated_at；
				// CAS 加 WHERE status=active（codex #2），末尾多帶 status arg
				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE "sessions" SET`).
					WithArgs(
						sqlmock.AnyArg(),          // duration
						sqlmock.AnyArg(),          // end_time
						model.SessionStatusClosed, // status (SET)
						sqlmock.AnyArg(),          // updated_at
						1,                         // id (WHERE)
						model.SessionStatusActive, // status (WHERE CAS)
					).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
			},
			wantErr: nil,
		},
		{
			name:      "Session not found",
			sessionID: 999,
			setupMock: func(mock sqlmock.Sqlmock) {
				// GORM First(id) 傳 id + limit 兩個參數，不指定 WithArgs
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnError(gorm.ErrRecordNotFound)
			},
			wantErr: ErrSessionNotFound,
		},
		{
			name:      "Session already closed",
			sessionID: 1,
			setupMock: func(mock sqlmock.Sqlmock) {
				// GORM First(id) 傳 id + limit 兩個參數，不指定 WithArgs
				rows := sqlmock.NewRows([]string{"id", "status", "start_time"}).
					AddRow(1, model.SessionStatusClosed, time.Now().Add(-1*time.Hour))
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnRows(rows)
				// CAS status=active（codex #2）：已終態列 RowsAffected=0，冪等回
				// ErrSessionAlreadyClosed，不覆寫終態
				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE "sessions" SET`).
					WithArgs(
						sqlmock.AnyArg(),          // duration
						sqlmock.AnyArg(),          // end_time
						model.SessionStatusClosed, // status (SET)
						sqlmock.AnyArg(),          // updated_at
						1,                         // id (WHERE)
						model.SessionStatusActive, // status (WHERE CAS)
					).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectCommit()
			},
			wantErr: ErrSessionAlreadyClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mock, _ := setupMockDB(t)
			service := NewSessionService(nil)

			tt.setupMock(mock)

			err := service.Close(tt.sessionID)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestTerminate 測試強制終止 Session
func TestTerminate(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     uint
		registry      ConnectionRegistry // 使用介面型別，避免 (*MockConnectionRegistry)(nil) typed-nil 問題
		setupMock     func(sqlmock.Sqlmock)
		wantErr       error
		wantCallCount int
	}{
		{
			name:      "Terminate with registry - success",
			sessionID: 1,
			registry: &MockConnectionRegistry{
				closeFunc: func(sessionID uint) error {
					return nil
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// GetByID：GORM First(id) 傳 id + limit 兩個參數，不指定 WithArgs
				// mock 列不含 user_id/asset_id（零值），GORM 跳過 Preload
				rows := sqlmock.NewRows([]string{"id", "status", "start_time"}).
					AddRow(1, model.SessionStatusActive, time.Now().Add(-1*time.Hour))
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnRows(rows)

				// Update：GORM 欄位字母序 duration, end_reason, end_time, status, updated_at；
				// CAS 守衛（F1）在 WHERE 追加 id, status=active
				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE "sessions" SET`).
					WithArgs(
						sqlmock.AnyArg(),                // duration
						model.EndReasonAdminTerminate,   // end_reason（1.2：admin 終止實際落 DB）
						sqlmock.AnyArg(),                // end_time
						model.SessionStatusDisconnected, // status (SET)
						sqlmock.AnyArg(),                // updated_at
						1,                               // WHERE id
						model.SessionStatusActive,       // WHERE status（CAS 守衛）
					).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
			},
			wantErr:       nil,
			wantCallCount: 1,
		},
		{
			name:      "Terminate with registry - registry error (still success)",
			sessionID: 1,
			registry: &MockConnectionRegistry{
				closeFunc: func(sessionID uint) error {
					return errors.New("websocket close error")
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// GORM First(id) 傳 id + limit 兩個參數，不指定 WithArgs
				// mock 列不含 user_id/asset_id（零值），GORM 跳過 Preload
				rows := sqlmock.NewRows([]string{"id", "status", "start_time"}).
					AddRow(1, model.SessionStatusActive, time.Now().Add(-1*time.Hour))
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnRows(rows)

				// Update：GORM 欄位字母序 duration, end_reason, end_time, status, updated_at；
				// CAS 守衛（F1）在 WHERE 追加 id, status=active
				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE "sessions" SET`).
					WithArgs(
						sqlmock.AnyArg(),                // duration
						model.EndReasonAdminTerminate,   // end_reason（1.2：admin 終止實際落 DB）
						sqlmock.AnyArg(),                // end_time
						model.SessionStatusDisconnected, // status (SET)
						sqlmock.AnyArg(),                // updated_at
						1,                               // WHERE id
						model.SessionStatusActive,       // WHERE status（CAS 守衛）
					).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
			},
			wantErr:       nil, // 雖然 WebSocket 關閉失敗，但資料庫更新成功，不應返回錯誤
			wantCallCount: 1,
		},
		{
			name:      "Terminate without registry",
			sessionID: 1,
			registry:  nil,
			setupMock: func(mock sqlmock.Sqlmock) {
				// GORM First(id) 傳 id + limit 兩個參數，不指定 WithArgs
				// mock 列不含 user_id/asset_id（零值），GORM 跳過 Preload
				rows := sqlmock.NewRows([]string{"id", "status", "start_time"}).
					AddRow(1, model.SessionStatusActive, time.Now().Add(-1*time.Hour))
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnRows(rows)

				// Update：GORM 欄位字母序 duration, end_reason, end_time, status, updated_at；
				// CAS 守衛（F1）在 WHERE 追加 id, status=active
				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE "sessions" SET`).
					WithArgs(
						sqlmock.AnyArg(),                // duration
						model.EndReasonAdminTerminate,   // end_reason（1.2：admin 終止實際落 DB）
						sqlmock.AnyArg(),                // end_time
						model.SessionStatusDisconnected, // status (SET)
						sqlmock.AnyArg(),                // updated_at
						1,                               // WHERE id
						model.SessionStatusActive,       // WHERE status（CAS 守衛）
					).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
			},
			wantErr:       nil,
			wantCallCount: 0, // registry 是 nil，不會被調用
		},
		{
			name:      "Session not found",
			sessionID: 999,
			registry:  &MockConnectionRegistry{},
			setupMock: func(mock sqlmock.Sqlmock) {
				// GORM First(id) 傳 id + limit 兩個參數，不指定 WithArgs
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnError(gorm.ErrRecordNotFound)
			},
			wantErr:       ErrSessionNotFound,
			wantCallCount: 0,
		},
		{
			name:      "Session already closed",
			sessionID: 1,
			registry:  &MockConnectionRegistry{},
			setupMock: func(mock sqlmock.Sqlmock) {
				// GORM First(id) 傳 id + limit 兩個參數，不指定 WithArgs
				// mock 列不含 user_id/asset_id（零值），GORM 跳過 Preload
				rows := sqlmock.NewRows([]string{"id", "status"}).
					AddRow(1, model.SessionStatusClosed)
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnRows(rows)
			},
			wantErr:       ErrSessionAlreadyClosed,
			wantCallCount: 0,
		},
		{
			// CAS 競態（F1）：GetByID 讀到 active，UPDATE 時已被他路徑收線，
			// RowsAffected=0 → ErrSessionAlreadyClosed 且不呼叫 registry.Close
			name:      "Concurrent close race (RowsAffected=0)",
			sessionID: 1,
			registry: &MockConnectionRegistry{
				closeFunc: func(sessionID uint) error { return nil },
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "status", "start_time"}).
					AddRow(1, model.SessionStatusActive, time.Now().Add(-1*time.Hour))
				mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
					WillReturnRows(rows)

				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE "sessions" SET`).
					WithArgs(
						sqlmock.AnyArg(),                // duration
						model.EndReasonAdminTerminate,   // end_reason
						sqlmock.AnyArg(),                // end_time
						model.SessionStatusDisconnected, // status (SET)
						sqlmock.AnyArg(),                // updated_at
						1,                               // WHERE id
						model.SessionStatusActive,       // WHERE status
					).
					WillReturnResult(sqlmock.NewResult(0, 0)) // 已被他路徑收線
				mock.ExpectCommit()
			},
			wantErr:       ErrSessionAlreadyClosed,
			wantCallCount: 0, // CAS 失敗不呼叫 registry.Close
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mock, _ := setupMockDB(t)
			service := NewSessionService(tt.registry)

			tt.setupMock(mock)

			err := service.Terminate(tt.sessionID, model.EndReasonAdminTerminate)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
			} else {
				assert.NoError(t, err)
			}

			// 驗證 registry.Close 被調用次數
			if mockReg, ok := tt.registry.(*MockConnectionRegistry); ok && mockReg != nil {
				assert.Equal(t, tt.wantCallCount, mockReg.callCount)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestGetStatistics 測試統計資訊
func TestGetStatistics(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	// Active sessions count
	mock.ExpectQuery(`SELECT count\(\*\) FROM "sessions" WHERE status`).
		WithArgs(model.SessionStatusActive).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	// Today sessions count
	mock.ExpectQuery(`SELECT count\(\*\) FROM "sessions" WHERE start_time`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(10))

	// Total sessions count
	mock.ExpectQuery(`SELECT count\(\*\) FROM "sessions"`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(100))

	stats, err := service.GetStatistics()
	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, int64(5), stats["active_sessions"])
	assert.Equal(t, int64(10), stats["today_sessions"])
	assert.Equal(t, int64(100), stats["total_sessions"])
}

// TestUpdateRecording 測試更新錄製資訊
func TestUpdateRecording(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	sessionID := uint(1)
	recordingPath := "/recordings/session_1.cast"
	recordingSize := int64(1024000)

	// GORM 對 map updates 依欄位名字母序排列參數:
	// has_recording, recording_path, recording_size, updated_at
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "sessions" SET`).
		WithArgs(
			true,
			recordingPath,
			recordingSize,
			sqlmock.AnyArg(), // updated_at
			sessionID,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := service.UpdateRecording(sessionID, recordingPath, recordingSize)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCloseBySessionID 測試根據 SessionID 關閉
func TestCloseBySessionID(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	sessionID := "sess_123"

	// GetBySessionID - 第一次查詢（GORM First 會添加 LIMIT）
	rows := sqlmock.NewRows([]string{"id", "session_id", "status", "start_time"}).
		AddRow(1, sessionID, model.SessionStatusActive, time.Now().Add(-1*time.Hour))
	// mock 列不含 user_id/asset_id（零值 FK），GORM 會跳過 Preload 查詢，
	// 因此不期望 users/assets 的 SELECT
	mock.ExpectQuery(`SELECT .+ FROM "sessions" WHERE session_id`).
		WillReturnRows(rows)

	// GetByID - 在 Close 方法中會再次查詢
	rows2 := sqlmock.NewRows([]string{"id", "status", "start_time"}).
		AddRow(1, model.SessionStatusActive, time.Now().Add(-1*time.Hour))
	mock.ExpectQuery(`SELECT .+ FROM "sessions"`).
		WillReturnRows(rows2)

	// Update
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "sessions" SET`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := service.CloseBySessionID(sessionID)
	assert.NoError(t, err)
}
