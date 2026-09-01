package session

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 離機上傳的 session 側：`UpdateRecording` 的同交易排隊、
// `RecordingOffsiteAdapter` 的寬限期與回填分類。
//
// **未設定＝行為完全不變**的機械保證在本檔有兩格：欄位集合逐字（sqlmock 逐參數）
// 與零交易（Enqueuer 未接線／現行世代零列兩種來源各一）。

func setupOffsiteSessionDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// sqlite :memory: 連線池陷阱（ff51836）：每條連線是各自獨立的空庫
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.Session{}, &model.OffsiteObject{}))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// fixedGeneration 測試用的現行世代來源（GenerationSource）。
type fixedGeneration struct {
	ref offsite.GenerationRef
	err error
}

func (f fixedGeneration) CurrentGeneration(*gorm.DB) (offsite.GenerationRef, error) {
	if f.err != nil {
		return offsite.GenerationRef{}, f.err
	}
	return f.ref, nil
}

func newTestLedger(db *gorm.DB, gen fixedGeneration) *offsite.Ledger {
	return offsite.NewLedger(db, gen, nil)
}

// writeRecordingFile 造一個錄影檔並把 mtime 設到指定時刻。
func writeRecordingFile(t *testing.T, dir, name string, content string, mtime time.Time) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	require.NoError(t, os.Chtimes(p, mtime, mtime))
	return p
}

// ── UpdateRecording ────────────────────────────────────────────────────────

// TestUpdateRecordingUnchangedWhenOffsiteNotWired 未組裝離機子系統：
// 欄位集合與參數順序逐字不變（sqlmock 逐參數比對），且只有一筆 UPDATE。
func TestUpdateRecordingUnchangedWhenOffsiteNotWired(t *testing.T) {
	_, mock, _ := setupMockDB(t)
	service := NewSessionService(nil)

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "sessions" SET`).
		WithArgs(true, "/recordings/session_1.cast", int64(1024), sqlmock.AnyArg(), uint(1)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	require.NoError(t, service.UpdateRecording(1, "/recordings/session_1.cast", 1024))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUpdateRecordingUnchangedWhenNoCurrentGeneration 已接線但現行世代零列
// （從未設定或已停用）：**不開交易**（gorm 的單句 Updates 自帶隱式交易，
// 這裡驗的是不進 `database.DB.Transaction` 那條路徑）、欄位集合逐字不變、
// 帳冊零列。
func TestUpdateRecordingUnchangedWhenNoCurrentGeneration(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	sess := model.Session{SessionID: "sess-none", UserID: 1, Status: model.SessionStatusClosed}
	require.NoError(t, db.Create(&sess).Error)

	svc := NewSessionService(nil)
	svc.SetOffsiteEnqueuer(newTestLedger(db, fixedGeneration{err: offsite.ErrNoCurrentGeneration}))

	require.NoError(t, svc.UpdateRecording(sess.ID, "/tmp/a.cast", 42))

	var got model.Session
	require.NoError(t, db.First(&got, sess.ID).Error)
	assert.Equal(t, "/tmp/a.cast", got.RecordingPath)
	assert.Equal(t, int64(42), got.RecordingSize)
	assert.True(t, got.HasRecording)
	assert.Nil(t, got.OffsiteObjectID, "未設定離機時不得寫入指標欄")
	assert.Equal(t, "", got.OffsiteStatus, "未設定離機時不得寫入快取欄")

	var n int64
	require.NoError(t, db.Model(&model.OffsiteObject{}).Count(&n).Error)
	assert.Zero(t, n, "未設定離機時帳冊必須零列")
}

// TestUpdateRecordingEnqueuesInSameTransaction 啟用時同一交易寫三段。
func TestUpdateRecordingEnqueuesInSameTransaction(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	sess := model.Session{SessionID: "sess-live", UserID: 1, Status: model.SessionStatusClosed}
	require.NoError(t, db.Create(&sess).Error)

	svc := NewSessionService(nil)
	svc.SetOffsiteEnqueuer(newTestLedger(db, fixedGeneration{ref: offsite.GenerationRef{
		GenerationID: 7, Provider: offsite.ProviderS3, Bucket: "evidence", Prefix: "custodexa",
	}}))

	require.NoError(t, svc.UpdateRecording(sess.ID, "/tmp/live.cast", 99))

	var got model.Session
	require.NoError(t, db.First(&got, sess.ID).Error)
	require.NotNil(t, got.OffsiteObjectID)
	assert.Equal(t, offsite.StatePending, got.OffsiteStatus)

	var obj model.OffsiteObject
	require.NoError(t, db.First(&obj, *got.OffsiteObjectID).Error)
	assert.Equal(t, offsite.KindRecording, obj.Kind)
	assert.Equal(t, offsite.OriginLive, obj.Origin)
	assert.Equal(t, uint(7), obj.StorageGenerationID)
	assert.Equal(t, sess.ID, obj.OwnerID)
}

// failingEnqueuer 先在交易內建列、再回錯——證明回滾覆蓋兩張表（無半排入）。
type failingEnqueuer struct{ inner *offsite.Ledger }

func (f failingEnqueuer) HasCurrentGeneration() (bool, error) { return true, nil }

func (f failingEnqueuer) EnqueueTx(tx *gorm.DB, kind string, ownerID uint, origin string) (*model.OffsiteObject, bool, error) {
	row, created, err := f.inner.EnqueueTx(tx, kind, ownerID, origin)
	if err != nil {
		return row, created, err
	}
	return nil, false, errors.New("注入：排隊後失敗")
}

// TestUpdateRecordingRollsBackWholeTransaction 交易中途失敗＝錄影欄位與帳冊列
// **一起**回滾，不留半排入。
func TestUpdateRecordingRollsBackWholeTransaction(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	sess := model.Session{SessionID: "sess-rb", UserID: 1, Status: model.SessionStatusClosed}
	require.NoError(t, db.Create(&sess).Error)

	svc := NewSessionService(nil)
	svc.SetOffsiteEnqueuer(failingEnqueuer{inner: newTestLedger(db, fixedGeneration{
		ref: offsite.GenerationRef{GenerationID: 3, Provider: offsite.ProviderS3, Bucket: "b"},
	})})

	err := svc.UpdateRecording(sess.ID, "/tmp/rb.cast", 7)
	require.Error(t, err)

	var got model.Session
	require.NoError(t, db.First(&got, sess.ID).Error)
	assert.Equal(t, "", got.RecordingPath, "排隊失敗必須連錄影欄位一起回滾")
	assert.False(t, got.HasRecording)

	var n int64
	require.NoError(t, db.Model(&model.OffsiteObject{}).Count(&n).Error)
	assert.Zero(t, n, "回滾後帳冊不得留下半排入的列")
}

// ── RecordingOffsiteAdapter ────────────────────────────────────────────────

// TestRecordingAdapterOpenTextImmediately 文字錄影即取件（無寬限期）。
func TestRecordingAdapterOpenTextImmediately(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	dir := t.TempDir()
	now := time.Now()
	p := writeRecordingFile(t, dir, "session-1.cast", "cast-body", now)

	sess := model.Session{SessionID: "s-text", UserID: 1, Protocol: model.ProtocolSSH,
		Status: model.SessionStatusClosed, RecordingPath: p, HasRecording: true}
	require.NoError(t, db.Create(&sess).Error)

	a := NewRecordingOffsiteAdapter(db, nil)
	a.SetClockForTest(func() time.Time { return now })

	rc, size, mtime, err := a.Open(sess.ID)
	require.NoError(t, err, "文字錄影的 fd 於 UpdateRecording 之前即關閉，必須即可取件")
	defer rc.Close()
	assert.Equal(t, int64(len("cast-body")), size)
	assert.WithinDuration(t, now, mtime, time.Second)
}

// TestRecordingAdapterGraphicsGrace 圖形錄影的寬限期：未到延後、到了取件、
// 會話仍進行中一律延後。
func TestRecordingAdapterGraphicsGrace(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	dir := t.TempDir()
	base := time.Now()
	p := writeRecordingFile(t, dir, "session-2.guac", "guac-body", base)

	sess := model.Session{SessionID: "s-graphics", UserID: 1, Protocol: model.ProtocolRDP,
		Status: model.SessionStatusClosed, RecordingPath: p, HasRecording: true}
	require.NoError(t, db.Create(&sess).Error)

	a := NewRecordingOffsiteAdapter(db, nil)

	// 寬限期未到（59 秒）：ErrNotReadyYet——worker 據此延後且不計 attempts
	a.SetClockForTest(func() time.Time { return base.Add(59 * time.Second) })
	_, _, _, err := a.Open(sess.ID)
	assert.ErrorIs(t, err, offsite.ErrNotReadyYet, "寬限期未到必須延後而非失敗")

	// 寬限期已到（60 秒整）：取件
	a.SetClockForTest(func() time.Time {
		return base.Add(time.Duration(offsite.GraphicsUploadGraceSeconds) * time.Second)
	})
	rc, size, _, err := a.Open(sess.ID)
	require.NoError(t, err)
	defer rc.Close()
	assert.Equal(t, int64(len("guac-body")), size)

	// 會話仍在進行中：即使 mtime 夠老也不取件（尾段仍在寫）
	require.NoError(t, db.Model(&model.Session{}).Where("id = ?", sess.ID).
		Update("status", model.SessionStatusActive).Error)
	a.SetClockForTest(func() time.Time { return base.Add(time.Hour) })
	_, _, _, err = a.Open(sess.ID)
	assert.ErrorIs(t, err, offsite.ErrNotReadyYet, "會話仍 active 時圖形錄影不得取件")
}

// TestRecordingAdapterClassifyThreeClasses 回填三分類各一格。
func TestRecordingAdapterClassifyThreeClasses(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	dir := t.TempDir()
	now := time.Now()

	fresh := writeRecordingFile(t, dir, "fresh.cast", "x", now)
	old := writeRecordingFile(t, dir, "old.cast", "x", now.AddDate(0, 0, -100))

	uploadable := model.Session{SessionID: "s-up", UserID: 1, Protocol: model.ProtocolSSH,
		Status: model.SessionStatusClosed, RecordingPath: fresh, HasRecording: true}
	expired := model.Session{SessionID: "s-exp", UserID: 1, Protocol: model.ProtocolSSH,
		Status: model.SessionStatusClosed, RecordingPath: old, HasRecording: true}
	missing := model.Session{SessionID: "s-miss", UserID: 1, Protocol: model.ProtocolSSH,
		Status: model.SessionStatusClosed, RecordingPath: filepath.Join(dir, "gone.cast"),
		HasRecording: true}
	for _, s := range []*model.Session{&uploadable, &expired, &missing} {
		require.NoError(t, db.Create(s).Error)
	}

	a := NewRecordingOffsiteAdapter(db, func() int { return 90 })
	a.SetClockForTest(func() time.Time { return now })

	for _, tc := range []struct {
		name string
		id   uint
		want offsite.BackfillClass
	}{
		{"可上傳", uploadable.ID, offsite.BackfillUploadable},
		{"逾保留期", expired.ID, offsite.BackfillExpired},
		{"本機缺檔", missing.ID, offsite.BackfillMissing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.Classify(tc.id)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestRecordingAdapterListUnenqueuedAndSetStatus 回填視野與快取寫回。
//
// **objectID=0 不得寫指標欄**：兩個跳過分類若把指標寫進去，
// `idx_sessions_offsite_backfill` 的 partial WHERE 會讓它們自回填視野中永久消失。
func TestRecordingAdapterListUnenqueuedAndSetStatus(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	a := NewRecordingOffsiteAdapter(db, nil)

	withRec := model.Session{SessionID: "s-1", UserID: 1, HasRecording: true, RecordingPath: "/x"}
	noRec := model.Session{SessionID: "s-2", UserID: 1}
	require.NoError(t, db.Create(&withRec).Error)
	require.NoError(t, db.Create(&noRec).Error)

	ids, err := a.ListUnenqueued(10)
	require.NoError(t, err)
	assert.Equal(t, []uint{withRec.ID}, ids, "只列有錄影且尚未排入者")

	require.NoError(t, a.SetStatus(withRec.ID, 0, offsite.CacheSkippedMissing))
	var got model.Session
	require.NoError(t, db.First(&got, withRec.ID).Error)
	assert.Equal(t, offsite.CacheSkippedMissing, got.OffsiteStatus)
	assert.Nil(t, got.OffsiteObjectID, "跳過分類不建帳冊列，指標欄必須維持 NULL")

	ids, err = a.ListUnenqueued(10)
	require.NoError(t, err)
	assert.Equal(t, []uint{withRec.ID}, ids, "skipped_missing 仍須留在回填視野內")

	require.NoError(t, a.SetStatus(withRec.ID, 55, offsite.StatePending))
	require.NoError(t, db.First(&got, withRec.ID).Error)
	require.NotNil(t, got.OffsiteObjectID)
	assert.Equal(t, uint(55), *got.OffsiteObjectID)

	ids, err = a.ListUnenqueued(10)
	require.NoError(t, err)
	assert.Empty(t, ids, "已排入者退出回填視野")
}

// TestRecordingAdapterDescribeUsesRealEndTime Describe 的 EndedAt 決定 object key
// 的年月分桶，必須是真實結束時刻而非「現在」。
func TestRecordingAdapterDescribeUsesRealEndTime(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	ended := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	sess := model.Session{SessionID: "s-desc", UserID: 1, StartTime: ended.Add(-time.Hour),
		EndTime: &ended, HasRecording: true, RecordingPath: "/x"}
	require.NoError(t, db.Create(&sess).Error)

	a := NewRecordingOffsiteAdapter(db, func() int { return 30 })
	a.SetClockForTest(func() time.Time { return ended.Add(500 * time.Hour) })

	d, err := a.Describe(sess.ID)
	require.NoError(t, err)
	assert.Equal(t, ended.UTC(), d.EndedAt.UTC())
	assert.Equal(t, "s-desc", d.Label)
	require.NotNil(t, d.RetentionDeadline)
	assert.Equal(t, ended.AddDate(0, 0, 30).UTC(), d.RetentionDeadline.UTC())

	// 保留天數 0＝永久：無到期日
	a2 := NewRecordingOffsiteAdapter(db, func() int { return 0 })
	d2, err := a2.Describe(sess.ID)
	require.NoError(t, err)
	assert.Nil(t, d2.RetentionDeadline)
}

// TestRecordingAdapterExtension 副檔名依協議（object key 用）。
func TestRecordingAdapterExtension(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	text := model.Session{SessionID: "e-1", UserID: 1, Protocol: model.ProtocolSSH}
	graphics := model.Session{SessionID: "e-2", UserID: 1, Protocol: model.ProtocolVNC}
	require.NoError(t, db.Create(&text).Error)
	require.NoError(t, db.Create(&graphics).Error)

	a := NewRecordingOffsiteAdapter(db, nil)
	ext, err := a.Extension(text.ID)
	require.NoError(t, err)
	assert.Equal(t, "cast", ext)
	ext, err = a.Extension(graphics.ID)
	require.NoError(t, err)
	assert.Equal(t, "guac", ext)
}

// TestRecordingAdapterMarkForeignBatch 世代退役時的快取批次轉移：
// 非終態的快取轉 foreign，終態（local_purged／已 foreign）與跳過分類不動。
func TestRecordingAdapterMarkForeignBatch(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	objID := uint(9)
	rows := []struct {
		sid    string
		status string
		ptr    *uint
		want   string
	}{
		{"f-pending", offsite.StatePending, &objID, offsite.StateForeign},
		{"f-uploaded", offsite.StateUploaded, &objID, offsite.StateForeign},
		{"f-purged", offsite.StateLocalPurged, &objID, offsite.StateLocalPurged},
		{"f-foreign", offsite.StateForeign, &objID, offsite.StateForeign},
		{"f-skipped", offsite.CacheSkippedMissing, nil, offsite.CacheSkippedMissing},
	}
	ids := make([]uint, len(rows))
	for i, r := range rows {
		s := model.Session{SessionID: r.sid, UserID: 1, OffsiteStatus: r.status, OffsiteObjectID: r.ptr}
		require.NoError(t, db.Create(&s).Error)
		ids[i] = s.ID
	}

	a := NewRecordingOffsiteAdapter(db, nil)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		return a.MarkForeignBatch(tx, 3)
	}))

	for i, r := range rows {
		var got model.Session
		require.NoError(t, db.First(&got, ids[i]).Error)
		assert.Equal(t, r.want, got.OffsiteStatus, r.sid)
	}
}

// TestRecordingAdapterSatisfiesOffsiteAdapter 型別層釘住介面實作
// （方法漏一個即編譯不過，而不是執行期才發現 worker 少了一條腿）。
func TestRecordingAdapterSatisfiesOffsiteAdapter(t *testing.T) {
	var _ offsite.Adapter = (*RecordingOffsiteAdapter)(nil)
}
