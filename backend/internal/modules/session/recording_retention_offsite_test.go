package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 離機啟用後的錄影保留。
//
// 兩段的語義相反，故本檔的每一格都同時斷言「該清的清了」與「該留的留著」：
// 快取段刪檔而三欄與 has_recording 不動；政策段刪檔且清三欄、帳冊轉移。

// retentionRig 真 Ledger（含逐狀態轉移表）＋真 RecordingService。
type retentionRig struct {
	svc    *RecordingService
	ledger *offsite.Ledger
	dir    string
}

func newRetentionRig(t *testing.T) *retentionRig {
	t.Helper()
	db := setupOffsiteSessionDB(t)
	dir := t.TempDir()
	ledger := offsite.NewLedger(db, fixedGeneration{
		ref: offsite.GenerationRef{GenerationID: 1, Provider: offsite.ProviderS3, Bucket: "b"},
	}, nil)
	svc := NewRecordingService(dir)
	svc.SetOffsiteRetentionLedger(ledger)
	return &retentionRig{svc: svc, ledger: ledger, dir: dir}
}

// seedOffsiteSession 造一場「已離機」的會話：本機檔、帳冊列、兩個快取欄。
func (r *retentionRig) seedOffsiteSession(t *testing.T, name, state string,
	uploadedAt *time.Time, endedAt time.Time) (model.Session, model.OffsiteObject) {
	t.Helper()
	db := database.DB
	path := filepath.Join(r.dir, name+".cast")
	require.NoError(t, os.WriteFile(path, []byte("body-"+name), 0o600))

	obj := model.OffsiteObject{
		Kind: offsite.KindRecording, Origin: offsite.OriginLive, Provider: offsite.ProviderS3,
		StorageGenerationID: 1, Bucket: "b", ObjectKey: "k/" + name + ".cast",
		State: state, UploadedAt: uploadedAt, SHA256: "abc", Size: 9,
	}
	require.NoError(t, db.Create(&obj).Error)

	sess := model.Session{SessionID: name, UserID: 1, Status: model.SessionStatusClosed,
		RecordingPath: path, RecordingSize: 9, HasRecording: true,
		EndTime: &endedAt, OffsiteObjectID: &obj.ID, OffsiteStatus: state}
	require.NoError(t, db.Create(&sess).Error)

	// 帳冊列的 owner 必須指回會話
	require.NoError(t, db.Model(&model.OffsiteObject{}).Where("id = ?", obj.ID).
		Update("owner_id", sess.ID).Error)
	obj.OwnerID = sess.ID
	return sess, obj
}

func reloadOffsiteSession(t *testing.T, id uint) model.Session {
	t.Helper()
	var got model.Session
	require.NoError(t, database.DB.First(&got, id).Error)
	return got
}

func reloadObject(t *testing.T, id uint) model.OffsiteObject {
	t.Helper()
	var got model.OffsiteObject
	require.NoError(t, database.DB.First(&got, id).Error)
	return got
}

// TestPurgeOffsiteLocalCacheKeepsRecordingPlayable 快取清除段：本機檔刪除，
// **三欄與 has_recording 不動**——錄影仍可播（來源判定改走離機）。
func TestPurgeOffsiteLocalCacheKeepsRecordingPlayable(t *testing.T) {
	r := newRetentionRig(t)
	old := time.Now().AddDate(0, 0, -10)
	sess, obj := r.seedOffsiteSession(t, "cache-expired", offsite.StateUploaded, &old, old)

	n, err := r.svc.PurgeOffsiteLocalCache(7)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	_, statErr := os.Stat(sess.RecordingPath)
	assert.True(t, os.IsNotExist(statErr), "快取期到了必須刪本機檔")

	got := reloadOffsiteSession(t, sess.ID)
	assert.Equal(t, sess.RecordingPath, got.RecordingPath, "快取清除不得清空 recording_path")
	assert.True(t, got.HasRecording, "快取清除不得把 has_recording 翻成 false")
	assert.Equal(t, int64(9), got.RecordingSize)

	after := reloadObject(t, obj.ID)
	assert.Equal(t, offsite.StateUploaded, after.State, "快取清除不改帳冊態")
}

// TestPurgeOffsiteLocalCacheSkipsForeignAndFresh foreign 不做快取清除
// （其遠端可達性已不由現行設定保證，本機副本可能是唯一可讀副本）；
// 未到期者亦不動。
func TestPurgeOffsiteLocalCacheSkipsForeignAndFresh(t *testing.T) {
	r := newRetentionRig(t)
	old := time.Now().AddDate(0, 0, -10)
	fresh := time.Now().AddDate(0, 0, -1)
	foreign, _ := r.seedOffsiteSession(t, "foreign-old", offsite.StateForeign, &old, old)
	recent, _ := r.seedOffsiteSession(t, "uploaded-fresh", offsite.StateUploaded, &fresh, fresh)

	n, err := r.svc.PurgeOffsiteLocalCache(7)
	require.NoError(t, err)
	assert.Zero(t, n)

	for _, s := range []model.Session{foreign, recent} {
		_, err := os.Stat(s.RecordingPath)
		assert.NoError(t, err, "%s 的本機檔不得被快取清除", s.SessionID)
	}
}

// TestPurgeOffsiteLocalCacheDisabledByDefault 快取期 0（政策出廠值）＝不提前清。
func TestPurgeOffsiteLocalCacheDisabledByDefault(t *testing.T) {
	r := newRetentionRig(t)
	old := time.Now().AddDate(0, 0, -100)
	sess, _ := r.seedOffsiteSession(t, "zero-days", offsite.StateUploaded, &old, old)

	n, err := r.svc.PurgeOffsiteLocalCache(0)
	require.NoError(t, err)
	assert.Zero(t, n)
	_, err = os.Stat(sess.RecordingPath)
	assert.NoError(t, err, "快取期 0 時不得刪任何本機檔")
}

// TestRetentionExpiryTransitionsPerPriorState 逐狀態到期轉移表：
// **每一種前態各一格**。少任何一格就會留下一種「本機檔已刪卻仍被 worker 領取」
// 或「狀態語義遺失」的孤兒形態。
func TestRetentionExpiryTransitionsPerPriorState(t *testing.T) {
	uploaded := time.Now().AddDate(0, 0, -100)
	cases := []struct {
		name      string
		prior     string
		wantState string
		wantClear bool
		// wantCount 本輪「處置數」。冪等命中為 0——那一列這一輪什麼也沒發生，
		// 計進去會讓單輪上限被已完成的工作吃掉
		wantCount int
	}{
		{"uploaded", offsite.StateUploaded, offsite.StateLocalPurged, true, 1},
		{"pending（從未離機）", offsite.StatePending, offsite.StateLocalPurged, true, 1},
		{"failed（從未離機）", offsite.StateFailed, offsite.StateLocalPurged, true, 1},
		{"integrity_mismatch", offsite.StateIntegrityMismatch, offsite.StateLocalPurged, true, 1},
		{"foreign（維持 foreign）", offsite.StateForeign, offsite.StateForeign, true, 1},
		{"local_purged（冪等）", offsite.StateLocalPurged, offsite.StateLocalPurged, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRetentionRig(t)
			sess, obj := r.seedOffsiteSession(t, "prior-"+tc.prior, tc.prior, &uploaded, uploaded)
			// 本機檔已不在（快取清除段刪過）——政策段的 DB 分支正是為這一格存在
			require.NoError(t, os.Remove(sess.RecordingPath))

			n, err := r.svc.PurgeExpiredOffsiteRecords(90, 0)
			require.NoError(t, err)
			assert.Equal(t, tc.wantCount, n)

			after := reloadObject(t, obj.ID)
			assert.Equal(t, tc.wantState, after.State)

			got := reloadOffsiteSession(t, sess.ID)
			if tc.wantClear {
				assert.Equal(t, "", got.RecordingPath, "到期處置必須清 recording_path")
				assert.False(t, got.HasRecording, "到期處置必須清 has_recording")
				assert.Equal(t, int64(0), got.RecordingSize)
				assert.Equal(t, tc.wantState, got.OffsiteStatus,
					"離機快取欄應寫處置後的狀態，而非清空（清空會讓「已到期清除」被讀成「從未離機」）")
			}
		})
	}
}

// TestRetentionExpiryDefersUploading `uploading` 在租約期內不被動；
// 租約回收回 pending 後，下一輪才處置。
//
// 少了這一格，在途上傳會與到期處置競跑：帳冊被標到期而 worker 手上還握著租約，
// 上傳完成時再把它寫回 uploaded——一份本機已刪、帳冊說可用的幽靈。
func TestRetentionExpiryDefersUploading(t *testing.T) {
	r := newRetentionRig(t)
	uploaded := time.Now().AddDate(0, 0, -100)
	sess, obj := r.seedOffsiteSession(t, "uploading-inflight", offsite.StateUploading, &uploaded, uploaded)
	require.NoError(t, os.Remove(sess.RecordingPath))

	n, err := r.svc.PurgeExpiredOffsiteRecords(90, 0)
	require.NoError(t, err)
	assert.Zero(t, n, "在途上傳本輪不得被處置")
	assert.Equal(t, offsite.StateUploading, reloadObject(t, obj.ID).State)
	assert.True(t, reloadOffsiteSession(t, sess.ID).HasRecording, "延後時擁有表三欄不得被清")

	// 租約回收（Reap 把 uploading→pending）後，下一輪按 pending 處置
	past := time.Now().Add(-time.Hour)
	require.NoError(t, database.DB.Model(&model.OffsiteObject{}).Where("id = ?", obj.ID).
		Update("lease_until", past).Error)
	_, err = r.ledger.Reap()
	require.NoError(t, err)

	n, err = r.svc.PurgeExpiredOffsiteRecords(90, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "租約回收後的下一輪必須完成處置")
	assert.Equal(t, offsite.StateLocalPurged, reloadObject(t, obj.ID).State)
}

// TestRetentionExpiryLeavesFileOnDiskToWalkSegment 本機檔還在者由 Walk 段負責，
// DB 分支不代刪——兩條路徑對同一個檔案競跑會出現「刪到一半的狀態」。
func TestRetentionExpiryLeavesFileOnDiskToWalkSegment(t *testing.T) {
	r := newRetentionRig(t)
	uploaded := time.Now().AddDate(0, 0, -100)
	sess, obj := r.seedOffsiteSession(t, "still-on-disk", offsite.StateUploaded, &uploaded, uploaded)

	n, err := r.svc.PurgeExpiredOffsiteRecords(90, 0)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Equal(t, offsite.StateUploaded, reloadObject(t, obj.ID).State)
	_, statErr := os.Stat(sess.RecordingPath)
	assert.NoError(t, statErr)
}

// TestCleanupOldRecordingsMarksLedgerOnWalk Walk 段刪本機檔時同步帳冊到期處置
// （走**真實的清除流程**，不直呼帳冊）。
func TestCleanupOldRecordingsMarksLedgerOnWalk(t *testing.T) {
	r := newRetentionRig(t)
	uploaded := time.Now().AddDate(0, 0, -100)
	sess, obj := r.seedOffsiteSession(t, "walk-expired", offsite.StateUploaded, &uploaded, uploaded)
	// mtime 倒填到保留期之外（Walk 的判準是檔案 mtime）
	old := time.Now().AddDate(0, 0, -100)
	require.NoError(t, os.Chtimes(sess.RecordingPath, old, old))

	deleted, err := r.svc.CleanupOldRecordings(90)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)

	assert.Equal(t, offsite.StateLocalPurged, reloadObject(t, obj.ID).State,
		"Walk 段刪本機檔後帳冊必須同步到期處置，否則 worker 會繼續領一個已不存在的檔案")
	got := reloadOffsiteSession(t, sess.ID)
	assert.Equal(t, "", got.RecordingPath)
	assert.False(t, got.HasRecording)
	assert.Equal(t, offsite.StateLocalPurged, got.OffsiteStatus)
}

// TestCleanupOldRecordingsUnchangedWithoutOffsite 未組裝離機：Walk 段逐字維持
// 既有行為（刪檔＋清三欄），離機欄不存在故不被觸碰。
func TestCleanupOldRecordingsUnchangedWithoutOffsite(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.cast")
	require.NoError(t, os.WriteFile(path, []byte("body"), 0o600))
	old := time.Now().AddDate(0, 0, -100)
	require.NoError(t, os.Chtimes(path, old, old))
	sess := model.Session{SessionID: "plain", UserID: 1, RecordingPath: path,
		RecordingSize: 4, HasRecording: true}
	require.NoError(t, db.Create(&sess).Error)

	svc := NewRecordingService(dir)
	deleted, err := svc.CleanupOldRecordings(90)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)

	got := reloadOffsiteSession(t, sess.ID)
	assert.Equal(t, "", got.RecordingPath)
	assert.False(t, got.HasRecording)
	assert.Equal(t, "", got.OffsiteStatus)
}

// TestPurgeExpiredRespectsMaxPerRun 單輪上限（沿 retention_max_per_run）。
func TestPurgeExpiredRespectsMaxPerRun(t *testing.T) {
	r := newRetentionRig(t)
	uploaded := time.Now().AddDate(0, 0, -100)
	for i := 0; i < 3; i++ {
		sess, _ := r.seedOffsiteSession(t, "bulk-"+string(rune('a'+i)),
			offsite.StateUploaded, &uploaded, uploaded)
		require.NoError(t, os.Remove(sess.RecordingPath))
	}

	n, err := r.svc.PurgeExpiredOffsiteRecords(90, 2)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "單輪上限必須被遵守")

	n, err = r.svc.PurgeExpiredOffsiteRecords(90, 2)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "下一輪處理剩下的")
}
