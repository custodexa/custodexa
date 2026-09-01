package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 來源判定：本機優先，本機異常才走離機。
//
// **這裡驗的是判準本身**（哪一種本機狀態算異常、退路原因是什麼）；
// 「取回的內容驗過才交付」由 `internal/offsite` 的 fetcher 測試承擔。

// stubRetriever 假的離機取回面：回固定的帳冊列與一份現成的暫存檔。
type stubRetriever struct {
	row        *model.OffsiteObject
	spoolPath  string
	fetchCalls int
	fetchErr   error
}

func (s *stubRetriever) Object(uint) (*model.OffsiteObject, error) { return s.row, nil }

func (s *stubRetriever) Fetch(context.Context, uint) (*offsite.FetchedObject, error) {
	s.fetchCalls++
	if s.fetchErr != nil {
		return nil, s.fetchErr
	}
	return &offsite.FetchedObject{Path: s.spoolPath, Size: s.row.Size,
		UploadedAt: time.Now(), Kind: offsite.KindRecording, OwnerID: s.row.OwnerID}, nil
}

// sourceFixture 造一場「已離機」的會話：本機檔、暫存檔、帳冊列各一。
type sourceFixture struct {
	svc       *RecordingService
	stub      *stubRetriever
	sessionID uint
	localPath string
	spoolPath string
	body      []byte
}

func newSourceFixture(t *testing.T) *sourceFixture {
	t.Helper()
	db := setupOffsiteSessionDB(t)
	dir := t.TempDir()
	body := []byte("evidence-body-1234567890")
	local := filepath.Join(dir, "session-1.cast")
	require.NoError(t, os.WriteFile(local, body, 0o600))
	spool := filepath.Join(dir, "spool-1.cast")
	require.NoError(t, os.WriteFile(spool, body, 0o600))

	sum := sha256.Sum256(body)
	objID := uint(77)
	sess := model.Session{SessionID: "s-src", UserID: 1, Protocol: model.ProtocolSSH,
		Status: model.SessionStatusClosed, RecordingPath: local, HasRecording: true,
		OffsiteObjectID: &objID, OffsiteStatus: offsite.StateUploaded}
	require.NoError(t, db.Create(&sess).Error)

	stub := &stubRetriever{
		row: &model.OffsiteObject{ID: objID, Kind: offsite.KindRecording, OwnerID: sess.ID,
			State: offsite.StateUploaded, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))},
		spoolPath: spool,
	}
	svc := NewRecordingService(dir)
	svc.SetOffsiteRetriever(stub)
	return &sourceFixture{svc: svc, stub: stub, sessionID: sess.ID,
		localPath: local, spoolPath: spool, body: body}
}

// TestResolveRecordingPrefersLocal 本機檔完好：用本機、零取回。
func TestResolveRecordingPrefersLocal(t *testing.T) {
	f := newSourceFixture(t)
	res, err := f.svc.ResolveRecording(f.sessionID, false)
	require.NoError(t, err)
	assert.Equal(t, RecordingSourceLocal, res.Source)
	assert.Equal(t, f.localPath, res.Path)
	assert.Empty(t, res.Fallback)
	assert.Zero(t, f.stub.fetchCalls, "本機可用時不得打離機")
}

// TestResolveRecordingLocalLongerStaysLocal 本機**比帳冊長**＝圖形錄影的尾段，
// 合法，不是異常。
func TestResolveRecordingLocalLongerStaysLocal(t *testing.T) {
	f := newSourceFixture(t)
	require.NoError(t, os.WriteFile(f.localPath, append(f.body, []byte("tail-frames")...), 0o600))

	res, err := f.svc.ResolveRecording(f.sessionID, false)
	require.NoError(t, err)
	assert.Equal(t, RecordingSourceLocal, res.Source,
		"本機比上傳版長是圖形錄影的正常尾段，不得判為異常")
	assert.Zero(t, f.stub.fetchCalls)
}

// TestResolveRecordingTruncatedFallsBack 本機被截斷→離機，退路原因 local_truncated。
func TestResolveRecordingTruncatedFallsBack(t *testing.T) {
	f := newSourceFixture(t)
	require.NoError(t, os.WriteFile(f.localPath, f.body[:5], 0o600))

	res, err := f.svc.ResolveRecording(f.sessionID, false)
	require.NoError(t, err)
	assert.Equal(t, RecordingSourceOffsite, res.Source)
	assert.Equal(t, FallbackLocalTruncated, res.Fallback)
	assert.Equal(t, f.spoolPath, res.Path)
	assert.Equal(t, int64(len(f.body)), res.Size, "離機來源的大小取帳冊記載值")
	assert.Equal(t, 1, f.stub.fetchCalls)
}

// TestResolveRecordingMissingFallsBack 本機檔被保留政策清掉→離機，退路 local_missing。
func TestResolveRecordingMissingFallsBack(t *testing.T) {
	f := newSourceFixture(t)
	require.NoError(t, os.Remove(f.localPath))

	res, err := f.svc.ResolveRecording(f.sessionID, false)
	require.NoError(t, err)
	assert.Equal(t, RecordingSourceOffsite, res.Source)
	assert.Equal(t, FallbackLocalMissing, res.Fallback)
	assert.Equal(t, 1, f.stub.fetchCalls)
}

// TestResolveRecordingUnreadableFallsBack 本機檔存在但讀不到（I/O 錯而非
// 「不存在」）→ 離機，退路 local_unreadable。
//
// **不用權限位元造這一格**：測試在容器內以 root 執行，chmod 000 對 root 無效，
// 那樣寫出來的測試會 skip 掉——一格永遠不跑的測試等於沒有這一格。改以符號連結
// 迴圈造出 ELOOP：`os.Stat` 失敗且**不是** IsNotExist，正是「檔案在那裡但讀不到」
// 這條分支要分辨的形態。
func TestResolveRecordingUnreadableFallsBack(t *testing.T) {
	f := newSourceFixture(t)
	require.NoError(t, os.Remove(f.localPath))
	loop := f.localPath + ".loop"
	require.NoError(t, os.Symlink(loop, f.localPath))
	require.NoError(t, os.Symlink(f.localPath, loop))

	res, err := f.svc.ResolveRecording(f.sessionID, false)
	require.NoError(t, err)
	assert.Equal(t, RecordingSourceOffsite, res.Source)
	assert.Equal(t, FallbackLocalUnreadable, res.Fallback,
		"stat 失敗但不是「不存在」＝讀不到，與檔案已被清除是兩種訊號")
}

// TestResolveRecordingDivergentOnlyOnWholeFilePath 大小相同而內容被改：
// **只有整檔路徑**（verifyHash）判得出來；串流路徑不為了播一個 Range 讀完整檔。
func TestResolveRecordingDivergentOnlyOnWholeFilePath(t *testing.T) {
	f := newSourceFixture(t)
	tampered := make([]byte, len(f.body))
	copy(tampered, f.body)
	tampered[0] = 'X'
	require.NoError(t, os.WriteFile(f.localPath, tampered, 0o600))

	stream, err := f.svc.ResolveRecording(f.sessionID, false)
	require.NoError(t, err)
	assert.Equal(t, RecordingSourceLocal, stream.Source, "串流路徑不算整檔雜湊")

	whole, err := f.svc.ResolveRecording(f.sessionID, true)
	require.NoError(t, err)
	assert.Equal(t, RecordingSourceOffsite, whole.Source)
	assert.Equal(t, FallbackLocalDivergent, whole.Fallback)
}

// TestResolveRecordingNotOffsiteKeepsExistingError 未離機且本機缺檔＝既有錯誤碼，
// 零改動（機械保證在讀取面的落點）。
func TestResolveRecordingNotOffsiteKeepsExistingError(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	dir := t.TempDir()
	sess := model.Session{SessionID: "s-nooffsite", UserID: 1,
		RecordingPath: filepath.Join(dir, "gone.cast"), HasRecording: true}
	require.NoError(t, db.Create(&sess).Error)

	stub := &stubRetriever{row: &model.OffsiteObject{}}
	svc := NewRecordingService(dir)
	svc.SetOffsiteRetriever(stub)

	_, err := svc.ResolveRecording(sess.ID, false)
	assert.ErrorIs(t, err, ErrRecordingNotFound)
	assert.Zero(t, stub.fetchCalls, "從未排入離機的會話不得觸發取回")
}

// TestGetRecordingMetadataCarriesSource metadata 帶 source；離機時 file_size
// 取帳冊值（本機檔已被清除，回報磁碟上的數字會說謊）。
func TestGetRecordingMetadataCarriesSource(t *testing.T) {
	f := newSourceFixture(t)

	meta, err := f.svc.GetRecordingMetadata(f.sessionID)
	require.NoError(t, err)
	assert.Equal(t, RecordingSourceLocal, meta.Source)

	require.NoError(t, os.Remove(f.localPath))
	meta, err = f.svc.GetRecordingMetadata(f.sessionID)
	require.NoError(t, err)
	assert.Equal(t, RecordingSourceOffsite, meta.Source)
	assert.Equal(t, int64(len(f.body)), meta.FileSize)
}

// TestResolveRecordingPropagatesIntegrityRefusal 取回被判不符時**不退回本機**、
// 不靜默——錯誤原樣上拋供 handler 收斂成機器碼。
func TestResolveRecordingPropagatesIntegrityRefusal(t *testing.T) {
	f := newSourceFixture(t)
	require.NoError(t, os.Remove(f.localPath))
	f.stub.fetchErr = offsite.ErrIntegrityMismatch

	_, err := f.svc.ResolveRecording(f.sessionID, false)
	require.Error(t, err)
	assert.Equal(t, offsite.ErrCodeIntegrityMismatch, offsite.MachineCodeOf(err))
}
