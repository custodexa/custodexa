package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 錄影可讀性的單一判定：本機檔「存在」「是一般檔」「開得了」三項，
// 對外只分不存在（ErrRecordingNotFound）與無法讀取（ErrRecordingUnreadable）。
//
// 權限兩案用真的權限位元：容器內的測試行程是 root 但不具 DAC override，
// chmod 之後確實讀不到。每案先以 requireUnreadable 證明檔案系統真的拒絕，
// 否則測到的會是「可讀」那條分支而非本案要驗的分支。

// newLocalOnlySession 造一場未排入離機的會話，錄影路徑由呼叫端決定。
func newLocalOnlySession(t *testing.T, recordingPath string) (*RecordingService, uint) {
	t.Helper()
	db := setupOffsiteSessionDB(t)
	sess := model.Session{SessionID: "s-readability", UserID: 1, Protocol: model.ProtocolSSH,
		Status: model.SessionStatusClosed, RecordingPath: recordingPath, HasRecording: true}
	require.NoError(t, db.Create(&sess).Error)
	return NewRecordingService(filepath.Dir(recordingPath)), sess.ID
}

// chmodRestore 改權限並在測試結束時改回，讓 t.TempDir 的清理刪得掉。
func chmodRestore(t *testing.T, path string, mode, restore os.FileMode) {
	t.Helper()
	require.NoError(t, os.Chmod(path, mode))
	t.Cleanup(func() { _ = os.Chmod(path, restore) })
}

func requireUnreadable(t *testing.T, path string) {
	t.Helper()
	_, err := os.ReadFile(path)
	require.Error(t, err, "前提不成立：檔案系統沒有拒絕讀取（行程具 DAC override？），本案測不到讀不到的分支")
}

func TestResolveLocalMissingIsNotFound(t *testing.T) {
	dir := t.TempDir()
	svc, id := newLocalOnlySession(t, filepath.Join(dir, "gone.cast"))

	_, err := svc.ResolveRecording(id, false)
	assert.ErrorIs(t, err, ErrRecordingNotFound)
	assert.NotErrorIs(t, err, ErrRecordingUnreadable)
}

func TestResolveLocalDirectoryIsUnreadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session-1.cast")
	require.NoError(t, os.Mkdir(path, 0o755))
	svc, id := newLocalOnlySession(t, path)

	_, err := svc.ResolveRecording(id, false)
	assert.ErrorIs(t, err, ErrRecordingUnreadable, "路徑是目錄不是可交付的錄影")
	assert.NotErrorIs(t, err, ErrRecordingNotFound)
}

func TestResolveLocalWriteOnlyFileIsUnreadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session-1.cast")
	require.NoError(t, os.WriteFile(path, []byte("body"), 0o600))
	chmodRestore(t, path, 0o200, 0o600)
	requireUnreadable(t, path)
	svc, id := newLocalOnlySession(t, path)

	_, err := svc.ResolveRecording(id, false)
	assert.ErrorIs(t, err, ErrRecordingUnreadable, "stat 成功但開不了＝無法讀取")
	assert.NotErrorIs(t, err, ErrRecordingNotFound)
}

func TestResolveLocalStatFailureIsUnreadable(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "locked")
	require.NoError(t, os.Mkdir(parent, 0o755))
	path := filepath.Join(parent, "session-1.cast")
	require.NoError(t, os.WriteFile(path, []byte("body"), 0o600))
	chmodRestore(t, parent, 0o000, 0o755)
	_, statErr := os.Stat(path)
	require.Error(t, statErr, "前提不成立：父目錄 000 仍 stat 得到")
	require.False(t, os.IsNotExist(statErr), "前提不成立：stat 錯誤是「不存在」")
	svc, id := newLocalOnlySession(t, path)

	_, err := svc.ResolveRecording(id, false)
	assert.ErrorIs(t, err, ErrRecordingUnreadable, "stat 的非「不存在」錯誤＝無法讀取")
	assert.NotErrorIs(t, err, ErrRecordingNotFound)
}

// TestResolveOffsiteDirectoryFallsBackUnreadable 已排入離機、本機路徑是目錄：
// 視為本機讀不到，退到離機並記 local_unreadable。
func TestResolveOffsiteDirectoryFallsBackUnreadable(t *testing.T) {
	f := newSourceFixture(t)
	require.NoError(t, os.Remove(f.localPath))
	require.NoError(t, os.Mkdir(f.localPath, 0o755))

	res, err := f.svc.ResolveRecording(f.sessionID, false)
	require.NoError(t, err)
	assert.Equal(t, RecordingSourceOffsite, res.Source)
	assert.Equal(t, FallbackLocalUnreadable, res.Fallback)
	assert.Equal(t, 1, f.stub.fetchCalls)
}

// TestResolveOffsiteUnreadableNoCopyIsUnreadable 本機讀不到而離機沒有副本：
// 回「無法讀取」，不收斂成「不存在」。
func TestResolveOffsiteUnreadableNoCopyIsUnreadable(t *testing.T) {
	f := newSourceFixture(t)
	chmodRestore(t, f.localPath, 0o200, 0o600)
	requireUnreadable(t, f.localPath)
	f.stub.fetchErr = offsite.ErrNoOffsiteCopy

	_, err := f.svc.ResolveRecording(f.sessionID, false)
	assert.ErrorIs(t, err, ErrRecordingUnreadable)
	assert.NotErrorIs(t, err, ErrRecordingNotFound)
	assert.Equal(t, 1, f.stub.fetchCalls)
}

// TestResolveOffsiteMissingNoCopyStaysNotFound 本機缺檔而離機沒有副本：維持「不存在」。
func TestResolveOffsiteMissingNoCopyStaysNotFound(t *testing.T) {
	f := newSourceFixture(t)
	require.NoError(t, os.Remove(f.localPath))
	f.stub.fetchErr = offsite.ErrNoOffsiteCopy

	_, err := f.svc.ResolveRecording(f.sessionID, false)
	assert.ErrorIs(t, err, ErrRecordingNotFound)
}
