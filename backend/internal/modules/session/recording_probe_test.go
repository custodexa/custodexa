package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 詳情頁的唯讀探測：不取回離機副本、不讀錄影內容。
// 每一案都斷言 Fetch 呼叫數為 0——開詳情頁觸發一次完整下載是本探測要防的事。

// probeRetriever 假的離機面：帳冊列可設、可回錯；Fetch 只計數。
type probeRetriever struct {
	row        *model.OffsiteObject
	objectErr  error
	fetchCalls int
}

func (p *probeRetriever) Object(uint) (*model.OffsiteObject, error) {
	if p.objectErr != nil {
		return nil, p.objectErr
	}
	return p.row, nil
}

func (p *probeRetriever) Fetch(context.Context, uint) (*offsite.FetchedObject, error) {
	p.fetchCalls++
	return nil, errors.New("探測不得取回離機副本")
}

func probeSession(path string, offsiteID *uint) *model.Session {
	return &model.Session{ID: 7, HasRecording: true, RecordingPath: path, OffsiteObjectID: offsiteID}
}

// localVariant 在 dir 造出指定狀態的本機錄影路徑。
func localVariant(t *testing.T, dir, kind string) string {
	t.Helper()
	path := filepath.Join(dir, "session-7.cast")
	switch kind {
	case "available":
		require.NoError(t, os.WriteFile(path, []byte("body"), 0o600))
	case "missing":
	case "writeonly":
		require.NoError(t, os.WriteFile(path, []byte("body"), 0o600))
		chmodRestore(t, path, 0o200, 0o600)
		requireUnreadable(t, path)
	case "directory":
		require.NoError(t, os.Mkdir(path, 0o755))
	default:
		t.Fatalf("未知變體 %q", kind)
	}
	return path
}

// TestProbeRecordingStateLocalOnly 未排入離機：可讀、缺檔、0200、目錄各回對應值。
func TestProbeRecordingStateLocalOnly(t *testing.T) {
	cases := []struct {
		kind, state, source string
	}{
		{"available", RecordingStateAvailable, RecordingSourceLocal},
		{"missing", RecordingStateMissing, ""},
		{"writeonly", RecordingStateUnreadable, ""},
		{"directory", RecordingStateUnreadable, ""},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			stub := &probeRetriever{row: &model.OffsiteObject{}}
			svc := NewRecordingService(t.TempDir())
			svc.SetOffsiteRetriever(stub)
			got, ok := svc.ProbeRecordingState(probeSession(localVariant(t, t.TempDir(), tc.kind), nil))
			require.True(t, ok)
			assert.Equal(t, RecordingProbe{State: tc.state, Source: tc.source}, got)
			assert.Zero(t, stub.fetchCalls)
		})
	}
}

// TestProbeRecordingStateOffsite 已排入離機：只讀帳冊列，不呼叫 Fetch。
func TestProbeRecordingStateOffsite(t *testing.T) {
	uploaded := &model.OffsiteObject{State: offsite.StateUploaded, ObjectKey: "k/7", SHA256: "abc", Size: 4}
	noCopy := &model.OffsiteObject{State: offsite.StateFailed}
	mismatch := &model.OffsiteObject{State: offsite.StateIntegrityMismatch, ObjectKey: "k/7", SHA256: "abc", Size: 4}
	cases := []struct {
		name      string
		local     string
		row       *model.OffsiteObject
		objectErr error
		want      RecordingProbe
		wantOK    bool
	}{
		{"本機缺檔＋帳冊有副本", "missing", uploaded, nil,
			RecordingProbe{State: RecordingStateAvailable, Source: RecordingSourceOffsite}, true},
		{"本機缺檔＋無副本", "missing", noCopy, nil, RecordingProbe{State: RecordingStateMissing}, true},
		{"本機 0200＋無副本", "writeonly", noCopy, nil, RecordingProbe{State: RecordingStateUnreadable}, true},
		{"帳冊完整性不符", "missing", mismatch, nil, RecordingProbe{State: RecordingStateUnreadable}, true},
		{"帳冊查詢失敗", "missing", nil, errors.New("db down"), RecordingProbe{}, false},
		{"本機可讀不查帳冊", "available", nil, errors.New("不該被查"),
			RecordingProbe{State: RecordingStateAvailable, Source: RecordingSourceLocal}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &probeRetriever{row: tc.row, objectErr: tc.objectErr}
			svc := NewRecordingService(t.TempDir())
			svc.SetOffsiteRetriever(stub)
			objID := uint(77)
			got, ok := svc.ProbeRecordingState(probeSession(localVariant(t, t.TempDir(), tc.local), &objID))
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
			assert.Zero(t, stub.fetchCalls, "詳情探測不得觸發離機取回")
		})
	}
}

// TestProbeRecordingStateNoRecording has_recording=false：不探測、不下結論。
func TestProbeRecordingStateNoRecording(t *testing.T) {
	svc := NewRecordingService(t.TempDir())
	_, ok := svc.ProbeRecordingState(&model.Session{ID: 1, HasRecording: false, RecordingPath: "/nonexistent"})
	assert.False(t, ok)
}
