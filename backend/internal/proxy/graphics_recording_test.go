package proxy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/recorder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 圖形錄影落地鏈的回歸測試（change graphics-teardown-sync，design D8 第 4 類）。
//
// 這四條守的是**失效通報不得沉默**：落地鏈四條失敗路徑各自要報出對應的 cause。
// 每條斷言的是「回報了哪一個 cause」，不是「沒 panic」——後者在注入根本沒觸發時
// 一樣會綠（memory: fault-injection-never-fired），故每條都先確認注入真的成立。

// recordingProbe 收集落地鏈對外的三個作用，供斷言。
type recordingProbe struct {
	failures      []recordedFailure
	resolved      int
	updates       []recordedUpdate
	updateErr     error
	statOverride  func(name string) (os.FileInfo, error)
	statCallCount int
}

type recordedFailure struct {
	sessionID uint
	cause     string
	params    map[string]string
}

type recordedUpdate struct {
	sessionID uint
	path      string
	size      int64
}

func (p *recordingProbe) deps() graphicsRecordingDeps {
	return graphicsRecordingDeps{
		stat: func(name string) (os.FileInfo, error) {
			p.statCallCount++
			if p.statOverride != nil {
				return p.statOverride(name)
			}
			return os.Stat(name)
		},
		rename: os.Rename,
		updateRecording: func(sessionID uint, path string, size int64) error {
			p.updates = append(p.updates, recordedUpdate{sessionID, path, size})
			return p.updateErr
		},
		reportFailure: func(sessionID uint, cause string, params map[string]string) {
			p.failures = append(p.failures, recordedFailure{sessionID, cause, params})
		},
		resolve: func() { p.resolved++ },
	}
}

// onlyCause 斷言恰好回報了一次、且是指定的 cause。
func (p *recordingProbe) onlyCause(t *testing.T, want string) recordedFailure {
	t.Helper()
	require.Len(t, p.failures, 1, "應恰好回報一次失效（%d 次）", len(p.failures))
	assert.Equal(t, want, p.failures[0].cause)
	assert.Zero(t, p.resolved, "失敗路徑不得同時呼叫 Resolve——那會自打嘴巴（一邊報失敗一邊報恢復）")
	return p.failures[0]
}

const testRecordingName = "rdp-1700000000000000000"

// TestGraphicsRecordingFinalizeSuccess temp 存在且更名成功：
// 大小入庫、Resolve 被呼叫、零失效通報。
func TestGraphicsRecordingFinalizeSuccess(t *testing.T) {
	base := t.TempDir()
	temp := recorder.GraphicsTempRecordingPath(base, testRecordingName)
	payload := []byte("4.sync,13.1700000000000;")
	require.NoError(t, os.WriteFile(temp, payload, 0o600))

	p := &recordingProbe{}
	finalizeGraphicsRecording(42, base, testRecordingName, p.deps())

	assert.Empty(t, p.failures, "成功路徑不得有失效通報")
	assert.Equal(t, 1, p.resolved, "錄影確認落地必須呼叫 Resolve 關閉圖形路徑的失效事件")
	require.Len(t, p.updates, 1)
	assert.Equal(t, uint(42), p.updates[0].sessionID)
	assert.Equal(t, filepath.Join(base, "session-42.guac"), p.updates[0].path,
		"落檔路徑必須經 recorder 收口點組出（保留期清理端以此字串精確比對）")
	assert.Equal(t, int64(len(payload)), p.updates[0].size)

	// 注入確認：temp 真的被搬走了，不是「什麼都沒做也會綠」
	_, err := os.Stat(temp)
	assert.True(t, os.IsNotExist(err), "更名成功後 temp 檔應已不存在")
	_, err = os.Stat(p.updates[0].path)
	assert.NoError(t, err, "更名後的檔案應存在")
}

// TestGraphicsRecordingFinalizeRenameFailed 更名失敗 → CauseRecordingRenameFailed。
//
// 注入方式：在目標路徑先放一個**非空目錄**。rename(檔案, 目錄) 在 Linux 上必失敗
// （EISDIR/ENOTEMPTY），且不受「容器內以 root 執行」影響——用 chmod 去掉寫權限的作法
// 在 root 下會被繞過，那樣注入不會觸發、測試會假綠。
func TestGraphicsRecordingFinalizeRenameFailed(t *testing.T) {
	base := t.TempDir()
	temp := recorder.GraphicsTempRecordingPath(base, testRecordingName)
	require.NoError(t, os.WriteFile(temp, []byte("x"), 0o600))

	target := recorder.GraphicsRecordingPath(base, 42)
	require.NoError(t, os.Mkdir(target, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(target, "occupied"), []byte("x"), 0o600))

	// 注入是否真的會觸發：目標必須是非空目錄
	info, err := os.Stat(target)
	require.NoError(t, err)
	require.True(t, info.IsDir(), "注入未成立：目標不是目錄，rename 會成功而本測試恆綠")
	require.Error(t, os.Rename(temp, target), "注入未成立：rename 竟然成功")
	require.FileExists(t, temp, "預跑的 rename 不應搬走 temp 檔")

	p := &recordingProbe{}
	finalizeGraphicsRecording(42, base, testRecordingName, p.deps())

	f := p.onlyCause(t, model.CauseRecordingRenameFailed)
	assert.Equal(t, uint(42), f.sessionID)
	assert.NotEmpty(t, f.params[model.CauseParamDetail], "底層錯誤原文須帶進 detail 供 forensic")
	assert.Empty(t, p.updates, "更名失敗後不得回寫 metadata")
}

// TestGraphicsRecordingFinalizeStatFailed 更名成功但取大小失敗 →
// CauseRecordingFileStatFailed。
//
// 真實檔案系統上這條只發生於 rename 與 stat 之間檔案被移走的競態，無法穩定重現，
// 故以注入的 stat 失敗覆蓋：第一次 stat（temp 存在性）走真實檔案系統，
// 第二次（更名後取大小）回錯。
func TestGraphicsRecordingFinalizeStatFailed(t *testing.T) {
	base := t.TempDir()
	temp := recorder.GraphicsTempRecordingPath(base, testRecordingName)
	require.NoError(t, os.WriteFile(temp, []byte("x"), 0o600))

	wantErr := errors.New("injected stat failure")
	p := &recordingProbe{}
	p.statOverride = func(name string) (os.FileInfo, error) {
		if p.statCallCount >= 2 {
			return nil, wantErr
		}
		return os.Stat(name)
	}

	finalizeGraphicsRecording(42, base, testRecordingName, p.deps())

	// 注入是否真的觸發：必須走到第二次 stat（＝更名確實成功了）
	require.GreaterOrEqual(t, p.statCallCount, 2,
		"注入未觸發：只 stat 了 %d 次，表示在更名前就早退，本測試沒測到 stat 失敗路徑", p.statCallCount)

	f := p.onlyCause(t, model.CauseRecordingFileStatFailed)
	assert.Equal(t, wantErr.Error(), f.params[model.CauseParamDetail])
	assert.Empty(t, p.updates, "取大小失敗後不得回寫 metadata")
}

// TestGraphicsRecordingFinalizeMetadataUpdateFailed metadata 回寫失敗 →
// CauseRecordingMetadataUpdateFailed。落地鏈第四個回報點，與上三條同族不可漏。
func TestGraphicsRecordingFinalizeMetadataUpdateFailed(t *testing.T) {
	base := t.TempDir()
	temp := recorder.GraphicsTempRecordingPath(base, testRecordingName)
	require.NoError(t, os.WriteFile(temp, []byte("xyz"), 0o600))

	p := &recordingProbe{updateErr: errors.New("injected db failure")}
	finalizeGraphicsRecording(42, base, testRecordingName, p.deps())

	// 注入是否真的觸發：必須真的呼叫過 updateRecording
	require.Len(t, p.updates, 1, "注入未觸發：updateRecording 根本沒被呼叫")

	f := p.onlyCause(t, model.CauseRecordingMetadataUpdateFailed)
	assert.Equal(t, "injected db failure", f.params[model.CauseParamDetail])
}

// TestGraphicsRecordingFinalizeFileMissing temp 不存在 → CauseRecordingFileMissing。
//
// guacd 錄影失敗不回傳協議層（fail-open），會後檔案存在性是 backend 唯一偵測點，
// 缺檔必須標記＋告警，不得沉默。
func TestGraphicsRecordingFinalizeFileMissing(t *testing.T) {
	base := t.TempDir()

	// 注入是否真的成立：檔案確實不存在
	_, err := os.Stat(recorder.GraphicsTempRecordingPath(base, testRecordingName))
	require.True(t, os.IsNotExist(err), "注入未成立：temp 檔竟然存在")

	p := &recordingProbe{}
	finalizeGraphicsRecording(42, base, testRecordingName, p.deps())

	f := p.onlyCause(t, model.CauseRecordingFileMissing)
	assert.Nil(t, f.params, "缺檔沒有底層錯誤可帶，params 維持 nil（與既有語義一致）")
	assert.Empty(t, p.updates)
}
