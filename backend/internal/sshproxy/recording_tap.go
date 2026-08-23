package sshproxy

import (
	"log"
	"os"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/recorder"
)

// recordingTap 將 asciicast 錄製器掛上 bridge 旁路。
// 只錄輸出方向（"o" 事件）與尺寸變更（"r" 事件）。
// 錄製失敗不影響轉發主路徑（fail-close 只掛簽發點），但不得沉默——
// 首個失敗經 onFailure 通報一次（標記＋告警）
type recordingTap struct {
	rec       *recorder.AsciicastRecorder
	startTime time.Time

	failOnce  sync.Once
	onFailure func(causeCode string, params map[string]string)
}

// newRecordingTap 啟動錄製；失敗回傳錯誤（呼叫端跳過掛載並通報，不斷線）
func newRecordingTap(basePath string, sessionID uint, cols, rows int) (*recordingTap, error) {
	rec := recorder.NewAsciicastRecorder(basePath)
	startTime := time.Now()

	metadata := recorder.RecordingMetadata{
		SessionID: sessionID,
		Protocol:  string(model.ProtocolSSH),
		Width:     cols,
		Height:    rows,
		Env:       map[string]string{"TERM": defaultTerm},
		StartTime: startTime,
	}
	if err := rec.Start(metadata); err != nil {
		log.Printf("[SSHProxy] 啟動錄製失敗 (SessionID=%d): %v（繼續連線）", sessionID, err)
		return nil, err
	}

	return &recordingTap{rec: rec, startTime: startTime}, nil
}

// SetOnFailure 註冊失敗通報回呼（只會觸發一次），並接上 recorder 的
// autoFlush 錯誤 latch——閒置會話的磁碟錯誤同樣浮出
func (t *recordingTap) SetOnFailure(cb func(causeCode string, params map[string]string)) {
	t.onFailure = cb
	t.rec.SetOnError(func(err error) {
		t.fail(model.CauseRecordingFlushFailed, err)
	})
}

// fail 首個失敗通報一次。causeCode 為 model.Cause* 機器碼，
// 底層 err 原文以 forensic detail 參數承載，不再組成散文 cause
func (t *recordingTap) fail(causeCode string, err error) {
	t.failOnce.Do(func() {
		params := map[string]string{}
		if err != nil {
			params[model.CauseParamDetail] = err.Error()
		}
		log.Printf("[SSHProxy] 錄製失敗偵測: %s (%v)", causeCode, err)
		if t.onFailure != nil {
			t.onFailure(causeCode, params)
		}
	})
}

func (t *recordingTap) WriteOutput(p []byte) {
	if err := t.rec.WriteOutput(time.Since(t.startTime), p); err != nil {
		t.fail(model.CauseRecordingWriteFailed, err)
	}
}

func (t *recordingTap) Resize(cols, rows int) {
	if err := t.rec.WriteResize(time.Since(t.startTime), cols, rows); err != nil {
		t.fail(model.CauseRecordingResizeWriteFailed, err)
	}
}

// Close 停止錄製並更新 Session 錄製資訊
func (t *recordingTap) Close(sessionService *session.SessionService, sessionID uint) {
	if err := t.rec.Stop(); err != nil {
		log.Printf("[SSHProxy] 停止錄製失敗 (SessionID=%d): %v", sessionID, err)
		t.fail(model.CauseRecordingStopFailed, err)
		return
	}

	filePath := t.rec.GetFilePath()
	if filePath == "" {
		return
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Printf("[SSHProxy] 取得錄製檔案大小失敗: %v", err)
		t.fail(model.CauseRecordingFileStatFailed, err)
		return
	}

	if err := sessionService.UpdateRecording(sessionID, filePath, fileInfo.Size()); err != nil {
		log.Printf("[SSHProxy] 更新錄製資訊失敗 (SessionID=%d): %v", sessionID, err)
		t.fail(model.CauseRecordingMetadataUpdateFailed, err)
		return
	}
	log.Printf("[SSHProxy] 錄製已完成: SessionID=%d, Path=%s, Size=%d", sessionID, filePath, fileInfo.Size())
}
