package session

import (
	"errors"
	"log"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
)

// 會話詳情的錄影可讀狀態（`GET /sessions/:id` 的 `recording_state`）。
const (
	RecordingStateAvailable  = "available"
	RecordingStateMissing    = "missing"
	RecordingStateUnreadable = "unreadable"
)

// RecordingProbe 詳情頁的錄影可讀判定結果。Source 只在 Available 時有值（local／offsite）。
type RecordingProbe struct {
	State  string
	Source string
}

// ProbeRecordingState 詳情頁用的**唯讀探測**：只回答「現在讀得到嗎、從哪裡讀」，
// 不交付、不取回。
//
// 與 resolveFor 刻意分開：後者在本機讀不到時會同步自離機取回整份副本，
// 開一次詳情頁不該觸發一次完整下載。本函式不發網路請求、不讀錄影內容：
//
//  1. 本機檔存在、是一般檔、開得了（開即關）→ available／local
//  2. 否則已排入離機：只讀帳冊列。有已上傳的副本且未判完整性不符 → available／offsite；
//     完整性不符 → unreadable；沒有副本 → 依本機狀況 missing／unreadable
//  3. 未排入離機：本機缺檔 missing，其餘 unreadable
//
// 第二個回傳值為 false 表示無法下結論（例如帳冊查詢失敗）：此時說 unreadable
// 可能是假的，呼叫端應省略欄位。會話沒有錄影時同樣回 false。
func (s *RecordingService) ProbeRecordingState(sess *model.Session) (RecordingProbe, bool) {
	if sess == nil || !sess.HasRecording || sess.RecordingPath == "" {
		return RecordingProbe{}, false
	}

	localState := probeLocalRecording(sess.RecordingPath)
	if localState == RecordingStateAvailable {
		return RecordingProbe{State: RecordingStateAvailable, Source: RecordingSourceLocal}, true
	}

	if s.offsite == nil || sess.OffsiteObjectID == nil {
		return RecordingProbe{State: localState}, true
	}

	row, err := s.offsite.Object(*sess.OffsiteObjectID)
	if err != nil || row == nil {
		log.Printf("[RecordingService] 詳情探測無法下結論（session=%d，object=%d）: %v",
			sess.ID, *sess.OffsiteObjectID, err)
		return RecordingProbe{}, false
	}
	if row.State == offsite.StateIntegrityMismatch {
		return RecordingProbe{State: RecordingStateUnreadable}, true
	}
	if row.ObjectKey != "" && row.SHA256 != "" {
		return RecordingProbe{State: RecordingStateAvailable, Source: RecordingSourceOffsite}, true
	}
	return RecordingProbe{State: localState}, true
}

// probeLocalRecording 本機檔的三項檢查（存在、是一般檔、開得了），開即關、不讀內容。
func probeLocalRecording(path string) string {
	f, _, err := OpenRecordingFile(path)
	if err != nil {
		if errors.Is(err, ErrRecordingNotFound) {
			return RecordingStateMissing
		}
		return RecordingStateUnreadable
	}
	f.Close()
	return RecordingStateAvailable
}
