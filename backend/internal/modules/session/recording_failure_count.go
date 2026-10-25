package session

import "github.com/custodexa/backend/internal/model"

// HasRecordingFailure 連線是否有錄影失敗記錄。活動連線的錄影失敗卡與
// 其落點列表共用這個述詞，兩邊的件數因此同源。
func HasRecordingFailure(s *model.Session) bool { return s.RecordingError != "" }

// CountRecordingFailures 計算集合中錄影失敗的連線數。
func CountRecordingFailures(sessions []model.Session) int {
	n := 0
	for i := range sessions {
		if HasRecordingFailure(&sessions[i]) {
			n++
		}
	}
	return n
}
