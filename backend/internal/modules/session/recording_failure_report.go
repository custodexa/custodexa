package session

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"log"
	"strconv"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// ReportSessionRecordingFailure 錄影失敗三位一體（recording-failure-handling D3）：
// sessions 首因標記（已有標記不覆蓋——最早的失敗最接近根因）＋per-session
// 審計列（主軌逐筆可追溯；失效事件表同機制去重，第二個以上失敗 session
// 的事實靠本列）＋失效事件/告警（機制族 recording_* 各自去重與恢復配對）。
// 簽發點（無 session）只走失效事件，不經本函式。
//
// causeCode 為 model.Cause* 常數；params 承載結構化細節（底層 err 原文放
// model.CauseParamDetail）。**sessions.recording_error 自 M5 起存碼不存散文**
// （backend-i18n-unification D8），前端按碼查譯；audit_logs.Details 維持
// forensic 原文（zh 短語＋detail），不碼化
func ReportSessionRecordingFailure(sessionID uint, mechanism, causeCode string, params map[string]string) {
	if err := database.DB.Model(&model.Session{}).
		Where("id = ? AND (recording_error IS NULL OR recording_error = '')", sessionID).
		Update("recording_error", causeCode).Error; err != nil {
		log.Printf("[Recording] 標記錄影失敗資訊失敗 (SessionID=%d): %v", sessionID, err)
	}

	// 審計列以 session 擁有者掛名（誰的操作軌跡缺失）；查不到時退 system
	var ownerID uint
	database.DB.Model(&model.Session{}).Select("user_id").
		Where("id = ?", sessionID).Scan(&ownerID)
	username := "system"
	if ownerID != 0 {
		var name string
		database.DB.Model(&model.User{}).Select("username").
			Where("id = ?", ownerID).Scan(&name)
		if name != "" {
			username = name
		}
	}
	sid := sessionID
	entry := &model.AuditLog{
		Action:     model.ActionRecordingFailed,
		Resource:   model.ResourceSession,
		ResourceID: &sid,
		Status:     model.StatusFailure,
		UserID:     ownerID,
		Username:   username,
		Details:    audit.CauseText(causeCode, params),
	}
	if err := database.DB.Create(entry).Error; err != nil {
		log.Printf("[Recording] 錄影失敗審計留痕失敗 (SessionID=%d): %v", sessionID, err)
	}

	if failure := audit.GetAuditFailure(); failure != nil {
		// session_id 併入 cause 參數：機制族事件表同機制去重，
		// 首個失敗 session 的歸屬靠此欄（原以 "SessionID=%d: " 前綴散文承載）
		failure.Report(mechanism, causeCode, withSessionID(params, sessionID))
	}
}

// withSessionID 複製 params 並補上 session_id（不改動呼叫端傳入的 map）
func withSessionID(params map[string]string, sessionID uint) map[string]string {
	out := make(map[string]string, len(params)+1)
	for k, v := range params {
		out[k] = v
	}
	out["session_id"] = strconv.FormatUint(uint64(sessionID), 10)
	return out
}
