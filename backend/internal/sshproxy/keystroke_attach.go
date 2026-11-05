package sshproxy

import (
	"log"

	"github.com/custodexa/backend/internal/keystroke"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
)

// attachKeystrokeTo 啟動鍵盤紀錄並把 tap 掛上 bridge（須在 Run 前呼叫）。
// 回傳的句柄由呼叫端在 bridge 結束、錄影收尾之後 Close；nil 表示沒有紀錄。
func (h *Handler) attachKeystrokeTo(b *bridge, sess *model.Session, protocol string, kind keystroke.SessionKind) *session.KeystrokeRecorder {
	rec := h.startKeystroke(sess, protocol, kind)
	if rec != nil {
		b.attachKeystroke(newKeystrokeTap(rec))
	}
	return rec
}

// startKeystroke 依涵蓋判定啟動鍵盤紀錄。
//
//   - 不涵蓋的類型寫一筆判定列，回傳 nil
//   - 涵蓋者啟動紀錄；失敗已留下標記並通報，回傳 nil，轉發照常
//
// KeystrokeService 或會話為 nil（既有測試與獨立路徑）時不做任何事。
// 錄影與鍵盤紀錄各自啟動、各自失敗，互不影響。
func (h *Handler) startKeystroke(sess *model.Session, protocol string, kind keystroke.SessionKind) *session.KeystrokeRecorder {
	if h.KeystrokeService == nil || sess == nil {
		return nil
	}
	covered, reason := keystroke.Coverage(kind)
	if !covered {
		if reason == "" {
			return nil
		}
		if err := h.KeystrokeService.RecordNotCovered(sess.ID, protocol, reason); err != nil {
			log.Printf("[SSHProxy] 鍵盤紀錄判定列寫入失敗 (SessionID=%d): %v", sess.ID, err)
		}
		return nil
	}
	rec, err := h.KeystrokeService.Start(sess, protocol)
	if err != nil {
		log.Printf("[SSHProxy] 鍵盤紀錄未啟動，轉發照常 (SessionID=%d)", sess.ID)
		return nil
	}
	return rec
}
