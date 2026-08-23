package proxy

import (
	"encoding/base64"
	"log"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/guacamole"
	"gorm.io/gorm"
)

// clipboardMaxBytes 單筆留存上限：超出即截斷丟棄後續
const clipboardMaxBytes = 64 * 1024

// ClipboardTap 重組 guacamole clipboard 流並留存（clipboard-audit）：
// 觀察 clipboard/blob/end 指令，僅 text/* mimetype；入庫失敗不影響會話
type ClipboardTap struct {
	db        *gorm.DB
	sessionID uint
	direction string // send / recv
	streams   map[string]*clipboardStream
}

type clipboardStream struct {
	textual   bool
	buf       strings.Builder
	truncated bool
}

// NewClipboardTap 建立單方向的剪貼簿觀察器
func NewClipboardTap(db *gorm.DB, sessionID uint, direction string) *ClipboardTap {
	return &ClipboardTap{
		db:        db,
		sessionID: sessionID,
		direction: direction,
		streams:   make(map[string]*clipboardStream),
	}
}

// Observe 觀察一條指令；非剪貼簿相關指令為 no-op
func (t *ClipboardTap) Observe(inst *guacamole.Instruction) {
	if t == nil || t.db == nil || t.sessionID == 0 {
		return
	}
	switch inst.Opcode {
	case "clipboard":
		// args: [stream_index, mimetype]
		if len(inst.Args) >= 2 {
			t.streams[inst.Args[0]] = &clipboardStream{
				textual: strings.HasPrefix(inst.Args[1], "text/"),
			}
		}
	case "blob":
		// args: [stream_index, base64data]
		if len(inst.Args) >= 2 {
			s, ok := t.streams[inst.Args[0]]
			if !ok || !s.textual || s.truncated {
				return
			}
			data, err := base64.StdEncoding.DecodeString(inst.Args[1])
			if err != nil {
				return
			}
			remain := clipboardMaxBytes - s.buf.Len()
			if len(data) > remain {
				data = data[:remain]
				s.truncated = true
			}
			s.buf.Write(data)
		}
	case "end":
		// args: [stream_index]
		if len(inst.Args) >= 1 {
			s, ok := t.streams[inst.Args[0]]
			if !ok {
				return
			}
			delete(t.streams, inst.Args[0])
			if !s.textual || s.buf.Len() == 0 {
				return
			}
			event := &model.ClipboardEvent{
				SessionID: t.sessionID,
				Direction: t.direction,
				Content:   s.buf.String(),
			}
			// 審計旁路 async 入庫：失敗僅記 log，不回壓會話
			db := t.db
			go func() {
				if err := db.Create(event).Error; err != nil {
					log.Printf("[ClipboardTap] 留存失敗: session=%d err=%v", event.SessionID, err)
				}
			}()
		}
	}
}
