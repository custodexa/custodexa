package proxy

import (
	"context"
	"encoding/base64"
	"log"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/guacamole"
	"gorm.io/gorm"
)

// clipboardMaxBytes 單筆留存上限：超出即截斷丟棄後續
const clipboardMaxBytes = 64 * 1024

// ClipboardEncryptor 剪貼簿內容的加密函式。
//
// 窄函式型別而非 crypto.ColumnCodec：tap 只需要「綁定 RefClipboardContent 的
// 加密」這一件事，欄位身分（CipherRef）由組裝根在建構時封進閉包，
// proxy 層自此拿不到「加密到別的欄」的能力。
type ClipboardEncryptor func(ctx context.Context, plaintext string) (string, error)

// ClipboardTap 重組 guacamole clipboard 流並留存（clipboard-audit）：
// 觀察 clipboard/blob/end 指令，僅 text/* mimetype；入庫失敗不影響會話。
//
// **落庫即密文**：內容經 encrypt 加密後寫 content_enc，明文不落庫。
// 加密失敗＝留**缺口紀錄**（會話、方向、時間、長度齊備，內容缺席、
// content_status=failed）——不明文降級、不中斷會話、不整筆丟棄，
// 使「此類永不清除、空白即無事件」的誠實宣稱不被靜默缺口打破。
type ClipboardTap struct {
	db        *gorm.DB
	encrypt   ClipboardEncryptor
	sessionID uint
	direction string // send / recv
	streams   map[string]*clipboardStream
}

type clipboardStream struct {
	textual   bool
	buf       strings.Builder
	truncated bool
}

// NewClipboardTap 建立單方向的剪貼簿觀察器。
// encrypt 為 nil 時視同每筆加密失敗（留缺口紀錄）——組裝缺線是 fail-visible
// 的缺口，不是明文降級的許可。
func NewClipboardTap(db *gorm.DB, encrypt ClipboardEncryptor, sessionID uint, direction string) *ClipboardTap {
	return &ClipboardTap{
		db:        db,
		encrypt:   encrypt,
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
			t.persist(s.buf.String())
		}
	}
}

// persist 加密後 async 入庫（審計旁路：失敗僅記 log，不回壓會話）。
//
// 加密與寫庫都在 goroutine 內：EncryptFor 會過 keyvault 讀鎖，放在 Observe
// 同步路徑上會把金鑰層的任何停頓傳導成會話卡頓。goroutine 帶 recover——
// 旁路功能沒有終止行程的權力（sidecar 紅線）。
func (t *ClipboardTap) persist(text string) {
	event := &model.ClipboardEvent{
		SessionID:     t.sessionID,
		Direction:     t.direction,
		ContentLength: len(text),
		ContentStatus: model.ClipboardContentAvailable,
	}
	db, encrypt := t.db, t.encrypt
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[ClipboardTap] 留存路徑 panic（已攔截，會話不受影響）: session=%d err=%v",
					event.SessionID, r)
			}
		}()
		if encrypt == nil {
			// 組裝缺線＝加密不可用：留缺口，不明文降級
			event.ContentStatus = model.ClipboardContentFailed
			log.Printf("[ClipboardTap] 加密器未注入，留存缺口紀錄: session=%d direction=%s len=%d",
				event.SessionID, event.Direction, event.ContentLength)
		} else if enc, err := encrypt(context.Background(), text); err != nil {
			// 加密失敗＝缺口紀錄：事實齊、內容缺、失敗標記
			event.ContentStatus = model.ClipboardContentFailed
			log.Printf("[ClipboardTap] 加密失敗，留存缺口紀錄: session=%d direction=%s len=%d err=%v",
				event.SessionID, event.Direction, event.ContentLength, err)
		} else {
			event.ContentEnc = enc
		}
		if err := db.Create(event).Error; err != nil {
			log.Printf("[ClipboardTap] 留存失敗: session=%d err=%v", event.SessionID, err)
		}
	}()
}
