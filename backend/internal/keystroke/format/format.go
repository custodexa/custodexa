// Package format 定義鍵盤紀錄檔的標頭與事件編碼。
//
// 檔案＝明文標頭＋若干加密段（段框架見 sealer）。標頭的 SHA-256 進每段 AAD，
// 因此標頭受認證。段內明文是事件序列，每筆事件：
//
//	delta  uvarint  相對起點的毫秒數（單調時鐘）
//	kind   1 byte   0x01 位元組流；0x02 keysym；0x03 無法解析的圖形按鍵；0x10 標記；其他值保留
//	flags  1 byte   bit0 platform（平台送出）、bit1 blocked（已阻斷、未送出）
//	len    uvarint  payload 長度
//	data   len bytes
//
// 所有 kind 共用同一個 payload 框架，讀取器遇到不認得的 kind 時保留原始位元組並續解。
package format

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// 檔頭常數。
const (
	Magic         = "CXKR"
	Version  byte = 1
	NonceLen      = 8
	UUIDLen       = 16
)

// 事件種類。0x02、0x03 為圖形協定（RDP、VNC）的按鍵事件。
const (
	KindBytes  byte = 0x01
	KindKeysym byte = 0x02
	// KindKeysymRaw 無法解析的圖形按鍵：payload＝uvarint 長度＋原始參數字串。
	KindKeysymRaw byte = 0x03
	KindMarker    byte = 0x10
)

// 事件旗標。
const (
	FlagPlatform byte = 1 << 0
	FlagBlocked  byte = 1 << 1
	flagsKnown        = FlagPlatform | FlagBlocked
)

// 上限：避免讀取器被惡意長度欄誘導配置大量記憶體。
const (
	MaxProtocolLen = 32
	MaxPayload     = 64 << 20
)

// Header 為檔案標頭。
type Header struct {
	RecordUUID  [UUIDLen]byte
	SessionID   uint64
	Protocol    string
	StartUnixNs int64
	SegmentMax  uint32
	NoncePrefix [NonceLen]byte
}

var (
	ErrShortHeader = errors.New("keystroke format: short header")
	ErrBadMagic    = errors.New("keystroke format: bad magic")
	ErrBadVersion  = errors.New("keystroke format: unsupported version")
	ErrBadHeader   = errors.New("keystroke format: malformed header")
	ErrBadEvent    = errors.New("keystroke format: malformed event")
)

// Encode 序列化標頭。
func (h Header) Encode() ([]byte, error) {
	if len(h.Protocol) > MaxProtocolLen {
		return nil, fmt.Errorf("keystroke format: protocol too long")
	}
	var b bytes.Buffer
	b.WriteString(Magic)
	b.WriteByte(Version)
	b.Write(h.RecordUUID[:])
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], h.SessionID)
	b.Write(n[:])
	b.WriteByte(byte(len(h.Protocol)))
	b.WriteString(h.Protocol)
	binary.BigEndian.PutUint64(n[:], uint64(h.StartUnixNs))
	b.Write(n[:])
	var s [4]byte
	binary.BigEndian.PutUint32(s[:], h.SegmentMax)
	b.Write(s[:])
	b.Write(h.NoncePrefix[:])
	return b.Bytes(), nil
}

// DecodeHeader 自位元組開頭解出標頭，回傳標頭與其占用的位元組數。
func DecodeHeader(p []byte) (Header, int, error) {
	var h Header
	const fixedHead = len(Magic) + 1 + UUIDLen + 8 + 1
	if len(p) < fixedHead {
		return h, 0, ErrShortHeader
	}
	if string(p[:len(Magic)]) != Magic {
		return h, 0, ErrBadMagic
	}
	if p[len(Magic)] != Version {
		return h, 0, ErrBadVersion
	}
	off := len(Magic) + 1
	copy(h.RecordUUID[:], p[off:off+UUIDLen])
	off += UUIDLen
	h.SessionID = binary.BigEndian.Uint64(p[off : off+8])
	off += 8
	pl := int(p[off])
	off++
	if pl > MaxProtocolLen {
		return h, 0, ErrBadHeader
	}
	tail := pl + 8 + 4 + NonceLen
	if len(p) < off+tail {
		return h, 0, ErrShortHeader
	}
	h.Protocol = string(p[off : off+pl])
	off += pl
	h.StartUnixNs = int64(binary.BigEndian.Uint64(p[off : off+8]))
	off += 8
	h.SegmentMax = binary.BigEndian.Uint32(p[off : off+4])
	off += 4
	copy(h.NoncePrefix[:], p[off:off+NonceLen])
	off += NonceLen
	return h, off, nil
}

// Event 為一筆解碼後的事件。Known 為 false 表示 kind 不認得，Payload 為原始位元組。
type Event struct {
	DeltaMs uint64
	Kind    byte
	Flags   byte
	Payload []byte
	Known   bool
}

// AppendEvent 將事件編碼附加到 dst。
func AppendEvent(dst []byte, deltaMs uint64, kind, flags byte, payload []byte) []byte {
	dst = binary.AppendUvarint(dst, deltaMs)
	dst = append(dst, kind, flags)
	dst = binary.AppendUvarint(dst, uint64(len(payload)))
	return append(dst, payload...)
}

// DecodeEvents 解出一段明文內的全部事件。
func DecodeEvents(seg []byte) ([]Event, error) {
	var out []Event
	for len(seg) > 0 {
		delta, n := binary.Uvarint(seg)
		if n <= 0 {
			return out, ErrBadEvent
		}
		seg = seg[n:]
		if len(seg) < 2 {
			return out, ErrBadEvent
		}
		kind, flags := seg[0], seg[1]
		seg = seg[2:]
		ln, n := binary.Uvarint(seg)
		if n <= 0 || ln > MaxPayload || uint64(len(seg)-n) < ln {
			return out, ErrBadEvent
		}
		seg = seg[n:]
		payload := make([]byte, ln)
		copy(payload, seg[:ln])
		seg = seg[ln:]
		out = append(out, Event{
			DeltaMs: delta, Kind: kind, Flags: flags & flagsKnown, Payload: payload,
			Known: kind == KindBytes || kind == KindKeysym || kind == KindKeysymRaw || kind == KindMarker,
		})
	}
	return out, nil
}

// KeysymPayloadLen 為 KindKeysym payload 長度：uint32 keysym（big-endian）＋1 byte 按放。
const KeysymPayloadLen = 5

// EncodeKeysym 組出 KindKeysym 的 payload。pressed 為 true 記 1（按下），否則 0（放開）。
func EncodeKeysym(keysym uint32, pressed bool) []byte {
	p := make([]byte, KeysymPayloadLen)
	binary.BigEndian.PutUint32(p, keysym)
	if pressed {
		p[4] = 1
	}
	return p
}

// DecodeKeysym 解出 KindKeysym 的 payload；長度或按放欄位不合回 ErrBadEvent。
func DecodeKeysym(p []byte) (keysym uint32, pressed bool, err error) {
	if len(p) != KeysymPayloadLen || p[4] > 1 {
		return 0, false, ErrBadEvent
	}
	return binary.BigEndian.Uint32(p), p[4] == 1, nil
}

// EncodeKeysymRaw 組出 KindKeysymRaw 的 payload：uvarint 長度＋原始參數字串位元組。
func EncodeKeysymRaw(raw []byte) []byte {
	out := binary.AppendUvarint(make([]byte, 0, len(raw)+binary.MaxVarintLen64), uint64(len(raw)))
	return append(out, raw...)
}

// DecodeKeysymRaw 解出 KindKeysymRaw 的 payload；長度欄與實際位元組數不符回 ErrBadEvent。
func DecodeKeysymRaw(p []byte) ([]byte, error) {
	ln, n := binary.Uvarint(p)
	if n <= 0 || uint64(len(p)-n) != ln {
		return nil, ErrBadEvent
	}
	return append([]byte(nil), p[n:]...), nil
}
