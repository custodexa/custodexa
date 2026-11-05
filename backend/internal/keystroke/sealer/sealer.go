// Package sealer 實作鍵盤紀錄檔的分段 AEAD。
//
// 檔案＝標頭＋若干段。段框架：4-byte 大端長度欄＋密文（含 GCM tag）。
// 長度欄最高位元為結束旗標，其餘 31 位元為密文長度。
// nonce＝標頭的 8-byte 前綴＋4-byte 段序號；
// AAD＝SHA256(標頭位元組)＋段序號(4 bytes)＋結束旗標(1 byte)。
// 因此改位元組、交換或刪除段、改結束旗標都會使該段驗證失敗。
package sealer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/custodexa/backend/internal/keystroke/format"
)

const (
	finalBit = uint32(1) << 31
	// MaxFrame 為單段密文長度上限（防長度欄被濫用）。
	MaxFrame = 1 << 28
)

var (
	ErrKeyLen   = errors.New("keystroke sealer: key must be 32 bytes")
	ErrTooLarge = errors.New("keystroke sealer: segment too large")
	ErrSeqEnd   = errors.New("keystroke sealer: segment sequence exhausted")
)

// Suite 綁定一組金鑰與一個標頭，可封段與開段。
type Suite struct {
	aead       cipher.AEAD
	prefix     [format.NonceLen]byte
	headerHash [sha256.Size]byte
}

// NewSuite 以 32-byte 金鑰與已編碼的標頭位元組建立。
func NewSuite(key []byte, hdr format.Header, hdrBytes []byte) (*Suite, error) {
	if len(key) != 32 {
		return nil, ErrKeyLen
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Suite{aead: aead, prefix: hdr.NoncePrefix, headerHash: sha256.Sum256(hdrBytes)}, nil
}

func (s *Suite) nonce(seq uint32) []byte {
	n := make([]byte, 0, 12)
	n = append(n, s.prefix[:]...)
	return binary.BigEndian.AppendUint32(n, seq)
}

func (s *Suite) aad(seq uint32, final bool) []byte {
	a := make([]byte, 0, sha256.Size+5)
	a = append(a, s.headerHash[:]...)
	a = binary.BigEndian.AppendUint32(a, seq)
	if final {
		return append(a, 1)
	}
	return append(a, 0)
}

// Seal 回傳完整的段框架（長度欄＋密文）。
func (s *Suite) Seal(seq uint32, plain []byte, final bool) ([]byte, error) {
	if seq == ^uint32(0) {
		return nil, ErrSeqEnd
	}
	ctLen := len(plain) + s.aead.Overhead()
	if ctLen >= MaxFrame {
		return nil, ErrTooLarge
	}
	frame := make([]byte, 4, 4+ctLen)
	l := uint32(ctLen)
	if final {
		l |= finalBit
	}
	binary.BigEndian.PutUint32(frame, l)
	return s.aead.Seal(frame, s.nonce(seq), plain, s.aad(seq, final)), nil
}

// Open 驗證並解開一段密文；final 取自段框架長度欄。
func (s *Suite) Open(seq uint32, ct []byte, final bool) ([]byte, error) {
	return s.aead.Open(nil, s.nonce(seq), ct, s.aad(seq, final))
}

// ParseLen 拆解長度欄。
func ParseLen(field [4]byte) (ctLen int, final bool) {
	v := binary.BigEndian.Uint32(field[:])
	return int(v &^ finalBit), v&finalBit != 0
}

// Syncer 為可 fsync 的寫入端（os.File）。
type Syncer interface{ Sync() error }

// WriteFrame 寫出一個段框架；寫入端支援 Sync 時於寫完後 fsync。
func WriteFrame(w io.Writer, frame []byte) error {
	if _, err := w.Write(frame); err != nil {
		return err
	}
	if sy, ok := w.(Syncer); ok {
		return sy.Sync()
	}
	return nil
}
