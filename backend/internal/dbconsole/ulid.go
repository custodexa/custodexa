package dbconsole

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// 執行單位的穩定識別＝ULID：48 位毫秒時戳＋80 位亂數，以 Crockford base32
// 編成 26 個字元。
//
// **為什麼自己實作而不加一個相依**：需要的性質只有三條——固定 26 字元、
// 同一毫秒內不重複、字典序約等於時間序。實作是四十行且無演進需求，
// 而每加一個依賴就要重跑授權盤點、進供應鏈風險面、在升級時被拖著走。
//
// **為什麼不用既有的 UUID**：ULID 的字典序＝時間序，使審計列與轉錄行按 ID
// 排序就是執行順序；UUIDv4 沒有這個性質，而事件 ID 會被人拿去排序。
// 長度也是理由：26 字元的固定形狀讓 DB 端可以用一條 CHECK 釘住它。

// crockfordAlphabet Crockford base32 字母表（去掉 I、L、O、U，
// 避免與 1、0 混淆並避開偶然拼出的髒字）
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ULIDLength 編碼後的字元數。DB 的 CHECK 與匯出 URL 的解析都假設這個長度
const ULIDLength = 26

// ulidState 同毫秒單調性的狀態。
//
// **單調性不是裝飾**：同一次送出的多個批次可能落在同一毫秒，而畫面、轉錄與
// 審計都以事件 ID 排序呈現「先後」。沒有單調保證時，同毫秒的兩個單位排出來
// 的順序是隨機的，讀的人會看到後執行的排在前面。
type ulidState struct {
	mu       sync.Mutex
	lastMS   uint64
	lastRand [10]byte
}

var defaultULIDState ulidState

// NewEventID 產生一個事件 ID。
//
// 同一毫秒內的後續呼叫以「亂數部分加一」保證嚴格遞增（ULID 規範的單調模式）；
// 加一溢位（同一毫秒內產出 2^80 個，實務上不可達）時退回重抽亂數——
// 那時同毫秒的排序失去保證，但 ID 仍然唯一，而唯一性才是 DB 約束在意的事。
func NewEventID() (string, error) {
	return defaultULIDState.next(time.Now())
}

func (s *ulidState) next(now time.Time) (string, error) {
	ms := uint64(now.UnixMilli())

	s.mu.Lock()
	defer s.mu.Unlock()

	// 時戳回退（NTP 校時、閏秒處理）時沿用較大的時戳，其後走同毫秒的加一路徑。
	// **回退不可以重抽亂數**：新抽的亂數有一半機率小於前一個，於是校時之後
	// 產出的事件 ID 會排在校時之前的那些前面——而稽核列就是按這個順序讀的
	if ms < s.lastMS {
		ms = s.lastMS
	}

	var entropy [10]byte
	if ms == s.lastMS {
		entropy = s.lastRand
		if !incrementEntropy(&entropy) {
			if _, err := rand.Read(entropy[:]); err != nil {
				return "", fmt.Errorf("產生事件 ID 亂數失敗: %w", err)
			}
		}
	} else if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("產生事件 ID 亂數失敗: %w", err)
	}
	s.lastMS = ms
	s.lastRand = entropy

	return encodeULID(ms, entropy), nil
}

// incrementEntropy 亂數部分加一（大端序）。回傳 false 代表全 0xFF 溢位。
func incrementEntropy(e *[10]byte) bool {
	for i := len(e) - 1; i >= 0; i-- {
		e[i]++
		if e[i] != 0 {
			return true
		}
	}
	return false
}

// encodeULID 把 48 位時戳與 80 位亂數編成 26 個 Crockford base32 字元。
//
// 逐位元取 5 bit：128 位的來源實際只用了 48+80＝128 位，而 26×5＝130，
// 故最前面兩個 bit 恆為 0（首字元因此落在 `0`–`7`，這是 ULID 的既定形狀）。
func encodeULID(ms uint64, entropy [10]byte) string {
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[0:8], ms<<16)
	copy(raw[6:], entropy[:])

	out := make([]byte, ULIDLength)
	for i := 0; i < ULIDLength; i++ {
		bitPos := i*5 - 2 // 前兩個 bit 是補位的 0
		out[i] = crockfordAlphabet[extract5Bits(raw, bitPos)]
	}
	return string(out)
}

// extract5Bits 自 128 位緩衝取出第 pos 位起的 5 個 bit（pos 可為負，代表左側補 0）。
func extract5Bits(raw [16]byte, pos int) byte {
	var v byte
	for i := 0; i < 5; i++ {
		p := pos + i
		v <<= 1
		if p < 0 || p >= 128 {
			continue
		}
		if raw[p/8]&(1<<(7-uint(p%8))) != 0 {
			v |= 1
		}
	}
	return v
}
