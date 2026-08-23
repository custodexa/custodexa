package sealjournal

import (
	"testing"
)

// TestHeaderRoundTrip 驗證 header 編解碼對稱，且 CRC32C 能偵測任一位元翻動。
func TestHeaderRoundTrip(t *testing.T) {
	h := &header{
		Generation:         42,
		SeqNext:            7,
		CriticalWriteIndex: 5,
		RejectedWriteIndex: 2,
		Live: counters{
			Received: 6, Published: 1, Success: 1, MaterialFail: 2,
			InitFail: 1, Timeout: 1, Aborted: 1,
			RejectedCooldown: 10, RejectedBackoff: 11, RejectedConflict: 12,
			RejectedObserved: 33, RejectedDurable: 33,
			RejectedOverwritten: 4, CriticalOverwritten: 3,
		},
		ReplaySnap:                  counters{Received: 2},
		CriticalOverwrittenFirstSeq: 1,
		CriticalOverwrittenLastSeq:  3,
		FirstEventTS:                111,
		LastEventTS:                 222,
		ReplayCheckpointSeq:         4,
		ReplayedEvents:              9,
		ReplayedBatches:             2,
		CriticalSlotCount:           64,
		RejectedSlotCount:           16,
		CriticalSlotSize:            criticalSlotSize,
		RejectedSlotSize:            rejectedSlotSize,
		CriticalRingOffset:          uint64(criticalRingOffset),
		RejectedRingOffset:          9999,
		FileSize:                    19456,
	}
	buf := encodeHeader(h)
	if len(buf) != headerSlotSize {
		t.Fatalf("header 槽長度應為 %d，得 %d", headerSlotSize, len(buf))
	}
	got, err := decodeHeader(buf)
	if err != nil {
		t.Fatalf("解碼失敗: %v", err)
	}
	if *got != *h {
		t.Fatalf("編解碼不對稱:\nwant %+v\ngot  %+v", *h, *got)
	}

	buf[100] ^= 0x01
	if _, err := decodeHeader(buf); err != errSlotCorrupt {
		t.Fatalf("位元翻動應被 CRC 偵測，得 %v", err)
	}

	zero := make([]byte, headerSlotSize)
	if _, err := decodeHeader(zero); err != errSlotEmpty {
		t.Fatalf("全零槽應判為空（不得因 CRC 恰好為 0 而誤判有效），得 %v", err)
	}
}

// TestCriticalSlotRoundTrip 驗證事件槽含齊佈局要求的欄位並可偵測 torn write。
func TestCriticalSlotRoundTrip(t *testing.T) {
	s := &criticalSlot{
		Kind:         slotKindOutcome,
		Seq:          12,
		Gen:          3,
		SlotIndex:    77,
		TSUnixNano:   1690000000000000000,
		BootID:       [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SourceDigest: testDigest,
		Outcome:      OutcomeMaterialFailure,
	}
	buf := encodeCriticalSlot(s)
	if len(buf) != criticalSlotSize {
		t.Fatalf("槽長度應為 %d，得 %d", criticalSlotSize, len(buf))
	}
	got, err := decodeCriticalSlot(buf)
	if err != nil {
		t.Fatalf("解碼失敗: %v", err)
	}
	if *got != *s {
		t.Fatalf("編解碼不對稱:\nwant %+v\ngot  %+v", *s, *got)
	}

	buf[70] ^= 0xFF
	if _, err := decodeCriticalSlot(buf); err != errSlotCorrupt {
		t.Fatalf("torn write 應被 CRC 偵測，得 %v", err)
	}
	if _, err := decodeCriticalSlot(make([]byte, criticalSlotSize)); err != errSlotEmpty {
		t.Fatal("未寫入的槽應判為空")
	}
}

// TestRejectedSlotRoundTrip 驗證合批槽編解碼。
func TestRejectedSlotRoundTrip(t *testing.T) {
	s := &rejectedSlot{
		BatchIndex: 4,
		Cooldown:   10,
		Backoff:    20,
		Conflict:   30,
		FirstTS:    100,
		LastTS:     200,
		BootID:     [16]byte{9},
	}
	buf := encodeRejectedSlot(s)
	got, err := decodeRejectedSlot(buf)
	if err != nil {
		t.Fatalf("解碼失敗: %v", err)
	}
	if *got != *s {
		t.Fatalf("編解碼不對稱:\nwant %+v\ngot  %+v", *s, *got)
	}
	buf[20] ^= 0x02
	if _, err := decodeRejectedSlot(buf); err != errSlotCorrupt {
		t.Fatalf("位元翻動應被 CRC 偵測，得 %v", err)
	}
}

// TestLayoutOffsetsAreFixedAndNonOverlapping 驗證固定佈局：
// 兩個 header 槽 → critical 環 → rejected 環，且檔案大小僅由容量決定。
func TestLayoutOffsetsAreFixedAndNonOverlapping(t *testing.T) {
	l := layout{criticalSlots: 8, rejectedSlots: 4}
	if criticalRingOffset != int64(headerSlotSize*headerSlotCount) {
		t.Fatal("critical 環起點必須緊接兩個 header 槽")
	}
	if l.rejectedRingOffset() != criticalRingOffset+8*criticalSlotSize {
		t.Fatalf("rejected 環起點錯誤: %d", l.rejectedRingOffset())
	}
	if l.fileSize() != l.rejectedRingOffset()+4*rejectedSlotSize {
		t.Fatalf("檔案大小錯誤: %d", l.fileSize())
	}
	// 環繞：索引取模，偏移必落在環內。
	if l.criticalOffset(8) != l.criticalOffset(0) {
		t.Fatal("critical 環未正確取模")
	}
	if l.rejectedOffset(4) != l.rejectedOffset(0) {
		t.Fatal("rejected 環未正確取模")
	}
	if got := headerSlotOffset(1); got != headerSlotSize {
		t.Fatalf("header 槽必須依 generation 奇偶輪替，得 %d", got)
	}
	if headerSlotOffset(2) != 0 {
		t.Fatal("header 槽輪替錯誤")
	}
}

// TestCountersDelta 驗證聚合列所需的計數器差額計算。
func TestCountersDelta(t *testing.T) {
	live := counters{Received: 10, RejectedCooldown: 5}
	base := counters{Received: 4, RejectedCooldown: 5}
	d := live.sub(base)
	if d.Received != 6 || d.RejectedCooldown != 0 {
		t.Fatalf("差額錯誤: %+v", d)
	}
	if d.isZero() {
		t.Fatal("有差額時 isZero 不得為真")
	}
	if !live.sub(live).isZero() {
		t.Fatal("相同快照的差額應為零")
	}
}
