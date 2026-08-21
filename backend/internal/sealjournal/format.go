package sealjournal

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// 本檔定義封印期 journal 的磁碟佈局（D6.5）。
// 佈局為段 1 預配置的定長檔案，永不成長：
//
//	[Header A | Header B]  雙槽輪替，各含 generation ＋ CRC32C
//	[critical ring]        定長槽陣列（received／outcome／published）
//	[rejected ring]        定長槽陣列（cooldown／backoff／conflict 合批）
//
// 崩潰一致性採 body-first／commit-last：先寫資料槽並 fdatasync，
// 再把 header 寫到「另一個」槽（generation+1）並 fdatasync。
// 任何時刻至少有一個 generation 較舊但完整的 header 可用。

const (
	// headerMagic 與 slot magic 用於區分「已寫入」與「預配置的全零」區域。
	// 全零槽的 CRC32C 亦為 0，若無 magic 便會被誤判為有效槽。
	headerMagic   uint64 = 0x5345414C4A524E31 // "SEALJRN1"
	criticalMagic uint32 = 0x53434A31         // "SCJ1"
	rejectedMagic uint32 = 0x53524A31         // "SRJ1"

	// formatVersion 為槽與 header 的格式版本，遞增即代表不相容。
	formatVersion uint16 = 1

	headerSlotSize  = 512
	headerSlotCount = 2

	// criticalRingOffset 為固定佈局偏移：兩個 header 槽之後即 critical 環。
	criticalRingOffset = int64(headerSlotSize * headerSlotCount)

	criticalSlotSize = 256
	rejectedSlotSize = 128

	// DefaultCriticalSlots／DefaultRejectedSlots 為預設環容量。
	// critical 4096 槽 × 256B = 1 MiB；rejected 1024 槽 × 128B = 128 KiB。
	DefaultCriticalSlots = 4096
	DefaultRejectedSlots = 1024

	// critical 槽內可變區的容量（扣除固定表頭與尾端 CRC）。
	criticalPayloadOffset = 64
	criticalPayloadCap    = criticalSlotSize - criticalPayloadOffset - 4

	maxSourceDigestLen = 64
	maxOutcomeLen      = 32
)

// 事件種類（critical 環）。
const (
	KindReceived  = "received"
	KindOutcome   = "outcome"
	KindPublished = "published"
)

// outcome 結果碼值域（D6.5，五類）。
const (
	OutcomeSuccess         = "success"
	OutcomeMaterialFailure = "material_failure"
	OutcomeInitFailed      = "init_failed"
	OutcomeTimeout         = "timeout"
	OutcomeAborted         = "aborted"
)

// rejected 環的被拒種類。
const (
	RejectedCooldown = "cooldown"
	RejectedBackoff  = "backoff"
	RejectedConflict = "conflict"
)

const (
	slotKindReceived  uint8 = 1
	slotKindOutcome   uint8 = 2
	slotKindPublished uint8 = 3
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var (
	errSlotEmpty   = errors.New("sealjournal: 槽為空")
	errSlotCorrupt = errors.New("sealjournal: 槽 CRC 不符（torn write 或竄改）")
)

// layout 描述一份 journal 檔的固定佈局。所有偏移與長度在建立時決定並寫入 header，
// 開檔時逐項比對；任一項不合即 fail-close（D6.5 (i-b)）。
type layout struct {
	criticalSlots int
	rejectedSlots int
}

func (l layout) criticalOffset(index uint64) int64 {
	return criticalRingOffset + int64(index%uint64(l.criticalSlots))*criticalSlotSize
}

func (l layout) rejectedRingOffset() int64 {
	return criticalRingOffset + int64(l.criticalSlots)*criticalSlotSize
}

func (l layout) rejectedOffset(index uint64) int64 {
	return l.rejectedRingOffset() + int64(index%uint64(l.rejectedSlots))*rejectedSlotSize
}

func (l layout) fileSize() int64 {
	return l.rejectedRingOffset() + int64(l.rejectedSlots)*rejectedSlotSize
}

// counters 為單調計數器組。header 內存兩份：Live（當前值）與
// ReplaySnap（上次回灌成功時的快照），兩者相減即聚合審計列所需的「計數器差額」。
type counters struct {
	Received     uint64
	Published    uint64
	Success      uint64
	MaterialFail uint64
	InitFail     uint64
	Timeout      uint64
	Aborted      uint64

	RejectedCooldown uint64
	RejectedBackoff  uint64
	RejectedConflict uint64
	RejectedObserved uint64
	RejectedDurable  uint64

	RejectedOverwritten uint64
	CriticalOverwritten uint64
}

func (c *counters) fields() []*uint64 {
	return []*uint64{
		&c.Received, &c.Published, &c.Success, &c.MaterialFail, &c.InitFail,
		&c.Timeout, &c.Aborted,
		&c.RejectedCooldown, &c.RejectedBackoff, &c.RejectedConflict,
		&c.RejectedObserved, &c.RejectedDurable,
		&c.RejectedOverwritten, &c.CriticalOverwritten,
	}
}

// sub 回傳 c 相對於 base 的差額（單調計數器，故不會為負）。
func (c counters) sub(base counters) counters {
	out := counters{}
	cf, bf, of := c.fields(), base.fields(), out.fields()
	for i := range cf {
		if *cf[i] >= *bf[i] {
			*of[i] = *cf[i] - *bf[i]
		}
	}
	return out
}

func (c counters) isZero() bool {
	for _, p := range c.fields() {
		if *p != 0 {
			return false
		}
	}
	return true
}

// header 為 journal 的控制區。單調計數器與 checkpoint 均存於此，
// 因此 header 一旦兩槽皆毀即 fail-close，絕不重建（重建＝把歷史歸零）。
type header struct {
	JournalUUID [16]byte
	Generation  uint64
	SeqNext     uint64

	CriticalWriteIndex uint64
	RejectedWriteIndex uint64

	Live       counters
	ReplaySnap counters

	CriticalOverwrittenFirstSeq uint64
	CriticalOverwrittenLastSeq  uint64

	FirstEventTS int64
	LastEventTS  int64

	ReplayCheckpointSeq uint64
	ReplayedEvents      uint64
	ReplayedBatches     uint64

	CriticalSlotCount  uint64
	RejectedSlotCount  uint64
	CriticalSlotSize   uint32
	RejectedSlotSize   uint32
	CriticalRingOffset uint64
	RejectedRingOffset uint64
	FileSize           uint64
}

func (h *header) layout() layout {
	return layout{criticalSlots: int(h.CriticalSlotCount), rejectedSlots: int(h.RejectedSlotCount)}
}

// encodeHeader 將 header 序列化為定長槽（尾端 4 bytes 為 CRC32C）。
func encodeHeader(h *header) []byte {
	buf := make([]byte, headerSlotSize)
	e := &encoder{buf: buf}
	e.u64(headerMagic)
	e.u16(formatVersion)
	e.u16(0)
	e.u32(0)
	e.bytes(h.JournalUUID[:])
	for _, v := range []uint64{
		h.Generation, h.SeqNext,
		h.CriticalWriteIndex, h.RejectedWriteIndex,
	} {
		e.u64(v)
	}
	for _, p := range h.Live.fields() {
		e.u64(*p)
	}
	for _, p := range h.ReplaySnap.fields() {
		e.u64(*p)
	}
	e.u64(h.CriticalOverwrittenFirstSeq)
	e.u64(h.CriticalOverwrittenLastSeq)
	e.i64(h.FirstEventTS)
	e.i64(h.LastEventTS)
	for _, v := range []uint64{
		h.ReplayCheckpointSeq, h.ReplayedEvents, h.ReplayedBatches,
		h.CriticalSlotCount, h.RejectedSlotCount,
	} {
		e.u64(v)
	}
	e.u32(h.CriticalSlotSize)
	e.u32(h.RejectedSlotSize)
	e.u64(h.CriticalRingOffset)
	e.u64(h.RejectedRingOffset)
	e.u64(h.FileSize)

	binary.LittleEndian.PutUint32(buf[headerSlotSize-4:], crc32.Checksum(buf[:headerSlotSize-4], castagnoli))
	return buf
}

// decodeHeader 解析 header 槽；magic／版本／CRC 任一不符即回錯（視為該槽無效）。
func decodeHeader(buf []byte) (*header, error) {
	if len(buf) != headerSlotSize {
		return nil, errSlotCorrupt
	}
	d := &decoder{buf: buf}
	if d.u64() != headerMagic {
		return nil, errSlotEmpty
	}
	if d.u16() != formatVersion {
		return nil, errSlotCorrupt
	}
	want := binary.LittleEndian.Uint32(buf[headerSlotSize-4:])
	if crc32.Checksum(buf[:headerSlotSize-4], castagnoli) != want {
		return nil, errSlotCorrupt
	}
	d.u16()
	d.u32()
	h := &header{}
	copy(h.JournalUUID[:], d.next(16))
	ptrs := []*uint64{&h.Generation, &h.SeqNext, &h.CriticalWriteIndex, &h.RejectedWriteIndex}
	ptrs = append(ptrs, h.Live.fields()...)
	ptrs = append(ptrs, h.ReplaySnap.fields()...)
	ptrs = append(ptrs, &h.CriticalOverwrittenFirstSeq, &h.CriticalOverwrittenLastSeq)
	for _, p := range ptrs {
		*p = d.u64()
	}
	h.FirstEventTS = d.i64()
	h.LastEventTS = d.i64()
	for _, p := range []*uint64{
		&h.ReplayCheckpointSeq, &h.ReplayedEvents, &h.ReplayedBatches,
		&h.CriticalSlotCount, &h.RejectedSlotCount,
	} {
		*p = d.u64()
	}
	h.CriticalSlotSize = d.u32()
	h.RejectedSlotSize = d.u32()
	h.CriticalRingOffset = d.u64()
	h.RejectedRingOffset = d.u64()
	h.FileSize = d.u64()
	return h, nil
}

// criticalSlot 為 critical 環的單一事件槽。
// 每槽含格式版本／boot ID／全域序號／事件種類／長度／時間／來源摘要／CRC32C（D6.5）。
type criticalSlot struct {
	Kind         uint8
	Seq          uint64
	Gen          uint64
	SlotIndex    uint64
	TSUnixNano   int64
	BootID       [16]byte
	SourceDigest string
	Outcome      string
}

func encodeCriticalSlot(s *criticalSlot) []byte {
	buf := make([]byte, criticalSlotSize)
	e := &encoder{buf: buf}
	e.u32(criticalMagic)
	e.u16(formatVersion)
	e.u8(s.Kind)
	e.u8(0)
	e.u64(s.Seq)
	e.u64(s.Gen)
	e.u64(s.SlotIndex)
	e.i64(s.TSUnixNano)
	e.bytes(s.BootID[:])
	payload := append([]byte(s.SourceDigest), []byte(s.Outcome)...)
	e.u16(uint16(len(payload)))
	e.u16(uint16(len(s.SourceDigest)))
	e.u16(uint16(len(s.Outcome)))
	e.u16(0)
	copy(buf[criticalPayloadOffset:criticalPayloadOffset+criticalPayloadCap], payload)
	binary.LittleEndian.PutUint32(buf[criticalSlotSize-4:], crc32.Checksum(buf[:criticalSlotSize-4], castagnoli))
	return buf
}

func decodeCriticalSlot(buf []byte) (*criticalSlot, error) {
	if len(buf) != criticalSlotSize {
		return nil, errSlotCorrupt
	}
	d := &decoder{buf: buf}
	if d.u32() != criticalMagic {
		if isZero(buf) {
			return nil, errSlotEmpty
		}
		return nil, errSlotCorrupt
	}
	if d.u16() != formatVersion {
		return nil, errSlotCorrupt
	}
	want := binary.LittleEndian.Uint32(buf[criticalSlotSize-4:])
	if crc32.Checksum(buf[:criticalSlotSize-4], castagnoli) != want {
		return nil, errSlotCorrupt
	}
	s := &criticalSlot{}
	s.Kind = d.u8()
	d.u8()
	s.Seq = d.u64()
	s.Gen = d.u64()
	s.SlotIndex = d.u64()
	s.TSUnixNano = d.i64()
	copy(s.BootID[:], d.next(16))
	total := int(d.u16())
	digestLen := int(d.u16())
	outcomeLen := int(d.u16())
	if total > criticalPayloadCap || digestLen+outcomeLen != total {
		return nil, errSlotCorrupt
	}
	payload := buf[criticalPayloadOffset : criticalPayloadOffset+total]
	s.SourceDigest = string(payload[:digestLen])
	s.Outcome = string(payload[digestLen:])
	return s, nil
}

// rejectedSlot 為 rejected 環的合批聚合槽。
// 被拒嘗試不逐筆 pwrite，改以定長記憶體聚合器按固定頻率合批（D6.5 同步分級）。
type rejectedSlot struct {
	BatchIndex uint64
	Cooldown   uint64
	Backoff    uint64
	Conflict   uint64
	FirstTS    int64
	LastTS     int64
	BootID     [16]byte
}

func encodeRejectedSlot(s *rejectedSlot) []byte {
	buf := make([]byte, rejectedSlotSize)
	e := &encoder{buf: buf}
	e.u32(rejectedMagic)
	e.u16(formatVersion)
	e.u16(0)
	e.u64(s.BatchIndex)
	e.u64(s.Cooldown)
	e.u64(s.Backoff)
	e.u64(s.Conflict)
	e.i64(s.FirstTS)
	e.i64(s.LastTS)
	e.bytes(s.BootID[:])
	binary.LittleEndian.PutUint32(buf[rejectedSlotSize-4:], crc32.Checksum(buf[:rejectedSlotSize-4], castagnoli))
	return buf
}

func decodeRejectedSlot(buf []byte) (*rejectedSlot, error) {
	if len(buf) != rejectedSlotSize {
		return nil, errSlotCorrupt
	}
	d := &decoder{buf: buf}
	if d.u32() != rejectedMagic {
		if isZero(buf) {
			return nil, errSlotEmpty
		}
		return nil, errSlotCorrupt
	}
	if d.u16() != formatVersion {
		return nil, errSlotCorrupt
	}
	want := binary.LittleEndian.Uint32(buf[rejectedSlotSize-4:])
	if crc32.Checksum(buf[:rejectedSlotSize-4], castagnoli) != want {
		return nil, errSlotCorrupt
	}
	d.u16()
	s := &rejectedSlot{}
	s.BatchIndex = d.u64()
	s.Cooldown = d.u64()
	s.Backoff = d.u64()
	s.Conflict = d.u64()
	s.FirstTS = d.i64()
	s.LastTS = d.i64()
	copy(s.BootID[:], d.next(16))
	return s, nil
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// encoder／decoder 為小型定序編解碼游標，避免手算偏移出錯。
type encoder struct {
	buf []byte
	off int
}

func (e *encoder) u8(v uint8) {
	e.buf[e.off] = v
	e.off++
}

func (e *encoder) u16(v uint16) {
	binary.LittleEndian.PutUint16(e.buf[e.off:], v)
	e.off += 2
}

func (e *encoder) u32(v uint32) {
	binary.LittleEndian.PutUint32(e.buf[e.off:], v)
	e.off += 4
}

func (e *encoder) u64(v uint64) {
	binary.LittleEndian.PutUint64(e.buf[e.off:], v)
	e.off += 8
}

func (e *encoder) i64(v int64) { e.u64(uint64(v)) }

func (e *encoder) bytes(b []byte) {
	copy(e.buf[e.off:], b)
	e.off += len(b)
}

type decoder struct {
	buf []byte
	off int
}

func (d *decoder) u8() uint8 {
	v := d.buf[d.off]
	d.off++
	return v
}

func (d *decoder) u16() uint16 {
	v := binary.LittleEndian.Uint16(d.buf[d.off:])
	d.off += 2
	return v
}

func (d *decoder) u32() uint32 {
	v := binary.LittleEndian.Uint32(d.buf[d.off:])
	d.off += 4
	return v
}

func (d *decoder) u64() uint64 {
	v := binary.LittleEndian.Uint64(d.buf[d.off:])
	d.off += 8
	return v
}

func (d *decoder) i64() int64 { return int64(d.u64()) }

func (d *decoder) next(n int) []byte {
	v := d.buf[d.off : d.off+n]
	d.off += n
	return v
}
