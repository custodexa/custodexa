package format

import (
	"bytes"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	h := Header{SessionID: 42, Protocol: "ssh", StartUnixNs: 1700000000123456789, SegmentMax: 16384}
	for i := range h.RecordUUID {
		h.RecordUUID[i] = byte(i + 1)
	}
	copy(h.NoncePrefix[:], []byte{9, 8, 7, 6, 5, 4, 3, 2})
	enc, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, n, err := DecodeHeader(append(enc, 0xAA, 0xBB))
	if err != nil || n != len(enc) {
		t.Fatalf("decode err=%v n=%d want=%d", err, n, len(enc))
	}
	if got != h {
		t.Fatalf("header mismatch")
	}
	if _, _, err := DecodeHeader(enc[:len(enc)-1]); err != ErrShortHeader {
		t.Fatalf("short header: got %v", err)
	}
	bad := append([]byte(nil), enc...)
	bad[0] = 'X'
	if _, _, err := DecodeHeader(bad); err != ErrBadMagic {
		t.Fatalf("bad magic: got %v", err)
	}
	bad = append([]byte(nil), enc...)
	bad[4] = 9
	if _, _, err := DecodeHeader(bad); err != ErrBadVersion {
		t.Fatalf("bad version: got %v", err)
	}
}

func TestEventRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		delta   uint64
		kind    byte
		flags   byte
		payload []byte
		known   bool
	}{
		{"arbitrary binary", 0, KindBytes, 0, []byte{0x00, 0xff, 0x1b, 0x03, 0x7f}, true},
		{"non utf8", 5, KindBytes, 0, []byte{0xc3, 0x28, 0xa0, 0xa1, 0xe2, 0x28, 0xa1}, true},
		{"empty payload", 1 << 20, KindBytes, 0, nil, true},
		{"platform flag", 7, KindBytes, FlagPlatform, []byte{0x03}, true},
		{"blocked flag", 8, KindBytes, FlagBlocked, []byte("x\r"), true},
		{"both flags", 9, KindBytes, FlagPlatform | FlagBlocked, []byte("y"), true},
		{"marker", 10, KindMarker, 0, []byte("session_end"), true},
		{"keysym press", 12, KindKeysym, 0, EncodeKeysym(0x61, true), true},
		{"keysym release max", 13, KindKeysym, 0, EncodeKeysym(0xFFFFFFFF, false), true},
		{"keysym unicode", 14, KindKeysym, 0, EncodeKeysym(0x01000000+0x4E2D, true), true},
		{"keysym raw empty", 15, KindKeysymRaw, 0, EncodeKeysymRaw(nil), true},
		{"keysym raw non utf8", 16, KindKeysymRaw, 0, EncodeKeysymRaw([]byte{0xc3, 0x28, 0xff}), true},
		{"unknown kind", 11, 0x7e, 0, []byte{1, 2, 3}, false},
	}
	var seg []byte
	for _, c := range cases {
		seg = AppendEvent(seg, c.delta, c.kind, c.flags, c.payload)
	}
	evs, err := DecodeEvents(seg)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != len(cases) {
		t.Fatalf("event count %d want %d", len(evs), len(cases))
	}
	for i, c := range cases {
		e := evs[i]
		if e.DeltaMs != c.delta || e.Kind != c.kind || e.Flags != c.flags || e.Known != c.known ||
			!bytes.Equal(e.Payload, c.payload) {
			t.Fatalf("case %q mismatch", c.name)
		}
	}
	// 未知 kind 之後的事件仍可續解（上面最後一筆之後再接一筆已驗證順序；此處驗中間插入）
	seg = AppendEvent(nil, 1, 0x7e, 0, []byte{9})
	seg = AppendEvent(seg, 2, KindBytes, 0, []byte("after"))
	evs, err = DecodeEvents(seg)
	if err != nil || len(evs) != 2 || evs[0].Known || !evs[1].Known {
		t.Fatalf("unknown kind must not stop decoding")
	}
}

func TestDecodeEventsMalformed(t *testing.T) {
	seg := AppendEvent(nil, 1, KindBytes, 0, []byte("abc"))
	if _, err := DecodeEvents(seg[:len(seg)-1]); err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

func TestKeysymPayloads(t *testing.T) {
	for _, ks := range []uint32{0, 0x61, 0xFF0D, 0x01000000 + 0x4E2D, 0xFFFFFFFF} {
		for _, pressed := range []bool{true, false} {
			got, p, err := DecodeKeysym(EncodeKeysym(ks, pressed))
			if err != nil || got != ks || p != pressed {
				t.Fatalf("keysym roundtrip failed for width/pressed=%v", pressed)
			}
		}
	}
	for _, bad := range [][]byte{nil, {1, 2, 3, 4}, {0, 0, 0, 1, 2}, {0, 0, 0, 1, 1, 0}} {
		if _, _, err := DecodeKeysym(bad); err != ErrBadEvent {
			t.Fatalf("bad keysym payload accepted: len=%d", len(bad))
		}
	}
	for _, raw := range [][]byte{nil, {}, []byte("1,2"), {0xc3, 0x28, 0xff}, bytes.Repeat([]byte{'a'}, 300)} {
		got, err := DecodeKeysymRaw(EncodeKeysymRaw(raw))
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("raw roundtrip failed len=%d", len(raw))
		}
	}
	for _, bad := range [][]byte{nil, {5, 'a'}, {1, 'a', 'b'}} {
		if _, err := DecodeKeysymRaw(bad); err != ErrBadEvent {
			t.Fatalf("bad raw payload accepted: len=%d", len(bad))
		}
	}
}
