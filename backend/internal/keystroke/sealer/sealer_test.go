package sealer

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/custodexa/backend/internal/keystroke/format"
)

func newSuite(t *testing.T) (*Suite, []byte, format.Header) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	var h format.Header
	_, _ = rand.Read(h.NoncePrefix[:])
	h.Protocol = "ssh"
	hb, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSuite(key, h, hb)
	if err != nil {
		t.Fatal(err)
	}
	return s, key, h
}

func TestSealOpenRoundTrip(t *testing.T) {
	s, _, _ := newSuite(t)
	plain := []byte("segment-plaintext-marker")
	frame, err := s.Seal(0, plain, false)
	if err != nil {
		t.Fatal(err)
	}
	var lf [4]byte
	copy(lf[:], frame[:4])
	n, final := ParseLen(lf)
	if final || n != len(frame)-4 {
		t.Fatalf("len field n=%d final=%v", n, final)
	}
	if bytes.Contains(frame, plain) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := s.Open(0, frame[4:], false)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open failed: %v", err)
	}
}

func TestOpenRejectsWrongSeqFinalOrBytes(t *testing.T) {
	s, _, _ := newSuite(t)
	frame, _ := s.Seal(3, []byte("abc"), false)
	ct := frame[4:]
	if _, err := s.Open(4, ct, false); err == nil {
		t.Fatal("wrong seq must fail")
	}
	if _, err := s.Open(3, ct, true); err == nil {
		t.Fatal("wrong final flag must fail")
	}
	bad := append([]byte(nil), ct...)
	bad[0] ^= 1
	if _, err := s.Open(3, bad, false); err == nil {
		t.Fatal("modified byte must fail")
	}
}

func TestEmptyFinalSegment(t *testing.T) {
	s, _, _ := newSuite(t)
	frame, err := s.Seal(0, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var lf [4]byte
	copy(lf[:], frame[:4])
	n, final := ParseLen(lf)
	if !final || n != 16 {
		t.Fatalf("empty final segment: n=%d final=%v", n, final)
	}
	got, err := s.Open(0, frame[4:], true)
	if err != nil || len(got) != 0 {
		t.Fatalf("open empty final: %v", err)
	}
}

func TestNonceUniquePerSeq(t *testing.T) {
	s, _, _ := newSuite(t)
	seen := map[string]bool{}
	for i := uint32(0); i < 1000; i++ {
		n := string(s.nonce(i))
		if seen[n] {
			t.Fatalf("nonce reused at seq %d", i)
		}
		seen[n] = true
	}
}

func TestHeaderBoundIntoAAD(t *testing.T) {
	s, key, h := newSuite(t)
	frame, _ := s.Seal(0, []byte("x"), false)
	h2 := h
	h2.SessionID = 99
	hb2, _ := h2.Encode()
	s2, err := NewSuite(key, h2, hb2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Open(0, frame[4:], false); err == nil {
		t.Fatal("different header must not verify")
	}
}

func TestKeyLen(t *testing.T) {
	var h format.Header
	if _, err := NewSuite(make([]byte, 16), h, nil); err != ErrKeyLen {
		t.Fatalf("got %v", err)
	}
}

// AAD 同時綁定段序號與結束旗標：序號只靠 nonce 區分時，AAD 這一層就失去縱深。
func TestAADBindsSeqAndFinalFlag(t *testing.T) {
	s, _, _ := newSuite(t)
	a := s.aad(1, false)
	if bytes.Equal(a, s.aad(2, false)) {
		t.Fatal("AAD must differ per segment sequence number")
	}
	if bytes.Equal(a, s.aad(1, true)) {
		t.Fatal("AAD must differ by final flag")
	}
	// 以錯誤的 AAD 序號開封必須失敗（直接用 AEAD，繞過 Open 的對稱重算）
	frame, err := s.Seal(1, []byte("payload"), false)
	if err != nil {
		t.Fatal(err)
	}
	ct := frame[4:]
	if _, err := s.aead.Open(nil, s.nonce(1), ct, s.aad(2, false)); err == nil {
		t.Fatal("opening with another sequence AAD must fail")
	}
	if _, err := s.aead.Open(nil, s.nonce(1), ct, s.aad(1, false)); err != nil {
		t.Fatalf("opening with the right AAD must succeed: %v", err)
	}
}
