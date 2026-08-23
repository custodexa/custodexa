package crypto

import "testing"

// TestFingerprintVector 固定測試向量：鎖定 hex 小寫、SHA-256 前 8 bytes 截斷方向、
// 輸出長度（三鑰共用，避免日後漂移）
func TestFingerprintVector(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// SHA-256("") = e3b0c44298fc1c14...；前 8 bytes hex
		{"", "e3b0c44298fc1c14"},
		// SHA-256("abc") = ba7816bf8f01cfea...
		{"abc", "ba7816bf8f01cfea"},
	}
	for _, c := range cases {
		if got := Fingerprint([]byte(c.in)); got != c.want {
			t.Fatalf("Fingerprint(%q)=%q want %q", c.in, got, c.want)
		}
	}
	// 恆為 16 hex chars（8 bytes）
	if got := Fingerprint([]byte("anything")); len(got) != 16 {
		t.Fatalf("指紋應為 16 hex chars，得 %d", len(got))
	}
}

// TestFingerprintMatchesKEKKeyID KEK KeyID 與 Fingerprint 對同一材料一致（值相容）
func TestFingerprintMatchesKEKKeyID(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x5A
	}
	p, err := NewEnvKEKProvider(key)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	if p.KeyID() != Fingerprint(key) {
		t.Fatalf("KEK KeyID %q != Fingerprint %q", p.KeyID(), Fingerprint(key))
	}
}
