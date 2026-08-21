package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
)

func testKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestEnvKEKProviderWrapUnwrapRoundtrip(t *testing.T) {
	p, err := NewEnvKEKProvider(testKey(1))
	if err != nil {
		t.Fatalf("NewEnvKEKProvider: %v", err)
	}

	dek := testKey(9)
	aad := DEKAAD("data", 1)
	wrapped, err := p.Wrap(context.Background(), dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped 內含明文金鑰材料")
	}

	got, err := p.Unwrap(context.Background(), wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("Unwrap 結果與原金鑰不符")
	}
}

func TestEnvKEKProviderKeyID(t *testing.T) {
	p1, _ := NewEnvKEKProvider(testKey(1))
	p1again, _ := NewEnvKEKProvider(testKey(1))
	p2, _ := NewEnvKEKProvider(testKey(2))

	if p1.KeyID() != p1again.KeyID() {
		t.Fatal("同一 KEK 指紋不穩定")
	}
	if p1.KeyID() == p2.KeyID() {
		t.Fatal("不同 KEK 指紋相同")
	}
	if len(p1.KeyID()) != 16 {
		t.Fatalf("指紋長度應為 16 hex 字元，得 %d", len(p1.KeyID()))
	}
}

func TestEnvKEKProviderWrongKEKUnwrapFails(t *testing.T) {
	p1, _ := NewEnvKEKProvider(testKey(1))
	p2, _ := NewEnvKEKProvider(testKey(2))

	aad := DEKAAD("data", 1)
	wrapped, err := p1.Wrap(context.Background(), testKey(9), aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := p2.Unwrap(context.Background(), wrapped, aad); err == nil {
		t.Fatal("錯誤 KEK 解包應失敗")
	}
}

func TestEnvKEKProviderRejectsShortKey(t *testing.T) {
	if _, err := NewEnvKEKProvider([]byte("short")); err == nil {
		t.Fatal("短金鑰應被拒絕")
	}
}

// TestParseEnvelopeStillReadsPreReleaseFormat 解析能力 SHALL 保留
// （release-transitional-cleanup D1）：`enc:v<N>` 的**寫出**能力已刪除，但
// **解析**能力是殘值盤點與退役 DEK 引用掃描的判定基礎——收斂解密不等於收斂解析。
// 本測試以手工字面（非編碼器產出，編碼器已無此能力）餵入。
func TestParseEnvelopeStillReadsPreReleaseFormat(t *testing.T) {
	raw := []byte("nonce-and-ciphertext-bytes")
	s := "enc:v3:" + base64.StdEncoding.EncodeToString(raw)

	version, got, ok, err := ParseEnvelope(s)
	if err != nil || !ok {
		t.Fatalf("ParseEnvelope: ok=%v err=%v", ok, err)
	}
	if version != 3 || !bytes.Equal(got, raw) {
		t.Fatalf("roundtrip 不符: version=%d", version)
	}
}

func TestParseEnvelopeLegacyPassthrough(t *testing.T) {
	// legacy 密文為純 base64，不帶前綴
	version, raw, ok, err := ParseEnvelope("aGVsbG8=")
	if err != nil {
		t.Fatalf("legacy 不應回錯: %v", err)
	}
	if ok || version != 0 || raw != nil {
		t.Fatal("legacy 應回 ok=false")
	}
}

func TestParseEnvelopeMalformed(t *testing.T) {
	cases := []string{
		"enc:v:aGVsbG8=",   // 缺 version
		"enc:vX:aGVsbG8=",  // 非數字 version
		"enc:v-1:aGVsbG8=", // 負 version
		"enc:v1:!!!notb64", // 壞 base64
		"enc:v1",           // 缺冒號與 payload
	}
	for _, c := range cases {
		if _, _, _, err := ParseEnvelope(c); err == nil {
			t.Fatalf("損毀格式應回錯: %q", c)
		}
	}
}

func TestAESCryptoBytesRoundtrip(t *testing.T) {
	c, err := NewAESCrypto(testKey(7))
	if err != nil {
		t.Fatalf("NewAESCrypto: %v", err)
	}
	plain := []byte("bytes-roundtrip")
	aad := DEKAAD("data", 1)
	ct, err := c.EncryptBytesAAD(plain, aad)
	if err != nil {
		t.Fatalf("EncryptBytesAAD: %v", err)
	}
	got, err := c.DecryptBytesAAD(ct, aad)
	if err != nil {
		t.Fatalf("DecryptBytesAAD: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("bytes roundtrip 不符")
	}
}
