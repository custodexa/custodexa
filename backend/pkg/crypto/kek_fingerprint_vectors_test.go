package crypto

import (
	"bufio"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kekFingerprintVectors 主金鑰指紋的已知答案向量（32 bytes 材料 → 指紋）。
// 期望值寫死；同一組向量輸出在管理腳本測試的 fixture，由下方測試比對兩邊一致。
var kekFingerprintVectors = []struct {
	label    string
	material []byte
	want     string
}{
	{"zeros", make([]byte, 32), "66687aadf862bd77"},
	{"ascending", func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}(), "630dcd2966c43366"},
	{"ff", func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = 0xff
		}
		return b
	}(), "af9613760f72635f"},
	{"fill5a", func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = 0x5a
		}
		return b
	}(), "60bf07c488aad18f"},
}

// TestKEKFingerprintVectors 鎖定指紋算法與 KEK provider 的 KeyID，並確認腳本端讀的
// fixture 與後端算出的完全一致。
func TestKEKFingerprintVectors(t *testing.T) {
	for _, v := range kekFingerprintVectors {
		if got := Fingerprint(v.material); got != v.want {
			t.Errorf("%s: Fingerprint=%q want %q", v.label, got, v.want)
		}
		p, err := NewEnvKEKProvider(v.material)
		if err != nil {
			t.Fatalf("%s: provider: %v", v.label, err)
		}
		if p.KeyID() != v.want {
			t.Errorf("%s: KeyID=%q want %q", v.label, p.KeyID(), v.want)
		}
	}

	path := filepath.Join("testdata", "kek-fingerprint-vectors.txt")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("fixture not readable: %v", err)
	}
	defer f.Close()
	got := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			t.Fatalf("bad fixture line %q", line)
		}
		raw, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("%s: base64: %v", parts[0], err)
		}
		if fp := Fingerprint(raw); fp != parts[2] {
			t.Errorf("fixture %s: backend computes %q, file says %q", parts[0], fp, parts[2])
		}
		got[parts[0]] = parts[2]
	}
	if len(got) != len(kekFingerprintVectors) {
		t.Fatalf("fixture has %d vectors, test has %d", len(got), len(kekFingerprintVectors))
	}
	for _, v := range kekFingerprintVectors {
		if got[v.label] != v.want {
			t.Errorf("fixture %s=%q want %q", v.label, got[v.label], v.want)
		}
	}
}
