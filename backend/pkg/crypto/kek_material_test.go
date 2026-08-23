package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// KEK 材料解碼器：
// 「輸入編碼」與「金鑰長度」拆開之後，三種寫法必須解出同一把 32 位元組金鑰，
// 且解不出 32 位元組者一律拒絕。

// sampleKey 一把固定的 32 位元組金鑰（刻意含 A-Za-z0-9 以外的位元組，
// 使「hex／base64 形態不受原字元字元集政策約束」這件事真的被驗到）。
var sampleKey = []byte{
	0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, 0x2b,
	0x2f, 0x3d, 0x5f, 0x2d, 0x41, 0x61, 0x30, 0x39,
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
}

// rawAlphaKey 一把恰 32 個 A-Za-z0-9 字元的材料（原字元形態的合法樣本）
const rawAlphaKey = "NEWKEK1234567890abcdefABCDEF0000"

func TestDecodeKEKMaterialThreeFormsYieldSameKey(t *testing.T) {
	cases := []struct {
		name  string
		input string
		form  string
	}{
		{"原字元（任意位元組）", string(sampleKey), KEKFormRaw},
		{"十六進位小寫", hex.EncodeToString(sampleKey), KEKFormHex},
		{"十六進位大寫", strings.ToUpper(hex.EncodeToString(sampleKey)), KEKFormHex},
		{"base64 標準有 padding", base64.StdEncoding.EncodeToString(sampleKey), KEKFormBase64},
		{"base64 標準無 padding", base64.RawStdEncoding.EncodeToString(sampleKey), KEKFormBase64},
		{"base64 URL-safe 有 padding", base64.URLEncoding.EncodeToString(sampleKey), KEKFormBase64},
		{"base64 URL-safe 無 padding", base64.RawURLEncoding.EncodeToString(sampleKey), KEKFormBase64},
		// 三條文件化生成指令的輸出都帶結尾換行，故 trim 是本功能的一部分
		{"十六進位帶結尾換行", hex.EncodeToString(sampleKey) + "\n", KEKFormHex},
		{"base64 帶前後空白", "  " + base64.StdEncoding.EncodeToString(sampleKey) + " \n", KEKFormBase64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, form, reason := DecodeKEKMaterial(tc.input)
			if reason != "" {
				t.Fatalf("應被接受，得原因 %q（輸入長度 %d）", reason, len(tc.input))
			}
			if form != tc.form {
				t.Fatalf("形態應為 %q，得 %q", tc.form, form)
			}
			if !bytes.Equal(key, sampleKey) {
				t.Fatalf("解出的金鑰與預期不符：%x", key)
			}
			// 三種寫法解出同一把金鑰 → 指紋必然相同（落庫的 kek_id 不因寫法而異）
			if Fingerprint(key) != Fingerprint(sampleKey) {
				t.Fatalf("指紋不一致：%s vs %s", Fingerprint(key), Fingerprint(sampleKey))
			}
		})
	}
}

// TestDecodeKEKMaterialReturnsIndependentBuffer 回傳的金鑰必須是新配置的切片
// ——呼叫端歸零金鑰時不得波及 payload 自身的 buffer（反之亦然）
func TestDecodeKEKMaterialReturnsIndependentBuffer(t *testing.T) {
	payload := append([]byte(nil), sampleKey...)
	key, _, reason := DecodeKEKMaterialBytes(payload)
	if reason != "" {
		t.Fatalf("應被接受，得 %q", reason)
	}
	zeroKEKBytes(payload)
	if !bytes.Equal(key, sampleKey) {
		t.Fatalf("歸零 payload 後金鑰被連帶抹除：%x", key)
	}
	zeroKEKBytes(key)
	for _, b := range key {
		if b != 0 {
			t.Fatal("歸零金鑰失敗")
		}
	}
}

// TestKEKMaterialFormsAreMutuallyExclusive 三種形態互斥：
// 對任一形態的合法樣本，另外兩種讀法都**得不到** 32 位元組。
// 這條性質使「判定順序」不是在多種可能讀法中仲裁——順序不影響任何輸入的結果。
func TestKEKMaterialFormsAreMutuallyExclusive(t *testing.T) {
	samples := map[string]string{
		KEKFormRaw:    rawAlphaKey,
		KEKFormHex:    hex.EncodeToString(sampleKey),
		KEKFormBase64: base64.StdEncoding.EncodeToString(sampleKey),
	}
	for form, input := range samples {
		// 十六進位讀法
		if form != KEKFormHex {
			if b, err := hex.DecodeString(input); err == nil && len(b) == KEKMaterialLength {
				t.Fatalf("形態 %q 的樣本 %q 亦可被讀為 32 bytes 的十六進位——形態不互斥", form, input)
			}
		}
		// base64 四變體讀法
		if form != KEKFormBase64 {
			for _, enc := range kekBase64Encodings {
				if b, err := enc.DecodeString(input); err == nil && len(b) == KEKMaterialLength {
					t.Fatalf("形態 %q 的樣本 %q 亦可被讀為 32 bytes 的 base64——形態不互斥", form, input)
				}
			}
		}
		// 原字元讀法
		if form != KEKFormRaw && len(strings.TrimSpace(input)) == KEKMaterialLength {
			t.Fatalf("形態 %q 的樣本長度為 32，與原字元形態衝突", form)
		}
	}
}

// TestDecodeKEKMaterialRejects 負面集合：解碼後非 32 位元組、字元不合法、
// 混用字母表、非嚴格 base64、空白。
func TestDecodeKEKMaterialRejects(t *testing.T) {
	// 43 個字元、最末量子的多餘位元非零（非規範編碼）。
	// 由合法編碼的最後一個字元改成同量子內的另一個字元取得
	nonCanonical := base64.RawStdEncoding.EncodeToString(sampleKey)
	nonCanonical = nonCanonical[:len(nonCanonical)-1] + "B"

	cases := []struct {
		name  string
		input string
	}{
		{"空字串", ""},
		{"全空白（非 32 bytes）", "   \n\t "},
		{"長度 33", rawAlphaKey + "x"},
		{"長度 31", rawAlphaKey[:31]},
		// 64 個 base64 字元本可解出 48 bytes；因長度不在 {43,44} 而根本不進 base64 讀法，
		// 又因含非十六進位字元而過不了 hex 讀法 → 拒
		{"64 個 base64 字元（非十六進位）", strings.Repeat("Zz", 32)},
		{"64 字元但非十六進位", strings.Repeat("g", 64)},
		{"43 字元但含非 base64 字元", strings.Repeat("!", 43)},
		{"混用標準與 URL-safe 字母表", "A+B_" + strings.Repeat("C", 39) + "="},
		{"非規範 base64（多餘位元非零）", nonCanonical},
		{"十六進位長度 63", hex.EncodeToString(sampleKey)[:63]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, _, reason := DecodeKEKMaterial(tc.input)
			if reason == "" {
				t.Fatalf("應被拒，卻解出 %d bytes：%x", len(key), key)
			}
			if key != nil {
				t.Fatalf("拒絕路徑不得回傳金鑰，得 %x", key)
			}
		})
	}
}

// TestThirtyTwoByteInputIsAlwaysRaw 恰 32 位元組的輸入**一律**是原字元形態，
// 不論其字元是否恰好全屬十六進位或 base64 字元集。
//
// 這條規則同時是零回歸保證的落點：兩個「刻意不套格式政策」的入口（未宣告
// KEK_PROVIDER 的相容路徑、金鑰表非空的一般解封）今天接受任意 32 位元組，
// 本規則使它們的語義**完全不變**——32 位元組進、同樣的 32 位元組出。
func TestThirtyTwoByteInputIsAlwaysRaw(t *testing.T) {
	cases := []string{
		rawAlphaKey,                        // 一般英數
		strings.Repeat("abcdef01", 4),      // 恰 32 字元且全屬十六進位字元集
		strings.Repeat("A", 32),            // 恰 32 字元且是 24 bytes 的合法 base64
		"++++////====----____!!!!????@@@@", // 含各種非英數字元（政策層才擋）
	}
	for _, input := range cases {
		if len(input) != KEKMaterialLength {
			t.Fatalf("樣本 %q 長度 %d，應為 %d", input, len(input), KEKMaterialLength)
		}
		key, form, reason := DecodeKEKMaterial(input)
		if reason != "" {
			t.Fatalf("恰 32 位元組必須被接受，%q 得 %q", input, reason)
		}
		if form != KEKFormRaw {
			t.Fatalf("%q 的形態應為 raw，得 %q", input, form)
		}
		if string(key) != input {
			t.Fatalf("%q 未原樣採用，得 %q", input, string(key))
		}
	}
}

// TestDecodeKEKMaterialPreservesExisting32ByteMaterial 零回歸保證：
// 恰 32 位元組的輸入（含其中的空白字元）在 trim 之前即命中原字元形態，
// 逐位元組原樣採用——今日可運作的部署不因本次改動而換鑰。
func TestDecodeKEKMaterialPreservesExisting32ByteMaterial(t *testing.T) {
	withSpaces := " abcdefghijklmnopqrstuvwxyzABCD " // 恰 32 bytes、含前後空白
	if len(withSpaces) != KEKMaterialLength {
		t.Fatalf("測試樣本長度 %d，應為 %d", len(withSpaces), KEKMaterialLength)
	}
	key, form, reason := DecodeKEKMaterial(withSpaces)
	if reason != "" {
		t.Fatalf("恰 32 位元組的材料必須原樣被接受，得 %q", reason)
	}
	if form != KEKFormRaw {
		t.Fatalf("形態應為 raw，得 %q", form)
	}
	if string(key) != withSpaces {
		t.Fatalf("金鑰被修剪：%q", string(key))
	}
}

// TestValidateKEKMaterialFormatCharsetAppliesToRawOnly 字元集政策只約束原字元形態
func TestValidateKEKMaterialFormatCharsetAppliesToRawOnly(t *testing.T) {
	// 原字元形態含字元集外字元 → 拒
	rawBad := "NEWKEK1234567890abcdefABCDE+/=0"
	if len(rawBad) != 31 {
		t.Fatalf("樣本長度 %d", len(rawBad))
	}
	rawBad += "0" // 補到 32
	if v := ValidateKEKMaterialFormat(rawBad); v == "" {
		t.Fatal("原字元形態含字元集外字元應被拒")
	}
	// hex／base64 形態即使解出含 `+` `/` 的位元組也放行（字元集是輸入編碼的性質）
	for _, input := range []string{
		hex.EncodeToString(sampleKey),
		base64.StdEncoding.EncodeToString(sampleKey),
		base64.RawURLEncoding.EncodeToString(sampleKey),
	} {
		if v := ValidateKEKMaterialFormat(input); v != "" {
			t.Fatalf("編碼形態不應受原字元字元集約束，%q 被拒：%s", input, v)
		}
	}
	// 恰 32 個空白字元：解碼層放行（相容路徑要它放行），政策層必須擋下
	blanks := strings.Repeat(" ", KEKMaterialLength)
	if _, _, reason := DecodeKEKMaterial(blanks); reason != "" {
		t.Fatalf("解碼層對 32 個空白應放行（相容路徑語義），得 %q", reason)
	}
	if v := ValidateKEKMaterialFormat(blanks); v == "" {
		t.Fatal("政策層必須擋下全空白材料")
	}
}
