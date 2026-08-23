package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
)

// KEK 材料的輸入編碼於解封端點的驗收。
//
// **紅線**：新增的解碼路徑不得製造新的可區分訊號。既有的
// TestUnsealFailureResponsesIndistinguishable 只涵蓋「格式／材料／解析」三類；
// 本檔把解碼失敗的各種形狀一併納入同一組比較，並且**每一步都呼叫生產函式**
// （config.ValidateKEKMaterial、buildUIKEKProvider），只把最後的「解不開代表列」
// 換成固定錯誤——那正是要被比較的對照組。

// unsealTestKey 一把測試用的 32 位元組金鑰（含 A-Za-z0-9 以外的位元組，
// 使 hex／base64 形態不因字元集政策而通過或失敗）
var unsealTestKey = []byte{
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	0x2b, 0x2f, 0x3d, 0x5f, 0x2d, 0x7f, 0x80, 0xfe,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

// unsealNoBackoffLimiter 退避關到最小，使每一次嘗試都真的走到驗證
func unsealNoBackoffLimiter() *seal.Limiter {
	return seal.NewLimiter(seal.LimiterConfig{
		BaseBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond,
		GlobalThreshold: 1000, GlobalCooldown: time.Minute, MaxGlobalCooldown: time.Minute,
	})
}

// initPathVerify 複刻**初始化解封**的材料判定序列（verifyInitializeUnseal 的前兩步），
// 每一步皆為生產函式；最後固定回 errTestMaterial 代表「格式全對但材料不是那一把」。
func initPathVerify(_ context.Context, material []byte) (seal.VerifiedMaterial, error) {
	payload, err := api.DecodeSealMaterial(material)
	if err != nil {
		return seal.VerifiedMaterial{}, err
	}
	defer payload.Zeroize()
	if v := config.ValidateKEKMaterial(string(payload.KEK)); v != "" {
		return seal.VerifiedMaterial{}, errors.New(v)
	}
	if _, err := buildUIKEKProvider(payload.KEK); err != nil {
		return seal.VerifiedMaterial{}, err
	}
	return seal.VerifiedMaterial{}, errTestMaterial
}

// normalPathVerify 複刻**一般解封**的材料判定序列（不套格式政策，只解碼）。
func normalPathVerify(_ context.Context, material []byte) (seal.VerifiedMaterial, error) {
	payload, err := api.DecodeSealMaterial(material)
	if err != nil {
		return seal.VerifiedMaterial{}, err
	}
	defer payload.Zeroize()
	if _, err := buildUIKEKProvider(payload.KEK); err != nil {
		return seal.VerifiedMaterial{}, err
	}
	return seal.VerifiedMaterial{}, errTestMaterial
}

// TestUnsealDecodeFailuresIndistinguishable 解碼失敗的各種形狀與既有材料失敗
// 回應**逐位元組相同**——新增的三種編碼不得帶進任何新的可區分訊號。
func TestUnsealDecodeFailuresIndistinguishable(t *testing.T) {
	// 混用兩套 base64 字母表的 44 字元字串
	mixedAlphabet := "A+B_" + strings.Repeat("C", 39) + "="
	// 非規範 base64（最末量子多餘位元非零）
	nonCanonical := base64.RawStdEncoding.EncodeToString(unsealTestKey)
	nonCanonical = nonCanonical[:len(nonCanonical)-1] + "B"

	variants := []struct {
		name string
		kek  string
	}{
		// 對照組：形狀完全合格，只是材料不對（初始化路徑的 charset 也過得了）
		{"合格材料但解不開", "NEWKEK1234567890abcdefABCDEF0000"},
		{"十六進位形態的合格材料但解不開", hex.EncodeToString(unsealTestKey)},
		{"base64 形態的合格材料但解不開", base64.StdEncoding.EncodeToString(unsealTestKey)},
		// 解碼失敗諸形狀
		{"64 字元但非十六進位", strings.Repeat("Zz", 32)},
		{"43 字元但含非 base64 字元", strings.Repeat("!", 43)},
		{"混用 base64 字母表", mixedAlphabet},
		{"非規範 base64", nonCanonical},
		{"長度 33", "NEWKEK1234567890abcdefABCDEF0000x"},
		{"長度 31", "NEWKEK1234567890abcdefABCDEF000"},
		{"全空白", "     "},
		{"十六進位長度 63", hex.EncodeToString(unsealTestKey)[:63]},
		// 出廠預設值的四種寫法
		{"出廠預設值（原字元）", config.DefaultEncryptionKey},
		{"出廠預設值（十六進位）", hex.EncodeToString([]byte(config.DefaultEncryptionKey))},
		{"出廠預設值（base64）", base64.StdEncoding.EncodeToString([]byte(config.DefaultEncryptionKey))},
		{"出廠預設值（base64 URL-safe 無 padding）",
			base64.RawURLEncoding.EncodeToString([]byte(config.DefaultEncryptionKey))},
	}

	paths := []struct {
		name   string
		verify seal.VerifyFunc
		// normal 路徑不套格式政策，故「字元集外」與「出廠預設值」在該路徑上
		// 本來就不是失敗——只比較解碼類與材料類
		skipPolicyOnly bool
	}{
		{"初始化路徑", initPathVerify, false},
		{"一般路徑", normalPathVerify, true},
	}

	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			clock := newFakeClock()
			_, h := newTestSealSetup(t,
				withLimiter(unsealNoBackoffLimiter()), withNow(clock.Now), withVerify(p.verify))
			r := sealEndpointRouter(t, h)

			var first, firstName string
			for _, v := range variants {
				if p.skipPolicyOnly && strings.HasPrefix(v.name, "出廠預設值") {
					// 一般路徑刻意不套政策：出廠預設值在該路徑上只是「一把解不開的鑰」，
					// 與對照組同結果，納入比較反而測不到東西
					continue
				}
				clock.Advance(time.Second)
				body := `{"kek":` + jsonQuote(v.kek) + `}`
				w := postUnseal(r, body, "")
				if w.Code != http.StatusBadRequest {
					t.Fatalf("%s 回 %d，期望 400", v.name, w.Code)
				}
				got := w.Body.String()
				if first == "" {
					first, firstName = got, v.name
					if !strings.Contains(got, string(apierror.CodeSealMaterialInvalid)) {
						t.Fatalf("回應未帶 %s：%s", apierror.CodeSealMaterialInvalid, got)
					}
					continue
				}
				if got != first {
					t.Fatalf("「%s」的回應與「%s」不同，解碼成因可被區分：\n  %s\n  %s",
						v.name, firstName, first, got)
				}
			}
		})
	}
}

// TestUnsealAcceptsThreeEncodingsForSameKey 三種寫法在解封路徑上解出同一個
// KEK provider（同一把金鑰、同一個金鑰引用）——「換一種寫法就換一把鑰」會使
// 既有部署解不開自己的資料，是本次改動最嚴重的失敗模式。
func TestUnsealAcceptsThreeEncodingsForSameKey(t *testing.T) {
	want := crypto.Fingerprint(unsealTestKey)
	inputs := map[string]string{
		"原字元":                       string(unsealTestKey),
		"十六進位":                      hex.EncodeToString(unsealTestKey),
		"十六進位（大寫、帶換行）":              strings.ToUpper(hex.EncodeToString(unsealTestKey)) + "\n",
		"base64 標準":                 base64.StdEncoding.EncodeToString(unsealTestKey),
		"base64 URL-safe 無 padding": base64.RawURLEncoding.EncodeToString(unsealTestKey),
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			p, err := buildUIKEKProvider([]byte(in))
			if err != nil {
				t.Fatalf("應被接受，得 %v", err)
			}
			if got := p.KeyRef().KeyID; got != want {
				t.Fatalf("金鑰引用 %s，期望 %s——不同寫法解出了不同的鑰", got, want)
			}
			if p.KeyRef().Provider != crypto.KeyRefProviderLocal {
				t.Fatalf("provider 應為 local，得 %s", p.KeyRef().Provider)
			}
		})
	}
}

// TestBuildUIKEKProviderRejectsUndecodable 解碼失敗一律回錯，且該錯經
// SealErrorResponse 收斂為與一般材料失敗**完全相同**的碼與狀態。
func TestBuildUIKEKProviderRejectsUndecodable(t *testing.T) {
	baseCode, baseStatus := api.SealErrorResponse(errTestMaterial)
	if baseCode != apierror.CodeSealMaterialInvalid || baseStatus != http.StatusBadRequest {
		t.Fatalf("對照組映射非預期：%s/%d", baseCode, baseStatus)
	}
	for _, in := range []string{
		strings.Repeat("Zz", 32),
		strings.Repeat("!", 43),
		"too-short",
		"",
		hex.EncodeToString(unsealTestKey)[:63],
	} {
		p, err := buildUIKEKProvider([]byte(in))
		if err == nil {
			t.Fatalf("%q 應被拒，卻建出 provider %v", in, p)
		}
		code, status := api.SealErrorResponse(err)
		if code != baseCode || status != baseStatus {
			t.Fatalf("%q 的失敗映射為 %s/%d，與一般材料失敗 %s/%d 不同——出現可區分訊號",
				in, code, status, baseCode, baseStatus)
		}
	}
}

// jsonQuote 產生 JSON 字串字面量（測試材料含 `+` `/` `=` 等字元，不需轉義，
// 但仍走標準轉義以免日後加入含引號的樣本時靜默出錯）。
func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				const hexDigits = "0123456789abcdef"
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xf])
				continue
			}
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
