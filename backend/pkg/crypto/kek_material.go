package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// KEK 材料的**輸入編碼**與**金鑰**是兩件事。
//
// 缺陷史：原本 `len(material) != 32` 這一條同時在說兩句話——「AES-256 要 32 bytes」
// 與「輸入必須是 32 個字元」。於是 operator 以標準指令生成的**完全正確**的 32 位元組
// 金鑰全被拒：`openssl rand -hex 32` 產出 64 個十六進位字元（正是該金鑰的 hex 編碼），
// `openssl rand -base64 32` 因字元集含 `+` `/` 被字元集規則擋下。
// 拆開之後，金鑰長度規則（恰 32 位元組、不引入 KDF）完全不變，只是允許三種寫法。

// KEKAlphabet 本地 KEK 材料**原字元形態**的字元集：可直接放 env 的可列印字元
// （62^32 ≈ 190 bits）。單一事實源——生成端（換鑰精靈）與驗證端（啟動判定、
// 精靈輸入驗證）共用。
//
// **只適用於原字元形態**：十六進位與 base64 形態的合法字元由其編碼本身界定，
// 再套一次本字元集等於把那兩種形態整個否定掉。
const KEKAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// KEKMaterialLength KEK 金鑰長度，單位為**位元組**（AES-256 需恰 32 bytes）。
// 它是解碼**之後**的長度要求，不是輸入字串的長度要求。
const KEKMaterialLength = 32

// KEK 材料的輸入形態。
const (
	// KEKFormRaw 原字元形態：恰 32 位元組，其位元組即金鑰
	KEKFormRaw = "raw"
	// KEKFormHex 十六進位形態：恰 64 個十六進位字元
	KEKFormHex = "hex"
	// KEKFormBase64 base64 形態：解碼後恰 32 位元組
	KEKFormBase64 = "base64"
)

// 三種形態要解出 32 位元組所需的輸入長度。**三者互斥**，這正是
// 「判定順序不是在多種讀法中仲裁」的算術根據（決策 2）：
//   - base64 解出 32 位元組只能是 43（無 padding）或 44（有 padding）；
//     32 個 base64 字元解出 24 位元組、64 個解出 48 位元組，都不是 32。
//   - hex 解出 32 位元組只能是 64。
//   - 原字元形態固定 32。
const (
	kekHexLength          = KEKMaterialLength * 2 // 64
	kekBase64RawLength    = 43                    // 無 padding
	kekBase64PaddedLength = 44                    // 有 padding
)

// 不洩密的違規原因（**只進伺服端錯誤鏈與啟動期日誌，不進 API 回應**）。
// 解碼失敗與既有材料失敗共用同一機器碼，回應內容不可區分。
const (
	kekReasonEmpty = "為空或全為空白字元"
	kekReasonForm  = "不是可接受的材料形態（須為 32 個字元、64 個十六進位字元、" +
		"或解碼後恰 32 bytes 的 base64）"
	kekReasonCharset = "含字元集外字元（僅允許 A-Z a-z 0-9）"
)

// kekBase64Encodings base64 的四個變體，**一律 Strict**。
//
// 同時收標準（`+/`）與 URL-safe（`-_`）：兩套字母表的非英數字元互斥，
// 含 `+` 的字串在 URL-safe 下不合法、含 `-` 的在標準下不合法，只含英數者兩套解出
// 同一結果——故逐一嘗試是確定性的，**不可能解出兩把不同的金鑰**。
// 刻意不做「`-`→`+` 正規化後統一解碼」：那會接受 `a+b_c` 這種**混用**字串，
// 而混用不是任何一種編碼的輸出。
//
// 同時收有／無 padding：`openssl rand -base64 32` 產出有 padding 的 44 字元，
// JWT 系與許多 SDK 產出無 padding 的 43 字元；只收其一就是在正確的金鑰上再劃一條
// 沒有理由的線——那正是本次要修的缺陷形狀。兩者長度不同，互不遮蔽。
//
// Strict：Go 預設不檢查最末量子的多餘位元是否為零，於是同一把金鑰會有多個
// 「都解得開」的寫法。Strict 使「一把金鑰 ↔ 一份規範編碼」更接近成立，
// 且不會誤殺任何正確編碼器的輸出（正確編碼器必然把多餘位元寫成零）。
var kekBase64Encodings = []*base64.Encoding{
	base64.StdEncoding.Strict(),
	base64.RawStdEncoding.Strict(),
	base64.URLEncoding.Strict(),
	base64.RawURLEncoding.Strict(),
}

// DecodeKEKMaterial 把使用者輸入的 KEK 材料解為 32 位元組金鑰。
//
// 這是「字串 → 32 位元組」的**唯一**轉換點：啟動判定、解封的兩條路徑、
// 換鑰精靈與出廠預設值閘全部走它，SHALL NOT 各自保留只認單一形態的平行實作。
//
// 回傳 reason 非空即為不合格（key 為 nil）；否則 key 恆為長度 32 的新配置切片，
// 其所有權移交呼叫端（**呼叫端負責在用畢後歸零**）。
//
// **本層只管編碼，不管政策**：不檢查字元集、不檢查出廠預設值。那兩項屬
// ValidateKEKMaterialFormat／config.ValidateKEKMaterial 的職責——因為有兩個入口
// （未宣告 KEK_PROVIDER 的相容路徑、金鑰表非空的一般解封）**刻意不套格式政策**，
// 兩層綁在一起就會逼它們也套上，而那會讓既有部署解不開自己的資料。
//
// 判定順序見 kekHexLength 一組常數的說明。**第一步刻意不 trim**：
// 上述兩個入口今天接受任意 32 位元組（其中可以含前後空白，那 32 個位元組就是金鑰），
// 先 trim 會把這種材料削成 31 位元組而使一個能開機的部署開不了機。先比長度即完全免疫。
// 其後的形態判定則必須 trim——`openssl rand -hex 32` 與 `-base64 32` 的輸出都帶
// 結尾換行，而空白不屬於任何一種形態的合法字元集，故 trim 不可能製造出新的歧義。
func DecodeKEKMaterial(material string) (key []byte, form string, reason string) {
	return DecodeKEKMaterialBytes([]byte(material))
}

// DecodeKEKMaterialBytes 同 DecodeKEKMaterial，但收 []byte。
//
// **解封路徑必須走這一支**：該路徑的材料自始至終是可覆寫的 []byte
// （internal/api.SealUnsealPayload 的整個防護論證即建立在此），
// 為了呼叫 string 版而 `string(material)` 會憑空多出一份不可覆寫的明文副本。
//
// 傳入的 material **不會**被修改，回傳的 key 恆為新配置的切片
// ——呼叫端可以獨立歸零它，而不影響 payload 自身的歸零時程。
func DecodeKEKMaterialBytes(material []byte) (key []byte, form string, reason string) {
	// 步 1：恰 32 位元組原樣採用（零回歸保證，見上）
	if len(material) == KEKMaterialLength {
		return cloneKEKBytes(material), KEKFormRaw, ""
	}

	s := bytes.TrimSpace(material)
	if len(s) == 0 {
		return nil, "", kekReasonEmpty
	}

	switch len(s) {
	case KEKMaterialLength:
		return cloneKEKBytes(s), KEKFormRaw, ""

	case kekHexLength:
		// hex 同時接受大小寫；長度已為偶數，故只剩字元合法性
		out := make([]byte, KEKMaterialLength)
		n, err := hex.Decode(out, s)
		if err != nil || n != KEKMaterialLength {
			zeroKEKBytes(out)
			return nil, "", kekReasonForm
		}
		return out, KEKFormHex, ""

	case kekBase64RawLength, kekBase64PaddedLength:
		if b, ok := decodeKEKBase64(s); ok {
			return b, KEKFormBase64, ""
		}
	}
	return nil, "", kekReasonForm
}

// decodeKEKBase64 逐一嘗試四個嚴格變體；第一個解出恰 32 位元組者勝出。
// 失敗路徑上的部分產出一律歸零——解碼器在報錯前仍可能已寫入部分位元組。
func decodeKEKBase64(s []byte) ([]byte, bool) {
	for _, enc := range kekBase64Encodings {
		out := make([]byte, enc.DecodedLen(len(s)))
		n, err := enc.Decode(out, s)
		if err == nil && n == KEKMaterialLength {
			return out[:KEKMaterialLength], true
		}
		zeroKEKBytes(out)
	}
	return nil, false
}

// cloneKEKBytes 複製一份新切片：回傳值的所有權必須與呼叫端傳入的 buffer 分離，
// 否則呼叫端歸零金鑰時會一併抹掉尚在使用中的 payload（或反之）。
func cloneKEKBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// ValidateKEKMaterialFormat 本地 KEK 材料的伺服端**格式政策**驗證：
// 可解碼為 32 位元組金鑰，且原字元形態須落在 KEKAlphabet 內。
// 回空字串＝合格；否則回不洩密的違規原因。
//
// **字元集只對原字元形態施加**：十六進位與 base64 形態的字元集由編碼本身界定
// （見 KEKAlphabet 的說明）。
//
// **誠實界定**（沿 JWT_SECRET 長度下限的既有措辭）：格式驗證是降低常見弱值
// 風險的務實手段，系統 SHALL NOT 宣稱能由單一值驗證其熵。
func ValidateKEKMaterialFormat(material string) string {
	if strings.TrimSpace(material) == "" {
		// 「恰 32 個空白字元」在此被擋下：位元組長度雖合法，trim 後為空即無效材料。
		// 本檢查必須在解碼之前——解碼層對這種輸入是放行的（相容路徑要它放行）。
		return kekReasonEmpty
	}
	key, form, reason := DecodeKEKMaterial(material)
	if reason != "" {
		return reason
	}
	// 只取判定結果的呼叫端不持有金鑰：解碼配置的緩衝就地歸零後才返回
	defer zeroKEKBytes(key)
	if form == KEKFormRaw {
		for _, b := range key {
			if strings.IndexByte(KEKAlphabet, b) < 0 {
				return kekReasonCharset
			}
		}
	}
	return ""
}

// zeroKEKBytes 逐位元組覆寫。
//
// **誠實邊界**：本函式覆寫的是傳入的那一份切片。以 string 傳入的原始材料、
// 以及呼叫鏈上任何把材料轉為 string 的中間值，在 Go 語義下不可覆寫，
// 其回收時點由 GC 決定；SHALL NOT 宣稱材料已自行程記憶體抹除。
func zeroKEKBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
