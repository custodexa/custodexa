package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// 解封請求的線上表述。
//
// **為何整個請求體就是 seal.UnsealRequest.Material**：狀態機的 VerifyFunc 只收
// `material []byte`，而初始化解封另需 paste-back 二次輸入與初始管理員憑證。
// 若把這些欄位另闢通道傳遞，就會出現「一部分輸入在臨界區內驗證、
// 另一部分在臨界區外解析」的分裂，且狀態機的「驗證結束即就地歸零材料」只蓋得到
// 一半。改為整包當材料有三個直接後果，皆為所欲：
//
//  1. 密碼與 paste-back 副本一併被歸零；
//  2. **連 JSON 解析失敗都落在臨界區內**，因而同樣計入解封退避——
//     否則攻擊者送壞掉的 JSON 即可零成本重試；
//  3. 解析錯誤與材料錯誤天然共用同一出口碼，滿足「回應內容不可區分」。
//
// **秘密欄位一律為可覆寫的 []byte，不是 string**：Go 的 string 不可變，
// `encoding/json` 解出的字串是獨立且不可覆寫的副本——歸零原始 body 與把欄位
// 置空都碰不到它。故本結構的秘密欄位改以自訂解析寫進我們自己配置的 byte
// buffer，Zeroize 覆寫的就是承載明文的那一份。
// 誠實邊界見 Zeroize 的說明：仍有兩類副本不在控制範圍內。
type SealUnsealPayload struct {
	// KEK 為使用者輸入的 KEK 材料。一般解封只用此欄。
	KEK []byte
	// KEKConfirm 為 paste-back 二次輸入。**僅初始化解封要求**。
	KEKConfirm []byte
	// ConfirmSaved 為保存確認旗標。**僅初始化解封要求**。
	//
	// 誠實界定：本欄是 UX 意圖聲明、**不具授權力**，SHALL NOT 被
	// 描述為安全不變式；伺服端唯一信任的機械不變式是 KEKConfirm 的逐字比對。
	ConfirmSaved bool
	// Username 為初始管理員帳號。**非秘密**（會進審計事件），故留 string。
	Username string
	// Password 為初始管理員密碼。**僅初始化解封要求**；
	// 一般解封不要求（要求 JWT 會在 admin 已開 MFA 時死鎖）。
	Password []byte

	// ── 委託模式的秘密（一律可覆寫的 []byte，封存時隨世代抹除）──────────
	//
	// 三家各一組，**按分支的精確鍵集**收取；混合分支的鍵集由呼叫端拒絕。
	// 這些值 SHALL NOT 落任何持久化位置、SHALL NOT 回顯、SHALL NOT 進錯誤訊息。

	// AccessKeyID／SecretAccessKey AWS 存取金鑰對。
	AccessKeyID     []byte
	SecretAccessKey []byte
	// ServiceAccountJSON GCP 服務帳號金鑰檔內容（另有欄位級大小上限）。
	ServiceAccountJSON []byte
	// VaultSecretID Vault AppRole 的角色密鑰。
	VaultSecretID []byte
	// VaultToken 直接提供的 Vault 權杖（與 VaultSecretID **二選一**）。
	VaultToken []byte

	// ── 非秘密欄位（核對綁定與全新安裝的拓撲）────────────────────────
	//
	// 留 string：非秘密，且其中數項要進審計本文。

	// TopologyDigest 核對步驟取得的拓撲摘要；與後端現行拓撲不符即拒並要求重新核對
	//（**舊核對結果不得授權送往新目的地**）。
	TopologyDigest string
	// Region 服務區域（全新安裝 · AWS）。
	Region string
	// KeyRef 金鑰識別（全新安裝：AWS 的金鑰 ARN／別名、GCP 的完整 CryptoKey 資源名）。
	KeyRef string
	// Address／TransitKeyName／RoleID Vault 拓撲（全新安裝 · Vault）。
	Address        string
	TransitKeyName string
	RoleID         string

	// present 本次請求實際出現過的鍵（**鍵集精確比對的輸入**）。
	// 分支判定在呼叫端（它才知道模式、服務商與是否為全新安裝），故解析層
	// 只記錄事實、不做分支判斷。
	present map[string]bool
}

// Present 回傳本次請求出現過的鍵集副本。
func (p *SealUnsealPayload) Present() map[string]bool {
	out := make(map[string]bool, len(p.present))
	for k := range p.present {
		out[k] = true
	}
	return out
}

// ErrSealPayloadMalformed 解封請求體無法解析。
//
// 呼叫端 SHALL NOT 讓本錯誤產生與材料錯誤不同的回應內容——它與材料錯誤同樣
// 收斂為 SEAL_MATERIAL_INVALID（回應內容不可區分）。
var ErrSealPayloadMalformed = errors.New("解封請求體無法解析")

// MaxSealUnsealBodyBytes 解封請求體大小上限（誠實邊界的「輸入大小上限」）。
//
// 上限存在的理由是使單次驗證成本有界，而非表達任何欄位長度政策。
// **自 8 KiB 上調至 24 KiB**：GCP 的服務帳號金鑰檔（含 PEM 私鑰）單欄即可達數
// KiB，原上限會讓合法輸入被當成格式錯誤而回一個指不出原因的碼。
const MaxSealUnsealBodyBytes = 24 << 10

// MaxServiceAccountJSONBytes 服務帳號金鑰檔內容的**欄位級**上限。
//
// 與本文上限分開訂：本文上限管的是單次驗證成本，欄位上限管的是「這個欄位收到的
// 是不是一份服務帳號金鑰檔」。實測一份含 2048-bit RSA 私鑰的金鑰檔約 2.3 KiB，
// 取 16 KiB 容納更長的金鑰與額外欄位，同時仍拒絕明顯不是金鑰檔的輸入。
const MaxServiceAccountJSONBytes = 16 << 10

// DecodeSealMaterial 解析解封材料。
//
// 三項嚴格性缺一不可：
//
//   - **未知欄位一律拒絕**：避免日後新增欄位時舊版伺服端靜默忽略而讓呼叫端
//     誤以為已生效——在「輸錯即固化為部署主金鑰」的初始化路徑上，靜默忽略是
//     不可接受的失敗模式。
//   - **重複欄位一律拒絕**：`{"kek":"A","kek":"B"}` 在 last-wins 語義下使
//     「送出的內容」與「被驗證的內容」可以不同，是 paste-back 的直接繞道。
//   - **首個物件之後只接受 EOF**：`{...}{...}` 這種串接在只 Decode 一次時，
//     第二個值完全不被檢視——嚴格驗證因此可被無聲繞過。
func DecodeSealMaterial(material []byte) (*SealUnsealPayload, error) {
	if len(material) == 0 || len(material) > MaxSealUnsealBodyBytes {
		return nil, ErrSealPayloadMalformed
	}
	p := &SealUnsealPayload{present: map[string]bool{}}
	dec := json.NewDecoder(bytes.NewReader(material))
	if err := decodeSealObject(dec, p); err != nil {
		p.Zeroize()
		return nil, ErrSealPayloadMalformed
	}
	// 尾隨內容檢查：只有 io.EOF 代表「物件之後什麼都沒有」。
	var trailing json.RawMessage
	err := dec.Decode(&trailing)
	zeroBytes(trailing)
	if !errors.Is(err, io.EOF) {
		p.Zeroize()
		return nil, ErrSealPayloadMalformed
	}
	return p, nil
}

// decodeSealObject 以 token 串流逐欄解析，使秘密值只以 []byte 形式落地。
//
// 不用 json.Unmarshal 到 struct：那條路徑必然產生不可覆寫的 string 副本，
// 而秘密欄位的整個防護論證就建立在「承載明文的那一份可被覆寫」之上。
func decodeSealObject(dec *json.Decoder, p *SealUnsealPayload) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("解封材料必須是 JSON 物件")
	}
	seen := map[string]bool{}
	if p.present == nil {
		// 直接建構本結構的呼叫端（單元測試）不經 DecodeSealMaterial，
		// 於此補建而非 panic——鍵集記錄是解析層的產物，不該要求呼叫端先備好容器。
		p.present = map[string]bool{}
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return errors.New("解封材料含非字串欄位名")
		}
		if seen[key] {
			return fmt.Errorf("解封材料含重複欄位 %q", key)
		}
		seen[key] = true
		p.present[key] = true
		if err := decodeSealField(dec, p, key); err != nil {
			return err
		}
	}
	tok, err = dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '}' {
		return errors.New("解封材料的 JSON 物件未正確結束")
	}
	return nil
}

// decodeSealField 解析單一欄位值。未知欄位即錯（等價 DisallowUnknownFields）。
func decodeSealField(dec *json.Decoder, p *SealUnsealPayload, key string) error {
	switch key {
	case "kek":
		return decodeSecretBytes(dec, &p.KEK)
	case "kek_confirm":
		return decodeSecretBytes(dec, &p.KEKConfirm)
	case "password":
		return decodeSecretBytes(dec, &p.Password)
	case "username":
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		v, err := jsonStringBytes(raw)
		if err != nil {
			return err
		}
		p.Username = string(v)
		return nil
	case "confirm_saved":
		var b bool
		if err := dec.Decode(&b); err != nil {
			return err
		}
		p.ConfirmSaved = b
		return nil
	case "access_key_id":
		return decodeSecretBytes(dec, &p.AccessKeyID)
	case "secret_access_key":
		return decodeSecretBytes(dec, &p.SecretAccessKey)
	case "service_account_json":
		if err := decodeSecretBytes(dec, &p.ServiceAccountJSON); err != nil {
			return err
		}
		// 欄位級上限：超限即拒且**不回顯任何片段**。
		if len(p.ServiceAccountJSON) > MaxServiceAccountJSONBytes {
			return fmt.Errorf("service_account_json 超出欄位上限 %d bytes", MaxServiceAccountJSONBytes)
		}
		return nil
	case "vault_secret_id":
		return decodeSecretBytes(dec, &p.VaultSecretID)
	case "vault_token":
		return decodeSecretBytes(dec, &p.VaultToken)
	case "topology_digest":
		return decodePlainString(dec, &p.TopologyDigest)
	case "region":
		return decodePlainString(dec, &p.Region)
	case "key_ref":
		return decodePlainString(dec, &p.KeyRef)
	case "address":
		return decodePlainString(dec, &p.Address)
	case "transit_key_name":
		return decodePlainString(dec, &p.TransitKeyName)
	case "role_id":
		return decodePlainString(dec, &p.RoleID)
	default:
		return fmt.Errorf("解封材料含未知欄位 %q", key)
	}
}

// decodePlainString 解析非秘密的字串欄位。
//
// 與 decodeSecretBytes 分開：這些值是拓撲與核對摘要，會進審計本文、需要以
// string 比對；把它們當秘密處置只會讓「哪些欄位是秘密」這件事在程式碼裡失焦。
func decodePlainString(dec *json.Decoder, dst *string) error {
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	v, err := jsonStringBytes(raw)
	if err != nil {
		return err
	}
	*dst = string(v)
	return nil
}

// decodeSecretBytes 把一個 JSON 字串值解進我方配置的 buffer，並覆寫中間副本。
func decodeSecretBytes(dec *json.Decoder, dst *[]byte) error {
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		zeroBytes(raw)
		return err
	}
	// RawMessage 是 encoding/json 交出的一份獨立副本，解完即覆寫。
	defer zeroBytes(raw)
	v, err := jsonStringBytes(raw)
	if err != nil {
		return err
	}
	*dst = v
	return nil
}

// jsonStringBytes 把 JSON 字串字面量解為位元組，輸出配置於單一不再成長的 buffer。
//
// **容量一次配足（len(body)）且只 append 不擴容**：反轉義只會使長度變短或
// 不變，故不會發生 realloc——若發生，舊 backing array 會成為一份無人持有、
// 因而永遠不會被覆寫的明文殘影。
func jsonStringBytes(raw []byte) (result []byte, resultErr error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("欄位值必須是 JSON 字串")
	}
	body := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(body))
	defer func() {
		if resultErr != nil {
			zeroBytes(out[:cap(out)])
		}
	}()
	for i := 0; i < len(body); {
		c := body[i]
		if c == '"' {
			return nil, errors.New("字串字面量含未轉義的引號")
		}
		if c < 0x20 {
			return nil, errors.New("字串字面量含未轉義的控制字元")
		}
		if c != '\\' {
			out = append(out, c)
			i++
			continue
		}
		i++
		if i >= len(body) {
			return nil, errors.New("字串字面量以未完成的轉義結尾")
		}
		switch body[i] {
		case '"', '\\', '/':
			out = append(out, body[i])
			i++
		case 'b':
			out = append(out, '\b')
			i++
		case 'f':
			out = append(out, '\f')
			i++
		case 'n':
			out = append(out, '\n')
			i++
		case 'r':
			out = append(out, '\r')
			i++
		case 't':
			out = append(out, '\t')
			i++
		case 'u':
			r, consumed, err := decodeUnicodeEscape(body[i:])
			if err != nil {
				return nil, err
			}
			var buf [utf8.UTFMax]byte
			out = append(out, buf[:utf8.EncodeRune(buf[:], r)]...)
			i += consumed
		default:
			return nil, fmt.Errorf("字串字面量含不合法的轉義 \\%c", body[i])
		}
	}
	return out, nil
}

// decodeUnicodeEscape 解析 \uXXXX（含代理對），回傳 rune 與消耗的位元組數。
// s 以 'u' 起始（反斜線已被呼叫端消耗）。
func decodeUnicodeEscape(s []byte) (rune, int, error) {
	v, err := hex4(s)
	if err != nil {
		return 0, 0, err
	}
	consumed := 5 // 'u' + 4 hex
	if utf16.IsSurrogate(rune(v)) {
		if len(s) >= consumed+6 && s[consumed] == '\\' && s[consumed+1] == 'u' {
			if v2, err2 := hex4(s[consumed+1:]); err2 == nil {
				if r := utf16.DecodeRune(rune(v), rune(v2)); r != utf8.RuneError {
					return r, consumed + 6, nil
				}
			}
		}
		// 落單的代理項：以替換字元表示，與 encoding/json 的行為一致。
		return utf8.RuneError, consumed, nil
	}
	return rune(v), consumed, nil
}

// hex4 解析 s[1:5] 的四位十六進位（s[0] 為 'u'）。
func hex4(s []byte) (uint32, error) {
	if len(s) < 5 {
		return 0, errors.New("\\u 轉義不足四位十六進位")
	}
	var v uint32
	for _, c := range s[1:5] {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint32(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= uint32(c-'A') + 10
		default:
			return 0, errors.New("\\u 轉義含非十六進位字元")
		}
	}
	return v, nil
}

// Zeroize 覆寫本結構持有的全部秘密位元組。
//
// **誠實邊界（SHALL NOT 宣稱「已完全歸零」）**：
//
//  1. `json.Decoder` 內部讀取緩衝區持有一份請求體副本，其記憶體不對外暴露，
//     本套件無從覆寫；它與狀態機就地歸零的 material 切片不是同一份。
//  2. 任何把秘密轉為 string 的呼叫（如 `config.ValidateKEKMaterial(string(kek))`、
//     bcrypt 的內部處理）都會產生不可變、不可覆寫的副本，其生命週期由 GC 決定。
//
// 本方法保證的是：**由本套件配置、承載明文的那些 buffer** 於驗證結束時被逐
// 位元組覆寫，而非「行程記憶體中不再存在該明文」。後者在 Go 的語義下不可達成，
// 宣稱達成即為不誠實。
func (p *SealUnsealPayload) Zeroize() {
	if p == nil {
		return
	}
	for _, b := range [][]byte{p.KEK, p.KEKConfirm, p.Password,
		p.AccessKeyID, p.SecretAccessKey, p.ServiceAccountJSON, p.VaultSecretID, p.VaultToken} {
		zeroBytes(b)
	}
	p.KEK = nil
	p.KEKConfirm = nil
	p.Password = nil
	p.AccessKeyID = nil
	p.SecretAccessKey = nil
	p.ServiceAccountJSON = nil
	p.VaultSecretID = nil
	p.VaultToken = nil
	p.Username = ""
	p.ConfirmSaved = false
	p.TopologyDigest = ""
	p.Region = ""
	p.KeyRef = ""
	p.Address = ""
	p.TransitKeyName = ""
	p.RoleID = ""
}

// TakeSecret 交出一個秘密欄位的**所有權**並自本結構斷開。
//
// 呼叫端（世代憑證持有者）自此負責歸零；本結構的 Zeroize 不再覆寫它——
// 兩邊都持有同一段位元組時，先歸零的一方會讓另一方讀到一段全零的「憑證」。
func TakeSecret(dst *[]byte) []byte {
	out := *dst
	*dst = nil
	return out
}

// zeroBytes 逐位元組覆寫。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
