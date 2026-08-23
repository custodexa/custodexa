package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// 換鑰精靈重包請求體：**discriminated union**。
//
// 本地目標 `{mode:"local", new_kek, new_kek_confirm, confirm_saved}` 與委託目標
// `{mode:"kms"|"hsm", key_ref}` 為**互斥**變體，由顯式 mode 判別。
//
// **混合 payload 或 mode 與所帶欄位不符一律 fail-close 拒絕**，
// SHALL NOT 以欄位優先序擇一處理：以優先序處理會留下
// provider-confusion 空間——繞過本地目標的格式驗證與 paste-back，或把使用者的
// KEK 明文誤送進本應只收引用的委託路徑。故本檔的解析採「逐變體的精確鍵集」：
// 缺必要鍵、多出他變體的鍵、或出現未知鍵，一律拒絕。
//
// **兩個確認欄位的證明力不同**：
//   - new_kek_confirm 的逐字比對是伺服端**唯一**信任的機械不變式——它證明呼叫端
//     當下持有並能完整重述該材料，可由伺服端獨立驗證。
//   - confirm_saved **不具任何授權力**：伺服端無法驗證「材料已離線保存」（直打 API
//     即可機械式填 true）。它是使用者意圖聲明（UX 欄位），SHALL NOT 被描述為安全
//     不變式、SHALL NOT 被當作「材料已安全保存」的證據。保存責任在使用者。

// 重包目標判別子的線上字面（與 service.RewrapTargetMode* 對齊）
const (
	rewrapModeLocal = "local"
	rewrapModeKMS   = "kms"
	rewrapModeHSM   = "hsm"
)

// 請求體欄位名（單一事實源：解析、鍵集比對與測試共用同一組字面）
const (
	rewrapFieldMode          = "mode"
	rewrapFieldNewKEK        = "new_kek"
	rewrapFieldNewKEKConfirm = "new_kek_confirm"
	rewrapFieldConfirmSaved  = "confirm_saved"
	rewrapFieldKeyRef        = "key_ref"
)

// maxRewrapBodyBytes 重包請求體大小上限。材料本身為 32 bytes，兩份副本加判別子
// 遠低於此值；上限存在的理由是使單次解析成本有界，而非表達欄位長度政策。
const maxRewrapBodyBytes = 8 << 10

var (
	// errRewrapPayloadMalformed 無法解析、超出大小上限、或型別不符
	errRewrapPayloadMalformed = errors.New("重包請求內容無法解析")
	// errRewrapModeInvalid 判別子缺漏或不在白名單
	errRewrapModeInvalid = errors.New("重包目標模式無效")
	// errRewrapPayloadMixed 混合 payload／mode 與欄位不符（fail-close）
	errRewrapPayloadMixed = errors.New("重包請求混用了不屬於該目標模式的欄位")
	// errRewrapConfirmMismatch paste-back 二次輸入不符（唯一的機械不變式）
	errRewrapConfirmMismatch = errors.New("二次輸入的新 KEK 與第一次不符")
	// errRewrapNotSaved 保存確認旗標非真（UX 意圖聲明，非安全不變式）
	errRewrapNotSaved = errors.New("尚未確認已保存新 KEK")
)

// rewrapPayload 解析後的重包請求（union 的宿主）
type rewrapPayload struct {
	// Mode 判別子（local／kms／hsm）
	Mode string
	// NewKEK／NewKEKConfirm／ConfirmSaved 僅本地變體有值
	NewKEK        string
	NewKEKConfirm string
	ConfirmSaved  bool
	// KeyRef 僅委託變體有值
	KeyRef string
}

// zeroRewrapBody 逐位元組覆寫原始請求體。
//
// 這是本流程中少數真的可覆寫的一份明文：`io.ReadAll` 交出的 []byte 由我們持有，
// 而 `encoding/json` 解出的 string 副本不是。
func zeroRewrapBody(body []byte) {
	for i := range body {
		body[i] = 0
	}
}

// Zeroize 就地放棄本結構持有的材料參考。
//
// **誠實界定（SHALL NOT 宣稱已抹除）**：本方法只放掉參考，不覆寫位元組——
// Go 的 string 不可變，其 backing array 無法覆寫，回收時點由 GC 決定。
// 本次請求處理過程中，材料另存在於三處不受本方法涵蓋的副本：
//
//  1. 原始請求體 []byte——由呼叫端 defer zeroRewrapBody 覆寫（可控）；
//  2. json.Decoder 的內部緩衝與解碼期間產生的中間 string——不可控；
//  3. keyvault.RewrapTarget 的材料副本與其 provider 內展開的 AES 金鑰表——
//     前者由 RewrapTarget.Destroy 覆寫（可控），後者 pkg/crypto 未提供銷毀
//     入口（不可控）。
//
// 故本方法承諾的是「處理結束後**本結構**不再持有材料」，不承諾行程記憶體中
// 已無該明文。
func (p *rewrapPayload) Zeroize() {
	if p == nil {
		return
	}
	p.NewKEK = ""
	p.NewKEKConfirm = ""
	p.ConfirmSaved = false
}

// 各變體的精確鍵集（含判別子）。**必要鍵＝全部鍵**——union 不允許選填欄位，
// 否則「缺漏」與「刻意不帶」無從區分，混合偵測就會出現縫隙。
var rewrapVariantKeys = map[string][]string{
	rewrapModeLocal: {rewrapFieldMode, rewrapFieldNewKEK, rewrapFieldNewKEKConfirm, rewrapFieldConfirmSaved},
	rewrapModeKMS:   {rewrapFieldMode, rewrapFieldKeyRef},
	rewrapModeHSM:   {rewrapFieldMode, rewrapFieldKeyRef},
}

// rewrapKnownFields 全部已知欄位（未知欄位一律拒絕，fail-close）
var rewrapKnownFields = map[string]bool{
	rewrapFieldMode: true, rewrapFieldNewKEK: true, rewrapFieldNewKEKConfirm: true,
	rewrapFieldConfirmSaved: true, rewrapFieldKeyRef: true,
}

// decodeRewrapPayload 解析並驗證重包請求體。
//
// 步驟即 fail-close 的順序：
//  1. 大小上限與 JSON 結構（含未知欄位）；
//  2. 判別子在白名單內；
//  3. **鍵集與變體精確相符**（多一鍵、少一鍵皆拒）——混合 payload 的攔截點；
//  4. 逐欄位型別；
//  5. 本地變體的 paste-back 比對與保存確認旗標。
//
// 材料的格式驗證**不在此處**：它屬伺服端不變式，落在
// keyvault.NewLocalRewrapTarget（唯一構造入口即驗證入口），避免出現「handler 驗過
// 一次、其他呼叫端沒驗」的縫隙。
// decodeRewrapObject 以 token 串流解出鍵值表，並擋掉兩種「精確鍵集」看不見的歧義。
//
//  1. **重複鍵**：`map[string]json.RawMessage` 對重複鍵靜默採最後值，故
//     `{"mode":"local","mode":"kms",...}` 這種輸入在鍵集比對眼中只有一個 mode——
//     union 的判別子因此可以「送兩個、驗一個」，而呼叫端與伺服端對於「這是哪一個
//     變體」的認知可以不同。歧義輸入一律拒絕，不做 first-wins／last-wins 的選擇。
//  2. **尾隨內容**：`Decoder.More()` 只回答「還有沒有下一個**元素**」，對
//     `{...}]` 與 `{...}}` 這類尾隨的結束符回 false，於是壞掉的輸入被當成乾淨的
//     單一文件接受。改為再解一次並要求恰為 io.EOF。
func decodeRewrapObject(body []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return nil, errRewrapPayloadMalformed
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errRewrapPayloadMalformed
	}
	raw := map[string]json.RawMessage{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, errRewrapPayloadMalformed
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errRewrapPayloadMalformed
		}
		if _, dup := raw[key]; dup {
			return nil, errRewrapPayloadMalformed
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errRewrapPayloadMalformed
		}
		raw[key] = v
	}
	tok, err = dec.Token()
	if err != nil {
		return nil, errRewrapPayloadMalformed
	}
	if d, ok := tok.(json.Delim); !ok || d != '}' {
		return nil, errRewrapPayloadMalformed
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errRewrapPayloadMalformed
	}
	return raw, nil
}

func decodeRewrapPayload(body []byte) (*rewrapPayload, error) {
	if len(body) == 0 || len(body) > maxRewrapBodyBytes {
		return nil, errRewrapPayloadMalformed
	}
	// 先解成原始鍵值：鍵的**存在與否**是混合偵測的判準，故不可直接解進 struct
	//（struct 會把「未帶」與「帶了零值」抹平成同一件事）
	raw, err := decodeRewrapObject(body)
	if err != nil {
		return nil, err
	}
	for key := range raw {
		if !rewrapKnownFields[key] {
			return nil, errRewrapPayloadMalformed
		}
	}

	modeRaw, ok := raw[rewrapFieldMode]
	if !ok {
		return nil, errRewrapModeInvalid
	}
	var mode string
	if err := json.Unmarshal(modeRaw, &mode); err != nil {
		return nil, errRewrapPayloadMalformed
	}
	want, known := rewrapVariantKeys[mode]
	if !known {
		return nil, errRewrapModeInvalid
	}

	// 鍵集精確比對：任一方向不符即混合 payload
	if len(raw) != len(want) {
		return nil, errRewrapPayloadMixed
	}
	for _, key := range want {
		if _, present := raw[key]; !present {
			return nil, errRewrapPayloadMixed
		}
	}

	p := &rewrapPayload{Mode: mode}
	switch mode {
	case rewrapModeLocal:
		if err := json.Unmarshal(raw[rewrapFieldNewKEK], &p.NewKEK); err != nil {
			return nil, errRewrapPayloadMalformed
		}
		if err := json.Unmarshal(raw[rewrapFieldNewKEKConfirm], &p.NewKEKConfirm); err != nil {
			return nil, errRewrapPayloadMalformed
		}
		if err := json.Unmarshal(raw[rewrapFieldConfirmSaved], &p.ConfirmSaved); err != nil {
			return nil, errRewrapPayloadMalformed
		}
		// paste-back 比對——伺服端唯一信任的機械不變式；不符即拒且不產生任何
		// data_keys 寫入
		if p.NewKEK != p.NewKEKConfirm {
			p.Zeroize()
			return nil, errRewrapConfirmMismatch
		}
		// 保存確認旗標：UX 意圖聲明，不具授權力，但契約上要求為真（否則直打 API
		// 即繞過精靈的警語）
		if !p.ConfirmSaved {
			p.Zeroize()
			return nil, errRewrapNotSaved
		}
	case rewrapModeKMS, rewrapModeHSM:
		if err := json.Unmarshal(raw[rewrapFieldKeyRef], &p.KeyRef); err != nil {
			return nil, errRewrapPayloadMalformed
		}
	}
	return p, nil
}
