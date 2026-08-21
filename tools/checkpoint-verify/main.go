// checkpoint-verify —— Custodexa 審計檢查點鏈的**獨立離線驗章工具**。
//
// 本程式刻意**不 import 任何產品程式碼、不依賴任何第三方套件**：它只吃
// 「公鑰 ＋ 檢查點欄位」，依 docs/security/audit-checkpoint-offline-verification.md
// 所載的 canonical 規格自行重建被簽位元組，再以 Ed25519 驗章。
// 這是「系統內驗證」以外的第二條獨立路徑——系統內驗證與封章共用同一份程式碼，
// 證明不了規格本身可被外部重建。
//
// 用法：
//
//	# 線上：直接向 API 取公鑰與檢查點
//	go run . -url http://localhost:8080 -token "$TOKEN"
//
//	# 離線：稽核方手上只有匯出的 JSON 與公鑰
//	go run . -input checkpoints.json -pubkey 2i0fl9yPbPABeYN1gxlPCmldrxcq5jrD5lMqXuzyYUE=
//
//	# 反向對照（證明驗證器真的會拒絕）：
//	go run . -input checkpoints.json -pubkey <KEY> -tamper payload-bit
//	go run . -input checkpoints.json -pubkey <KEY> -tamper row-count
//	go run . -input checkpoints.json -pubkey <KEY> -tamper signature-bit
//
//	# 只印某一點重建出的 payload 位元組（供他語言實作逐位元組比對）
//	go run . -input checkpoints.json -pubkey <KEY> -only-seq 21 -show-payload
//
// 離開碼：0＝全部通過；1＝有檢查點未通過；2＝輸入或環境錯誤。
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

// checkpoint 為 API `GET /api/v1/audit-checkpoints` 回傳的單筆檢查點。
//
// 時間欄以字串收下（RFC 3339），**不使用 time.Time 自動解析**：
// canonical 規格要的是微秒整數，解析與換算過程必須是本程式看得見的一步
type checkpoint struct {
	Seq                uint64  `json:"seq"`
	IDFrom             uint64  `json:"id_from"`
	IDTo               uint64  `json:"id_to"`
	RowCount           int64   `json:"row_count"`
	AggHash            string  `json:"agg_hash"`
	AggScheme          string  `json:"agg_scheme"`
	PrevCheckpointHash string  `json:"prev_checkpoint_hash"`
	MinCreatedAt       *string `json:"min_created_at"`
	MaxCreatedAt       *string `json:"max_created_at"`
	SealedAt           string  `json:"sealed_at"`
	SigningKeyVersion  int     `json:"signing_key_version"`
	Signature          string  `json:"signature"`
}

// ── canonical 位元組重建（本檔的核心；規格見 docs/security/…-offline-verification.md）──

// jsonString 依 JSON 規範輸出字串常量。
//
// 檢查點的字串欄位只會是 hex／base64／受控枚舉，理論上不含需跳脫字元；
// 遇到意外字元時**直接報錯而不猜跳脫規則**——猜錯會產出一個「看起來驗不過」
// 的結果，把規格問題偽裝成竄改
func jsonString(buf *bytes.Buffer, s string) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			return fmt.Errorf("欄位值含需跳脫字元 %q（位置 %d）：本工具僅支援 hex／base64／枚舉值，請比對規格文件的跳脫章節", c, i)
		}
	}
	buf.WriteByte('"')
	buf.WriteString(s)
	buf.WriteByte('"')
	return nil
}

// unixMicro 將 RFC 3339 時間字串轉為 Unix 微秒（向下取整至微秒）
func unixMicro(s string) (int64, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, fmt.Errorf("解析時間 %q 失敗: %w", s, err)
	}
	return t.UnixMicro(), nil
}

// signBytes 重建檢查點的簽章輸入位元組。
//
// 欄位順序與型別為規格的一部分，逐欄手寫而非仰賴 struct tag 順序：
// 手寫使「順序」成為本檔可被審視的明文事實
func signBytes(cp checkpoint) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')

	b.WriteString(`"seq":`)
	b.WriteString(strconv.FormatUint(cp.Seq, 10))

	b.WriteString(`,"id_from":`)
	b.WriteString(strconv.FormatUint(cp.IDFrom, 10))

	b.WriteString(`,"id_to":`)
	b.WriteString(strconv.FormatUint(cp.IDTo, 10))

	b.WriteString(`,"row_count":`)
	b.WriteString(strconv.FormatInt(cp.RowCount, 10))

	b.WriteString(`,"agg_hash":`)
	if err := jsonString(&b, cp.AggHash); err != nil {
		return nil, err
	}

	b.WriteString(`,"agg_scheme":`)
	if err := jsonString(&b, cp.AggScheme); err != nil {
		return nil, err
	}

	b.WriteString(`,"prev_checkpoint_hash":`)
	if err := jsonString(&b, cp.PrevCheckpointHash); err != nil {
		return nil, err
	}

	// 可空時間欄：API 在空區間時**省略**該鍵，canonical payload 則必須寫出 null
	b.WriteString(`,"min_created_at_us":`)
	if err := writeMicroOrNull(&b, cp.MinCreatedAt); err != nil {
		return nil, err
	}
	b.WriteString(`,"max_created_at_us":`)
	if err := writeMicroOrNull(&b, cp.MaxCreatedAt); err != nil {
		return nil, err
	}

	sealed, err := unixMicro(cp.SealedAt)
	if err != nil {
		return nil, err
	}
	b.WriteString(`,"sealed_at_us":`)
	b.WriteString(strconv.FormatInt(sealed, 10))

	b.WriteString(`,"signing_key_version":`)
	b.WriteString(strconv.Itoa(cp.SigningKeyVersion))

	b.WriteByte('}')
	return b.Bytes(), nil
}

func writeMicroOrNull(b *bytes.Buffer, s *string) error {
	if s == nil || *s == "" {
		b.WriteString("null")
		return nil
	}
	us, err := unixMicro(*s)
	if err != nil {
		return err
	}
	b.WriteString(strconv.FormatInt(us, 10))
	return nil
}

// linkHash 重建鏈接雜湊＝下一個檢查點的 prev_checkpoint_hash。
//
// signed 以「原樣位元組」內嵌（非再次字串化）：巢狀字串化會引入跳脫規則，
// 外部驗證者難以逐位元組重建
func linkHash(signed []byte, signature string) (string, error) {
	var b bytes.Buffer
	b.WriteString(`{"signed":`)
	b.Write(signed)
	b.WriteString(`,"signature":`)
	if err := jsonString(&b, signature); err != nil {
		return "", err
	}
	b.WriteByte('}')
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// ── 輸入取得 ────────────────────────────────────────────────────────────

type listEnvelope struct {
	Data struct {
		Items []checkpoint `json:"items"`
		Total int64        `json:"total"`
	} `json:"data"`
}

type keyEnvelope struct {
	Data struct {
		Algorithm   string `json:"algorithm"`
		Version     int    `json:"version"`
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	} `json:"data"`
}

// parseCheckpoints 接受三種形態：API 回應封套、裸陣列、單筆物件
func parseCheckpoints(raw []byte) ([]checkpoint, error) {
	var env listEnvelope
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Data.Items) > 0 {
		return env.Data.Items, nil
	}
	var arr []checkpoint
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return arr, nil
	}
	var one checkpoint
	if err := json.Unmarshal(raw, &one); err == nil && one.Seq > 0 {
		return []checkpoint{one}, nil
	}
	return nil, fmt.Errorf("無法解析輸入：預期 API 回應封套、檢查點陣列或單筆檢查點物件")
}

// fetchAllCheckpoints 逐頁取完整條鏈。
//
// **必須分頁而非只取第一頁**：列表端點單頁上限 200，而鏈長可達萬級；
// 只取首頁會讓「其餘檢查點」在報表上安靜消失——那正是本工具要防的失真
func fetchAllCheckpoints(base, token string) ([]checkpoint, error) {
	const pageSize = 200
	var all []checkpoint
	for page := 1; ; page++ {
		url := fmt.Sprintf("%s/api/v1/audit-checkpoints?page=%d&page_size=%d", base, page, pageSize)
		raw, err := httpGetJSON(url, token)
		if err != nil {
			return nil, err
		}
		var env listEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("解析列表回應失敗: %w", err)
		}
		all = append(all, env.Data.Items...)
		if len(env.Data.Items) == 0 || int64(len(all)) >= env.Data.Total {
			if int64(len(all)) != env.Data.Total {
				return nil, fmt.Errorf("取回 %d 筆與 total=%d 不符：鏈可能在讀取期間變動，請重試",
					len(all), env.Data.Total)
			}
			return all, nil
		}
	}
}

func httpGetJSON(url, token string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s 回 %d: %s", url, resp.StatusCode, truncate(string(body), 200))
	}
	return body, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── 主流程 ──────────────────────────────────────────────────────────────

func main() {
	var (
		apiURL      = flag.String("url", "", "Custodexa 基底 URL（例：http://localhost:8080）")
		token       = flag.String("token", "", "admin 或 auditor 的 Bearer token（配合 -url）")
		input       = flag.String("input", "", "檢查點 JSON 檔（API 回應封套或裸陣列）；與 -url 擇一")
		pubkeyB64   = flag.String("pubkey", "", "Ed25519 公鑰（base64，32 bytes）；用 -url 時可省略，會自動取得")
		onlySeq     = flag.Uint64("only-seq", 0, "只驗指定 seq")
		showPayload = flag.Bool("show-payload", false, "印出重建的 canonical payload 位元組")
		tamper      = flag.String("tamper", "", "反向對照：payload-bit｜row-count｜signature-bit（預期驗證失敗）")
	)
	flag.Parse()

	if *apiURL == "" && *input == "" {
		fmt.Fprintln(os.Stderr, "錯誤：必須指定 -url 或 -input")
		flag.Usage()
		os.Exit(2)
	}

	var raw []byte
	var err error
	key := *pubkeyB64

	var fetched []checkpoint
	if *apiURL != "" {
		fetched, err = fetchAllCheckpoints(*apiURL, *token)
		if err != nil {
			fail(err)
		}
		if key == "" {
			kraw, kerr := httpGetJSON(*apiURL+"/api/v1/audit-checkpoints/public-key", *token)
			if kerr != nil {
				fail(kerr)
			}
			var ke keyEnvelope
			if jerr := json.Unmarshal(kraw, &ke); jerr != nil {
				fail(jerr)
			}
			key = ke.Data.PublicKey
			fmt.Printf("公鑰來源：API  演算法=%s  版本=%d  指紋=%s\n",
				ke.Data.Algorithm, ke.Data.Version, ke.Data.Fingerprint)
		}
	} else {
		raw, err = os.ReadFile(*input)
		if err != nil {
			fail(err)
		}
	}
	if key == "" {
		fail(fmt.Errorf("缺少公鑰：請給 -pubkey，或以 -url 自動取得"))
	}

	pub, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		fail(fmt.Errorf("公鑰 base64 解碼失敗: %w", err))
	}
	if len(pub) != ed25519.PublicKeySize {
		fail(fmt.Errorf("公鑰長度 %d ≠ %d", len(pub), ed25519.PublicKeySize))
	}
	fmt.Printf("公鑰指紋（SHA-256 前 8 bytes hex）＝%s\n", pubFingerprint(pub))

	cps := fetched
	if cps == nil {
		cps, err = parseCheckpoints(raw)
		if err != nil {
			fail(err)
		}
	}
	if len(cps) == 0 {
		fail(fmt.Errorf("沒有任何檢查點可驗"))
	}
	sort.Slice(cps, func(i, j int) bool { return cps[i].Seq < cps[j].Seq })

	if *tamper != "" {
		fmt.Printf("反向對照模式：-tamper %s（以下結果應為 FAIL）\n", *tamper)
	}
	fmt.Printf("檢查點 %d 筆，seq %d..%d\n\n", len(cps), cps[0].Seq, cps[len(cps)-1].Seq)

	var okSig, badSig, okLink, badLink int
	prevLink := ""
	prevIDTo := uint64(0)
	failed := false

	for i, cp := range cps {
		// 鏈接雜湊必須逐點續算，故即使 -only-seq 也不能跳過重建
		mutated := cp
		if *tamper == "row-count" && shouldTamper(cp.Seq, *onlySeq) {
			mutated.RowCount++
		}
		signed, berr := signBytes(mutated)
		if berr != nil {
			fail(berr)
		}
		if *tamper == "payload-bit" && shouldTamper(cp.Seq, *onlySeq) {
			signed[len(signed)-3] ^= 0x01
		}
		sigB64 := cp.Signature
		if *tamper == "signature-bit" && shouldTamper(cp.Seq, *onlySeq) {
			sigB64 = flipSignatureBit(sigB64)
		}

		sig, derr := base64.StdEncoding.DecodeString(sigB64)
		if derr != nil {
			fail(fmt.Errorf("seq=%d 簽章 base64 解碼失敗: %w", cp.Seq, derr))
		}
		sigOK := ed25519.Verify(pub, signed, sig)

		linkState := "n/a（鏈頭）"
		if i > 0 {
			if cp.PrevCheckpointHash == prevLink {
				linkState = "PASS"
				okLink++
			} else {
				linkState = fmt.Sprintf("FAIL（記錄 %s… ≠ 重算 %s…）",
					head(cp.PrevCheckpointHash, 16), head(prevLink, 16))
				badLink++
			}
		}
		adjState := "n/a"
		if i > 0 {
			if cp.IDFrom == prevIDTo+1 {
				adjState = "PASS"
			} else {
				adjState = fmt.Sprintf("FAIL（id_from=%d ≠ 前點 id_to+1=%d）", cp.IDFrom, prevIDTo+1)
			}
		}

		if *onlySeq == 0 || cp.Seq == *onlySeq {
			state := "PASS"
			if !sigOK {
				state = "FAIL"
			}
			fmt.Printf("seq=%-4d 簽章=%-4s 鏈接=%-12s 區間鄰接=%-8s 區間=[%d,%d] rows=%d key_ver=%d\n",
				cp.Seq, state, linkState, adjState, cp.IDFrom, cp.IDTo, cp.RowCount, cp.SigningKeyVersion)
			if *showPayload {
				fmt.Printf("   payload = %s\n", signed)
				fmt.Printf("   sha256(payload) = %x\n", sha256.Sum256(signed))
			}
		}
		if sigOK {
			okSig++
		} else {
			badSig++
			failed = true
		}
		if linkState != "PASS" && i > 0 {
			failed = true
		}

		lh, lerr := linkHash(signed, sigB64)
		if lerr != nil {
			fail(lerr)
		}
		prevLink = lh
		prevIDTo = cp.IDTo
	}

	fmt.Printf("\n總計：簽章 PASS=%d FAIL=%d；鏈接 PASS=%d FAIL=%d\n", okSig, badSig, okLink, badLink)
	fmt.Println("註：鏈頭（最小 seq）的 prev_checkpoint_hash 錨定 integrity_baselines，")
	fmt.Println("    該錨定值需要基準記錄才能重算，不在本工具的外部可驗範圍內（見規格文件「誠實邊界」）。")
	if failed {
		fmt.Println("結果：未全數通過")
		os.Exit(1)
	}
	fmt.Println("結果：全數通過")
}

func shouldTamper(seq, only uint64) bool { return only == 0 || seq == only }

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func pubFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// flipSignatureBit 翻轉簽章的一個位元（base64 解碼後改，再編回去）
func flipSignatureBit(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 {
		return b64
	}
	raw[0] ^= 0x01
	return base64.StdEncoding.EncodeToString(raw)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "錯誤:", err)
	os.Exit(2)
}
