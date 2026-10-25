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
//	go run . -input checkpoints.json -pubkey <KEY> -tamper perm-origin      # 翻轉第四版附證的起點旗標
//	go run . -input checkpoints.json -pubkey <KEY> -tamper scheme-downgrade # 第四版點改標第三版並拿掉 perm
//
//	# 只印某一點重建出的 payload 位元組（供他語言實作逐位元組比對）
//	go run . -input checkpoints.json -pubkey <KEY> -only-seq 21 -show-payload
//
// 支援的載荷版本：cp-agg-v1、v2（角色指派快照）、v3（帳本區間四欄）、v4（權限附證 perm 鍵）。
//
// 離開碼：0＝全部通過；1＝有檢查點未通過（含「載荷無法重建」）；2＝輸入或環境錯誤（含未知版本）。
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
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

	// 以下四欄自載荷版本 cp-agg-v2 起存在（角色指派納入鏈）。
	// v1 的檢查點沒有這些欄位，API 亦不回傳——**缺席即代表 v1**，
	// 不可視為「v2 但欄位遺失」而放行
	RoleStateSnapshot   *string `json:"role_state_snapshot"`
	RoleStateHash       *string `json:"role_state_hash"`
	RoleStateCount      *int64  `json:"role_state_count"`
	RoleStateReconciled *bool   `json:"role_state_reconciled"`

	// 帳本區間四欄：自 cp-agg-v3 起必備（v1／v2 不得帶）
	ToolCallIDFrom   *uint64 `json:"tool_call_id_from"`
	ToolCallIDTo     *uint64 `json:"tool_call_id_to"`
	ToolCallRowCount *int64  `json:"tool_call_row_count"`
	ToolCallAggHash  *string `json:"tool_call_agg_hash"`

	// perm：自 cp-agg-v4 起每一列都帶此鍵（物件或 null）。以原始位元組另行解析（見 parsePermWire），
	// 不經 encoding/json 的結構映射：要分辨「鍵缺席」與「值為 null」，且整數不得經 float64 中轉
	permPresent bool
	permRaw     json.RawMessage
}

// permEntry 第四版載荷 perm 物件的八個值（鍵序固定，見 permKeys）
type permEntry struct {
	format, model  string // 十進位整數字面（原樣保留，不經 float64）
	catalog        string
	snapshotDigest string
	eventSeq       string
	eventHead      string
	reconciled     string // "true"／"false"／"null"
	origin         bool
}

var permKeys = []string{"format", "model", "catalog", "snapshot_digest", "event_seq", "event_head", "reconciled", "origin"}

// supportedPermFormats 本工具支援的權限快照格式版本（perm.format 的值域），與產品端能解碼的格式同一集合。
// 未列出的值（含大於現行版本的正整數）一律報「載荷無法重建」：產品端對未知格式判 payload_invalid，
// 驗證器若照樣重建去驗章，只會把格式不符誤報成簽章無效。產品新增格式時，本集合與規格文件一併擴充。
var supportedPermFormats = map[string]bool{"1": true, "2": true}

// supportedPermFormatList 供錯誤訊息列出已支援的格式（固定次序）
const supportedPermFormatList = "1、2"

// 載荷版本標識（欄位 agg_scheme）。
//
// v1：不含 state。v2：加 state 與 role_state_reconciled 兩鍵。
// 未知版本一律拒驗——猜一個形狀去驗，結果會是「簽章驗不過」而掩蓋真正的原因
const (
	schemeV1 = "cp-agg-v1"
	schemeV2 = "cp-agg-v2"
	schemeV3 = "cp-agg-v3"
	schemeV4 = "cp-agg-v4"
)

// schemeRank 載荷版本序；未知為 0
func schemeRank(s string) int {
	switch s {
	case schemeV1:
		return 1
	case schemeV2:
		return 2
	case schemeV3:
		return 3
	case schemeV4:
		return 4
	}
	return 0
}

// errPayload 「載荷無法重建」：欄位組合不合規格（缺鍵、多鍵、值域外）。
// 與「簽章無效」分開回報——兩者的處置不同
type errPayload struct{ msg string }

func (e errPayload) Error() string { return "載荷無法重建：" + e.msg }

func payloadErr(format string, a ...any) error { return errPayload{fmt.Sprintf(format, a...)} }

// stateEntry 載荷內單一狀態表的摘要
type stateEntry struct {
	table string
	hash  string
	count int64
}

// stateHash 狀態表快照本體的長度前綴 SHA-256（hex）：
// SHA-256( 大端 8 bytes 的本體長度 ‖ 本體位元組 )
func stateHash(body []byte) string {
	var prefix [8]byte
	n := uint64(len(body))
	for i := 7; i >= 0; i-- {
		prefix[i] = byte(n)
		n >>= 8
	}
	h := sha256.New()
	h.Write(prefix[:])
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// stateEntries 由 role_state_snapshot 重建載荷的 state 陣列。
//
// 摘要**由快照本體現算**（不取 role_state_hash 欄）：產品端簽的就是現算值，
// 取欄位會讓「本體被改、摘要欄沒改」的檢查點在本工具這裡驗過而在系統內驗不過。
// 快照本體不可得時（部署把該欄自 API 投影拿掉）退回摘要欄，並在報表上標明——
// 那時本工具驗的是「摘要未被改」，不是「快照未被改」
func stateEntries(cp checkpoint) ([]stateEntry, bool, error) {
	if cp.RoleStateSnapshot == nil || *cp.RoleStateSnapshot == "" {
		if cp.RoleStateHash == nil || cp.RoleStateCount == nil {
			return nil, false, fmt.Errorf("seq=%d 宣稱載荷版本 %s 卻無 role_state_snapshot／role_state_hash：無從重建 state",
				cp.Seq, cp.AggScheme)
		}
		return []stateEntry{{table: "user_roles", hash: *cp.RoleStateHash, count: *cp.RoleStateCount}}, true, nil
	}
	var tables map[string]json.RawMessage
	if err := json.Unmarshal([]byte(*cp.RoleStateSnapshot), &tables); err != nil {
		return nil, false, fmt.Errorf("seq=%d 的 role_state_snapshot 不是以表名為鍵的 JSON 物件: %w", cp.Seq, err)
	}
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]stateEntry, 0, len(names))
	for _, name := range names {
		body := []byte(tables[name])
		var elems []json.RawMessage
		if err := json.Unmarshal(body, &elems); err != nil {
			return nil, false, fmt.Errorf("seq=%d 表 %s 的快照本體不是陣列: %w", cp.Seq, name, err)
		}
		out = append(out, stateEntry{table: name, hash: stateHash(body), count: int64(len(elems))})
	}
	return out, false, nil
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
	rank := schemeRank(cp.AggScheme)
	if rank == 0 {
		return nil, fmt.Errorf("seq=%d 的 agg_scheme %q 非本工具已知的載荷版本（%s／%s／%s／%s）："+
			"請改用與該版本相符的驗證器，猜一個形狀去驗只會產出誤導的失敗",
			cp.Seq, cp.AggScheme, schemeV1, schemeV2, schemeV3, schemeV4)
	}
	hasLedger := cp.ToolCallIDFrom != nil || cp.ToolCallIDTo != nil || cp.ToolCallRowCount != nil || cp.ToolCallAggHash != nil
	if rank < 3 && hasLedger {
		return nil, payloadErr("seq=%d 宣稱 %s 卻帶帳本區間欄（降版）", cp.Seq, cp.AggScheme)
	}
	if rank < 4 && cp.permPresent {
		return nil, payloadErr("seq=%d 宣稱 %s 卻帶 perm 鍵（第四版之前的列不得帶）", cp.Seq, cp.AggScheme)
	}
	if rank >= 3 && (cp.ToolCallIDFrom == nil || cp.ToolCallIDTo == nil || cp.ToolCallRowCount == nil || cp.ToolCallAggHash == nil) {
		return nil, payloadErr("seq=%d 宣稱 %s 卻缺帳本區間四欄", cp.Seq, cp.AggScheme)
	}
	var perm *permEntry
	if rank == 4 {
		if !cp.permPresent {
			return nil, payloadErr("seq=%d 是 %s 卻缺 perm 鍵（本工具不自行補 null）", cp.Seq, cp.AggScheme)
		}
		p, err := parsePermWire(cp.permRaw)
		if err != nil {
			return nil, payloadErr("seq=%d 的 perm：%v", cp.Seq, err)
		}
		perm = p
	}
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

	// v2 起：state 與 role_state_reconciled 插在兩個時間欄之間（規格所定的欄位順序）
	if rank >= 2 {
		entries, _, err := stateEntries(cp)
		if err != nil {
			return nil, err
		}
		b.WriteString(`,"state":[`)
		for i, e := range entries {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`{"table":`)
			if err := jsonString(&b, e.table); err != nil {
				return nil, err
			}
			b.WriteString(`,"hash":`)
			if err := jsonString(&b, e.hash); err != nil {
				return nil, err
			}
			b.WriteString(`,"count":`)
			b.WriteString(strconv.FormatInt(e.count, 10))
			b.WriteByte('}')
		}
		b.WriteString(`],"role_state_reconciled":`)
		switch {
		case cp.RoleStateReconciled == nil:
			b.WriteString("null")
		case *cp.RoleStateReconciled:
			b.WriteString("true")
		default:
			b.WriteString("false")
		}
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

	// v3 起：帳本區間四欄接在 signing_key_version 之後
	if rank >= 3 {
		b.WriteString(`,"tool_call_id_from":`)
		b.WriteString(strconv.FormatUint(*cp.ToolCallIDFrom, 10))
		b.WriteString(`,"tool_call_id_to":`)
		b.WriteString(strconv.FormatUint(*cp.ToolCallIDTo, 10))
		b.WriteString(`,"tool_call_row_count":`)
		b.WriteString(strconv.FormatInt(*cp.ToolCallRowCount, 10))
		b.WriteString(`,"tool_call_agg_hash":`)
		if err := jsonString(&b, *cp.ToolCallAggHash); err != nil {
			return nil, err
		}
	}

	// v4：perm 鍵在最後（物件依固定鍵序重建，或 null）
	if rank == 4 {
		b.WriteString(`,"perm":`)
		if perm == nil {
			b.WriteString("null")
		} else {
			writePerm(&b, perm)
		}
	}

	b.WriteByte('}')
	return b.Bytes(), nil
}

// writePerm 依固定鍵序寫出 perm 物件（所有字串值已驗過為小寫 hex，不需跳脫）
func writePerm(b *bytes.Buffer, p *permEntry) {
	b.WriteString(`{"format":` + p.format)
	b.WriteString(`,"model":` + p.model)
	b.WriteString(`,"catalog":"` + p.catalog + `"`)
	b.WriteString(`,"snapshot_digest":"` + p.snapshotDigest + `"`)
	b.WriteString(`,"event_seq":` + p.eventSeq)
	b.WriteString(`,"event_head":"` + p.eventHead + `"`)
	b.WriteString(`,"reconciled":` + p.reconciled)
	if p.origin {
		b.WriteString(`,"origin":true}`)
	} else {
		b.WriteString(`,"origin":false}`)
	}
}

// parsePermWire 解析列表回應中的 perm 值：null 回 (nil, nil)；物件則逐鍵讀取，
// 重複鍵、未知鍵、缺鍵、型別或值域不符、format 不在已支援集合一律回錯（呼叫端報「載荷無法重建」）。
// 不要求 wire 上的鍵序；重建時依規格的固定鍵序輸出。
func parsePermWire(raw json.RawMessage) (*permEntry, error) {
	trimmed := bytes.TrimSpace(raw)
	if string(trimmed) == "null" {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("不是物件也不是 null")
	}
	seen := map[string]bool{}
	var p permEntry
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := kt.(string)
		if seen[key] {
			return nil, fmt.Errorf("重複鍵 %q", key)
		}
		seen[key] = true
		vt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch key {
		case "format", "model", "event_seq":
			n, ok := vt.(json.Number)
			if !ok || !positiveDecimal(string(n)) {
				return nil, fmt.Errorf("%s 不是正十進位整數：%v", key, vt)
			}
			switch key {
			case "format":
				p.format = string(n)
			case "model":
				p.model = string(n)
			default:
				p.eventSeq = string(n)
			}
		case "catalog", "snapshot_digest", "event_head":
			str, ok := vt.(string)
			want := 64
			if key == "catalog" {
				want = 32
			}
			if !ok || !lowerHex(str, want) {
				return nil, fmt.Errorf("%s 不是 %d 字元小寫 hex", key, want)
			}
			switch key {
			case "catalog":
				p.catalog = str
			case "snapshot_digest":
				p.snapshotDigest = str
			default:
				p.eventHead = str
			}
		case "reconciled":
			switch v := vt.(type) {
			case nil:
				p.reconciled = "null"
			case bool:
				p.reconciled = strconv.FormatBool(v)
			default:
				return nil, fmt.Errorf("reconciled 不是布林或 null")
			}
		case "origin":
			v, ok := vt.(bool)
			if !ok {
				return nil, fmt.Errorf("origin 不是布林")
			}
			p.origin = v
		default:
			return nil, fmt.Errorf("未知鍵 %q", key)
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("物件之後還有多餘內容")
	}
	for _, k := range permKeys {
		if !seen[k] {
			return nil, fmt.Errorf("缺鍵 %q", k)
		}
	}
	if !supportedPermFormats[p.format] {
		return nil, fmt.Errorf("format %s 不是本工具支援的權限快照格式版本（已支援：%s）", p.format, supportedPermFormatList)
	}
	if p.origin && p.eventSeq != "1" {
		return nil, fmt.Errorf("origin=true 時 event_seq 必為 1（得 %s）", p.eventSeq)
	}
	if _, err := strconv.ParseInt(p.eventSeq, 10, 64); err != nil {
		return nil, fmt.Errorf("event_seq 超出 int64：%v", err)
	}
	return &p, nil
}

// positiveDecimal 十進位、無符號前綴、無前導零、無小數與指數、≥ 1
func positiveDecimal(s string) bool {
	if s == "" || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
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

type keyEnvelope struct {
	Data struct {
		Algorithm   string `json:"algorithm"`
		Version     int    `json:"version"`
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	} `json:"data"`
}

type rawListEnvelope struct {
	Data struct {
		Items []json.RawMessage `json:"items"`
		Total int64             `json:"total"`
	} `json:"data"`
}

// decodeCheckpoint 解一筆檢查點：一般欄位走結構映射，perm 另取原始位元組並記下是否出現
// （同一列出現兩個 perm 鍵視為輸入錯誤）
func decodeCheckpoint(raw json.RawMessage) (checkpoint, error) {
	var cp checkpoint
	if err := json.Unmarshal(raw, &cp); err != nil {
		return cp, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return cp, err
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return cp, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return cp, err
		}
		if kt == "perm" {
			if cp.permPresent {
				return cp, fmt.Errorf("seq=%d 帶兩個 perm 鍵", cp.Seq)
			}
			cp.permPresent, cp.permRaw = true, v
		}
	}
	return cp, nil
}

func decodeCheckpoints(items []json.RawMessage) ([]checkpoint, error) {
	out := make([]checkpoint, 0, len(items))
	for _, it := range items {
		cp, err := decodeCheckpoint(it)
		if err != nil {
			return nil, err
		}
		out = append(out, cp)
	}
	return out, nil
}

// parseCheckpoints 接受三種形態：API 回應封套、裸陣列、單筆物件
func parseCheckpoints(raw []byte) ([]checkpoint, error) {
	var env rawListEnvelope
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Data.Items) > 0 {
		return decodeCheckpoints(env.Data.Items)
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return decodeCheckpoints(arr)
	}
	if one, err := decodeCheckpoint(raw); err == nil && one.Seq > 0 {
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
		var env rawListEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("解析列表回應失敗: %w", err)
		}
		items, err := decodeCheckpoints(env.Data.Items)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run 主流程（可測）：回傳離開碼。
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("checkpoint-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		apiURL      = fs.String("url", "", "Custodexa 基底 URL（例：http://localhost:8080）")
		token       = fs.String("token", "", "admin 或 auditor 的 Bearer token（配合 -url）")
		input       = fs.String("input", "", "檢查點 JSON 檔（API 回應封套或裸陣列）；與 -url 擇一")
		pubkeyB64   = fs.String("pubkey", "", "Ed25519 公鑰（base64，32 bytes）；用 -url 時可省略，會自動取得")
		onlySeq     = fs.Uint64("only-seq", 0, "只驗指定 seq")
		showPayload = fs.Bool("show-payload", false, "印出重建的 canonical payload 位元組")
		tamper      = fs.String("tamper", "", "反向對照：payload-bit｜row-count｜signature-bit｜perm-origin｜scheme-downgrade（預期驗證失敗）")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "錯誤:", err)
		return 2
	}

	if *apiURL == "" && *input == "" {
		fmt.Fprintln(stderr, "錯誤：必須指定 -url 或 -input")
		fs.Usage()
		return 2
	}

	var raw []byte
	var err error
	key := *pubkeyB64

	var fetched []checkpoint
	if *apiURL != "" {
		fetched, err = fetchAllCheckpoints(*apiURL, *token)
		if err != nil {
			return fail(err)
		}
		if key == "" {
			kraw, kerr := httpGetJSON(*apiURL+"/api/v1/audit-checkpoints/public-key", *token)
			if kerr != nil {
				return fail(kerr)
			}
			var ke keyEnvelope
			if jerr := json.Unmarshal(kraw, &ke); jerr != nil {
				return fail(jerr)
			}
			key = ke.Data.PublicKey
			fmt.Fprintf(stdout, "公鑰來源：API  演算法=%s  版本=%d  指紋=%s\n",
				ke.Data.Algorithm, ke.Data.Version, ke.Data.Fingerprint)
		}
	} else {
		raw, err = os.ReadFile(*input)
		if err != nil {
			return fail(err)
		}
	}
	if key == "" {
		return fail(fmt.Errorf("缺少公鑰：請給 -pubkey，或以 -url 自動取得"))
	}

	pub, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fail(fmt.Errorf("公鑰 base64 解碼失敗: %w", err))
	}
	if len(pub) != ed25519.PublicKeySize {
		return fail(fmt.Errorf("公鑰長度 %d ≠ %d", len(pub), ed25519.PublicKeySize))
	}
	fmt.Fprintf(stdout, "公鑰指紋（SHA-256 前 8 bytes hex）＝%s\n", pubFingerprint(pub))

	cps := fetched
	if cps == nil {
		cps, err = parseCheckpoints(raw)
		if err != nil {
			return fail(err)
		}
	}
	if len(cps) == 0 {
		return fail(fmt.Errorf("沒有任何檢查點可驗"))
	}
	sort.Slice(cps, func(i, j int) bool { return cps[i].Seq < cps[j].Seq })

	if *tamper != "" {
		fmt.Fprintf(stdout, "反向對照模式：-tamper %s（以下結果應為 FAIL）\n", *tamper)
	}
	fmt.Fprintf(stdout, "檢查點 %d 筆，seq %d..%d\n\n", len(cps), cps[0].Seq, cps[len(cps)-1].Seq)

	var okSig, badSig, okLink, badLink, stateFallback int
	perScheme := map[string]int{}
	prevLink := ""
	prevIDTo := uint64(0)
	prevRank := 0
	failed := false

	for i, cp := range cps {
		// 鏈接雜湊必須逐點續算，故即使 -only-seq 也不能跳過重建
		mutated := cp
		if *tamper == "row-count" && shouldTamper(cp.Seq, *onlySeq) {
			mutated.RowCount++
		}
		if *tamper == "perm-origin" && shouldTamper(cp.Seq, *onlySeq) && cp.AggScheme == schemeV4 {
			mutated.permRaw = flipPermOrigin(cp.permRaw)
		}
		if *tamper == "scheme-downgrade" && shouldTamper(cp.Seq, *onlySeq) && cp.AggScheme == schemeV4 {
			// 模擬只持資料庫帳密者把第四版點改標第三版並清空附證：以第三版形狀重建
			mutated.AggScheme, mutated.permPresent, mutated.permRaw = schemeV3, false, nil
		}
		signed, berr := signBytes(mutated)
		if berr != nil {
			var pe errPayload
			if errors.As(berr, &pe) {
				fmt.Fprintf(stdout, "seq=%-4d %v\n", cp.Seq, berr)
				fmt.Fprintln(stdout, "結果：未全數通過（載荷無法重建，之後的鏈接無從續算）")
				return 1
			}
			return fail(berr)
		}
		perScheme[mutated.AggScheme]++
		if r := schemeRank(mutated.AggScheme); r < prevRank {
			fmt.Fprintf(stdout, "seq=%-4d 載荷版本 %s 低於前一點（版本序不得遞減）\n", cp.Seq, mutated.AggScheme)
			failed = true
		} else {
			prevRank = r
		}
		if schemeRank(cp.AggScheme) >= 2 {
			if _, fellBack, serr := stateEntries(cp); serr == nil && fellBack {
				stateFallback++
			}
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
			return fail(fmt.Errorf("seq=%d 簽章 base64 解碼失敗: %w", cp.Seq, derr))
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
			fmt.Fprintf(stdout, "seq=%-4d %s 簽章=%-4s 鏈接=%-12s 區間鄰接=%-8s 區間=[%d,%d] rows=%d key_ver=%d\n",
				cp.Seq, mutated.AggScheme, state, linkState, adjState, cp.IDFrom, cp.IDTo, cp.RowCount, cp.SigningKeyVersion)
			if *showPayload {
				fmt.Fprintf(stdout, "   payload = %s\n", signed)
				fmt.Fprintf(stdout, "   sha256(payload) = %x\n", sha256.Sum256(signed))
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
			return fail(lerr)
		}
		prevLink = lh
		prevIDTo = cp.IDTo
	}

	fmt.Fprintf(stdout, "\n總計：簽章 PASS=%d FAIL=%d；鏈接 PASS=%d FAIL=%d\n", okSig, badSig, okLink, badLink)
	fmt.Fprintf(stdout, "載荷版本：%s %d 筆（含權限附證 perm 鍵）、%s %d 筆（含帳本區間）、%s %d 筆（含角色指派快照）、%s %d 筆\n",
		schemeV4, perScheme[schemeV4], schemeV3, perScheme[schemeV3], schemeV2, perScheme[schemeV2], schemeV1, perScheme[schemeV1])
	if stateFallback > 0 {
		fmt.Fprintf(stdout, "註：其中 %d 筆未取得 role_state_snapshot，改以 role_state_hash 欄重建 state。\n"+
			"    此時驗到的是「摘要欄未被改」，不是「快照本體未被改」。\n", stateFallback)
	}
	if perScheme[schemeV4] > 0 {
		fmt.Fprintln(stdout, "註：第四版的 perm 物件只帶權限快照的摘要，本工具驗到的是「摘要、界標、對帳結果與起點旗標未被改」，")
		fmt.Fprintln(stdout, "    不是「快照本體未被改」（本體不外送，由產品端現算摘要比對）。")
	}
	fmt.Fprintln(stdout, "註：鏈頭（最小 seq）的 prev_checkpoint_hash 錨定 integrity_baselines，")
	fmt.Fprintln(stdout, "    該錨定值需要基準記錄才能重算，不在本工具的外部可驗範圍內（見規格文件「誠實邊界」）。")
	if failed {
		fmt.Fprintln(stdout, "結果：未全數通過")
		return 1
	}
	fmt.Fprintln(stdout, "結果：全數通過")
	return 0
}

// flipPermOrigin 翻轉 perm 物件的 origin 值（反向對照用）；null 或解析不了時原樣回傳
func flipPermOrigin(raw json.RawMessage) json.RawMessage {
	s := string(raw)
	switch {
	case strings.Contains(s, `"origin":true`):
		return json.RawMessage(strings.Replace(s, `"origin":true`, `"origin":false`, 1))
	case strings.Contains(s, `"origin":false`):
		return json.RawMessage(strings.Replace(s, `"origin":false`, `"origin":true`, 1))
	}
	return raw
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
