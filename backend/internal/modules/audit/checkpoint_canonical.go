package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"sort"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 檢查點鏈的 canonical 編碼（audit-checkpoint-chain，Open Question O1 判定）。
//
// **一經釘定不再變更**（比照列級 `integrityPayload` 的相容性紀律）：任何編碼
// 演進一律以新的 `agg_scheme` 值表示，舊檢查點續以其原 scheme 重算驗證。
// golden 測試 `TestCheckpointCanonicalGolden` 逐位元組釘住本檔的兩種編碼。
//
// **O1 結論——兩種編碼刻意不同形**：
//
//	聚合串流（每列三元組）＝**定長二進位、HMAC 帶長度前綴**。
//	  理由一（正確性）：分隔符文字編碼在對手可寫 DB 的威脅模型下不是單射——
//	  攻擊者只要把分隔位元組寫進 integrity_hmac 欄，就能讓「一列」與「兩列」
//	  產生相同串流而使抽列不被偵測。長度前綴使編碼對任意欄位內容皆單射，
//	  這正是本機制唯一要防的事。
//	  理由二（成本）：每區間至多約 1 萬列，定長寫入無額外配置，
//	  逐列 json.Marshal 則是萬次配置。
//
//	簽章 payload（檢查點欄位）＝**固定 struct canonical JSON**。
//	  理由：欄位少、人可讀，且離線驗證者（auditor／QSA）以任何語言的 JSON
//	  函式庫即可重建位元組——公鑰離線驗章是本機制的對外承諾，
//	  可重建性優先於微幅效能。與列級 `integrityPayload` 同形，維護心智一致。
//
// 時間欄一律取 UnixMicro：postgres timestamptz 保存微秒精度，
// 納秒會在 round-trip 後不一致（列級蓋章已踩過此坑）。

// checkpointAggEntry 聚合串流的單列輸入（id 升冪，取自 audit_logs 的三欄）
type checkpointAggEntry struct {
	ID            uint
	KeyVersion    int
	IntegrityHMAC string
}

// checkpointAggWriter 聚合雜湊的串流計算器：逐列 Write，最後 Sum。
//
// 串流而非收集後一次算：區間至多約 1 萬列，全載入記憶體無必要，
// 且掃描端本來就是 rows 迭代
type checkpointAggWriter struct {
	h   hash.Hash
	n   int64
	buf [14]byte // 8(id) + 4(key_version) + 2(hmac len)
}

func newCheckpointAggWriter() *checkpointAggWriter {
	return &checkpointAggWriter{h: sha256.New()}
}

// Add 併入一列。編碼＝
//
//	id            8 bytes  big-endian uint64
//	key_version   4 bytes  big-endian int32（負值以二補數寫出，不會發生但不靜默截斷）
//	len(hmac)     2 bytes  big-endian uint16
//	hmac          len bytes 原始位元組（不解 hex——欄位可能為空或非 hex，
//	                        解碼失敗的分支本身就是資訊遺失面）
//
// 長度前綴是本編碼的安全核心：無它則「HMAC 欄含分隔位元組」可構造碰撞。
func (w *checkpointAggWriter) Add(e checkpointAggEntry) {
	binary.BigEndian.PutUint64(w.buf[0:8], uint64(e.ID))
	binary.BigEndian.PutUint32(w.buf[8:12], uint32(int32(e.KeyVersion)))
	hm := []byte(e.IntegrityHMAC)
	if len(hm) > 0xFFFF {
		// 不可能態（欄位為 varchar(64)）；截斷會製造碰撞面，故直接以
		// 長度上限標記——後續 Sum 必與封章時不同，驗證誠實地不通過
		hm = hm[:0xFFFF]
	}
	binary.BigEndian.PutUint16(w.buf[12:14], uint16(len(hm)))
	w.h.Write(w.buf[:])
	w.h.Write(hm)
	w.n++
}

// Sum 回傳 (hex 聚合雜湊, 列數)。空區間＝空輸入的 SHA-256
// （e3b0c442...b855），與「有列但雜湊碰巧相同」不可混淆，因為 row_count 另存
func (w *checkpointAggWriter) Sum() (string, int64) {
	return hex.EncodeToString(w.h.Sum(nil)), w.n
}

// ComputeAggHash 一次性計算聚合雜湊（測試與小批量用；封章路徑走串流 writer）
func ComputeAggHash(entries []checkpointAggEntry) (string, int64) {
	w := newCheckpointAggWriter()
	for _, e := range entries {
		w.Add(e)
	}
	return w.Sum()
}

// checkpointSignPayloadV1 檢查點簽章涵蓋欄位的 canonical 序列化（固定 struct＝固定鍵序）。
//
// **v1 的位元組永遠不再變**：本能力之前封的檢查點全部以此形狀重建驗證，
// 動它一個鍵就是讓全部歷史檢查點驗不過。新欄位一律進 v2（見下）。
//
// 涵蓋範圍**不含** anchor_status／purged_at／
// purge_signature／purge_signing_key_version——皆為封章後才發生的狀態，
// 蓋進簽章就永遠簽不了；purge 的真實性由獨立的 purge 簽章承擔。
type checkpointSignPayloadV1 struct {
	Seq                uint   `json:"seq"`
	IDFrom             uint   `json:"id_from"`
	IDTo               uint   `json:"id_to"`
	RowCount           int64  `json:"row_count"`
	AggHash            string `json:"agg_hash"`
	AggScheme          string `json:"agg_scheme"`
	PrevCheckpointHash string `json:"prev_checkpoint_hash"`
	MinCreatedAtUs     *int64 `json:"min_created_at_us"`
	MaxCreatedAtUs     *int64 `json:"max_created_at_us"`
	SealedAtUs         int64  `json:"sealed_at_us"`
	SigningKeyVersion  int    `json:"signing_key_version"`
}

// checkpointStateEntry 單一登記狀態表在簽章載荷內的摘要
// （載荷形狀：`state: [{table, hash, count}]`）。
//
// **只放摘要不放快照本體**：本體可達數十 KB，簽章載荷是離線驗證者要逐位元組
// 重建的東西，塞進去會讓「以任何語言重建」的承諾變得昂貴。本體的真偽由
// hash 承擔——而 hash 是**由本體現算**的（見 checkpointStateEntries），
// 故改寫快照本體欄會使簽章驗不過，不會只是「欄位與雜湊對不上」
type checkpointStateEntry struct {
	Table string `json:"table"`
	Hash  string `json:"hash"`
	Count int64  `json:"count"`
}

// checkpointSignPayloadV2 第二版載荷：v1 的全部欄位＋狀態表摘要。
//
// **欄位順序依 spec 條文**（`…、min_created_at_us、state、max_created_at_us、…`）：
// 順序是規格的一部分，離線驗證者照文件手寫重建，故此處以 spec 的列舉為準
// 而非「新欄位排在最後」的直覺。`role_state_reconciled` 緊接 state
// ——它是封章當下對帳結果的主張，與 state 同屬一組事實。
//
// 兩個版本各為一個獨立 struct 而非「一個 struct 加 omitempty」：後者要靠
// 「nil 時省略、非 nil 時寫出」的耦合來維持 v1 位元組不變，而 v2 的
// role_state_reconciled 恰恰必須在 nil 時寫出 null——同一個 tag 做不到兩件事
type checkpointSignPayloadV2 struct {
	Seq                 uint                   `json:"seq"`
	IDFrom              uint                   `json:"id_from"`
	IDTo                uint                   `json:"id_to"`
	RowCount            int64                  `json:"row_count"`
	AggHash             string                 `json:"agg_hash"`
	AggScheme           string                 `json:"agg_scheme"`
	PrevCheckpointHash  string                 `json:"prev_checkpoint_hash"`
	MinCreatedAtUs      *int64                 `json:"min_created_at_us"`
	State               []checkpointStateEntry `json:"state"`
	RoleStateReconciled *bool                  `json:"role_state_reconciled"`
	MaxCreatedAtUs      *int64                 `json:"max_created_at_us"`
	SealedAtUs          int64                  `json:"sealed_at_us"`
	SigningKeyVersion   int                    `json:"signing_key_version"`
}

// ErrCheckpointPayloadInvalid 檢查點欄位組合建不出合法載荷
// （未知的 agg_scheme、v2 缺快照欄、快照欄不是合法 canonical JSON）。
//
// **與「簽章驗不過」分開**：載荷建不出來時根本沒有東西可以拿去驗簽，
// 把它報成 signature_invalid 會讓「欄位被清空」與「簽章被換掉」在報表上
// 同形，而兩者的處置不同
var ErrCheckpointPayloadInvalid = errors.New("檢查點載荷不合法")

// checkpointStateEntries 由檢查點的快照本體欄推導簽章載荷的 state 陣列。
//
// **hash 現算而非取 role_state_hash 欄**：若簽的是那個欄位，攻擊者改寫
// role_state_snapshot（對帳唯一的輸入）卻不動 hash 欄，簽章照樣通過——
// 而對帳讀的正是被改過的本體。現算使「快照本體」整個落在簽章涵蓋內。
//
// count 取本體陣列的元素數，同樣不取 role_state_count 欄（同一個理由）
func checkpointStateEntries(cp *model.AuditCheckpoint) ([]checkpointStateEntry, error) {
	if cp.RoleStateSnapshot == nil || *cp.RoleStateSnapshot == "" {
		return nil, fmt.Errorf("%w: agg_scheme=%s 但無狀態快照欄", ErrCheckpointPayloadInvalid, cp.AggScheme)
	}
	tables, err := DecodeStateSnapshotColumn(*cp.RoleStateSnapshot)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCheckpointPayloadInvalid, err)
	}
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]checkpointStateEntry, 0, len(names))
	for _, name := range names {
		body := []byte(tables[name])
		var elems []json.RawMessage
		if err := json.Unmarshal(body, &elems); err != nil {
			return nil, fmt.Errorf("%w: 表 %s 的快照本體不是陣列: %v",
				ErrCheckpointPayloadInvalid, name, err)
		}
		entries = append(entries, checkpointStateEntry{
			Table: name,
			Hash:  stateHash(body),
			Count: int64(len(elems)),
		})
	}
	return entries, nil
}

// checkpointLinkPayload 鏈接雜湊的輸入：「被簽章欄位＋其 signature」。
//
// signed 以 RawMessage 內嵌而非再次字串化——巢狀字串化會引入跳脫規則，
// 離線驗證者難以逐位元組重建
type checkpointLinkPayload struct {
	Signed    json.RawMessage `json:"signed"`
	Signature string          `json:"signature"`
}

// checkpointGenesisAnchor genesis 的 prev_checkpoint_hash 輸入：既有完整性基準。
//
// kind 欄使本雜湊的輸入域與 checkpointLinkPayload 不相交——否則理論上
// 存在「構造一個 link payload 使其雜湊等於 genesis 錨」的域混淆面
type checkpointGenesisAnchor struct {
	Kind         string `json:"kind"`
	MaxLogID     uint   `json:"max_log_id"`
	BaselineAtUs int64  `json:"baseline_at_us"`
}

// checkpointGenesisAnchorKind genesis 錨定的域標識
const checkpointGenesisAnchorKind = "integrity_baseline"

func timePtrToUnixMicro(t *time.Time) *int64 {
	if t == nil {
		return nil
	}
	us := t.UnixMicro()
	return &us
}

// CheckpointSignBytes 檢查點的簽章輸入位元組（離線驗章者重建的就是這串）。
//
// 取 *model.AuditCheckpoint 而非個別參數：封章與驗證兩側必須吃同一個
// 建構函式，否則「封章時多帶一欄、驗證時少帶一欄」的漂移不會被任何測試看見
func CheckpointSignBytes(cp *model.AuditCheckpoint) ([]byte, error) {
	switch cp.AggScheme {
	case model.AggSchemeV1:
		return checkpointSignBytesV1(cp)
	case model.AggSchemeV2:
		return checkpointSignBytesV2(cp)
	default:
		// 未知版本不猜：拿 v1 的形狀去驗一個未知版本的檢查點，
		// 結果會是「簽章驗不過」而掩蓋掉真正的原因（版本無法辨識）
		return nil, fmt.Errorf("%w: 未知的 agg_scheme %q", ErrCheckpointPayloadInvalid, cp.AggScheme)
	}
}

func checkpointSignBytesV1(cp *model.AuditCheckpoint) ([]byte, error) {
	payload := checkpointSignPayloadV1{
		Seq:                cp.Seq,
		IDFrom:             cp.IDFrom,
		IDTo:               cp.IDTo,
		RowCount:           cp.RowCount,
		AggHash:            cp.AggHash,
		AggScheme:          cp.AggScheme,
		PrevCheckpointHash: cp.PrevCheckpointHash,
		MinCreatedAtUs:     timePtrToUnixMicro(cp.MinCreatedAt),
		MaxCreatedAtUs:     timePtrToUnixMicro(cp.MaxCreatedAt),
		SealedAtUs:         cp.SealedAt.UnixMicro(),
		SigningKeyVersion:  cp.SigningKeyVersion,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化檢查點簽章 payload 失敗: %w", err)
	}
	return raw, nil
}

func checkpointSignBytesV2(cp *model.AuditCheckpoint) ([]byte, error) {
	state, err := checkpointStateEntries(cp)
	if err != nil {
		return nil, err
	}
	payload := checkpointSignPayloadV2{
		Seq:                 cp.Seq,
		IDFrom:              cp.IDFrom,
		IDTo:                cp.IDTo,
		RowCount:            cp.RowCount,
		AggHash:             cp.AggHash,
		AggScheme:           cp.AggScheme,
		PrevCheckpointHash:  cp.PrevCheckpointHash,
		MinCreatedAtUs:      timePtrToUnixMicro(cp.MinCreatedAt),
		State:               state,
		RoleStateReconciled: cp.RoleStateReconciled,
		MaxCreatedAtUs:      timePtrToUnixMicro(cp.MaxCreatedAt),
		SealedAtUs:          cp.SealedAt.UnixMicro(),
		SigningKeyVersion:   cp.SigningKeyVersion,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化檢查點簽章 payload 失敗: %w", err)
	}
	return raw, nil
}

// CheckpointLinkHash 檢查點的鏈接雜湊（hex）＝下一個檢查點的 prev_checkpoint_hash。
// 輸入為「被簽章欄位＋signature」——只鏈欄位不鏈簽章，換簽章不會斷鏈
func CheckpointLinkHash(cp *model.AuditCheckpoint) (string, error) {
	signed, err := CheckpointSignBytes(cp)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(checkpointLinkPayload{Signed: signed, Signature: cp.Signature})
	if err != nil {
		return "", fmt.Errorf("序列化檢查點鏈接 payload 失敗: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ── 清除 tombstone 與鏈修剪的 canonical 編碼（log-retention spec）────────────

// checkpointPurgeKind／checkpointTrimKind 域標識。
//
// **不可省**：三種 payload 都是固定 struct JSON 且都以同一把 Ed25519 私鑰簽，
// 少了域標識，一個結構相容的 payload 就可能被當成另一種用途的有效簽章
// （跨用途重放）。kind 使三個輸入域互不相交
const (
	checkpointPurgeKind = "checkpoint_purge"
	checkpointTrimKind  = "checkpoint_trim"
)

// checkpointPurgePayload 合法清除 tombstone 的簽章涵蓋欄位。
//
// 涵蓋 row_count 與 policy_days 的理由：tombstone 要主張的不只是「清了」，
// 而是「依 N 天政策清掉了本檢查點宣稱的那 M 列」。少了這兩欄，
// 同一把私鑰簽出的 tombstone 可被搬到任何區間上重放
type checkpointPurgePayload struct {
	Kind       string `json:"kind"`
	Seq        uint   `json:"seq"`
	PurgedAtUs int64  `json:"purged_at_us"`
	RowCount   int64  `json:"row_count"`
	PolicyDays int    `json:"policy_days"`
}

// CheckpointPurgeSignBytes 清除 tombstone 的簽章輸入位元組。
//
// 封章側與驗證側共用本函式（同 CheckpointSignBytes 的理由）：
// 兩側各寫一份，欄位漂移不會被任何測試看見
func CheckpointPurgeSignBytes(seq uint, purgedAt time.Time, rowCount int64, policyDays int) ([]byte, error) {
	raw, err := json.Marshal(checkpointPurgePayload{
		Kind:       checkpointPurgeKind,
		Seq:        seq,
		PurgedAtUs: purgedAt.UnixMicro(),
		RowCount:   rowCount,
		PolicyDays: policyDays,
	})
	if err != nil {
		return nil, fmt.Errorf("序列化清除 tombstone payload 失敗: %w", err)
	}
	return raw, nil
}

// checkpointTrimPayload 鏈修剪記錄的簽章涵蓋欄位。
//
// LastTrimmedLinkHash 是關鍵欄：它使修剪記錄成為殘鏈的**可驗錨點**
// （殘鏈鏈頭的 prev_checkpoint_hash 必須等於它），否則「合法修剪」與
// 「鏈頭被挖」在驗證端無法區分
type checkpointTrimPayload struct {
	Kind                string `json:"kind"`
	FromSeq             uint   `json:"from_seq"`
	LastTrimmedSeq      uint   `json:"last_trimmed_seq"`
	TrimmedCount        int64  `json:"trimmed_count"`
	LastTrimmedLinkHash string `json:"last_trimmed_link_hash"`
	GenesisIDFrom       uint   `json:"genesis_id_from"`
	PolicyDays          int    `json:"policy_days"`
	TrimmedAtUs         int64  `json:"trimmed_at_us"`
}

// CheckpointTrimSignBytes 鏈修剪記錄的簽章輸入位元組
func CheckpointTrimSignBytes(trim *model.AuditCheckpointTrim) ([]byte, error) {
	raw, err := json.Marshal(checkpointTrimPayload{
		Kind:                checkpointTrimKind,
		FromSeq:             trim.FromSeq,
		LastTrimmedSeq:      trim.LastTrimmedSeq,
		TrimmedCount:        trim.TrimmedCount,
		LastTrimmedLinkHash: trim.LastTrimmedLinkHash,
		GenesisIDFrom:       trim.GenesisIDFrom,
		PolicyDays:          trim.PolicyDays,
		TrimmedAtUs:         trim.TrimmedAt.UnixMicro(),
	})
	if err != nil {
		return nil, fmt.Errorf("序列化鏈修剪記錄 payload 失敗: %w", err)
	}
	return raw, nil
}

// CheckpointGenesisPrevHash genesis 的 prev_checkpoint_hash：錨定既有完整性基準。
//
// 錨定基準而非取零值：零值的 genesis 可被憑空重造（攻擊者刪光鏈後補一個
// 全新 genesis），錨定基準使重造需要同時偽造 integrity_baselines
func CheckpointGenesisPrevHash(maxLogID uint, baselineAt time.Time) (string, error) {
	raw, err := json.Marshal(checkpointGenesisAnchor{
		Kind:         checkpointGenesisAnchorKind,
		MaxLogID:     maxLogID,
		BaselineAtUs: baselineAt.UnixMicro(),
	})
	if err != nil {
		return "", fmt.Errorf("序列化 genesis 錨定 payload 失敗: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
