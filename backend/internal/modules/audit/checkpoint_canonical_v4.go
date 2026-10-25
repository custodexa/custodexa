package audit

import (
	"encoding/json"
	"fmt"

	"github.com/custodexa/backend/internal/model"
)

// 第四版載荷：v3 全部 17 鍵之後追加一鍵 `perm`（權限附證本體）。
//
// 附證在檢查點自己的簽章與鏈接雜湊之內：清空、部分清空或改動任一附證欄都使**該點自己**
// 驗不過（鏈尾那一點與其他點同等），不需要另一把附證簽章，也不靠下一點的鏈接。
//
// `perm` 的值是 null 或固定鍵序的八鍵物件；由欄位重建的唯一規則見 checkpointPermFromColumns，
// 封章側、驗證側與離線驗證者都照它重建。所有字串值域都是小寫 hex，JSON 跳脫規則在物件內
// 永遠不會被觸發；整數一律十進位。

// checkpointPermEntry `perm` 物件（鍵序即欄位順序）。
type checkpointPermEntry struct {
	Format         int    `json:"format"`
	Model          int    `json:"model"`
	Catalog        string `json:"catalog"`
	SnapshotDigest string `json:"snapshot_digest"`
	EventSeq       int64  `json:"event_seq"`
	EventHead      string `json:"event_head"`
	Reconciled     *bool  `json:"reconciled"`
	Origin         bool   `json:"origin"`
}

type checkpointSignPayloadV4 struct {
	checkpointSignPayloadV3
	Perm *checkpointPermEntry `json:"perm"`
}

// checkpointSchemeRank 載荷版本的序（v1 < v2 < v3 < v4）；未知版本為 0。
// 鏈上的版本序不得遞減，帳本四欄自 v3 起必備，兩者都以此比較。
func checkpointSchemeRank(scheme string) int {
	switch scheme {
	case model.AggSchemeV1:
		return 1
	case model.AggSchemeV2:
		return 2
	case model.AggSchemeV3:
		return 3
	case model.AggSchemeV4:
		return 4
	}
	return 0
}

// checkpointHasLedger 該版本的載荷帶帳本四欄（v3 以上）。
func checkpointHasLedger(scheme string) bool { return checkpointSchemeRank(scheme) >= 3 }

func isLowerHex64(s string) bool { return isLowerHexLen(s, 64) }

// permCatalogHexLen 權限目錄摘要的長度：內建權限目錄與範本集合 SHA-256 的前 32 個 hex 字元
// （權限快照本體 meta.catalog 的既有形狀）。
const permCatalogHexLen = 32

func isLowerHexLen(s string, n int) bool {
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

// checkpointHasAnyPermColumn 六個附證欄任一非 NULL（部分清空、空字串都算痕跡）。
func checkpointHasAnyPermColumn(cp *model.AuditCheckpoint) bool {
	return cp.PermStateSnapshot != nil || cp.PermFormat != nil || cp.PermEventSeq != nil ||
		cp.PermEventHead != nil || cp.PermReconciled != nil || cp.PermOrigin != nil
}

// checkpointPermFromColumns 由欄位重建 `perm`（唯一規則）：
//
//  1. 五個必要欄（快照本體、格式、事件序號、事件鏈頭、起點旗標）全為 NULL 且對帳結果為 NULL → null。
//  2. 五個必要欄全部非 NULL → 值域檢查後重建；對帳結果照欄位三態輸出。
//  3. 其餘組合（部分為 NULL）→ ErrCheckpointPayloadInvalid，不猜。非 NULL 的空字串、字面 "null"、
//     空快照都不等同 NULL，走規則 2 的值域拒絕。
//
// 值域：格式為已支援版本且等於快照本體最外層的 v；模型版本 ≥ 1；目錄摘要為 32 字元、事件鏈頭為
// 64 字元小寫 hex；快照本體可解碼且為 canonical；事件序號 ≥ 1；起點旗標為真時事件序號必為 1。
// 快照摘要由本體現算（長度前綴 SHA-256，與 state[].hash 同一條規則），不取任何摘要欄。
func checkpointPermFromColumns(cp *model.AuditCheckpoint) (*checkpointPermEntry, error) {
	required := []bool{cp.PermStateSnapshot != nil, cp.PermFormat != nil, cp.PermEventSeq != nil,
		cp.PermEventHead != nil, cp.PermOrigin != nil}
	present := 0
	for _, ok := range required {
		if ok {
			present++
		}
	}
	switch {
	case present == 0 && cp.PermReconciled == nil:
		return nil, nil
	case present != len(required):
		return nil, fmt.Errorf("%w: 權限附證欄不齊（%d／%d 個必要欄）", ErrCheckpointPayloadInvalid, present, len(required))
	}
	format := *cp.PermFormat
	if format < 1 || !permissionFormatSupported(format) {
		return nil, fmt.Errorf("%w: 未知的權限快照格式版本 %d", ErrCheckpointPayloadInvalid, format)
	}
	st, err := DecodePermissionState([]byte(*cp.PermStateSnapshot))
	if err != nil {
		return nil, fmt.Errorf("%w: 權限快照本體: %v", ErrCheckpointPayloadInvalid, err)
	}
	if st.Meta.FormatVersion != format {
		return nil, fmt.Errorf("%w: 快照本體的格式版本 %d 與附證欄 %d 不符", ErrCheckpointPayloadInvalid, st.Meta.FormatVersion, format)
	}
	if st.Meta.Model < 1 {
		return nil, fmt.Errorf("%w: 權限模型版本 %d", ErrCheckpointPayloadInvalid, st.Meta.Model)
	}
	if !isLowerHexLen(st.Meta.Catalog, permCatalogHexLen) {
		return nil, fmt.Errorf("%w: 權限目錄摘要不是 %d 字元小寫 hex", ErrCheckpointPayloadInvalid, permCatalogHexLen)
	}
	if *cp.PermEventSeq < 1 {
		return nil, fmt.Errorf("%w: 權限事件序號 %d", ErrCheckpointPayloadInvalid, *cp.PermEventSeq)
	}
	if !isLowerHex64(*cp.PermEventHead) {
		return nil, fmt.Errorf("%w: 權限事件鏈頭不是 64 字元小寫 hex", ErrCheckpointPayloadInvalid)
	}
	if *cp.PermOrigin && *cp.PermEventSeq != 1 {
		return nil, fmt.Errorf("%w: 起點附證的事件序號必為 1（得 %d）", ErrCheckpointPayloadInvalid, *cp.PermEventSeq)
	}
	return &checkpointPermEntry{
		Format: format, Model: st.Meta.Model, Catalog: st.Meta.Catalog,
		SnapshotDigest: stateHash([]byte(*cp.PermStateSnapshot)),
		EventSeq:       *cp.PermEventSeq, EventHead: *cp.PermEventHead,
		Reconciled: cp.PermReconciled, Origin: *cp.PermOrigin,
	}, nil
}

func checkpointSignBytesV4(cp *model.AuditCheckpoint) ([]byte, error) {
	perm, err := checkpointPermFromColumns(cp)
	if err != nil {
		return nil, err
	}
	raw, err := checkpointSignBytesV3(cp)
	if err != nil {
		return nil, err
	}
	var v3 checkpointSignPayloadV3
	if err := json.Unmarshal(raw, &v3); err != nil {
		return nil, err
	}
	return json.Marshal(checkpointSignPayloadV4{checkpointSignPayloadV3: v3, Perm: perm})
}

// CheckpointPermWire 列表 API 的 `perm` 值（wire 契約）：第四版的點一律帶此鍵——有附證者為
// 八鍵物件（鍵序同載荷，無個資），無附證者為 JSON null；第四版之前的點不帶此鍵（回 nil）。
// 附證欄組合建不出合法載荷的第四版點（部分清空、出值域）也不帶此鍵：離線驗證者據此回報
// 「載荷無法重建」，與產品端的 payload_invalid 同一個結論，不讓它被當成 null 去驗簽。
func CheckpointPermWire(cp *model.AuditCheckpoint) json.RawMessage {
	if cp.AggScheme != model.AggSchemeV4 {
		return nil
	}
	perm, err := checkpointPermFromColumns(cp)
	if err != nil {
		return nil
	}
	raw, err := json.Marshal(perm) // nil 指標序列化為 null
	if err != nil {
		return nil
	}
	return raw
}
