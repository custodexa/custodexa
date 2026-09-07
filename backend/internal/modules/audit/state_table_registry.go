package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"gorm.io/gorm"
)

// 狀態表登記清單（role-assignment-integrity）。
//
// # 為什麼要有登記清單這一層
//
// 檢查點鏈原本只覆蓋 `audit_logs`——一張 append-only 的表。權限真相不在那裡，
// 它在 `user_roles`：能直接寫資料庫的人把自己掛上 admin，下次登入就是管理者，
// 而系統分不出這是 API 改的還是資料庫直改的。把這類**狀態表**的指紋簽進同一條鏈，
// 「僅持有資料庫權限者造不出通過驗證的紀錄」才延伸得到提權這件事上。
//
// 登記清單而非硬寫死一張表的理由：封章、驗證與對帳三處都要遍歷同一組表，
// 三處各寫一份表名就是三份會漂移的事實；且日後擴充（資產授權、群組成員、
// 審批範圍）只該是加一行登記＋補其寫入點的審計列。
// **未登記的表一律不參與比對**（spec 明文）——比對一張沒有留痕路徑的表，
// 產出的只會是假警報。
//
// # 守衛
//
// 登記一張表就同時承諾了兩件事：它有快照測試、它有竄改矩陣列。
// `TestStateTableRegistryGuard` 雙向盯住（多登記一張沒測試的表轉紅、
// 矩陣多一列未登記的表轉紅），使「加了登記卻沒有人證明它真的抓得到」不可能發生。

// StateTableUserRoles 角色指派表（本期唯一登記項）
const StateTableUserRoles = "user_roles"

// StateSnapshot 單一狀態表的一份正規化快照。
//
// Body 是**逐位元組固定**的 canonical 編碼（見各表的快照函式），
// Hash 為其長度前綴 SHA-256、Count 為筆數。三者的關係一經釘定即不可變：
// Hash 進簽章載荷，Body 入庫供對帳重放上一狀態
type StateSnapshot struct {
	Table string
	Body  []byte
	Hash  string
	Count int64
}

// StateTable 登記清單的一項。
//
// EventResource 是該表的變更在 `audit_logs` 內的資源名——對帳以它篩出
// 「上一檢查點之後、經應用程式發生的變更」。本期只有一張表，欄位仍以登記項
// 的形式帶著：對帳器要能對任一登記表運作，而不是對 user_roles 寫死
type StateTable struct {
	Name          string
	EventResource string
	Snapshot      func(ctx context.Context, tx *gorm.DB) (StateSnapshot, error)
}

// StateTableRegistry 登記清單（本期只含 user_roles）。
//
// 回傳新 slice 而非暴露套件變數：呼叫端不得就地改寫登記清單，
// 「執行期被改掉的登記清單」等於一個可被關閉的完整性機制
func StateTableRegistry() []StateTable {
	return []StateTable{
		{
			Name:          StateTableUserRoles,
			EventResource: "user_role",
			Snapshot:      SnapshotUserRoles,
		},
	}
}

// stateHash 快照本體的長度前綴 SHA-256（hex）。
//
// **長度前綴不可省**：本編碼的輸入是攻擊者可寫的資料，無長度前綴時
// 「一張表的快照」與「兩張表的快照串接」可構造出相同的雜湊輸入
// （列級 HMAC 與區間聚合是同一個理由，見 checkpoint_canonical.go 的 O1 結論）
func stateHash(body []byte) string {
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], uint64(len(body)))
	h := sha256.New()
	h.Write(prefix[:])
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// RolePair 一筆角色指派（快照的元素）
type RolePair struct {
	UserID uint64
	RoleID uint64
}

// RolePairSource 讀出 `user_roles` 全表的來源（消費者側窄介面）。
//
// 表歸 identity 模組所有；audit 只需要「現在有哪些 (user_id, role_id)」這一件事，
// 由 identity 以 tx-taking 函式提供（`identity.SnapshotUserRolePairs`），組裝時經
// SetUserRolesSource 注入。identity 已 import audit，故方向只能如此，不可反向。
// 排序、去重、編碼與雜湊仍在本模組（EncodeRolePairs）——來源只負責讀，
// 「同一狀態必得同一雜湊」的責任不外移
type RolePairSource func(ctx context.Context, tx *gorm.DB) ([]RolePair, error)

var userRolesSource RolePairSource

// ErrUserRolesSourceUnset 來源未注入。fail-close：沒有來源就沒有快照，
// 封章與對帳都會以錯誤停下，而不是拿空集合當「沒有任何角色指派」封進鏈裡
var ErrUserRolesSourceUnset = errors.New("角色指派快照來源未注入（SetUserRolesSource）")

// SetUserRolesSource 注入 `user_roles` 的讀取來源（組裝時呼叫，早於任何封章與對帳）
func SetUserRolesSource(src RolePairSource) {
	userRolesSource = src
}

// SnapshotUserRoles 經注入的來源讀 `user_roles` 全表並產出正規化快照。
//
// canonical 編碼＝`[[user_id,role_id],…]`，依 user_id、role_id 升冪排序。
// 三個刻意：
//
//   - **排序在 Go 端做，不靠 SQL ORDER BY**：定序（collation）與型別提升在不同
//     資料庫上不保證一致，而「同一狀態必得同一雜湊」是本機制的地基。
//   - **不含帳號名、電子郵件或任何個資**（spec 明文）：快照會進檢查點、
//     會離機、會被稽核方拿去。呈現時再以現行資料換算為帳號名與角色名。
//   - **原生 SQL 而非 ORM 關聯**（由來源實作）：user_roles 是裸 join 表
//     （無 model、無時間欄），經 many2many 讀出會被 GORM 的關聯載入改變形狀
func SnapshotUserRoles(ctx context.Context, tx *gorm.DB) (StateSnapshot, error) {
	if userRolesSource == nil {
		return StateSnapshot{}, ErrUserRolesSourceUnset
	}
	pairs, err := userRolesSource(ctx, tx)
	if err != nil {
		return StateSnapshot{}, fmt.Errorf("讀取 user_roles 快照失敗: %w", err)
	}
	body, count := EncodeRolePairs(pairs)
	return StateSnapshot{
		Table: StateTableUserRoles,
		Body:  body,
		Hash:  stateHash(body),
		Count: count,
	}, nil
}

// EncodeRolePairs 把角色指派對編碼為 canonical 快照本體（排序＋去重）。
//
// 去重的理由：複合主鍵理論上排除重複，但快照的輸入若來自對帳推導
// （上一快照 ⊕ 審計列），同一筆 assign 出現兩次是可能的，而「集合」
// 的語義下那應該是同一個狀態、同一個雜湊
func EncodeRolePairs(pairs []RolePair) ([]byte, int64) {
	sorted := make([]RolePair, len(pairs))
	copy(sorted, pairs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].UserID != sorted[j].UserID {
			return sorted[i].UserID < sorted[j].UserID
		}
		return sorted[i].RoleID < sorted[j].RoleID
	})
	out := make([]byte, 0, 4+len(sorted)*16)
	out = append(out, '[')
	var n int64
	var prev RolePair
	for i, p := range sorted {
		if i > 0 && p == prev {
			continue
		}
		prev = p
		if n > 0 {
			out = append(out, ',')
		}
		out = append(out, '[')
		out = appendUint(out, p.UserID)
		out = append(out, ',')
		out = appendUint(out, p.RoleID)
		out = append(out, ']')
		n++
	}
	out = append(out, ']')
	return out, n
}

func appendUint(dst []byte, v uint64) []byte {
	if v == 0 {
		return append(dst, '0')
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return append(dst, buf[i:]...)
}

// DecodeRolePairs 由 canonical 快照本體還原角色指派對（對帳重放上一狀態用）
func DecodeRolePairs(body []byte) ([]RolePair, error) {
	var raw [][2]uint64
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析角色指派快照失敗: %w", err)
	}
	pairs := make([]RolePair, 0, len(raw))
	for _, r := range raw {
		pairs = append(pairs, RolePair{UserID: r[0], RoleID: r[1]})
	}
	return pairs, nil
}

// DiffRolePairs 兩組角色指派的差集：missing＝expected 有而 actual 無、
// extra＝actual 有而 expected 無。兩者皆依 canonical 順序排序，
// 使同一組差集在報表與事件 details 上逐次一致
func DiffRolePairs(expected, actual []RolePair) (missing, extra []RolePair) {
	exp := make(map[RolePair]bool, len(expected))
	for _, p := range expected {
		exp[p] = true
	}
	act := make(map[RolePair]bool, len(actual))
	for _, p := range actual {
		act[p] = true
	}
	for p := range exp {
		if !act[p] {
			missing = append(missing, p)
		}
	}
	for p := range act {
		if !exp[p] {
			extra = append(extra, p)
		}
	}
	sortRolePairs(missing)
	sortRolePairs(extra)
	return missing, extra
}

func sortRolePairs(ps []RolePair) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].UserID != ps[j].UserID {
			return ps[i].UserID < ps[j].UserID
		}
		return ps[i].RoleID < ps[j].RoleID
	})
}

// SnapshotStateTables 依登記清單取全部狀態表的快照，回傳
// (以表名為鍵的 canonical JSON 快照本體, 各表快照)。
//
// 快照本體欄的形狀為 `{"<表名>":<該表的 canonical 本體>,…}`，表名升冪。
// **手工組裝而非 map + json.Marshal**：encoding/json 對 map 的鍵排序恰好也是
// 升冪，但那是實作行為不是規格承諾；本欄的每一個位元組都在簽章的推導鏈上
func SnapshotStateTables(ctx context.Context, tx *gorm.DB) (string, []StateSnapshot, error) {
	reg := StateTableRegistry()
	snaps := make([]StateSnapshot, 0, len(reg))
	for _, st := range reg {
		snap, err := st.Snapshot(ctx, tx)
		if err != nil {
			return "", nil, err
		}
		if snap.Table != st.Name {
			return "", nil, fmt.Errorf("登記表 %s 的快照回報表名 %s：登記清單與快照函式不一致",
				st.Name, snap.Table)
		}
		snaps = append(snaps, snap)
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].Table < snaps[j].Table })

	out := make([]byte, 0, 64)
	out = append(out, '{')
	for i, s := range snaps {
		if i > 0 {
			out = append(out, ',')
		}
		name, err := json.Marshal(s.Table)
		if err != nil {
			return "", nil, fmt.Errorf("序列化表名 %s 失敗: %w", s.Table, err)
		}
		out = append(out, name...)
		out = append(out, ':')
		out = append(out, s.Body...)
	}
	out = append(out, '}')
	return string(out), snaps, nil
}

// DecodeStateSnapshotColumn 由檢查點的快照本體欄還原各表的 canonical 本體。
//
// 以 json.RawMessage 收下而**不重新序列化**：本體的位元組本身是雜湊輸入，
// 任何 re-marshal（空白、數字格式）都會改變雜湊而把合法檢查點判成竄改
func DecodeStateSnapshotColumn(raw string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("解析檢查點狀態快照欄失敗: %w", err)
	}
	return m, nil
}
