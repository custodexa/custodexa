package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"gorm.io/gorm"
)

// 權限狀態快照。
//
// 權限真相不只 user_roles 的 (user, role) 對：角色內容、來源、範圍、群組指派、節點集合、
// 兩條外部映射與群組成員來源都會改變「誰能做什麼」。本檔把這些投影成版本化的
// canonical 快照，供封章附證（permission_attestation.go）簽章與對帳重放。
//
// 不改舊 user_roles pair 編碼、不進 StateTableRegistry 的基礎三項：
// 基礎快照欄是既有簽章載荷的輸入，改寫它會讓所有歷史封章驗不過。

const (
	// PermissionStateFormat 快照格式識別字串
	PermissionStateFormat = "permission_state"
	// PermissionStateFormatVersion 快照格式版本；與模型版本分開，未知版本拒絕解碼。
	PermissionStateFormatVersion = 2
	// PermissionSummaryVersion 備份摘要（snapshot.txt 的 authz. 行）的格式版本，管理腳本讀的是它。
	// 與快照格式版本分開：快照格式 2 只是在摘要裡多了兩條 authz.count 行（腳本容許額外的計數行），
	// 摘要的鍵集與形狀沒有改變，所以腳本認得的版本不動；摘要的鍵集或形狀改變時才推進它並同步腳本。
	PermissionSummaryVersion = 1
	// PermissionStateFormatV1 較早的快照格式（十個集合）。舊封章、舊事件鏈頭仍以此解碼與驗章，
	// 不改寫；新封章與新事件一律寫目前版本。
	PermissionStateFormatV1 = 1
	// PermissionModelVersion 權限資料模型版本（user_roles／群組指派／節點範圍模型）。
	PermissionModelVersion = 1
)

// 集合名稱（固定次序，canonical 編碼依此排列）。每個元素是一列 canonical JSON 陣列字串，
// 欄序固定、ID 為十進位數字、布林為 0／1。
const (
	PermSetRoles        = "roles"         // [role_id, builtin_key, deleted]
	PermSetUserRoles    = "user_roles"    // [user_id, role_id, scope_kind, source]
	PermSetGroupRoles   = "group_roles"   // [group_id, role_id, scope_kind]
	PermSetBindingNodes = "binding_nodes" // [subject_kind, subject_id, role_id, node_id]
	PermSetNodes        = "nodes"         // [node_id, deleted]
	PermSetRoleMaps     = "role_maps"     // [rule_id, source_kind, source_id, role_id, match_fp, enabled, deleted]
	PermSetGroupMaps    = "group_maps"    // [rule_id, source_kind, source_id, group_id, match_fp, enabled, deleted]
	PermSetMembers      = "members"       // [group_id, user_id, source]
	PermSetGroups       = "groups"        // [group_id, deleted]
	PermSetPrincipals   = "principals"    // [user_id, kind, owner_user_id, active, deleted, local_login]
	// 格式版本 2 起：自訂角色定義。
	PermSetRoleDefs  = "role_defs"  // [role_id, definition_version, template_role_id（無來源為 0）]
	PermSetRolePerms = "role_perms" // [role_id, permission_key]
)

// permissionSetNames 目前格式 canonical 編碼的集合次序（新增集合＝新的格式版本）。
func permissionSetNames() []string { return permissionSetNamesFor(PermissionStateFormatVersion) }

// permissionSetNamesFor 指定格式版本的集合次序；未支援的版本回 nil。
func permissionSetNamesFor(v int) []string {
	v1 := []string{
		PermSetRoles, PermSetUserRoles, PermSetGroupRoles, PermSetBindingNodes, PermSetNodes,
		PermSetRoleMaps, PermSetGroupMaps, PermSetMembers, PermSetGroups, PermSetPrincipals,
	}
	switch v {
	case PermissionStateFormatV1:
		return v1
	case PermissionStateFormatVersion:
		return append(v1, PermSetRoleDefs, PermSetRolePerms)
	}
	return nil
}

// permissionFormatSupported 該格式版本是否可解碼與驗章。
func permissionFormatSupported(v int) bool { return permissionSetNamesFor(v) != nil }

// ProjectTo 把狀態投影成較舊的格式版本（丟掉該版本沒有的集合）；用於跨版本比較。
// 目標版本不低於自身版本時回傳深拷貝。
func (s *PermissionState) ProjectTo(v int) *PermissionState {
	c := s.Clone()
	if v >= c.Meta.FormatVersion || !permissionFormatSupported(v) {
		return c
	}
	keep := map[string]bool{}
	for _, n := range permissionSetNamesFor(v) {
		keep[n] = true
	}
	for name := range c.Sets {
		if !keep[name] {
			delete(c.Sets, name)
		}
	}
	c.Meta.FormatVersion = v
	return c
}

// permissionStatesEqual 兩份狀態在較舊一方的格式下是否相同。鏈頭可能是舊格式（升級前寫入），
// 不能因格式差異把「沒有任何變動」判成無來源變動。
func permissionStatesEqual(a, b *PermissionState) (bool, error) {
	if a.Meta.FormatVersion < b.Meta.FormatVersion {
		b = b.ProjectTo(a.Meta.FormatVersion)
	} else if b.Meta.FormatVersion < a.Meta.FormatVersion {
		a = a.ProjectTo(b.Meta.FormatVersion)
	}
	ad, err := a.Digest()
	if err != nil {
		return false, err
	}
	bd, err := b.Digest()
	if err != nil {
		return false, err
	}
	return ad == bd, nil
}

// PermissionSetNames 集合的 canonical 次序（備份摘要列出各集合筆數時使用）。
func PermissionSetNames() []string { return permissionSetNames() }

// PermissionMeta 快照的版本維度。
type PermissionMeta struct {
	Model         int    `json:"model"`
	Catalog       string `json:"catalog"`       // 內建權限目錄與範本集合的 digest
	Version       int64  `json:"version"`       // authz_state.version
	GenerationFP  string `json:"generation_fp"` // 恢復世代的指紋；空世代為空字串
	RestoreOpID   string `json:"restore_op_id"` // 已提交的恢復操作識別；無則空
	FormatVersion int    `json:"-"`
}

// PermissionState 一份權限狀態：版本維度＋各集合（排序、去重）。
type PermissionState struct {
	Meta PermissionMeta
	Sets map[string][]string
}

// PermissionPart 某個模組可提供的集合（consumer-side 窄介面的回傳）。
type PermissionPart struct {
	Meta *PermissionMeta // 只有 authz 部分提供
	Sets map[string][]string
}

// PermissionPartSource 由所有者模組以 tx-taking 函式提供的讀取來源。
type PermissionPartSource func(ctx context.Context, tx *gorm.DB) (PermissionPart, error)

var (
	permissionAuthzSource    PermissionPartSource
	permissionIdentitySource PermissionPartSource
)

// ErrPermissionSourceUnset 權限狀態來源未注入。fail-close：沒有來源就沒有快照，
// 封章以錯誤停下，而不是把空集合封成「沒有任何權限」。
var ErrPermissionSourceUnset = errors.New("權限狀態快照來源未注入（SetPermissionSources）")

// SetPermissionSources 組裝時注入兩個所有者模組（authz、identity）的讀取來源。
func SetPermissionSources(authzPart, identityPart PermissionPartSource) {
	permissionAuthzSource = authzPart
	permissionIdentitySource = identityPart
}

// PermissionSourcesWired 來源是否已注入（事件寫入點用來判斷是否已進入受管狀態）。
func PermissionSourcesWired() bool {
	return permissionAuthzSource != nil && permissionIdentitySource != nil
}

// PermissionActivationLock 由權限版本列的所有者模組（authz）以 tx-taking 函式提供：
// 在呼叫端交易 tx 內對版本列取 FOR UPDATE 列鎖並持有到交易結束。錯誤原樣回傳，
// 呼叫端據 SQLSTATE 40001 判讓位重試。
type PermissionActivationLock func(ctx context.Context, tx *gorm.DB) error

var permissionActivationLock PermissionActivationLock

// ErrPermissionActivationLockUnset 首次啟用交界鎖未注入。fail-close：PG 上沒有這把鎖，
// 首次啟用與合法權限寫入無從序列化，寧可本輪不封章、不接受，也不在無鎖下寫事件鏈起點。
var ErrPermissionActivationLockUnset = errors.New("權限附證首次啟用交界鎖未注入（SetPermissionActivationLock）")

// SetPermissionActivationLock 組裝時注入 authz 模組的交界鎖。
func SetPermissionActivationLock(lock PermissionActivationLock) {
	permissionActivationLock = lock
}

// lockPermissionActivation 首次啟用（事件表為空）時與合法權限寫入的交界鎖。
// 只在 PG 上取（SQLite 本身單寫者，不需要）；PG 上未注入則 fail-close。
func lockPermissionActivation(ctx context.Context, tx *gorm.DB) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	if permissionActivationLock == nil {
		return ErrPermissionActivationLockUnset
	}
	return permissionActivationLock(ctx, tx)
}

// PermissionRow 把欄位值編成一列 canonical JSON 陣列字串（json.Marshal 對 []any 次序固定）。
func PermissionRow(vals ...any) string {
	b, err := json.Marshal(vals)
	if err != nil {
		panic(fmt.Sprintf("permission row 無法編碼: %v", err)) // 只接受 string／整數／0-1，不會發生
	}
	return string(b)
}

// PermBool 布林欄的 canonical 表示（0／1）。
func PermBool(v bool) int {
	if v {
		return 1
	}
	return 0
}

func normalizeSet(rows []string) []string {
	out := make([]string, len(rows))
	copy(out, rows)
	sort.Strings(out)
	n := 0
	for i, r := range out {
		if i > 0 && r == out[n-1] {
			continue
		}
		out[n] = r
		n++
	}
	return out[:n]
}

// ReadPermissionState 在同一個資料庫視圖（呼叫端提供的 tx）內擷取權限狀態。
// 兩個來源都必須在同一個 tx 上讀，不能跨交易拼出不存在的狀態。
func ReadPermissionState(ctx context.Context, tx *gorm.DB) (*PermissionState, error) {
	if !PermissionSourcesWired() {
		return nil, ErrPermissionSourceUnset
	}
	a, err := permissionAuthzSource(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("讀取授權模組權限狀態失敗: %w", err)
	}
	if a.Meta == nil {
		return nil, errors.New("授權模組來源未提供版本維度")
	}
	id, err := permissionIdentitySource(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("讀取身分模組權限狀態失敗: %w", err)
	}
	st := &PermissionState{Meta: *a.Meta, Sets: map[string][]string{}}
	st.Meta.FormatVersion = PermissionStateFormatVersion
	known := map[string]bool{}
	for _, n := range permissionSetNames() {
		known[n] = true
	}
	for _, part := range []PermissionPart{a, id} {
		for name, rows := range part.Sets {
			if !known[name] {
				return nil, fmt.Errorf("權限狀態來源提供未登記的集合 %q", name)
			}
			if _, dup := st.Sets[name]; dup {
				return nil, fmt.Errorf("集合 %q 被兩個來源同時提供", name)
			}
			st.Sets[name] = normalizeSet(rows)
		}
	}
	for _, n := range permissionSetNames() {
		if _, ok := st.Sets[n]; !ok {
			return nil, fmt.Errorf("權限狀態缺集合 %q：來源不完整，不得以空集合代替", n)
		}
	}
	return st, nil
}

// Encode 產出 canonical bytes：固定欄序、集合依 permissionSetNames 次序、元素已排序。
// 手工組裝而非 map + Marshal：每個位元組都在簽章的推導鏈上。
func (s *PermissionState) Encode() ([]byte, error) {
	names := permissionSetNamesFor(s.Meta.FormatVersion)
	if names == nil {
		return nil, fmt.Errorf("不支援的權限快照格式版本 %d", s.Meta.FormatVersion)
	}
	inFormat := map[string]bool{}
	for _, n := range names {
		inFormat[n] = true
	}
	for _, n := range permissionSetNames() {
		if !inFormat[n] && len(s.Sets[n]) > 0 {
			return nil, fmt.Errorf("集合 %s 不屬於格式版本 %d", n, s.Meta.FormatVersion)
		}
	}
	out := []byte(`{"format":"` + PermissionStateFormat + `","v":`)
	out = append(out, []byte(fmt.Sprint(s.Meta.FormatVersion))...)
	meta, err := json.Marshal(s.Meta) // 欄序固定：model、catalog、version、generation_fp、restore_op_id
	if err != nil {
		return nil, err
	}
	out = append(out, []byte(`,"meta":`)...)
	out = append(out, meta...)
	out = append(out, []byte(`,"sets":{`)...)
	for i, name := range names {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, []byte(`"`+name+`":[`)...)
		for j, row := range normalizeSet(s.Sets[name]) {
			if j > 0 {
				out = append(out, ',')
			}
			out = append(out, row...)
		}
		out = append(out, ']')
	}
	out = append(out, '}', '}')
	return out, nil
}

// Digest 快照 canonical bytes 的長度前綴 SHA-256（沿用基礎快照的 stateHash）。
func (s *PermissionState) Digest() (string, error) {
	b, err := s.Encode()
	if err != nil {
		return "", err
	}
	return stateHash(b), nil
}

// ErrPermissionSnapshotFormat 未知格式／版本或結構不合；一律拒絕，不默認空集合。
var ErrPermissionSnapshotFormat = errors.New("權限狀態快照格式不支援或結構不合")

type permissionWire struct {
	Format string                       `json:"format"`
	V      int                          `json:"v"`
	Meta   PermissionMeta               `json:"meta"`
	Sets   map[string][]json.RawMessage `json:"sets"`
}

// DecodePermissionState 由 canonical bytes 還原。嚴格：未知格式／版本／缺集合／多餘集合皆拒絕。
func DecodePermissionState(body []byte) (*PermissionState, error) {
	var w permissionWire
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPermissionSnapshotFormat, err)
	}
	if w.Format != PermissionStateFormat || !permissionFormatSupported(w.V) {
		return nil, fmt.Errorf("%w: format=%q v=%d", ErrPermissionSnapshotFormat, w.Format, w.V)
	}
	names := permissionSetNamesFor(w.V)
	if len(w.Sets) != len(names) {
		return nil, fmt.Errorf("%w: 集合數 %d", ErrPermissionSnapshotFormat, len(w.Sets))
	}
	st := &PermissionState{Meta: w.Meta, Sets: map[string][]string{}}
	st.Meta.FormatVersion = w.V
	for _, name := range names {
		rows, ok := w.Sets[name]
		if !ok {
			return nil, fmt.Errorf("%w: 缺集合 %s", ErrPermissionSnapshotFormat, name)
		}
		list := make([]string, 0, len(rows))
		for _, r := range rows {
			list = append(list, string(r))
		}
		st.Sets[name] = normalizeSet(list)
	}
	// 重新編碼必須與輸入逐位元組相同，否則不是 canonical（空白、順序、數字格式皆不容許）。
	again, err := st.Encode()
	if err != nil || string(again) != string(body) {
		return nil, fmt.Errorf("%w: 非 canonical 編碼", ErrPermissionSnapshotFormat)
	}
	return st, nil
}

// Clone 深拷貝（重放時就地套用 delta 用）。
func (s *PermissionState) Clone() *PermissionState {
	c := &PermissionState{Meta: s.Meta, Sets: make(map[string][]string, len(s.Sets))}
	for k, v := range s.Sets {
		c.Sets[k] = append([]string(nil), v...)
	}
	return c
}

// PermissionDelta 兩份狀態在元素層級的差集（add／del 依集合名索引）。
type PermissionDelta struct {
	Add map[string][]string `json:"add,omitempty"`
	Del map[string][]string `json:"del,omitempty"`
}

// Empty 差集是否為空。
func (d PermissionDelta) Empty() bool { return len(d.Add) == 0 && len(d.Del) == 0 }

// DiffPermissionState 回傳 from → to 的元素差集（版本維度另計）。
func DiffPermissionState(from, to *PermissionState) PermissionDelta {
	d := PermissionDelta{Add: map[string][]string{}, Del: map[string][]string{}}
	for _, name := range permissionSetNames() {
		a, b := toSetMap(from.Sets[name]), toSetMap(to.Sets[name])
		for r := range b {
			if !a[r] {
				d.Add[name] = append(d.Add[name], r)
			}
		}
		for r := range a {
			if !b[r] {
				d.Del[name] = append(d.Del[name], r)
			}
		}
		sort.Strings(d.Add[name])
		sort.Strings(d.Del[name])
	}
	for k, v := range d.Add {
		if len(v) == 0 {
			delete(d.Add, k)
		}
	}
	for k, v := range d.Del {
		if len(v) == 0 {
			delete(d.Del, k)
		}
	}
	return d
}

// Apply 把差集套用到狀態（回傳新狀態；del 的元素不存在視為錯誤，重放不容許靜默容忍）。
func (s *PermissionState) Apply(d PermissionDelta) (*PermissionState, error) {
	out := s.Clone()
	for name, rows := range d.Del {
		set := toSetMap(out.Sets[name])
		for _, r := range rows {
			if !set[r] {
				return nil, fmt.Errorf("重放失敗：集合 %s 沒有要移除的元素 %s", name, r)
			}
			delete(set, r)
		}
		out.Sets[name] = setKeys(set)
	}
	for name, rows := range d.Add {
		if _, ok := out.Sets[name]; !ok {
			if !isPermissionSet(name) {
				return nil, fmt.Errorf("重放失敗：未知集合 %s", name)
			}
		}
		set := toSetMap(out.Sets[name])
		for _, r := range rows {
			if set[r] {
				return nil, fmt.Errorf("重放失敗：集合 %s 已有元素 %s", name, r)
			}
			set[r] = true
		}
		out.Sets[name] = setKeys(set)
	}
	return out, nil
}

func isPermissionSet(name string) bool {
	for _, n := range permissionSetNames() {
		if n == name {
			return true
		}
	}
	return false
}

func toSetMap(rows []string) map[string]bool {
	m := make(map[string]bool, len(rows))
	for _, r := range rows {
		m[r] = true
	}
	return m
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PermissionMatchFingerprint 外部比對字串的不可逆指紋（快照不放原文）。
func PermissionMatchFingerprint(value string) string {
	h := sha256.Sum256([]byte("permission-match-fp/v1\x00" + value))
	return hex.EncodeToString(h[:16])
}

// PermissionGenerationFingerprint 恢復世代的指紋；空世代回空字串。
func PermissionGenerationFingerprint(generation string) string {
	if generation == "" {
		return ""
	}
	h := sha256.Sum256([]byte("permission-generation-fp/v1\x00" + generation))
	return hex.EncodeToString(h[:16])
}
