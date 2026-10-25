package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// 角色定義的權限狀態表示。
//
// 純資料與純函式，不碰資料庫：呈現「附證應含什麼」與「怎麼核對」，由權限狀態的版本化快照消費。
// 只含穩定識別、權限鍵、版本與相容目錄識別；**不含角色名稱、說明或任何自由文字**。
// 本表示自帶格式版本；permission_state 快照把它當作子段嵌入（外層快照版本由該快照決定）。

// RoleDefinitionStateFormat 本表示的格式版本。未知版本一律拒絕，不當成空集合忽略。
const RoleDefinitionStateFormat = 1

// RoleDefinitionStateRole 一個自訂角色的狀態。
type RoleDefinitionStateRole struct {
	RoleID            uint     `json:"role_id"`
	DefinitionVersion int64    `json:"definition_version"`
	TemplateRoleID    *uint    `json:"template_role_id,omitempty"`
	Keys              []string `json:"keys"`
}

// RoleDefinitionState 自訂角色集合、定義版本、範本識別與相容目錄識別。
type RoleDefinitionState struct {
	Format int `json:"format"`
	// LegacyCatalogIDs 升級前存量相容目錄的角色 ID（definition_version = 0）。
	LegacyCatalogIDs []uint `json:"legacy_catalog_ids"`
	// BuiltinRoleIDs 內建與鎖定範本的角色 ID（集合在程式中，不隨快照）。
	BuiltinRoleIDs []uint                    `json:"builtin_role_ids"`
	Roles          []RoleDefinitionStateRole `json:"roles"`
}

// Canonical 排序後的副本（決定性）。
func (s RoleDefinitionState) Canonical() RoleDefinitionState {
	out := RoleDefinitionState{Format: s.Format,
		LegacyCatalogIDs: append([]uint{}, s.LegacyCatalogIDs...),
		BuiltinRoleIDs:   append([]uint{}, s.BuiltinRoleIDs...),
		Roles:            make([]RoleDefinitionStateRole, 0, len(s.Roles))}
	sort.Slice(out.LegacyCatalogIDs, func(i, j int) bool { return out.LegacyCatalogIDs[i] < out.LegacyCatalogIDs[j] })
	sort.Slice(out.BuiltinRoleIDs, func(i, j int) bool { return out.BuiltinRoleIDs[i] < out.BuiltinRoleIDs[j] })
	for _, r := range s.Roles {
		r.Keys = append([]string{}, r.Keys...)
		sort.Strings(r.Keys)
		out.Roles = append(out.Roles, r)
	}
	sort.Slice(out.Roles, func(i, j int) bool { return out.Roles[i].RoleID < out.Roles[j].RoleID })
	return out
}

// Digest 狀態的 SHA-256（對 Canonical 的 JSON）。集合、版本、範本識別或相容目錄改變即改變；
// 角色名稱與說明不在狀態內，改名不改摘要。
func (s RoleDefinitionState) Digest() (string, error) {
	b, err := json.Marshal(s.Canonical())
	if err != nil {
		return "", fmt.Errorf("序列化角色定義狀態失敗: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ValidateRoleDefinitionState 恢復核對：未知格式、無效權限鍵（含 ui:／保留能力）、
// 懸空的範本來源參照、重複角色一律回錯，不刪壞列、不補權。
func ValidateRoleDefinitionState(s RoleDefinitionState) error {
	if s.Format != RoleDefinitionStateFormat {
		return fmt.Errorf("角色定義狀態格式未知: %d", s.Format)
	}
	known := map[uint]bool{}
	for _, id := range s.LegacyCatalogIDs {
		known[id] = true
	}
	for _, id := range s.BuiltinRoleIDs {
		known[id] = true
	}
	seen := map[uint]bool{}
	for _, r := range s.Roles {
		if seen[r.RoleID] || known[r.RoleID] {
			return fmt.Errorf("角色定義狀態重複的角色 ID: %d", r.RoleID)
		}
		seen[r.RoleID] = true
	}
	for _, r := range s.Roles {
		if r.DefinitionVersion < 1 {
			return fmt.Errorf("自訂角色 %d 的定義版本無效: %d", r.RoleID, r.DefinitionVersion)
		}
		if _, err := NormalizeRolePermissions(r.Keys); err != nil {
			return fmt.Errorf("自訂角色 %d: %w", r.RoleID, err)
		}
		if r.TemplateRoleID != nil && !known[*r.TemplateRoleID] && !seen[*r.TemplateRoleID] {
			return fmt.Errorf("自訂角色 %d 的範本來源 %d 不存在", r.RoleID, *r.TemplateRoleID)
		}
	}
	return nil
}

// RoleDefinitionStateEvent 同交易寫入的可重放事件（與 identity.RoleDefinitionEvent 同形，供權限狀態事件寫入面轉接）。
type RoleDefinitionStateEvent struct {
	Action            string
	RoleID            uint
	DefinitionVersion int64
	Before, After     []string
}

// 與 model 四個審計 action 同值；authz 不依賴 model 的 action 常數，這裡只認字串。
const (
	roleEventCreate = "role_definition_create"
	roleEventCopy   = "role_definition_copy"
	roleEventUpdate = "role_definition_update"
	roleEventDelete = "role_definition_delete"
)

// ReplayRoleDefinitionEvents 依序重放事件得到 role_id → 權限鍵。
// 每個事件的 Before 必須等於重放當下的集合、版本必須連續（建立為 1，其後逐次加一），
// 否則回錯指出該事件：無對應事件的直接變更因此會在下一個事件處或與現況比較時被辨識。
// 刪除事件使該角色自結果移除。
func ReplayRoleDefinitionEvents(events []RoleDefinitionStateEvent) (map[uint][]string, error) {
	cur := map[uint][]string{}
	ver := map[uint]int64{}
	for i, ev := range events {
		switch ev.Action {
		case roleEventCreate, roleEventCopy:
			if _, ok := ver[ev.RoleID]; ok {
				return nil, fmt.Errorf("事件 %d：角色 %d 重複建立", i, ev.RoleID)
			}
			if ev.DefinitionVersion != 1 || len(ev.Before) != 0 {
				return nil, fmt.Errorf("事件 %d：建立事件的版本或前集合不合法", i)
			}
		case roleEventUpdate, roleEventDelete:
			v, ok := ver[ev.RoleID]
			if !ok {
				return nil, fmt.Errorf("事件 %d：角色 %d 無先前事件", i, ev.RoleID)
			}
			if ev.DefinitionVersion != v+1 {
				return nil, fmt.Errorf("事件 %d：角色 %d 版本不連續 (%d -> %d)", i, ev.RoleID, v, ev.DefinitionVersion)
			}
			if !sameKeySet(cur[ev.RoleID], ev.Before) {
				return nil, fmt.Errorf("事件 %d：角色 %d 的前集合與重放結果不符", i, ev.RoleID)
			}
		default:
			return nil, fmt.Errorf("事件 %d：未知動作 %q", i, ev.Action)
		}
		ver[ev.RoleID] = ev.DefinitionVersion
		after := append([]string{}, ev.After...)
		sort.Strings(after)
		cur[ev.RoleID] = after
		if ev.Action == roleEventDelete {
			delete(cur, ev.RoleID)
			ver[ev.RoleID] = ev.DefinitionVersion
		}
	}
	return cur, nil
}

func sameKeySet(a, b []string) bool {
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// DiffRoleDefinitionState 重放結果與現況（只含未刪除自訂角色）的差異角色 ID（排序）。
// 非空代表有未經事件的直接變更（含直接新增、移除或改集合）。
func DiffRoleDefinitionState(replayed map[uint][]string, live RoleDefinitionState) []uint {
	liveByID := map[uint][]string{}
	for _, r := range live.Roles {
		liveByID[r.RoleID] = r.Keys
	}
	diff := map[uint]bool{}
	for id, keys := range replayed {
		lk, ok := liveByID[id]
		if !ok || !sameKeySet(keys, lk) {
			diff[id] = true
		}
	}
	for id := range liveByID {
		if _, ok := replayed[id]; !ok {
			diff[id] = true
		}
	}
	out := make([]uint, 0, len(diff))
	for id := range diff {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
