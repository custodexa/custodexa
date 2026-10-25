package api

import (
	"encoding/json"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/modules/identity"
)

// 角色指派請求的範圍欄位偵測。
//
// 節點範圍指派開放前，指派請求帶任何範圍或節點欄位都整筆拒絕。JSON 綁定會默默丟掉不認得的鍵，
// 不先看原文的話，帶節點的請求會被當成全域寫入；所以判定一律看請求原文的頂層鍵。

// isRoleScopeField 鍵名含 scope 或 node（不分大小寫）即視為範圍欄位。
func isRoleScopeField(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "scope") || strings.Contains(k, "node")
}

// bodyRequestsRoleScope 請求原文是 JSON 物件且頂層有範圍欄位。空 body 或不是物件時回 false，
// 形狀錯誤由各端點自己的綁定處理。
func bodyRequestsRoleScope(raw []byte) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return false
	}
	for k := range fields {
		if isRoleScopeField(k) {
			return true
		}
	}
	return false
}

// boundBodyRequestsRoleScope 以 ShouldBindBodyWith 綁定後，從 gin 保留的原文判定。
func boundBodyRequestsRoleScope(c *gin.Context) bool {
	v, ok := c.Get(gin.BodyBytesKey)
	if !ok {
		return false
	}
	raw, ok := v.([]byte)
	return ok && bodyRequestsRoleScope(raw)
}

// roleNodesKey 兩個整組替換入口的節點範圍欄位；它有自己的語義（省略保留、null 全域、陣列節點），
// 不走「帶範圍欄位一律拒絕」的偵測。
const roleNodesKey = "role_nodes"

// bodyRequestsRoleScopeExceptNodes 請求原文頂層有 role_nodes 以外的範圍欄位。
func bodyRequestsRoleScopeExceptNodes(raw []byte) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return false
	}
	for k := range fields {
		if k != roleNodesKey && isRoleScopeField(k) {
			return true
		}
	}
	return false
}

// parseRoleNodes 解析 role_nodes：{"<鍵>": [節點ID…] | null}。鍵不存在或整個欄位為 null 回空表。
// 形狀錯誤（不是物件、值不是 null 或整數陣列）回 false。
func parseRoleNodes(raw json.RawMessage) (map[string]identity.RoleNodesValue, bool) {
	out := map[string]identity.RoleNodesValue{}
	if len(raw) == 0 || string(raw) == "null" {
		return out, true
	}
	var m map[string]*[]uint
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, false
	}
	for k, v := range m {
		if v == nil {
			out[k] = identity.RoleNodesValue{Global: true}
			continue
		}
		out[k] = identity.RoleNodesValue{NodeIDs: *v}
	}
	return out, true
}
