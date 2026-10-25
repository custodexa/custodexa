package audit

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// 角色指派類審計列的原因碼與參數。
//
// 這些列的 details 只存識別碼（角色、對象、節點），名稱在讀取時由 API 層換上
// （見 internal/api 的名稱換算器），所以這裡的參數預設值都是 `#<識別碼>`。

const (
	reasonUserRoleAssign       = "user_role_assign"
	reasonUserRoleAssignNodes  = "user_role_assign_nodes"
	reasonUserRoleRevoke       = "user_role_revoke"
	reasonGroupRoleAssign      = "user_group_role_assign"
	reasonGroupRoleRevoke      = "user_group_role_revoke"
	reasonRangeGlobal          = "global"
	reasonTargetKindUser       = "user"
	reasonTargetKindUserGroup  = "user_group"
	reasonRoleAssignmentIDHash = "#"
)

// IsRoleAssignmentReasonCode 是否為角色指派類原因碼；API 層的名稱換算器以它判斷要不要換名。
func IsRoleAssignmentReasonCode(code string) bool {
	switch code {
	case reasonUserRoleAssign, reasonUserRoleAssignNodes, reasonUserRoleRevoke,
		reasonGroupRoleAssign, reasonGroupRoleRevoke,
		reasonEventPrefix + model.RoleBindingRangeChangedEvent:
		return true
	}
	return false
}

// idRef 識別碼的預設呈現：`#<id>`；缺值回 "—"
func (d reasonDetails) idRef(key string) string {
	if v, ok := d.num(key); ok {
		return reasonRoleAssignmentIDHash + v
	}
	return "—"
}

// rangeValue 範圍欄位（"global" 或節點編號陣列）轉成參數值與總數。
// 欄位不存在回空字串；節點清單以 `#<id>` 逗號接，總數優先取 `<key>_count`（清單因上限被截斷時仍正確）
func (d reasonDetails) rangeValue(key string) (value, count string) {
	switch v := d[key].(type) {
	case string:
		if v == reasonRangeGlobal {
			return reasonRangeGlobal, "0"
		}
		return "", ""
	case []any:
		ids := make([]string, 0, len(v))
		for _, it := range v {
			if n, ok := it.(json.Number); ok {
				ids = append(ids, reasonRoleAssignmentIDHash+n.String())
			}
		}
		count = d.numOr(key+"_count", "")
		if count == "" {
			count = strconv.Itoa(len(ids))
		}
		return strings.Join(ids, reasonListSeparator), count
	}
	return "", ""
}

func roleAssignmentShapes() []auditReasonShape {
	return []auditReasonShape{
		{Codes: []string{reasonUserRoleAssign, reasonUserRoleAssignNodes, reasonUserRoleRevoke},
			Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
				if in.Resource != string(model.ResourceUserRole) {
					return "", nil, false
				}
				params := reasonParams{"role": d.idRef("role_id"), "target": d.idRef("user_id"), "origin": opaque(d.str("origin"))}
				switch in.Action {
				case string(model.ActionAssign):
					// 範圍欄位不存在或為 "global" 都是全系統指派；只有節點清單才是限節點
					if nodes, count := d.rangeValue("range_after"); nodes != "" && nodes != reasonRangeGlobal {
						params["nodes"], params["nodes_count"] = nodes, count
						return reasonUserRoleAssignNodes, params, true
					}
					return reasonUserRoleAssign, params, true
				case string(model.ActionRevoke):
					return reasonUserRoleRevoke, params, true
				}
				return "", nil, false
			}},
		{Codes: []string{reasonGroupRoleAssign, reasonGroupRoleRevoke},
			Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
				if in.Resource != string(model.ResourceUserGroupRole) {
					return "", nil, false
				}
				// 句子本身已寫明「使用者群組」，對象只帶名稱（不帶 target_kind，避免前端再加一次字樣）
				params := reasonParams{"role": d.idRef("role_id"), "target": d.idRef("user_group_id")}
				switch in.Action {
				case string(model.ActionAssign):
					return reasonGroupRoleAssign, params, true
				case string(model.ActionRevoke):
					return reasonGroupRoleRevoke, params, true
				}
				return "", nil, false
			}},
	}
}

// roleBindingRangeChangedParams 只改範圍的事件列：帳號列與群組列共用，對象種類看 details 帶哪個鍵
func roleBindingRangeChangedParams(d reasonDetails) reasonParams {
	params := reasonParams{"role": d.idRef("role_id")}
	if _, ok := d["user_group_id"]; ok {
		params["target"], params["target_kind"] = d.idRef("user_group_id"), reasonTargetKindUserGroup
	} else {
		params["target"], params["target_kind"] = d.idRef("user_id"), reasonTargetKindUser
	}
	if v, c := d.rangeValue("range_before"); v != "" {
		params["before"], params["before_count"] = v, c
	}
	if v, c := d.rangeValue("range_after"); v != "" {
		params["after"], params["after_count"] = v, c
	}
	return params
}

// grantChangeGradedParams 授權分級列：帶出已建立告警的標記（逗號接）
func grantChangeGradedParams(d reasonDetails) reasonParams {
	return reasonParams{"marks": opaqueList(d.strList("grant_marks"))}
}
