package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 角色內容修改與 agent 持有者的重驗。
//
// 指派當下的關卡只看當時的角色內容；角色之後被改成含管理、稽核或審核類權限點時，
// 已持有它的 agent 會隨之取得不該有的能力。這裡補兩件事：
//   - 修改交易內（鎖定角色列之後）以已提交讀取列出持有者，命中即拒（rejectRoleUpdateForAgents），
//     拒絕明細隨錯誤回給呼叫端，由 HTTP 層併入該次請求的審計列；
//   - 不加新鎖，因此修改與指派可能並發而雙雙提交，兩側各在自己的寫入提交之後，
//     以新交易重查同一個判定（detectRestrictedAgentHolders），命中即建立系統告警並留審計。

const (
	// RoleUpdateAgentRestrictedEvent 提交後偵測命中的審計事件名（角色側與指派側共用）。
	RoleUpdateAgentRestrictedEvent = "role_update_agent_restricted_detected"
	// DetectedByRoleUpdate／DetectedByAssignment 偵測命中的一側。
	DetectedByRoleUpdate = "role_update"
	DetectedByAssignment = "assignment"

	agentRevalidationDetectedPathRole   = "role_update_detected"
	agentRevalidationDetectedPathAssign = "assignment_detected"
)

// agentRoleUpdateRejection 角色修改因 agent 持有者被拒：錯誤本體沿指派關卡的 agent 角色拒絕，
// 另帶留痕所需的事實（不放進回應；由 HTTP 層併入該次請求的審計列）。
type agentRoleUpdateRejection struct {
	denial     error
	agentCount int
	restricted []string
}

func (e *agentRoleUpdateRejection) Error() string { return e.denial.Error() }
func (e *agentRoleUpdateRejection) Unwrap() error { return e.denial }

// AgentRoleUpdateRejectionFacts 角色修改因 agent 持有者被拒時的留痕事實：受影響 agent 數與
// 新集合中 agent 不得持有的權限點（升冪）。不是這種拒絕時 ok 為 false。
// 只供呼叫端併入該次請求的審計列；服務本身不另寫拒絕審計。
func AgentRoleUpdateRejectionFacts(err error) (agentCount int, restricted []string, ok bool) {
	var rej *agentRoleUpdateRejection
	if !errors.As(err, &rej) {
		return 0, nil, false
	}
	return rej.agentCount, append([]string(nil), rej.restricted...), true
}

// agentRoleHolders 經直接指派與經群組成員持有該角色、且未刪除的 agent（升冪、去重）。
func agentRoleHolders(db *gorm.DB, roleID uint) ([]uint, error) {
	var direct, viaGroup []uint
	if err := db.Table("user_roles").
		Joins("JOIN users ON users.id = user_roles.user_id").
		Where("user_roles.role_id = ? AND users.kind = ? AND users.deleted_at IS NULL", roleID, model.KindAgent).
		Pluck("users.id", &direct).Error; err != nil {
		return nil, fmt.Errorf("讀取直接持有角色的 agent 失敗: %w", err)
	}
	// 群組路徑經授權模組的對外讀取（與主體解析同一條件），再以本模組的帳號表篩出 agent。
	pairs, err := authz.GroupRoleHolders(db)
	if err != nil {
		return nil, err
	}
	var members []uint
	for _, p := range pairs {
		if p.RoleID == roleID {
			members = append(members, p.UserID)
		}
	}
	if len(members) > 0 {
		if err := db.Model(&model.User{}).Where("id IN ? AND kind = ?", members, model.KindAgent).
			Pluck("id", &viaGroup).Error; err != nil {
			return nil, fmt.Errorf("讀取經群組持有角色的 agent 失敗: %w", err)
		}
	}
	return unionIDs(direct, viaGroup), nil
}

// restrictedKeysForAgent 權限集合中 agent 不得持有的權限點（逐點套同一個判定函式）。
func restrictedKeysForAgent(perms []authz.Permission) []string {
	out := []string{}
	for _, p := range perms {
		if authz.CapabilityRestrictedForAgent([]authz.Permission{p}) {
			out = append(out, string(p))
		}
	}
	sort.Strings(out)
	return out
}

// rejectRoleUpdateForAgents 修改交易內呼叫：新集合受限且有 agent 持有者即回拒絕。
func rejectRoleUpdateForAgents(tx *gorm.DB, roleID uint, perms []authz.Permission) error {
	if !authz.CapabilityRestrictedForAgent(perms) {
		return nil
	}
	holders, err := agentRoleHolders(tx, roleID)
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		return nil
	}
	return &agentRoleUpdateRejection{
		denial:     deny(DenyReasonAgentRole, ErrAgentRoleForbidden),
		agentCount: len(holders),
		restricted: restrictedKeysForAgent(perms),
	}
}

// agentDetection 一次提交後偵測的輸入。
type agentDetection struct {
	by     string
	op     Operator
	roleID uint
	// agentIDs 指派側：本次新增持有角色的 agent 候選；角色側為 nil（全部持有者）。
	agentIDs []uint
	// 審計的資源：角色側為角色，指派側為該次指派寫入的資源。
	action     model.AuditAction
	resource   string
	resourceID uint
	// 角色側的修改前後集合。
	before, after []string
}

// detectRestrictedAgentHolders 提交後以新交易重查：角色對 agent 受限且仍有 agent 持有，
// 即留審計並對每個 agent 建立管理類發放告警（同一關聯編號）。不回復原寫入，失敗只記錯誤日誌。
func (g *GrantGrader) detectRestrictedAgentHolders(db *gorm.DB, in agentDetection) {
	if g == nil || db == nil {
		return
	}
	if err := g.detectInNewTx(db, in); err != nil {
		log.Printf("[AgentRoleRevalidation] 提交後偵測失敗（原寫入維持已提交）: role=%d by=%s err=%v", in.roleID, in.by, err)
	}
}

func (g *GrantGrader) detectInNewTx(db *gorm.DB, in agentDetection) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var role model.Role
		if err := tx.First(&role, in.roleID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return fmt.Errorf("讀取角色失敗: %w", err)
		}
		forbidden, err := roleForbiddenForAgent(tx, role)
		if err != nil || !forbidden {
			return err
		}
		holders, err := agentRoleHolders(tx, role.ID)
		if err != nil {
			return err
		}
		if in.agentIDs != nil {
			holders = intersectIDs(holders, in.agentIDs)
		}
		if len(holders) == 0 {
			return nil
		}
		perms, err := roleCurrentPermissions(tx, role)
		if err != nil {
			return err
		}
		corr, err := newCorrelationID()
		if err != nil {
			return err
		}
		details := map[string]any{
			"event": RoleUpdateAgentRestrictedEvent, "detected_by": in.by,
			"role_id": role.ID, "role_name": role.Name, "agent_ids": holders,
			"restricted_permissions": restrictedKeysForAgent(perms), "correlation_id": corr,
		}
		if in.by == DetectedByRoleUpdate {
			added, removed := setDiff(in.before, in.after)
			details["permissions_before"], details["permissions_after"] = in.before, in.after
			details["added"], details["removed"] = added, removed
		} else {
			details["permissions"] = permStrings(perms)
		}
		raw, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("序列化偵測審計失敗: %w", err)
		}
		rid := in.resourceID
		if err := port.WriteInTx(g.auditTx, tx, port.AuditEvent{
			Action: string(in.action), Resource: in.resource, ResourceID: &rid,
			Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: in.op.UserID, Username: in.op.Username},
			Request: gatewayapi.RequestMeta{ClientIP: in.op.ClientIP}, Details: string(raw),
		}); err != nil {
			return fmt.Errorf("偵測審計寫入失敗: %w", err)
		}
		if in.op.UserID == 0 {
			// 沒有可指認的操作者（內部入口）：系統告警要求操作者，只留審計。
			return nil
		}
		path := agentRevalidationDetectedPathAssign
		if in.by == DetectedByRoleUpdate {
			path = agentRevalidationDetectedPathRole
		}
		for _, agentID := range holders {
			var name string
			if err := tx.Model(&model.User{}).Where("id = ?", agentID).Pluck("username", &name).Error; err != nil {
				return fmt.Errorf("查詢 agent 名稱失敗: %w", err)
			}
			granted := []authz.GrantEntry{{RoleID: role.ID, RoleName: role.Name, Scope: model.ScopeKindGlobal}}
			if _, err := port.RaiseInTx(g.alerts, tx, port.SystemAlertEvent{
				Type:     port.SystemAlertType(authz.AlertKeyManagementGranted),
				Actor:    port.SystemAlertActor{UserID: in.op.UserID, Username: in.op.Username},
				ClientIP: in.op.ClientIP, CorrelationID: corr,
				Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetUser, ID: fmt.Sprint(agentID)},
				Params: authz.ManagementGrantParams(path, name, granted),
			}); err != nil {
				return fmt.Errorf("系統告警事件寫入失敗: %w", err)
			}
		}
		return nil
	})
}

// roleCurrentPermissions 角色當下的權限點集合（內建取程式定義、自訂取權限表）。
func roleCurrentPermissions(tx *gorm.DB, r model.Role) ([]authz.Permission, error) {
	if r.BuiltinKey != nil && *r.BuiltinKey != "" {
		return authz.RolePermissionsForGuard(*r.BuiltinKey), nil
	}
	if r.DefinitionVersion < 1 {
		return nil, nil
	}
	return customRolePermissions(tx, r.ID)
}

func intersectIDs(a, b []uint) []uint {
	in := map[uint]bool{}
	for _, id := range b {
		in[id] = true
	}
	out := []uint{}
	for _, id := range a {
		if in[id] {
			out = append(out, id)
		}
	}
	return out
}

// afterAgentRoleWrite 指派側：使 agent 新增持有角色的寫入提交之後呼叫，逐角色以同一偵測函式重查。
// op 為 nil（內部入口）時以零值操作者處理。
func (g *GrantGrader) afterAgentRoleWrite(db *gorm.DB, op *Operator, resource string, resourceID uint, agentIDs, roleIDs []uint) {
	if g == nil || len(agentIDs) == 0 || len(roleIDs) == 0 {
		return
	}
	var o Operator
	if op != nil {
		o = *op
	}
	for _, rid := range roleIDs {
		g.detectRestrictedAgentHolders(db, agentDetection{
			by: DetectedByAssignment, op: o, roleID: rid, agentIDs: agentIDs,
			action: model.ActionUpdate, resource: resource, resourceID: resourceID,
		})
	}
}

// roleIDsByNames 依角色名稱取角色編號（查不到的名稱略過）。
func roleIDsByNames(db *gorm.DB, names []string) []uint {
	if len(names) == 0 {
		return nil
	}
	var ids []uint
	if err := db.Model(&model.Role{}).Where("name IN ?", names).Pluck("id", &ids).Error; err != nil {
		log.Printf("[AgentRoleRevalidation] 讀取角色編號失敗: %v", err)
		return nil
	}
	return ids
}
