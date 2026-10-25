package identity

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 角色內容修改的授權變更分級（同交易）。
//
// 指派不變而角色的權限集合改變時，指派鍵比較看不到差異；這裡改以權限集合差判定，
// 對操作者本人持有的角色產生自我授權事件，對他人新發放管理類能力則以「角色」為目標產生
// 一筆管理類發放事件（不逐持有者展開，持有者與引用數量寫在審計 details）。
// 審計列、事件與角色內容同一交易，任一步失敗整筆回滾。

// PathRoleDefinition 角色定義修改的取得路徑代碼（告警摘要 path 欄的值）。
const PathRoleDefinition AssignmentPath = "role_definition"

// roleContentGrade 一次修改的分級結果；事件在審計列寫入後由 raiseRoleContent 落地。
type roleContentGrade struct {
	op      authz.RoleContentOperation
	impact  authz.RoleContentImpact
	corr    string
	nameOld string
	nameNew string
	roleID  uint
}

// gradeContentChange 交易內求出修改的分級。角色有持有者或引用而分級器未注入時回錯。
func (s *RoleDefinitionService) gradeContentChange(tx *gorm.DB, actor *model.User, role *model.Role, newName string,
	before []string, after []authz.Permission) (*roleContentGrade, error) {
	impact, err := authz.LoadRoleContentImpact(tx, role.ID, RoleMappingRuleCount)
	if err != nil {
		return nil, err
	}
	if !impact.Referenced() {
		return nil, nil
	}
	if s.grader == nil {
		return nil, ErrRoleGraderMissing
	}
	prev := make([]authz.Permission, len(before))
	for i, k := range before {
		prev[i] = authz.Permission(k)
	}
	op := authz.ClassifyRoleContentOperation(authz.ClassifyRoleContentChange(prev, after), impact, actor.ID)
	if len(op.Marks) == 0 {
		return nil, nil
	}
	corr, err := newCorrelationID()
	if err != nil {
		return nil, err
	}
	return &roleContentGrade{op: op, impact: impact, corr: corr, nameOld: role.Name, nameNew: newName, roleID: role.ID}, nil
}

// raiseRoleContent 依分級結果寫系統告警事件；res 沒有分級命中時不做事。以 nil 接收者呼叫時，
// 只有「有命中卻沒有分級器」才會走到這裡，而那在 gradeContentChange 已被拒絕。
func (g *GrantGrader) raiseRoleContent(tx *gorm.DB, op Operator, res *writeResult) error {
	gr := res.grade
	if gr == nil {
		return nil
	}
	if g == nil {
		return ErrRoleGraderMissing
	}
	actor := port.SystemAlertActor{UserID: op.UserID, Username: op.Username}
	if gr.op.SelfDirection != authz.GrantNone {
		if _, err := port.RaiseInTx(g.alerts, tx, port.SystemAlertEvent{
			Type: port.SystemAlertType(authz.SelfPrivilegeAlertKey(gr.op.SelfDirection)), Actor: actor,
			ClientIP: op.ClientIP, CorrelationID: gr.corr,
			Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetUser, ID: fmt.Sprint(op.UserID)},
			Params: map[string]string{"path": string(PathRoleDefinition), "roles_before": gr.nameOld, "roles_after": gr.nameNew},
		}); err != nil {
			return fmt.Errorf("系統告警事件寫入失敗: %w", err)
		}
	}
	if gr.op.ManagementGranted {
		if _, err := port.RaiseInTx(g.alerts, tx, port.SystemAlertEvent{
			Type: port.SystemAlertType(authz.AlertKeyManagementGranted), Actor: actor,
			ClientIP: op.ClientIP, CorrelationID: gr.corr,
			Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetRole, ID: fmt.Sprint(gr.roleID)},
			Params: map[string]string{"path": string(PathRoleDefinition), "recipient": gr.nameNew, "role_name": gr.nameNew},
		}); err != nil {
			return fmt.Errorf("系統告警事件寫入失敗: %w", err)
		}
	}
	return nil
}
