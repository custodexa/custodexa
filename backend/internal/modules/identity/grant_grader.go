package identity

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 授權變更的分級與留痕（同交易）。
//
// 每個寫入點在寫入前取主體的授權摘要、寫入後再取一次，交給 authz 的分類器判定：
// 對自己的增加為高、純減少為低；對他人發放管理類角色為中；其餘不告警。命中時在同一交易內
// 先寫一列帶標記的服務審計，再經系統告警落地面寫事件，兩者共用同一個關聯編號。
// 任一步失敗由呼叫端整筆回滾；拒絕的寫入不會走到這裡。
//
// 事件只帶角色名稱、範圍與授權規則數量，不含密碼、token、外部 subject。

// GrantGrader 授權變更的分級與留痕。無狀態，可共用；nil 代表未啟用（僅限測試與內部入口）。
type GrantGrader struct {
	auditTx port.TxSink
	alerts  port.SystemAlertSink
	// preview 映射規則寫入餵危險組合預覽的輸入；nil 表示不餵
	preview MappingImpactPreview
}

// NewGrantGrader 建立分級器；兩個落地面都由組裝根注入。
func NewGrantGrader(auditTx port.TxSink, alerts port.SystemAlertSink) *GrantGrader {
	return &GrantGrader{auditTx: auditTx, alerts: alerts}
}

// grantTracker 一次寫入的前後比對。以 nil 接收者呼叫皆為無操作。
type grantTracker struct {
	g           *GrantGrader
	op          Operator
	path        AssignmentPath
	subject     uint // 直接路徑的被異動主體；群組路徑為 0
	before      authz.GrantSummary
	groupBefore []authz.GrantEntry
}

// begin 在寫入前取前摘要。直接路徑的主體是被異動帳號（建帳號時為 0，前摘要為空）；
// 群組路徑的比對主體是操作者本人（他是否為成員由前後摘要的差自然判出）。
func (g *GrantGrader) begin(tx *gorm.DB, op Operator, path AssignmentPath, directTarget uint, groupID uint) (*grantTracker, error) {
	if g == nil {
		return nil, nil
	}
	t := &grantTracker{g: g, op: op, path: path}
	subject := directTarget
	if groupID != 0 {
		subject = op.UserID
	}
	t.subject = subject
	if subject != 0 {
		sum, err := authz.SummarizeGrants(tx, subject)
		if err != nil {
			return nil, err
		}
		t.before = sum
	}
	if groupID != 0 {
		ents, err := authz.GroupGrantEntries(tx, groupID)
		if err != nil {
			return nil, err
		}
		t.groupBefore = ents
	}
	return t, nil
}

// finishDirect 直接路徑：寫入後比對被異動帳號。subject 在建帳號時才知道，故由呼叫端帶入。
func (t *grantTracker) finishDirect(tx *gorm.DB, subject uint) error {
	if t == nil {
		return nil
	}
	after, err := authz.SummarizeGrants(tx, subject)
	if err != nil {
		return err
	}
	cls := authz.ClassifyGrantChange(t.before, after, subject == t.op.UserID)
	return t.emitUser(tx, subject, t.before, after, cls)
}

// finishGroup 群組路徑：operator 若因此增減自己的授權，產生自我授權事件；
// 群組新增的管理類角色（角色指派路徑），或有他人被加入而群組帶管理類角色（成員加入路徑），
// 產生一筆以群組為目標的管理類發放事件。
func (t *grantTracker) finishGroup(tx *gorm.DB, groupID uint, groupName string, addedOthers int) error {
	if t == nil {
		return nil
	}
	after, err := authz.SummarizeGrants(tx, t.op.UserID)
	if err != nil {
		return err
	}
	cls := authz.ClassifyGrantChange(t.before, after, true)
	if err := t.emitUser(tx, t.op.UserID, t.before, after, cls); err != nil {
		return err
	}
	groupAfter, err := authz.GroupGrantEntries(tx, groupID)
	if err != nil {
		return err
	}
	var mgmt []authz.GrantEntry
	switch t.path {
	case PathGroupRoles:
		mgmt = authz.ClassifyGroupManagementGrant(authz.GrantEntriesAdded(t.groupBefore, groupAfter))
	case PathGroupMember:
		if addedOthers > 0 {
			mgmt = authz.ClassifyGroupManagementGrant(groupAfter)
		}
	}
	if len(mgmt) == 0 {
		return nil
	}
	return t.emitManagement(tx, port.SystemAlertTargetUserGroup, groupID, groupName, mgmt,
		"user_group", groupID)
}

func (t *grantTracker) emitUser(tx *gorm.DB, subject uint, before, after authz.GrantSummary, cls authz.GrantClassification) error {
	if len(cls.Marks) == 0 {
		return nil
	}
	var name string
	if err := tx.Model(&model.User{}).Where("id = ?", subject).Pluck("username", &name).Error; err != nil {
		return fmt.Errorf("查詢主體名稱失敗: %w", err)
	}
	if cls.SelfDirection != authz.GrantNone {
		typ := port.SystemAlertType(authz.SelfPrivilegeAlertKey(cls.SelfDirection))
		corr, err := newCorrelationID()
		if err != nil {
			return err
		}
		if err := t.writeMarkedAudit(tx, "user", subject, []string{authz.GrantMarkSelfAuthorization}, corr); err != nil {
			return err
		}
		if _, err := port.RaiseInTx(t.g.alerts, tx, port.SystemAlertEvent{
			Type: typ, Actor: port.SystemAlertActor{UserID: t.op.UserID, Username: t.op.Username},
			ClientIP: t.op.ClientIP, CorrelationID: corr,
			Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetUser, ID: fmt.Sprint(subject)},
			Params: authz.SelfPrivilegeParams(string(t.path), before.Entries, after.Entries),
		}); err != nil {
			return fmt.Errorf("系統告警事件寫入失敗: %w", err)
		}
	}
	if len(cls.ManagementGranted) > 0 {
		return t.emitManagement(tx, port.SystemAlertTargetUser, subject, name, cls.ManagementGranted, "user", subject)
	}
	return nil
}

func (t *grantTracker) emitManagement(tx *gorm.DB, kind port.SystemAlertTargetKind, targetID uint, recipient string,
	granted []authz.GrantEntry, auditResource string, auditID uint) error {
	corr, err := newCorrelationID()
	if err != nil {
		return err
	}
	if err := t.writeMarkedAudit(tx, auditResource, auditID, []string{authz.GrantMarkManagementGrant}, corr); err != nil {
		return err
	}
	if _, err := port.RaiseInTx(t.g.alerts, tx, port.SystemAlertEvent{
		Type: port.SystemAlertType(authz.AlertKeyManagementGranted), Actor: port.SystemAlertActor{UserID: t.op.UserID, Username: t.op.Username},
		ClientIP: t.op.ClientIP, CorrelationID: corr,
		Target: port.SystemAlertTarget{Kind: kind, ID: fmt.Sprint(targetID)},
		Params: authz.ManagementGrantParams(string(t.path), recipient, granted),
	}); err != nil {
		return fmt.Errorf("系統告警事件寫入失敗: %w", err)
	}
	return nil
}

// writeMarkedAudit 帶標記的服務審計列；與事件共用關聯編號。
func (t *grantTracker) writeMarkedAudit(tx *gorm.DB, resource string, id uint, marks []string, corr string) error {
	rid := id
	details := mustJSON(map[string]any{
		"event": "grant_change_graded", "path": string(t.path),
		"grant_marks": marks, "correlation_id": corr,
	})
	if err := port.WriteInTx(t.g.auditTx, tx, port.AuditEvent{
		Action: string(model.ActionUpdate), Resource: resource, ResourceID: &rid,
		Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: t.op.UserID, Username: t.op.Username},
		Request: gatewayapi.RequestMeta{ClientIP: t.op.ClientIP}, Details: details,
	}); err != nil {
		return fmt.Errorf("稽核留痕失敗: %w", err)
	}
	return nil
}
