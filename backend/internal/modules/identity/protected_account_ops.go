package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 帳號身分操作的控制權與告警（置於服務邊界，各路由與日後的詳情頁共用）。
//
// 受控的四項操作：管理端設定密碼、管理端停用 MFA、綁定外部身分、解綁外部身分（含解綁並停用）。
//   - 目標帳號持有內建超管身分（直接、群組、映射任一來源）而操作者不是超管：
//     設定密碼、停 MFA、綁定一律拒絕；解綁不在受控清單，照現行規則。
//   - 目標帳號持有系統安全管理員身分而操作者不是超管：操作照常成功，同交易寫一筆服務審計
//     與一筆系統告警事件；任一寫入失敗整筆回滾。超管操作不產生事件。
//
// 事件內容只含操作者、目標帳號識別與動作類別，不含密碼、MFA 秘密或外部 subject。
//
// 停用、刪除（含解綁並停用）與啟用帳號另成一類：前兩者等於收回該帳號的全部角色、啟用等於讓
// 該帳號重新取得全部角色，與「取得或失去保護角色限超管」同一界線——目標帳號持有內建超管或
// 系統安全管理員身分（任一來源）而操作者不是超管時一律拒絕；目標不持保護角色時照現行規則，
// 不產生事件。

// AccountOperation 帳號身分操作類別；同時是告警參數 action 的值。
type AccountOperation string

const (
	AccountOpPasswordChange  AccountOperation = "password_change"
	AccountOpMFADisabled     AccountOperation = "mfa_disabled"
	AccountOpExternalBound   AccountOperation = "external_bound"
	AccountOpExternalUnbound AccountOperation = "external_unbound"
	// AccountOpDisable 停用帳號（含解綁並停用的停用部分）
	AccountOpDisable AccountOperation = "account_disabled"
	// AccountOpDelete 刪除帳號
	AccountOpDelete AccountOperation = "account_deleted"
	// AccountOpEnable 啟用帳號（重新啟用已停用的帳號）
	AccountOpEnable AccountOperation = "account_enabled"
)

// togglesAllRoles 停用、刪除與啟用：帳號的全部角色隨之失效或恢復，保護角色的持有者限超管處置。
func (a AccountOperation) togglesAllRoles() bool {
	return a == AccountOpDisable || a == AccountOpDelete || a == AccountOpEnable
}

// ProtectedAccountOps 帳號身分操作的關卡與留痕。無狀態，可共用。
// 兩個落地面都由組裝根注入；未注入時需要留痕的操作以錯誤失敗（fail-close），
// 不需要留痕的路徑（目標不是系統安全管理員）不受影響。
type ProtectedAccountOps struct {
	auditTx port.TxSink
	alerts  port.SystemAlertSink
}

// NewProtectedAccountOps 建立帳號身分操作關卡。
func NewProtectedAccountOps(auditTx port.TxSink, alerts port.SystemAlertSink) *ProtectedAccountOps {
	return &ProtectedAccountOps{auditTx: auditTx, alerts: alerts}
}

// accountOpsOrDefault nil 時回只有控制權、沒有落地面的關卡。
func accountOpsOrDefault(o *ProtectedAccountOps) *ProtectedAccountOps {
	if o == nil {
		return &ProtectedAccountOps{}
	}
	return o
}

// Gate 裁決一次帳號身分操作；notify 為 true 表示操作成功後 SHALL 呼叫 Record。
// 判定以 db 讀到的現值為準：呼叫端在寫入交易內呼叫即為交易內重讀。
func (o *ProtectedAccountOps) Gate(db *gorm.DB, op Operator, targetID uint, action AccountOperation) (notify bool, err error) {
	if op.UserID == 0 {
		return false, ErrProtectedAccountOperation
	}
	var operator model.User
	if err := db.First(&operator, op.UserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, ErrProtectedAccountOperation
		}
		return false, fmt.Errorf("查詢操作者失敗: %w", err)
	}
	opPrincipal, err := authz.ResolveUserOn(db, op.UserID, authz.TokenFacts{SubjectKind: operator.Kind})
	if err != nil {
		return false, err
	}
	if opPrincipal.IsSuperAdmin() {
		return false, nil
	}
	var target model.User
	if err := db.First(&target, targetID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, ErrUserNotFound
		}
		return false, fmt.Errorf("查詢目標帳號失敗: %w", err)
	}
	tp, err := authz.ResolveUserOn(db, targetID, authz.TokenFacts{SubjectKind: target.Kind})
	if err != nil {
		return false, err
	}
	notify, refused := classifyAccountOp(false, tp, action)
	if refused {
		return false, ErrProtectedAccountOperation
	}
	return notify, nil
}

// classifyAccountOp 保護身分這一層的純分類：操作者是否超管、目標的有效主體、操作類別。
// Gate 與唯讀投影共用，兩邊不會各自長出不同的口徑。
// refused 為真是只有超管能做；notify 為真是照常執行並通知安全人員。
func classifyAccountOp(operatorSuper bool, tp *authz.Principal, action AccountOperation) (notify, refused bool) {
	if operatorSuper {
		return false, false
	}
	if action.togglesAllRoles() {
		return false, tp.IsSuperAdmin() || tp.HasBuiltin(model.BuiltinSecurityAdmin)
	}
	if tp.IsSuperAdmin() && action != AccountOpExternalUnbound {
		return false, true
	}
	return tp.HasBuiltin(model.BuiltinSecurityAdmin), false
}

// Record 在操作交易內寫服務審計與系統告警事件。回錯即讓呼叫端回滾。
func (o *ProtectedAccountOps) Record(tx *gorm.DB, op Operator, targetID uint, action AccountOperation) error {
	var target model.User
	if err := tx.Select("id", "username").First(&target, targetID).Error; err != nil {
		return fmt.Errorf("查詢目標帳號失敗: %w", err)
	}
	corr, err := newCorrelationID()
	if err != nil {
		return err
	}
	tid := targetID
	details := mustJSON(map[string]any{
		"event": "security_admin_account_operated", "action": string(action),
		"target_user_id": targetID, "target_username": target.Username, "correlation_id": corr,
	})
	if err := port.WriteInTx(o.auditTx, tx, port.AuditEvent{
		Action: string(auditActionOf(action)), Resource: string(model.ResourceUser), ResourceID: &tid,
		Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: op.UserID, Username: op.Username},
		Request: gatewayapi.RequestMeta{ClientIP: op.ClientIP}, Details: details,
	}); err != nil {
		return fmt.Errorf("稽核留痕失敗: %w", err)
	}
	if _, err := port.RaiseInTx(o.alerts, tx, port.SystemAlertEvent{
		Type:          port.SystemAlertSecurityAdminAccountOperated,
		Actor:         port.SystemAlertActor{UserID: op.UserID, Username: op.Username},
		ClientIP:      op.ClientIP,
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetUser, ID: fmt.Sprint(targetID)},
		CorrelationID: corr,
		Params:        map[string]string{"action": string(action)},
	}); err != nil {
		return fmt.Errorf("系統告警事件寫入失敗: %w", err)
	}
	return nil
}

func auditActionOf(a AccountOperation) model.AuditAction {
	switch a {
	case AccountOpExternalBound:
		return model.ActionCreate
	case AccountOpExternalUnbound:
		return model.ActionDelete
	default:
		return model.ActionUpdate
	}
}

func newCorrelationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("產生關聯編號失敗: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// gateAndRecord 在交易內裁決並登記後續留痕：回傳的 record 在操作成功寫入之後呼叫（可為 nil）。
func (o *ProtectedAccountOps) gateAndRecord(tx *gorm.DB, op Operator, targetID uint, action AccountOperation) (func() error, error) {
	notify, err := o.Gate(tx, op, targetID, action)
	if err != nil {
		return nil, err
	}
	if !notify {
		return func() error { return nil }, nil
	}
	return func() error { return o.Record(tx, op, targetID, action) }, nil
}

// gateLifecycle 停用、刪除與啟用帳號的關卡：op 為 nil 是無操作者的系統路徑（閒置自動停用），不經關卡；
// 帶操作者時持保護角色的目標只有超管能處置。這三類操作不產生系統安全管理員操作事件。
//
// 呼叫端 SHALL 已持目標的使用者憑證鎖並在寫入交易內呼叫：判定讀的是鎖內的現行角色，而所有
// 會改變該使用者有效角色集的寫入都持同一把鎖，判定與寫入之間不會有角色變動插隊。
func (s *UserService) gateLifecycle(db *gorm.DB, op *Operator, targetID uint, action AccountOperation) error {
	if op == nil {
		return nil
	}
	_, err := accountOpsOrDefault(s.acctOps).Gate(db, *op, targetID, action)
	return err
}

// SetProtectedAccountOps 注入帳號身分操作關卡（組裝根）。
func (s *UserService) SetProtectedAccountOps(o *ProtectedAccountOps) { s.acctOps = o }

// SetProtectedAccountOps 注入帳號身分操作關卡（組裝根）。
func (s *AuthService) SetProtectedAccountOps(o *ProtectedAccountOps) { s.acctOps = o }

// ChangePasswordBy 帶操作者的管理端設定密碼：經帳號身分操作關卡。
func (s *UserService) ChangePasswordBy(op Operator, userID uint, newPassword string) error {
	// 受保護目標先於政策驗證拒絕，避免以密碼政策錯誤探測目標身分
	if _, err := accountOpsOrDefault(s.acctOps).Gate(s.db, op, userID, AccountOpPasswordChange); err != nil {
		return err
	}
	return s.setPasswordOp(userID, newPassword, s.forceChangeOnReset(), &op)
}

// AdminDisableMFABy 帶操作者的管理端停用 MFA：關卡與清除在同一交易。
func (s *AuthService) AdminDisableMFABy(op Operator, targetUserID uint) error {
	db := s.epochDB()
	ops := accountOpsOrDefault(s.acctOps)
	return db.Transaction(func(tx *gorm.DB) error {
		var user model.User
		if err := tx.First(&user, targetUserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrUserNotFound
			}
			return err
		}
		if user.Kind == model.KindAgent {
			return ErrAgentHumanOnly
		}
		record, err := ops.gateAndRecord(tx, op, targetUserID, AccountOpMFADisabled)
		if err != nil {
			return err
		}
		if err := tx.Model(&model.User{}).Where("id = ?", targetUserID).
			Updates(map[string]interface{}{"totp_secret_enc": "", "totp_enabled": false}).Error; err != nil {
			return err
		}
		return record()
	})
}
