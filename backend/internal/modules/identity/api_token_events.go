package identity

import (
	"fmt"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// apiTokenEventRecorder 建立與撤銷 API token 的交易內留痕：稽核列經交易內寫入面（不受稽核開關控制），
// 授權角色含超級管理者或系統安全管理員時同交易產生系統告警並排入通知佇列。任一寫入失敗即回錯，
// 呼叫端整筆回滾。稽核細節與告警參數只含名稱、角色、到期與原因，不含明文或雜湊。
type apiTokenEventRecorder struct {
	auditTx port.TxSink
	alerts  port.SystemAlertSink
}

// NewAPITokenEventRecorder 組出建立與撤銷的留痕落地面。兩個落地面都必須注入：
// 缺任一個時寫入回錯（交易回滾），不靜默略過。
func NewAPITokenEventRecorder(auditTx port.TxSink, alerts port.SystemAlertSink) APITokenEventRecorder {
	return apiTokenEventRecorder{auditTx: auditTx, alerts: alerts}
}

func apiTokenRoleRefsJSON(roles []APITokenRoleRef) []map[string]any {
	out := make([]map[string]any, 0, len(roles))
	for _, r := range roles {
		out = append(out, map[string]any{"role_id": r.RoleID, "name": r.Name, "builtin_key": r.BuiltinKey})
	}
	return out
}

// apiTokenRoleLabels 角色的呈現值：內建角色用內建鍵，自訂角色用角色名稱。
func apiTokenRoleLabels(roles []APITokenRoleRef) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if r.BuiltinKey != "" {
			out = append(out, r.BuiltinKey)
		} else {
			out = append(out, r.Name)
		}
	}
	return out
}

func apiTokenExpiryValue(at *time.Time) any {
	if at == nil {
		return nil
	}
	return at.UTC().Format(time.RFC3339)
}

func (r apiTokenEventRecorder) APITokenCreated(tx *gorm.DB, ev APITokenCreatedEvent) error {
	tokenID := ev.TokenID
	corr := ""
	if len(ev.PrivilegedKeys) > 0 {
		id, err := newCorrelationID()
		if err != nil {
			return err
		}
		corr = id
	}
	detail := map[string]any{
		"token_id": ev.TokenID, "token_name": ev.Name,
		"owner_user_id": ev.OwnerID, "owner_username": ev.OwnerUsername,
		"granted_roles": apiTokenRoleRefsJSON(ev.GrantedRoles),
		"expires_at":    apiTokenExpiryValue(ev.ExpiresAt), "never_expires": ev.ExpiresAt == nil,
		"privileged": len(ev.PrivilegedKeys) > 0,
	}
	if corr != "" {
		detail["correlation_id"] = corr
	}
	if err := port.WriteInTx(r.auditTx, tx, port.AuditEvent{
		Action: string(model.ActionCreate), Resource: string(model.ResourceAPIToken), ResourceID: &tokenID,
		Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: ev.Operator.UserID, Username: ev.Operator.Username},
		Request: ev.Operator.RequestMeta(), Details: mustJSON(detail),
	}); err != nil {
		return fmt.Errorf("稽核留痕失敗: %w", err)
	}
	if corr == "" {
		return nil
	}
	params := map[string]string{
		"privileged_roles": strings.Join(ev.PrivilegedKeys, ","),
		"token_name":       ev.Name,
		"granted_roles":    strings.Join(apiTokenRoleLabels(ev.GrantedRoles), ","),
	}
	// 到期一律明寫：expiry 為 at（另帶 expires_at）或 never，收件人分得出永不到期與資料缺漏
	if ev.ExpiresAt != nil {
		params["expiry"] = apiTokenAlertExpiryAt
		params["expires_at"] = ev.ExpiresAt.UTC().Format(time.RFC3339)
	} else {
		params["expiry"] = apiTokenAlertExpiryNever
	}
	if _, err := port.RaiseInTx(r.alerts, tx, port.SystemAlertEvent{
		Type:          port.SystemAlertPrivilegedAPITokenCreated,
		Actor:         port.SystemAlertActor{UserID: ev.Operator.UserID, Username: ev.Operator.Username},
		ClientIP:      ev.Operator.ClientIP,
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetUser, ID: fmt.Sprint(ev.OwnerID)},
		CorrelationID: corr,
		Params:        params,
	}); err != nil {
		return fmt.Errorf("系統告警事件寫入失敗: %w", err)
	}
	return nil
}

// 高權限 token 告警的到期參數值。
const (
	apiTokenAlertExpiryAt    = "at"
	apiTokenAlertExpiryNever = "never"
)

func (r apiTokenEventRecorder) APITokenRevoked(tx *gorm.DB, ev APITokenRevokedEvent) error {
	tokenID := ev.TokenID
	detail := map[string]any{
		"token_id": ev.TokenID, "token_name": ev.Name,
		"owner_user_id": ev.OwnerID, "owner_username": ev.OwnerUsername,
		"revoke_note": ev.Note, "revoked_at": ev.RevokedAt.UTC().Format(time.RFC3339),
	}
	if err := port.WriteInTx(r.auditTx, tx, port.AuditEvent{
		Action: string(model.ActionAPITokenRevoked), Resource: string(model.ResourceAPIToken), ResourceID: &tokenID,
		Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: ev.Operator.UserID, Username: ev.Operator.Username},
		Request: ev.Operator.RequestMeta(), Details: mustJSON(detail),
	}); err != nil {
		return fmt.Errorf("稽核留痕失敗: %w", err)
	}
	return nil
}
