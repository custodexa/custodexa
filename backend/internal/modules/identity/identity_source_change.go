package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 身分來源設定變更（LDAP 目錄與 OIDC 身分提供者的建立、修改、啟停、刪除）的告警。
//
// 這是對來源設定的留痕，不是限制：修改來源設定不加權限門檻，但每一筆變更在同一個交易內
// 寫審計並產生系統告警事件，內容列出變更的欄位與「此來源目前有多少位超級管理者」。
// 事件寫入失敗時整筆變更回滾。秘密（bind 密碼、client secret）只標示「已變更」，
// 不帶值也不帶摘要。

// OIDCProviderSettingsAuditEvent OIDC 身分提供者設定變更的審計事件碼（Details.event）。
const OIDCProviderSettingsAuditEvent = "oidc_provider_settings_change"

// SourceChangeKind 事件參數 source_kind 的值。
const (
	sourceKindLDAP = "ldap"
	sourceKindOIDC = "oidc"
)

// sourceChange 一次來源設定變更的描述。
type sourceChange struct {
	Kind     string   // ldap | oidc
	SourceID uint     // 來源識別
	Fields   []string // 變更的欄位代碼（小寫英數與底線），建立與刪除用 created／deleted
	// SecretChanged 為 nil 表示此來源種類無秘密欄位；否則表示 bind 密碼或 client secret 是否被設定或清除
	SecretChanged *bool
}

// countSuperAdminsViaSource 可經此來源登入、且有效角色含超級管理者的帳號數。
//
// 有效角色含直接指派與經使用者群組取得（映射帶來的也算在內，兩者都落在同樣的表）。
// LDAP 以帳號的目錄帳號旗標判定；OIDC 以仍有效的外部身分綁定判定。
func countSuperAdminsViaSource(tx *gorm.DB, kind string, sourceID uint) (int64, error) {
	viaGroup, err := authz.UserIDsInGroupsWithBuiltin(tx, model.BuiltinSuperAdmin)
	if err != nil {
		return 0, err
	}
	if len(viaGroup) == 0 {
		viaGroup = []uint{0} // 空集合的 IN 子句在各方言行為不一，放不可能命中的編號
	}
	var n int64
	switch kind {
	case sourceKindLDAP:
		err = tx.Raw(`SELECT COUNT(*) FROM users u WHERE u.deleted_at IS NULL AND u.is_ldap = ? AND (
		EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
			WHERE ur.user_id = u.id AND r.deleted_at IS NULL AND r.builtin_key = ?)
		OR u.id IN ?)`, true, model.BuiltinSuperAdmin, viaGroup).Scan(&n).Error
	case sourceKindOIDC:
		err = tx.Raw(`SELECT COUNT(*) FROM users u WHERE u.deleted_at IS NULL AND
		EXISTS (SELECT 1 FROM user_external_identities e WHERE e.user_id = u.id AND e.provider_id = ? AND e.deleted_at IS NULL) AND (
		EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
			WHERE ur.user_id = u.id AND r.deleted_at IS NULL AND r.builtin_key = ?)
		OR u.id IN ?)`, sourceID, model.BuiltinSuperAdmin, viaGroup).Scan(&n).Error
	default:
		return 0, fmt.Errorf("未知的身分來源種類 %q", kind)
	}
	if err != nil {
		return 0, fmt.Errorf("計算來源的超級管理者人數失敗: %w", err)
	}
	return n, nil
}

// SystemSourceActorName 內部與系統呼叫（沒有人類操作者）寫入身分來源設定變更時，
// 審計與事件記錄的操作者名稱。留痕不因沒有人類操作者而省略，操作者明確記為系統。
const SystemSourceActorName = "system"

// sourceActorOrSystem 零值操作者（沒有任何身分資訊）一律換成明確的系統操作者；
// 帶任何身分資訊的操作者原樣保留。
func sourceActorOrSystem(a GroupRoleMappingActor) GroupRoleMappingActor {
	if a.ID == 0 && a.Name == "" {
		a.Name = SystemSourceActorName
	}
	return a
}

// raiseIdentitySourceChanged 在來源變更的交易內產生 identity_source_changed 事件。
//
// 落地面缺注入時回錯（port.ErrSystemAlertSinkMissing），整筆設定變更回滾；
// 沒有欄位變動的存檔不產生事件。呼叫端 SHALL 讓錯誤逸出交易閉包。
func raiseIdentitySourceChanged(tx *gorm.DB, sink port.SystemAlertSink, actor GroupRoleMappingActor,
	ch sourceChange, correlationID string) error {
	if len(ch.Fields) == 0 {
		return nil
	}
	actor = sourceActorOrSystem(actor)
	count, err := countSuperAdminsViaSource(tx, ch.Kind, ch.SourceID)
	if err != nil {
		return err
	}
	params := map[string]string{
		"source_kind":       ch.Kind,
		"changed_fields":    strings.Join(ch.Fields, ","),
		"super_admin_count": strconv.FormatInt(count, 10),
	}
	if ch.SecretChanged != nil {
		params["bind_password_changed"] = strconv.FormatBool(*ch.SecretChanged)
	}
	if _, err := port.RaiseInTx(sink, tx, port.SystemAlertEvent{
		Type:          port.SystemAlertIdentitySourceChanged,
		Actor:         port.SystemAlertActor{UserID: actor.ID, Username: actor.Name},
		ClientIP:      actor.IP,
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetIdentitySource, ID: ch.Kind + ":" + strconv.FormatUint(uint64(ch.SourceID), 10)},
		CorrelationID: correlationID,
		Params:        params,
	}); err != nil {
		return fmt.Errorf("產生身分來源變更告警失敗: %w", err)
	}
	return nil
}

// changedFields 比對前後欄位值，回傳有變動者的欄位代碼（保持輸入順序）。
func changedFields(pairs ...fieldPair) []string {
	var out []string
	for _, p := range pairs {
		if p.Before != p.After {
			out = append(out, p.Name)
		}
	}
	return out
}

type fieldPair struct {
	Name          string
	Before, After string
}

func boolStr(b bool) string { return strconv.FormatBool(b) }

// newSourceCorrelationID 審計列與告警共用的關聯識別（隨機、不含任何輸入內容）。
//
// 隨機來源失敗時回錯，由呼叫端讓整筆設定變更失敗：退回固定值會讓不同變更共用同一個
// 關聯識別，審計列與告警就無法互相回查。
func newSourceCorrelationID() (string, error) {
	return sourceCorrelationIDFrom(rand.Read)
}

// sourceCorrelationIDFrom 以給定的隨機來源產生關聯識別（拆出以便測試失敗路徑）。
func sourceCorrelationIDFrom(read func([]byte) (int, error)) (string, error) {
	b := make([]byte, 12)
	if _, err := read(b); err != nil {
		return "", fmt.Errorf("產生身分來源變更關聯識別失敗: %w", err)
	}
	return "src-" + hex.EncodeToString(b), nil
}

// sinkMissing 介面值是否沒有可用實作（含 typed-nil）。
func sinkMissing(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return rv.IsNil()
	}
	return false
}

// ErrSourceChangeSinksMissing 身分來源設定變更的留痕落地面缺注入。
var ErrSourceChangeSinksMissing = errors.New("身分來源設定變更的稽核或告警落地面未注入")

// SourceChangeSinksReady 組裝根啟動自檢：LDAP 目錄服務的稽核與告警落地面都已注入。
func (s *LDAPDirectoryService) SourceChangeSinksReady() error {
	if sinkMissing(s.auditTx) || sinkMissing(s.alerts) {
		return fmt.Errorf("LDAP 目錄服務: %w", ErrSourceChangeSinksMissing)
	}
	return nil
}

// SourceChangeSinksReady 組裝根啟動自檢：OIDC 身分提供者服務的稽核與告警落地面都已注入。
func (s *OIDCProviderService) SourceChangeSinksReady() error {
	if sinkMissing(s.mappingAuditTx) || sinkMissing(s.alerts) {
		return fmt.Errorf("OIDC 身分提供者服務: %w", ErrSourceChangeSinksMissing)
	}
	return nil
}
