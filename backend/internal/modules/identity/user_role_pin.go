package identity

import (
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 釘住：把外部群組賦予的角色固定為管理者指派。
//
// # 為什麼是獨立端點而不是替換端點的副作用
//
// 釘住是一個顯式動作。做成「把讀出來的兩份集合併起來回寫」的副作用，
// 等於讓一次例行的表單送出靜默把映射角色升格為管理者指派——升格之後那個角色
// 不再隨外部群組異動消失，而審計上它與管理者主動指派完全同形。
//
// # 為什麼要求目標角色目前有映射成分
//
// 釘住的語義是「把外部給的這一半固定下來」。目標角色沒有映射成分時該動作沒有
// 意義，靜默當成一般追加會讓「釘住」與「指派」在同一支端點上得到兩種語義。

// ErrRoleNotMapped 目標角色目前不是由外部群組映射賦予
var ErrRoleNotMapped = errors.New("此角色目前並非由群組映射賦予")

// MappingPinAuditEvent 釘住的審計事件碼（Details.event）。
const MappingPinAuditEvent = "role_mapping_pin"

// ErrPinAuditUnavailable 釘住需要交易內審計落地面而服務未注入（fail-close，不以空替身代寫）。
var ErrPinAuditUnavailable = errors.New("釘住審計落地面未接線")

// PinMappedRole 無操作者的釘住入口（供內部與既有測試）：不經指派關卡、不留服務層審計。
// 對外入口一律走 PinMappedRoleBy。
func (s *UserService) PinMappedRole(userID uint, roleName string) (*RoleSets, error) {
	return s.pinMappedRole(nil, userID, roleName)
}

// PinMappedRoleBy 把目標角色的來源自 mapped 升為 both（已是 both 即為 no-op）。
//
// 經共用指派關卡裁決（保護目標、指派能力、對象可寫），並在同一交易內寫 role_mapping_pin
// 審計；審計寫入失敗整筆回滾，來源維持 mapped。釘住不新建有效角色（該角色本來就在有效集裡），
// **不推進憑證世代**——來源欄是投影，投影變動不改變有效集。
func (s *UserService) PinMappedRoleBy(op Operator, userID uint, roleName string) (*RoleSets, error) {
	if s.pinAudit == nil {
		return nil, ErrPinAuditUnavailable
	}
	return s.pinMappedRole(&op, userID, roleName)
}

func (s *UserService) pinMappedRole(op *Operator, userID uint, roleName string) (*RoleSets, error) {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("查詢使用者失敗: %w", err)
	}
	if err := GuardAgentRoles(s.db, &user, []string{roleName}); err != nil {
		return nil, err
	}
	var role model.Role
	if err := s.assignmentGuard().catalog.Scope(s.db.Where("name = ?", roleName)).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("查詢角色失敗: %w", err)
	}

	var sets RoleSets
	// 判定與升格同交易、同鎖：鎖外預讀會讓一次併發的登入重算把來源改掉，
	// 而本次仍以舊來源決定放行與否
	if err := WithUserCredentialLock(s.db, userID, func(tx *gorm.DB) error {
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		if op != nil {
			if err := s.assignmentGuard().Check(tx, *op, AssignmentChange{
				Path: PathPin, TargetUserID: userID, NewRoleIDs: []uint{role.ID},
			}); err != nil {
				return err
			}
		}
		source, exists, err := model.UserRoleSourceOf(tx, userID, role.ID)
		if err != nil {
			return err
		}
		if !exists || source == model.RoleSourceManual {
			return ErrRoleNotMapped
		}
		if source == model.RoleSourceMapped {
			if _, err := AddManualRole(tx, userID, role.ID); err != nil {
				return err
			}
			if op != nil {
				if err := s.auditPin(tx, *op, userID, role.Name); err != nil {
					return err
				}
				if err := s.gradePin(tx, *op, userID, role.ID); err != nil {
					return err
				}
			}
		}
		sets, err = roleSetsOf(tx, userID)
		return err
	}); err != nil {
		if errors.Is(err, ErrRoleNotMapped) {
			return nil, err
		}
		var pe *PrincipalError
		if errors.As(err, &pe) {
			return nil, err
		}
		return nil, fmt.Errorf("釘住角色失敗: %w", err)
	}
	if user.Kind == model.KindAgent {
		s.grader.afterAgentRoleWrite(s.db, op, string(model.ResourceUser), userID, []uint{userID}, []uint{role.ID})
	}
	return &sets, nil
}

// auditPin 釘住的服務層同交易審計。細節只記角色名與前後來源，不帶外部 subject。
func (s *UserService) auditPin(tx *gorm.DB, op Operator, userID uint, roleName string) error {
	payload, err := json.Marshal(map[string]any{
		"event":         MappingPinAuditEvent,
		"user_id":       userID,
		"role":          roleName,
		"source_before": model.RoleSourceMapped,
		"source_after":  model.RoleSourceBoth,
	})
	if err != nil {
		return fmt.Errorf("序列化釘住稽核內容失敗: %w", err)
	}
	id := userID
	if err := port.WriteInTx(s.pinAudit, tx, port.AuditEvent{
		Action:     string(model.ActionUpdate),
		Resource:   string(model.ResourceUser),
		ResourceID: &id,
		Status:     string(model.StatusSuccess),
		Actor:      gatewayapi.Actor{UserID: op.UserID, Username: op.Username},
		Request:    gatewayapi.RequestMeta{ClientIP: op.ClientIP},
		Details:    string(payload),
	}); err != nil {
		return fmt.Errorf("寫入釘住稽核失敗: %w", err)
	}
	return nil
}

// gradePin 釘住的授權變更分級：釘住使角色不再隨外部群組移除而消失，視為授權增加。
// 對操作者本人為自我授權增加（高）；對他人且角色屬管理類為管理類發放（中）；其餘不告警。
// 與釘住本體、釘住審計同交易；grader 未注入時不分級（僅單元測試；組裝根啟動自檢拒絕）。
func (s *UserService) gradePin(tx *gorm.DB, op Operator, userID, roleID uint) error {
	if s.grader == nil {
		return nil
	}
	entry, found, err := authz.RoleGrantEntry(tx, roleID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	t := &grantTracker{g: s.grader, op: op, path: PathPin}
	if userID == op.UserID {
		after, err := authz.SummarizeGrants(tx, userID)
		if err != nil {
			return err
		}
		// 釘住前這個角色隨外部群組存在，釘住後固定下來：前摘要不含它，後摘要含它
		before := authz.GrantSummary{RuleIDs: after.RuleIDs}
		for _, e := range after.Entries {
			if e.RoleID == roleID && e.Via == authz.ViaDirect {
				continue
			}
			before.Entries = append(before.Entries, e)
		}
		cls := authz.ClassifyGrantChange(before, after, true)
		return t.emitUser(tx, userID, before, after, cls)
	}
	if !entry.Management {
		return nil
	}
	var name string
	if err := tx.Model(&model.User{}).Where("id = ?", userID).Pluck("username", &name).Error; err != nil {
		return fmt.Errorf("查詢主體名稱失敗: %w", err)
	}
	return t.emitManagement(tx, port.SystemAlertTargetUser, userID, name, []authz.GrantEntry{entry}, "user", userID)
}
