package identity

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

const (
	UserGroupMappingEventCreate = "group_user_group_mapping_create"
	UserGroupMappingEventUpdate = "group_user_group_mapping_update"
	UserGroupMappingEventDelete = "group_user_group_mapping_delete"
)

type UserGroupMappingInput struct {
	MatchValue               string `json:"match_value"`
	UserGroupID              uint   `json:"user_group_id"`
	Enabled                  *bool  `json:"enabled"`
	RiskAcknowledged         bool   `json:"risk_acknowledged"`
	SourceConfigAcknowledged bool   `json:"source_config_acknowledged"`
	Note                     string `json:"note"`
	// 範圍欄位只用來偵測並整筆拒絕（映射規則本身沒有範圍）
	MappingScopeFields
	Actor GroupRoleMappingActor `json:"-"`
}

// userGroupMappingDuplicate 同一來源是否已有群組值與目標群組皆相同的未刪除規則。
// exceptID 為修改中的那一條（建立時為 0）。群組值逐字相等，與群組字典的唯一索引同一個定義。
func userGroupMappingDuplicate(tx *gorm.DB, kind string, sourceID uint, matchValue string, userGroupID, exceptID uint) error {
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return err
	}
	q := tx.Model(&model.GroupUserGroupMapping{}).
		Where(column+" = ? AND user_group_id = ?", sourceID, userGroupID).
		Where("external_group_id IN (?)", tx.Model(&model.ExternalGroup{}).Select("id").
			Where(column+" = ? AND match_value = ?", sourceID, matchValue))
	if exceptID != 0 {
		q = q.Where("id <> ?", exceptID)
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return fmt.Errorf("讀取使用者群組映射規則失敗: %w", err)
	}
	if n > 0 {
		return ErrMappingRuleExists
	}
	return nil
}

func userGroupMappingRow(tx *gorm.DB, kind string, sourceID, ruleID uint) (*model.GroupUserGroupMapping, error) {
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return nil, err
	}
	var row model.GroupUserGroupMapping
	if err := tx.Where("id=? AND "+column+"=?", ruleID, sourceID).First(&row).Error; err != nil {
		// 只有「沒有這一列」才是不存在；查詢本身失敗時無法確認，原樣往上報，
		// 不讓呼叫端把暫時的讀取失敗當成規則已被移除
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrMappingRuleNotFound
		}
		return nil, err
	}
	return &row, nil
}

func validateMappingTargetGroup(tx *gorm.DB, id uint) error {
	var n int64
	if err := tx.Model(&model.UserGroup{}).Where("id=?", id).Count(&n).Error; err != nil {
		return err
	}
	if n != 1 {
		return ErrUserGroupNotFound
	}
	return nil
}

func (s *IdentitySourceService) auditUserGroupMapping(tx *gorm.DB, actor GroupRoleMappingActor, action model.AuditAction, event, kind string, sourceID uint, match string, acknowledged, sourceConfigAcknowledged bool, row *model.GroupUserGroupMapping) error {
	payload, err := json.Marshal(map[string]any{"event": event, "source_kind": kind, "source_id": sourceID, "match_value": match, "risk_acknowledged": acknowledged, "source_config_acknowledged": sourceConfigAcknowledged, "rule_id": row.ID, "external_group_id": row.ExternalGroupID, "user_group_id": row.UserGroupID, "enabled": row.Enabled})
	if err != nil {
		return err
	}
	id := row.ID
	if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{Action: string(action), Resource: string(model.ResourceUserGroup), ResourceID: &id, Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: actor.ID, Username: actor.Name}, Request: actor.requestMeta(), Details: string(payload), ErrorMsg: event}); err != nil {
		return fmt.Errorf("使用者群組映射稽核失敗: %w", err)
	}
	return nil
}

func (s *IdentitySourceService) CreateUserGroupMapping(kind string, sourceID uint, in UserGroupMappingInput) (*model.GroupUserGroupMapping, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	if in.MappingScopeFields.Present() {
		return nil, ErrMappingScopeFieldRejected
	}
	match, err := validateMatchValue(kind, in.MatchValue)
	if err != nil {
		return nil, err
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	var result *model.GroupUserGroupMapping
	err = withMappingSourceLock(s.db, kind, sourceID, func(tx *gorm.DB) error {
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		source, err := resolveSource(tx, kind, sourceID)
		if err != nil {
			return err
		}
		if err := validateMappingTargetGroup(tx, in.UserGroupID); err != nil {
			return err
		}
		newRoles, err := groupRoleIDs(tx, in.UserGroupID)
		if err != nil {
			return err
		}
		if err := s.guardMappingTargets(tx, in.Actor, kind, sourceID, nil, newRoles); err != nil {
			return err
		}
		usage, err := usageOfUserGroup(tx, in.UserGroupID)
		if err != nil {
			return err
		}
		if usage.HasAny() && !in.RiskAcknowledged {
			return &UserGroupMappingUsageAckError{usage}
		}
		if !source.attrSet && !in.SourceConfigAcknowledged {
			return &MappingAckRequiredError{Warnings: []string{mappingWarningSourceAttrUnset}}
		}
		// 重複判定排在守衛與兩種確認之後：無權寫入的操作者不因組合是否存在而得到不同回應
		if err := userGroupMappingDuplicate(tx, kind, sourceID, match, in.UserGroupID, 0); err != nil {
			return err
		}
		tracker, err := s.beginUserGroupMappingWrite(tx, in.Actor, kind, sourceID, mappingWrite{
			OldMatch: match, NewMatch: match, NewEnabled: enabled, Created: true,
		}, 0, in.UserGroupID)
		if err != nil {
			return err
		}
		groupID, err := ensureExternalGroupWithNote(tx, kind, sourceID, match, in.Note)
		if err != nil {
			return err
		}
		row := &model.GroupUserGroupMapping{ExternalGroupID: groupID, UserGroupID: in.UserGroupID, Enabled: enabled, CreatedBy: in.Actor.ID}
		if kind == model.RoleMappingChannelKindDirectory {
			row.LDAPDirectoryID = &sourceID
		} else {
			row.OIDCProviderID = &sourceID
		}
		if err := tx.Create(row).Error; err != nil {
			return mappingInsertError(err)
		}
		if !enabled {
			if err := tx.Model(row).Update("enabled", false).Error; err != nil {
				return err
			}
		}
		// 權限版本：新規則於下一次登入重算即授出群組成員資格，與建列同交易
		if err := authz.AdvanceVersion(tx); err != nil {
			return err
		}
		if err := tracker.finish(tx, row.ID); err != nil {
			return err
		}
		if err := s.auditUserGroupMapping(tx, in.Actor, model.ActionCreate, UserGroupMappingEventCreate, kind, sourceID, match, in.RiskAcknowledged, in.SourceConfigAcknowledged, row); err != nil {
			return err
		}
		result = row
		return nil
	})
	return result, err
}

func (s *IdentitySourceService) UpdateUserGroupMapping(kind string, sourceID, ruleID uint, in UserGroupMappingInput) (*model.GroupUserGroupMapping, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	if in.MappingScopeFields.Present() {
		return nil, ErrMappingScopeFieldRejected
	}
	match, err := validateMatchValue(kind, in.MatchValue)
	if err != nil {
		return nil, err
	}
	var result *model.GroupUserGroupMapping
	err = withMappingSourceLock(s.db, kind, sourceID, func(tx *gorm.DB) error {
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		source, err := resolveSource(tx, kind, sourceID)
		if err != nil {
			return err
		}
		old, err := userGroupMappingRow(tx, kind, sourceID, ruleID)
		if err != nil {
			return err
		}
		if err := validateMappingTargetGroup(tx, in.UserGroupID); err != nil {
			return err
		}
		var dictionary model.ExternalGroup
		if err := tx.First(&dictionary, old.ExternalGroupID).Error; err != nil {
			return err
		}
		enabled := old.Enabled
		if in.Enabled != nil {
			enabled = *in.Enabled
		}
		wasEnabled := old.Enabled
		identityChanged := dictionary.MatchValue != match || old.UserGroupID != in.UserGroupID
		// 沒有任何實際變動的存檔不是授權變更，不做守衛裁決
		if identityChanged || enabled != wasEnabled {
			oldRoles, err := groupRoleIDs(tx, old.UserGroupID)
			if err != nil {
				return err
			}
			newRoles, err := groupRoleIDs(tx, in.UserGroupID)
			if err != nil {
				return err
			}
			if err := s.guardMappingTargets(tx, in.Actor, kind, sourceID, oldRoles, newRoles); err != nil {
				return err
			}
		}
		if !source.attrSet && !in.SourceConfigAcknowledged {
			return &MappingAckRequiredError{Warnings: []string{mappingWarningSourceAttrUnset}}
		}
		if old.UserGroupID != in.UserGroupID {
			usage, err := usageOfUserGroup(tx, in.UserGroupID)
			if err != nil {
				return err
			}
			if usage.HasAny() && !in.RiskAcknowledged {
				return &UserGroupMappingUsageAckError{usage}
			}
		}
		if identityChanged {
			if err := userGroupMappingDuplicate(tx, kind, sourceID, match, in.UserGroupID, old.ID); err != nil {
				return err
			}
		}
		var tracker *mappingTracker
		if identityChanged || enabled != wasEnabled {
			tracker, err = s.beginUserGroupMappingWrite(tx, in.Actor, kind, sourceID, mappingWrite{
				OldMatch: dictionary.MatchValue, NewMatch: match, OldEnabled: wasEnabled, NewEnabled: enabled,
			}, old.UserGroupID, in.UserGroupID)
			if err != nil {
				return err
			}
		}
		if identityChanged {
			newGroupID, err := ensureExternalGroupWithNote(tx, kind, sourceID, match, in.Note)
			if err != nil {
				return err
			}
			next := &model.GroupUserGroupMapping{LDAPDirectoryID: old.LDAPDirectoryID, OIDCProviderID: old.OIDCProviderID, ExternalGroupID: newGroupID, UserGroupID: in.UserGroupID, Enabled: enabled, CreatedBy: in.Actor.ID}
			if err := tx.Create(next).Error; err != nil {
				return mappingInsertError(err)
			}
			if h := loadLockOrderHook(); h != nil {
				h("mapping_group_after_rule_insert", tx, in.Actor.ID)
			}
			if !enabled {
				if err := tx.Model(next).Update("enabled", false).Error; err != nil {
					return err
				}
			}
			if err := revokeMappingSupportsLocked(tx, s.auditTx, kind, sourceID, "group", old.ID); err != nil {
				return err
			}
			if err := tx.Delete(old).Error; err != nil {
				return err
			}
			result = next
		} else {
			if old.Enabled && !enabled {
				if err := revokeMappingSupportsLocked(tx, s.auditTx, kind, sourceID, "group", old.ID); err != nil {
					return err
				}
			}
			if err := tx.Model(old).Update("enabled", enabled).Error; err != nil {
				return err
			}
			old.Enabled = enabled
			result = old
		}
		// 權限版本：比對值、目標群組或啟用旗標有實際變動才推進（與寫入同交易）
		if identityChanged || enabled != wasEnabled {
			if err := authz.AdvanceVersion(tx); err != nil {
				return err
			}
			if err := tracker.finish(tx, result.ID); err != nil {
				return err
			}
		}
		return s.auditUserGroupMapping(tx, in.Actor, model.ActionUpdate, UserGroupMappingEventUpdate, kind, sourceID, match, in.RiskAcknowledged, in.SourceConfigAcknowledged, result)
	})
	return result, err
}

func (s *IdentitySourceService) DeleteUserGroupMapping(kind string, sourceID, ruleID uint, actor GroupRoleMappingActor) error {
	if s == nil || s.db == nil {
		return ErrMappingServiceUnavailable
	}
	return withMappingSourceLock(s.db, kind, sourceID, func(tx *gorm.DB) error {
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		if _, err := resolveSource(tx, kind, sourceID); err != nil {
			return err
		}
		row, err := userGroupMappingRow(tx, kind, sourceID, ruleID)
		if err != nil {
			return err
		}
		oldRoles, err := groupRoleIDs(tx, row.UserGroupID)
		if err != nil {
			return err
		}
		if err := s.guardMappingTargets(tx, actor, kind, sourceID, oldRoles, nil); err != nil {
			return err
		}
		var oldGroup model.ExternalGroup
		if err := tx.First(&oldGroup, row.ExternalGroupID).Error; err != nil {
			return err
		}
		tracker, err := s.beginUserGroupMappingWrite(tx, actor, kind, sourceID, mappingWrite{
			OldMatch: oldGroup.MatchValue, OldEnabled: row.Enabled, Deleted: true,
		}, row.UserGroupID, 0)
		if err != nil {
			return err
		}
		if err := revokeMappingSupportsLocked(tx, s.auditTx, kind, sourceID, "group", ruleID); err != nil {
			return err
		}
		if err := tx.Delete(row).Error; err != nil {
			return err
		}
		// 權限版本：與軟刪除同交易
		if err := authz.AdvanceVersion(tx); err != nil {
			return err
		}
		if err := tracker.finish(tx, ruleID); err != nil {
			return err
		}
		var group model.ExternalGroup
		if err := tx.First(&group, row.ExternalGroupID).Error; err != nil {
			return err
		}
		return s.auditUserGroupMapping(tx, actor, model.ActionDelete, UserGroupMappingEventDelete, kind, sourceID, group.MatchValue, false, false, row)
	})
}
