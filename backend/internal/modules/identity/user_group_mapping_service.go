package identity

import (
	"encoding/json"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

const (
	UserGroupMappingEventCreate = "group_user_group_mapping_create"
	UserGroupMappingEventUpdate = "group_user_group_mapping_update"
	UserGroupMappingEventDelete = "group_user_group_mapping_delete"
)

type UserGroupMappingInput struct {
	MatchValue               string                `json:"match_value"`
	UserGroupID              uint                  `json:"user_group_id"`
	Enabled                  *bool                 `json:"enabled"`
	RiskAcknowledged         bool                  `json:"risk_acknowledged"`
	SourceConfigAcknowledged bool                  `json:"source_config_acknowledged"`
	Note                     string                `json:"note"`
	Actor                    GroupRoleMappingActor `json:"-"`
}

func userGroupMappingRow(tx *gorm.DB, kind string, sourceID, ruleID uint) (*model.GroupUserGroupMapping, error) {
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return nil, err
	}
	var row model.GroupUserGroupMapping
	if err := tx.Where("id=? AND "+column+"=?", ruleID, sourceID).First(&row).Error; err != nil {
		return nil, ErrMappingRuleNotFound
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
	if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{Action: string(action), Resource: string(model.ResourceUserGroup), ResourceID: &id, Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: actor.ID, Username: actor.Name}, Request: gatewayapi.RequestMeta{ClientIP: actor.IP}, Details: string(payload), ErrorMsg: event}); err != nil {
		return fmt.Errorf("使用者群組映射稽核失敗: %w", err)
	}
	return nil
}

func (s *IdentitySourceService) CreateUserGroupMapping(kind string, sourceID uint, in UserGroupMappingInput) (*model.GroupUserGroupMapping, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
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
		source, err := resolveSource(tx, kind, sourceID)
		if err != nil {
			return err
		}
		if err := validateMappingTargetGroup(tx, in.UserGroupID); err != nil {
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
			return err
		}
		if !enabled {
			if err := tx.Model(row).Update("enabled", false).Error; err != nil {
				return err
			}
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
	match, err := validateMatchValue(kind, in.MatchValue)
	if err != nil {
		return nil, err
	}
	var result *model.GroupUserGroupMapping
	err = withMappingSourceLock(s.db, kind, sourceID, func(tx *gorm.DB) error {
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
		var dictionary model.ExternalGroup
		if err := tx.First(&dictionary, old.ExternalGroupID).Error; err != nil {
			return err
		}
		enabled := old.Enabled
		if in.Enabled != nil {
			enabled = *in.Enabled
		}
		if dictionary.MatchValue != match || old.UserGroupID != in.UserGroupID {
			newGroupID, err := ensureExternalGroupWithNote(tx, kind, sourceID, match, in.Note)
			if err != nil {
				return err
			}
			next := &model.GroupUserGroupMapping{LDAPDirectoryID: old.LDAPDirectoryID, OIDCProviderID: old.OIDCProviderID, ExternalGroupID: newGroupID, UserGroupID: in.UserGroupID, Enabled: enabled, CreatedBy: in.Actor.ID}
			if err := tx.Create(next).Error; err != nil {
				return err
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
		return s.auditUserGroupMapping(tx, in.Actor, model.ActionUpdate, UserGroupMappingEventUpdate, kind, sourceID, match, in.RiskAcknowledged, in.SourceConfigAcknowledged, result)
	})
	return result, err
}

func (s *IdentitySourceService) DeleteUserGroupMapping(kind string, sourceID, ruleID uint, actor GroupRoleMappingActor) error {
	if s == nil || s.db == nil {
		return ErrMappingServiceUnavailable
	}
	return withMappingSourceLock(s.db, kind, sourceID, func(tx *gorm.DB) error {
		if _, err := resolveSource(tx, kind, sourceID); err != nil {
			return err
		}
		row, err := userGroupMappingRow(tx, kind, sourceID, ruleID)
		if err != nil {
			return err
		}
		if err := revokeMappingSupportsLocked(tx, s.auditTx, kind, sourceID, "group", ruleID); err != nil {
			return err
		}
		if err := tx.Delete(row).Error; err != nil {
			return err
		}
		var group model.ExternalGroup
		if err := tx.First(&group, row.ExternalGroupID).Error; err != nil {
			return err
		}
		return s.auditUserGroupMapping(tx, actor, model.ActionDelete, UserGroupMappingEventDelete, kind, sourceID, group.MatchValue, false, false, row)
	})
}
