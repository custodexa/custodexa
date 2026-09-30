package identity

import (
	"fmt"
	"sort"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"gorm.io/gorm"
)

const (
	MappingRuleRevokedEvent   = "group_mapping_rule_revoked"
	MappingSourceRevokedEvent = "group_mapping_source_revoked"
)

// revokeMappingSupportsLocked runs within a transaction that already holds the
// source lock. It scans every affected user and keeps the entire batch atomic.
// ruleType is "role", "group", or "source" (both tables for a channel).
func revokeMappingSupportsLocked(tx *gorm.DB, auditSink port.TxSink, kind string, sourceID uint, ruleType string, ruleID uint) error {
	channel := model.RoleMappingChannel(kind, sourceID)
	users := map[uint]bool{}
	if ruleType == "role" || ruleType == "source" {
		q := tx.Table("user_role_mapping_rule_supports").Where("channel=?", channel)
		if ruleType == "role" {
			q = q.Where("rule_id=?", ruleID)
		}
		var ids []uint
		if err := q.Distinct().Pluck("user_id", &ids).Error; err != nil {
			return err
		}
		for _, id := range ids {
			users[id] = true
		}
	}
	if ruleType == "group" || ruleType == "source" {
		q := tx.Table("user_group_mapping_rule_supports").Where("channel=?", channel)
		if ruleType == "group" {
			q = q.Where("rule_id=?", ruleID)
		}
		var ids []uint
		if err := q.Distinct().Pluck("user_id", &ids).Error; err != nil {
			return err
		}
		for _, id := range ids {
			users[id] = true
		}
	}
	ids := make([]uint, 0, len(users))
	for id := range users {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	ruleValues := make(map[string]string)
	for _, userID := range ids {
		if err := withUserCredentialLockTx(tx, userID, func(locked *gorm.DB) error {
			var supportChanges []mappingSupportChange
			if ruleType == "role" || ruleType == "source" {
				q := locked.Where("user_id=? AND channel=?", userID, channel)
				if ruleType == "role" {
					q = q.Where("rule_id=?", ruleID)
				}
				var rows []model.UserRoleMappingRuleSupport
				if err := q.Find(&rows).Error; err != nil {
					return err
				}
				for _, row := range rows {
					change, err := cachedSupportChange(locked, ruleValues, "role", mappingSupport{TargetID: row.RoleID, RuleID: row.RuleID}, "remove")
					if err != nil {
						return err
					}
					supportChanges = append(supportChanges, change)
				}
			}
			if ruleType == "group" || ruleType == "source" {
				q := locked.Where("user_id=? AND channel=?", userID, channel)
				if ruleType == "group" {
					q = q.Where("rule_id=?", ruleID)
				}
				var rows []model.UserGroupMappingRuleSupport
				if err := q.Find(&rows).Error; err != nil {
					return err
				}
				for _, row := range rows {
					change, err := cachedSupportChange(locked, ruleValues, "user_group", mappingSupport{TargetID: row.UserGroupID, RuleID: row.RuleID}, "remove")
					if err != nil {
						return err
					}
					supportChanges = append(supportChanges, change)
				}
			}
			sortSupportChanges(supportChanges)
			var groupIDs []uint
			gq := locked.Table("user_group_mapping_rule_supports").Where("user_id=? AND channel=?", userID, channel)
			if ruleType == "group" {
				gq = gq.Where("rule_id=?", ruleID)
			}
			if ruleType == "group" || ruleType == "source" {
				if err := gq.Distinct().Pluck("user_group_id", &groupIDs).Error; err != nil {
					return err
				}
			}
			if ruleType == "role" {
				if err := locked.Exec("DELETE FROM user_role_mapping_rule_supports WHERE user_id=? AND channel=? AND rule_id=?", userID, channel, ruleID).Error; err != nil {
					return err
				}
			}
			if ruleType == "group" {
				if err := locked.Exec("DELETE FROM user_group_mapping_rule_supports WHERE user_id=? AND channel=? AND rule_id=?", userID, channel, ruleID).Error; err != nil {
					return err
				}
			}
			if ruleType == "source" {
				if err := locked.Exec("DELETE FROM user_role_mapping_rule_supports WHERE user_id=? AND channel=?", userID, channel).Error; err != nil {
					return err
				}
				if err := locked.Exec("DELETE FROM user_group_mapping_rule_supports WHERE user_id=? AND channel=?", userID, channel).Error; err != nil {
					return err
				}
			}
			var keepRoles []uint
			if err := locked.Table("user_role_mapping_rule_supports").Where("user_id=? AND channel=?", userID, channel).Distinct().Pluck("role_id", &keepRoles).Error; err != nil {
				return err
			}
			removedRoles, err := RevokeMappedRolesForChannel(locked, userID, channel, keepRoles)
			if err != nil {
				return err
			}
			removedGroups, err := reconcileGroupMembers(locked, userID, groupIDs)
			if err != nil {
				return err
			}
			bumped := len(removedRoles) > 0 || len(removedGroups) > 0
			if bumped {
				if err := BumpCredentialEpoch(locked, userID, "group_mapping_revoked"); err != nil {
					return err
				}
				if _, err := RevokeAllRefreshTokens(locked, userID, model.RefreshRevokeCredentialEpoch); err != nil {
					return err
				}
			}
			var user model.User
			if err := locked.First(&user, userID).Error; err != nil {
				return err
			}
			code := MappingRuleRevokedEvent
			if ruleType == "source" {
				code = MappingSourceRevokedEvent
			}
			if err := writeRoleMappingAudit(locked, auditSink, &user, GroupObservation{Kind: kind, SourceID: sourceID}, code, map[string]any{
				"channel": channel, "rule_type": ruleType, "rule_id": ruleID, "roles_removed": removedRoles, "groups_removed": removedGroups, "epoch_bumped": bumped,
				"support_changes": supportChanges,
			}); err != nil {
				return fmt.Errorf("撤權稽核失敗: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func countUserGroupMappings(tx *gorm.DB, kind string, sourceID uint) (int64, error) {
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return 0, err
	}
	var n int64
	if err := tx.Model(&model.GroupUserGroupMapping{}).Where(column+"=?", sourceID).Count(&n).Error; err != nil {
		return 0, err
	}
	return n, nil
}

// Historical soft-deleted rules must be removed before dictionary entries and
// the source, because each reference is protected by a real foreign key.
func cleanupMappingHistoryForSourceLocked(tx *gorm.DB, sink port.TxSink, kind string, sourceID uint) error {
	roles, _, err := CountMappings(tx, kind, sourceID)
	if err != nil {
		return err
	}
	groups, err := countUserGroupMappings(tx, kind, sourceID)
	if err != nil {
		return err
	}
	if roles+groups > 0 {
		return ErrMappingSourceHasRules
	}
	if err := revokeMappingSupportsLocked(tx, sink, kind, sourceID, "source", 0); err != nil {
		return err
	}
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return err
	}
	if err := tx.Unscoped().Where(column+"=?", sourceID).Delete(&model.GroupRoleMapping{}).Error; err != nil {
		return err
	}
	if err := tx.Unscoped().Where(column+"=?", sourceID).Delete(&model.GroupUserGroupMapping{}).Error; err != nil {
		return err
	}
	if err := tx.Where(column+"=?", sourceID).Delete(&model.ExternalGroup{}).Error; err != nil {
		return err
	}
	return nil
}
