package identity

import (
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// RevocationPreview counts effective permissions that would disappear if the
// selected rule, or all rules of a source, were revoked at this snapshot.
type RevocationPreview struct {
	AffectedUserCount        int64 `json:"affected_user_count"`
	EffectiveRoleLossCount   int64 `json:"effective_role_loss_count"`
	EffectiveMemberLossCount int64 `json:"effective_member_loss_count"`
}

type mappingPair struct{ userID, targetID uint }

func previewMappingRevocation(tx *gorm.DB, kind string, sourceID uint, ruleType string, ruleID uint) (RevocationPreview, error) {
	var out RevocationPreview
	channel := model.RoleMappingChannel(kind, sourceID)
	selectedRoles := map[mappingPair]bool{}
	selectedGroups := map[mappingPair]bool{}
	users := map[uint]bool{}
	if ruleType == "role" || ruleType == "source" {
		q := tx.Where("channel=?", channel)
		if ruleType == "role" {
			q = q.Where("rule_id=?", ruleID)
		}
		var rows []model.UserRoleMappingRuleSupport
		if err := q.Find(&rows).Error; err != nil {
			return out, err
		}
		for _, row := range rows {
			selectedRoles[mappingPair{row.UserID, row.RoleID}] = true
			users[row.UserID] = true
		}
	}
	if ruleType == "group" || ruleType == "source" {
		q := tx.Where("channel=?", channel)
		if ruleType == "group" {
			q = q.Where("rule_id=?", ruleID)
		}
		var rows []model.UserGroupMappingRuleSupport
		if err := q.Find(&rows).Error; err != nil {
			return out, err
		}
		for _, row := range rows {
			selectedGroups[mappingPair{row.UserID, row.UserGroupID}] = true
			users[row.UserID] = true
		}
	}
	out.AffectedUserCount = int64(len(users))
	if len(users) == 0 {
		return out, nil
	}
	ids := make([]uint, 0, len(users))
	for id := range users {
		ids = append(ids, id)
	}
	var roleSupports []model.UserRoleMappingRuleSupport
	var groupSupports []model.UserGroupMappingRuleSupport
	var roleFacts []model.UserRoleMapping
	var roles []model.UserRole
	var members []model.UserGroupMember
	for _, item := range []struct{ dest any }{{&roleSupports}, {&groupSupports}, {&roleFacts}, {&roles}, {&members}} {
		if err := tx.Where("user_id IN ?", ids).Find(item.dest).Error; err != nil {
			return out, err
		}
	}
	remainingRoles := map[mappingPair]bool{}
	remainingGroups := map[mappingPair]bool{}
	otherRoleFacts := map[mappingPair]bool{}
	for _, row := range roleSupports {
		removed := row.Channel == channel && (ruleType == "source" || ruleType == "role" && row.RuleID == ruleID)
		if !removed {
			remainingRoles[mappingPair{row.UserID, row.RoleID}] = true
		}
	}
	for _, row := range groupSupports {
		removed := row.Channel == channel && (ruleType == "source" || ruleType == "group" && row.RuleID == ruleID)
		if !removed {
			remainingGroups[mappingPair{row.UserID, row.UserGroupID}] = true
		}
	}
	for _, row := range roleFacts {
		if row.Channel != channel {
			otherRoleFacts[mappingPair{row.UserID, row.RoleID}] = true
		}
	}
	roleMapped := map[mappingPair]bool{}
	for _, row := range roles {
		roleMapped[mappingPair{row.UserID, row.RoleID}] = row.Source == model.RoleSourceMapped
	}
	groupMapped := map[mappingPair]bool{}
	for _, row := range members {
		groupMapped[mappingPair{row.UserID, row.UserGroupID}] = !row.Manual
	}
	for pair := range selectedRoles {
		if !remainingRoles[pair] && !otherRoleFacts[pair] && roleMapped[pair] {
			out.EffectiveRoleLossCount++
		}
	}
	for pair := range selectedGroups {
		if !remainingGroups[pair] && groupMapped[pair] {
			out.EffectiveMemberLossCount++
		}
	}
	return out, nil
}
