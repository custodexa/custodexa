package identity

import (
	"fmt"
	"sort"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// A support identifies the precise rule that made an aggregate mapping true.
type mappingSupport struct {
	TargetID uint
	RuleID   uint
}

type mappingSupportChange struct {
	RuleID        uint   `json:"rule_id"`
	ExternalGroup string `json:"external_group"`
	TargetType    string `json:"target_type"`
	TargetID      uint   `json:"target_id"`
	Direction     string `json:"direction"`
}

func supportChange(tx *gorm.DB, targetType string, support mappingSupport, direction string) (mappingSupportChange, error) {
	change := mappingSupportChange{RuleID: support.RuleID, TargetType: targetType, TargetID: support.TargetID, Direction: direction}
	if targetType == "role" {
		var rule model.GroupRoleMapping
		if err := tx.Unscoped().First(&rule, support.RuleID).Error; err != nil {
			return change, err
		}
		change.ExternalGroup = rule.MatchValue
	} else {
		var rule model.GroupUserGroupMapping
		if err := tx.Unscoped().First(&rule, support.RuleID).Error; err != nil {
			return change, err
		}
		var group model.ExternalGroup
		if err := tx.First(&group, rule.ExternalGroupID).Error; err != nil {
			return change, err
		}
		change.ExternalGroup = group.MatchValue
	}
	return change, nil
}

// A bulk revocation can affect many users through the same rule. Resolve the
// rule's original group value once per transaction, not once per user.
func cachedSupportChange(tx *gorm.DB, values map[string]string, targetType string, support mappingSupport, direction string) (mappingSupportChange, error) {
	key := fmt.Sprintf("%s:%d", targetType, support.RuleID)
	if value, ok := values[key]; ok {
		return mappingSupportChange{RuleID: support.RuleID, ExternalGroup: value, TargetType: targetType, TargetID: support.TargetID, Direction: direction}, nil
	}
	change, err := supportChange(tx, targetType, support, direction)
	if err == nil {
		values[key] = change.ExternalGroup
	}
	return change, err
}

func sortSupportChanges(changes []mappingSupportChange) {
	sort.Slice(changes, func(i, j int) bool {
		a, b := changes[i], changes[j]
		if a.TargetType != b.TargetType {
			return a.TargetType < b.TargetType
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.TargetID != b.TargetID {
			return a.TargetID < b.TargetID
		}
		return a.Direction < b.Direction
	})
}

func diffMappingSupports(current, desired []mappingSupport) (remove []mappingSupport, affected []uint) {
	want := map[mappingSupport]bool{}
	targets := map[uint]bool{}
	for _, d := range desired {
		want[d] = true
		targets[d.TargetID] = true
	}
	for _, old := range current {
		targets[old.TargetID] = true
	}
	for _, old := range current {
		if !want[old] {
			remove = append(remove, old)
		}
	}
	for id := range targets {
		affected = append(affected, id)
	}
	sort.Slice(affected, func(i, j int) bool { return affected[i] < affected[j] })
	return remove, affected
}

func syncRoleRuleSupports(tx *gorm.DB, userID uint, channel string, desired []mappingSupport) ([]mappingSupportChange, error) {
	var rows []model.UserRoleMappingRuleSupport
	if err := tx.Where("user_id=? AND channel=?", userID, channel).Find(&rows).Error; err != nil {
		return nil, err
	}
	current := make([]mappingSupport, 0, len(rows))
	for _, r := range rows {
		current = append(current, mappingSupport{r.RoleID, r.RuleID})
	}
	remove, _ := diffMappingSupports(current, desired)
	var changes []mappingSupportChange
	for _, r := range remove {
		change, err := supportChange(tx, "role", r, "remove")
		if err != nil {
			return nil, err
		}
		if err := tx.Exec("DELETE FROM user_role_mapping_rule_supports WHERE user_id=? AND channel=? AND role_id=? AND rule_id=?", userID, channel, r.TargetID, r.RuleID).Error; err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}
	for _, r := range desired {
		res := tx.Exec("INSERT INTO user_role_mapping_rule_supports(user_id,role_id,channel,rule_id) VALUES (?,?,?,?) ON CONFLICT DO NOTHING", userID, r.TargetID, channel, r.RuleID)
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected > 0 {
			change, err := supportChange(tx, "role", r, "add")
			if err != nil {
				return nil, err
			}
			changes = append(changes, change)
		}
	}
	sortSupportChanges(changes)
	return changes, nil
}

// reconcileGroupMembers updates only the effective projection. A manual row is
// never removed by a mapping recomputation, even if its last rule disappears.
func reconcileGroupMembers(tx *gorm.DB, userID uint, groupIDs []uint) (removed []uint, err error) {
	for _, groupID := range groupIDs {
		var count int64
		if err := tx.Table("user_group_mapping_rule_supports").Where("user_id=? AND user_group_id=?", userID, groupID).Count(&count).Error; err != nil {
			return nil, err
		}
		var rows []model.UserGroupMember
		if err := tx.Where("user_id=? AND user_group_id=?", userID, groupID).Find(&rows).Error; err != nil {
			return nil, err
		}
		if count > 0 && len(rows) == 0 {
			if err := tx.Exec("INSERT INTO user_group_members (user_group_id,user_id,manual) VALUES (?,?,false)", groupID, userID).Error; err != nil {
				return nil, err
			}
		} else if count == 0 && len(rows) > 0 && !rows[0].Manual {
			if err := tx.Exec("DELETE FROM user_group_members WHERE user_group_id=? AND user_id=?", groupID, userID).Error; err != nil {
				return nil, err
			}
			removed = append(removed, groupID)
		}
	}
	return removed, nil
}

func activeUserGroupRules(tx *gorm.DB, kind string, sourceID uint) ([]model.GroupUserGroupMapping, error) {
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return nil, err
	}
	var rules []model.GroupUserGroupMapping
	if err := tx.Preload("ExternalGroup").Where(column+"=? AND enabled=?", sourceID, true).Order("id").Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("讀取使用者群組映射規則失敗: %w", err)
	}
	for _, r := range rules {
		if r.ExternalGroup == nil {
			return nil, fmt.Errorf("規則 %d 的外部群組不存在", r.ID)
		}
		if kind == model.RoleMappingChannelKindDirectory && (r.ExternalGroup.LDAPDirectoryID == nil || *r.ExternalGroup.LDAPDirectoryID != sourceID) {
			return nil, fmt.Errorf("規則 %d 的來源與字典不一致", r.ID)
		}
		if kind == model.RoleMappingChannelKindProvider && (r.ExternalGroup.OIDCProviderID == nil || *r.ExternalGroup.OIDCProviderID != sourceID) {
			return nil, fmt.Errorf("規則 %d 的來源與字典不一致", r.ID)
		}
	}
	return rules, nil
}

func syncGroupRuleSupports(tx *gorm.DB, userID uint, obs GroupObservation) (changes []mappingSupportChange, removed []uint, err error) {
	rules, err := activeUserGroupRules(tx, obs.Kind, obs.SourceID)
	if err != nil {
		return nil, nil, err
	}
	matcher := groupMatcherFor(obs.Kind)
	desired := make([]mappingSupport, 0, len(rules))
	for _, r := range rules {
		hits, _ := matcher(obs.Groups, r.ExternalGroup.MatchValue)
		if len(hits) > 0 {
			desired = append(desired, mappingSupport{r.UserGroupID, r.ID})
		}
	}
	var rows []model.UserGroupMappingRuleSupport
	if err := tx.Where("user_id=? AND channel=?", userID, obs.Channel()).Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	current := make([]mappingSupport, 0, len(rows))
	for _, r := range rows {
		current = append(current, mappingSupport{r.UserGroupID, r.RuleID})
	}
	remove, affected := diffMappingSupports(current, desired)
	for _, r := range remove {
		change, err := supportChange(tx, "user_group", r, "remove")
		if err != nil {
			return nil, nil, err
		}
		if err := tx.Exec("DELETE FROM user_group_mapping_rule_supports WHERE user_id=? AND channel=? AND user_group_id=? AND rule_id=?", userID, obs.Channel(), r.TargetID, r.RuleID).Error; err != nil {
			return nil, nil, err
		}
		changes = append(changes, change)
	}
	for _, r := range desired {
		res := tx.Exec("INSERT INTO user_group_mapping_rule_supports(user_id,user_group_id,channel,rule_id) VALUES (?,?,?,?) ON CONFLICT DO NOTHING", userID, r.TargetID, obs.Channel(), r.RuleID)
		if res.Error != nil {
			return nil, nil, res.Error
		}
		if res.RowsAffected > 0 {
			change, err := supportChange(tx, "user_group", r, "add")
			if err != nil {
				return nil, nil, err
			}
			changes = append(changes, change)
		}
	}
	removed, err = reconcileGroupMembers(tx, userID, affected)
	sortSupportChanges(changes)
	return changes, removed, err
}
