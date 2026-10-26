package identity

import (
	"strconv"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/authz"
)

// 權限一覽用的映射規則唯讀查詢：被檢視者某角色（或某使用者群組成員資格）目前由哪些映射規則支持。
// 只讀支持表與規則表，不寫任何表。已刪除的規則不列。

// PermissionOverviewMappings 實作 authz.OverviewMappingReader。
type PermissionOverviewMappings struct{}

// NewPermissionOverviewMappings 建立映射規則唯讀查詢。
func NewPermissionOverviewMappings() PermissionOverviewMappings { return PermissionOverviewMappings{} }

var _ authz.OverviewMappingReader = PermissionOverviewMappings{}

type overviewRuleRow struct {
	TargetID        uint
	RuleID          uint
	ExternalGroup   string
	LDAPDirectoryID *uint
	OIDCProviderID  *uint
}

// RoleMappingRules 被檢視者各角色（鍵為角色編號）的支持規則。
func (PermissionOverviewMappings) RoleMappingRules(db *gorm.DB, userID uint) (map[uint][]authz.OverviewRuleRef, error) {
	var rows []overviewRuleRow
	if err := db.Raw(`SELECT DISTINCT s.role_id AS target_id, s.rule_id AS rule_id, r.match_value AS external_group,
 r.ldap_directory_id AS ldap_directory_id, r.oidc_provider_id AS oidc_provider_id
 FROM user_role_mapping_rule_supports s
 JOIN group_role_mappings r ON r.id = s.rule_id AND r.deleted_at IS NULL
 WHERE s.user_id = ? ORDER BY s.role_id, s.rule_id`, userID).Scan(&rows).Error; err != nil {
		return nil, err
	}
	return overviewRulesOf(db, rows)
}

// GroupMappingRules 被檢視者各使用者群組（鍵為群組編號）成員資格的支持規則。
func (PermissionOverviewMappings) GroupMappingRules(db *gorm.DB, userID uint) (map[uint][]authz.OverviewRuleRef, error) {
	var rows []overviewRuleRow
	if err := db.Raw(`SELECT DISTINCT s.user_group_id AS target_id, s.rule_id AS rule_id, g.match_value AS external_group,
 m.ldap_directory_id AS ldap_directory_id, m.oidc_provider_id AS oidc_provider_id
 FROM user_group_mapping_rule_supports s
 JOIN group_user_group_mappings m ON m.id = s.rule_id AND m.deleted_at IS NULL
 JOIN external_groups g ON g.id = m.external_group_id
 WHERE s.user_id = ? ORDER BY s.user_group_id, s.rule_id`, userID).Scan(&rows).Error; err != nil {
		return nil, err
	}
	return overviewRulesOf(db, rows)
}

// overviewRulesOf 補上身分來源顯示名後依目標分組。
func overviewRulesOf(db *gorm.DB, rows []overviewRuleRow) (map[uint][]authz.OverviewRuleRef, error) {
	names := map[string]string{}
	nameOf := func(kind string, id uint) (string, error) {
		key := kind + ":" + strconv.FormatUint(uint64(id), 10)
		if v, ok := names[key]; ok {
			return v, nil
		}
		var name string
		var q *gorm.DB
		if kind == "ldap" {
			q = db.Table("ldap_directories")
		} else {
			q = db.Table("oidc_providers")
		}
		if err := q.Where("id = ?", id).Limit(1).Pluck("name", &name).Error; err != nil {
			return "", err
		}
		names[key] = name
		return name, nil
	}
	out := map[uint][]authz.OverviewRuleRef{}
	for _, r := range rows {
		ref := authz.OverviewRuleRef{RuleID: r.RuleID, ExternalGroup: r.ExternalGroup}
		var err error
		switch {
		case r.LDAPDirectoryID != nil:
			ref.SourceName, err = nameOf("ldap", *r.LDAPDirectoryID)
		case r.OIDCProviderID != nil:
			ref.SourceName, err = nameOf("oidc", *r.OIDCProviderID)
		}
		if err != nil {
			return nil, err
		}
		out[r.TargetID] = append(out[r.TargetID], ref)
	}
	return out, nil
}
