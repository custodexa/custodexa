package model

import (
	"time"

	"gorm.io/gorm"
)

// ExternalGroup is the shared, source-scoped dictionary entry used by both
// mapping types. MatchValue is retained exactly as entered.
type ExternalGroup struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	LDAPDirectoryID *uint     `gorm:"uniqueIndex:idx_external_groups_ldap_value,where:ldap_directory_id IS NOT NULL" json:"ldap_directory_id,omitempty"`
	OIDCProviderID  *uint     `gorm:"column:oidc_provider_id;uniqueIndex:idx_external_groups_oidc_value,where:oidc_provider_id IS NOT NULL" json:"oidc_provider_id,omitempty"`
	MatchValue      string    `gorm:"size:500;not null;uniqueIndex:idx_external_groups_ldap_value;uniqueIndex:idx_external_groups_oidc_value" json:"match_value"`
	Note            string    `gorm:"size:200;not null;default:''" json:"note"`
}

func (ExternalGroup) TableName() string { return "external_groups" }

// GroupUserGroupMapping maps a source group to one Custodexa user group.
type GroupUserGroupMapping struct {
	ID              uint           `gorm:"primaryKey" json:"id"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
	LDAPDirectoryID *uint          `json:"ldap_directory_id,omitempty"`
	OIDCProviderID  *uint          `gorm:"column:oidc_provider_id" json:"oidc_provider_id,omitempty"`
	ExternalGroupID uint           `gorm:"not null;uniqueIndex:idx_group_user_group_mappings_external_target,where:deleted_at IS NULL" json:"external_group_id"`
	UserGroupID     uint           `gorm:"not null;uniqueIndex:idx_group_user_group_mappings_external_target" json:"user_group_id"`
	Enabled         bool           `gorm:"not null;default:true" json:"enabled"`
	CreatedBy       uint           `gorm:"not null" json:"created_by"`
	ExternalGroup   *ExternalGroup `gorm:"foreignKey:ExternalGroupID" json:"external_group,omitempty"`
}

func (GroupUserGroupMapping) TableName() string { return "group_user_group_mappings" }

type UserRoleMappingRuleSupport struct {
	UserID  uint   `gorm:"primaryKey;autoIncrement:false"`
	RoleID  uint   `gorm:"primaryKey;autoIncrement:false"`
	Channel string `gorm:"primaryKey;size:64"`
	RuleID  uint   `gorm:"primaryKey;autoIncrement:false"`
}

func (UserRoleMappingRuleSupport) TableName() string { return "user_role_mapping_rule_supports" }

type UserGroupMappingRuleSupport struct {
	UserID      uint   `gorm:"primaryKey;autoIncrement:false"`
	UserGroupID uint   `gorm:"primaryKey;autoIncrement:false"`
	Channel     string `gorm:"primaryKey;size:64"`
	RuleID      uint   `gorm:"primaryKey;autoIncrement:false"`
}

func (UserGroupMappingRuleSupport) TableName() string { return "user_group_mapping_rule_supports" }

// UserGroupMember is the effective authorization projection. Manual membership
// remains even if every mapped support disappears.
type UserGroupMember struct {
	UserGroupID uint `gorm:"primaryKey;autoIncrement:false"`
	UserID      uint `gorm:"primaryKey;autoIncrement:false"`
	Manual      bool `gorm:"not null;default:true"`
}

func (UserGroupMember) TableName() string { return "user_group_members" }
