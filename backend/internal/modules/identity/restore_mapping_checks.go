package identity

import (
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// RestoreMappingRefChecks 還原完整性關卡中屬於 identity 的參照檢查（外部群組映射的目標、
// 外部群組與來源是否仍存在）。這些表歸 identity 所有，檢查由本模組以字面量 SQL 提供，
// 組裝根交給 authz.CheckRestoreIntegrity 的 extra 參數；authz 因此不直接讀他模組的表。
// 只檢查、不修復。
func RestoreMappingRefChecks() []authz.RefCheck {
	return append(mappingRefChecks(), roleDefinitionRefChecks()...)
}

func mappingRefChecks() []authz.RefCheck {
	return []authz.RefCheck{
		{Code: "dangling_role_mapping_target", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT m.id FROM group_role_mappings m LEFT JOIN roles r ON r.id = m.role_id WHERE r.id IS NULL`)
		}},
		{Code: "dangling_role_mapping_external_group", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT m.id FROM group_role_mappings m LEFT JOIN external_groups g ON g.id = m.external_group_id WHERE g.id IS NULL`)
		}},
		{Code: "dangling_role_mapping_source", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT m.id FROM group_role_mappings m WHERE (m.ldap_directory_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM ldap_directories d WHERE d.id = m.ldap_directory_id))
    OR (m.oidc_provider_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM oidc_providers p WHERE p.id = m.oidc_provider_id))`)
		}},
		{Code: "dangling_group_mapping_target", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT m.id FROM group_user_group_mappings m LEFT JOIN user_groups g ON g.id = m.user_group_id WHERE g.id IS NULL`)
		}},
		{Code: "dangling_group_mapping_external_group", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT m.id FROM group_user_group_mappings m LEFT JOIN external_groups g ON g.id = m.external_group_id WHERE g.id IS NULL`)
		}},
		{Code: "dangling_group_mapping_source", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT m.id FROM group_user_group_mappings m WHERE (m.ldap_directory_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM ldap_directories d WHERE d.id = m.ldap_directory_id))
    OR (m.oidc_provider_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM oidc_providers p WHERE p.id = m.oidc_provider_id))`)
		}},
	}
}

// roleDefinitionRefChecks 自訂角色定義的還原核對：
// 懸空角色、未知權限鍵、目錄內但不可指派的保留鍵、懸空範本來源、不合法的定義版本、
// 內建或存量角色帶有自訂權限列一律列為發現，不當成空集合放行，也不修復。
// 鍵的判準與 authz.ValidateRoleDefinitionState（NormalizeRolePermissions）一致。
// role_permissions 與 roles 的定義欄歸 identity 所有。
func roleDefinitionRefChecks() []authz.RefCheck {
	keys := make([]string, 0, len(authz.CatalogKeys()))
	reserved := []string{}
	for _, k := range authz.CatalogKeys() {
		keys = append(keys, string(k))
		if !authz.IsAssignable(k) {
			reserved = append(reserved, string(k))
		}
	}
	return []authz.RefCheck{
		{Code: "dangling_role_permission_role", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT p.role_id || ':' || p.permission_key FROM role_permissions p LEFT JOIN roles r ON r.id = p.role_id WHERE r.id IS NULL`)
		}},
		{Code: "unknown_role_permission_key", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT p.role_id || ':' || p.permission_key FROM role_permissions p WHERE p.permission_key NOT IN ?`, keys)
		}},
		{Code: "non_assignable_role_permission_key", Query: func(tx *gorm.DB) *gorm.DB {
			if len(reserved) == 0 {
				return tx.Raw(`SELECT p.role_id || ':' || p.permission_key FROM role_permissions p WHERE 1 = 0`)
			}
			return tx.Raw(`SELECT p.role_id || ':' || p.permission_key FROM role_permissions p WHERE p.permission_key IN ?`, reserved)
		}},
		{Code: "dangling_role_template_source", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT r.id FROM roles r WHERE r.template_role_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM roles t WHERE t.id = r.template_role_id)`)
		}},
		{Code: "invalid_role_definition_version", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT r.id FROM roles r WHERE r.definition_version < 0`)
		}},
		{Code: "role_permissions_on_locked_role", Query: func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT p.role_id || ':' || p.permission_key FROM role_permissions p JOIN roles r ON r.id = p.role_id WHERE r.builtin_key IS NOT NULL OR r.definition_version = 0`)
		}},
	}
}
