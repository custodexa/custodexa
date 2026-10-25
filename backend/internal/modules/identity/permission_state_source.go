package identity

import (
	"context"
	"fmt"

	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 權限狀態快照的身分模組部分：
// 兩條外部映射、使用者群組與成員來源、主體種類與擁有者、本地登入能力。
// 不含密碼、憑證雜湊、姓名、電子郵件或外部群組名稱原文（比對字串只記不可逆指紋）。

func mappingSourceKind(ldapID, oidcID *uint) (string, uint) {
	switch {
	case ldapID != nil:
		return "ldap", *ldapID
	case oidcID != nil:
		return "oidc", *oidcID
	}
	return "none", 0
}

// PermissionStateIdentityPart 於呼叫端的一致性視圖（tx）讀身分模組擁有的權限真相。
func PermissionStateIdentityPart(ctx context.Context, tx *gorm.DB) (audit.PermissionPart, error) {
	tx = tx.WithContext(ctx)
	// 先建立自己擁有的全部集合（空也是明確的空，不是遺漏）
	sets := map[string][]string{audit.PermSetRoleMaps: {}, audit.PermSetGroupMaps: {}, audit.PermSetMembers: {},
		audit.PermSetGroups: {}, audit.PermSetPrincipals: {}, audit.PermSetRoleDefs: {}, audit.PermSetRolePerms: {}}

	// 自訂角色定義：定義版本與範本來源只含數字，權限鍵為目錄內固定字串；
	// 角色名稱、說明等自由文字不進快照。存量相容目錄角色的定義版本為 0。
	var defs []struct {
		ID                uint
		DefinitionVersion int64
		TemplateRoleID    *uint
	}
	if err := tx.Raw(`SELECT id, definition_version, template_role_id FROM roles WHERE builtin_key IS NULL`).Scan(&defs).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取角色定義版本失敗: %w", err)
	}
	for _, d := range defs {
		var tpl uint
		if d.TemplateRoleID != nil {
			tpl = *d.TemplateRoleID
		}
		sets[audit.PermSetRoleDefs] = append(sets[audit.PermSetRoleDefs], audit.PermissionRow(d.ID, d.DefinitionVersion, tpl))
	}
	var rps []struct {
		RoleID        uint
		PermissionKey string
	}
	if err := tx.Raw(`SELECT role_id, permission_key FROM role_permissions`).Scan(&rps).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 role_permissions 失敗: %w", err)
	}
	for _, rp := range rps {
		sets[audit.PermSetRolePerms] = append(sets[audit.PermSetRolePerms], audit.PermissionRow(rp.RoleID, rp.PermissionKey))
	}

	var rms []struct {
		ID              uint
		LdapDirectoryID *uint `gorm:"column:ldap_directory_id"`
		OidcProviderID  *uint `gorm:"column:oidc_provider_id"`
		RoleID          uint
		MatchValue      string
		Enabled         bool
		Deleted         bool
	}
	if err := tx.Raw(`SELECT id, ldap_directory_id, oidc_provider_id, role_id, match_value, enabled,
 (deleted_at IS NOT NULL) AS deleted FROM group_role_mappings`).Scan(&rms).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 group_role_mappings 失敗: %w", err)
	}
	for _, m := range rms {
		kind, src := mappingSourceKind(m.LdapDirectoryID, m.OidcProviderID)
		sets[audit.PermSetRoleMaps] = append(sets[audit.PermSetRoleMaps], audit.PermissionRow(
			m.ID, kind, src, m.RoleID, audit.PermissionMatchFingerprint(m.MatchValue), audit.PermBool(m.Enabled), audit.PermBool(m.Deleted)))
	}

	var gms []struct {
		ID              uint
		LdapDirectoryID *uint `gorm:"column:ldap_directory_id"`
		OidcProviderID  *uint `gorm:"column:oidc_provider_id"`
		UserGroupID     uint
		MatchValue      string
		Enabled         bool
		Deleted         bool
	}
	if err := tx.Raw(`SELECT m.id AS id, m.ldap_directory_id AS ldap_directory_id, m.oidc_provider_id AS oidc_provider_id,
 m.user_group_id AS user_group_id, COALESCE(g.match_value, '') AS match_value, m.enabled AS enabled,
 (m.deleted_at IS NOT NULL) AS deleted
 FROM group_user_group_mappings m LEFT JOIN external_groups g ON g.id = m.external_group_id`).Scan(&gms).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 group_user_group_mappings 失敗: %w", err)
	}
	for _, m := range gms {
		kind, src := mappingSourceKind(m.LdapDirectoryID, m.OidcProviderID)
		sets[audit.PermSetGroupMaps] = append(sets[audit.PermSetGroupMaps], audit.PermissionRow(
			m.ID, kind, src, m.UserGroupID, audit.PermissionMatchFingerprint(m.MatchValue), audit.PermBool(m.Enabled), audit.PermBool(m.Deleted)))
	}

	var mem []struct {
		UserGroupID uint
		UserID      uint
		Manual      bool
		Mapped      bool
	}
	if err := tx.Raw(`SELECT m.user_group_id AS user_group_id, m.user_id AS user_id, m.manual AS manual,
 (EXISTS (SELECT 1 FROM user_group_mapping_rule_supports s WHERE s.user_id = m.user_id AND s.user_group_id = m.user_group_id)) AS mapped
 FROM user_group_members m`).Scan(&mem).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 user_group_members 失敗: %w", err)
	}
	for _, m := range mem {
		src := "mapped"
		switch {
		case m.Manual && m.Mapped:
			src = "both"
		case m.Manual:
			src = "manual"
		}
		sets[audit.PermSetMembers] = append(sets[audit.PermSetMembers], audit.PermissionRow(m.UserGroupID, m.UserID, src))
	}

	var groups []struct {
		ID      uint
		Deleted bool
	}
	if err := tx.Raw(`SELECT id, (deleted_at IS NOT NULL) AS deleted FROM user_groups`).Scan(&groups).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 user_groups 失敗: %w", err)
	}
	for _, g := range groups {
		sets[audit.PermSetGroups] = append(sets[audit.PermSetGroups], audit.PermissionRow(g.ID, audit.PermBool(g.Deleted)))
	}

	// 主體：種類、擁有者、有效／刪除狀態，以及支撐最後本地超管計數的非秘密布林
	// （可本地登入＝未外部託管、非 LDAP、本地供應來源、密碼非空）。
	var us []struct {
		ID         uint
		Kind       string
		OwnerID    *uint `gorm:"column:owner_user_id"`
		Active     bool
		Deleted    bool
		LocalLogin bool
	}
	if err := tx.Raw(`SELECT id, kind, owner_user_id, active, (deleted_at IS NOT NULL) AS deleted,
 (external_credential = ? AND is_ldap = ? AND password IS NOT NULL AND TRIM(password) <> ''
  AND (provisioning_origin IS NULL OR provisioning_origin = '' OR provisioning_origin = 'local')) AS local_login
 FROM users`, false, false).Scan(&us).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 users 失敗: %w", err)
	}
	for _, u := range us {
		var owner uint
		if u.OwnerID != nil {
			owner = *u.OwnerID
		}
		sets[audit.PermSetPrincipals] = append(sets[audit.PermSetPrincipals], audit.PermissionRow(
			u.ID, u.Kind, owner, audit.PermBool(u.Active), audit.PermBool(u.Deleted), audit.PermBool(u.LocalLogin)))
	}
	return audit.PermissionPart{Sets: sets}, nil
}
