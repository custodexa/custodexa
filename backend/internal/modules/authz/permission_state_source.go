package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 權限狀態快照的授權模組部分：
// 角色與內建身分、直接指派、群組指派、節點範圍、版本維度。
// 經 audit.SetPermissionSources 注入；排序、去重、編碼與雜湊留在 audit。

// CatalogDigest 內建權限目錄與全部內建範本權限點集合的摘要。範本在程式內定義，
// 內建範本沒有 role_permissions 列，所以還原核對以此與快照釘住的版本相比。
func CatalogDigest() string {
	keys := make([]string, 0)
	for _, k := range CatalogKeys() {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			fmt.Fprintf(h, "%d:%s;", len(p), p)
		}
		h.Write([]byte{'\n'})
	}
	write(append([]string{"catalog"}, keys...)...)
	for _, bk := range builtinTemplateKeys() {
		perms := make([]string, 0)
		for _, p := range TemplatePermissions(bk) {
			perms = append(perms, string(p))
		}
		sort.Strings(perms)
		write(append([]string{"template", bk}, perms...)...)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// PermissionStateAuthzPart 於呼叫端的一致性視圖（tx）讀授權模組擁有的權限真相。
func PermissionStateAuthzPart(ctx context.Context, tx *gorm.DB) (audit.PermissionPart, error) {
	tx = tx.WithContext(ctx)
	var st model.AuthzState
	if err := tx.Where("id = 1").Limit(1).Find(&st).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 authz_state 失敗: %w", err)
	}
	meta := &audit.PermissionMeta{
		Model: audit.PermissionModelVersion, Catalog: CatalogDigest(), Version: st.Version,
		GenerationFP: audit.PermissionGenerationFingerprint(st.RestoreGeneration), RestoreOpID: st.RestoreOpID,
	}
	// 先建立自己擁有的全部集合（空也是明確的空，不是遺漏）
	sets := map[string][]string{audit.PermSetRoles: {}, audit.PermSetUserRoles: {}, audit.PermSetGroupRoles: {},
		audit.PermSetBindingNodes: {}, audit.PermSetNodes: {}}

	var roles []struct {
		ID         uint
		BuiltinKey *string
		Deleted    bool
	}
	if err := tx.Raw(`SELECT id, builtin_key, (deleted_at IS NOT NULL) AS deleted FROM roles`).Scan(&roles).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 roles 失敗: %w", err)
	}
	for _, r := range roles {
		bk := ""
		if r.BuiltinKey != nil {
			bk = *r.BuiltinKey
		}
		sets[audit.PermSetRoles] = append(sets[audit.PermSetRoles], audit.PermissionRow(r.ID, bk, audit.PermBool(r.Deleted)))
	}

	var urs []model.UserRole
	if err := tx.Raw(`SELECT user_id, role_id, source, scope_kind FROM user_roles`).Scan(&urs).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 user_roles 失敗: %w", err)
	}
	for _, u := range urs {
		sets[audit.PermSetUserRoles] = append(sets[audit.PermSetUserRoles], audit.PermissionRow(u.UserID, u.RoleID, u.ScopeKind, u.Source))
	}

	var grs []model.UserGroupRole
	if err := tx.Find(&grs).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 user_group_roles 失敗: %w", err)
	}
	for _, g := range grs {
		sets[audit.PermSetGroupRoles] = append(sets[audit.PermSetGroupRoles], audit.PermissionRow(g.UserGroupID, g.RoleID, g.ScopeKind))
	}

	var bns []model.RoleBindingNode
	if err := tx.Find(&bns).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取 role_binding_nodes 失敗: %w", err)
	}
	for _, b := range bns {
		sets[audit.PermSetBindingNodes] = append(sets[audit.PermSetBindingNodes], audit.PermissionRow(b.SubjectKind, b.SubjectID, b.RoleID, b.NodeID))
	}

	// 節點只取被指派引用者：節點是軟刪除，快照需保留「被引用的節點是否仍存在」。
	var nodes []struct {
		ID      uint
		Deleted bool
	}
	if err := tx.Raw(`SELECT asset_groups.id AS id, (asset_groups.deleted_at IS NOT NULL) AS deleted FROM asset_groups
 WHERE asset_groups.id IN (SELECT node_id FROM role_binding_nodes)`).Scan(&nodes).Error; err != nil {
		return audit.PermissionPart{}, fmt.Errorf("讀取被引用的節點失敗: %w", err)
	}
	for _, n := range nodes {
		sets[audit.PermSetNodes] = append(sets[audit.PermSetNodes], audit.PermissionRow(n.ID, audit.PermBool(n.Deleted)))
	}
	return audit.PermissionPart{Meta: meta, Sets: sets}, nil
}
