package authz

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"gorm.io/gorm"
)

// EffectiveAccessResolver 有效權限解析。
// subject 一律顯式參數——嚴禁自 request context 推導（既有 CheckPermission/
// GetAuthorizedAssets 從 ctx 讀呼叫者角色且 admin/auditor 短路全通過，
// admin-only 端點直接復用會把任何目標誤判為全權）。
// 來源全集六種，聯集＝執行期判定：授權記錄四路徑（帶 authorization_id）、
// approver_scope（審核範圍隱含 view）、role_override（admin/auditor 角色隱含，
// 摘要標示不逐列展開）。SQL 一律走 repository 共用建塊，禁另寫等價 SQL
type EffectiveAccessResolver struct {
	repo *assetAuthorizationRepository
	db   *gorm.DB
}

// NewEffectiveAccessResolver 建立有效權限解析器
func NewEffectiveAccessResolver(db *gorm.DB) *EffectiveAccessResolver {
	return &EffectiveAccessResolver{
		repo: newAssetAuthorizationRepository(db),
		db:   db,
	}
}

// 溯因路徑類別（authorization-management spec）
const (
	PathDirectUser         = "direct_user"           // 個人×直授資產
	PathUserGroup          = "user_group"            // 群組×直授資產
	PathAssetNode          = "asset_node"            // 個人×節點含子樹
	PathUserGroupAssetNode = "user_group_asset_node" // 群組×節點含子樹
	PathApproverScope      = "approver_scope"        // 審核範圍隱含 view（無授權記錄）
)

// EffectivePath 單條溯因路徑
type EffectivePath struct {
	Kind            string               `json:"kind"`
	Permission      model.PermissionType `json:"permission"`
	AuthorizationID *uint                `json:"authorization_id,omitempty"`
	ViaGroupID      *uint                `json:"via_group_id,omitempty"`
	ViaGroupName    string               `json:"via_group_name,omitempty"`
	ViaNodeID       *uint                `json:"via_node_id,omitempty"`
	ViaNodePath     string               `json:"via_node_path,omitempty"`
	DateStart       *time.Time           `json:"date_start,omitempty"`
	DateExpired     *time.Time           `json:"date_expired,omitempty"`
}

// EffectiveAssetEntry 主體視角單資產
type EffectiveAssetEntry struct {
	AssetID    uint                 `json:"asset_id"`
	AssetName  string               `json:"asset_name"`
	Protocol   model.ProtocolType   `json:"protocol"`
	Permission model.PermissionType `json:"permission"`
	Paths      []EffectivePath      `json:"paths"`
}

// EffectiveAssetsResult 主體視角結果。RoleOverride 非空＝subject 具 admin/auditor
// 角色隱含全部資產（UI 以摘要橫幅呈現，Assets 仍僅列顯式授權記錄路徑）
type EffectiveAssetsResult struct {
	UserID       uint                  `json:"user_id"`
	Username     string                `json:"username"`
	RoleOverride string                `json:"role_override,omitempty"`
	Assets       []EffectiveAssetEntry `json:"assets"`
}

// EffectiveUserEntry 客體視角單使用者
type EffectiveUserEntry struct {
	UserID     uint                 `json:"user_id"`
	Username   string               `json:"username"`
	Permission model.PermissionType `json:"permission"`
	Paths      []EffectivePath      `json:"paths"`
}

// EffectiveUsersResult 客體視角結果。RoleOverrideNote 恆帶：admin/auditor 角色
// 帳號隱含可及本資產（不逐人列舉，spec「角色隱含以摘要標示」）
//
// i18n：RoleOverrideNote 為 zh wire fallback，
// RoleOverrideNoteCode 為穩定機器碼供前端查譯（沿 key_management_handler 的
// NameCode/NoteCode 同型作法）。此欄直穿 UI，硬編中文會在 en/ja 介面原樣外洩
type EffectiveUsersResult struct {
	AssetID          uint   `json:"asset_id"`
	AssetName        string `json:"asset_name"`
	RoleOverrideNote string `json:"role_override_note"`
	// RoleOverrideNoteCode 說明機器碼（前端查譯 effectiveAccessNote.<code>）
	RoleOverrideNoteCode string               `json:"role_override_note_code,omitempty"`
	Users                []EffectiveUserEntry `json:"users"`
}

// roleOverrideNoteCode 客體視角角色隱含摘要的機器碼（值域單一，前端查譯）
const roleOverrideNoteCode = "asset_role_override"

// ErrEffectiveSubjectNotFound 查詢主體不存在
var ErrEffectiveSubjectNotFound = errors.New("使用者不存在")

// ErrEffectiveAssetNotFound 查詢資產不存在
var ErrEffectiveAssetNotFound = errors.New("資產不存在")

// roleOverrideOf 主體角色隱含判定：角色自 DB 查詢（非 request context），
// admin 優先於 auditor
func roleOverrideOf(roles []model.Role) string {
	override := ""
	for _, r := range roles {
		if r.Name == model.RoleAdmin {
			return model.RoleAdmin
		}
		if r.Name == model.RoleAuditor {
			override = model.RoleAuditor
		}
	}
	return override
}

// grantPath 授權記錄→溯因路徑（主體/客體視角共用；nodePaths 供節點全路徑）
func grantPath(g *model.AssetAuthorization, nodePaths map[uint]string) EffectivePath {
	p := EffectivePath{
		Permission:  g.Permission,
		DateStart:   g.DateStart,
		DateExpired: g.DateExpired,
	}
	id := g.ID
	p.AuthorizationID = &id
	viaGroup := g.UserGroupID != nil
	viaNode := g.AssetGroupID != nil
	switch {
	case viaGroup && viaNode:
		p.Kind = PathUserGroupAssetNode
	case viaGroup:
		p.Kind = PathUserGroup
	case viaNode:
		p.Kind = PathAssetNode
	default:
		p.Kind = PathDirectUser
	}
	if viaGroup {
		p.ViaGroupID = g.UserGroupID
		if g.UserGroup != nil {
			p.ViaGroupName = g.UserGroup.Name
		}
	}
	if viaNode {
		p.ViaNodeID = g.AssetGroupID
		if nodePaths != nil {
			p.ViaNodePath = nodePaths[*g.AssetGroupID]
		}
	}
	return p
}

// upgradePermission 聚合最高等級（connect > view）
func upgradePermission(current, candidate model.PermissionType) model.PermissionType {
	weight := map[model.PermissionType]int{model.PermissionView: 1, model.PermissionConnect: 2}
	if weight[candidate] > weight[current] {
		return candidate
	}
	return current
}

// ResolveEffectiveAssets 主體視角：subject 於 now 時刻實際可及的資產與溯因
func (r *EffectiveAccessResolver) ResolveEffectiveAssets(
	subjectUserID uint,
	now time.Time,
) (*EffectiveAssetsResult, error) {
	var user model.User
	if err := r.db.Preload("Roles").First(&user, subjectUserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrEffectiveSubjectNotFound
		}
		return nil, fmt.Errorf("查詢使用者失敗: %w", err)
	}

	result := &EffectiveAssetsResult{
		UserID:       user.ID,
		Username:     user.Username,
		RoleOverride: roleOverrideOf(user.Roles),
		Assets:       []EffectiveAssetEntry{},
	}

	// 授權記錄四路徑：可及資產集合＋主體全部時窗內授權（共用 SQL 建塊）
	allPerms := []model.PermissionType{model.PermissionView, model.PermissionConnect}
	assets, err := r.repo.AccessibleAssetsWithin(subjectUserID, allPerms, now)
	if err != nil {
		return nil, err
	}
	grants, err := r.repo.SubjectGrantsWithin(subjectUserID, now)
	if err != nil {
		return nil, err
	}

	assetIDs := make([]uint, 0, len(assets))
	for _, a := range assets {
		assetIDs = append(assetIDs, a.ID)
	}
	ancestors, err := r.repo.AssetAncestorNodes(assetIDs)
	if err != nil {
		return nil, err
	}
	nodePaths, err := asset.NodePathMap(r.db)
	if err != nil {
		nodePaths = nil // 路徑映射失敗退回單名不擋解析（同 authNodePaths 慣例）
	}

	// 授權記錄按客體維度索引：直授資產→記錄、節點→記錄
	byAsset := make(map[uint][]*model.AssetAuthorization)
	byNode := make(map[uint][]*model.AssetAuthorization)
	for i := range grants {
		g := &grants[i]
		if g.AssetID != nil {
			byAsset[*g.AssetID] = append(byAsset[*g.AssetID], g)
		}
		if g.AssetGroupID != nil {
			byNode[*g.AssetGroupID] = append(byNode[*g.AssetGroupID], g)
		}
	}

	entries := make(map[uint]*EffectiveAssetEntry, len(assets))
	for _, a := range assets {
		entry := &EffectiveAssetEntry{AssetID: a.ID, AssetName: a.Name, Protocol: a.Protocol}
		for _, g := range byAsset[a.ID] {
			entry.Paths = append(entry.Paths, grantPath(g, nodePaths))
			entry.Permission = upgradePermission(entry.Permission, g.Permission)
		}
		for _, nodeID := range ancestors[a.ID] {
			for _, g := range byNode[nodeID] {
				entry.Paths = append(entry.Paths, grantPath(g, nodePaths))
				entry.Permission = upgradePermission(entry.Permission, g.Permission)
			}
		}
		entries[a.ID] = entry
	}

	// approver_scope 第五來源：範圍隱含 view（無授權記錄，authorization_id 空）
	scoped, err := r.repo.ApproverScopedAssets(subjectUserID)
	if err != nil {
		return nil, err
	}
	for _, a := range scoped {
		entry, ok := entries[a.ID]
		if !ok {
			entry = &EffectiveAssetEntry{AssetID: a.ID, AssetName: a.Name, Protocol: a.Protocol}
			entries[a.ID] = entry
		}
		entry.Paths = append(entry.Paths, EffectivePath{Kind: PathApproverScope, Permission: model.PermissionView})
		entry.Permission = upgradePermission(entry.Permission, model.PermissionView)
	}

	for _, e := range entries {
		result.Assets = append(result.Assets, *e)
	}
	sort.Slice(result.Assets, func(i, j int) bool { return result.Assets[i].AssetID < result.Assets[j].AssetID })
	return result, nil
}

// ResolveEffectiveUsers 客體視角：now 時刻實際可及指定資產的使用者與溯因
// （群組主體展開至成員；admin/auditor 角色隱含以摘要標示不逐人列舉）
func (r *EffectiveAccessResolver) ResolveEffectiveUsers(
	assetID uint,
	now time.Time,
) (*EffectiveUsersResult, error) {
	var assetRow model.Asset
	if err := r.db.First(&assetRow, assetID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrEffectiveAssetNotFound
		}
		return nil, fmt.Errorf("查詢資產失敗: %w", err)
	}

	result := &EffectiveUsersResult{
		AssetID:              assetRow.ID,
		AssetName:            assetRow.Name,
		RoleOverrideNote:     "admin 角色帳號隱含可及、auditor 角色帳號隱含檢視本資產（角色權限，不逐人列舉）",
		RoleOverrideNoteCode: roleOverrideNoteCode,
		Users:                []EffectiveUserEntry{},
	}

	grants, err := r.repo.AssetGrantsWithin(assetID, now)
	if err != nil {
		return nil, err
	}

	nodePaths, err := asset.NodePathMap(r.db)
	if err != nil {
		nodePaths = nil
	}

	groupIDs := make([]uint, 0)
	for i := range grants {
		if grants[i].UserGroupID != nil {
			groupIDs = append(groupIDs, *grants[i].UserGroupID)
		}
	}
	members, err := r.repo.GroupMembersByGroupIDs(groupIDs)
	if err != nil {
		return nil, err
	}

	entries := make(map[uint]*EffectiveUserEntry)
	ensure := func(id uint, username string) *EffectiveUserEntry {
		if e, ok := entries[id]; ok {
			return e
		}
		e := &EffectiveUserEntry{UserID: id, Username: username}
		entries[id] = e
		return e
	}

	for i := range grants {
		g := &grants[i]
		path := grantPath(g, nodePaths)
		switch {
		case g.UserID != nil:
			username := ""
			if g.User.ID != 0 {
				username = g.User.Username
			}
			e := ensure(*g.UserID, username)
			e.Paths = append(e.Paths, path)
			e.Permission = upgradePermission(e.Permission, g.Permission)
		case g.UserGroupID != nil:
			for _, m := range members[*g.UserGroupID] {
				e := ensure(m.ID, m.Username)
				e.Paths = append(e.Paths, path)
				e.Permission = upgradePermission(e.Permission, g.Permission)
			}
		}
	}

	// approver_scope：範圍涵蓋本資產的 approver 隱含 view
	approverIDs, err := r.repo.ApproversCoveringAsset(assetID)
	if err != nil {
		return nil, err
	}
	if len(approverIDs) > 0 {
		var approvers []model.User
		if err := r.db.Where("id IN ?", approverIDs).Find(&approvers).Error; err != nil {
			return nil, fmt.Errorf("查詢審核人失敗: %w", err)
		}
		for _, u := range approvers {
			e := ensure(u.ID, u.Username)
			e.Paths = append(e.Paths, EffectivePath{Kind: PathApproverScope, Permission: model.PermissionView})
			e.Permission = upgradePermission(e.Permission, model.PermissionView)
		}
	}

	for _, e := range entries {
		result.Users = append(result.Users, *e)
	}
	sort.Slice(result.Users, func(i, j int) bool { return result.Users[i].UserID < result.Users[j].UserID })
	return result, nil
}
