package api

import (
	"log"
	"math"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 角色指派類審計列的讀取期換名。
//
// 審計列的 details 只存識別碼（鑑識原文，不改寫）；原因參數裡的角色、對象與節點
// 在回應前由這裡換成名稱，稽核人員才讀得懂，又不需要角色檢視權。
// 刪除的物件保留 `#<識別碼>`，已刪除的角色去掉改名字尾還原原名。
// 每次呼叫的查詢次數固定（角色、帳號、群組、節點路徑各至多一次），不隨列數成長。

// auditReasonNameSource 帳號、角色、群組的批次取名面（實作＝identity 的兩個服務；含軟刪）
type auditReasonNameSource interface {
	RoleAssignmentUsernames(ids []uint64) (map[uint64]string, error)
	RoleAssignmentRoleNames(ids []uint64) (map[uint64]string, error)
}

// auditReasonGroupNameSource 使用者群組的批次取名面
type auditReasonGroupNameSource interface {
	RoleAssignmentGroupNames(ids []uint64) (map[uint64]string, error)
}

// AuditReasonNamer 名稱換算器；零值與 nil 都是不換名
type AuditReasonNamer struct {
	names     auditReasonNameSource
	groups    auditReasonGroupNameSource
	nodePaths func() (map[uint]string, error)
}

// NewAuditReasonNamer 建立換算器；節點路徑取自資產模組的全節點路徑映射
func NewAuditReasonNamer(names auditReasonNameSource, groups auditReasonGroupNameSource) *AuditReasonNamer {
	return &AuditReasonNamer{
		names: names, groups: groups,
		nodePaths: func() (map[uint]string, error) { return asset.NodePathMap(database.DB) },
	}
}

// stripDeletedRoleSuffix 去掉角色刪除時追加在名稱後的字尾（`~del<編號>`）
func stripDeletedRoleSuffix(name string) string {
	i := strings.LastIndex(name, "~del")
	if i < 0 || i+4 == len(name) {
		return name
	}
	for _, r := range name[i+4:] {
		if r < '0' || r > '9' {
			return name
		}
	}
	return name[:i]
}

// auditReasonRef 一列的原因碼與參數；參數 map 就地改寫
type auditReasonRef struct {
	code   string
	params map[string]string
}

// targetIsGroup 對象是使用者群組：群組角色指派的碼，或範圍事件帶 target_kind=user_group
func targetIsGroup(code string, params map[string]string) bool {
	return params["target_kind"] == "user_group" || strings.HasPrefix(code, "user_group_role_")
}

func parseIDRef(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "#") {
		return 0, false
	}
	n, err := strconv.ParseUint(s[1:], 10, 64)
	return n, err == nil
}

func splitIDList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// rename 就地換名。查詢失敗時該類名稱保留 `#<識別碼>`，不影響回應
func (n *AuditReasonNamer) rename(refs []auditReasonRef) {
	if n == nil {
		return
	}
	type pickedRef struct {
		code   string
		params map[string]string
	}
	var picked []pickedRef
	roleIDs, userIDs, groupIDs, nodeIDs := map[uint64]bool{}, map[uint64]bool{}, map[uint64]bool{}, map[uint64]bool{}
	for _, r := range refs {
		if !audit.IsRoleAssignmentReasonCode(r.code) || r.params == nil {
			continue
		}
		picked = append(picked, pickedRef{r.code, r.params})
		p := r.params
		if id, ok := parseIDRef(p["role"]); ok {
			roleIDs[id] = true
		}
		if id, ok := parseIDRef(p["target"]); ok {
			if targetIsGroup(r.code, p) {
				groupIDs[id] = true
			} else {
				userIDs[id] = true
			}
		}
		for _, key := range []string{"nodes", "before", "after"} {
			for _, part := range splitIDList(p[key]) {
				if id, ok := parseIDRef(part); ok {
					nodeIDs[id] = true
				}
			}
		}
	}
	if len(picked) == 0 {
		return
	}
	roles := n.lookup(roleIDs, func(ids []uint64) (map[uint64]string, error) {
		if n.names == nil {
			return nil, nil
		}
		return n.names.RoleAssignmentRoleNames(ids)
	})
	users := n.lookup(userIDs, func(ids []uint64) (map[uint64]string, error) {
		if n.names == nil {
			return nil, nil
		}
		return n.names.RoleAssignmentUsernames(ids)
	})
	groups := n.lookup(groupIDs, func(ids []uint64) (map[uint64]string, error) {
		if n.groups == nil {
			return nil, nil
		}
		return n.groups.RoleAssignmentGroupNames(ids)
	})
	var paths map[uint]string
	if len(nodeIDs) > 0 && n.nodePaths != nil {
		var err error
		if paths, err = n.nodePaths(); err != nil {
			log.Printf("[AuditReasonNamer] 節點路徑查詢失敗: %v", err)
			paths = nil
		}
	}
	for _, pk := range picked {
		p := pk.params
		if id, ok := parseIDRef(p["role"]); ok {
			if name, found := roles[id]; found {
				p["role"] = stripDeletedRoleSuffix(name)
			}
		}
		if id, ok := parseIDRef(p["target"]); ok {
			src := users
			if targetIsGroup(pk.code, p) {
				src = groups
			}
			if name, found := src[id]; found {
				p["target"] = name
			}
		}
		for _, key := range []string{"nodes", "before", "after"} {
			v, has := p[key]
			if !has || v == "global" {
				continue
			}
			parts := splitIDList(v)
			for i, part := range parts {
				if id, ok := parseIDRef(part); ok && id <= math.MaxUint32 {
					nodeID := uint(id)
					if path, found := paths[nodeID]; found && path != "" {
						parts[i] = path
					}
				}
			}
			p[key] = strings.Join(parts, ",")
		}
	}
}

func (n *AuditReasonNamer) lookup(set map[uint64]bool, fn func([]uint64) (map[uint64]string, error)) map[uint64]string {
	if len(set) == 0 {
		return nil
	}
	ids := make([]uint64, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	out, err := fn(ids)
	if err != nil {
		log.Printf("[AuditReasonNamer] 名稱查詢失敗: %v", err)
		return nil
	}
	return out
}

// RenameViews 對操作日誌列表或單筆的回應列換名
func (n *AuditReasonNamer) RenameViews(views []audit.AuditLogView) {
	if n == nil {
		return
	}
	refs := make([]auditReasonRef, 0, len(views))
	for i := range views {
		refs = append(refs, auditReasonRef{code: views[i].ReasonCode, params: views[i].ReasonParams})
	}
	n.rename(refs)
}

// RenameEventItems 對每日簽核明細的事件列換名
func (n *AuditReasonNamer) RenameEventItems(items []audit.DailyReviewEventItem) {
	if n == nil {
		return
	}
	refs := make([]auditReasonRef, 0, len(items))
	for i := range items {
		refs = append(refs, auditReasonRef{code: items[i].ReasonCode, params: items[i].ReasonParams})
	}
	n.rename(refs)
}

// ScopeNodes 節點編號換成 {id, path}；節點已刪除（或路徑查詢失敗）時 path 為空。
// 未注入換算器時一律回空路徑。
func (n *AuditReasonNamer) ScopeNodes(ids []uint) []audit.SystemAlertScopeNode {
	out := make([]audit.SystemAlertScopeNode, 0, len(ids))
	var paths map[uint]string
	if n != nil && n.nodePaths != nil && len(ids) > 0 {
		var err error
		if paths, err = n.nodePaths(); err != nil {
			log.Printf("[AuditReasonNamer] 節點路徑查詢失敗: %v", err)
			paths = nil
		}
	}
	for _, id := range ids {
		out = append(out, audit.SystemAlertScopeNode{ID: id, Path: paths[id]})
	}
	return out
}
