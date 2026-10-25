package authz

import (
	"sort"
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// 目前使用者的能力投影。
//
// 投影只用來讓前端決定「顯示什麼」，後端每個操作仍用原裁決來源。輸入是逐請求解析的
// Principal 加上同一次組裝得到的既有資格值（審核資格、agent 兩旗標），不快取、不讀 JWT
// 角色、不重新比對角色名稱。

// 摘要的指派範圍：全域，或只經節點範圍指派生效（附節點）。
const (
	BindingScopeGlobal = "global"
	BindingScopeNodes  = "nodes"
)

// 衍生呈現點（`ui:` 命名空間）：伺服器產生、不可指派，與可指派的權限點目錄分開。
// 它們不是任何角色的能力、不寫入指派、不出現在 scope_summary，也不是後端 API 的授權依據。
const (
	UIPrefix             = "ui:"
	UIApprovals          = "ui:approvals"
	UIMyAgents           = "ui:my-agents"
	UIAssetsGlobal       = "ui:assets-global"
	UISelfServiceActions = "ui:self-service-actions"
	UIConnectBypass      = "ui:connect-bypass"
	// UISuperAdmin 保留的內建超級管理者身分本身（與 IsSuperAdmin 同源）。供只限超管的畫面元素
	// 使用，與連線豁免分開：豁免規則日後調整不影響這類元素。
	UISuperAdmin = "ui:super-admin"
)

// UIPresentationPoints 全部呈現點（排序副本）。
func UIPresentationPoints() []string {
	out := []string{UIApprovals, UIMyAgents, UIAssetsGlobal, UISelfServiceActions, UIConnectBypass, UISuperAdmin}
	sort.Strings(out)
	return out
}

// ProjectionInputs 與 UserInfo 同一次組裝得到的既有資格值；投影不再自行查詢一次而與其矛盾。
type ProjectionInputs struct {
	IsApprover         bool
	OwnsAgents         bool
	CanSelfCreateAgent bool
}

// ScopeSummaryEntry 指派範圍摘要的一筆。全域條目不帶 nodes 鍵（與節點範圍開放前同形）。
type ScopeSummaryEntry struct {
	Permission   string             `json:"permission"`
	BindingScope string             `json:"binding_scope"`
	Nodes        []ScopeSummaryNode `json:"nodes,omitempty"`
}

// ScopeSummaryNode 節點條目的一個節點：識別碼與由根到該節點的名稱路徑（每層一個元素）。
// 只作呈現，不是資源可見性、連線資格或逐筆操作的授權依據。
type ScopeSummaryNode struct {
	ID   uint     `json:"id"`
	Path []string `json:"path"`
}

// CapabilityProjection GET／PATCH /auth/me 新增的兩個欄位。兩者恆為非 nil 的陣列。
type CapabilityProjection struct {
	Permissions  []string
	ScopeSummary []ScopeSummaryEntry
}

// ProjectCapabilities 不帶節點路徑的投影：只經節點範圍指派生效的權限點列在 permissions、
// 不列摘要。需要節點條目的呼叫端（目前使用者回應）改用 ProjectCapabilitiesWithNodePaths。
func ProjectCapabilities(p *Principal, in ProjectionInputs) CapabilityProjection {
	return ProjectCapabilitiesWithNodePaths(p, in, nil)
}

// ProjectCapabilitiesWithNodePaths 由逐請求解析的主體、既有資格值與節點名稱路徑計算投影。
// paths 取自拓撲唯讀介面（ScopeSummaryNodeIDs 列出的節點）；不在 paths 內的節點視為已刪除、不列，
// 一個節點都不剩的條目不列。p 為 nil 時只回空集合。
func ProjectCapabilitiesWithNodePaths(p *Principal, in ProjectionInputs, paths map[uint][]string) CapabilityProjection {
	out := CapabilityProjection{Permissions: []string{}, ScopeSummary: []ScopeSummaryEntry{}}
	if p == nil {
		return out
	}
	for _, perm := range p.Capabilities() { // 已排序
		out.Permissions = append(out.Permissions, string(perm))
		if e, ok := p.scopeSummaryEntry(perm, paths); ok {
			out.ScopeSummary = append(out.ScopeSummary, e)
		}
	}
	derived := []string{}
	if in.IsApprover {
		derived = append(derived, UIApprovals)
	}
	if in.OwnsAgents || in.CanSelfCreateAgent {
		derived = append(derived, UIMyAgents)
	}
	// 全域資產檢視的相容判定：內建超管，或舊主角色為稽核（與連線短路的 view 判定同源）。
	if p.ConnectionShortcut(model.PermissionView) {
		derived = append(derived, UIAssetsGlobal)
	}
	// 原本顯示申請／待申請操作的判定：舊主角色不是 admin 也不是 auditor。
	if lr := p.LegacyRole(); lr != LegacyRoleAdmin && lr != LegacyRoleAuditor {
		derived = append(derived, UISelfServiceActions)
	}
	if p.IsSuperAdmin() {
		derived = append(derived, UIConnectBypass, UISuperAdmin)
	}
	out.Permissions = append(out.Permissions, derived...)
	sort.Strings(out.Permissions)
	return out
}

// ScopeSummaryNodeIDs 摘要的節點條目會用到的節點（去重、依 ID 排序）：只經節點範圍指派生效的
// 權限點，其各來源指派的有效節點聯集。只持全域指派（含 agent、零指派）的主體回空。
func ScopeSummaryNodeIDs(p *Principal) []uint {
	if p == nil {
		return nil
	}
	seen := map[uint]bool{}
	for perm := range p.caps {
		global, nodes := p.bindingOf(perm)
		if global {
			continue
		}
		for _, id := range nodes {
			seen[id] = true
		}
	}
	return sortedNodeIDs(seen)
}

// bindingOf 權限點的生效來源：任一來源為全域生效的指派（或 agent／零指派的固定範本）即為全域；
// 否則回各節點範圍來源的有效節點聯集。來源即權限解析時「同一筆指派、該點實際生效」記下的那些
// 指派，故全域判定只認含此點且使其生效的全域指派，不因主體另有其他全域指派而成立。
func (p *Principal) bindingOf(perm Permission) (global bool, nodes []uint) {
	seen := map[uint]bool{}
	for _, src := range p.srcs[perm] {
		if src == implicitGlobalSource || globalEffective(p.Assignments[src]) {
			return true, nil
		}
		for _, id := range p.Assignments[src].LiveNodeIDs {
			seen[id] = true
		}
	}
	return false, sortedNodeIDs(seen)
}

// scopeSummaryEntry 一個生效權限點的摘要條目；節點條目依路徑字典序排序（同路徑依 ID）。
func (p *Principal) scopeSummaryEntry(perm Permission, paths map[uint][]string) (ScopeSummaryEntry, bool) {
	global, ids := p.bindingOf(perm)
	if global {
		return ScopeSummaryEntry{Permission: string(perm), BindingScope: BindingScopeGlobal}, true
	}
	nodes := make([]ScopeSummaryNode, 0, len(ids))
	for _, id := range ids {
		if path, ok := paths[id]; ok && len(path) > 0 {
			nodes = append(nodes, ScopeSummaryNode{ID: id, Path: append([]string(nil), path...)})
		}
	}
	if len(nodes) == 0 {
		return ScopeSummaryEntry{}, false
	}
	sort.Slice(nodes, func(i, j int) bool {
		if c := comparePaths(nodes[i].Path, nodes[j].Path); c != 0 {
			return c < 0
		}
		return nodes[i].ID < nodes[j].ID
	})
	return ScopeSummaryEntry{Permission: string(perm), BindingScope: BindingScopeNodes, Nodes: nodes}, true
}

// comparePaths 名稱路徑逐層字典序比較；前綴較短者在前。
func comparePaths(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := strings.Compare(a[i], b[i]); c != 0 {
			return c
		}
	}
	return len(a) - len(b)
}

func sortedNodeIDs(set map[uint]bool) []uint {
	out := make([]uint, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsPresentationPoint 鍵是否在 `ui:` 命名空間。
func IsPresentationPoint(key string) bool { return strings.HasPrefix(key, UIPrefix) }
