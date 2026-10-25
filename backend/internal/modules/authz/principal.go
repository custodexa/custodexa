package authz

import (
	"sort"

	"github.com/custodexa/backend/internal/model"
)

// 主體。
//
// 主體由 Resolver 在每個請求自資料庫解析，不快取；授權判斷不讀 JWT 內的角色。
// JWT 只提供主體種類、認證來源與憑證世代（TokenFacts），照舊保留。

// 指派來源：使用者直接指派，或經使用者群組取得。
const (
	ViaDirect = "direct"
	ViaGroup  = "group"
)

// TokenFacts 取自 token 的事實（照舊保留，不影響能力計算以外的語義）。
type TokenFacts struct {
	SubjectKind string // model.KindHuman／model.KindAgent；空值視為 human
	AuthMethod  string
	CredEpoch   int
}

// Assignment 一筆有效指派（角色已刪除者不會出現）。
type Assignment struct {
	RoleID     uint
	RoleName   string
	BuiltinKey string // 非內建角色為空
	Via        string // ViaDirect／ViaGroup
	GroupID    uint   // Via == ViaGroup 時為使用者群組 ID
	Scope      string // model.ScopeKindGlobal／model.ScopeKindNodes
	// RoleSource 使用者直接指派的來源（manual／mapped／both）；群組指派為空。
	RoleSource string
	// LiveNodeIDs 範圍為節點時，指派涵蓋且尚未刪除的節點；空集合或全部已刪除即為空。
	LiveNodeIDs []uint
	// Permissions 自訂角色（無內建識別、定義版本 >= 1）的明確權限集合；其他角色為空。
	Permissions []Permission
	// Custom 該指派的角色是新服務管理的自訂角色（即使集合為空也為 true）。
	Custom bool
}

// Principal 解析後的主體。零值不可用；由 Resolver 或 NewPrincipal 建立。
type Principal struct {
	UserID      uint
	Facts       TokenFacts
	Assignments []Assignment

	cat        Catalogue
	legacyRole string
	builtins   map[string]bool
	caps       map[Permission]bool
	// srcs 每個生效權限點的來源：指派在 Assignments 的索引，或 implicitGlobalSource
	// （agent 固定範本、零角色相容）。與 caps 在同一處寫入，故 Has 為真 ⇔ 至少有一個來源。
	srcs map[Permission][]int
}

// implicitGlobalSource 不經任何指派的全域來源（agent 固定範本、零指派相容）。
const implicitGlobalSource = -1

// grant 記錄權限點生效及其來源；caps 與 srcs 只在這裡寫入。
func (p *Principal) grant(perm Permission, source int) {
	p.caps[perm] = true
	p.srcs[perm] = append(p.srcs[perm], source)
}

// scopeGrants 一筆指派在指定權限點上是否生效（同一筆指派內判定，不跨指派組合）：
//   - 全域指派對所有權限點生效；
//   - 非全域指派只對 scoped-enforced 的權限點、且範圍節點集合非空時生效；
//     global-only 與 scoped-reserved 的權限點一律不生效，也不回退成全域。
func scopeGrants(a Assignment, def PermissionDef) bool {
	if a.Scope == model.ScopeKindGlobal {
		return true
	}
	return a.Scope == model.ScopeKindNodes && def.Scope == ScopeEnforced && len(a.LiveNodeIDs) > 0
}

// globalEffective 該指派是否為全域生效（內建身分與舊主角色折疊只認全域指派）。
func globalEffective(a Assignment) bool { return a.Scope == model.ScopeKindGlobal }

// NewPrincipal 由指派清單計算舊相容設定檔下的有效能力（Resolver 與測試共用）。
func NewPrincipal(userID uint, facts TokenFacts, assignments []Assignment) *Principal {
	return NewPrincipalOn(ProductCatalogue(), userID, facts, assignments)
}

// NewPrincipalOn 以指定目錄計算有效能力；NewPrincipal 即正式目錄版。
func NewPrincipalOn(cat Catalogue, userID uint, facts TokenFacts, assignments []Assignment) *Principal {
	p := &Principal{UserID: userID, Facts: facts, Assignments: assignments, cat: cat,
		builtins: map[string]bool{}, caps: map[Permission]bool{}, srcs: map[Permission][]int{}}
	if facts.SubjectKind != model.KindAgent { // agent 不因角色列取得任何內建身分（含超管、審核者）
		for _, a := range assignments {
			if a.BuiltinKey != "" && globalEffective(a) {
				p.builtins[a.BuiltinKey] = true
			}
		}
	}
	switch {
	case facts.SubjectKind == model.KindAgent:
		// agent 主體：能力固定為一般使用者範本（method＋path allowlist 由既有中介層處理），
		// 不受其角色列影響。
		p.legacyRole = LegacyRoleUser
	case len(assignments) == 0:
		p.legacyRole = LegacyRoleUser // 零角色視同 user
	case p.builtins[model.BuiltinSuperAdmin]:
		p.legacyRole = LegacyRoleAdmin
	case p.builtins[model.BuiltinAuditor]:
		p.legacyRole = LegacyRoleAuditor
	case p.builtins[model.BuiltinUser]:
		p.legacyRole = LegacyRoleUser
	default:
		p.legacyRole = LegacyRoleNone // 只有審核者、非內建角色或不生效的指派：無能力
	}
	if key := legacyTemplateKey(p.legacyRole); key != "" {
		p.grantTemplate(key, facts.SubjectKind == model.KindAgent || len(assignments) == 0)
	}
	p.grantDefinitions()
	return p
}

// grantDefinitions 聯集每筆有效指派的新角色集合：
// 鎖定管理範本取程式中的集合，自訂角色取其明確集合。權限與範圍以**同一筆指派**裁決，
// 不跨指派拼接；agent 能力固定為一般使用者範本，不受新角色影響。空集合的自訂角色
// 不補一般使用者能力（相容規則只在「完全沒有指派」時適用）。
func (p *Principal) grantDefinitions() {
	if p.Facts.SubjectKind == model.KindAgent {
		return
	}
	for i, a := range p.Assignments {
		var perms []Permission
		switch {
		case IsLockedManagementTemplate(a.BuiltinKey):
			perms = TemplatePermissions(a.BuiltinKey)
		case a.Custom:
			perms = a.Permissions
		default:
			continue
		}
		for _, perm := range perms {
			// 超管保留的鍵不因自訂角色集合而生效（舊資料內若存在也一樣）
			if a.Custom && !IsAssignable(perm) {
				continue
			}
			if def, ok := p.cat.Lookup(perm); ok && scopeGrants(a, def) {
				p.grant(perm, i)
			}
		}
	}
}

// grantTemplate 加入範本的權限點。unconditional 為 true（agent 固定範本、零角色）時不查指派；
// 否則逐權限點要求至少一筆「同一筆指派」帶該範本且在該權限點上生效。
func (p *Principal) grantTemplate(key string, unconditional bool) {
	for _, perm := range TemplatePermissions(key) {
		def, ok := p.cat.Lookup(perm)
		if !ok {
			continue
		}
		if unconditional {
			p.grant(perm, implicitGlobalSource)
			continue
		}
		for i, a := range p.Assignments {
			if a.BuiltinKey == key && scopeGrants(a, def) {
				p.grant(perm, i)
			}
		}
	}
}

// Has 主體是否持有權限點。
func (p *Principal) Has(perm Permission) bool { return p != nil && p.caps[perm] }

// assignsPermission 主體是否有任何一筆指派的角色含該權限點，且該指派在範圍節點仍有效時會讓它生效
// （全域指派，或 scoped-enforced 權限點的節點範圍指派）；不看節點是否仍有效。
// 與 Has 的差別在節點範圍指派的有效節點已空（節點刪除）時：Has 為假，本函式仍為真。
// agent 的能力固定為一般使用者範本、不受角色列影響，一律回假。
func (p *Principal) assignsPermission(perm Permission) bool {
	if p == nil || p.Facts.SubjectKind == model.KindAgent {
		return false
	}
	def, ok := p.cat.Lookup(perm)
	if !ok {
		return false
	}
	legacyKey := legacyTemplateKey(p.legacyRole)
	for _, a := range p.Assignments {
		if a.Scope != model.ScopeKindGlobal && !(a.Scope == model.ScopeKindNodes && def.Scope == ScopeEnforced) {
			continue
		}
		var perms []Permission
		switch {
		case IsLockedManagementTemplate(a.BuiltinKey):
			perms = TemplatePermissions(a.BuiltinKey)
		case a.Custom:
			if !IsAssignable(perm) {
				continue
			}
			perms = a.Permissions
		case a.BuiltinKey != "" && a.BuiltinKey == legacyKey:
			perms = TemplatePermissions(a.BuiltinKey)
		}
		for _, k := range perms {
			if k == perm {
				return true
			}
		}
	}
	return false
}

// Capabilities 有效能力集合（排序副本）。
func (p *Principal) Capabilities() []Permission {
	if p == nil {
		return nil
	}
	out := make([]Permission, 0, len(p.caps))
	for k := range p.caps {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// LegacyRole 舊主角色（admin／auditor／user，空＝無能力）。只供保留例外與短路判定使用。
func (p *Principal) LegacyRole() string {
	if p == nil {
		return LegacyRoleNone
	}
	return p.legacyRole
}

// HasBuiltin 是否持有（全域生效的）指定內建身分。
func (p *Principal) HasBuiltin(key string) bool { return p != nil && p.builtins[key] }

// IsApprover 審核者資格：獨立的內建身分判定，不經能力集合。
func (p *Principal) IsApprover() bool { return p.HasBuiltin(model.BuiltinApprover) }
