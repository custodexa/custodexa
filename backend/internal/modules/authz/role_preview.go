package authz

import (
	"sort"

	"github.com/custodexa/backend/internal/model"
)

// 角色預覽的權限集合。
//
// 預覽回答「只持這個角色一筆全域指派、沒有任何個人資格的人，登入後拿到什麼」。
// 計算全程是純函式：不讀不寫資料庫、不簽發任何憑證；與目前使用者回應走同一套
// 主體解析（NewPrincipalOn）與能力投影（ProjectCapabilitiesWithNodePaths），
// 頁面狀態直接取編輯畫面白話摘要的同一個判定（SummarizeRole）。

// 預覽不可用的原因（機器碼）。
const PreviewReasonReservedSuperAdmin = "reserved_super_admin"

// 預覽中頁面的三種狀態。
const (
	PreviewStateManage    = "manage"
	PreviewStateRead      = "read"
	PreviewStateAvailable = "available"
)

// PreviewEntryState 一個可進入頁面的狀態。Entry 為描述表入口 ID（跟隨入口者填被跟隨的入口，
// 固定頁填固定入口 ID）。
type PreviewEntryState struct {
	Entry string `json:"entry"`
	Path  string `json:"path"`
	State string `json:"state"`
}

// RolePreview 一個角色的預覽結果。Permissions 與 EntryStates 恆為非 nil 的陣列。
type RolePreview struct {
	Previewable bool
	// Reason 只在 Previewable 為假時有值。
	Reason      string
	Permissions []string
	EntryStates []PreviewEntryState
}

// PreviewRole 計算角色的預覽。builtinKey 為角色的內建識別（無則空字串）；definitionVersion
// 與 permissions 為角色的定義版本與已儲存的權限鍵（與正式解析相同：無內建識別且版本 >= 1 者
// 為自訂角色，取其明確集合並略過目錄外的鍵）。是否為超級管理者由主體的保留身分判定，
// 不比對角色名稱。
func PreviewRole(builtinKey string, definitionVersion int64, permissions []string) *RolePreview {
	a := Assignment{BuiltinKey: builtinKey, Via: ViaDirect, Scope: model.ScopeKindGlobal}
	if builtinKey == "" && definitionVersion >= 1 {
		a.Custom = true
		cat := ProductCatalogue()
		for _, k := range permissions {
			if _, ok := cat.Lookup(Permission(k)); ok {
				a.Permissions = append(a.Permissions, Permission(k))
			}
		}
	}
	p := NewPrincipal(0, TokenFacts{SubjectKind: model.KindHuman}, []Assignment{a})
	if p.IsSuperAdmin() {
		return &RolePreview{Reason: PreviewReasonReservedSuperAdmin, Permissions: []string{}, EntryStates: []PreviewEntryState{}}
	}
	// 個人資格（審核資格、agent 兩旗標）一律為否，不來自角色。
	proj := ProjectCapabilitiesWithNodePaths(p, ProjectionInputs{}, nil)
	out := &RolePreview{Previewable: true, Permissions: proj.Permissions, EntryStates: previewEntryStates(p, proj.Permissions)}
	return out
}

// previewRank 頁面狀態的高低（同一路徑多個入口時取最高）。
func previewRank(s string) int {
	switch s {
	case PreviewStateManage:
		return 3
	case PreviewStateRead:
		return 2
	}
	return 1
}

// previewStateOf 摘要分級到預覽狀態。沒有授予（hidden）的入口只會在入口鏡像放行時被問到，
// 此時取可用：hidden 表示描述表不認得這個授予，標成唯讀等於替描述表說話。
func previewStateOf(level string) string {
	switch level {
	case StateManage, statePartial:
		return PreviewStateManage
	case StateRead:
		return PreviewStateRead
	}
	return PreviewStateAvailable
}

func previewEntryStates(p *Principal, permissions []string) []PreviewEntryState {
	// 摘要的輸入是實際生效的權限點（不含衍生的呈現點）。
	sum := SummarizeRole(p.Capabilities())
	level := map[string]string{}
	for _, g := range []struct {
		l   string
		ids []string
	}{
		{StateManage, sum.Manage}, {statePartial, sum.Partial}, {StateRead, sum.Read},
		{StateAvailable, sum.Available}, {StateHidden, sum.Hidden},
	} {
		for _, id := range g.ids {
			level[id] = g.l
		}
	}
	held := make(map[string]bool, len(permissions))
	for _, k := range permissions {
		held[k] = true
	}
	has := func(k string) bool { return held[k] }

	pages := EntryPagePaths()
	byPath := map[string][]string{} // 路徑 → 直接對應的入口 ID（依描述表序）
	for _, e := range EntryDescriptors() {
		if path, ok := pages[e.ID]; ok {
			byPath[path] = append(byPath[path], e.ID)
		}
	}
	followed, fixed := FollowedPagePaths(), FixedPagePaths()
	personal := map[string]bool{}
	for _, path := range PersonalQualificationPaths() {
		personal[path] = true
	}

	out := []PreviewEntryState{}
	for _, r := range RouteEntryRules() { // 依路徑升冪
		if personal[r.Path] || !r.satisfiedBy(has) {
			continue
		}
		switch {
		case len(byPath[r.Path]) > 0:
			best, bestState := "", ""
			for _, id := range byPath[r.Path] {
				s := previewStateOf(level[id])
				if best == "" || previewRank(s) > previewRank(bestState) {
					best, bestState = id, s
				}
			}
			out = append(out, PreviewEntryState{Entry: best, Path: r.Path, State: bestState})
		case followed[r.Path] != "":
			id := followed[r.Path]
			out = append(out, PreviewEntryState{Entry: id, Path: r.Path, State: previewStateOf(level[id])})
		case fixed[r.Path] != "":
			out = append(out, PreviewEntryState{Entry: fixed[r.Path], Path: r.Path, State: PreviewStateAvailable})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
