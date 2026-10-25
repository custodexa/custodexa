package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/modules/authz"
)

// 範圍宣告守衛：標為 scoped-enforced 的權限點，凡以它為要求的登錄項（基本要求、並列進入能力、
// 欄位條件含萬用欄位）都須在 authz.RouteScopeDeclarations() 宣告目標解析或列表投影；
// 資料面登錄項不帶管理權限點、也不得出現在宣告表。
//
// 突變自檢：從 scopePendingExpected 拿掉一列或改錯樣板，pending_list_matches_ownership 轉紅；
// scopeRequirements 略過 AnyOf 或 Fields 來源，anyof_only／fields_only 轉紅。

// scopeOwnershipKeys 範圍歸屬對照表涵蓋的八組權限點（資產、帳號、憑證、節點、授權規則、
// 存取政策、審核範圍、改密）。
var scopeOwnershipKeys = []authz.Permission{
	authz.PermAssetView, authz.PermAssetCreate, authz.PermAssetUpdate, authz.PermAssetDelete, authz.PermAssetTest,
	authz.PermAccountRotate,
	authz.PermCredentialManage, authz.PermCredentialView, authz.PermCredentialCreate, authz.PermCredentialUpdate,
	authz.PermCredentialSetSecret, authz.PermCredentialRotate, authz.PermCredentialConvertScope,
	authz.PermCredentialDetach, authz.PermCredentialDelete, authz.PermCredentialBind,
	authz.PermAssetGroupManage,
	authz.PermAuthorizationManage,
	authz.PermAccessPolicyManage,
	authz.PermApproverScopeManage,
	authz.PermChangeSecretManage,
}

type scopeTriple struct {
	Method, Path string
	Source       authz.RequirementSource
}

func (t scopeTriple) String() string { return fmt.Sprintf("(%s, %s, %s)", t.Method, t.Path, t.Source) }

// scopePendingExpected 八組權限點全數改標 scoped-enforced 時，尚未宣告的 (方法, 樣板, 來源)。
// 與範圍歸屬對照表逐列相同；某條路由補上宣告時，同一次變更從這裡拿掉對應列。
// 目前已全數宣告，清單為空；守衛仍逐列比對，新增未宣告要求會以「守衛報出、預期清單沒有」轉紅。
var scopePendingExpected = []scopeTriple{}

// scopeRequirement 登錄項上的一個權限點要求。
type scopeRequirement struct {
	Method, Path string
	Source       authz.RequirementSource
	Perm         authz.Permission
	Field        string
}

func (r scopeRequirement) triple() scopeTriple { return scopeTriple{r.Method, r.Path, r.Source} }

func (r scopeRequirement) declKey() string {
	return strings.Join([]string{r.Method, r.Path, string(r.Source), string(r.Perm), r.Field}, "\x00")
}

func declKeyOf(d authz.RouteScopeDecl) string {
	return strings.Join([]string{d.Method, d.Path, string(d.Source), string(d.Perm), d.Field}, "\x00")
}

// allRequirements 登錄項的全部權限點要求（不看範圍屬性）。
func allRequirements(e authz.RouteEntry) []scopeRequirement {
	var out []scopeRequirement
	if e.Base == authz.BasePerm && e.Perm != "" {
		out = append(out, scopeRequirement{e.Method, e.Path, authz.ReqSourcePerm, e.Perm, ""})
	}
	for _, p := range e.AnyOf {
		out = append(out, scopeRequirement{e.Method, e.Path, authz.ReqSourceAnyOf, p, ""})
	}
	for _, f := range e.Fields {
		out = append(out, scopeRequirement{e.Method, e.Path, authz.ReqSourceFields, f.Perm, f.Field})
		// 欄位的相容並列能力與欄位權限點同一欄位、同一來源
		for _, p := range f.AnyOf {
			out = append(out, scopeRequirement{e.Method, e.Path, authz.ReqSourceFields, p, f.Field})
		}
	}
	return out
}

// scopeRequirements 要求的權限點在 cat 中為 scoped-enforced 者。
func scopeRequirements(cat authz.Catalogue, entries []authz.RouteEntry) []scopeRequirement {
	var out []scopeRequirement
	for _, e := range entries {
		for _, r := range allRequirements(e) {
			if d, ok := cat.Lookup(r.Perm); ok && d.Scope == authz.ScopeEnforced {
				out = append(out, r)
			}
		}
	}
	return out
}

// 守衛認得的宣告種類與目標種類；後續新增種類時同步登記。
var (
	knownScopeDeclKinds = map[authz.ScopeDeclKind]bool{
		authz.ScopeDeclTarget: true, authz.ScopeDeclListProjection: true, authz.ScopeDeclBatchSet: true,
		authz.ScopeDeclServiceTx: true, authz.ScopeDeclRouteGuard: true, authz.ScopeDeclServiceRead: true,
		authz.ScopeDeclSubjectDirectory: true,
	}
	knownScopeTargetKinds = map[authz.ScopeTargetKind]bool{
		authz.ScopeTargetAsset: true, authz.ScopeTargetAssetAccount: true, authz.ScopeTargetNode: true,
	}
)

// subjectDirectoryRoutes 唯一准許使用主體目錄宣告種類的路由（方法 + 樣板）：
// 授權主體選擇器與審核方選擇器，兩者皆只回有限欄位的使用者與群組目錄。
var subjectDirectoryRoutes = map[string]bool{
	"GET /api/v1/authorizations/subject-options":   true,
	"GET /api/v1/approver-scopes/approver-options": true,
}

// scopeDeclarationGaps 守衛本體：回傳未宣告的要求（依 (方法, 樣板, 來源) 排序）與其他違規。
func scopeDeclarationGaps(cat authz.Catalogue, entries []authz.RouteEntry, decls []authz.RouteScopeDecl) (missing []scopeRequirement, problems []string) {
	declared := map[string]authz.RouteScopeDecl{}
	for _, d := range decls {
		k := declKeyOf(d)
		if _, dup := declared[k]; dup {
			problems = append(problems, fmt.Sprintf("宣告重複 (%s, %s, %s) perm=%s field=%q", d.Method, d.Path, d.Source, d.Perm, d.Field))
		}
		declared[k] = d
	}

	existing := map[string]bool{}
	dataPlane := map[string]bool{}
	for _, e := range entries {
		for _, r := range allRequirements(e) {
			existing[r.declKey()] = true
		}
		if !e.DataPlane {
			continue
		}
		dataPlane[e.Key()] = true
		if e.Base == authz.BasePerm || e.Perm != "" || len(e.AnyOf) != 0 || len(e.Fields) != 0 {
			problems = append(problems, fmt.Sprintf("資料面登錄項帶權限點 %s: Base=%s Perm=%q AnyOf=%v Fields=%v", e.Key(), e.Base, e.Perm, e.AnyOf, e.Fields))
		}
	}

	for _, d := range decls {
		where := fmt.Sprintf("(%s, %s, %s) perm=%s field=%q", d.Method, d.Path, d.Source, d.Perm, d.Field)
		if dataPlane[d.Method+" "+d.Path] {
			problems = append(problems, "資料面登錄項不得出現在範圍宣告表 "+where)
		}
		if !existing[declKeyOf(d)] {
			problems = append(problems, "宣告對不到登錄表的任何要求 "+where)
		}
		if !knownScopeDeclKinds[d.Kind] {
			problems = append(problems, fmt.Sprintf("宣告種類未登記 %q %s", d.Kind, where))
		}
		if d.Kind == authz.ScopeDeclSubjectDirectory && !subjectDirectoryRoutes[d.Method+" "+d.Path] {
			problems = append(problems, "主體目錄宣告只准登記的主體選擇器使用 "+where)
		}
		if d.Kind == authz.ScopeDeclTarget && !knownScopeTargetKinds[d.Target] {
			problems = append(problems, fmt.Sprintf("目標解析宣告的目標種類未登記 %q %s", d.Target, where))
		}
		if d.Source != authz.ReqSourceFields && d.Field != "" {
			problems = append(problems, "非欄位條件來源不得帶欄位名 "+where)
		}
		if strings.TrimSpace(d.Owner) == "" {
			problems = append(problems, "宣告缺負責段 "+where)
		}
	}

	for _, r := range scopeRequirements(cat, entries) {
		if _, ok := declared[r.declKey()]; !ok {
			missing = append(missing, r)
		}
	}
	sort.SliceStable(missing, func(i, j int) bool { return missing[i].triple().String() < missing[j].triple().String() })
	for _, r := range missing {
		problems = append(problems, fmt.Sprintf("scoped-enforced 要求未宣告目標解析或列表投影 %s perm=%s field=%q", r.triple(), r.Perm, r.Field))
	}
	return missing, problems
}

func pendingTriples(missing []scopeRequirement) []scopeTriple {
	seen := map[scopeTriple]bool{}
	var out []scopeTriple
	for _, r := range missing {
		if t := r.triple(); !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// ownershipCatalogue 八組權限點全數為 scoped-enforced 的目錄：正式目錄已啟用者沿用，其餘以注入翻轉。
// 沿用的鍵須在正式目錄已是 scoped-enforced（不是就表示清單或目錄漂移，直接失敗）。
func ownershipCatalogue(t *testing.T) authz.Catalogue {
	t.Helper()
	product := authz.ProductCatalogue()
	var inject []authz.Permission
	for _, k := range scopeOwnershipKeys {
		d, ok := product.Lookup(k)
		if !ok {
			t.Fatalf("八組權限點 %s 不在正式目錄", k)
		}
		switch d.Scope {
		case authz.ScopeEnforced:
		case authz.ScopeReserved:
			inject = append(inject, k)
		default:
			t.Fatalf("八組權限點 %s 的範圍類別為 %s，既非 scoped-reserved 也非 scoped-enforced", k, d.Scope)
		}
	}
	cat := injectedCatalogue(t, inject...)
	for _, k := range scopeOwnershipKeys {
		if d, _ := cat.Lookup(k); d.Scope != authz.ScopeEnforced {
			t.Fatalf("注入後 %s 仍非 scoped-enforced", k)
		}
	}
	return cat
}

func injectedCatalogue(t *testing.T, keys ...authz.Permission) authz.Catalogue {
	t.Helper()
	cat, err := authz.CatalogueWithScopedEnforcedForTest(keys...)
	if err != nil {
		t.Fatalf("注入目錄失敗: %v", err)
	}
	return cat
}

// entriesRequiringOnlyVia 要求 key、且只經 src 來源要求它的登錄項。
func entriesRequiringOnlyVia(entries []authz.RouteEntry, key authz.Permission, src authz.RequirementSource) []authz.RouteEntry {
	var out []authz.RouteEntry
	for _, e := range entries {
		via := map[authz.RequirementSource]bool{}
		for _, r := range allRequirements(e) {
			if r.Perm == key {
				via[r.Source] = true
			}
		}
		if len(via) == 1 && via[src] {
			out = append(out, e)
		}
	}
	return out
}

func assertReported(t *testing.T, cat authz.Catalogue, entries []authz.RouteEntry, key authz.Permission, src authz.RequirementSource, wantField string) {
	t.Helper()
	targets := entriesRequiringOnlyVia(entries, key, src)
	if len(targets) == 0 {
		t.Fatalf("登錄表沒有只經 %s 要求 %s 的登錄項，案例不成立", src, key)
	}
	_, problems := scopeDeclarationGaps(cat, entries, nil)
	joined := strings.Join(problems, "\n")
	fieldSeen := wantField == ""
	for _, e := range targets {
		want := scopeTriple{e.Method, e.Path, src}.String()
		if !strings.Contains(joined, want) {
			t.Errorf("守衛未報出 %s（只經 %s 要求 %s）", want, src, key)
			continue
		}
		t.Logf("EVIDENCE scope-guard-report key=%s triple=%s", key, want)
		if wantField != "" && strings.Contains(joined, fmt.Sprintf("%s perm=%s field=%q", want, key, wantField)) {
			fieldSeen = true
		}
	}
	if !fieldSeen {
		t.Errorf("守衛輸出未含欄位 %q 的要求", wantField)
	}
}

func TestScopedEnforcedRequiresTargetResolution(t *testing.T) {
	entries := authz.RegistryEntries()
	product := authz.ProductCatalogue()

	t.Run("product_catalogue_zero", func(t *testing.T) {
		// 正式目錄只准出現已逐鍵啟用的 scoped-enforced 權限點；其餘仍須為零
		enabled := map[authz.Permission]bool{authz.PermAssetGroupManage: true,
			authz.PermAssetUpdate: true, authz.PermAssetDelete: true, authz.PermAssetTest: true, authz.PermAssetView: true,
			authz.PermCredentialView: true, authz.PermCredentialCreate: true, authz.PermCredentialUpdate: true,
			authz.PermCredentialSetSecret: true, authz.PermCredentialRotate: true, authz.PermCredentialConvertScope: true,
			authz.PermCredentialDetach: true, authz.PermCredentialDelete: true, authz.PermCredentialBind: true,
			authz.PermAuthorizationManage: true, authz.PermApproverScopeManage: true, authz.PermAssetCreate: true,
			authz.PermChangeSecretManage: true, authz.PermAccountRotate: true, authz.PermAccessPolicyManage: true}
		n := 0
		for _, k := range authz.CatalogKeys() {
			if d, ok := product.Lookup(k); ok && d.Scope == authz.ScopeEnforced {
				n++
				if !enabled[k] {
					t.Errorf("正式目錄出現未啟用的 scoped-enforced: %s", k)
				}
			}
		}
		if n != len(enabled) {
			t.Errorf("正式目錄的 scoped-enforced 數 %d，應為已啟用的 %d 個", n, len(enabled))
		}
		t.Logf("EVIDENCE scope-enforced-product count=%d", n)
		missing, problems := scopeDeclarationGaps(product, entries, authz.RouteScopeDeclarations())
		if len(missing) != 0 || len(problems) != 0 {
			t.Errorf("正式目錄下守衛應無違規: %s", strings.Join(problems, "\n"))
		}
	})

	t.Run("subject_directory_only_subject_options", func(t *testing.T) {
		var users []string
		for _, d := range authz.RouteScopeDeclarations() {
			if d.Kind == authz.ScopeDeclSubjectDirectory {
				users = append(users, d.Method+" "+d.Path)
			}
		}
		if len(users) != len(subjectDirectoryRoutes) {
			t.Fatalf("主體目錄宣告種類只准 %v 使用，實際 %v", subjectDirectoryRoutes, users)
		}
		for _, u := range users {
			if !subjectDirectoryRoutes[u] {
				t.Fatalf("主體目錄宣告種類只准 %v 使用，實際 %v", subjectDirectoryRoutes, users)
			}
		}
		// 守衛自檢：別的路由用此種類要報出
		cat := ownershipCatalogue(t)
		decls := append([]authz.RouteScopeDecl(nil), authz.RouteScopeDeclarations()...)
		for i := range decls {
			if decls[i].Method == "GET" && decls[i].Path == "/api/v1/authorizations" {
				decls[i].Kind = authz.ScopeDeclSubjectDirectory
			}
		}
		_, problems := scopeDeclarationGaps(cat, entries, decls)
		if !strings.Contains(strings.Join(problems, "\n"), "主體目錄宣告只准登記的主體選擇器使用 (GET, /api/v1/authorizations, Perm)") {
			t.Errorf("守衛未報出別的路由使用主體目錄宣告種類:\n%s", strings.Join(problems, "\n"))
		}
		t.Logf("EVIDENCE scope-subject-directory users=%v", users)
	})

	t.Run("anyof_only", func(t *testing.T) {
		assertReported(t, injectedCatalogue(t, authz.PermCredentialCreate), entries, authz.PermCredentialCreate, authz.ReqSourceAnyOf, "")
	})

	t.Run("fields_only", func(t *testing.T) {
		assertReported(t, injectedCatalogue(t, authz.PermAccessPolicyManage), entries, authz.PermAccessPolicyManage, authz.ReqSourceFields, "access_policy")
	})

	t.Run("fields_anyof_only", func(t *testing.T) {
		// 欄位條件的相容並列能力也是要求：注入為 enforced 且不給宣告時須報出該欄位
		assertReported(t, injectedCatalogue(t, authz.PermCredentialManage), entries, authz.PermCredentialManage,
			authz.ReqSourceFields, "credential_identity_fields")
	})

	t.Run("fields_wildcard_only", func(t *testing.T) {
		assertReported(t, injectedCatalogue(t, authz.PermAssetUpdate), entries, authz.PermAssetUpdate, authz.ReqSourceFields, authz.FieldWildcard)
	})

	t.Run("pending_list_matches_ownership", func(t *testing.T) {
		cat := ownershipCatalogue(t)
		missing, _ := scopeDeclarationGaps(cat, entries, authz.RouteScopeDeclarations())
		got := pendingTriples(missing)
		gotSet, wantSet := map[scopeTriple]bool{}, map[scopeTriple]bool{}
		routes := map[string]bool{}
		for _, tr := range got {
			gotSet[tr] = true
			routes[tr.Method+" "+tr.Path] = true
			t.Logf("EVIDENCE scope-pending\t%s\t%s\t%s", tr.Method, tr.Path, tr.Source)
		}
		for _, tr := range scopePendingExpected {
			if wantSet[tr] {
				t.Errorf("預期清單重複 %s", tr)
			}
			wantSet[tr] = true
			if !gotSet[tr] {
				t.Errorf("預期待宣告、守衛未報: %s", tr)
			}
		}
		for _, tr := range got {
			if !wantSet[tr] {
				t.Errorf("守衛報出、預期清單沒有: %s", tr)
			}
		}
		t.Logf("EVIDENCE scope-pending-total rows=%d routes=%d expected=%d", len(got), len(routes), len(scopePendingExpected))
	})

	t.Run("declarations_satisfy_and_are_checked", func(t *testing.T) {
		cat := ownershipCatalogue(t)
		all, _ := scopeDeclarationGaps(cat, entries, nil)
		decls := make([]authz.RouteScopeDecl, 0, len(all))
		for _, r := range all {
			decls = append(decls, authz.RouteScopeDecl{Method: r.Method, Path: r.Path, Source: r.Source, Perm: r.Perm, Field: r.Field,
				Kind: authz.ScopeDeclTarget, Target: authz.ScopeTargetAsset, Owner: "test"})
		}
		if missing, problems := scopeDeclarationGaps(cat, entries, decls); len(missing) != 0 || len(problems) != 0 {
			t.Fatalf("完整宣告下應無違規: %s", strings.Join(problems, "\n"))
		}

		cases := []struct {
			name   string
			mutate func(*authz.RouteScopeDecl)
			want   []string
		}{
			{"wrong_path", func(d *authz.RouteScopeDecl) { d.Path += "/x" }, []string{"宣告對不到登錄表", "未宣告目標解析或列表投影 " + all[0].triple().String()}},
			{"unknown_kind", func(d *authz.RouteScopeDecl) { d.Kind = "subject_catalogue" }, []string{"宣告種類未登記"}},
			{"target_missing", func(d *authz.RouteScopeDecl) { d.Target = "" }, []string{"目標種類未登記"}},
			{"owner_missing", func(d *authz.RouteScopeDecl) { d.Owner = "" }, []string{"宣告缺負責段"}},
		}
		for _, c := range cases {
			mut := append([]authz.RouteScopeDecl(nil), decls...)
			c.mutate(&mut[0])
			_, problems := scopeDeclarationGaps(cat, entries, mut)
			joined := strings.Join(problems, "\n")
			for _, w := range c.want {
				if !strings.Contains(joined, w) {
					t.Errorf("%s: 守衛輸出未含 %q:\n%s", c.name, w, joined)
				}
			}
		}
	})

	t.Run("data_plane_no_management_keys", func(t *testing.T) {
		n := 0
		for _, e := range entries {
			if !e.DataPlane {
				continue
			}
			n++
			for _, r := range allRequirements(e) {
				t.Errorf("資料面登錄項帶權限點 %s", r.triple())
			}
			for _, d := range authz.RouteScopeDeclarations() {
				if d.Method == e.Method && d.Path == e.Path {
					t.Errorf("資料面登錄項出現在範圍宣告表 %s", e.Key())
				}
			}
		}
		if n == 0 {
			t.Fatal("登錄表沒有資料面登錄項，案例不成立")
		}
		t.Logf("EVIDENCE scope-data-plane entries=%d", n)

		// 守衛自檢：資料面登錄項帶管理權限點、或被宣告，都要報出。
		bad := authz.RouteEntry{Method: "GET", Path: "/zz/data-plane", Base: authz.BaseAuthenticated, DataPlane: true,
			Fields: []authz.FieldCondition{{Field: authz.FieldWildcard, Perm: authz.PermAssetUpdate}}}
		decl := authz.RouteScopeDecl{Method: bad.Method, Path: bad.Path, Source: authz.ReqSourceFields, Perm: authz.PermAssetUpdate,
			Field: authz.FieldWildcard, Kind: authz.ScopeDeclTarget, Target: authz.ScopeTargetAsset, Owner: "test"}
		_, problems := scopeDeclarationGaps(product, []authz.RouteEntry{bad}, []authz.RouteScopeDecl{decl})
		joined := strings.Join(problems, "\n")
		for _, w := range []string{"資料面登錄項帶權限點 GET /zz/data-plane", "資料面登錄項不得出現在範圍宣告表"} {
			if !strings.Contains(joined, w) {
				t.Errorf("守衛未報出 %q:\n%s", w, joined)
			}
		}
	})
}
