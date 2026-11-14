package principalfacts

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// 授權主體建構點清冊與守衛。
//
// 授權解析的角色限定是請求主體事實（authz.TokenFacts）的一部分。凡是自行組出事實或主體的位置
// （複合字面量 authz.TokenFacts{...}、authz.Principal{...}，以及型別為 authz.TokenFacts 的零值宣告），
// 都可能讓重解退回帳號的完整身分。本守衛以型別資訊找出全部這類建構點，每一處須登記分類與處置；
// 新增未登記的建構點、或登記了卻已不存在，皆失敗（雙向）。
//
// 經變數傳遞事實的重解不在字面量的視野內，其正確性依賴「事實一律來自請求主體」，由行為測試涵蓋。
//
// 掃描範圍為整棵 module 的非測試 Go 檔。

const authzPkgPath = guardModulePath + "/internal/modules/authz"

// 分類（與重解點盤點的五類一致，另加請求主體本身與不涉及帳號的建構）
const (
	classRequestPrincipal = "請求主體"    // 認證入口建立的請求主體
	classOperator         = "操作者授權"   // 判定這次請求能做什麼
	classTarget           = "目標保護資格"  // 被操作帳號的身分，維持完整身分
	classProjection       = "清單與投影"   // 呈現帳號的權限，維持完整身分或取請求主體
	classCredentialCheck  = "獨立的帳密驗證" // 與請求主體無關
	classBackground       = "背景作業"    // 以帳號完整身分重驗
	classNoAccount        = "不涉及帳號"   // 以給定的假設指派計算，不重查任何帳號
	classResolver         = "解析器本體"   // 主體的唯一建構函式
)

// 處置
const (
	dispCarriesFilter = "帶限定"     // 事實取自請求主體（含角色限定）
	dispFullIdentity  = "維持完整身分"  // 刻意以帳號完整身分解析
	dispRouteExcluded = "路由範圍已排除" // 只在不對 API token 開放的路由上可達
	dispNotApplicable = "不適用"     // 不是帳號的重解
)

// constructionSite 清冊項。判定鍵為 (kind, file, fn)，count 為該函式內允許的次數。
type constructionSite struct {
	kind        string // "TokenFacts{}"、"Principal{}"、"var TokenFacts"
	file        string // 相對 backend/
	fn          string // 所在函式（方法記為 Type.Method）
	count       int
	class       string
	disposition string
	why         string
}

var principalConstructionSites = []constructionSite{
	// 解析器本體與請求主體
	{"Principal{}", "internal/modules/authz/principal.go", "NewPrincipalOn", 1, classResolver, dispNotApplicable,
		"主體的唯一建構函式；角色限定在此依事實過濾指派"},
	{"TokenFacts{}", "internal/middleware/auth.go", "AuthMiddleware", 1, classRequestPrincipal, dispNotApplicable,
		"人類工作階段的請求主體，不帶角色限定"},
	{"TokenFacts{}", "internal/middleware/auth.go", "authenticateAgent", 1, classRequestPrincipal, dispNotApplicable,
		"AI agent 鑰匙的請求主體（固定一般使用者範本，不查指派）"},
	{"TokenFacts{}", "internal/middleware/auth.go", "authenticateAPIToken", 1, classRequestPrincipal, dispCarriesFilter,
		"API token 的請求主體：限定為 token 建立時授權的角色（空集合亦為非 nil 的限定）"},

	// 操作者授權
	{"TokenFacts{}", "internal/modules/authz/capability_check.go", "Resolver.HasAllCapabilitiesFiltered", 1, classOperator, dispCarriesFilter,
		"憑證管理關卡的能力判定；限定由轉接頭取自請求主體，背景作業傳 nil"},
	{"TokenFacts{}", "internal/modules/identity/assignment_guard.go", "Operator.RequestFacts", 1, classOperator, dispCarriesFilter,
		"拒絕分支的零值回傳；放行時事實取自操作者攜帶的請求主體"},
	{"TokenFacts{}", "internal/modules/identity/role_definition_service.go", "principalFacts", 1, classOperator, dispCarriesFilter,
		"拒絕分支的零值回傳；放行時沿用請求主體的事實"},
	{"TokenFacts{}", "internal/api/auth_me_projection.go", "resolveProjectionPrincipal", 1, classOperator, dispNotApplicable,
		"已認證的請求取請求主體、缺主體即拒絕；此分支只在未經認證入口標示的呼叫"},
	{"TokenFacts{}", "internal/modules/identity/auth_principal.go", "AuthService.CurrentConnectPrincipalAndSourcePolicy", 1, classOperator, dispRouteExcluded,
		"連線票證、WebSocket 與以既存秘密連線的路由不對 API token 開放"},
	{"TokenFacts{}", "internal/modules/authz/access_request_revoke_scope.go", "factsOfUser", 2, classOperator, dispRouteExcluded,
		"申請單撤銷的資格判定；申請與簽核路由不對 API token 開放"},
	{"Principal{}", "internal/modules/authz/access_request_revoke_scope.go", "AuthorizationWriteScope.AllAssetsInScope", 1, classOperator, dispRouteExcluded,
		"申請單撤銷交易內的範圍判定；申請與簽核路由不對 API token 開放"},

	// 目標保護資格
	{"TokenFacts{}", "internal/modules/identity/assignment_guard.go", "AssignmentGuard.Check", 1, classTarget, dispFullIdentity,
		"被指派帳號是否為超級管理者，不得套用操作者的限定"},
	{"TokenFacts{}", "internal/modules/identity/protected_account_ops.go", "ProtectedAccountOps.Gate", 1, classTarget, dispFullIdentity,
		"被操作帳號是否持保護角色，不得套用操作者的限定"},
	{"TokenFacts{}", "internal/modules/authz/self_grant_guard.go", "SelfGrantGuard.CheckOwnerTransfer", 1, classTarget, dispFullIdentity,
		"agent 新擁有者帳號的連線豁免資格"},

	// 清單與投影
	{"TokenFacts{}", "internal/modules/identity/role_assignment_projection.go", "RoleProjector.AccountOps", 1, classProjection, dispFullIdentity,
		"帳號詳情的目標分類（操作者的重解取請求主體的事實）"},
	{"TokenFacts{}", "internal/modules/authz/permission_overview.go", "PermissionOverviewService.subjectOf", 1, classProjection, dispFullIdentity,
		"權限總覽的被檢視帳號"},
	{"TokenFacts{}", "internal/modules/authz/capability_preview.go", "previewSubject", 1, classProjection, dispFullIdentity,
		"能力預覽受影響帳號的起點"},
	{"TokenFacts{}", "internal/modules/authz/capability_preview.go", "evalState", 1, classProjection, dispFullIdentity,
		"能力預覽以模擬後的指派計算受影響帳號"},
	{"TokenFacts{}", "internal/modules/authz/capability_preview_counts.go", "previewManagedAssetCounts", 1, classProjection, dispFullIdentity,
		"能力預覽的受管資產計數"},
	{"TokenFacts{}", "internal/modules/authz/capability_preview_mapping_rule.go", "LoadSubjectState", 1, classProjection, dispFullIdentity,
		"映射規則預覽命中帳號的起點"},
	{"TokenFacts{}", "internal/modules/authz/grant_summary.go", "SummarizeGrants", 1, classProjection, dispFullIdentity,
		"授權變更分級量的是帳號實際得到或失去什麼"},

	// 獨立的帳密驗證
	{"TokenFacts{}", "internal/modules/identity/local_admin_invariant.go", "hasEffectiveGlobalSuperAdmin", 1, classCredentialCheck, dispNotApplicable,
		"封印期以本文帳密指認的帳號，與請求主體無關"},

	// 背景作業
	{"Principal{}", "internal/modules/authz/credential_ownership_scope.go", "CredentialActorPrincipal", 1, classBackground, dispFullIdentity,
		"只在帶背景發起者標示（且不是請求脈絡）時以帳號完整身分重驗；其餘缺主體一律拒絕"},
	{"TokenFacts{}", "cmd/server/stage2.go", "runStage2", 1, classBackground, dispRouteExcluded,
		"稽核匯出工作的申請者重驗；稽核匯出路由不對 API token 開放"},
	{"var TokenFacts", "internal/api/recording_handler.go", "RecordingHandler.IssueRecordingToken", 1, classBackground, dispRouteExcluded,
		"錄影存取權杖的事實取自請求主體；錄影路由不對 API token 開放"},

	// 不涉及帳號
	{"TokenFacts{}", "internal/modules/authz/grant_summary.go", "assignmentIsManagement", 1, classNoAccount, dispNotApplicable,
		"以單筆指派判定是否管理類"},
	{"TokenFacts{}", "internal/modules/authz/scope_assignments.go", "principalFromAssignments", 1, classNoAccount, dispNotApplicable,
		"以呼叫端給定的假設指派建主體"},
	{"TokenFacts{}", "internal/modules/authz/role_preview.go", "PreviewRole", 1, classNoAccount, dispNotApplicable,
		"單一角色的能力預覽"},
}

// minPrincipalGuardPackages 載入包數下限：掃描根錯置或載入失敗時不在近乎空集合下假綠。
const minPrincipalGuardPackages = 30

// minPrincipalConstructionHits 命中數下限（現況見清冊；整批消失代表型別比對失配）。
const minPrincipalConstructionHits = 25

type constructionScan struct {
	Packages int
	Sites    map[string][]string // "kind|file|fn" → file:line
	Hits     int
}

func loadModulePackages(t *testing.T) ([]*packages.Package, *token.FileSet, string) {
	t.Helper()
	root := guardModuleRoot(t)
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps,
		Dir: root, Fset: fset, Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) < minPrincipalGuardPackages {
		t.Fatalf("只載入 %d 個包（下限 %d）：掃描範圍已失真", len(pkgs), minPrincipalGuardPackages)
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			t.Fatalf("包 %s 有 %d 個載入／型別錯誤（首個：%v）：拒絕在殘缺的 AST 上作判定",
				p.PkgPath, len(p.Errors), p.Errors[0])
		}
	}
	return pkgs, fset, root
}

// isAuthzNamed 型別是否為 authz 套件內指定名稱的具名型別。
func isAuthzNamed(t types.Type, name string) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj() == nil || n.Obj().Pkg() == nil {
		return false
	}
	return n.Obj().Pkg().Path() == authzPkgPath && n.Obj().Name() == name
}

func funcDisplayName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if idx, ok := typ.(*ast.IndexExpr); ok {
		typ = idx.X
	}
	if ident, ok := typ.(*ast.Ident); ok {
		return ident.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// enclosingFunc 回傳 pos 所在的頂層函式顯示名；檔案層級記為 <file-scope>。
func enclosingFunc(f *ast.File, pos token.Pos) string {
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && pos >= fd.Pos() && pos < fd.End() {
			return funcDisplayName(fd)
		}
	}
	return "<file-scope>"
}

func relPath(root, abs string) string {
	r, err := filepath.Rel(root, abs)
	if err != nil {
		return abs
	}
	return filepath.ToSlash(r)
}

func scanPrincipalConstructions(t *testing.T) constructionScan {
	t.Helper()
	pkgs, fset, root := loadModulePackages(t)
	scan := constructionScan{Packages: len(pkgs), Sites: map[string][]string{}}
	record := func(f *ast.File, kind string, pos token.Pos) {
		file := relPath(root, fset.Position(f.Pos()).Filename)
		key := kind + "|" + file + "|" + enclosingFunc(f, pos)
		scan.Sites[key] = append(scan.Sites[key], fmt.Sprintf("%s:%d", file, fset.Position(pos).Line))
		scan.Hits++
	}
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			if strings.HasSuffix(fset.Position(f.Pos()).Filename, "_test.go") {
				continue
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					tv, ok := p.TypesInfo.Types[x]
					if !ok {
						return true
					}
					switch {
					case isAuthzNamed(tv.Type, "TokenFacts"):
						record(f, "TokenFacts{}", x.Pos())
					case isAuthzNamed(tv.Type, "Principal"):
						record(f, "Principal{}", x.Pos())
					}
				case *ast.ValueSpec:
					if len(x.Values) != 0 {
						return true
					}
					for _, name := range x.Names {
						if obj := p.TypesInfo.Defs[name]; obj != nil && isAuthzNamed(obj.Type(), "TokenFacts") {
							record(f, "var TokenFacts", name.Pos())
						}
					}
				case *ast.CallExpr:
					// new(authz.TokenFacts) 同為零值建構
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
						if tv, ok := p.TypesInfo.Types[x.Args[0]]; ok && isAuthzNamed(tv.Type, "TokenFacts") {
							record(f, "var TokenFacts", x.Pos())
						}
					}
				}
				return true
			})
		}
	}
	return scan
}

// diffRegistry 雙向比對清冊與掃描結果：回傳未登記（或超出次數）與登記了卻不存在（或次數不足）的描述。
func diffRegistry(sites map[string][]string, registered map[string]int) (extra, missing []string) {
	keys := map[string]bool{}
	for k := range sites {
		keys[k] = true
	}
	for k := range registered {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	for _, k := range ordered {
		got, want := len(sites[k]), registered[k]
		switch {
		case got > want:
			extra = append(extra, fmt.Sprintf("%s：實際 %d 處、登記 %d 處 %v", k, got, want, sites[k]))
		case got < want:
			missing = append(missing, fmt.Sprintf("%s：登記 %d 處、實際 %d 處", k, want, got))
		}
	}
	return extra, missing
}

func validClass(c string) bool {
	switch c {
	case classRequestPrincipal, classOperator, classTarget, classProjection, classCredentialCheck,
		classBackground, classNoAccount, classResolver:
		return true
	}
	return false
}

func validDisposition(d string) bool {
	switch d {
	case dispCarriesFilter, dispFullIdentity, dispRouteExcluded, dispNotApplicable:
		return true
	}
	return false
}

// TestPrincipalConstructionSitesRegistered 授權主體建構點清冊守衛（雙向）。
func TestPrincipalConstructionSitesRegistered(t *testing.T) {
	scan := scanPrincipalConstructions(t)
	t.Logf("主體建構點命中數=%d（下限 %d）／載入包數=%d", scan.Hits, minPrincipalConstructionHits, scan.Packages)
	if scan.Hits < minPrincipalConstructionHits {
		t.Fatalf("只掃到 %d 處建構點（下限 %d）：型別比對或掃描根失配，此時「沒有未登記的建構點」不成立",
			scan.Hits, minPrincipalConstructionHits)
	}
	registered := map[string]int{}
	for _, s := range principalConstructionSites {
		if !validClass(s.class) || !validDisposition(s.disposition) || strings.TrimSpace(s.why) == "" {
			t.Errorf("清冊項 %s|%s|%s 的分類、處置或理由不完整", s.kind, s.file, s.fn)
		}
		registered[s.kind+"|"+s.file+"|"+s.fn] += s.count
	}
	extra, missing := diffRegistry(scan.Sites, registered)
	for _, e := range extra {
		t.Errorf("未登記的主體建構點（登記分類與處置後才可新增；事實應取自請求主體）：%s", e)
	}
	for _, m := range missing {
		t.Errorf("清冊登記的建構點已不存在（請同步移除或更正）：%s", m)
	}
}
