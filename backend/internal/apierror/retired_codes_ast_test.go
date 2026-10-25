package apierror

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 退役能力拒絕碼守衛
//
// 語義：RetiredDenialCodes() 列出的碼不得再被生產碼寫出。掃描範圍為 internal/ 與
// cmd/ 的全部非測試檔；凡引用退役碼的常數名或字串字面值即報，不論寫出形式
// （Respond、RespondInternal、Write 的 ErrorResponse、連線閘 Deny／DenyInternal、
// PrincipalError 建構、裸字串、經由變數轉手）。以「引用」而非「呼叫引數」為判準，
// 是為了讓先存進變數再傳入的寫法也無處可躲。
//
// 唯二排除：宣告退役常數本身的 register 規格，與 retired_codes.go 的清單函式。
// ---------------------------------------------------------------------------

// convergedDenialCodes 是 1.2「收斂」碼集合（共 8 個），退役清單等於它減去
// CodePermissionDenied。來源：拒絕碼盤點中標為「收斂」的碼。
var convergedDenialCodes = []ErrCode{
	"AUTH_ROLE_REQUIRED",
	"AUTH_TAG_LIST_PRIVILEGED_ONLY",
	"AUTH_TAG_GOVERNANCE_ADMIN_ONLY",
	"AUTH_SESSION_TERMINATE_ADMIN_ONLY",
	"AUTH_MONITOR_ROLE_REQUIRED",
	"AUTH_APPROVER_REQUIRED",
	"AUTH_ROLE_ASSIGNMENT_FORBIDDEN",
	"AUTH_PERMISSION_DENIED",
}

// retiredScanDirs 是掃描根（相對 backend/）。
var retiredScanDirs = []string{"internal", "cmd"}

// retiredListFile 是清單函式所在檔，守衛排除其中的 RetiredDenialCodes 函式。
const retiredListFile = "internal/apierror/retired_codes.go"

// minRetiredScanFiles 防空集合假綠：掃描檔數低於此值視為掃描根失真。
const minRetiredScanFiles = 300

type retiredHit struct {
	File string
	Line int
	Form string
	Ref  string
}

func (h retiredHit) String() string {
	return h.File + ":" + strconv.Itoa(h.Line) + " [" + h.Form + "] " + h.Ref
}

// retiredIdentNames 由 apierror 套件自己的 register 規格導出「退役碼字串 → 常數名」，
// 不手抄常數名；任何一個退役碼找不到宣告常數即回報。
func retiredIdentNames(t *testing.T) map[string]string {
	t.Helper()
	want := map[string]bool{}
	for _, c := range RetiredDenialCodes() {
		want[string(c)] = true
	}
	files, err := collectScanFiles(backendRoot(), []string{"internal/apierror"})
	if err != nil {
		t.Fatalf("collect apierror files: %v", err)
	}
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, rel := range files {
		f, err := parser.ParseFile(fset, filepath.Join(backendRoot(), filepath.FromSlash(rel)), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				call, ok := vs.Values[0].(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					continue
				}
				if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "register" {
					continue
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				s, _ := strconv.Unquote(lit.Value)
				if want[s] {
					out[s] = vs.Names[0].Name
				}
			}
		}
	}
	for c := range want {
		if out[c] == "" {
			t.Fatalf("退役碼 %s 找不到以 register 宣告的常數：無法導出常數名，守衛會漏掉常數引用", c)
		}
	}
	return out
}

// scanRetiredRefs 掃一個檔，回傳引用退役碼的命中。skipFuncs 為要整段略過的函式名。
func scanRetiredRefs(fset *token.FileSet, f *ast.File, rel string, codes, idents map[string]string, skipFuncs map[string]bool) []retiredHit {
	identSet := map[string]string{}
	for code, name := range idents {
		identSet[name] = code
	}
	var hits []retiredHit
	var stack []ast.Node
	record := func(n ast.Node, ref string) {
		hits = append(hits, retiredHit{File: rel, Line: fset.Position(n.Pos()).Line, Form: retiredForm(stack), Ref: ref})
	}
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if fd, ok := n.(*ast.FuncDecl); ok && skipFuncs[fd.Name.Name] {
			return false
		}
		if vs, ok := n.(*ast.ValueSpec); ok && strings.HasPrefix(rel, "internal/apierror/") {
			// 宣告退役常數本身的 register 規格不算引用；同區塊的其他規格照掃。
			for _, nm := range vs.Names {
				if _, isRetired := identSet[nm.Name]; isRetired {
					return false
				}
			}
		}
		stack = append(stack, n)
		switch x := n.(type) {
		case *ast.Ident:
			if _, ok := identSet[x.Name]; ok {
				record(x, x.Name)
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if s, err := strconv.Unquote(x.Value); err == nil {
					if _, ok := codes[s]; ok {
						record(x, strconv.Quote(s))
					}
				}
			}
		}
		return true
	}
	ast.Inspect(f, visit)
	return hits
}

// retiredForm 依命中點的祖先判斷寫出形式；最內層的已知形式優先。
func retiredForm(stack []ast.Node) string {
	for i := len(stack) - 1; i >= 0; i-- {
		switch x := stack[i].(type) {
		case *ast.CompositeLit:
			switch typeName(x.Type) {
			case "PrincipalError":
				return "PrincipalError 建構"
			case "ErrorResponse":
				return "apierror.Write 的 ErrorResponse"
			}
		case *ast.CallExpr:
			switch typeName(x.Fun) {
			case "Respond":
				return "apierror.Respond"
			case "RespondInternal":
				return "apierror.RespondInternal"
			case "Write":
				return "apierror.Write"
			case "Deny":
				return "連線閘 Deny"
			case "DenyInternal":
				return "連線閘 DenyInternal"
			}
		}
	}
	return "其他引用（變數、欄位、回傳值）"
}

func typeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

// retiredHitsInSource 對一段原始碼跑同一個掃描（反例用），檔名當作非 apierror 檔。
func retiredHitsInSource(t *testing.T, src string, codes, idents map[string]string) []retiredHit {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	return scanRetiredRefs(fset, f, "internal/synthetic/synthetic.go", codes, idents, nil)
}

func retiredMaps(t *testing.T) (codes, idents map[string]string) {
	idents = retiredIdentNames(t)
	codes = map[string]string{}
	for c := range idents {
		codes[c] = c
	}
	return codes, idents
}

func TestRetiredDenialCodesNotEmitted(t *testing.T) {
	// 1. 清單恰等於收斂碼減 AUTH_PERMISSION_DENIED，且與登記、三語譯文一致。
	wantSet := map[string]bool{}
	for _, c := range convergedDenialCodes {
		if c != CodePermissionDenied {
			wantSet[string(c)] = true
		}
	}
	gotSet := map[string]bool{}
	for _, c := range RetiredDenialCodes() {
		if gotSet[string(c)] {
			t.Errorf("退役清單重複：%s", c)
		}
		gotSet[string(c)] = true
	}
	if len(wantSet) != 7 || !equalStringSets(wantSet, gotSet) {
		t.Errorf("退役清單 %v 不等於收斂碼減 AUTH_PERMISSION_DENIED（%v）", keysOf(gotSet), keysOf(wantSet))
	}
	if gotSet[string(CodePermissionDenied)] {
		t.Errorf("AUTH_PERMISSION_DENIED 是收斂後的單一形狀，不得列為退役")
	}

	dir := localeDir(t)
	byLocale := map[string]map[string]string{}
	for _, l := range locales {
		byLocale[l] = loadAPIError(t, dir, l)
	}
	for _, c := range RetiredDenialCodes() {
		if !IsRegistered(c) {
			t.Errorf("退役碼 %s 不在登記：登記要保留給舊版前端相容", c)
		}
		for _, l := range locales {
			if byLocale[l][string(c)] == "" {
				t.Errorf("退役碼 %s 在 %s 的 apiError 譯文缺失：譯文要保留給舊版前端", c, l)
			}
		}
	}

	// 2. 生產碼 0 命中。
	codes, idents := retiredMaps(t)
	root := backendRoot()
	files, err := collectScanFiles(root, retiredScanDirs)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(files) < minRetiredScanFiles {
		t.Fatalf("只掃到 %d 個檔（下限 %d）：掃描根失真，守衛會在空集合下假綠", len(files), minRetiredScanFiles)
	}
	var hits []string
	sawList := false
	fset := token.NewFileSet()
	for _, rel := range files {
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		var skip map[string]bool
		if rel == retiredListFile {
			sawList = true
			skip = map[string]bool{"RetiredDenialCodes": true}
		}
		for _, h := range scanRetiredRefs(fset, f, rel, codes, idents, skip) {
			hits = append(hits, h.String())
		}
	}
	if !sawList {
		t.Fatalf("掃描沒有涵蓋 %s：排除規則無從驗證", retiredListFile)
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		t.Errorf("生產碼引用了 %d 處退役能力拒絕碼（能力拒絕一律走 CodePermissionDenied 的單一形狀）：\n  %s",
			len(hits), strings.Join(hits, "\n  "))
	}
}

// 合成原始碼反例：每種寫出形式至少一段，必須被報且形式標籤正確；
// 另有不應被報的對照（單一形狀的碼）。
func TestRetiredDenialCodesGuardDetectsForms(t *testing.T) {
	codes, idents := retiredMaps(t)
	cases := []struct {
		name string
		src  string
		form string
	}{
		{"Respond", `package p
func f(c *gin.Context) { apierror.Respond(c, 403, apierror.CodeRoleRequired, nil) }`, "apierror.Respond"},
		{"RespondInternal", `package p
func f(c *gin.Context) { apierror.RespondInternal(c, 403, apierror.CodeApproverRequired, nil) }`, "apierror.RespondInternal"},
		{"Write 的 ErrorResponse", `package p
func f(c *gin.Context) { apierror.Write(c, 403, apierror.ErrorResponse{Code: apierror.CodeTagGovernanceAdminOnly}) }`, "apierror.Write 的 ErrorResponse"},
		{"ErrorResponse 先建後傳", `package p
func f() apierror.ErrorResponse { return apierror.ErrorResponse{Code: apierror.CodeTagListPrivilegedOnly} }`, "apierror.Write 的 ErrorResponse"},
		{"連線閘 Deny", `package p
func f() { _ = connectgate.Deny(403, string(apierror.CodeMonitorRoleRequired), nil) }`, "連線閘 Deny"},
		{"連線閘 DenyInternal", `package p
func f() { _ = connectgate.DenyInternal(403, string(apierror.CodeSessionTerminateAdminOnly), nil) }`, "連線閘 DenyInternal"},
		{"PrincipalError 建構", `package p
var e = &identity.PrincipalError{Code: apierror.CodeAuthRoleAssignmentForbidden, Status: 403}`, "PrincipalError 建構"},
		{"裸字串碼", `package p
func f(c *gin.Context) { apierror.Respond(c, 403, apierror.ErrCode("AUTH_ROLE_REQUIRED"), nil) }`, "apierror.Respond"},
		{"經由變數轉手", `package p
func f(c *gin.Context) {
	code := apierror.CodeSessionTerminateAdminOnly
	apierror.Respond(c, 403, code, nil)
}`, "其他引用（變數、欄位、回傳值）"},
		{"套件內同名裸識別字", `package p
func f(c *gin.Context) { Respond(c, 403, CodeRoleRequired, nil) }`, "apierror.Respond"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := retiredHitsInSource(t, tc.src, codes, idents)
			if len(hits) == 0 {
				t.Fatalf("守衛沒有報出引用退役碼的合成原始碼")
			}
			found := false
			for _, h := range hits {
				if h.Form == tc.form {
					found = true
				}
			}
			if !found {
				t.Errorf("命中形式 %v 不含預期的 %q", hits, tc.form)
			}
		})
	}

	t.Run("單一形狀的碼與無關字串不報", func(t *testing.T) {
		src := `package p
func f(c *gin.Context) {
	apierror.Respond(c, 403, apierror.CodePermissionDenied, nil)
	_ = "AUTH_PERMISSION_DENIED"
	_ = "AUTH_ROLE_REQUIREDX"
}`
		if hits := retiredHitsInSource(t, src, codes, idents); len(hits) != 0 {
			t.Errorf("不應命中卻命中：%v", hits)
		}
	})
}
