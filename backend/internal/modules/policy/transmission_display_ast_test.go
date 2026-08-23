package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 後端顯示字串 i18n 的全域 AST 守衛：
// risk 項只能經 newRisk（含 label）或 riskItemsFromKeys（key-only fingerprint）產生、
// inventory note/preflight 只能經 setNote/setPreflight 設定。任何他處直接建 risk 字面量
// （含 alias import／指標/map elision）或設 InventoryChannel 的 Note/StrictPreflight，都繞過
// registry 與完備性測試，一律禁止。
//
// Scope note：本 detector 為 AST 語法層，無 go/types。已涵蓋：alias import 的
// `X.TransmissionRisk`、`RiskItem` alias、`[]T`/`[]*T`/`map[K]T` elision。無法涵蓋的殘餘
// （具名切片型別 `type Risks []RiskItem` 的 elision、以型別別名間接命名）需 go/types 才能
// 判定，屬已知限制；此類實務罕見，且完備性 bijection 測試為第二道防線。

// sanctionedDisplayFuncs 唯一可建 risk 字面量／設 inventory Note/StrictPreflight 的建構子，
// 精確到 (檔名, 函式名)——同名函式在他檔不豁免。
var sanctionedDisplayFuncs = map[string]string{
	"newRisk":           "transmission_policy_service.go",
	"riskItemsFromKeys": "transmission_consent_service.go",
	"setNote":           "transmission_inventory_service.go",
	"setPreflight":      "transmission_inventory_service.go",
}

// minInternalScannedFiles internal/ 掃描的檔數下限（防空集合假綠）。
// 2026-08-09 實測 257 檔（見 internalGoFiles 的 t.Logf），門檻取 230。
const minInternalScannedFiles = 230

func internalGoFiles(t *testing.T) []string {
	t.Helper()
	// 掃描根以 go.mod module 身分為錨（repoRoot，見 aad_write_guard_test.go）：
	// 原先是「本測試檔所在目錄的上一層」，與本 package 的樹深綁死——package
	// 下移一層即掃到 internal/<模組>/ 這一小塊，其餘 internal 全成免檢區，
	// 而「掃不到裸字面量」與「沒有裸字面量」在斷言上不可分辨。
	internalDir := filepath.Join(repoRoot(t), "internal")
	var files []string
	err := filepath.Walk(internalDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	if len(files) < minInternalScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d，掃描根 %s）：掃描範圍已失真，"+
			"守衛將在近乎空集合下假綠。若目錄結構改變，改的是掃描根而不是下限",
			len(files), minInternalScannedFiles, internalDir)
	}
	t.Logf("transmission-display AST 守衛掃描檔數=%d（下限 %d）", len(files), minInternalScannedFiles)
	return files
}

// derefType unwraps *T → T.
func derefType(e ast.Expr) ast.Expr {
	if s, ok := e.(*ast.StarExpr); ok {
		return s.X
	}
	return e
}

// isRiskType reports whether e names the risk struct: `RiskItem` (alias) or any
// `X.TransmissionRisk` selector (catches an aliased model import, e.g. `m.TransmissionRisk`).
func isRiskType(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "RiskItem"
	case *ast.SelectorExpr:
		return v.Sel.Name == "TransmissionRisk"
	}
	return false
}

// riskContainerElem returns the element type of a []T / [N]T / map[K]T literal, else nil —
// so elided element literals `[]RiskItem{{...}}`, `[]*RiskItem{{...}}`, `map[K]RiskItem{...}`
// can be detected via the container type.
func riskContainerElem(e ast.Expr) ast.Expr {
	switch v := e.(type) {
	case *ast.ArrayType:
		return v.Elt
	case *ast.MapType:
		return v.Value
	}
	return nil
}

func isInventoryType(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "InventoryChannel"
}

func compositeHasIdentField(cl *ast.CompositeLit, name string) bool {
	for _, elt := range cl.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == name {
				return true
			}
		}
	}
	return false
}

// scanDisplayViolations flags, outside the sanctioned (file, func) constructors:
//
//	(1) any risk composite literal — direct `RiskItem{...}` / `X.TransmissionRisk{...}`, or an
//	    elided element inside a `[]T` / `[]*T` / `map[K]T` risk container (any field, incl key-only,
//	    since a bare key-only literal outside riskItemsFromKeys also bypasses the registry);
//	(2) an InventoryChannel composite literal that sets Note or StrictPreflight;
//	(3) an assignment to a .Note or .StrictPreflight selector.
func scanDisplayViolations(fset *token.FileSet, f *ast.File, base string) []string {
	var out []string
	loc := func(n ast.Node) string { return base + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) }

	check := func(node ast.Node) {
		ast.Inspect(node, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CompositeLit:
				// direct risk literal (composite type can't be *T in Go, but be defensive)
				if isRiskType(derefType(v.Type)) {
					out = append(out, loc(v)+" (risk literal — use newRisk/riskItemsFromKeys)")
				}
				// elided element literals inside a risk container
				if elem := riskContainerElem(v.Type); elem != nil && isRiskType(derefType(elem)) {
					for _, elt := range v.Elts {
						cl := elt
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							cl = kv.Value // map element value
						}
						if inner, ok := cl.(*ast.CompositeLit); ok {
							out = append(out, loc(inner)+" (risk element literal — use newRisk/riskItemsFromKeys)")
						}
					}
				}
				if isInventoryType(v.Type) && (compositeHasIdentField(v, "Note") || compositeHasIdentField(v, "StrictPreflight")) {
					out = append(out, loc(v)+" (InventoryChannel literal sets Note/StrictPreflight — use setNote/setPreflight)")
				}
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Note" || sel.Sel.Name == "StrictPreflight") {
						out = append(out, loc(v)+" (assign ."+sel.Sel.Name+" — use setNote/setPreflight)")
					}
				}
			}
			return true
		})
	}

	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			// skip only if this exact (file, function) is sanctioned
			if expFile, sanctioned := sanctionedDisplayFuncs[fn.Name.Name]; sanctioned && expFile == base {
				continue
			}
			check(fn)
		} else {
			check(decl)
		}
	}
	return out
}

// TestNoBareDisplayLiterals is the acceptance gate: no production file outside
// the sanctioned constructors may build a risk item or inventory note/preflight directly.
func TestNoBareDisplayLiterals(t *testing.T) {
	fset := token.NewFileSet()
	var violations []string
	for _, path := range internalGoFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		violations = append(violations, scanDisplayViolations(fset, f, filepath.Base(path))...)
	}
	if len(violations) > 0 {
		t.Errorf("bare display literals bypassing registry (%d):\n  %s", len(violations), strings.Join(violations, "\n  "))
	}
}

// TestDisplayASTDetectorsCatchViolations proves the scanner flags each bypass form (so the gate
// is not a false-green) and does NOT flag the in-file sanctioned constructors.
func TestDisplayASTDetectorsCatchViolations(t *testing.T) {
	// Parsed AS transmission_policy_service.go so the in-file `newRisk` is treated as sanctioned.
	const snippet = `package sample
func bypass() {
	_ = model.TransmissionRisk{Key: "x", Label: "raw"}   // direct selector
	_ = m.TransmissionRisk{Key: "x", Label: "raw"}       // aliased selector import
	_ = RiskItem{Key: "x", Label: "raw"}                 // alias literal
	_ = []RiskItem{{Key: "x", Label: "raw"}}             // elided array element
	_ = []*RiskItem{{Key: "x"}}                          // elided pointer-array element
	_ = map[string]RiskItem{"a": {Key: "x"}}             // elided map element
	_ = RiskItem{Key: "x"}                               // key-only outside riskItemsFromKeys
	ch := InventoryChannel{Note: "raw"}                  // InventoryChannel literal Note
	ch.Note = "raw"                                      // .Note assignment
	ch.StrictPreflight = "raw"                           // .StrictPreflight assignment
	_ = InventoryChannel{Channel: "ssh"}                 // OK: no Note/StrictPreflight
}
func newRisk() { _ = RiskItem{Key: "x", Label: "ok"} }  // OK: sanctioned in-file
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "transmission_policy_service.go", snippet, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := scanDisplayViolations(fset, f, "transmission_policy_service.go")
	// bypass(): 7 risk literals (2 direct selector + 1 alias + 3 elided + 1 key-only) + 1 inventory literal + 2 assigns = 10
	if len(got) != 10 {
		t.Errorf("got %d violations, want 10:\n  %s", len(got), strings.Join(got, "\n  "))
	}

	// off-file same-named sanctioned function is NOT exempt.
	const offFile = `package sample
func newRisk() { _ = RiskItem{Key: "x", Label: "smuggled"} }
`
	fset2 := token.NewFileSet()
	f2, err := parser.ParseFile(fset2, "elsewhere.go", offFile, 0)
	if err != nil {
		t.Fatalf("parse offFile: %v", err)
	}
	if g := scanDisplayViolations(fset2, f2, "elsewhere.go"); len(g) != 1 {
		t.Errorf("off-file newRisk should be flagged: got %d %v, want 1", len(g), g)
	}
}
