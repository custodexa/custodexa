package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 間接寫入審計細節的來源登記。擴充方式：
//   - denialIndirectWriters：把細節併入請求審計細節的 helper 函式名；任何非測試檔對它的呼叫，
//     其 map 字面值引數的鍵都會納入重疊檢查（全 internal 掃描，不需逐檔登記）。
//   - denialIndirectDiffFiles：以區域 map 變數累積鍵、由呼叫端再整包設為審計細節的檔，
//     值為該變數名；僅掃該變數的索引賦值（避免誤收同檔無關的 map）。
var denialIndirectWriters = map[string]bool{"mergeAuditDetails": true}

var denialIndirectDiffFiles = map[string]string{
	filepath.Join("modules", "identity", "user_service.go"): "diff",
}

func strLit(e ast.Expr) (string, bool) {
	if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
		if s, err := strconv.Unquote(b.Value); err == nil {
			return s, true
		}
	}
	return "", false
}

// indirectAuditDetailKeysIn 回傳檔內經間接路徑寫入審計細節的鍵。diffVar 為空則不掃索引賦值。
func indirectAuditDetailKeysIn(t *testing.T, path string, src []byte, diffVar string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	require.NoError(t, err, path)
	var keys []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			var name string
			switch fn := x.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			if !denialIndirectWriters[name] {
				return true
			}
			for _, a := range x.Args {
				if cl, ok := a.(*ast.CompositeLit); ok {
					for _, el := range cl.Elts {
						if kv, ok := el.(*ast.KeyValueExpr); ok {
							if s, ok := strLit(kv.Key); ok {
								keys = append(keys, s)
							}
						}
					}
				}
			}
		case *ast.AssignStmt:
			if diffVar == "" {
				return true
			}
			for _, l := range x.Lhs {
				if ix, ok := l.(*ast.IndexExpr); ok {
					if id, ok := ix.X.(*ast.Ident); ok && id.Name == diffVar {
						if s, ok := strLit(ix.Index); ok {
							keys = append(keys, s)
						}
					}
				}
			}
		}
		return true
	})
	return keys
}

// collectIndirectDenialKeys 掃 internal 全部非測試檔的間接寫入鍵，回傳 鍵 -> 檔案。
func collectIndirectDenialKeys(t *testing.T) map[string][]string {
	t.Helper()
	found := map[string][]string{}
	root := filepath.Join("..", "..", "internal")
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		diffVar := denialIndirectDiffFiles[rel]
		callsWriter := false
		for w := range denialIndirectWriters {
			if strings.Contains(string(src), w+"(") {
				callsWriter = true
			}
		}
		if !callsWriter && diffVar == "" {
			return nil
		}
		for _, k := range indirectAuditDetailKeysIn(t, path, src, diffVar) {
			found[k] = append(found[k], rel)
		}
		return nil
	}))
	return found
}

func overlapWithDenialKeys(keys []string) []string {
	var hit []string
	for _, k := range keys {
		for _, n := range denialNewKeys {
			if k == n {
				hit = append(hit, k)
			}
		}
	}
	return hit
}

func TestDenialIndirectWritersDisjoint(t *testing.T) {
	found := collectIndirectDenialKeys(t)
	files := map[string]bool{}
	var all []string
	for k, fs := range found {
		all = append(all, k)
		for _, f := range fs {
			files[f] = true
		}
	}
	sort.Strings(all)
	t.Logf("EVIDENCE indirect keys (%d): %v", len(all), all)
	for f := range files {
		t.Logf("EVIDENCE indirect file: %s", f)
	}
	require.True(t, files[filepath.Join("sshproxy", "connect_gates.go")], "正向對照：須掃到 connect_gates.go")
	require.True(t, files[filepath.Join("modules", "identity", "user_service.go")], "正向對照：須掃到 user_service.go")
	for _, k := range []string{"recording_exemption", "email.before"} {
		require.NotEmpty(t, found[k], "正向對照：須掃到間接鍵 %q", k)
	}
	for _, k := range denialNewKeys {
		assert.Empty(t, found[k], "間接寫入點使用了本段新增鍵 %q：%v", k, found[k])
	}
}

func TestDenialIndirectScanCatchesOverlap(t *testing.T) {
	direct := []byte(`package x
func f(c C) { c.Set("audit_details", map[string]string{"denial": "x"}) }`)
	viaHelper := []byte(`package x
func g(c C) { mergeAuditDetails(c, map[string]string{"basis": "x", "ok": "y"}) }`)
	viaDiff := []byte(`package x
func h() { diff := map[string]string{}; diff["count"] = "1" }`)
	assert.Equal(t, []string{"denial"}, overlapWithDenialKeys(auditDetailKeysIn(t, "d.go", direct)), "直接寫入反例須被報")
	assert.Equal(t, []string{"basis"}, overlapWithDenialKeys(indirectAuditDetailKeysIn(t, "h.go", viaHelper, "")), "經間接 helper 反例須被報")
	assert.Equal(t, []string{"count"}, overlapWithDenialKeys(indirectAuditDetailKeysIn(t, "u.go", viaDiff, "diff")), "diff 索引賦值反例須被報")
}
