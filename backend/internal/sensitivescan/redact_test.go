package sensitivescan

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	r := builtinRules(t)
	secret := []string{"4111111111111111", "378282246310005", "-----BEGIN RSA PRIVATE KEY-----"}
	input := strings.Join(secret, "\n")
	output, count := r.Redact(input)
	if count != 3 || output != strings.Join([]string{RedactionPlaceholder, RedactionPlaceholder, RedactionPlaceholder}, "\n") {
		t.Fatalf("redaction: %q %d", output, count)
	}
	for _, v := range secret {
		for i := 0; i+8 <= len(v); i++ {
			if strings.Contains(output, v[i:i+8]) {
				t.Fatal("original 8-byte fragment retained")
			}
		}
	}
	clean := "hello\x1b[0m 世界\n"
	output, count = r.Redact(clean)
	if output != clean || count != 0 {
		t.Fatal("nonmatching text changed")
	}
}

// Wave 4: exactly one delivery-layer callsite; evidence paths remain forbidden.
func TestRedactHasNoProductCallers(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate guard source")
	}
	root := filepath.Dir(source)
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("cannot locate backend module root")
		}
		root = parent
	}

	var callers []string
	fset := token.NewFileSet()
	definition := filepath.Join(root, "internal", "sensitivescan", "redact.go")
	for _, dir := range []string{"internal", "pkg"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == definition {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if ok && selector.Sel.Name == "Redact" {
					fn := "<package>"
					for _, decl := range file.Decls {
						if f, ok := decl.(*ast.FuncDecl); ok && selector.Pos() >= f.Pos() && selector.End() <= f.End() {
							fn = f.Name.Name
							break
						}
					}
					callers = append(callers, fmt.Sprintf("%s:%s", filepath.ToSlash(rel), fn))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", dir, err)
		}
	}
	if !reflect.DeepEqual(callers, []string{"internal/agentmcp/dispatch.go:redactValue"}) {
		t.Fatalf("found %d product .Redact( calls; want only MCP delivery callsite:\n%s", len(callers), strings.Join(callers, "\n"))
	}
}
