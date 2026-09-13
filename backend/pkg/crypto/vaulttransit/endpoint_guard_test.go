package vaulttransit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Detect explicit bypasses as well as default client or proxy inheritance.
func transportBypasses(source string) (int, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "input.go", source, 0)
	if err != nil {
		return 0, err
	}
	hits := 0
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "http" && (x.Sel.Name == "DefaultClient" || x.Sel.Name == "DefaultTransport" || x.Sel.Name == "ProxyFromEnvironment") {
				hits++
			}
		case *ast.KeyValueExpr:
			if id, ok := x.Key.(*ast.Ident); ok && id.Name == "InsecureSkipVerify" {
				if value, ok := x.Value.(*ast.Ident); !ok || value.Name != "false" {
					hits++
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if s, ok := lhs.(*ast.SelectorExpr); ok && s.Sel.Name == "InsecureSkipVerify" {
					hits++
				}
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "checkedAdapter" && len(x.Args) == 3 {
				if b, ok := x.Args[2].(*ast.Ident); !ok || b.Name != "false" {
					hits++
				}
			}
		}
		return true
	})
	return hits, nil
}
func TestVaultEndpointGuard(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		count, err := transportBypasses(string(body))
		if err != nil || count != 0 {
			t.Fatalf("transport bypass in %s", e.Name())
		}
		scanned++
	}
	if scanned < 4 {
		t.Fatal("scan scope incomplete")
	}
	for _, source := range []string{`package p; var x = http.DefaultClient`, `package p; var x = tls.Config{InsecureSkipVerify:true}`, `package p; func f(){ c.InsecureSkipVerify=true }`, `package p; func f(){ checkedAdapter(origin,tr,true) }`, `package p; var x = http.ProxyFromEnvironment`} {
		hits, err := transportBypasses(source)
		if err != nil || hits == 0 {
			t.Fatal("positive control missed bypass")
		}
	}
	hits, err := transportBypasses(`package p; func f(){ checkedAdapter(origin,tr,false) }; var x = tls.Config{InsecureSkipVerify:false}`)
	if err != nil || hits != 0 {
		t.Fatal("safe control rejected")
	}
}
