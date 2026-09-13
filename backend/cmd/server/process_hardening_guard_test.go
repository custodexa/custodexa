package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestProcessHardeningMainFirst(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" || fn.Recv != nil {
			continue
		}
		for _, stmt := range fn.Body.List {
			if _, ok := stmt.(*ast.DeclStmt); ok {
				continue
			}
			var expr ast.Expr
			switch first := stmt.(type) {
			case *ast.IfStmt:
				if init, ok := first.Init.(*ast.AssignStmt); ok && len(init.Rhs) == 1 {
					expr = init.Rhs[0]
				}
			case *ast.AssignStmt:
				if len(first.Rhs) == 1 {
					expr = first.Rhs[0]
				}
			case *ast.ExprStmt:
				expr = first.X
			}
			if call, ok := expr.(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Harden" {
					if name, ok := selector.X.(*ast.Ident); ok && name.Name == "prochardening" {
						return
					}
				}
			}
			t.Fatal("main first non-declaration statement must call prochardening.Harden")
		}
		t.Fatal("main has no executable statements")
	}
	t.Fatal("main function not found")
}
