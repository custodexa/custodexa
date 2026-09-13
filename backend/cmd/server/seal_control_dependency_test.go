package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestSealControlDependencyGuard(t *testing.T) {
	source, err := os.ReadFile("../../internal/modules/identity/seal_authorizer.go")
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "seal_authorizer.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"context": true, "errors": true, "time": true, "github.com/custodexa/backend/internal/model": true, "github.com/custodexa/backend/pkg/crypto": true, "gorm.io/gorm": true}
	for _, imp := range f.Imports {
		if !allowed[strings.Trim(imp.Path.Value, "\"")] {
			t.Fatalf("unexpected control dependency %s", imp.Path.Value)
		}
	}
	fields := 0
	ast.Inspect(f, func(n ast.Node) bool {
		if ts, ok := n.(*ast.TypeSpec); ok && ts.Name.Name == "SealAuthorizer" {
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				t.Fatal("authorizer must remain a struct")
			}
			for _, field := range st.Fields.List {
				for _, name := range field.Names {
					if name.Name != "verify" && name.Name != "db" {
						t.Fatalf("unexpected retained dependency %s", name.Name)
					}
					fields++
				}
			}
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
				switch selector.Sel.Name {
				case "NewAuthService", "GenerateToken", "GenerateScopedToken", "GenerateTokenNotAfter", "DecryptFor", "DecryptBytesFor":
					t.Fatalf("forbidden control dependency %s", selector.Sel.Name)
				}
			}
		}
		return true
	})
	if fields != 2 {
		t.Fatalf("authorizer fields=%d", fields)
	}
	for _, required := range []string{"validateIdentityToken(manager, token)", "VerifyCredentialGenerationTx(", "checkConnectableUser(&user)", "primaryRoleOf(&user)"} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("missing shared identity check %s", required)
		}
	}
	t.Log("control retains JWT verifier and identity DB only; no MFA codec, DEK, login or token issuance")
}
