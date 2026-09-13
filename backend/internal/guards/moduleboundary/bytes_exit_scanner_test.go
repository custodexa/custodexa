package moduleboundary

import (
	"go/parser"
	"go/token"
	"testing"
)

func TestBytesExitScannerDetectsViolations(t *testing.T) {
	path := "internal/modules/asset/credential_resolver.go"
	refs := map[string]string{"RefCredentialVersionPassword": "credential_secret_versions"}
	for _, tc := range []struct {
		name, source string
		valid        bool
	}{
		{"declared_bytes", `package asset; func (r *CredentialResolver) ResolveForBinding(){r.crypto.DecryptBytesFor(ctx,keyvault.RefCredentialVersionPassword,cipher)}`, true},
		{"unregistered", `package asset; func leak(){codec.DecryptBytesFor(ctx,keyvault.RefCredentialVersionPassword,cipher)}`, false},
		{"renamed_exit", `package asset; func (r *CredentialResolver) Decode(){r.crypto.DecryptBytesFor(ctx,keyvault.RefCredentialVersionPassword,cipher)}`, false},
		{"method_alias", `package asset; func (r *CredentialResolver) ResolveForBinding(){decode:=r.crypto.DecryptBytesFor;decode(ctx,keyvault.RefCredentialVersionPassword,cipher)}`, false},
		{"global_alias", `package asset; var decode=codec.DecryptBytesFor;func (r *CredentialResolver) ResolveForBinding(){decode(ctx,keyvault.RefCredentialVersionPassword,cipher)}`, false},
		{"wrapper", `package asset; func wrapper(ref crypto.CipherRef){codec.DecryptBytesFor(ctx,ref,cipher)};func (r *CredentialResolver) ResolveForBinding(){wrapper(keyvault.RefCredentialVersionPassword)}`, false},
		{"missing_exit", `package asset;func (r *CredentialResolver) ResolveForBinding(){}`, false},
		{"string_adapter", `package asset;func (r *CredentialResolver) ResolveForBinding(){r.crypto.DecryptFor(ctx,keyvault.RefCredentialVersionPassword,cipher)}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, tc.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			seen, bad, unknown := scanCredentialExits(fset, f, path, refs)
			valid := len(bad) == 0 && len(unknown) == 0 && len(seen[path+"#(*CredentialResolver).ResolveForBinding"]) > 0
			if valid != tc.valid {
				t.Fatalf("scanner accepted=%v want=%v violations=%d unresolved=%d seen=%d", valid, tc.valid, len(bad), len(unknown), len(seen))
			}
			t.Logf("accepted=%v violations=%d unresolved=%d observed_exits=%d", valid, len(bad), len(unknown), len(seen))
		})
	}
}
