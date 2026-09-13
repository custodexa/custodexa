package gcpkms

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

// The scanner follows import aliases and inspects function values as well as calls.
// Production injection is restricted to the owned constructor and fixed ADC setup.
func scanGCPSource(path string, source []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, source, 0)
	if err != nil {
		return nil, err
	}
	aliases := map[string]string{}
	relevant := strings.HasPrefix(path, "pkg/crypto/gcpkms/")
	for _, imp := range f.Imports {
		value, _ := strconv.Unquote(imp.Path.Value)
		name := filepath.Base(value)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		aliases[name] = value
		if value == "cloud.google.com/go/kms/apiv1" || strings.HasSuffix(value, "/crypto/gcpkms") {
			relevant = true
		}
	}
	if !relevant {
		return nil, nil
	}
	var out []string
	report := func(n ast.Node) { out = append(out, path+":"+strconv.Itoa(fset.Position(n.Pos()).Line)) }
	enclosing := func(pos token.Pos) string {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Pos() <= pos && pos <= fn.End() {
				return fn.Name.Name
			}
		}
		return ""
	}
	allowed := func(pos token.Pos, file, fn string) bool {
		return path == "pkg/crypto/gcpkms/"+file && enclosing(pos) == fn
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ImportSpec:
			if node.Name != nil && node.Name.Name == "." {
				report(node)
			}
		case *ast.SelectorExpr:
			id, ok := node.X.(*ast.Ident)
			if !ok {
				break
			}
			pkg := aliases[id.Name]
			name := node.Sel.Name
			if pkg == "google.golang.org/api/option" {
				switch name {
				case "WithLogger", "WithTelemetryDisabled":
					if !allowed(node.Pos(), "transport.go", "resolveExplicit") && !allowed(node.Pos(), "sdk_client.go", "newClient") {
						report(node)
					}
				case "WithHTTPClient":
					if !allowed(node.Pos(), "sdk_client.go", "newClient") {
						report(node)
					}
				case "WithCredentialsJSON":
					// **唯一被授權的認證注入入口**（委託拓撲與憑證改由介面管理）：
					// 認證材料自本版起是顯式輸入，不再由環境自動發現。允許的位置收得
					// 極窄——只有 `resolveExplicit` 這一個函式，且它的參數是呼叫端
					// 交進來的服務帳號金鑰檔內容。任何其他位置出現它，就是第二條
					// 認證來源，而第二條來源正是本掃描器存在的理由。
					if !allowed(node.Pos(), "transport.go", "resolveExplicit") {
						report(node)
					}
				default:
					report(node)
				}
			}
			if pkg == "google.golang.org/api/option/internaloption" && !allowed(node.Pos(), "transport.go", "resolveExplicit") {
				report(node)
			}
			if pkg == "cloud.google.com/go/kms/apiv1" && strings.HasPrefix(name, "New") && (!allowed(node.Pos(), "sdk_client.go", "newClient") || name != "NewKeyManagementRESTClient") {
				report(node)
			}
			if pkg == "google.golang.org/api/transport/http" && name == "NewTransport" && !allowed(node.Pos(), "transport.go", "resolveExplicit") {
				report(node)
			}
		case *ast.KeyValueExpr:
			if id, ok := node.Key.(*ast.Ident); ok {
				switch id.Name {
				case "InsecureSkipVerify", "DialTLS", "DialTLSContext", "Proxy", "ServerName":
					report(node)
				case "Transport", "CheckRedirect":
					if !allowed(node.Pos(), "sdk_client.go", "newClient") {
						report(node)
					}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if s, ok := lhs.(*ast.SelectorExpr); ok {
					switch s.Sel.Name {
					case "InsecureSkipVerify", "DialTLS", "DialTLSContext", "Proxy", "ServerName", "Transport", "CheckRedirect":
						report(node)
					}
				}
			}
		case *ast.CallExpr:
			if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "newClient" {
				// 正式建構只有一條路：`NewClient` 以 `resolveExplicit(<顯式憑證>)`
				// 作為 resolver。改前釘的是裸識別字 `resolveADC`；自憑證改為顯式
				// 注入起，resolver 是一個**帶參數的建構**，故這裡改釘
				// 「呼叫 resolveExplicit 且恰一個參數」——比裸識別字更窄，
				// 因為它同時排除了「傳一個看起來像 resolver 的變數進來」。
				resolver, isCall := node.Args[2].(*ast.CallExpr)
				var resolverName string
				var resolverArgs int
				if isCall {
					if fn, ok := resolver.Fun.(*ast.Ident); ok {
						resolverName = fn.Name
					}
					resolverArgs = len(resolver.Args)
				}
				if !allowed(node.Pos(), "sdk_client.go", "NewClient") || len(node.Args) != 5 ||
					resolverName != "resolveExplicit" || resolverArgs != 1 {
					report(node)
				}
			}
			if node.Ellipsis.IsValid() && !allowed(node.Pos(), "transport.go", "resolveExplicit") {
				report(node)
			}
		}
		return true
	})
	return out, nil
}
func TestGCPEndpointScanner(t *testing.T) {
	root := filepath.Clean("../../..")
	body, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil || !strings.Contains(string(body), "module github.com/custodexa/backend\n") {
		t.Fatal("backend scan root unavailable")
	}
	scanned := 0
	var violations []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" || d.Name() == "tmp" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		found, err := scanGCPSource(filepath.ToSlash(rel), src)
		if err != nil {
			return err
		}
		scanned++
		violations = append(violations, found...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 270 {
		t.Fatal("scanner input unexpectedly small")
	}
	if len(violations) > 0 {
		t.Fatalf("GCP transport injection detected: %v", violations)
	}
	t.Logf("production files scanned=%d", scanned)
}
func TestGCPEndpointScannerControls(t *testing.T) {
	for name, src := range map[string]string{
		"option-alias":          `package gcpkms; import o "google.golang.org/api/option"; func f(){ _ = o.WithEndpoint("http://x") }`,
		"option-function-value": `package gcpkms; import o "google.golang.org/api/option"; var bypass = o.WithoutAuthentication`,
		"token-source":          `package gcpkms; import o "google.golang.org/api/option"; func f(){ _ = o.WithTokenSource(nil) }`,
		"credentials":           `package gcpkms; import o "google.golang.org/api/option"; func f(){ _ = o.WithCredentialsFile("x") }`,
		"http-client":           `package gcpkms; import o "google.golang.org/api/option"; func f(){ _ = o.WithHTTPClient(nil) }`,
		"sdk-direct":            `package gcpkms; import k "cloud.google.com/go/kms/apiv1"; func f(){ k.NewKeyManagementRESTClient(ctx) }`,
		"tls-literal":           `package gcpkms; func f(){ _ = Config{InsecureSkipVerify:true} }`,
		"tls-assignment":        `package gcpkms; func f(){ t.InsecureSkipVerify=true }`,
		"transport-assignment":  `package gcpkms; func f(){ c.Transport=bad }`,
		"constructor-injection": `package gcpkms; func f(){ newClient(ctx,s,bad,base,close) }`,
		"spread-options":        `package gcpkms; func f(){ call(opts...) }`,
	} {
		t.Run(name, func(t *testing.T) {
			out, err := scanGCPSource("pkg/crypto/gcpkms/bypass.go", []byte(src))
			if err != nil || len(out) == 0 {
				t.Fatal("scanner failed to reject injected bypass")
			}
		})
	}
	t.Run("read-only-control", func(t *testing.T) {
		out, err := scanGCPSource("pkg/crypto/gcpkms/read.go", []byte(`package gcpkms; func f(){ _ = t.InsecureSkipVerify }`))
		if err != nil || len(out) != 0 {
			t.Fatal("read mistaken for injection")
		}
	})
	t.Run("parse-failure", func(t *testing.T) {
		if _, err := scanGCPSource("pkg/crypto/gcpkms/broken.go", []byte(`package gcpkms; func {`)); err == nil {
			t.Fatal("malformed source silently accepted")
		}
	})
}
