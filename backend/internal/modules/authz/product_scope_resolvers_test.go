package authz

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 原始碼中宣告的目標種類（扣掉內建三種）必須與 ProductScopeTargetKinds 相等：
// 新增種類卻漏登記解析器時，正式組裝會把該種類的所有判定當成「找不到解析器」。
func TestProductScopeTargetKindsCoverDeclared(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`ScopeTargetKind\s*=\s*"([^"]+)"`)
	builtin := map[string]bool{"asset": true, "asset_account": true, "node": true}
	declared := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			if !builtin[m[1]] {
				declared[m[1]] = true
			}
		}
	}
	registered := map[string]bool{}
	for _, k := range ProductScopeTargetKinds() {
		registered[string(k)] = true
	}
	keys := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	for k := range declared {
		if !registered[k] {
			t.Errorf("target kind %q is declared but not registered in ProductScopeResolvers", k)
		}
	}
	for k := range registered {
		if !declared[k] {
			t.Errorf("target kind %q is registered but no declaration was found", k)
		}
	}
	if len(declared) == 0 {
		t.Fatalf("no declared kinds found; scan is broken (registered: %v)", keys(registered))
	}
}

func TestProductScopeResolversFreshSlices(t *testing.T) {
	a := ProductScopeResolvers()
	a[0].Kind = "zz_mutated"
	if ProductScopeResolvers()[0].Kind == "zz_mutated" {
		t.Fatal("ProductScopeResolvers must return a fresh slice")
	}
	if len(ProductScopeResolvers()) != len(ProductScopeTargetKinds()) {
		t.Fatalf("resolver count %d differs from declared kind count %d", len(ProductScopeResolvers()), len(ProductScopeTargetKinds()))
	}
	e := NewScopeEvaluator(ProductCatalogue(), nil, ProductScopeResolvers()...)
	for _, k := range ProductScopeTargetKinds() {
		if !e.HasResolver(k) {
			t.Errorf("evaluator lacks resolver for %s", k)
		}
	}
	if e.HasResolver("zz_none") {
		t.Fatal("HasResolver true for unknown kind")
	}
}
