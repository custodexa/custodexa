package main

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 延後執行的端到端情境（開頭呼叫 apiTokenBaselineGate，含競態偵測的整包步驟以 AUTHZ_BASELINE=deferred 略過）
// 必須有地方真的執行：列在 testdata/ci-deferred-scenarios.txt 的，由 CI 的授權基準步驟與
// scripts/authz_baseline.sh 在基準比對之後執行；其餘列在 deferredLocalOnly 並寫明理由，只在本機整包執行。
// 新增一支延後的情境而兩邊都沒列，本測試失敗。

const deferredScenarioList = "testdata/ci-deferred-scenarios.txt"

// deferredLocalOnly 延後但目前只在本機整包執行的情境與理由。
var deferredLocalOnly = map[string]string{
	"TestAPITokenActorConversionRowsAttributed":         "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenAttachAlertAuditLookup":                "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenAttachAlertSingleActorAndSource":       "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenAttachAuditTrail":                      "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenCreateUserRowsCarryRequestOrigin":      "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenCredentialReferenceParity":             "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenDialOutActionsStayClosed":              "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenLevelsEndToEnd":                        "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenPlanRunScopeRecheckedForVisibleTarget": "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenRouteComparisonAndScope":               "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenScheduledPlanRunRowsNotAttributed":     "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenSelfUnlockViaToken":                    "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestAPITokenServiceRules":                          "API token 端到端情境，尚未排入 CI 的專用步驟",
	"TestExactNameLookupAcrossPrincipals":               "精確查找的端到端情境，尚未排入 CI 的專用步驟",
	"TestWriteResponseMatchesRead":                      "寫入回應與讀取一致的端到端情境，尚未排入 CI 的專用步驟",
}

// gatedTests 本套件測試檔中，函式本體直接呼叫 apiTokenBaselineGate 的頂層測試名稱。
func gatedTests(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) < 50 {
		t.Fatalf("列出測試檔失敗或數量異常（%d）：%v", len(files), err)
	}
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("解析 %s：%v", f, err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "apiTokenBaselineGate" {
						out[fn.Name.Name] = true
					}
				}
				return true
			})
		}
	}
	return out
}

// readDeferredScenarioList 讀取排入 CI 專用步驟的情境名單（略過空行與 # 註解）。
func readDeferredScenarioList(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(deferredScenarioList)
	if err != nil {
		t.Fatalf("讀取 %s：%v", deferredScenarioList, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// checkDeferredScheduled 每一支延後的情境恰在名單或本機清單之一；兩份清單都不含不存在或沒有延後的測試。
func checkDeferredScheduled(gated map[string]bool, ciList []string, localOnly map[string]string) []string {
	var probs []string
	inCI := map[string]bool{}
	for _, name := range ciList {
		if inCI[name] {
			probs = append(probs, name+"：在 CI 名單重複出現")
		}
		inCI[name] = true
		if !gated[name] {
			probs = append(probs, name+"：在 CI 名單內，但不是延後的情境（不存在或沒有呼叫 apiTokenBaselineGate）")
		}
	}
	for name, why := range localOnly {
		if !gated[name] {
			probs = append(probs, name+"：在本機清單內，但不是延後的情境")
		}
		if strings.TrimSpace(why) == "" {
			probs = append(probs, name+"：本機清單要寫理由")
		}
	}
	for name := range gated {
		_, local := localOnly[name]
		switch {
		case inCI[name] && local:
			probs = append(probs, name+"：同時在 CI 名單與本機清單")
		case !inCI[name] && !local:
			probs = append(probs, name+"：延後的情境沒有排入 CI 名單（"+deferredScenarioList+"），也沒有列在本機清單；CI 的整包步驟會略過它")
		}
	}
	sort.Strings(probs)
	return probs
}

func TestDeferredScenariosAreScheduled(t *testing.T) {
	gated := gatedTests(t)
	ciList := readDeferredScenarioList(t)
	for _, name := range []string{"TestManagedResourceReadContract", "TestAssetListPageSizeCapAcrossPaths", "TestSingleReadMatchesList"} {
		found := false
		for _, n := range ciList {
			found = found || n == name
		}
		if !found {
			t.Errorf("%s 是納管資源讀取面的共用測試，必須排入 CI 名單", name)
		}
	}
	for _, p := range checkDeferredScheduled(gated, ciList, deferredLocalOnly) {
		t.Error(p)
	}
	t.Logf("延後的情境 %d 支：排入 CI %d、只在本機 %d", len(gated), len(ciList), len(deferredLocalOnly))

	t.Run("selfcheck", func(t *testing.T) {
		g := map[string]bool{"TestA": true, "TestB": true}
		if p := checkDeferredScheduled(g, []string{"TestA"}, map[string]string{"TestB": "x"}); len(p) != 0 {
			t.Fatalf("前提：無問題，得 %v", p)
		}
		for label, c := range map[string]struct {
			ci    []string
			local map[string]string
			want  string
		}{
			"漏排":   {[]string{"TestA"}, nil, "TestB：延後的情境沒有排入"},
			"名單過時": {[]string{"TestA", "TestGone"}, map[string]string{"TestB": "x"}, "TestGone：在 CI 名單內，但不是延後的情境"},
			"重複歸屬": {[]string{"TestA", "TestB"}, map[string]string{"TestB": "x"}, "TestB：同時在"},
			"沒有理由": {[]string{"TestA"}, map[string]string{"TestB": " "}, "TestB：本機清單要寫理由"},
		} {
			found := false
			for _, p := range checkDeferredScheduled(g, c.ci, c.local) {
				found = found || strings.Contains(p, c.want)
			}
			if !found {
				t.Errorf("%s：沒有指出 %q", label, c.want)
			}
		}
	})
}
