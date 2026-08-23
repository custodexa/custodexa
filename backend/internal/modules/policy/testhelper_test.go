package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// policy 包內測試助手。
//
// **為何是複本而非共用**：本包的包內測試（`package policy`）SHALL NOT import
// `internal/service`——後者 import 本包，測試內 import 會構成 Go 的
// 「import cycle not allowed in test」。故 `internal/service` 側仍保留
// `aad_write_guard_test.go` 的原本宣告，本檔為 policy 側的等價複本，
// 實作逐行相同（比照 keyvault 的 `testhelper_test.go`）。

// policyGuardModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const policyGuardModulePath = "github.com/custodexa/backend"

// repoRoot 定位 backend module 根（本包守衛的共用掃描根）。
//
// **不用 cwd 相對、也不用固定層數 `..`**（統一修法）：兩者都與
// 「本 package 目前住在樹的第幾層」綁死，package 一下移就指向錯誤位置，而
// WalkDir 對不存在／空目錄多半只回零命中——守衛於是在掃空的情況下照樣綠。
// 本包正是「下移一層」的當事人（`internal/service` → `internal/modules/policy`），
// 錨點式定位使搬遷前後掃描根逐位相同。
func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + policyGuardModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				gomod, policyGuardModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位",
				filepath.Dir(self), policyGuardModulePath)
		}
		dir = parent
	}
}

// repoParent 定位「backend 之上」的專案根（frontend／.env.example 等非 module 內資產）。
//
// 只有一層 `..`，但那一層是相對於 **module 根**（由 go.mod 錨定）而非相對於
// 呼叫端 package 的位置，故 package 下移不影響。取得後必須驗證 marker 存在，
// 讀不到即 Fatal——讀不到被驗證對象等於沒有守衛。
func repoParent(t *testing.T, marker string) string {
	t.Helper()
	parent := filepath.Dir(repoRoot(t))
	if _, err := os.Stat(filepath.Join(parent, filepath.FromSlash(marker))); err != nil {
		t.Fatalf("自模組根上溯一層得 %s，但其中找不到 %s：專案根定位失效，"+
			"守衛讀不到被驗證對象即等於沒有守衛（故 Fatal 而非 skip）: %v", parent, marker, err)
	}
	return parent
}
