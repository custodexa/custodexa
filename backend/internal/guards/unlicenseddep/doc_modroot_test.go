// Package unlicenseddep 承載「無授權第三方依賴不得復活」的機械守衛。
//
// # 守的是什麼
//
// terminal-screen-parser-inhouse 自行實作了終端螢幕解析器（internal/vtscreen），
// 把無授權的 `github.com/LeeEirc/terminalparser` 從相依樹上拔掉。
// 拔掉是一次性動作，**留下來的風險是它會自己長回來**：
// 任何人一次 `go get`、一段從舊碼複製過來的片段、或 IDE 自動補上的 import，
// 都會把它帶回 go.mod，而在本守衛之前**沒有任何機制會出聲**——
// 編譯照過、測試照綠，授權缺口卻已經重新開啟。
// 不需要惡意，一次順手的複製貼上就會發生（charter §6 三問判為 A 類，必修）。
//
// # 為什麼是獨立 package
//
// 與 `internal/guards/auditmask`／`internal/guards/moduleboundary` 同一理由：
// 輸入是整棵原始碼樹與 module 檔案，與組裝根的編譯狀態解耦。
// 本目錄刻意只有測試檔——守衛不是產品程式碼。
package unlicenseddep

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// unlicensedDepModulePath 掃描根核對用的 module 路徑。
const unlicensedDepModulePath = "github.com/custodexa/backend"

// unlicensedDepModuleRoot 由本測試檔位置向上找 go.mod，並核對 module 行。
// 不用目錄層數推算：那在守衛檔搬家時會靜默指到別處，掃到空樹仍然全綠
// （基線 §6.2 實證 17 處守衛因層數推算而失效）。作法沿用 auditmask 的同名輔助。
func unlicensedDepModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + unlicensedDepModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				gomod, unlicensedDepModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位", filepath.Dir(self), unlicensedDepModulePath)
		}
		dir = parent
	}
}
