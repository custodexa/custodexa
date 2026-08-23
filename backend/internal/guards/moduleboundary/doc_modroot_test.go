// Package moduleboundary 承載「輸入是原始碼樹本身」的模組邊界類機械守衛。
//
// # 為什麼是獨立 package（自 cmd/server 拆出）
//
// 本目錄的守衛全部以 `packages.Load("./...")`／`filepath.WalkDir` 把**整棵 module
// 原始碼樹**當輸入，一行都不碰 `package main` 的內部符號。它們原本住在
// `cmd/server`，帶來兩個結構性後果：
//
//   - 同 package 的測試循序執行，九支各自重跑一次全樹型別檢查，
//     整包逼近 `go test` 的 600 秒 per-package 預設上限，
//     照文件跑 `go test ./...`（不帶 `-timeout`）會得到一個「看起來像壞掉」的逾時。
//   - `cmd/server` 或其任何相依只要編譯不過，這批守衛就跑不起來＝靜默失效
//     （被他人進行中的改動連坐）。
//
// 拆成獨立 package 後：與其他 package 並行執行、各自的耗時遠低於上限，
// 且不再受組裝根的編譯狀態連坐。先例見 `internal/auditcopy`（本目錄同樣刻意只有測試檔）。
//
// **拆分只換位置，不換判準**：上限常數、豁免清單、fail-close 分支、失敗訊息
// 一律與拆分前逐字相同。掃描根一律由 go.mod 反查（見 lifecycleModuleRoot），
// 與守衛檔自己住哪無關，故位置變更不影響掃描範圍。
package moduleboundary

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// lifecycleModulePath 掃描根核對用的 module 路徑。
//
// **本檔是 cmd/server/lifecycle_manifest_guard_test.go 同名工具的逐字副本**：
// 該檔因依賴 `stage2ServiceInventory`（package main 的變數）而無法一併搬出，
// 而把私有符號改成公開只為了共用一個 25 行的路徑解析器並不划算。
// 專案內同型副本已有數份（gwModuleRoot／guardModuleRoot／auditPointModuleRoot／
// gateModuleRoot），此處延續同一慣例。
const lifecycleModulePath = "github.com/custodexa/backend"

// lifecycleModuleRoot 由本測試檔位置向上找 go.mod，並核對 module 行。
// 不用「Dir(Caller)/../..」的層數推算：那在守衛檔搬家時會靜默指到別處。
func lifecycleModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + lifecycleModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				gomod, lifecycleModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位", filepath.Dir(self), lifecycleModulePath)
		}
		dir = parent
	}
}
