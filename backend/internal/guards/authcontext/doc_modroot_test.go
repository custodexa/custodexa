// Package authcontext 承載「認證脈絡貫穿點」機械守衛。
//
// # 為什麼是獨立 package（自 cmd/server 拆出）
//
// 本守衛以 `packages.Load("./...")` 把**整棵 module 原始碼樹**當輸入，
// 一行都不碰 `package main` 的內部符號。它原本住在 `cmd/server`，
// 與另外八支同型全樹掃描守衛擠在同一個 package 內循序執行，
// 整包逼近 `go test` 的 600 秒 per-package 預設上限——照專案文件跑
// `go test ./...`（不帶 `-timeout`）會得到一個「看起來像壞掉」的逾時，
// 而它其實只是慢。且 `cmd/server` 或其任何相依編譯不過時，
// 這支守衛就跑不起來＝靜默失效（被他人進行中的改動連坐）。
//
// 它另外自成一個 package（而非與 `internal/guards/moduleboundary` 合住）的理由：
// 它是全部全樹掃描守衛中最貴的一支（單支即佔 moduleboundary 拆分前約四分之一
// 的耗時），獨立出來可讓兩邊各自遠離 600 秒上限。
//
// 先例見 `internal/auditcopy`（本目錄同樣刻意只有測試檔）。
//
// **拆分只換位置，不換判準**：上限常數、豁免清單、fail-close 分支、失敗訊息
// 一律與拆分前逐字相同。掃描根一律由 go.mod 反查（見 lifecycleModuleRoot），
// 與守衛檔自己住哪無關，故位置變更不影響掃描範圍。
package authcontext

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// lifecycleModulePath 掃描根核對用的 module 路徑。
//
// **本檔的 lifecycleModuleRoot 與 itoa 是 cmd/server 同名工具的逐字副本**：
// 其原宿主（lifecycle_manifest_guard_test.go／model_audit_write_guard_test.go）
// 一個因依賴 `stage2ServiceInventory` 而無法搬出、一個屬於別的守衛群，
// 而把私有符號改成公開只為了共用二十來行工具並不划算。專案內同型副本已有數份
// （gwModuleRoot／guardModuleRoot／auditPointModuleRoot／w10ModuleRoot），
// 此處延續同一慣例。
const lifecycleModulePath = "github.com/custodexa/backend"

// lifecycleModuleRoot 由本測試檔位置向上找 go.mod，並核對 module 行。
// 不用「Dir(Caller)/../..」的層數推算：那在守衛檔搬家時會靜默指到別處（R4 F-掃描根）。
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
