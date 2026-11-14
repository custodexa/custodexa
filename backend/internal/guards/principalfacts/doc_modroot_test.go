// Package principalfacts 承載「請求主體的建構點」與「背景／系統來源的建構點」機械守衛。
//
// 以 `packages.Load("./...")` 讀整棵 module 原始碼樹（含型別資訊），刻意只有測試檔，
// 自成一個 package 以免與其他全樹掃描守衛擠在同一個 600 秒上限內。
package principalfacts

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const guardModulePath = "github.com/custodexa/backend"

// guardModuleRoot 由本測試檔位置向上找 go.mod，並核對 module 行（不以層數推算，守衛檔搬家時不會靜默指到別處）。
func guardModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + guardModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("%s 的 module 不是 %s：掃描根錯置", gomod, guardModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("找不到 go.mod：掃描根無從定位")
		}
		dir = parent
	}
}
