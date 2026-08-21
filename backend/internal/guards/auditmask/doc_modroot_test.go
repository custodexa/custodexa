// Package auditmask 承載「審計請求內容遮罩允許清單」的機械守衛。
//
// # 守的是什麼
//
// `audit.MaskSensitiveFields` 是 default-deny 的允許清單：清單內的鍵原樣入審計，
// 清單外一律換成 `***MASKED***`。這個策略方向是對的（新欄位預設不外洩），
// 但它有一個安靜的失效形態——**課責必要的欄位忘了登記，審計列照樣寫成功，
// 只是內容全是遮罩標記**。實測缺陷即此形態：`PUT /users/:id/roles` 的
// `roles`（複數）不在清單、清單裡卻有一個沒有任何請求綁定的 `role`（單數），
// 於是「誰把誰升成什麼角色」全庫無處可查，而沒有任何測試會紅。
//
// # 為什麼是獨立 package
//
// 與 `internal/guards/moduleboundary` 同一理由：輸入是整棵原始碼樹
// （`packages.Load` 帶型別資訊），與組裝根的編譯狀態解耦，且可與其他 package 並行。
// 本目錄刻意只有測試檔——守衛不是產品程式碼。
package auditmask

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// auditMaskModulePath 掃描根核對用的 module 路徑。
const auditMaskModulePath = "github.com/custodexa/backend"

// auditMaskModuleRoot 由本測試檔位置向上找 go.mod，並核對 module 行。
// 不用層數推算：那在守衛檔搬家時會靜默指到別處。
func auditMaskModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + auditMaskModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				gomod, auditMaskModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位", filepath.Dir(self), auditMaskModulePath)
		}
		dir = parent
	}
}
