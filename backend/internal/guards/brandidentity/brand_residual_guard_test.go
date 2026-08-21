package brandidentity

// 品牌識別字單一性守衛（brand-residual-cleanup，specs/brand-identity）。
//
// **釘住什麼**：backend module 內不得出現歷史品牌名。歷史上這件事失敗過一次——
// 一次只做顯示層的更名把技術識別字列為 Non-goals（見 specs/brand-identity
// 的「為何需要獨立能力」段），結果舊品牌繼續出現在**對外送出**的三個面
// （syslog app-name、通知測試內容、改密寫進目標主機的帳號 comment）
// 直到 2026-08-14 被使用者實測發現。
//
// **射程邊界（明載，不誇大）**：本守衛只掃 backend module。repo 其餘部分
// （frontend、docker、compose、scripts、docs、行銷產出）由維護者側的全樹品牌掃描
// 承擔（repo 級工具，以 `git ls-files` 取版控清單、不隨公開發佈）。
//
// **為什麼不把 repo 掛進容器讓本守衛全掃**：試過，是錯的。`.:/app/testdata/repo:ro`
// 使 host 的 .env（JWT_SECRET／ENCRYPTION_KEY／ADMIN_INITIAL_PASSWORD）與 data*/
// 備份目錄對容器內的 dbcli 降權身分可讀，`localpty.TestCLIUserCannotReadLiveCredentials`
// 當場轉紅——那是 DB CLI 逃逸防護的核心性質。**為了擴大守衛射程而擴大容器的檔案
// 視野，是拿真實安全性質換測試覆蓋，不划算。**
//
// **威脅模型**：防的是「維護者不慎寫入歷史品牌名」。**不抵抗蓄意規避**——大小寫
// 變體、同形字元、字串拼接都繞得過，而具備提交權限者可直接刪掉本檔。針對規避形態
// 加強沒有實質防護價值（同 route-guard 對蓄意規避形態的既有裁決），故只比對四個字面量。
//
// **為什麼掃描檔數下限是必要的**：掃描根定位失準或例外清單過寬時，「零命中」與
// 「什麼都沒掃」在結果上完全相同。沒有下限的掃描式守衛會在空集合下永遠全綠。

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// brandModulePath 掃描根定位的身分錨點：go.mod 的 module 行必須等於此值。
const brandModulePath = "github.com/custodexa/backend"

// legacyBrandLiterals 歷史品牌名的字面形態。
//
// 只列這四個：它們是 2026-07-20 更名前實際使用過的形態。新增變體前先問
// 「這個形態真的在版控裡出現過嗎」——為假想形態擴充清單只會增加誤報面。
var legacyBrandLiterals = []string{
	"open-terminal",
	"open_terminal",
	"Open Terminal",
	"OpenTerminal",
}

// excludedPrefixes 例外路徑（相對 module 根，slash 分隔）。
//
// **只涵蓋結構性排除項**（specs/brand-identity 明文要求）：非本 module 的掛載內容
// 與建置產物。**SHALL NOT 用於豁免個別產品程式碼檔案**——若某支產品程式碼「必須」
// 保留歷史品牌名，那是設計問題，不是例外清單問題。
var excludedPrefixes = []string{
	// Air 熱重載的建置產物
	"tmp/",
	// 本守衛自身：legacyBrandLiterals 的定義必然含這四個字面量。
	// 具名到檔案而非整個目錄——同目錄若日後新增別的檔案仍在射程內。
	"internal/guards/brandidentity/brand_residual_guard_test.go",
}

// excludedDirNames 任意層級下即排除的目錄名。
//
// `testdata` 需要這種形態而非前綴比對：唯讀掛載點分散在多層
// （module 根的 testdata/openspec、cmd/server/testdata/docs 等），
// 且 Go 工具鏈本就忽略 testdata——它們不是 backend 自己的原始碼。
var excludedDirNames = map[string]bool{
	"testdata": true,
}

// minBrandScannedFiles 實際被讀取比對的文字檔下限。
//
// backend module 現況約 870 個版控檔，扣掉二進位與超大檔後實掃約 840；取 600
// 為保守下界。低於此即代表掃描根失準或例外清單過寬，守衛將在近乎空集合下假綠。
const minBrandScannedFiles = 600

// maxScanFileSize 單檔讀取上限：超過即跳過（不計入 scanned）。
const maxScanFileSize = 1 << 20

type brandScan struct {
	Hits    []string // "相對路徑:行號: 命中的字面量"
	Scanned int
	Err     error
}

var (
	brandScanOnce  sync.Once
	brandScanCache brandScan
)

// moduleRoot 由本測試檔位置向上找 go.mod 並核對 module 行。
// 不用層數推算：守衛檔搬家時會靜默指到別處，那是掃描式守衛最常見的失效形態。
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			want := "module " + brandModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效",
				dir, brandModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位",
				filepath.Dir(self), brandModulePath)
		}
		dir = parent
	}
}

func isExcluded(rel string) bool {
	for _, p := range excludedPrefixes {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

func scanBrand(t *testing.T) brandScan {
	t.Helper()
	root := moduleRoot(t)
	brandScanOnce.Do(func() { brandScanCache = runBrandScan(root) })
	if brandScanCache.Err != nil {
		t.Fatalf("%v", brandScanCache.Err)
	}
	return brandScanCache
}

// runBrandScan 遍歷 module 根，讀每個文字檔比對歷史品牌字面量。
//
// 不接 *testing.T：在 sync.Once 內執行，任何 t 都只屬於第一個進入者
// （同 guard-scan-cost-reduction 對共用掃描的處置）。
func runBrandScan(root string) brandScan {
	res := brandScan{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 讀不到的節點跳過，不中斷掃描
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if excludedDirNames[d.Name()] || isExcluded(rel+"/") {
				return fs.SkipDir
			}
			return nil
		}
		if isExcluded(rel) || !d.Type().IsRegular() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > maxScanFileSize {
			return nil
		}
		body, rerr2 := os.ReadFile(path)
		if rerr2 != nil {
			return nil
		}
		// 含 NUL 即視為二進位，不掃（品牌字串不會以此形態進版控）
		if bytes.IndexByte(body, 0) >= 0 {
			return nil
		}
		res.Scanned++
		for i, line := range strings.Split(string(body), "\n") {
			for _, lit := range legacyBrandLiterals {
				if strings.Contains(line, lit) {
					res.Hits = append(res.Hits, rel+":"+itoa(i+1)+": 命中 "+lit)
				}
			}
		}
		return nil
	})
	if err != nil {
		res.Err = err
	}
	return res
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestNoLegacyBrandResidualsInBackend backend module 內不得出現歷史品牌名。
func TestNoLegacyBrandResidualsInBackend(t *testing.T) {
	scan := scanBrand(t)

	if scan.Scanned < minBrandScannedFiles {
		t.Fatalf("只掃描 %d 個文字檔（下限 %d）：掃描根失準或例外清單過寬，"+
			"「零命中」在此狀態下不構成證據。修掃描根或收窄例外清單，不得調降下限",
			scan.Scanned, minBrandScannedFiles)
	}

	if len(scan.Hits) > 0 {
		t.Errorf("下列 %d 處出現歷史品牌名（已掃描 %d 檔）：\n  %s\n\n"+
			"品牌識別字的單一來源是 internal/branding（Name 顯示用、Slug 技術識別字用）。"+
			"**不得以加入例外清單的方式讓本守衛變綠**——例外清單只收結構性排除項。\n"+
			"註：backend 以外的檔案不在本守衛射程，由維護者側的全樹品牌掃描承擔。",
			len(scan.Hits), scan.Scanned, strings.Join(scan.Hits, "\n  "))
	}

	t.Logf("品牌掃描（backend module）：%d 個文字檔、%d 處命中", scan.Scanned, len(scan.Hits))
}
