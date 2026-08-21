//go:build linux

package localpty

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// 執行環境的檔案系統不變式（database-protocol「CLI 執行環境的可驗證不變式」）。
//
// 新方案放棄輸入層過濾後，`\copy … FROM '檔案'`／`\i` 這類「不需 shell 的本機
// 讀檔」是刻意允許的——保證改由「該身分讀得到的檔案裡沒有任何有價值的東西」承擔。
// 這件事無法靠人眼複查維持：任何人日後把含活憑證的檔案掛進容器、或把資料目錄
// 的權限放寬，本組測試就必須轉紅。這是整個方案唯一的守門人。

// 掃描時剪掉的樹：/proc 與 /sys 是核心介面（/proc/kcore 之類讀起來會爆），
// 其可讀性另以定點斷言檢查（見 TestCLIUserCannotReadBackendProcessEnviron）
var scanPrunedRoots = map[string]bool{"/proc": true, "/sys": true}

// 已知且可接受的可寫路徑：docker 執行期掛載的 tmpfs（1777、nosuid/nodev/noexec），
// image 內改不掉。可寫但不可執行、不含任何憑證，且 CLI 子程序寫進去的東西
// 只有同一身分（其他 DB 會話）看得到——不構成憑證竊取路徑（跨會話的檔案交換面
// 已登記於 spec 的殘留清單）。
//
// allowlist 為**子樹**語義：這些掛載點是設計上允許的可寫面，其中出現檔案是預期
// 行為（CLI 會話真的會寫進去），不得使守門測試轉紅——假紅會訓練人忽略這組測試。
// 反之，allowlist 之外任何新增的可寫路徑仍照常轉紅；allowlist 本身的正當性另由
// assertWritableAllowlistIsRuntimeMount 核對（見 TestCLIUserHasNoWritablePaths）。
var scanWritableAllowlist = []string{"/dev/shm", "/dev/mqueue"}

// underWritableAllowlist 路徑本身或其祖先在 allowlist 內
func underWritableAllowlist(path string) bool {
	for _, root := range scanWritableAllowlist {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

type fsScan struct {
	readableFiles []string // 該身分可達且可讀的一般檔案
	writablePaths []string // 該身分可寫的目錄或檔案
	setuidFiles   []string // 全 image 的 setuid/setgid 一般檔（不受可達性剪枝影響）
	prunedDirs    int      // 因不可進入而整棵略過的目錄數
}

var (
	scanOnce   sync.Once
	scanResult *fsScan
)

// modeBitsFor 回傳 uid/gid 這個身分對 st 適用的權限三位元（owner/group/other 擇一）
func modeBitsFor(st *syscall.Stat_t, uid, gid uint32) uint32 {
	switch {
	case st.Uid == uid:
		return (st.Mode >> 6) & 7
	case st.Gid == gid:
		return (st.Mode >> 3) & 7
	default:
		return st.Mode & 7
	}
}

func statOf(t *testing.T, path string) *syscall.Stat_t {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		t.Fatalf("lstat %s 失敗: %v", path, err)
	}
	return &st
}

func writableByUser(t *testing.T, path string, uid, gid int) bool {
	t.Helper()
	return modeBitsFor(statOf(t, path), uint32(uid), uint32(gid))&2 != 0
}

func readableByUser(t *testing.T, path string, uid, gid int) bool {
	t.Helper()
	return modeBitsFor(statOf(t, path), uint32(uid), uint32(gid))&4 != 0
}

// scanFilesystem 以權限位元推算「CLI 降權身分」在整個容器內能讀什麼、能寫什麼。
// 用位元推算而非實際以該身分開檔：測試程序是 root（DAC_OVERRIDE 讓 root 讀得動
// 一切），實際開檔反而測不出該身分的邊界。目錄不可進入即整棵剪掉（不可達）。
func scanFilesystem(t *testing.T, uid, gid uint32) *fsScan {
	t.Helper()
	scanOnce.Do(func() {
		res := &fsScan{}
		// **單趟不剪枝遍歷，可達性沿途維護**（fsinvariant-scope-correction）。
		//
		// 原本是兩趟：第一趟剪枝收可讀／可寫面、第二趟不剪枝收 setuid。兩趟的判準
		// 不同（setuid 是全映像性質，不得因「該身分進不去」而漏掃），但走的是同一棵樹。
		// 實測第二趟佔本測試 22.7 秒中的 17.7 秒——它不剪枝，走訪的節點比第一趟更多。
		//
		// 合併方式：不剪枝走完全樹，另以 dirReachable 記錄每個目錄對降權身分是否可達
		// （WalkDir 保證父目錄先於子項訪問，故查父即可）。可達者計入可讀／可寫面，
		// **不可達者仍計入 setuid**——兩項判準與合併前逐字相同，變的只是走訪次數。
		dirReachable := map[string]bool{"/": true}
		_ = filepath.WalkDir("/", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // 讀不到的節點跳過（競態刪除等），不中斷掃描
			}
			parentReachable := path == "/" || dirReachable[filepath.Dir(path)]

			if d.IsDir() {
				if scanPrunedRoots[path] {
					return fs.SkipDir // /proc、/sys：核心 tmpfs，兩項判準皆不適用
				}
				// **取不到 metadata 時視為不可達，但仍走完子樹**：SkipDir 會連 setuid
				// 掃描一併跳過，而 spec 第 5 項要求該項涵蓋全映像。合併前的第二趟不對
				// 目錄取 Info，故無此問題；合併後若在此 SkipDir 即是把涵蓋面縮掉了。
				// （由獨立驗收指出，2026-08-14。）
				info, ierr := d.Info()
				if ierr != nil {
					dirReachable[path] = false
					return nil
				}
				st, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					dirReachable[path] = false
					return nil
				}
				bits := modeBitsFor(st, uid, gid)
				// 可寫面：僅在該目錄本身可達時才構成落檔面
				if parentReachable && bits&2 != 0 && !underWritableAllowlist(path) {
					res.writablePaths = append(res.writablePaths, path)
				}
				reachable := parentReachable && bits&1 != 0
				dirReachable[path] = reachable
				if parentReachable && !reachable {
					// 由可達轉為不可達的邊界即原本剪枝的位置，計數語義不變
					res.prunedDirs++
				}
				return nil // **不剪枝**：子樹仍需納入 setuid 掃描
			}

			if !d.Type().IsRegular() { // symlink/device/socket 不讀（symlink 的目標
				return nil // 另需目標自身權限，走不到這裡就是走不到）
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}

			// setuid/setgid：全映像性質，**不受可達性影響**（剪掉的子樹裡若藏 setuid 檔，
			// 一旦上層目錄權限被放寬就直接變成升權面）
			if st.Mode&(syscall.S_ISUID|syscall.S_ISGID) != 0 {
				res.setuidFiles = append(res.setuidFiles,
					fmt.Sprintf("%s (mode=%o)", path, st.Mode&07777))
			}

			// 可讀／可寫面：僅在該身分真的到得了時才成立
			if !parentReachable {
				return nil
			}
			bits := modeBitsFor(st, uid, gid)
			if bits&4 != 0 {
				res.readableFiles = append(res.readableFiles, path)
			}
			if bits&2 != 0 && !underWritableAllowlist(path) {
				res.writablePaths = append(res.writablePaths, path)
			}
			return nil
		})
		scanResult = res
	})
	return scanResult
}

// credProbe 一個活憑證探針。strict＝短值，只在「憑證賦值語境」內採信。
type credProbe struct {
	name   string
	val    []byte
	strict bool
}

const (
	// 長值：熵足夠，任何位置的子字串命中都當真
	probeRawMinLen = 12
	// 短值：需賦值語境；再短就連語境都撐不住鑑別力（4 字元的值在二進位裡
	// 撞上 `=xxxx` 的機率不可忽略）
	probeStrictMinLen = 4
	// 短值回頭找賦值符號時允許的左側脈絡長度（引號＋空白）
	probeLeftContext = 32
)

var credNameRe = regexp.MustCompile(`(?i)(SECRET|PASSWORD|PASSWD|_PWD|TOKEN|_KEY$|_KEY_|APIKEY|CREDENTIAL)`)

// shortProbeExcludedTrees 短值探針不掃的樹——**僅開發版 image 有這兩棵**：
//
//   - `/app`：開發版把主機的原始碼樹 bind-mount 進來（正式版 runtime stage 只有
//     `/root/custodexa` 一個二進位）。原始碼、測試夾具與設計文件本來就寫著
//     開發用預設值（`DB_PASSWORD=postgres` 之類），那不是「有人把憑證掛進容器」。
//   - `/go`：Go 工具鏈與 module cache（同樣只存在於開發版）。第三方套件的
//     README／測試檔含 `password=postgres` 這種樣板字串。
//
// **長值探針照掃這兩棵**：真正的高熵憑證（KEK、JWT secret）若出現在原始碼或
// 相依套件裡仍會轉紅——那才是要抓的事。排除範圍僅止於「低熵短值在開發樹內的
// 樣板字串」，且每次執行都會把被排除的檔案數印出來（不靜默）。
var shortProbeExcludedTrees = []string{"/app", "/go"}

// contentScanExcludedTrees **完全不讀取內容**的樹（fsinvariant-scope-correction）。
//
// 與 shortProbeExcludedTrees 是不同軸：那個只降低探針敏感度、檔案內容照樣讀過；
// 這個是整棵移出內容讀取範圍，省下的是 I/O 本身。
//
// **判準：該樹的內容是否經由我方寫入路徑產生**（specs/database-protocol 第 1 項）。
// 這兩棵都不是——
//
//   - `/go/pkg/mod`：`go mod download` 由公開套件倉庫寫入（27135 檔／933 MB）
//   - `/usr/local/go`：語言 toolchain，映像建置時寫入（14179 檔／283 MB）
//
// 我方沒有任何路徑往這兩棵寫東西，故憑證不可能「非預期地」出現於此。要讓它出現
// 需在容器內手動寫入——那是信任邊界內（charter §6 C 類），且該前提下
// `/proc/<backend>/environ` 是短得多的路徑，由 TestCLIUserCannotReadBackendProcessEnviron
// 獨立守著。
//
// **這是刻意縮小的射程，代價要明說**：本 change 之前，長值探針會掃這兩棵，
// 用意是「高熵憑證若出現在相依套件裡仍要轉紅」。該覆蓋自此放棄，換取 1.2 GB
// 的內容讀取（實測佔本測試 114 秒中的絕大部分）。**排除量每次執行都印出**，
// 使射程悄悄擴大在輸出中可見。
//
// **`/app` 刻意不列入**：那是我方原始碼與掛載點所在。真實事故（含活憑證的 .env
// 經 /app/testdata/repo 掛入而對降權身分可讀）正是在該範圍被抓到，且那個路徑
// 當天才產生、不在任何清單上——排除它等同放棄本斷言唯一被證明過的抓捕能力。
var contentScanExcludedTrees = []string{"/go/pkg/mod", "/usr/local/go"}

// underContentScanExclusion 路徑是否落在完全不讀內容的樹內
func underContentScanExclusion(path string) bool {
	for _, root := range contentScanExcludedTrees {
		if strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

func underShortProbeExclusion(path string) bool {
	for _, root := range shortProbeExcludedTrees {
		if strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// liveCredentialProbes 從測試程序的環境取「活憑證」當探針。
//
// **不以長度過濾探針**：舊版「長度 >= 12 才掃描」會讓 8 字的 DB_PASSWORD、
// 9 字的 LDAP_BIND_PASSWORD 整個不在掃描範圍內——把真憑證放進世界可讀的檔案
// 測試仍是綠的。改為依長度切換**比對方式**而非切換是否比對：
//
//   - >= 12：原樣子字串比對（熵足夠，撞不到）。
//   - >= 4 且 < 12：需完整 token 邊界（前後皆非 token 位元組）**且**緊鄰在賦值
//     符號（`=` / `:`，容許引號與空白）之後。`postgres` 這種低熵預設值因此不會
//     被 `/usr/bin/psql` 內的字串或 `postgresql` 之類路徑誤判，但
//     `DB_PASSWORD=postgres`、`password: postgres`、`postgres://u:postgres@h`
//     這些憑證真的會外洩的形態一律命中。
//   - < 4：無法鑑別，列為未覆蓋並在輸出中點名（不靜默丟棄）。
//
// 值為空的變數（例如未設定的 AUDIT_INTEGRITY_KEY）不構成探針，直接略過。
// 輸出一律只印變數名，值不得進 log。
func liveCredentialProbes(t *testing.T) []credProbe {
	t.Helper()
	var probes []credProbe
	var uncovered []string
	for _, kv := range os.Environ() {
		name, val, ok := strings.Cut(kv, "=")
		if !ok || val == "" || !credNameRe.MatchString(name) {
			continue
		}
		switch {
		case len(val) >= probeRawMinLen:
			probes = append(probes, credProbe{name: name, val: []byte(val)})
		case len(val) >= probeStrictMinLen:
			probes = append(probes, credProbe{name: name, val: []byte(val), strict: true})
		default:
			uncovered = append(uncovered, name)
		}
	}
	if len(uncovered) > 0 {
		t.Logf("下列憑證變數的值短於 %d 字元，無法鑑別故未覆蓋: %s",
			probeStrictMinLen, strings.Join(uncovered, ", "))
	}
	if len(probes) < 2 {
		t.Fatalf("環境中找不到足夠的活憑證探針（取得 %d 個）——測試會假綠。"+
			"本測試須在帶完整 .env 的 backend 容器內執行", len(probes))
	}
	return probes
}

// isProbeTokenByte 判定位元組是否屬於「同一個 token」——短值比對要求前後皆非
// token 位元組，`postgres` 才不會在 `postgresql`／`/var/lib/postgres-data` 命中
func isProbeTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_' || b == '-' || b == '.' || b == '/':
		return true
	}
	return false
}

// credKeyRe 賦值符號左側必須出現的「機密欄位名」形態（`DB_PASSWORD=`、
// `password:`、`PGPASSWORD =`、URI 的 `user:pass@` 不在此列——見下方說明）
var credKeyRe = regexp.MustCompile(`(?i)(pass|pwd|secret|token|credential|api[-_]?key|[-_]key)[a-z0-9_-]*["' \t]*$`)

// inAssignmentContext 判定 window[idx:idx+n] 這個命中是否位於**機密賦值語境**：
// token 邊界完整、往左跳過引號與空白後緊接 `=` 或 `:`，且該符號左側是機密欄位名。
//
// 只要求「有賦值符號」是不夠的：`postgres` 這種低熵預設值在 `/etc/group` 的
// `…:postgres`、Go module cache 的 `user=postgres` 之類位置到處都是（實測 20+ 個
// 檔案命中）。要求欄位名把命中收斂到「這個檔案把某個機密欄位設成了活憑證」，
// 那正是本測試要偵測的形態（有人把 .env／config／k8s secret 掛進容器）。
// window 的左側脈絡由分塊重疊保證（見 fileContainsAny 的 overlap）。
func inAssignmentContext(window []byte, idx, n int) bool {
	if idx+n < len(window) && isProbeTokenByte(window[idx+n]) {
		return false
	}
	i := idx - 1
	if i >= 0 && (window[i] == '"' || window[i] == '\'') {
		i--
	}
	for i >= 0 && (window[i] == ' ' || window[i] == '\t') {
		i--
	}
	if i < 0 || idx-i > probeLeftContext {
		return false
	}
	if window[i] != '=' && window[i] != ':' {
		return false
	}
	left := window[max(0, i-probeLeftContext):i]
	if k := bytes.LastIndexAny(left, "\r\n"); k >= 0 {
		left = left[k+1:] // 欄位名須與賦值同一行
	}
	return credKeyRe.Match(left)
}

// probeHits 回傳 window 內命中的探針名稱
func probeHits(window []byte, probes []credProbe, seen map[string]bool) []string {
	var found []string
	for _, p := range probes {
		if seen[p.name] {
			continue
		}
		if !p.strict {
			if bytes.Contains(window, p.val) {
				seen[p.name] = true
				found = append(found, p.name)
			}
			continue
		}
		for off := 0; ; {
			rel := bytes.Index(window[off:], p.val)
			if rel < 0 {
				break
			}
			idx := off + rel
			if inAssignmentContext(window, idx, len(p.val)) {
				seen[p.name] = true
				found = append(found, p.name)
				break
			}
			off = idx + 1
		}
	}
	return found
}

// TestCLIUserCannotReadLiveCredentials CLI 降權身分讀得到的檔案裡不得含任何活憑證。
//
// 失敗條件（兩位顧問共同指出、也是撤除輸入層過濾後的唯一風險）：有人把含活憑證的
// 檔案掛進容器、或放寬了資料/日誌目錄的權限——本測試即轉紅。
func TestCLIUserCannotReadLiveCredentials(t *testing.T) {
	uid, gid, _, err := LookupUser(CLIUser)
	if err != nil {
		t.Fatalf("查不到 CLI 降權身分 %q（backend image 需重建）: %v", CLIUser, err)
	}
	probes := liveCredentialProbes(t)
	scan := scanFilesystem(t, uint32(uid), uint32(gid))
	if len(scan.readableFiles) == 0 {
		t.Fatal("掃描結果為零檔案——掃描器壞了，測試會假綠")
	}

	maxNeedle := 0
	strictCount := 0
	var rawProbes []credProbe
	for _, p := range probes {
		if len(p.val) > maxNeedle {
			maxNeedle = len(p.val)
		}
		if p.strict {
			strictCount++
		} else {
			rawProbes = append(rawProbes, p)
		}
	}

	var hits []string
	shortExcluded := 0
	contentExcluded := 0
	for _, path := range scan.readableFiles {
		// 內容完全不讀的樹：跳過前先計數，使排除量可見（spec 第 1 項的量化要求）
		if underContentScanExclusion(path) {
			contentExcluded++
			continue
		}
		use := probes
		if underShortProbeExclusion(path) {
			use = rawProbes
			shortExcluded++
		}
		for _, name := range fileContainsAny(t, path, use, maxNeedle) {
			// 只印檔案路徑與變數名——憑證值不得進測試輸出
			hits = append(hits, path+" 含 $"+name+" 的值")
		}
	}
	if len(hits) > 0 {
		t.Errorf("CLI 降權身分可讀到含活憑證的檔案（共 %d 處）:\n  %s",
			len(hits), strings.Join(hits, "\n  "))
	}
	t.Logf("掃描完成: 可讀檔案 %d、因不可進入而剪除的目錄 %d、探針 %d 個（其中短值 %d 個）；"+
		"開發樹 %v 內有 %d 個檔案只套長值探針；"+
		"依賴樹 %v 內有 %d 個檔案完全未讀取內容（實際比對 %d 檔）",
		len(scan.readableFiles), scan.prunedDirs, len(probes), strictCount,
		shortProbeExcludedTrees, shortExcluded,
		contentScanExcludedTrees, contentExcluded,
		len(scan.readableFiles)-contentExcluded)
}

// fileContainsAny 串流比對（1 MiB 分塊、重疊 maxNeedle-1＋短值所需的左側脈絡），
// 不設檔案大小上限——設上限等於留下「把憑證放進大檔案」的漏洞
func fileContainsAny(t *testing.T, path string, probes []credProbe, maxNeedle int) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return nil // 競態刪除或特殊檔：跳過
	}
	defer f.Close()

	const chunk = 1 << 20
	overlap := maxNeedle - 1 + probeLeftContext
	buf := make([]byte, chunk+overlap)
	seen := map[string]bool{}
	var found []string
	filled := 0
	for {
		n, rerr := f.Read(buf[filled:])
		if n > 0 {
			window := buf[:filled+n]
			found = append(found, probeHits(window, probes, seen)...)
			if len(window) > overlap {
				copy(buf, window[len(window)-overlap:])
				filled = overlap
			} else {
				filled = len(window)
			}
		}
		if rerr != nil {
			break
		}
	}
	return found
}

// TestCLIUserHasNoWritablePaths CLI 降權身分在容器內不得有任何可寫路徑
// （allowlist 內的 docker 執行期 tmpfs 除外）。
//
// 可寫路徑本身不是憑證洩漏，但它是「落檔、跨會話交換、累積狀態」的起點；
// 唯讀環境讓「子程序能做什麼」這件事可被窮舉。
func TestCLIUserHasNoWritablePaths(t *testing.T) {
	uid, gid, _, err := LookupUser(CLIUser)
	if err != nil {
		t.Fatalf("查不到 CLI 降權身分: %v", err)
	}
	assertWritableAllowlistIsRuntimeMount(t)
	scan := scanFilesystem(t, uint32(uid), uint32(gid))
	if len(scan.writablePaths) > 0 {
		t.Errorf("CLI 降權身分有 %d 個可寫路徑（期望 0，allowlist 外）:\n  %s",
			len(scan.writablePaths), strings.Join(scan.writablePaths, "\n  "))
	}
}

// assertWritableAllowlistIsRuntimeMount allowlist 的每一項都必須真的是「docker
// 執行期掛載、映像內改不掉」的 nosuid/nodev/noexec 掛載點。
//
// 沒有這道檢查，allowlist 就是一張可以隨手加一行就讓任意目錄消音的名單（歷史
// 教訓：允許清單只驗刪除、不驗放寬）。加入映像內的一般目錄會在此轉紅。
func assertWritableAllowlistIsRuntimeMount(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("讀 /proc/self/mountinfo 失敗: %v", err)
	}
	opts := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		opts[f[4]] = f[5] // 掛載點 -> 掛載選項
	}
	for _, root := range scanWritableAllowlist {
		o, ok := opts[root]
		if !ok {
			t.Errorf("可寫 allowlist 的 %s 不是掛載點——它是映像內的一般目錄，"+
				"不得以 allowlist 消音", root)
			continue
		}
		for _, must := range []string{"nosuid", "nodev", "noexec"} {
			if !strings.Contains(","+o+",", ","+must+",") {
				t.Errorf("可寫 allowlist 的 %s 缺 %s（實得 %s）——"+
					"allowlist 的前提是它可寫但不可執行、不可帶 setuid", root, must, o)
			}
		}
	}
}

// TestImageHasNoSetuidFiles 映像內不得有 setuid／setgid 檔。
//
// spec 的「不具任何 capability（非 root 執行，且映像內 SHALL NOT 含 setuid／
// setgid 檔）」原本只有散文、沒有任何機械斷言，與同份 spec「不得僅以人工複查
// 維持」自相矛盾。setuid 檔是降權身分唯一的原生升權原語，必須有人看著。
func TestImageHasNoSetuidFiles(t *testing.T) {
	uid, gid, _, err := LookupUser(CLIUser)
	if err != nil {
		t.Fatalf("查不到 CLI 降權身分: %v", err)
	}
	scan := scanFilesystem(t, uint32(uid), uint32(gid))
	if len(scan.setuidFiles) > 0 {
		t.Errorf("映像內有 %d 個 setuid/setgid 檔（期望 0，它們是降權身分的升權面）:\n  %s",
			len(scan.setuidFiles), strings.Join(scan.setuidFiles, "\n  "))
	}
}

// TestCLIUserCannotReadBackendProcessEnviron 後端程序的環境區塊（KEK／JWT secret
// 所在）不得被 CLI 降權身分讀取。/proc 在掃描時被剪掉，故此處定點斷言。
//
// 測試程序與後端程序同身分（root），/proc/self 的權限模型即後端程序的。
func TestCLIUserCannotReadBackendProcessEnviron(t *testing.T) {
	uid, gid, _, err := LookupUser(CLIUser)
	if err != nil {
		t.Fatalf("查不到 CLI 降權身分: %v", err)
	}
	// 只列權限位元即為保護的節點：maps/stat 之類由核心的 ptrace 檢查把關，
	// 位元看起來是 0444 但跨 uid 開啟仍會被拒，拿位元判定會製造假紅
	for _, p := range []string{"/proc/self/environ", "/proc/self/mem"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if readableByUser(t, p, uid, gid) {
			t.Errorf("%s 對 CLI 降權身分可讀（後端機密外洩面）", p)
		}
	}

	// cmdline 由核心固定為 0444，任何身分都讀得到——它的安全性來自另一條既有
	// 不變式：憑證一律走環境變數、不落 argv（dbproxy.BuildCommand）。在此定點驗證
	cmdline, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		t.Fatalf("讀 /proc/self/cmdline 失敗: %v", err)
	}
	for _, p := range liveCredentialProbes(t) {
		if bytes.Contains(cmdline, p.val) {
			t.Errorf("/proc/self/cmdline（全域可讀）含 $%s 的值——憑證落入 argv", p.name)
		}
	}
}

// TestCLIProcessEnvironFirstEntryIsNotCredential 子程序環境組裝順序的確定性斷言。
//
// **本測試原本的論證已被推翻（2026-08-12，design D15）**：舊版以「環境區塊以 NUL
// 分隔，client 的讀檔類命令只取得到第一段」為由讓憑證走環境變數，並以本測試釘住
// 「第一段是 PATH」作為該保護的前提。實測 psql 的 `\lo_import` 是二進位讀取原語，
// 可完整讀出 `/proc/<pid>/environ`（含跨會話），該保護根本不存在。
//
// 憑證面現在由「CLI 子程序完全不持有真憑證」承擔（密碼改 PTY 提示注入），
// 守衛在 `dbproxy.TestCredentialNeverEntersChildProcess`。本測試降級為環境組裝的
// 確定性檢查（順序穩定、機密不混入前段），**SHALL NOT 再被引用為憑證面的保護**。
func TestCLIProcessEnvironFirstEntryIsNotCredential(t *testing.T) {
	// 以子程序自己印出的 environ 順序驗證（root 在容器內無 CAP_SYS_PTRACE，
	// 讀不到降權子程序的 /proc/<pid>/environ）
	conn, err := StartWithOptions("/bin/busybox", []string{"env"},
		[]string{"PGPASSWORD=sentinel-not-a-real-secret"}, 80, 24, Options{User: CLIUser})
	if err != nil {
		t.Fatalf("降權啟動失敗: %v", err)
	}
	defer conn.Close()

	out := readUntil(t, conn, "PGPASSWORD=", 3*time.Second)
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "PATH=") {
		t.Errorf("子程序環境的第一段為 %q，期望 PATH=…（環境組裝順序不確定）", out)
	}

}

// TestCLIProcessProcNodesNotWorldReadable CLI 子程序的 /proc 節點不得對「該身分
// 以外」開放。
//
// 已知且已實測的殘留：同一降權身分的其他 DB 會話讀得到彼此的 `environ`／`cmdline`
// （以 `\lo_import` 這類二進位讀取原語可取得完整內容——舊版「止於第一個 NUL」的
// 說法只對文字讀取成立，見 design D15；憑證已不在其中），`fd/` 亦可列出並 readlink
// （同 uid 的 ptrace 檢查通過）。擋下 fd 實際讀寫的是 pts 節點的 root:tty 權限，
// 見 TestCLISessionPTYIsNotAccessibleToCLIUser。
// 要完全消除跨會話面需 per-session uid，見 design 的殘留風險段。
func TestCLIProcessProcNodesNotWorldReadable(t *testing.T) {
	uid, gid, _, err := LookupUser(CLIUser)
	if err != nil {
		t.Fatalf("查不到 CLI 降權身分: %v", err)
	}
	// cat 常駐：短命子程序變成殭屍後 /proc 節點的 owner 會退回 root，測到的
	// 就不是「執行中的 CLI」（曾因此假綠）
	conn, err := StartWithOptions("/bin/busybox", []string{"cat"}, nil, 80, 24,
		Options{User: CLIUser})
	if err != nil {
		t.Fatalf("降權啟動失敗: %v", err)
	}
	defer conn.Close()

	for _, node := range []string{"environ", "fd"} {
		st := statOf(t, fmt.Sprintf("/proc/%d/%s", conn.Pid(), node))
		if st.Mode&0044 != 0 {
			t.Errorf("/proc/<cli-pid>/%s 的 group/other 位元非零（mode=%o）——"+
				"非 CLI 身分者亦可讀", node, st.Mode&07777)
		}
		if st.Uid != uint32(uid) || st.Gid != uint32(gid) {
			t.Logf("/proc/<cli-pid>/%s owner=%d:%d（非 %d:%d，子程序可能已結束）",
				node, st.Uid, st.Gid, uid, gid)
		}
	}
}
