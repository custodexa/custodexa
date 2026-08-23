package config

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
)

// 文件化的 KEK 生成指令與伺服端驗證的**相容性**守衛。
//
// 缺陷史（兩輪，兩次都是「文件叫人做的事，系統會拒絕」）：
//
//  1. `.env.example` 與列 3b 錯誤訊息都指示 `openssl rand -base64 24`，但驗證器只收
//     A-Za-z0-9；base64 字元集含 `+` `/`，理論 (62/64)^32 ≈ 36% 通過。照文件做有六成
//     機率拒啟動，而錯誤訊息又重複同一條壞指令 → 操作者無自救線索。
//  2. 2026-08-16 全新安裝實測：operator 自行使用 `openssl rand -hex 32`（一把完全
//     正確的 32 位元組金鑰的 hex 編碼）而被拒。真因是驗證器把「輸入編碼」與「金鑰
//     長度」綁成同一條規則；處置是拆開兩者，並把單一指令改為涵蓋三形態的集合。
//
// 本檔釘住三件事：
//  1. 集合中的每一條指令都是**實跑**必然產出合格值的（不是「通常會過」）；
//  2. 每條指令實際產出的形態與其宣告的 Form 相符（宣告漂移會被抓到）；
//  3. 三種形態都有代表，且列 3b 錯誤訊息逐條列出（自救線索）。
//
// **不做 skip**：本測試需要 `openssl` 與 `tr`，兩者皆已備於 dev 映像
// （docker/backend/Dockerfile.dev）。缺二進位就跳過會得到一個「綠燈但什麼都沒驗」
// 的守衛——而那正是上述兩輪缺陷得以存活的機制。

// documentedKEKCommandRuns 每條指令的實跑次數。單次通過機率若為 p，N 次全過的機率
// 為 p^N；舊壞指令 p≈0.36 時 30 次全過的機率 ≈ 5e-14，故本測試對「指令又被換回
// 不相容形式」是實質偵測器而非空轉。
const documentedKEKCommandRuns = 30

// TestDocumentedKEKCommandsAlwaysValidate 集合中每條指令的產出**必然**通過伺服端驗證
func TestDocumentedKEKCommandsAlwaysValidate(t *testing.T) {
	if runtime.GOOS != "linux" {
		// 專案約定測試一律在 docker-compose（linux）內跑；非 linux 時
		// /dev/urandom、tr 與 openssl 的行為不保證一致，跳過而非假紅
		t.Skipf("非 linux（%s）：本測試須於 docker-compose 容器內執行", runtime.GOOS)
	}
	for _, spec := range KEKGenerateCommands {
		t.Run(spec.Command, func(t *testing.T) {
			for i := 0; i < documentedKEKCommandRuns; i++ {
				// 走 shell 是本測試的**受測對象本身**：這些指令是文件化給操作者
				// 貼進 shell 的管線（含 `<` 與 `|`），必須以同一方式執行才算驗到
				// 「照文件做會怎樣」。它們是本套件的編譯期字面，非使用者輸入，無注入面。
				out, err := exec.Command("sh", "-c", spec.Command).Output() //nolint:gosec // 常數指令，非使用者輸入
				if err != nil {
					t.Fatalf("第 %d 次執行文件化生成指令失敗（指令本身不可用即等同文件失效）：%v\n指令：%s",
						i+1, err, spec.Command)
				}
				material := string(out)
				if v := ValidateKEKMaterial(material); v != "" {
					t.Fatalf("第 %d 次執行的產出未通過伺服端驗證（%s）：輸入長度=%d\n"+
						"指令：%s\n照文件生成的值必須恆可啟動",
						i+1, v, len(material), spec.Command)
				}
				// 宣告漂移守衛：指令若被換成別種形態而 Form 欄未同步，
				// 介面的「每形態各一條」承諾會靜默失效
				key, form, reason := crypto.DecodeKEKMaterial(material)
				if reason != "" {
					t.Fatalf("第 %d 次產出無法解碼（%s）：%s", i+1, reason, spec.Command)
				}
				if len(key) != crypto.KEKMaterialLength {
					t.Fatalf("第 %d 次產出解出 %d bytes，應為 %d：%s",
						i+1, len(key), crypto.KEKMaterialLength, spec.Command)
				}
				if form != spec.Form {
					t.Fatalf("指令產出形態為 %q，但集合宣告為 %q：%s", form, spec.Form, spec.Command)
				}
			}
		})
	}
}

// TestDocumentedKEKCommandsCoverEveryForm 三種輸入形態各至少一條，且無重複形態
// ——「每形態恰一條」是設計裁決（列多條同形態只是雜訊、列不全則使用者仍會自創指令）
func TestDocumentedKEKCommandsCoverEveryForm(t *testing.T) {
	seen := map[string]string{}
	for _, spec := range KEKGenerateCommands {
		switch spec.Form {
		case crypto.KEKFormRaw, crypto.KEKFormHex, crypto.KEKFormBase64:
		default:
			t.Fatalf("指令 %q 宣告了未知形態 %q", spec.Command, spec.Form)
		}
		if prev, dup := seen[spec.Form]; dup {
			t.Fatalf("形態 %q 有兩條指令（%q 與 %q）：每形態恰一條", spec.Form, prev, spec.Command)
		}
		seen[spec.Form] = spec.Command
		if strings.TrimSpace(spec.Command) == "" {
			t.Fatalf("形態 %q 的指令為空", spec.Form)
		}
	}
	for _, form := range []string{crypto.KEKFormRaw, crypto.KEKFormHex, crypto.KEKFormBase64} {
		if seen[form] == "" {
			t.Fatalf("形態 %q 缺少文件化生成指令：使用者會自行發明指令，而那正是缺陷成因", form)
		}
	}
}

// TestRow3bErrorMessageQuotesEveryCommand 列 3b 的錯誤訊息必須附上**全部**可用的
// 生成指令——這條訊息壞過兩次：一次重複了同一條壞指令，一次只給了一條而使用者
// 自創了一條被拒的指令。兩次的共同解法都是「把可用的選項完整攤在眼前」
func TestRow3bErrorMessageQuotesEveryCommand(t *testing.T) {
	env := map[string]string{
		EnvKeyKEKProvider:   KEKModeEnv,
		EnvKeyEncryptionKey: "short",
	}
	_, err := DecideKEK(MapEnvLookup(env), false)
	if err == nil {
		t.Fatal("材料不合格應拒絕啟動（列 3b）")
	}
	if !strings.Contains(err.Error(), "[列 3b]") {
		t.Fatalf("應命中列 3b，得：%v", err)
	}
	for _, cmd := range KEKGenerateCommandLines() {
		if !strings.Contains(err.Error(), cmd) {
			t.Fatalf("列 3b 錯誤訊息須附上每一條生成指令（缺 %q）：%v", cmd, err)
		}
	}
}

// frontendKEKCommandsRel 前端指令集合相對專案根的路徑（host 直跑時的 fallback）
const frontendKEKCommandsRel = "frontend/src/constants/kek-generate-commands.json"

// frontendKEKCommandsMount dev compose 於 backend 容器內的唯讀掛載點。
// 相對本套件目錄（容器內 /app/config）解析，故 `../testdata` 即 /app/testdata。
const frontendKEKCommandsMount = "../testdata/frontend-constants/kek-generate-commands.json"

// TestFrontendKEKCommandsMatchBackend 介面列出的生成指令與後端集合**逐條相同**。
//
// 為何需要機械守衛而非人工約定：本次缺陷的形狀正是「文件／介面說的做法與系統
// 會接受的東西不一致」。介面列一組、範本列另一組而沒有任何東西會轉紅，
// 只會把同一個缺陷換個位置再犯一次——**不一致的指引比沒有指引更糟**。
//
// 找不到檔案即 Fatal，不 skip：skip 的守衛不算驗過。
func TestFrontendKEKCommandsMatchBackend(t *testing.T) {
	path := frontendKEKCommandsPath(t)
	body, err := os.ReadFile(path) //nolint:gosec // 測試資料路徑，非使用者輸入
	if err != nil {
		t.Fatalf("讀取前端 KEK 生成指令 %s 失敗（守衛不得在缺檔時跳過）: %v", path, err)
	}
	var doc struct {
		Commands []struct {
			Command string `json:"command"`
			Form    string `json:"form"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("解析 %s 失敗: %v", path, err)
	}
	if len(doc.Commands) != len(KEKGenerateCommands) {
		t.Fatalf("前端列 %d 條生成指令，後端 %d 條：兩處必須逐條一致",
			len(doc.Commands), len(KEKGenerateCommands))
	}
	for i, want := range KEKGenerateCommands {
		got := doc.Commands[i]
		if got.Command != want.Command || got.Form != want.Form {
			t.Fatalf("第 %d 條不一致：前端 %q/%q，後端 %q/%q",
				i+1, got.Command, got.Form, want.Command, want.Form)
		}
	}
}

// frontendKEKCommandsPath 解析前端指令檔路徑：容器掛載點優先，其次 host repo 根。
func frontendKEKCommandsPath(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat(frontendKEKCommandsMount); err == nil {
		return frontendKEKCommandsMount
	}
	// host 直跑：本套件位於 <repo>/backend/config
	host := filepath.Join("..", "..", frontendKEKCommandsRel)
	if _, err := os.Stat(host); err == nil {
		return host
	}
	t.Fatalf("找不到前端 KEK 生成指令檔（掛載點 %s、host 路徑 %s 皆不存在）"+
		"：守衛不得在缺檔時跳過", frontendKEKCommandsMount, host)
	return ""
}
