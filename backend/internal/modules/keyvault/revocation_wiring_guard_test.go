package keyvault_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 撤銷管道接線守衛。
//
// 三條使用者級／provider 級的收線管道（協議會話、唯讀訂閱、錄影 token）在
// service 端一律採 **nil 容忍**：revokeUserAccess／revokeProviderAccess 對未注入的
// 管道靜默跳過。那是刻意的——把它們改成必要依賴會讓大量只測判定邏輯的測試被迫
// 構造三個假管道。代價是接線本身失去任何訊號：若未來重構漏掉 stage2.go 的某個
// Set* 呼叫，停用／解綁／provider 撤銷會**永久靜默失效**，既不 panic 也不報錯，
// 且行為看起來一切正常（操作回 200、審計寫下「已撤銷」），只有攻擊者會發現。
//
// 本守衛以 AST 掃描 stage2.go（比照 auth_context_touchpoints_guard_test.go 的形狀）
// 把「接線存在」變成編譯期以外的機械保證：六個呼叫缺任一即紅。
//
// 判定方向與 touchpoints 守衛相反且刻意：那份擋的是「未登記的新呼叫點」，
// 本份擋的是「登記的呼叫點消失」——nil 容忍的缺口只可能以「少一行」的形態出現。

// revocationWiringSite 一條必須存在的撤銷管道接線
type revocationWiringSite struct {
	receiver string // 接收者識別字（`userService` 或 `s.userService` 皆記為 userService）
	method   string // 注入方法名
	purpose  string // 缺少時會靜默失效的能力
}

// revocationWiringSites stage2.go 必須完成的六條接線。
//
// 兩個 service × 三條管道：使用者級（解綁／解綁＋停用／改為僅外部登入）與
// provider 級（停用／刪除／密鑰輪替）各自需要完整三條，缺一即留下一類存活的存取。
var revocationWiringSites = []revocationWiringSite{
	{receiver: "userService", method: "SetSessionTerminator",
		purpose: "使用者級協議會話終斷：連線建立後不再出示憑證，對世代閘完全免疫"},
	{receiver: "userService", method: "SetSubscriptionTerminator",
		purpose: "使用者級唯讀訂閱收線：監看／分享不建 sessions 列，會話掃描掃不到"},
	{receiver: "userService", method: "SetRecordingTokenRevoker",
		purpose: "使用者級錄影 token 撤銷：token 為 in-memory 且不做世代比對，唯一失效途徑"},
	{receiver: "oidcProviderService", method: "SetSessionTerminator",
		purpose: "provider 級協議會話終斷（停用／刪除／密鑰輪替後的既有連線）"},
	{receiver: "oidcProviderService", method: "SetSubscriptionTerminator",
		purpose: "provider 級唯讀訂閱收線"},
	{receiver: "oidcProviderService", method: "SetRecordingTokenRevoker",
		purpose: "provider 級錄影 token 撤銷"},
}

// scanRevocationWiring 掃出檔案內出現過的 `<receiver>.<method>()` 呼叫集合。
// key 為 "receiver.method"；接收者識別字取運算式最後一個 Ident（`s.userService`
// 與 `userService` 視為同一個），與 touchpoints 守衛的 receiverKey 同語義
func scanRevocationWiring(t *testing.T, path string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗: %v", path, err)
	}
	methods := map[string]bool{}
	for _, s := range revocationWiringSites {
		methods[s.method] = true
	}
	found := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !methods[sel.Sel.Name] {
			return true
		}
		found[receiverKey(sel.X)+"."+sel.Sel.Name] = true
		return true
	})
	return found
}

// missingRevocationWiring 清冊中未出現於 found 的接線（排序後回傳，訊息穩定）
func missingRevocationWiring(found map[string]bool) []revocationWiringSite {
	var missing []revocationWiringSite
	for _, s := range revocationWiringSites {
		if !found[s.receiver+"."+s.method] {
			missing = append(missing, s)
		}
	}
	sort.Slice(missing, func(i, j int) bool {
		return missing[i].receiver+missing[i].method < missing[j].receiver+missing[j].method
	})
	return missing
}

const revocationWiringFile = "cmd/server/stage2.go"

// TestRevocationChannelsWired 六條撤銷管道皆已於 stage2.go 接線
func TestRevocationChannelsWired(t *testing.T) {
	// 掃描根以 go.mod module 身分為錨（repoRoot，見 aad_write_guard_test.go）：
	// 原先的 filepath.Join("..","..") 綁死「本 package 住在 internal/service」，
	// package 一下移即指向不存在的路徑。
	path := filepath.Join(repoRoot(t), filepath.FromSlash(revocationWiringFile))
	// 具名路徑的 fail-close：組裝根搬家時必須「找不到即紅」，
	// 不能讓 parser 的錯誤訊息把人導向別處。
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("找不到組裝根 %s（%s）：接線守衛的被驗證對象不存在即等於沒有守衛。"+
			"若組裝根搬遷，SHALL 同步更新 revocationWiringFile: %v",
			revocationWiringFile, path, err)
	}
	found := scanRevocationWiring(t, path)
	if len(found) == 0 {
		t.Fatalf("在 %s 未掃到任何 Set* 撤銷管道呼叫——AST 掃描失效，守衛已失去意義",
			revocationWiringFile)
	}

	missing := missingRevocationWiring(found)
	if len(missing) == 0 {
		return
	}
	var lines []string
	for _, s := range missing {
		lines = append(lines, "  "+s.receiver+"."+s.method+"() 缺失 —— "+s.purpose)
	}
	t.Fatalf("撤銷管道接線缺失會使停用/解綁靜默失效：\n%s\n\n"+
		"service 端對未注入的管道採 nil 容忍（為測試便利，刻意不改成必要依賴），"+
		"故漏掉接線既不會 panic 也不會有任何錯誤訊號——操作照樣回成功、審計照樣寫下"+
		"「已撤銷」，但既有的協議連線／唯讀訂閱／錄影 token 全部繼續存活。\n"+
		"請於 %s 補回上列 Set* 呼叫；若接線位置搬移到其他檔案，"+
		"須同步更新本守衛的 revocationWiringFile。",
		strings.Join(lines, "\n"), revocationWiringFile)
}

// TestRevocationWiringGuardDetectsMissingCall 守衛的自我驗證（突變測試）。
//
// 以「刻意漏接一條」的 fixture 餵給同一個掃描器，斷言它確實抓得到。
// 缺此案時，掃描器若因日後重構（例如接收者改名）而恆回空集合，
// 上面那條 TestRevocationChannelsWired 會靜默轉為假綠
func TestRevocationWiringGuardDetectsMissingCall(t *testing.T) {
	path := filepath.Join("testdata", "revocation_wiring_missing.go.txt")
	found := scanRevocationWiring(t, path)

	missing := missingRevocationWiring(found)
	if len(missing) != 1 {
		t.Fatalf("fixture 漏接一條，掃描器回報 %d 條缺失, want 1（found=%v）", len(missing), found)
	}
	if missing[0].receiver != "oidcProviderService" || missing[0].method != "SetRecordingTokenRevoker" {
		t.Errorf("抓到的缺失 = %s.%s, want oidcProviderService.SetRecordingTokenRevoker",
			missing[0].receiver, missing[0].method)
	}
}

// ── [cmd/server/auth_context_touchpoints_guard_test.go] 的複本 ─────
//
// 這兩項原本住在 `internal/service/identity_fixtures_leftover_test.go`；
// 該檔隨 `internal/service` 一併消滅，而本檔是它在本包內的唯一消費者，
// 故就近落在本檔而不另立夾具檔。

// authContextUnknownRecv 解析不出接收者識別字時的佔位鍵
const authContextUnknownRecv = "<unknown>"

// receiverKey 方法呼叫接收者的辨識鍵：取運算式最後一個識別字
// （`h.ConnectTokens` → `ConnectTokens`、`strings` → `strings`）。
// 取不到識別字（如 `f().Join(...)`）回 authContextUnknownRecv，一律不套用例外清單
// ——即 fail-close，強迫登記。
func receiverKey(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	default:
		return authContextUnknownRecv
	}
}
