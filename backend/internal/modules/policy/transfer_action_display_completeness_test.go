package policy

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 資料傳輸能力動作碼（`TransferAction*`）的三語完備性守衛。
//
// **為何既有守衛擋不住**：transmission_display_completeness_test.go 管的是
// policyLabel／riskLabel／transportNote 等 6 個 namespace，不含
// `transferCapability.action`；i18n.spec.js 只比對三語鍵集合是否相等，後端新增
// 一個 `TransferActionFileXxx` 而三語同缺時集合仍相等、全綠。實際後果是
// FileManager.vue 的 `deniedActionLabels` 對該動作渲染出裸 i18n 鍵
// （`transferCapability.action.file_rename`）貼在「以下動作已被政策停用」的提示裡。
//
// **只要求 file_ 前綴的動作有譯文**：deniedFileActions 顯式 `startsWith('file_')`
// 過濾，剪貼簿兩個動作走另一條提示路徑、刻意無 action 標籤。若日後剪貼簿也要
// 列名，屆時應同時放寬本守衛與前端過濾——兩者一起改才對得起來。

// transferActionSourceRel TransferAction 常數所在（相對本 package 目錄）
const transferActionSourceRel = "data_transfer_service.go"

// transferActionNS locale 中的巢狀 namespace 路徑
var transferActionNS = []string{"transferCapability", "action"}

// transferActionLabeledPrefix 需要顯示名的動作前綴（見檔頭）
const transferActionLabeledPrefix = "file_"

// minTransferActions 後端常數數量下限（防空集合假綠）。
// 2026-08-13 現況 5 個（剪貼簿 2＋檔案 3），門檻取 5
const minTransferActions = 5

// transferActionValues 由 AST 抽出全部 `TransferActionXxx = "..."` 常數值。
//
// 以 AST 而非正則：常數區塊排版一改，正則會靜默回空集合而假綠
func transferActionValues(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, transferActionSourceRel, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗：守衛拒絕在殘缺的 AST 上作判定: %v", transferActionSourceRel, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if !strings.HasPrefix(name.Name, "TransferAction") || i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			if s, err := strconv.Unquote(lit.Value); err == nil && s != "" {
				out = append(out, s)
			}
		}
		return true
	})
	sort.Strings(out)
	return out
}

// diffTransferActionLabels 比對「後端需標名的動作」與「單一 locale 的譯文表」。
//
// 抽成純函式是為了讓偵測力本身可被測試（合成輸入自證，不碰真實 locale）
func diffTransferActionLabels(actions []string, got map[string]string) (missing, stale []string) {
	need := map[string]bool{}
	for _, a := range actions {
		if !strings.HasPrefix(a, transferActionLabeledPrefix) {
			continue
		}
		need[a] = true
		if v, ok := got[a]; !ok || v == "" {
			missing = append(missing, a)
		}
	}
	for k := range got {
		if !need[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	return missing, stale
}

func transferActionLocale(t *testing.T, dir, locale string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, locale+".json"))
	if err != nil {
		t.Fatalf("讀 %s locale 失敗: %v", locale, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 %s locale 失敗: %v", locale, err)
	}
	node := any(doc)
	for _, seg := range transferActionNS {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%s 的 %v 路徑中斷於 %q", locale, transferActionNS, seg)
		}
		node, ok = m[seg]
		if !ok {
			t.Fatalf("%s 缺 %v（斷在 %q）：檔案面停用提示將整段顯示裸 i18n 鍵", locale, transferActionNS, seg)
		}
	}
	body, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("%s 的 %v 不是物件", locale, transferActionNS)
	}
	out := map[string]string{}
	for k, v := range body {
		s, _ := v.(string)
		out[k] = s
	}
	return out
}

// TestTransferActionLabelsTranslated 後端每個檔案面動作碼在三語皆有顯示名。
func TestTransferActionLabelsTranslated(t *testing.T) {
	actions := transferActionValues(t)
	if len(actions) < minTransferActions {
		t.Fatalf("只掃到 %d 個 TransferAction 常數（現況至少 %d）：AST 條件已失真，本守衛正在放行一切",
			len(actions), minTransferActions)
	}
	dir := displayLocaleDir(t)
	for _, locale := range displayLocales {
		got := transferActionLocale(t, dir, locale)
		missing, stale := diffTransferActionLabels(actions, got)
		for _, a := range missing {
			t.Errorf("%s 的 transferCapability.action 缺 %q：停用提示會顯示裸 i18n 鍵", locale, a)
		}
		for _, a := range stale {
			t.Errorf("%s 的 transferCapability.action 登記了 %q 但後端無此動作：譯文腐爛，請刪除該條目", locale, a)
		}
	}
	if !t.Failed() {
		t.Logf("TransferAction 常數 %d 個（%v），檔案面動作三語皆有顯示名", len(actions), actions)
	}
}

// TestTransferActionDiffDetectsBothDirections 比對器的偵測力自證（合成輸入）。
func TestTransferActionDiffDetectsBothDirections(t *testing.T) {
	actions := []string{"clipboard_send", "file_upload", "file_download"}

	// 方向一：後端新增 file_ 動作而三語同缺
	missing, stale := diffTransferActionLabels(actions,
		map[string]string{"file_upload": "Upload"})
	if len(missing) != 1 || missing[0] != "file_download" {
		t.Fatalf("漏譯未被偵測：missing=%v", missing)
	}
	if len(stale) != 0 {
		t.Fatalf("誤報腐爛：stale=%v", stale)
	}

	// 剪貼簿動作不要求標名（刻意），不得被算成漏譯
	missing, _ = diffTransferActionLabels(actions,
		map[string]string{"file_upload": "Upload", "file_download": "Download"})
	if len(missing) != 0 {
		t.Fatalf("剪貼簿動作被誤判為需標名：missing=%v", missing)
	}

	// 方向二：locale 有而後端已無
	_, stale = diffTransferActionLabels(actions, map[string]string{
		"file_upload": "a", "file_download": "b", "file_rename": "c"})
	if len(stale) != 1 || stale[0] != "file_rename" {
		t.Fatalf("腐爛條目未被偵測：stale=%v", stale)
	}

	// 空字串譯文等同缺譯
	missing, _ = diffTransferActionLabels(actions, map[string]string{
		"file_upload": "", "file_download": "b"})
	if len(missing) != 1 || missing[0] != "file_upload" {
		t.Fatalf("空字串譯文未被當成缺譯：missing=%v", missing)
	}
}
