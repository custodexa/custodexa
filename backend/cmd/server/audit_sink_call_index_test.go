package main

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
	"testing"
)

// 審計落地面的 **sink 呼叫主索引**。
//
// # 為什麼字面量不能當主索引
//
// `audit_points_manifest_guard_test.go` 的第 4 條判準（`port.AuditEvent{…}`／
// `gatewayapi.AuditEvent{…}` 複合字面量）抓的是**事件在哪裡被建構**。它在現行收口
// 形態下剛好與「審計寫入點」一一對應，但那是巧合，不是不變式：只要下一波把事件建構
// 改成 helper constructor（`newAssetEvent(...)`）、函式回傳（`return port.AuditEvent{…}`
// 收進一個 builder）、或用變數轉傳（`ev := …; …; WriteInTx(sink, tx, ev)`），
// **真正的 sink 呼叫仍在，字面量卻從掃描面上消失**——而且產生點總數還可能被別處
// 新增的字面量抵銷，看起來一動也沒動。
//
// 本守衛換一個索引軸：**sink 呼叫本身**（`port.WriteInTx(...)` 與
// `AsyncSink.Submit(ctx, ev)`）。它是「審計真的被交出去落地」的那一刻，
// 不依賴事件是怎麼被組出來的。字面量判準退為輔助（仍在原守衛內）。
//
// 兩個下界分開釘（同一份審查焦點 3 明列）：
//   - **消費端產生點**——業務程式碼呼叫 sink 的位置。它們是 fail-close 語義的所在，
//     少一個就是少一條審計；且每一個都必須在 manifest 有登記列。
//   - **sink 實作點**——落地面自身（`WriteInTx`／`Submit` 的方法宣告）。它們是
//     19 個 TxSink 點的唯一實際寫入位置；被繞過、被複製出第二份、或被改成
//     no-op，消費端的下界一個都不會動。

// ── 受管的 sink 方法名與判定規則 ──────────────────────────────────────────

const (
	auditSinkModuleDir = "internal/modules/audit/" // sink 實作與 port 的家
)

// minAuditSinkConsumerWriteInTx 消費端 `port.WriteInTx(...)` 呼叫點下界。
// 現況 5（asset_group ×2／user_group／ldap_directory／ldap_seed）；asset 模組收口
// 後會增至 19。取現況值——**這條只准增不准減**，減少即代表某個 fail-close 點
// 被改回舊形態或整條消失。
const minAuditSinkConsumerWriteInTx = 5

// minAuditSinkConsumerSubmit 消費端 AsyncSink `Submit(ctx, ev)` 呼叫點下界（現況 2）。
const minAuditSinkConsumerSubmit = 2

// minAuditSinkImplWriteInTx／Submit sink 實作點（方法宣告）下界。
// 現況：WriteInTx＝2（`port.WriteInTx` 包裝函式＋`txSink.WriteInTx` 落地本體）、
// Submit＝2（`AuditLogService.Submit`＋`directSink.Submit`）。
const (
	minAuditSinkImplWriteInTx = 2
	minAuditSinkImplSubmit    = 2
)

type sinkCallSite struct {
	File string
	Line int
	Kind string // WriteInTx／Submit
	Form string // 呼叫形態（錯誤訊息用）
}

func (s sinkCallSite) key() string { return fmt.Sprintf("%s:%d", s.File, s.Line) }

type sinkImplSite struct {
	File string
	Line int
	Kind string
	Decl string
}

// scanAuditSinkSites 掃出全模組（非測試碼）的 sink 呼叫點與實作點。
//
// 判定規則（刻意保守且可解釋，不做型別推導——本守衛的價值在「索引軸不同」，
// 不在「判定更聰明」；型別層的雙射另以 go/types 三方雙射處理）：
//
//	消費端 WriteInTx：`port.WriteInTx(...)` 三引數呼叫，或 `X.WriteInTx(tx, ev)`
//	                  兩引數選擇器呼叫且**不在** internal/modules/audit/ 下。
//	消費端 Submit    ：`X.Submit(a, b)` **恰兩個引數**的選擇器呼叫，且不在 audit 模組下。
//	                  兩引數是關鍵鑑別條件——同名的 `AccessRequestService.Submit`
//	                  是四引數，不會誤收（`TestAuditSinkSubmitArityIsDiscriminating`
//	                  把這個前提釘住，它一旦不成立本守衛會誤判）。
//	實作點          ：名為 WriteInTx／Submit 的 FuncDecl（含 port 的包裝函式）。
func scanAuditSinkSites(t *testing.T, root string) ([]sinkCallSite, []sinkImplSite, int) {
	t.Helper()
	files, scanned := parseModuleFiles(t, root)
	if scanned < minScannedGoFiles {
		t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）：掃描根或走訪邏輯已失真",
			scanned, minScannedGoFiles)
	}
	var calls []sinkCallSite
	var impls []sinkImplSite
	for _, pf := range files {
		inAudit := strings.HasPrefix(pf.Rel, auditSinkModuleDir)
		ast.Inspect(pf.File, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				if node.Name == nil {
					return true
				}
				name := node.Name.Name
				if name != "WriteInTx" && name != "Submit" {
					return true
				}
				if !inAudit {
					return true
				}
				impls = append(impls, sinkImplSite{
					File: pf.Rel, Line: pf.Fset.Position(node.Pos()).Line,
					Kind: name, Decl: declLabel(node),
				})
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				x, isIdent := sel.X.(*ast.Ident)
				switch sel.Sel.Name {
				case "WriteInTx":
					if inAudit {
						return true
					}
					form := "X.WriteInTx(tx, ev)"
					if isIdent && x.Name == "port" {
						if len(node.Args) != 3 {
							return true
						}
						form = "port.WriteInTx(sink, tx, ev)"
					} else if len(node.Args) != 2 {
						return true
					}
					calls = append(calls, sinkCallSite{
						File: pf.Rel, Line: pf.Fset.Position(node.Pos()).Line,
						Kind: "WriteInTx", Form: form,
					})
				case "Submit":
					if inAudit || len(node.Args) != 2 {
						return true
					}
					calls = append(calls, sinkCallSite{
						File: pf.Rel, Line: pf.Fset.Position(node.Pos()).Line,
						Kind: "Submit", Form: "X.Submit(ctx, ev)",
					})
				}
			}
			return true
		})
	}
	sort.Slice(calls, func(i, j int) bool {
		if calls[i].File != calls[j].File {
			return calls[i].File < calls[j].File
		}
		return calls[i].Line < calls[j].Line
	})
	sort.Slice(impls, func(i, j int) bool {
		if impls[i].File != impls[j].File {
			return impls[i].File < impls[j].File
		}
		return impls[i].Line < impls[j].Line
	})
	return calls, impls, scanned
}

func declLabel(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return "func " + fn.Name.Name
	}
	return "method " + fn.Name.Name
}

// TestAuditSinkCallSitesArePrimaryIndex sink 呼叫主索引的兩個下界＋manifest 交叉核對。
//
// 名稱刻意不叫 “…Complete”：它釘的是**下界**與**登記完備**，不是「這就是全部」。
func TestAuditSinkCallSitesArePrimaryIndex(t *testing.T) {
	root := auditPointModuleRoot(t)
	calls, impls, scanned := scanAuditSinkSites(t, root)

	byKind := map[string][]sinkCallSite{}
	for _, c := range calls {
		byKind[c.Kind] = append(byKind[c.Kind], c)
	}
	implByKind := map[string][]sinkImplSite{}
	for _, i := range impls {
		implByKind[i.Kind] = append(implByKind[i.Kind], i)
	}

	// ── 下界 1：消費端產生點 ──
	if got := len(byKind["WriteInTx"]); got < minAuditSinkConsumerWriteInTx {
		t.Errorf("消費端 TxSink 呼叫點只剩 %d 個（下界 %d）：某個交易內 fail-close 點被改回舊形態、"+
			"被繞過、或整條消失。**這條下界只准增不准減**——收口後應為 19。實測清單：\n  %s",
			got, minAuditSinkConsumerWriteInTx, formatCalls(byKind["WriteInTx"]))
	}
	if got := len(byKind["Submit"]); got < minAuditSinkConsumerSubmit {
		t.Errorf("消費端 AsyncSink 呼叫點只剩 %d 個（下界 %d）：非交易審計的落地面被繞過。實測清單：\n  %s",
			got, minAuditSinkConsumerSubmit, formatCalls(byKind["Submit"]))
	}

	// ── 下界 2：sink 實作點 ──
	//
	// 消費端下界不動、實作點被改成 no-op 或被複製出第二份，是「字面量索引」與
	// 「消費端索引」都看不見的退化：呼叫還在、事件還在、審計卻不落地。
	if got := len(implByKind["WriteInTx"]); got < minAuditSinkImplWriteInTx {
		t.Errorf("TxSink 落地面的實作點只剩 %d 個（下界 %d）：`port.WriteInTx` 包裝或 "+
			"`txSink.WriteInTx` 落地本體之一已消失——nil 檢查與唯一寫入位置的保證隨之失效。實測：\n  %s",
			got, minAuditSinkImplWriteInTx, formatImpls(implByKind["WriteInTx"]))
	}
	if got := len(implByKind["Submit"]); got < minAuditSinkImplSubmit {
		t.Errorf("AsyncSink 落地面的實作點只剩 %d 個（下界 %d）。實測：\n  %s",
			got, minAuditSinkImplSubmit, formatImpls(implByKind["Submit"]))
	}

	// ── 交叉核對：每個消費端 sink 呼叫點都必須在 manifest 有登記列 ──
	//
	// 這是把「主索引」真正接上權威的一步：字面量消失時，manifest 的反向斷言
	// （現實→manifest）看不見這些點，本段仍看得見。
	rows := parseAuditPointManifest(t, auditPointManifestPath(t, root))
	inManifest := map[string]manifestRow{}
	for _, r := range rows {
		inManifest[r.key()] = r
	}
	for _, c := range calls {
		r, ok := inManifest[c.key()]
		if !ok {
			t.Errorf("[sink 呼叫→manifest] %s（%s，%s）未登記於 manifest："+
				"審計落地面被呼叫卻沒有對應的產生點列——事件建構若改走 helper／builder，"+
				"字面量判準會同時失明，此時只有本段看得見它",
				c.key(), c.Kind, c.Form)
			continue
		}
		wantVariant := "TxSink"
		if c.Kind == "Submit" {
			wantVariant = "AsyncSink"
		}
		if r.Variant != wantVariant {
			t.Errorf("[sink 呼叫→manifest] %s（%s，manifest L%d）實際呼叫 %s，manifest 卻分派 %q",
				r.ID, c.key(), r.DocLine, c.Kind, r.Variant)
		}
		if c.Kind == "WriteInTx" && !strings.HasPrefix(r.TxBase, "是") {
			t.Errorf("[sink 呼叫→manifest] %s（%s，manifest L%d）走 TxSink 的 WriteInTx，"+
				"「呼叫方交易內」欄卻是 %q——交易內寫入的判定與實際落地面不一致",
				r.ID, c.key(), r.DocLine, r.TxBase)
		}
	}

	t.Logf("sink 呼叫主索引（掃描 %d 檔）：消費端 WriteInTx %d／Submit %d；"+
		"實作點 WriteInTx %d／Submit %d", scanned,
		len(byKind["WriteInTx"]), len(byKind["Submit"]),
		len(implByKind["WriteInTx"]), len(implByKind["Submit"]))
}

// TestAuditSinkSubmitArityIsDiscriminating 釘住上面用來鑑別 `Submit` 的前提。
//
// 本模組另有一個同名但語義完全不同的方法：`AccessRequestService.Submit`
// （四引數，送出存取申請）。主索引以「恰兩個引數」把它排除。這個前提一旦不成立
// （例如 AsyncSink 的 Submit 改成三引數、或存取申請的 Submit 減到兩引數），
// 主索引會靜默誤收／漏收——本測試讓那一刻直接轉紅，而不是等某次人工比對。
func TestAuditSinkSubmitArityIsDiscriminating(t *testing.T) {
	root := auditPointModuleRoot(t)
	files, _ := parseModuleFiles(t, root)

	sinkIfaceArity, accessReqArity := -1, -1
	for _, pf := range files {
		ast.Inspect(pf.File, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.InterfaceType:
				// gatewayapi.AsyncSink 的方法集
				if pf.Rel != "pkg/gatewayapi/audit.go" {
					return true
				}
				for _, m := range node.Methods.List {
					if len(m.Names) != 1 || m.Names[0].Name != "Submit" {
						continue
					}
					if ft, ok := m.Type.(*ast.FuncType); ok {
						sinkIfaceArity = paramCount(ft)
					}
				}
			case *ast.FuncDecl:
				if node.Name == nil || node.Name.Name != "Submit" || node.Recv == nil {
					return true
				}
				// **以接收者型別定位，不以檔案路徑定位**：
				// 原本判 `pf.Rel == "internal/service/access_request_service.go"`，
				// 該檔遷入 `internal/modules/authz/` 後這個判準就指不到東西。
				// 它自帶 `accessReqArity < 0 即 t.Fatal` 故會紅不會恆綠，但「紅的理由是
				// 找不到檔案」會誘人把路徑改一改了事——下一次搬檔再壞一次。
				// 接收者型別名跟著程式碼走，搬到哪個包都成立。
				if receiverTypeName(node.Recv) == "AccessRequestService" {
					accessReqArity = paramCount(node.Type)
				}
			}
			return true
		})
	}
	if sinkIfaceArity != 2 {
		t.Fatalf("gatewayapi.AsyncSink.Submit 的參數數量為 %d（期望 2）："+
			"sink 呼叫主索引以「恰兩個引數」鑑別 Submit，此前提已不成立，"+
			"主索引正在漏收 AsyncSink 呼叫點", sinkIfaceArity)
	}
	if accessReqArity == 2 {
		t.Fatal("AccessRequestService.Submit 已變成兩引數：與 AsyncSink.Submit 的鑑別條件相撞，" +
			"sink 呼叫主索引會把存取申請誤收為審計落地點")
	}
	if accessReqArity < 0 {
		t.Fatal("找不到 AccessRequestService.Submit：本測試釘住的同名衝突前提無從驗證，" +
			"若該方法只是改名，請同步更新本測試指向新的同名衝突對象（或刪掉本測試並說明衝突已消失）")
	}
	t.Logf("Submit 鑑別條件成立：AsyncSink.Submit 參數 %d、AccessRequestService.Submit 參數 %d",
		sinkIfaceArity, accessReqArity)
}

func paramCount(ft *ast.FuncType) int {
	if ft == nil || ft.Params == nil {
		return 0
	}
	n := 0
	for _, f := range ft.Params.List {
		if len(f.Names) == 0 {
			n++
			continue
		}
		n += len(f.Names)
	}
	return n
}

func formatCalls(cs []sinkCallSite) string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, fmt.Sprintf("%s（%s）", c.key(), c.Form))
	}
	if len(out) == 0 {
		return "（空）"
	}
	return strings.Join(out, "\n  ")
}

func formatImpls(is []sinkImplSite) string {
	out := make([]string, 0, len(is))
	for _, i := range is {
		out = append(out, fmt.Sprintf("%s:%d（%s）", i.File, i.Line, i.Decl))
	}
	if len(out) == 0 {
		return "（空）"
	}
	return strings.Join(out, "\n  ")
}

// receiverTypeName 取方法接收者的型別名（剝指標）；非方法或取不到回空字串。
//
// 存在的理由見 TestAuditSinkSubmitArityIsDiscriminating 內的註解：
// 以型別身分定位比以檔案路徑定位對搬檔免疫。
func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) != 1 {
		return ""
	}
	e := recv.List[0].Type
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}
