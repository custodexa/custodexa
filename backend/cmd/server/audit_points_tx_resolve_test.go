package main

// 審計產生點交易歸屬判定的**單點解析**（承 `audit_points_tx_dataflow_test.go` 的
// 模組級索引；判定原則、格序與誠實邊界一律見該檔的檔頭）。
//
// 拆檔只為控制單檔行數：前一檔負責「解析全模組並建立可信事實」（作用域、同包函式表、
// 包級變數、tx 逃逸不變式、AuditLogEntry 落地面自檢），本檔負責「拿這些事實對單一
// 產生點作四值判定」——找落地寫入 → 一跳 → receiver 鏈追到根。

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// ── 單點判定 ──────────────────────────────────────────────────────────────

func (idx *txIndex) enclosing(pf *parsedFile, pos token.Pos) []*fnScope {
	var out []*fnScope
	for i := range pf.scopes {
		s := &pf.scopes[i]
		if pos >= s.start && pos < s.end {
			out = append(out, s)
		}
	}
	return out
}

// innermostLabel 產生點最內層包覆函式的標籤（允許清單的語法指紋之一）
func (idx *txIndex) innermostLabel(pf *parsedFile, pos token.Pos) string {
	enc := idx.enclosing(pf, pos)
	if len(enc) == 0 {
		return "(包級)"
	}
	return enc[len(enc)-1].label
}

// verdictAt 對單一產生點作四值判定。
func (idx *txIndex) verdictAt(pf *parsedFile, n ast.Node, kind auditPointKind) (txVerdict, txReason, string) {
	switch kind {
	case kindAuditEntryLit:
		return idx.entryVerdict()
	case kindAuditEventLit:
		return idx.eventVerdict(pf, n)
	case kindRecordCall:
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return txIndeterminate, reasonUnresolvedRoot, "審計 helper 呼叫無引數"
		}
		// 交易句柄的位置隨收口形態改變（W6 6.1）：
		//   收口前 `model.RecordAssetAccountChange(tx, …)`  → 第 1 引數
		//   收口後 `writeAssetAccountAudit(sink, tx, …)`    → 第 2 引數
		// **不能只認第 1 引數**：那會把 sink（非 DB 句柄）當成落地句柄去追，
		// 結果是 11 個交易內產生點整批降為 Indeterminate，TxBound 下限隨即轉紅
		// ——會紅不會靜默，但紅的理由是錯的，且修法會誘向放寬下限。
		argIdx := 0
		note := "落地句柄＝呼叫第一引數；"
		if id, ok := call.Fun.(*ast.Ident); ok && assetAuditWriteFuncs[id.Name] {
			if len(call.Args) < 2 {
				return txIndeterminate, reasonUnresolvedRoot, "asset 審計 helper 引數不足兩個"
			}
			argIdx = 1
			note = "落地句柄＝呼叫第二引數（sink 在前）；"
		}
		enc := idx.enclosing(pf, call.Pos())
		v, r, why := idx.originOf(pf, enc, call.Args[argIdx], 0)
		return v, r, note + why
	default:
		return idx.resolveRow(pf, n, 0)
	}
}

// entryVerdict `service.AuditLogEntry` 的型別層結論。
//
// entry 本身不帶 DB 句柄，落地一律在收下它的函式內以該函式自己的句柄寫入；只要
// **沒有任何落地面同時吃 entry 與 `*gorm.DB`**，呼叫方的 tx 就沒有語法途徑進入該寫入。
// 三個前提任一不成立即降為 Indeterminate（不是靜默沿用結論）。
func (idx *txIndex) entryVerdict() (txVerdict, txReason, string) {
	if !idx.entryTypeFound {
		return txIndeterminate, reasonEntryLandingUnsafe, "找不到 audit.AuditLogEntry 型別宣告，型別層結論無從成立"
	}
	if !idx.entryTypeClean {
		return txIndeterminate, reasonEntryLandingUnsafe, "AuditLogEntry 已帶 gorm.DB 欄位，型別層結論失效"
	}
	if len(idx.entryLandingBad) > 0 {
		return txIndeterminate, reasonEntryLandingUnsafe,
			"下列落地面同時吃 AuditLogEntry 與 *gorm.DB：" + strings.Join(idx.entryLandingBad, "、")
	}
	if len(idx.txEscapes) > 0 {
		return txIndeterminate, reasonTxEscape, txEscapeSummary(idx.txEscapes)
	}
	return txNotBound, reasonEntryTypeLevel,
		"AuditLogEntry 不含 DB 句柄且無任何落地面同時吃 entry 與 *gorm.DB：呼叫方 tx 無語法途徑進入該寫入"
}

func txEscapeSummary(esc []txEscape) string {
	parts := make([]string, 0, len(esc))
	for _, e := range esc {
		parts = append(parts, e.Where+"（"+e.How+"）")
	}
	return "全域 tx 逃逸不變式已破，struct 欄位來源不再可證：" + strings.Join(parts, "；")
}

// resolveRow 追 `model.AuditLog` 字面量的落地寫入。
func (idx *txIndex) resolveRow(pf *parsedFile, lit ast.Node, hop int) (txVerdict, txReason, string) {
	enc := idx.enclosing(pf, lit.Pos())
	if len(enc) == 0 {
		return txIndeterminate, reasonNoWrite, "字面量不在任何函式內（包級宣告），無落地寫入可追"
	}
	inner := enc[len(enc)-1]
	name, def := carrierNameOf(inner.body, lit)
	return idx.resolveCarrier(pf, enc, inner, name, lit, def, hop)
}

// carrierNameOf 字面量若被賦給區域變數，回傳該變數名與定義節點；否則回空名（字面量自身即 carrier）。
func carrierNameOf(body *ast.BlockStmt, lit ast.Node) (string, ast.Node) {
	name, def := "", ast.Node(nil)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, r := range node.Rhs {
				if !sameCarrier(r, "", lit) || i >= len(node.Lhs) {
					continue
				}
				if id, ok := node.Lhs[i].(*ast.Ident); ok {
					name, def = id.Name, node
				}
			}
		case *ast.ValueSpec:
			for i, v := range node.Values {
				if !sameCarrier(v, "", lit) || i >= len(node.Names) {
					continue
				}
				name, def = node.Names[i].Name, node
			}
		}
		return true
	})
	return name, def
}

type callUse struct {
	call   *ast.CallExpr
	argIdx int
}

type carrierUses struct {
	writes  []*ast.CallExpr
	calls   []callUse
	escapes []string
}

func (u carrierUses) total() int { return len(u.writes) + len(u.calls) + len(u.escapes) }

// collectCarrierUses 掃 body 內 carrier 的全部使用點並分類。
func collectCarrierUses(pf *parsedFile, body *ast.BlockStmt, name string, node ast.Node, def ast.Node) carrierUses {
	var u carrierUses
	at := func(n ast.Node) string { return fmt.Sprintf("L%d", pf.Fset.Position(n.Pos()).Line) }
	ast.Inspect(body, func(n ast.Node) bool {
		if n == def {
			return false
		}
		switch stmt := n.(type) {
		case *ast.CallExpr:
			for i, a := range stmt.Args {
				if !sameCarrier(a, name, node) {
					continue
				}
				if sel, ok := stmt.Fun.(*ast.SelectorExpr); ok && gormWriteMethods[sel.Sel.Name] {
					u.writes = append(u.writes, stmt)
				} else {
					u.calls = append(u.calls, callUse{call: stmt, argIdx: i})
				}
				break
			}
		case *ast.ReturnStmt:
			for _, r := range stmt.Results {
				if sameCarrier(r, name, node) {
					u.escapes = append(u.escapes, at(stmt)+" return 出本作用域")
				}
			}
		case *ast.SendStmt:
			if sameCarrier(stmt.Value, name, node) {
				u.escapes = append(u.escapes, at(stmt)+" 送進 channel")
			}
		case *ast.AssignStmt:
			for _, r := range stmt.Rhs {
				if sameCarrier(r, name, node) {
					u.escapes = append(u.escapes, at(stmt)+" 轉賦給其他變數／欄位")
				}
			}
		case *ast.CompositeLit:
			for _, el := range stmt.Elts {
				v := el
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					v = kv.Value
				}
				if sameCarrier(v, name, node) {
					u.escapes = append(u.escapes, at(stmt)+" 被包進其他複合字面量")
				}
			}
		}
		return true
	})
	return u
}

// sameCarrier e 是否指向 carrier（具名時比對識別字，匿名時比對節點本體；`&x` 視同 `x`）
func sameCarrier(e ast.Expr, name string, node ast.Node) bool {
	x := unparen(e)
	if u, ok := x.(*ast.UnaryExpr); ok && u.Op == token.AND {
		x = unparen(u.X)
	}
	if name != "" {
		id, ok := x.(*ast.Ident)
		return ok && id.Name == name
	}
	return ast.Node(x) == node
}

// 註：`unparen`（剝括號）已由同包的 routes_guard_test.go 提供，此處直接沿用。

// resolveCarrier carrier 的使用點分類 → 落地寫入 → receiver 來源。
func (idx *txIndex) resolveCarrier(pf *parsedFile, enc []*fnScope, inner *fnScope,
	name string, node ast.Node, def ast.Node, hop int) (txVerdict, txReason, string) {
	u := collectCarrierUses(pf, inner.body, name, node, def)
	label := name
	if label == "" {
		label = "該字面量"
	}
	switch {
	case len(u.writes) == 1 && u.total() == 1:
		w := u.writes[0]
		sel := w.Fun.(*ast.SelectorExpr)
		v, r, why := idx.originOf(pf, enc, sel.X, 0)
		return v, r, fmt.Sprintf("%s 於 %s 由 %s 落地；%s", label, inner.label, exprText(sel), why)
	case len(u.calls) == 1 && u.total() == 1:
		if hop >= 1 {
			return txIndeterminate, reasonUnresolvedCallee,
				fmt.Sprintf("%s 再經一層轉手（%s），本判定只追一跳", label, exprText(u.calls[0].call.Fun))
		}
		return idx.oneHop(pf, enc, inner, u.calls[0], hop+1)
	case u.total() == 0:
		return txIndeterminate, reasonNoWrite,
			fmt.Sprintf("%s 在 %s 內找不到任何落地寫入或轉手", label, inner.label)
	case u.total() == 1 && len(u.escapes) == 1:
		return txIndeterminate, reasonEscapesScope,
			fmt.Sprintf("%s 於 %s %s：落地在別處，本作用域的資料流說不出交易歸屬", label, inner.label, u.escapes[0])
	default:
		return txIndeterminate, reasonMultiConsumer,
			fmt.Sprintf("%s 於 %s 有 %d 個落地候選（寫入 %d／轉手 %d／逸出 %d：%s），無法唯一決定",
				label, inner.label, u.total(), len(u.writes), len(u.calls), len(u.escapes),
				strings.Join(u.escapes, "、"))
	}
}

// oneHop 追進被呼叫的同包函式／方法，對應參數再判一次。
func (idx *txIndex) oneHop(pf *parsedFile, enc []*fnScope, inner *fnScope, use callUse, hop int) (txVerdict, txReason, string) {
	fe := idx.resolveCallee(pf, enc, use.call)
	if fe == nil {
		return txIndeterminate, reasonUnresolvedCallee,
			fmt.Sprintf("轉手目標 %s 無法在同包解析（跨包、介面派發或函式值）", exprText(use.call.Fun))
	}
	names, variadic := paramNames(fe.decl.Type.Params)
	if variadic || use.argIdx >= len(names) || names[use.argIdx] == "" || names[use.argIdx] == "_" {
		return txIndeterminate, reasonUnresolvedCallee,
			fmt.Sprintf("轉手目標 %s 的第 %d 個參數無法對位（可變參數或匿名參數）", fe.decl.Name.Name, use.argIdx)
	}
	calleeEnc := idx.enclosing(fe.pf, fe.decl.Body.Pos())
	if len(calleeEnc) == 0 {
		return txIndeterminate, reasonUnresolvedCallee, "轉手目標函式體無作用域紀錄"
	}
	calleeInner := calleeEnc[len(calleeEnc)-1]
	v, r, why := idx.resolveCarrier(fe.pf, calleeEnc, calleeInner, names[use.argIdx], nil, nil, hop)
	return v, r, fmt.Sprintf("經一跳交給 %s（參數 %s）：%s", fe.decl.Name.Name, names[use.argIdx], why)
}

func (idx *txIndex) resolveCallee(pf *parsedFile, enc []*fnScope, call *ast.CallExpr) *funcEntry {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return idx.funcs[funcKey(pf.Pkg, "", fn.Name)]
	case *ast.SelectorExpr:
		x, ok := fn.X.(*ast.Ident)
		if !ok || pf.imports[x.Name] {
			return nil
		}
		for i := len(enc) - 1; i >= 0; i-- {
			if enc[i].recvName == x.Name && enc[i].recvType != "" {
				return idx.funcs[funcKey(pf.Pkg, enc[i].recvType, fn.Sel.Name)]
			}
		}
		return nil
	}
	return nil
}

func paramNames(fl *ast.FieldList) ([]string, bool) {
	var out []string
	if fl == nil {
		return out, false
	}
	for _, f := range fl.List {
		if _, ok := f.Type.(*ast.Ellipsis); ok {
			return out, true
		}
		if len(f.Names) == 0 {
			out = append(out, "")
			continue
		}
		for _, nm := range f.Names {
			out = append(out, nm.Name)
		}
	}
	return out, false
}

// ── receiver 來源追溯 ─────────────────────────────────────────────────────

// originOf 把寫入 call 的 receiver 鏈往下走到根運算式並判定來源。
func (idx *txIndex) originOf(pf *parsedFile, enc []*fnScope, expr ast.Expr, depth int) (txVerdict, txReason, string) {
	if depth > 8 {
		return txIndeterminate, reasonUnresolvedRoot, "來源追溯深度超限"
	}
	switch e := unparen(expr).(type) {
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok {
			return txIndeterminate, reasonUnresolvedRoot, "寫入 receiver 來自非方法呼叫，來源不可追"
		}
		switch sel.Sel.Name {
		case "Session":
			det, provable := detachedSessionArg(e)
			if !provable {
				return txIndeterminate, reasonUnresolvedRoot,
					"寫入鏈上的 Session(...) 引數不是可判讀的 &gorm.Session{…} 字面量，脫離與否證不出"
			}
			if det {
				return txDetached, reasonDetachedSession,
					"寫入 call 自身的 receiver 鏈帶 Session(&gorm.Session{NewDB: true})：明示脫離呼叫方交易"
			}
		case "Begin":
			return txIndeterminate, reasonSelfBegin,
				"寫入 receiver 來自 Begin() 自開交易：機器判不出它與呼叫方交易的關係"
		}
		return idx.originOf(pf, enc, sel.X, depth+1)

	case *ast.Ident:
		for i := len(enc) - 1; i >= 0; i-- {
			if enc[i].dbParams[e.Name] {
				kind := "包覆函式 " + enc[i].label + " 的 *gorm.DB 參數"
				if enc[i].txClosure {
					kind = "Transaction 閉包參數"
				}
				return txBound, reasonTxParam, "receiver " + e.Name + " ＝ " + kind
			}
		}
		if idx.pkgVars[pf.Pkg+"."+e.Name] {
			return txNotBound, reasonRootHandle, "receiver " + e.Name + " ＝ 本包包級變數（根句柄）"
		}
		rhs, n := assignmentsOf(enc, e.Name)
		if n == 1 {
			v, r, why := idx.originOf(pf, enc, rhs, depth+1)
			return v, r, "receiver " + e.Name + " ← " + why
		}
		if n == 0 {
			return txIndeterminate, reasonUnresolvedRoot,
				"receiver " + e.Name + " 既非 *gorm.DB 參數、非包級變數，且本作用域內無賦值可追"
		}
		return txIndeterminate, reasonUnresolvedRoot,
			fmt.Sprintf("receiver %s 有 %d 處賦值，來源不唯一", e.Name, n)

	case *ast.SelectorExpr:
		x, ok := unparen(e.X).(*ast.Ident)
		if !ok {
			return txIndeterminate, reasonUnresolvedRoot, "寫入 receiver 為多層運算式，來源不可追"
		}
		if pf.imports[x.Name] {
			return txNotBound, reasonRootHandle, "receiver " + exprText(e) + " ＝ 跨包包級句柄"
		}
		if idx.pkgVars[pf.Pkg+"."+x.Name] {
			return txNotBound, reasonRootHandle, "receiver " + exprText(e) + " ＝ 本包包級變數的欄位"
		}
		if len(idx.txEscapes) > 0 {
			return txIndeterminate, reasonTxEscape, txEscapeSummary(idx.txEscapes)
		}
		return txNotBound, reasonStructField,
			"receiver " + exprText(e) + " ＝ struct 欄位，且全域 tx 逃逸不變式成立（無交易句柄被存進欄位／包級變數／context）"
	}
	return txIndeterminate, reasonUnresolvedRoot, "寫入 receiver 形態不在可追集合內"
}

// assignmentsOf 自內而外找對 name 的賦值；回傳唯一 RHS 與賦值次數。
func assignmentsOf(enc []*fnScope, name string) (ast.Expr, int) {
	var rhs ast.Expr
	count := 0
	for i := len(enc) - 1; i >= 0; i-- {
		ast.Inspect(enc[i].body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for j, l := range node.Lhs {
					id, ok := l.(*ast.Ident)
					if !ok || id.Name != name || j >= len(node.Rhs) {
						continue
					}
					rhs = node.Rhs[j]
					count++
				}
			case *ast.ValueSpec:
				for j, nm := range node.Names {
					if nm.Name != name || j >= len(node.Values) {
						continue
					}
					rhs = node.Values[j]
					count++
				}
			}
			return true
		})
		if count > 0 {
			return rhs, count
		}
	}
	return nil, 0
}

// detachedSessionArg 判 `Session(&gorm.Session{NewDB: true})`。
// 回傳 (是否脫離, 是否可判讀)——引數不是可判讀的字面量時 provable=false，一律 Indeterminate。
func detachedSessionArg(call *ast.CallExpr) (bool, bool) {
	if len(call.Args) != 1 {
		return false, false
	}
	arg := unparen(call.Args[0])
	if u, ok := arg.(*ast.UnaryExpr); ok && u.Op == token.AND {
		arg = unparen(u.X)
	}
	lit, ok := arg.(*ast.CompositeLit)
	if !ok || typeNameOf(lit.Type, "") != "gorm.Session" {
		return false, false
	}
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			return false, false
		}
		k, ok := kv.Key.(*ast.Ident)
		if !ok {
			return false, false
		}
		if k.Name != "NewDB" {
			continue
		}
		v, ok := unparen(kv.Value).(*ast.Ident)
		if !ok || (v.Name != "true" && v.Name != "false") {
			return false, false
		}
		return v.Name == "true", true
	}
	return false, true // 有字面量但未設 NewDB：可判讀，且不脫離
}

// exprText 供錯誤訊息用的簡短運算式文字
func exprText(e ast.Expr) string {
	switch x := unparen(e).(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprText(x.X) + "." + x.Sel.Name
	case *ast.CallExpr:
		return exprText(x.Fun) + "(…)"
	case *ast.UnaryExpr:
		return x.Op.String() + exprText(x.X)
	case *ast.IndexExpr:
		return exprText(x.X) + "[…]"
	}
	return "…"
}

// assertGormImportUnaliased 判定以語法形態 `*gorm.DB` 辨識參數型別，gorm 的 import
// 一旦被別名，判定會靜默失效（TxBound 漏判）。當場 Fatal 而非默默放行。
func assertGormImportUnaliased(t *testing.T, rel string, file *ast.File) {
	t.Helper()
	for _, imp := range file.Imports {
		if imp.Path == nil || strings.Trim(imp.Path.Value, `"`) != "gorm.io/gorm" {
			continue
		}
		if imp.Name != nil && imp.Name.Name != "gorm" {
			t.Fatalf("%s 以別名 %q import gorm.io/gorm：交易歸屬判定以語法形態 `*gorm.DB` "+
				"辨識參數型別，別名會讓判定靜默漏判。請改用預設名，或擴充 isGormDBPtr 以吃該別名",
				rel, imp.Name.Name)
		}
	}
}

// ── W4 收口形態：AuditEvent 字面量 ────────────────────────────────────────

// sinkTxWriteMethods TxSink 落地面的方法／函式名（吃 tx，回 error）。
var sinkTxWriteMethods = map[string]bool{"WriteInTx": true}

// sinkAsyncWriteMethods AsyncSink 投遞面的方法名（不吃 tx）。
var sinkAsyncWriteMethods = map[string]bool{"Submit": true}

// eventVerdict `port.AuditEvent{...}` 字面量的交易歸屬。
//
// 收口後的產生點不再自己落地，而是把事件交給 sink；交易句柄是那次呼叫的**顯式引數**，
// 這比舊形態（receiver 鏈）更容易正面證明，不需要放寬任何格序：
//
//	port.WriteInTx(sink, tx, ev)  → tx ＝ 事件引數的前一個引數
//	sink.WriteInTx(tx, ev)        → 同上（方法形態）
//	sink.Submit(ctx, ev)          → AsyncSink，簽名不帶 *gorm.DB ⇒ NotTxBound
//
// 找不到唯一的 sink 呼叫、或引數位置對不上，一律 Indeterminate（不猜）。
func (idx *txIndex) eventVerdict(pf *parsedFile, lit ast.Node) (txVerdict, txReason, string) {
	enc := idx.enclosing(pf, lit.Pos())
	if len(enc) == 0 {
		return txIndeterminate, reasonNoWrite, "事件字面量不在任何函式內（包級宣告），無落地可追"
	}
	inner := enc[len(enc)-1]
	name, def := carrierNameOf(inner.body, lit)
	u := collectCarrierUses(pf, inner.body, name, lit, def)
	label := name
	if label == "" {
		label = "該事件字面量"
	}
	if len(u.calls) != 1 || u.total() != 1 {
		return txIndeterminate, reasonMultiConsumer,
			fmt.Sprintf("%s 於 %s 有 %d 個消費點（呼叫 %d／寫入 %d／逸出 %d），無法唯一決定 sink 呼叫",
				label, inner.label, u.total(), len(u.calls), len(u.writes), len(u.escapes))
	}
	use := u.calls[0]
	fnName := calleeName(use.call.Fun)
	switch {
	case sinkAsyncWriteMethods[fnName]:
		return txNotBound, reasonSinkAsyncCall,
			fmt.Sprintf("%s 於 %s 交給 AsyncSink（%s）：介面簽名不帶 *gorm.DB，呼叫方 tx 無語法途徑進入該寫入",
				label, inner.label, exprText(use.call.Fun))
	case sinkTxWriteMethods[fnName]:
		if use.argIdx == 0 {
			return txIndeterminate, reasonUnresolvedRoot,
				fmt.Sprintf("%s 是 %s 的第一個引數，取不到交易句柄引數", label, exprText(use.call.Fun))
		}
		txArg := use.call.Args[use.argIdx-1]
		v, r, why := idx.originOf(pf, enc, txArg, 0)
		if v == txBound {
			return txBound, reasonSinkTxArg,
				fmt.Sprintf("%s 於 %s 交給 TxSink（%s），交易句柄引數 %s；%s",
					label, inner.label, exprText(use.call.Fun), exprText(txArg), why)
		}
		return v, r, fmt.Sprintf("%s 於 %s 交給 TxSink（%s），交易句柄引數 %s；%s",
			label, inner.label, exprText(use.call.Fun), exprText(txArg), why)
	default:
		return txIndeterminate, reasonUnresolvedCallee,
			fmt.Sprintf("%s 於 %s 交給 %s，非受管的 sink 落地面（受管：WriteInTx／Submit）",
				label, inner.label, exprText(use.call.Fun))
	}
}

// calleeName 取呼叫目標的最末識別字（`port.WriteInTx` → WriteInTx；`s.Submit` → Submit）。
func calleeName(fun ast.Expr) string {
	switch f := unparen(fun).(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}
