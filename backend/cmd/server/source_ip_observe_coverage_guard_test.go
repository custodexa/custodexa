package main

// 新來源位址觀察點的閉集合守衛。
//
// # 為什麼需要它
//
// 基準與告警是**旁路**：呼叫端一律「失敗只記 log、不阻主流程」，消費端一律
// `baseline == nil` 即 return。這兩個性質加起來意味著——**把任何一個觀察點的
// 呼叫刪掉，全樹沒有任何測試會轉紅，服務照常啟動、連線照常建立、登入照常成功**，
// 而唯一的症狀是「那條路徑的新位址從此永遠不算新」。那正是這個功能存在的全部理由。
//
// 單元測試證明的是「呼叫了會怎樣」；本守衛證明的是「有沒有呼叫」。兩者缺一不可。
//
// # 判準
//
// 建線側：兩條協議路徑各自的檔內必須出現一次 ObserveSession 的呼叫鏈。
// 登入側：五個正式會話發放點（密碼登入、多因素完成、強制註冊完成、改密完成、
// OIDC 交換）所在的函式內必須各有一次 observeLoginSource 呼叫。
//
// 以「函式名 → 期望呼叫」的字面量表列比對，且**雙向**：表列的函式必須存在
// （改名不得靜默漏掉）、且期望的呼叫必須真的在那個函式體內。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// sourceIPObservePoints 觀察點閉集合：檔 → 函式 → 該函式體內必須出現的呼叫名。
//
// **新增正式會話發放點或建線路徑時 SHALL 同步登記**——漏登的那條路徑不會有
// 任何訊號告訴你它沒進基準。
var sourceIPObservePoints = []struct {
	File string
	Func string
	Call string
	Why  string
}{
	{"internal/sshproxy/handler.go", "HandleSSH", "observeSourceIP",
		"文字終端建線：session 主鍵已得、fail-close 已過之後才呼叫觀察"},
	{"internal/sshproxy/source_ip_observe.go", "observeSourceIP", "ObserveSession",
		"文字終端觀察本體：呼叫鏈的另一半，只釘住上一列會讓這裡被掏空仍全綠"},
	{"internal/proxy/handler.go", "HandleConnect", "ObserveSession",
		"圖形建線：同上，於 CreateWithGenerationGuard 成功之後"},
	{"internal/api/auth_handler.go", "Login", "observeLoginSource",
		"發放端點 1／6：密碼登入的正式會話"},
	{"internal/api/auth_handler.go", "ChangePassword", "observeLoginSource",
		"發放端點 4／6：改密完成換發的正式會話"},
	{"internal/api/auth_mfa_handler.go", "MFAVerify", "observeLoginSource",
		"發放端點 2／6：多因素第二階段完成"},
	{"internal/api/auth_mfa_handler.go", "MFAEnrollConfirm", "observeLoginSource",
		"發放端點 3／6：強制註冊完成"},
	{"internal/api/oidc_handler.go", "Exchange", "observeLoginSource",
		"發放端點 5／6：OIDC 交換（巢狀回應，六者中最易漏的一個）"},
}

// minSourceIPObservePoints 下限：表被整批清空時逐項比對恆滿足，故另設下界
const minSourceIPObservePoints = 8

func TestSourceIPObservePointsAllWired(t *testing.T) {
	root := lifecycleModuleRoot(t)
	if len(sourceIPObservePoints) < minSourceIPObservePoints {
		t.Fatalf("觀察點表只剩 %d 列（下限 %d）：表被縮減即守衛射程歸零",
			len(sourceIPObservePoints), minSourceIPObservePoints)
	}

	// 檔 → 該檔內「函式名 → 函式體」
	parsed := map[string]map[string]*ast.FuncDecl{}
	loadFile := func(rel string) map[string]*ast.FuncDecl {
		if fns, ok := parsed[rel]; ok {
			return fns
		}
		abs := filepath.Join(root, rel)
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("觀察點所在檔 %s 不存在（%v）：守衛拒絕在掃不到的樹上宣稱通過", rel, err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), abs, nil, 0)
		if err != nil {
			t.Fatalf("解析 %s 失敗: %v", rel, err)
		}
		fns := map[string]*ast.FuncDecl{}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				fns[fn.Name.Name] = fn
			}
		}
		parsed[rel] = fns
		return fns
	}

	for _, p := range sourceIPObservePoints {
		fns := loadFile(p.File)
		fn, ok := fns[p.Func]
		if !ok {
			t.Errorf("%s 內找不到函式 %s（登記理由：%s）：函式改名或搬家後，"+
				"該觀察點是否還在就沒有東西看得住了", p.File, p.Func, p.Why)
			continue
		}
		if !callsNamed(fn.Body, p.Call) {
			t.Errorf("%s 的 %s 內沒有呼叫 %s（登記理由：%s）："+
				"這條路徑的新來源位址不會進基準，也不會有任何錯誤訊號——"+
				"事後只會看到「這個帳號從沒從這裡進來過」這件事永遠答不出來",
				p.File, p.Func, p.Call, p.Why)
		}
	}
}
