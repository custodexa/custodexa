package main

import (
	"context"
	"go/ast"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
)

// TestCredentialAuthorizationWiring 憑證背景工作授權重驗的組裝接線：
// 改密執行器、候選重試、輪替引擎三處都注入同一個生產判定器，缺任一拒絕啟動。
func TestCredentialAuthorizationWiring(t *testing.T) {
	t.Run("三處缺一即回報缺口（未注入不是放行）", func(t *testing.T) {
		full := map[string]revalidationWired{
			"changeSecretRunner":      asset.NewChangeSecretRunner(nil, nil, nil, nil, nil).WithManagementAuthorizer(stubAuthorizer{}),
			"changeSecretRetryRunner": asset.NewChangeSecretRetryRunner(nil, nil, nil, nil, nil).WithManagementAuthorizer(stubAuthorizer{}).WithAuditSink(audit.NewTxSink()),
			"credentialRotations":     asset.NewCredentialRotationService(nil, nil, nil, nil, nil, audit.NewTxSink(), stubAuthorizer{}),
		}
		if gaps := credentialAuthorizationWiringGaps(full); len(gaps) != 0 {
			t.Fatalf("三處皆已注入卻回報缺口: %v", gaps)
		}
		// 失權後的有限驗證必須有審計落地面：只有判定器、缺審計落地面同樣算缺口
		noAudit := map[string]revalidationWired{}
		for k, v := range full {
			noAudit[k] = v
		}
		noAudit["changeSecretRetryRunner"] = asset.NewChangeSecretRetryRunner(nil, nil, nil, nil, nil).WithManagementAuthorizer(stubAuthorizer{})
		if gaps := credentialAuthorizationWiringGaps(noAudit); len(gaps) != 1 || gaps[0] != "changeSecretRetryRunner" {
			t.Fatalf("候選重試缺審計落地面應回報缺口，實得 %v", gaps)
		}
		// 還原前留下的改密意圖靠還原世代比對擋下：判定器讀不到世代同樣算缺口
		noGen := map[string]revalidationWired{}
		for k, v := range full {
			noGen[k] = v
		}
		noGen["changeSecretRunner"] = asset.NewChangeSecretRunner(nil, nil, nil, nil, nil).WithManagementAuthorizer(bareAuthorizer{})
		if gaps := credentialAuthorizationWiringGaps(noGen); len(gaps) != 1 || gaps[0] != "changeSecretRunner" {
			t.Fatalf("判定器沒有還原世代讀取應回報缺口，實得 %v", gaps)
		}
		for _, name := range credentialAuthorizationWiringNames() {
			m := map[string]revalidationWired{}
			for k, v := range full {
				m[k] = v
			}
			switch name {
			case "changeSecretRunner":
				m[name] = asset.NewChangeSecretRunner(nil, nil, nil, nil, nil)
			case "changeSecretRetryRunner":
				m[name] = asset.NewChangeSecretRetryRunner(nil, nil, nil, nil, nil)
			case "credentialRotations":
				m[name] = asset.NewCredentialRotationService(nil, nil, nil, nil, nil, nil, nil)
			}
			gaps := credentialAuthorizationWiringGaps(m)
			if len(gaps) != 1 || gaps[0] != name {
				t.Fatalf("缺 %s 時應只回報它，實得 %v", name, gaps)
			}
			if credentialAuthorizationWiringError(gaps) == nil {
				t.Fatalf("缺 %s 時應回傳啟動錯誤", name)
			}
		}
		if gaps := credentialAuthorizationWiringGaps(map[string]revalidationWired{}); len(gaps) != len(credentialAuthorizationWiringNames()) {
			t.Fatalf("清單缺項也算缺口，實得 %v", gaps)
		}
	})

	t.Run("組裝根的三處建構都傳入生產判定器且啟動自檢真的被呼叫", func(t *testing.T) {
		root := parseAssemblyRoot(t)
		found := map[string]bool{}
		selfCheck := false
		for _, f := range root.files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch calleeIdentName(call.Fun) {
				case "credentialAuthorizationWiringError":
					selfCheck = true
				case "NewCredentialRotationService":
					if len(call.Args) == 7 && isIdent(call.Args[6], "credentialManagement") {
						found["credentialRotations"] = true
					}
				case "WithManagementAuthorizer":
					if len(call.Args) == 1 && isIdent(call.Args[0], "credentialManagement") {
						switch chainRootName(call.Fun) {
						case "NewChangeSecretRunner":
							found["changeSecretRunner"] = true
						case "NewChangeSecretRetryRunner":
							found["changeSecretRetryRunner"] = true
						}
					}
				}
				return true
			})
		}
		for _, name := range credentialAuthorizationWiringNames() {
			if !found[name] {
				t.Errorf("組裝根沒有把 credentialManagement 傳給 %s：背景工作會在未注入下被一律拒絕", name)
			}
		}
		if !selfCheck {
			t.Error("組裝根沒有呼叫 credentialAuthorizationWiringError：缺接線不會拒絕啟動")
		}
	})
}

// managementInjection 一筆必須存在於組裝根的注入：subject 是方法鏈的根（變數名或建構子名），
// method 是注入方法，arg 是傳入的組裝根變數（或同名的路由依賴欄位）。
type managementInjection struct{ subject, method, arg string }

// requiredManagementInjections 前景寫入面的判定器與系統告警落地面。
//
// 判定器缺席時這些服務對內嵌秘密宣告、掛載、範圍轉換等一律拒絕（fail closed），
// 漏接的症狀是功能整片 500／403 而不是放行；告警落地面缺席時共用憑證換密、範圍轉換
// 等安全事件不產生系統告警。兩者都不會讓啟動失敗，故由本表在組裝層釘住。
var requiredManagementInjections = []managementInjection{
	{"assetService", "WithManagementAuthorizer", "credentialManagement"},
	{"assetService", "WithSystemAlertSink", "systemAlertSink"},
	{"NewCredentialService", "WithManagementAuthorizer", "credentialManagement"},
	{"NewCredentialService", "WithSystemAlertSink", "systemAlertSink"},
	{"NewAssetAccountService", "WithManagementAuthorizer", "credentialManagement"},
	{"NewAssetAccountService", "WithSystemAlertSink", "systemAlertSink"},
	{"NewCredentialRotationService", "WithSystemAlertSink", "systemAlertSink"},
}

// TestCredentialManagementInjectionWiring 資產、憑證庫、資產帳號服務的判定器與告警落地面
// 注入必須出現在組裝根，且注入的是生產用的那個變數（不是 nil、不是別的實例）。
func TestCredentialManagementInjectionWiring(t *testing.T) {
	root := parseAssemblyRoot(t)
	found := map[managementInjection]bool{}
	for _, f := range root.files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			arg := argName(call.Args[0])
			if arg == "" {
				return true
			}
			found[managementInjection{chainSubject(sel), sel.Sel.Name, arg}] = true
			return true
		})
	}
	for _, want := range requiredManagementInjections {
		if !found[want] {
			t.Errorf("組裝根沒有對 %s 呼叫 %s(%s)：漏接時寫入面一律拒絕或安全事件不告警，且啟動不會失敗",
				want.subject, want.method, want.arg)
		}
	}
}

// chainSubject 沿 x.A(...).B(...) 走到鏈根：根是變數時回變數名，根是 pkg.NewX(...) 時回 NewX。
func chainSubject(sel *ast.SelectorExpr) string {
	for {
		switch x := sel.X.(type) {
		case *ast.Ident:
			return x.Name
		case *ast.CallExpr:
			inner, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return calleeIdentName(x.Fun)
			}
			if _, pkg := inner.X.(*ast.Ident); pkg && strings.HasPrefix(inner.Sel.Name, "New") {
				return inner.Sel.Name
			}
			sel = inner
		default:
			return ""
		}
	}
}

// argName 注入引數的名稱：組裝根變數 `x`，或路由依賴結構上的同名欄位 `s.x`。
func argName(e ast.Expr) string {
	switch a := e.(type) {
	case *ast.Ident:
		return a.Name
	case *ast.SelectorExpr:
		return a.Sel.Name
	}
	return ""
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// chainRootName 沿 a.B(...).C(...) 的方法鏈走到最內層建構呼叫，回傳其函式名。
func chainRootName(fun ast.Expr) string {
	for {
		sel, ok := fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		call, ok := sel.X.(*ast.CallExpr)
		if !ok {
			return ""
		}
		if name := calleeIdentName(call.Fun); name != "" && !isChainMethod(call.Fun) {
			return name
		}
		fun = call.Fun
	}
}

// isChainMethod 呼叫的接收者本身是另一個呼叫（鏈上的方法）。
func isChainMethod(fun ast.Expr) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	_, isCall := sel.X.(*ast.CallExpr)
	return isCall
}

// stubAuthorizer 只用來讓判定器「已注入」，測試不呼叫它。
type stubAuthorizer struct{}

func (stubAuthorizer) AuthorizeCredentialManagement(context.Context, *gorm.DB,
	asset.CredentialManagementActor, asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	return asset.CredentialManagementDecision{}, nil
}

// RestoreGeneration 讓判定器同時通過還原世代讀取的自檢；回空世代，測試不依賴其值。
func (stubAuthorizer) RestoreGeneration(*gorm.DB) (string, error) { return "", nil }

// bareAuthorizer 只有判定、沒有還原世代讀取：啟動自檢必須視為缺口。
type bareAuthorizer struct{}

func (bareAuthorizer) AuthorizeCredentialManagement(context.Context, *gorm.DB,
	asset.CredentialManagementActor, asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	return asset.CredentialManagementDecision{}, nil
}
