package principalfacts

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"
	"testing"
)

// 背景與系統來源的建構點清冊與守衛。
//
// 授權判定依路徑分三種：請求路徑取請求主體、背景作業以帳號完整身分重驗、系統工作不經操作者關卡。
// 後兩者都會取得比請求主體更寬的判定，所以能產生這兩種來源的入口只能在登記過的位置呼叫：
//   - 背景發起者脈絡：model.WithBackgroundInitiator 與資產模組的 backgroundInitiatorContext；
//   - 系統操作者：身分模組的 systemOperator，以及以它進入的三個系統專用入口
//     （閒置自動停用的 UpdateStatus、DeleteWithSummary、UnbindExternalIdentityAndDisable）。
//
// 新增未登記的呼叫點、或登記了卻已不存在，皆失敗（雙向）。

// originWatched 被列管的符號：宣告所在的包、接收者型別（函式為空）與名稱。
var originWatched = []struct{ pkg, recv, name string }{
	{guardModulePath + "/internal/model", "", "WithBackgroundInitiator"},
	{guardModulePath + "/internal/modules/asset", "", "backgroundInitiatorContext"},
	{guardModulePath + "/internal/modules/identity", "", "systemOperator"},
	{guardModulePath + "/internal/modules/identity", "UserService", "UpdateStatus"},
	{guardModulePath + "/internal/modules/identity", "UserService", "DeleteWithSummary"},
	{guardModulePath + "/internal/modules/identity", "UserService", "UnbindExternalIdentityAndDisable"},
}

// originSite 清冊項：(callee, file, fn) 與次數、用途。
type originSite struct {
	callee string
	file   string
	fn     string
	count  int
	why    string
}

var originSites = []originSite{
	{"WithBackgroundInitiator", "internal/modules/asset/credential_management_authz.go", "backgroundInitiatorContext", 1,
		"資產模組唯一的背景發起者脈絡入口"},
	{"backgroundInitiatorContext", "internal/modules/asset/credential_job_authorization.go", "initiatorContext", 1,
		"背景工作以持久授權脈絡的發起者重驗（派送前、每個遠端步驟前、主機身分承接）"},
	{"backgroundInitiatorContext", "internal/modules/asset/credential_job_authorization.go", "CredentialRotationService.revalidateRequeuer", 1,
		"輪替成員的重排者在背景重驗"},
	{"backgroundInitiatorContext", "internal/modules/asset/change_secret_batch_revalidate.go", "CredentialRotationService.revalidateAssetBound", 1,
		"批次拆分成員的重排者在背景重驗"},
	{"backgroundInitiatorContext", "internal/modules/asset/change_secret_batch_credential.go", "ChangeSecretRunner.createBatchSharedCredential", 1,
		"批次執行時由發起者在交易內重驗共用憑證歸屬"},
	{"backgroundInitiatorContext", "internal/modules/asset/change_secret_batch_credential.go", "ChangeSecretRunner.splitOneCredential", 1,
		"批次執行時由發起者拆分共用憑證"},
	{"backgroundInitiatorContext", "internal/modules/asset/change_secret_runner.go", "ChangeSecretRunner.revalidateTarget", 1,
		"計劃執行時逐台以發起者重驗"},
	{"backgroundInitiatorContext", "internal/modules/asset/change_secret_runner.go", "ChangeSecretRunner.runCredentialTarget", 1,
		"憑證目標計劃執行時以發起者啟動輪替"},
	{"backgroundInitiatorContext", "internal/modules/asset/change_secret_runner.go", "ChangeSecretRunner.manualBoundRejection", 1,
		"手動執行時以計劃保存者的授權脈絡判定上界（保存者不是點擊者）"},
	{"backgroundInitiatorContext", "internal/modules/asset/change_secret_batch_service.go", "ChangeSecretBatchService.Create", 1,
		"沒有請求脈絡的批次建立入口（請求路徑走 CreateFor 並保留請求主體）"},
	{"systemOperator", "internal/modules/identity/user_service.go", "UserService.UpdateStatus", 1,
		"閒置自動停用的系統專用入口"},
	{"systemOperator", "internal/modules/identity/user_service.go", "UserService.DeleteWithSummary", 1,
		"無操作者的刪除入口（管理端一律走帶操作者的入口）"},
	{"systemOperator", "internal/modules/identity/external_identity_service.go", "UserService.UnbindExternalIdentityAndDisable", 1,
		"無操作者的解綁並停用入口（管理端一律走帶操作者的入口）"},
	{"UserService.UpdateStatus", "internal/modules/identity/inactivity_service.go", "InactivityService.DisableInactive", 1,
		"閒置自動停用排程"},
	{"UserService.DeleteWithSummary", "internal/modules/identity/user_service.go", "UserService.Delete", 1,
		"無操作者的刪除包裝"},
}

// minOriginSites 命中數下限。
const minOriginSites = 10

func watchedKey(obj types.Object) (string, bool) {
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return "", false
	}
	recv := ""
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		rt := sig.Recv().Type()
		if p, ok := rt.(*types.Pointer); ok {
			rt = p.Elem()
		}
		if n, ok := types.Unalias(rt).(*types.Named); ok {
			recv = n.Obj().Name()
		}
	}
	for _, w := range originWatched {
		if w.pkg == fn.Pkg().Path() && w.recv == recv && w.name == fn.Name() {
			if recv != "" {
				return recv + "." + fn.Name(), true
			}
			return fn.Name(), true
		}
	}
	return "", false
}

// TestBackgroundAndSystemOriginSitesRegistered 背景發起者脈絡與系統操作者的呼叫點清冊守衛（雙向）。
func TestBackgroundAndSystemOriginSitesRegistered(t *testing.T) {
	pkgs, fset, root := loadModulePackages(t)
	sites := map[string][]string{}
	resolved := map[string]bool{}
	hits := 0
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			if strings.HasSuffix(fset.Position(f.Pos()).Filename, "_test.go") {
				continue
			}
			for _, obj := range p.TypesInfo.Defs {
				if obj != nil {
					if k, ok := watchedKey(obj); ok {
						resolved[k] = true
					}
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var id *ast.Ident
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					id = fun
				case *ast.SelectorExpr:
					id = fun.Sel
				default:
					return true
				}
				obj := p.TypesInfo.Uses[id]
				if obj == nil {
					return true
				}
				k, ok := watchedKey(obj)
				if !ok {
					return true
				}
				file := relPath(root, fset.Position(f.Pos()).Filename)
				key := k + "|" + file + "|" + enclosingFunc(f, call.Pos())
				sites[key] = append(sites[key], fmt.Sprintf("%s:%d", file, fset.Position(call.Pos()).Line))
				hits++
				return true
			})
		}
	}
	for _, w := range originWatched {
		k := w.name
		if w.recv != "" {
			k = w.recv + "." + w.name
		}
		if !resolved[k] {
			t.Errorf("列管符號 %s（%s）找不到宣告：改名或刪除會讓本清冊靜默失效", k, w.pkg)
		}
	}
	t.Logf("背景／系統來源呼叫點命中數=%d（下限 %d）", hits, minOriginSites)
	if hits < minOriginSites {
		t.Fatalf("只掃到 %d 處呼叫（下限 %d）：掃描或比對失配", hits, minOriginSites)
	}
	registered := map[string]int{}
	for _, s := range originSites {
		if strings.TrimSpace(s.why) == "" {
			t.Errorf("清冊項 %s|%s|%s 缺用途說明", s.callee, s.file, s.fn)
		}
		registered[s.callee+"|"+s.file+"|"+s.fn] += s.count
	}
	extra, missing := diffRegistry(sites, registered)
	for _, e := range extra {
		t.Errorf("未登記的背景／系統來源呼叫點（請求內的用法須保留請求主體，不得取得背景或系統來源）：%s", e)
	}
	for _, m := range missing {
		t.Errorf("清冊登記的呼叫點已不存在：%s", m)
	}
}
