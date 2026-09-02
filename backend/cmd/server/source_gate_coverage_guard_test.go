package main

// 來源限定閘（G1）的**閉集合守衛**。
//
// # 缺口形狀
//
// 判定點有十八個，散在四個 handler 檔裡。刪掉其中任何一個的呼叫，全樹會發生
// 什麼事：服務照常啟動、那個端點照常回 200、全部行為測試照常綠——只有
// 「清單外的來源打這一個端點時不會被擋」，而那正是這個功能存在的全部理由。
// 行為測試證明「有呼叫時會怎樣」；本守衛證明「有沒有呼叫」。
//
// # 兩個方向
//
//	(1) 涵蓋面：盤點表 #1–#19 對應的 handler 函式**必須**呼叫 requireSourceAllowed
//	    （refresh 走服務層，改釘 RefreshSession 內的判定呼叫）。
//	(2) 閉集合：`/auth/*` 與 `/users/:id/{password,unlock,mfa/disable}` 之下
//	    **每一條已註冊路由**都必須落在「判」或「明列不判」兩個字面量集合之一。
//	    新增一條認證類端點而未歸類即紅——這是本守衛與單純的涵蓋面清單的差別：
//	    前者擋得住「忘了加閘」，後者只擋得住「把既有的閘刪掉」。
//
// 列舉來源是 `buildRouter` 的 `r.Routes()`（實際註冊的路由集），不是人寫的清單
// ——沿 `audit_route_classification_guard_test.go` 的同一條紀律。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// sourceGateHelperName 全庫唯一的 web 判定 helper 名（三個 handler 型別各有薄包覆，
// 呼叫點一律是這個名字）
const sourceGateHelperName = "requireSourceAllowed"

// sourceGateEnforcementPoints 盤點表 #1–#19 的實作位置：檔 → 函式 → 必須出現的呼叫。
//
// 多個表列共用同一次判定（表內註明「與 #n 同一請求，判一次」），故列數少於 19。
// **新增認證因子端點時 SHALL 同步登記**——漏登的那條路徑不會有任何訊號。
var sourceGateEnforcementPoints = []struct {
	Points string // 盤點表的列編號
	File   string
	Func   string
	Call   string
	Why    string
}{
	{"#1/#3/#4", "internal/api/auth_handler.go", "Login", sourceGateHelperName,
		"密碼登入：正式會話、enrollment 票證、password_change 票證三條分支之前判一次"},
	{"#7/#10", "internal/api/auth_handler.go", "ChangePassword", sourceGateHelperName,
		"自助改密：token 解析之後、SelfChangePassword 之前"},
	{"#5/#13", "internal/api/auth_mfa_handler.go", "MFAVerify", sourceGateHelperName,
		"多因素完成：發正式會話（或改密票證）之前"},
	{"#6/#12", "internal/api/auth_mfa_handler.go", "MFAEnrollConfirm", sourceGateHelperName,
		"強制註冊完成：CompleteEnrollment 之前（其後即已寫入第二因子）"},
	{"#11", "internal/api/auth_mfa_handler.go", "MFAEnrollSetup", sourceGateHelperName,
		"強制註冊設定：產生並回傳 secret 之前"},
	{"#14", "internal/api/auth_mfa_handler.go", "MFASetup", sourceGateHelperName,
		"正式會話下的 pending secret 寫入並回傳"},
	{"#15", "internal/api/auth_mfa_handler.go", "MFAEnable", sourceGateHelperName,
		"正式會話下的 MFA 啟用"},
	{"#16", "internal/api/auth_mfa_handler.go", "MFADisable", sourceGateHelperName,
		"正式會話下的 MFA 自助停用"},
	{"#17", "internal/api/auth_mfa_handler.go", "AdminDisableMFA", sourceGateHelperName,
		"管理者對他人的 MFA 重設（依操作者清單）"},
	{"#8", "internal/api/oidc_handler.go", "Exchange", sourceGateHelperName,
		"OIDC 交換：正式會話與 enrollment 分支判、pending 不判"},
	{"#18", "internal/api/user_handler.go", "ChangePassword", sourceGateHelperName,
		"管理者對他人的密碼寫入（依操作者清單）"},
	{"#19", "internal/api/user_handler.go", "Unlock", sourceGateHelperName,
		"管理者解鎖他人（依操作者清單）"},
	{"#9", "internal/modules/identity/auth_refresh_service.go", "RefreshSession", "Evaluate",
		"refresh 輪替：**服務層**判定（交易內、世代複查之後、CAS 撤舊之前），" +
			"形狀與其餘十七點不同——拒絕時零寫入、不消耗憑證，故不走 handler helper"},
}

// minSourceGateEnforcementPoints 下限：表被整批清空時逐項比對恆滿足
const minSourceGateEnforcementPoints = 13

// sourceGateJudged 「判」的閉集合：這些路由的 handler 必須有來源判定。
//
// 鍵為 `METHOD PATH`（`r.Routes()` 的形狀）。
var sourceGateJudged = map[string]string{
	"POST /api/v1/auth/login":              "盤點表 #1／#3／#4",
	"POST /api/v1/auth/mfa/verify":         "盤點表 #5／#13",
	"POST /api/v1/auth/mfa/enroll/setup":   "盤點表 #11",
	"POST /api/v1/auth/mfa/enroll/confirm": "盤點表 #6／#12",
	"POST /api/v1/auth/change-password":    "盤點表 #7／#10",
	"POST /api/v1/auth/mfa/setup":          "盤點表 #14",
	"POST /api/v1/auth/mfa/enable":         "盤點表 #15",
	"POST /api/v1/auth/mfa/disable":        "盤點表 #16",
	"POST /api/v1/auth/refresh":            "盤點表 #9（服務層交易內判定）",
	"POST /api/v1/auth/oidc/exchange":      "盤點表 #8（正式與 enrollment 判、pending 不判）",
	"POST /api/v1/users/:id/mfa/disable":   "盤點表 #17（依操作者清單）",
	"PUT /api/v1/users/:id/password":       "盤點表 #18（依操作者清單）",
	"POST /api/v1/users/:id/unlock":        "盤點表 #19（依操作者清單）",
}

// sourceGateNotJudged 「明列不判」的閉集合：每條都必須附理由。
//
// **登記＝豁免，不是備忘**：多登一條就是預先開一個洞，故理由必須寫得出
// 「為什麼這條不需要判」，而不是「這條還沒做」。
var sourceGateNotJudged = map[string]string{
	"GET /api/v1/auth/me": "唯讀自我檢視，不寫任何認證狀態；" +
		"其 source_ip 欄只回本人這次請求的來源，無新資料暴露",
	"PATCH /api/v1/auth/me": "非認證因子（僅 local_display_name）：盤點表的邊界第 3 條" +
		"——範圍止於認證因子，擴到一般寫入等於每請求判一次（規格明列的非目標）",
	"POST /api/v1/auth/logout": "撤銷自己的憑證。擋掉它只會讓清單外的人**無法登出**，" +
		"安全方向相反",
	"GET /api/v1/auth/banner": "登入前告示讀取，使用者尚未解析（與登入方式列舉同理：無身分可判、亦不寫任何認證狀態）",
	"GET /api/v1/auth/methods": "登入方式列舉，使用者尚未解析（盤點表 #21，明列不判）",
	"GET /api/v1/auth/oidc/:id/begin": "OIDC 授權起點，使用者尚未解析" +
		"（判定在 exchange；盤點表 #21，明列不判）",
	"GET /api/v1/auth/oidc/callback": "IdP 回呼，交棒前（同上；且來源是 IdP 的瀏覽器導向，" +
		"不是使用者的 API 呼叫）",
}

// sourceGateRoutePrefixes 閉集合的射程：這些前綴之下的路由必須被歸類。
//
// **只涵蓋認證因子面**：擴到全部路由就等於主張「每個端點都該判來源」，
// 那是規格明列的非目標。
var sourceGateRoutePrefixes = []string{"/api/v1/auth/"}

// sourceGateExplicitRoutes 前綴之外仍納入閉集合的具名路由（管理者對他人的認證因子）
var sourceGateExplicitRoutes = []string{
	"POST /api/v1/users/:id/mfa/disable",
	"PUT /api/v1/users/:id/password",
	"POST /api/v1/users/:id/unlock",
}

// TestSourceGateEnforcementPointsAllWired 方向 (1)：登記的判定點都真的有呼叫。
func TestSourceGateEnforcementPointsAllWired(t *testing.T) {
	root := lifecycleModuleRoot(t)
	if len(sourceGateEnforcementPoints) < minSourceGateEnforcementPoints {
		t.Fatalf("判定點表只剩 %d 列（下限 %d）：表被縮減即守衛射程歸零",
			len(sourceGateEnforcementPoints), minSourceGateEnforcementPoints)
	}

	parsed := map[string]map[string]*ast.FuncDecl{}
	loadFile := func(rel string) map[string]*ast.FuncDecl {
		if fns, ok := parsed[rel]; ok {
			return fns
		}
		abs := filepath.Join(root, rel)
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("判定點所在檔 %s 不存在（%v）：守衛拒絕在掃不到的樹上宣稱通過", rel, err)
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

	for _, p := range sourceGateEnforcementPoints {
		fns := loadFile(p.File)
		fn, ok := fns[p.Func]
		if !ok {
			t.Errorf("%s 內找不到函式 %s（盤點表 %s）：函式改名或搬家後，"+
				"這個判定點是否還在就沒有東西看得住了", p.File, p.Func, p.Points)
			continue
		}
		if !callsNamed(fn.Body, p.Call) {
			t.Errorf("%s 的 %s 內沒有呼叫 %s（盤點表 %s：%s）："+
				"這條路徑對清單外來源靜默放行，而且不會有任何錯誤訊號——"+
				"服務照常啟動、端點照常回 200、其餘測試照常綠",
				p.File, p.Func, p.Call, p.Points, p.Why)
		}
	}
}

// TestSourceGateRouteUniverseIsClassified 方向 (2)：射程內每條路由都已歸類。
//
// 三個方向都紅：未歸類的新路由、同時列在兩個集合、登記了不存在的路由。
func TestSourceGateRouteUniverseIsClassified(t *testing.T) {
	routes, _ := buildRouter(t, gin.ReleaseMode, true)
	if len(routes) < minAuditRoutesScanned {
		t.Fatalf("buildRouter 只回了 %d 條路由（下界 %d）：列舉來源失效時"+
			"逐路由迴圈零迭代即全綠", len(routes), minAuditRoutesScanned)
	}

	explicit := map[string]bool{}
	for _, k := range sourceGateExplicitRoutes {
		explicit[k] = true
	}

	inScope := map[string]bool{}
	for k := range routes {
		key := k[0] + " " + k[1]
		if explicit[key] {
			inScope[key] = true
			continue
		}
		for _, prefix := range sourceGateRoutePrefixes {
			if strings.HasPrefix(k[1], prefix) {
				inScope[key] = true
				break
			}
		}
	}
	if len(inScope) < len(sourceGateJudged)+len(sourceGateNotJudged) {
		t.Fatalf("射程內只掃到 %d 條路由，少於兩個集合的總和 %d：前綴或具名清單失真",
			len(inScope), len(sourceGateJudged)+len(sourceGateNotJudged))
	}

	for key := range inScope {
		_, judged := sourceGateJudged[key]
		reason, notJudged := sourceGateNotJudged[key]
		switch {
		case judged && notJudged:
			t.Errorf("路由 %s 同時列在「判」與「明列不判」兩個集合：兩者必須互斥", key)
		case !judged && !notJudged:
			t.Errorf("路由 %s 既未登記為「判」也未登記為「明列不判」："+
				"新增認證類端點時必須回答「這條要不要判來源」——"+
				"不回答的預設是靜默放行，而那是本功能唯一要擋的事", key)
		case notJudged && strings.TrimSpace(reason) == "":
			t.Errorf("路由 %s 登記為「明列不判」但缺理由（缺理由即紅）："+
				"登記＝豁免，不是備忘", key)
		}
	}

	// 反向：兩個集合的每一條都必須對應到實際註冊的路由（陳舊條目＝預先開好的洞）
	for key := range sourceGateJudged {
		if !inScope[key] {
			t.Errorf("「判」集合列了 %s，但它不在實際註冊的路由集內（射程失真或路由已刪）", key)
		}
	}
	for key := range sourceGateNotJudged {
		if !inScope[key] {
			t.Errorf("「明列不判」集合列了 %s，但它不在實際註冊的路由集內"+
				"——陳舊豁免會為將來同名路由預先開好洞", key)
		}
	}
}
