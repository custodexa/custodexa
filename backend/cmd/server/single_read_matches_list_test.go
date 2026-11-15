package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 單筆讀取與列表一致（端到端，正式的路由註冊與完整服務圖）：同一個請求主體對同一資源，單筆回應與該主體的
// 列表中那一筆逐欄相同（節點排除直掛資產清單）；列表看不到的識別，單筆回應與不存在的識別逐位元組相同；
// 列表被拒時單筆以同一回應被拒。以 API token 呼叫時，比對基準是同一把 token 的列表。

const srMissingID = 999999

// srResult 一次呼叫的狀態碼、回應標頭與原始本文。
type srResult struct {
	code   int
	header http.Header
	body   []byte
}

// srVolatileHeaders 比對回應標頭時排除的鍵：每次請求都會變的值，與資源是否存在、是否可見無關。
// 清單以外的標頭一律比對鍵與值。
var srVolatileHeaders = map[string]string{
	"Date": "回應產生時刻",
}

// srHeaders 去掉變動值後的回應標頭（鍵已正規化）。
func srHeaders(h http.Header) map[string][]string {
	out := map[string][]string{}
	for k, v := range h {
		if _, skip := srVolatileHeaders[http.CanonicalHeaderKey(k)]; skip {
			continue
		}
		out[http.CanonicalHeaderKey(k)] = v
	}
	return out
}

// srSame 兩次回應的狀態碼、回應標頭（排除變動值）與本文皆相同。
func srSame(a, b srResult) bool {
	return a.code == b.code && string(a.body) == string(b.body) && reflect.DeepEqual(srHeaders(a.header), srHeaders(b.header))
}

// srShow 失敗訊息用的回應摘要。
func srShow(r srResult) string {
	return fmt.Sprintf("%d %v %s", r.code, srHeaders(r.header), clipCmp(string(r.body)))
}

func (e *baselineEnv) srGet(subj *baselineSubject, path string) srResult {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	subj.authorize(req)
	w := e.serve(req)
	awaitBackground(e.t)
	return srResult{code: w.Code, header: w.Header().Clone(), body: w.Body.Bytes()}
}

// srIDs 表中全部識別（含已軟刪除者）。
func (e *baselineEnv) srIDs(table string) []uint {
	e.t.Helper()
	var ids []uint
	if err := e.db.Table(table).Order("id").Pluck("id", &ids).Error; err != nil {
		e.t.Fatalf("讀取 %s 識別：%v", table, err)
	}
	return ids
}

// srListItems 解析列表本文的 data 陣列，鍵為元素識別。drop 為比對前移除的鍵。
func srListItems(t *testing.T, body []byte, drop ...string) map[uint]map[string]any {
	t.Helper()
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("解析列表：%v：%s", err, body)
	}
	items := map[uint]map[string]any{}
	for _, it := range out.Data {
		for _, k := range drop {
			delete(it, k)
		}
		items[uint(it["id"].(float64))] = it
	}
	return items
}

// srCounts 一個主體在一種資源上的比對計數。
type srCounts struct{ readable, hidden, denied int }

// srMalformedIDs 不是 32 位元無號整數的識別：非數字、負數、超出 32 位元、超出 64 位元與更長的整數。
// 回應只由輸入決定：同一主體同一路由下彼此同一回應，與任何資源是否存在無關。
var srMalformedIDs = []string{"abc", "-1", "4294967296", "18446744073709551616", "99999999999999999999999"}

// srCompare 單筆與列表的比對：listPath 的回應決定每個 single(id) 的預期。回計數。
// 另驗識別的邊界值：32 位元上限（合法、查無）與不存在同一回應；前導零與同值的識別同一回應；
// 不合法的識別回 400 且彼此相同；zeroMalformed 為真時 0 歸入不合法，否則與不存在同一回應。
// 列表被拒時，合法的識別都與列表同一回應；不合法的識別彼此同一回應，且為列表的拒絕或 400 之一
// （入口或資產層的拒絕可能先於、也可能後於格式檢查，但都不依賴任何帳號或資源是否存在）。
func (e *baselineEnv) srCompare(t *testing.T, label string, subj *baselineSubject, listPath string,
	single func(string) string, ids []uint, zeroMalformed bool, drop ...string) srCounts {
	t.Helper()
	var c srCounts
	// 每次比對都從範本狀態開始並還原回範本（讀取也會留下稽核列與使用時間等寫入）
	e.apiTokenRuleRestore()
	defer e.apiTokenRuleRestore()
	byID := func(id uint) string { return single(fmt.Sprint(id)) }
	list := e.srGet(subj, listPath)
	miss := e.srGet(subj, byID(srMissingID))
	malformed := append([]string{}, srMalformedIDs...)
	wellFormed := []string{"4294967295"}
	if zeroMalformed {
		malformed = append(malformed, "0")
	} else {
		wellFormed = append(wellFormed, "0")
	}
	if list.code != http.StatusOK {
		raws := append([]string{}, wellFormed...)
		for _, id := range append(ids, srMissingID) {
			raws = append(raws, fmt.Sprint(id), "0"+fmt.Sprint(id))
		}
		for _, raw := range raws {
			got := e.srGet(subj, single(raw))
			if !srSame(got, list) {
				t.Errorf("[%s] %s：列表被拒（%s），單筆 %q 回 %s", label, listPath, srShow(list), raw, srShow(got))
			}
			c.denied++
		}
		first := e.srGet(subj, single(malformed[0]))
		if !srSame(first, list) && first.code != http.StatusBadRequest {
			t.Errorf("[%s] %s：列表被拒時不合法的識別應為列表的拒絕或 400，得 %s", label, single(malformed[0]), srShow(first))
		}
		for _, raw := range malformed[1:] {
			if got := e.srGet(subj, single(raw)); !srSame(got, first) {
				t.Errorf("[%s] %s：不合法的識別應彼此同一回應（%s），得 %s", label, single(raw), srShow(first), srShow(got))
			}
		}
		return c
	}
	if miss.code != http.StatusNotFound {
		t.Errorf("[%s] %s：不存在的識別應回 404，得 %s", label, byID(srMissingID), srShow(miss))
	}
	items := srListItems(t, list.body, drop...)
	if strings.Contains(listPath, "/authorizations") {
		var meta struct {
			Total int `json:"total"`
		}
		_ = json.Unmarshal(list.body, &meta)
		if meta.Total > len(items) {
			t.Fatalf("[%s] 授權列表跨頁（total=%d），比對前提不成立", label, meta.Total)
		}
	}
	for _, id := range ids {
		got := e.srGet(subj, byID(id))
		// 前導零與同值的識別同一回應（可讀者同一筆、看不到者同不存在）
		if lead := e.srGet(subj, single("0"+fmt.Sprint(id))); !srSame(lead, got) {
			t.Errorf("[%s] %s：前導零的識別應與同值識別同一回應：%s／%s", label, single("0"+fmt.Sprint(id)), srShow(lead), srShow(got))
		}
		if want, ok := items[id]; ok {
			var one map[string]any
			if got.code != http.StatusOK || json.Unmarshal(got.body, &one) != nil || !reflect.DeepEqual(want, one) {
				wantRaw, _ := json.Marshal(want)
				t.Errorf("[%s] %s：單筆與列表中那一筆不同\n  列表 %s\n  單筆 %s", label, byID(id),
					clipCmp(string(wantRaw)), srShow(got))
			}
			if !reflect.DeepEqual(srHeaders(got.header), srHeaders(list.header)) {
				t.Errorf("[%s] %s：單筆與列表的回應標頭不同：%v／%v", label, byID(id), srHeaders(got.header), srHeaders(list.header))
			}
			c.readable++
			continue
		}
		if !srSame(got, miss) {
			t.Errorf("[%s] %s：列表看不到，單筆應與不存在相同（%s），得 %s", label, byID(id), srShow(miss), srShow(got))
		}
		c.hidden++
	}
	if got := e.srGet(subj, single("4294967295")); !srSame(got, miss) {
		t.Errorf("[%s] %s：32 位元上限的識別應與不存在相同（%s），得 %s", label, single("4294967295"), srShow(miss), srShow(got))
	}
	if !zeroMalformed {
		if got := e.srGet(subj, single("0")); !srSame(got, miss) {
			t.Errorf("[%s] %s：識別 0 應與不存在相同（%s），得 %s", label, single("0"), srShow(miss), srShow(got))
		}
	}
	first := e.srGet(subj, single(malformed[0]))
	if first.code != http.StatusBadRequest {
		t.Errorf("[%s] %s：不合法的識別應回 400，得 %s", label, single(malformed[0]), srShow(first))
	}
	for _, raw := range malformed[1:] {
		if got := e.srGet(subj, single(raw)); !srSame(got, first) {
			t.Errorf("[%s] %s：不合法的識別應彼此同一回應（%s），得 %s", label, single(raw), srShow(first), srShow(got))
		}
	}
	return c
}

// srSubjectCounts 一個主體對四種資源的比對結果。
type srSubjectCounts map[string]srCounts

// srCheckSubject 對四種資源逐一比對；帳號以每台資產（含已刪除與不存在的資產）分別比對其列表，候選識別為全部帳號。
// 資產可見、不可見、不存在三種情形因此都與合法、不合法的帳號識別交叉比對。
func (e *baselineEnv) srCheckSubject(t *testing.T, label string, subj *baselineSubject) srSubjectCounts {
	t.Helper()
	out := srSubjectCounts{}
	out["node"] = e.srCompare(t, label+" node", subj, "/api/v1/asset-groups",
		func(id string) string { return "/api/v1/asset-groups/" + id }, e.srIDs("asset_groups"), false, "assets")
	out["user_group"] = e.srCompare(t, label+" user_group", subj, "/api/v1/user-groups",
		func(id string) string { return "/api/v1/user-groups/" + id }, e.srIDs("user_groups"), false)
	out["authorization"] = e.srCompare(t, label+" authorization", subj, "/api/v1/authorizations?page_size=100",
		func(id string) string { return "/api/v1/authorizations/" + id }, e.srIDs("asset_authorizations"), false)
	accounts := e.srIDs("asset_accounts")
	var acc srCounts
	for _, assetID := range append(e.srIDs("assets"), srMissingID) {
		a := assetID
		c := e.srCompare(t, fmt.Sprintf("%s account@asset%d", label, a), subj, fmt.Sprintf("/api/v1/assets/%d/accounts", a),
			func(id string) string { return fmt.Sprintf("/api/v1/assets/%d/accounts/%s", a, id) }, accounts, true)
		acc.readable += c.readable
		acc.hidden += c.hidden
		acc.denied += c.denied
	}
	out["account"] = acc
	t.Logf("[%s] 可讀／列表看不到／被拒：節點 %v、群組 %v、授權 %v、帳號 %v", label,
		out["node"], out["user_group"], out["authorization"], out["account"])
	return out
}

// srResources 每個主體都要比對的四種資源。
var srResources = []string{"node", "user_group", "authorization", "account"}

// srNoReadable 主體本來就讀不到任何一筆的組合（主體標籤 → 資源 → 理由）。表外的每個組合，單筆至少要有一筆
// 可讀並與列表比對過；否則全部被拒或全部看不到時比對照樣通過，等於沒有驗到「可讀的單筆與列表相同」。
// 表內的組合反過來必須確實一筆都讀不到，表才不會在權限改變後留著過時的除外。
var srNoReadable = map[string]map[string]string{
	"稽核者 S03": {
		"user_group":    "稽核者沒有使用者群組管理能力，群組列表被拒",
		"authorization": "稽核者沒有授權規則管理能力，授權列表被拒",
	},
	"一般使用者 S02": {
		"user_group":    "一般使用者沒有使用者群組管理能力，群組列表被拒",
		"authorization": "一般使用者沒有授權規則管理能力，授權列表被拒",
	},
	"自動化帳號 S12": {
		"node":          "自動化帳號只能讀帳號，節點列表被拒",
		"user_group":    "自動化帳號只能讀帳號，群組列表被拒",
		"authorization": "自動化帳號只能讀帳號，授權列表被拒",
	},
	"節點範圍管理者": {
		"user_group": "節點範圍角色不含使用者群組管理能力，群組列表被拒",
	},
	"token 只有節點範圍角色（本人為超級管理者）": {
		"user_group": "token 只授權節點範圍角色，不含使用者群組管理能力，群組列表被拒",
	},
	"節點範圍的憑證檢視者": {
		"user_group":    "只有資產檢視與憑證相關能力，群組列表被拒",
		"authorization": "只有資產檢視與憑證相關能力，授權列表被拒",
	},
	"token 角色收回後": {
		"node":          "token 唯一的角色已收回，節點列表為空",
		"user_group":    "token 唯一的角色已收回，群組列表被拒",
		"authorization": "token 唯一的角色已收回，授權列表被拒",
		"account":       "token 唯一的角色已收回，每台資產的帳號列表都被拒",
	},
}

// srRequireReadable 表外的組合至少一筆可讀；表內的組合一筆都不可讀。每個組合都要實際比對過至少一個識別。
func srRequireReadable(t *testing.T, label string, got srSubjectCounts) {
	t.Helper()
	for _, res := range srResources {
		c := got[res]
		if c.readable+c.hidden+c.denied == 0 {
			t.Errorf("[%s] %s：沒有比對任何識別", label, res)
			continue
		}
		if why, exempt := srNoReadable[label][res]; exempt {
			if c.readable != 0 {
				t.Errorf("[%s] %s 列為讀不到任何一筆（%s），實際可讀 %d 筆：除外已過時", label, res, why, c.readable)
			}
			continue
		}
		if c.readable == 0 {
			t.Errorf("[%s] %s：可讀的單筆為 0（列表看不到 %d、被拒 %d），沒有任何一筆驗到與列表相同", label, res, c.hidden, c.denied)
		}
	}
}

// srNodeScopedRole 節點範圍角色：資產檢視、節點管理、授權規則管理、憑證檢視。
func (e *baselineEnv) srNodeScopedRole() uint {
	return e.apiTokenCustomRole("sr-node-role", authz.PermAssetView, authz.PermAssetGroupManage,
		authz.PermAuthorizationManage, authz.PermCredentialView)
}

func (e *baselineEnv) srGrantNodes(userID, roleID, node uint) {
	e.t.Helper()
	if err := e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID, Source: model.RoleSourceManual,
		ScopeKind: model.ScopeKindNodes}).Error; err != nil {
		e.t.Fatalf("節點範圍指派：%v", err)
	}
	if err := e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: userID,
		RoleID: roleID, NodeID: node}).Error; err != nil {
		e.t.Fatalf("節點範圍：%v", err)
	}
}

func (e *baselineEnv) srSession(id string, u cmpIdentity) *baselineSubject {
	return &baselineSubject{ID: id, Username: u.username, UserID: u.userID, Token: e.issueSessionToken(u.userID), Kind: "session"}
}

func (e *baselineEnv) srToken(id string, owner cmpIdentity, roleIDs ...uint) *baselineSubject {
	plain, _ := e.apiTokenIssue(owner, "sr-"+strings.ToLower(id), roleIDs...)
	return &baselineSubject{ID: id, Username: owner.username, UserID: owner.userID, Token: plain, Kind: "api_token"}
}

// srReadableAuthorizations 主體在授權列表中看得到的規則識別。
func (e *baselineEnv) srReadableAuthorizations(t *testing.T, subj *baselineSubject) map[uint]bool {
	t.Helper()
	r := e.srGet(subj, "/api/v1/authorizations?page_size=100")
	if r.code != http.StatusOK {
		return map[uint]bool{}
	}
	out := map[uint]bool{}
	for id := range srListItems(t, r.body) {
		out[id] = true
	}
	return out
}

func TestSingleReadMatchesList(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	ag1 := e.object("assetGroup.1").(uint)
	nodeRole := e.srNodeScopedRole()
	mgmt := e.apiTokenCustomRole("sr-mgmt-role", authz.PermAssetView, authz.PermAssetGroupManage,
		authz.PermAuthorizationManage, authz.PermUserGroupManage)
	credView := e.apiTokenCustomRole("sr-cred-view-role", authz.PermCredentialView, authz.PermCredentialManage)
	admin := e.roleID(model.RoleAdmin)

	// 節點範圍管理者（人類工作階段）
	nodeMgr := e.apiTokenUser("sr-node-manager")
	e.srGrantNodes(nodeMgr.userID, nodeRole, ag1)
	// token 甲：與本人同權限（本人只持有超級管理者，token 授權超級管理者）
	sameOwner := e.apiTokenUser("sr-same-owner", admin)
	// token 乙：本人為超級管理者並以節點範圍持有節點角色，token 只授權節點角色
	superOwner := e.apiTokenUser("sr-super-owner", admin)
	e.srGrantNodes(superOwner.userID, nodeRole, ag1)
	// token 丙：本人持有管理角色與憑證檢視，token 只授權管理角色
	credOwner := e.apiTokenUser("sr-cred-owner", mgmt, credView)
	// 帳號與節點的連線可視來自授權規則：本人（token 沿用同一主體）與自動化帳號各對一台資產有連線授權
	sshAsset := e.object("asset.ssh").(uint)
	for _, uid := range []uint{credOwner.userID, e.subjects["S12"].UserID} {
		u := uid
		if err := e.db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &sshAsset, Permission: model.PermissionConnect,
			Source: model.AuthorizationSourceManual, GrantedBy: e.subjects["S01"].UserID,
			Accounts: model.AccountScope{model.AccountScopeAll}}).Error; err != nil {
			t.Fatalf("連線授權：%v", err)
		}
	}

	tokSame := e.srToken("T-same", sameOwner, admin)
	tokNode := e.srToken("T-node", superOwner, nodeRole)
	tokNoCred := e.srToken("T-no-cred", credOwner, mgmt)
	sessNodeMgr := e.srSession("H-node-manager", nodeMgr)
	sessSame := e.srSession("H-same-owner", sameOwner)
	sessSuper := e.srSession("H-super-owner", superOwner)
	sessCred := e.srSession("H-cred-owner", credOwner)
	// 節點範圍的憑證檢視者：帳號列的憑證身分欄位需全域的憑證管理能力，節點範圍內再依憑證檢視集合收窄；
	// 範圍內資產上綁定全域共用憑證的帳號列因此是「範圍外憑證」的列
	scopedCred := e.apiTokenUser("sr-scoped-cred-viewer", e.apiTokenCustomRole("sr-cred-manage-role", authz.PermCredentialManage))
	e.srGrantNodes(scopedCred.userID, e.apiTokenCustomRole("sr-node-cred-view-role", authz.PermAssetView,
		authz.PermCredentialView), ag1)
	sessScopedCred := e.srSession("H-scoped-cred-viewer", scopedCred)
	e.apiTokenRetemplate()

	subjects := []struct {
		label string
		subj  *baselineSubject
	}{
		{"超級管理者 S01", e.subjects["S01"]},
		{"稽核者 S03", e.subjects["S03"]},
		{"一般使用者 S02", e.subjects["S02"]},
		{"自動化帳號 S12", e.subjects["S12"]},
		{"節點範圍管理者", sessNodeMgr},
		{"token 與本人同權限", tokSame},
		{"token 只有節點範圍角色（本人為超級管理者）", tokNode},
		{"token 沒有憑證檢視（本人有）", tokNoCred},
		{"本人工作階段：與 token 同權限者", sessSame},
		{"本人工作階段：超級管理者", sessSuper},
		{"本人工作階段：有憑證檢視者", sessCred},
		{"節點範圍的憑證檢視者", sessScopedCred},
	}
	cases := 0
	results := map[string]srSubjectCounts{}
	for _, s := range subjects {
		results[s.label] = e.srCheckSubject(t, s.label, s.subj)
		srRequireReadable(t, s.label, results[s.label])
		for _, c := range results[s.label] {
			cases += c.readable + c.hidden + c.denied
		}
	}

	t.Run("automation_account_reads_accounts_and_is_refused_elsewhere_like_list", func(t *testing.T) {
		r := results["自動化帳號 S12"]
		for _, k := range []string{"node", "user_group", "authorization"} {
			if r[k].denied == 0 || r[k].readable != 0 {
				t.Errorf("自動化帳號的 %s 應照列表被拒：%v", k, r[k])
			}
		}
		if r["account"].readable == 0 {
			t.Errorf("自動化帳號應讀得到帳號（與帳號列表相同）：%v", r["account"])
		}
	})

	t.Run("token_with_owner_permissions_equals_owner_session", func(t *testing.T) {
		var paths []string
		for _, path := range []string{"/api/v1/asset-groups/%d", "/api/v1/user-groups/%d", "/api/v1/authorizations/%d"} {
			table := map[string]string{"/api/v1/asset-groups/%d": "asset_groups", "/api/v1/user-groups/%d": "user_groups",
				"/api/v1/authorizations/%d": "asset_authorizations"}[path]
			for _, id := range append(e.srIDs(table), srMissingID) {
				paths = append(paths, fmt.Sprintf(path, id))
			}
		}
		// 帳號：每台資產（含不存在的資產）的每個帳號識別（含不存在的帳號）
		for _, assetID := range append(e.srIDs("assets"), srMissingID) {
			for _, id := range append(e.srIDs("asset_accounts"), srMissingID) {
				paths = append(paths, fmt.Sprintf("/api/v1/assets/%d/accounts/%d", assetID, id))
			}
		}
		accountOK := 0
		for _, path := range paths {
			a, b := e.srGet(tokSame, path), e.srGet(sessSame, path)
			if !srSame(a, b) {
				t.Errorf("%s：同權限的 token 與本人工作階段不同：%s／%s", path, srShow(a), srShow(b))
			}
			if strings.Contains(path, "/accounts/") && a.code == http.StatusOK {
				accountOK++
			}
		}
		if accountOK == 0 {
			t.Errorf("前提：同權限的 token 應讀得到至少一個帳號")
		}
	})

	t.Run("token_narrower_than_super_admin_owner_reads_out_of_scope_rule_as_missing", func(t *testing.T) {
		tokenSees := e.srReadableAuthorizations(t, tokNode)
		ownerSees := e.srReadableAuthorizations(t, sessSuper)
		var outOfScope []uint
		for id := range ownerSees {
			if !tokenSees[id] {
				outOfScope = append(outOfScope, id)
			}
		}
		if len(outOfScope) == 0 {
			t.Fatalf("前提：應有本人看得到而 token 看不到的規則（token %d 條、本人 %d 條）", len(tokenSees), len(ownerSees))
		}
		sort.Slice(outOfScope, func(i, j int) bool { return outOfScope[i] < outOfScope[j] })
		miss := e.srGet(tokNode, fmt.Sprintf("/api/v1/authorizations/%d", srMissingID))
		for _, id := range outOfScope {
			tok := e.srGet(tokNode, fmt.Sprintf("/api/v1/authorizations/%d", id))
			own := e.srGet(sessSuper, fmt.Sprintf("/api/v1/authorizations/%d", id))
			if tok.code != http.StatusNotFound || string(tok.body) != string(miss.body) {
				t.Errorf("規則 %d：token 應與不存在相同，得 %d %s", id, tok.code, clipCmp(string(tok.body)))
			}
			if own.code != http.StatusOK {
				t.Errorf("規則 %d：本人工作階段應讀得到，得 %d", id, own.code)
			}
		}
		t.Logf("token 看得到 %d 條、本人 %d 條；範圍外 %d 條逐一驗證", len(tokenSees), len(ownerSees), len(outOfScope))
	})

	t.Run("token_without_credential_view_gets_slim_account_rows", func(t *testing.T) {
		shapes := func(subj *baselineSubject) (full, slim int) {
			for _, assetID := range e.srIDs("assets") {
				r := e.srGet(subj, fmt.Sprintf("/api/v1/assets/%d/accounts", assetID))
				if r.code != http.StatusOK {
					continue
				}
				for id := range srListItems(t, r.body) {
					one := e.srGet(subj, fmt.Sprintf("/api/v1/assets/%d/accounts/%d", assetID, id))
					var row map[string]any
					if one.code != http.StatusOK || json.Unmarshal(one.body, &row) != nil || row["id"] == nil {
						t.Errorf("帳號 %d@資產 %d：列表有的帳號單筆應回 200 且為帳號物件，得 %s", id, assetID, srShow(one))
						continue
					}
					if _, ok := row["credential_id"]; ok {
						full++
					} else {
						slim++
					}
				}
			}
			return
		}
		tf, ts := shapes(tokNoCred)
		hf, hs := shapes(sessCred)
		if tf != 0 || ts == 0 {
			t.Errorf("token 沒有憑證檢視：單筆應全為精簡版（完整 %d、精簡 %d）", tf, ts)
		}
		if hf == 0 || hs != 0 {
			t.Errorf("前提：本人工作階段有憑證檢視，單筆應全為完整版（完整 %d、精簡 %d）", hf, hs)
		}
	})

	t.Run("scoped_credential_viewer_reads_out_of_scope_credential_row_like_list", func(t *testing.T) {
		sshAcc := e.object("account.sshShared").(uint)
		list := e.srGet(sessScopedCred, fmt.Sprintf("/api/v1/assets/%d/accounts", sshAsset))
		if list.code != http.StatusOK {
			t.Fatalf("前提：範圍內資產的帳號列表可讀，得 %s", srShow(list))
		}
		rows := srListItems(t, list.body)
		row, ok := rows[sshAcc]
		if !ok || row["credential_out_of_scope"] != true {
			t.Fatalf("前提：綁定全域共用憑證的帳號列在列表中為範圍外憑證的列，得 %v", row)
		}
		for _, k := range []string{"credential_id", "credential_name", "binding_count"} {
			if _, has := row[k]; has {
				t.Errorf("範圍外憑證的列不應含 %s：%v", k, row)
			}
		}
		inScope := 0
		for id, r := range rows {
			if id != sshAcc && r["credential_id"] != nil {
				inScope++
			}
		}
		if inScope == 0 {
			t.Errorf("前提：同一台資產上另有範圍內憑證的列（帶憑證識別）：%v", rows)
		}
		one := e.srGet(sessScopedCred, fmt.Sprintf("/api/v1/assets/%d/accounts/%d", sshAsset, sshAcc))
		var got map[string]any
		if one.code != http.StatusOK || json.Unmarshal(one.body, &got) != nil || !reflect.DeepEqual(row, got) {
			t.Errorf("範圍外憑證的列：單筆應與列表中那一列相同，列表 %v，單筆 %s", row, srShow(one))
		}
		for _, k := range []string{"credential_id", "credential_name", "binding_count"} {
			if strings.Contains(string(one.body), `"`+k+`"`) {
				t.Errorf("範圍外憑證的列：單筆原文不應含 %s：%s", k, one.body)
			}
		}
	})

	t.Run("token_role_revoked_follows_list", func(t *testing.T) {
		before := results["token 只有節點範圍角色（本人為超級管理者）"]
		if before["authorization"].readable == 0 {
			t.Fatalf("前提：收回前 token 讀得到授權規則：%v", before["authorization"])
		}
		if err := e.db.Where("user_id = ? AND role_id = ?", superOwner.userID, nodeRole).Delete(&model.UserRole{}).Error; err != nil {
			t.Fatalf("收回角色：%v", err)
		}
		if err := e.db.Where("subject_kind = ? AND subject_id = ? AND role_id = ?", model.BindingSubjectUser,
			superOwner.userID, nodeRole).Delete(&model.RoleBindingNode{}).Error; err != nil {
			t.Fatalf("收回範圍：%v", err)
		}
		// 收回併入範本（比對每一步都從範本狀態開始）；併入時一併推進權限版本
		e.apiTokenRetemplate()
		after := e.srCheckSubject(t, "token 角色收回後", tokNode)
		srRequireReadable(t, "token 角色收回後", after)
		for _, k := range srResources {
			cases += after[k].readable + after[k].hidden + after[k].denied
		}
		if after["authorization"].readable != 0 {
			t.Errorf("角色收回後 token 不應再讀到授權規則：%v", after["authorization"])
		}
	})

	checkedLabels := map[string]bool{"token 角色收回後": true}
	for _, s := range subjects {
		checkedLabels[s.label] = true
	}
	for label := range srNoReadable {
		if !checkedLabels[label] {
			t.Errorf("除外表列了不存在的主體 %q", label)
		}
	}
	t.Logf("主體 %d 個（另含 token 角色收回後一次）；單筆對照案例共 %d 筆", len(subjects), cases)
}
