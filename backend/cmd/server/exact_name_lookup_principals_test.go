package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 名稱精確查找與列表一致（端到端，正式的認證、路由登錄與完整服務圖）：同一個請求主體，帶名稱參數的列表
// 等於不帶參數的同一列表中名稱完全相同的那幾列，總數只計這幾列，分頁欄位與其他附帶欄位不變；列表看不到的
// 名稱與不存在的名稱同一回應（狀態碼、標頭、本文）；列表被拒時帶名稱參數也以同一回應被拒。以 API token 呼叫時，
// 比對基準是同一把 token 的列表。

const enMissingName = "zz-exact-lookup-no-such-name"

// enRoute 一個支援名稱精確查找的列表：listPath 為不帶名稱參數的請求，候選名稱取自 table.column（含已刪除列）。
// fullPath 非空表示 listPath 的每頁筆數（pageSize）小到一頁裝不下可見集合：預期值改取自 fullPath 這條
// 一頁涵蓋全部的列表，listPath 的第一頁只用來辨認哪些名稱原本落在後頁。
type enRoute struct {
	key, listPath, param, table, column string
	fullPath                            string
	pageSize                            int
}

var enRoutes = []enRoute{
	{key: "asset", listPath: "/api/v1/assets?page_size=1000", param: "name", table: "assets", column: "name"},
	{key: "asset_paged", listPath: "/api/v1/assets?page=1&page_size=2", param: "name", table: "assets", column: "name",
		fullPath: "/api/v1/assets?page_size=1000", pageSize: 2},
	{key: "node", listPath: "/api/v1/asset-groups", param: "name", table: "asset_groups", column: "name"},
	{key: "user", listPath: "/api/v1/users?page_size=1000", param: "username", table: "users", column: "username"},
	{key: "user_group", listPath: "/api/v1/user-groups", param: "name", table: "user_groups", column: "name"},
	{key: "credential", listPath: "/api/v1/credentials", param: "name", table: "credentials", column: "name"},
	// 每頁 200 筆涵蓋夾具的全部憑證：與不分頁的路由同樣逐列比對，另驗分頁欄位
	{key: "credential_paged", listPath: "/api/v1/credentials?page=1&page_size=200", param: "name", table: "credentials", column: "name"},
}

func (r enRoute) lookup(name string) string {
	sep := "?"
	if strings.Contains(r.listPath, "?") {
		sep = "&"
	}
	return r.listPath + sep + url.Values{r.param: {name}}.Encode()
}

// enCandidates 候選名稱：表中全部名稱（含已刪除列與自動化帳號），另加一個不存在的名稱。
func (e *baselineEnv) enCandidates(r enRoute) []string {
	e.t.Helper()
	var names []string
	if err := e.db.Table(r.table).Where(r.column+" IS NOT NULL").Distinct(r.column).Order(r.column).
		Pluck(r.column, &names).Error; err != nil {
		e.t.Fatalf("讀取 %s.%s：%v", r.table, r.column, err)
	}
	return append(names, enMissingName)
}

// enParse 列表本文：data 陣列（每列正規化為 JSON 字串）與其餘頂層欄位（總數另列）。
func enParse(t *testing.T, body []byte) (rows []map[string]any, total any, rest map[string]any) {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("解析列表：%v：%s", err, body)
	}
	data, _ := top["data"].([]any)
	for _, d := range data {
		rows = append(rows, d.(map[string]any))
	}
	total = top["total"]
	delete(top, "data")
	delete(top, "total")
	return rows, total, top
}

func enCanon(rows []map[string]any) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		b, _ := json.Marshal(r)
		out = append(out, string(b))
	}
	sort.Strings(out)
	return out
}

// enOutcome 一個主體在一個列表上的比對結果：可見（查得到）的名稱、看不到的名稱數、被拒的名稱數。
type enOutcome struct {
	visible map[string]bool
	hidden  int
	denied  int
	// later 每頁兩筆的路由中，查得到且原本落在未篩選第一頁之外的名稱數
	later int
}

// enCompare 一個主體在一個列表上逐一比對全部候選名稱。
func (e *baselineEnv) enCompare(t *testing.T, label string, subj *baselineSubject, r enRoute) enOutcome {
	t.Helper()
	out := enOutcome{visible: map[string]bool{}}
	defer e.apiTokenRuleRestore()
	// 每次請求都從範本狀態開始：自動化帳號的資產列表會寫入曝露紀錄，前一次請求的寫入不得影響下一次
	get := func(path string) srResult {
		e.apiTokenRuleRestore()
		return e.srGet(subj, path)
	}
	list := get(r.listPath)
	miss := get(r.lookup(enMissingName))
	if list.code != http.StatusOK {
		for _, name := range e.enCandidates(r) {
			if got := get(r.lookup(name)); !srSame(got, list) {
				t.Errorf("[%s %s] 列表被拒（%s），%s=%q 回 %s", label, r.key, srShow(list), r.param, name, srShow(got))
			}
			out.denied++
		}
		return out
	}
	rows, total, rest := enParse(t, list.body)
	paged := r.fullPath != ""
	if !paged && total != nil && int(total.(float64)) > len(rows) {
		t.Fatalf("[%s %s] 列表跨頁（total=%v、本頁 %d），比對前提不成立", label, r.key, total, len(rows))
	}
	// 一頁裝不下的路由：預期值取自同一主體一頁涵蓋全部的列表（依列表順序），未篩選的第一頁只用來
	// 辨認哪些名稱原本落在後頁
	base := rows
	firstPage := map[any]bool{}
	if paged {
		full := get(r.fullPath)
		if full.code != http.StatusOK {
			t.Fatalf("[%s %s] 完整列表應回 200，得 %s", label, r.key, srShow(full))
		}
		fullRows, fullTotal, _ := enParse(t, full.body)
		if fullTotal != nil && int(fullTotal.(float64)) > len(fullRows) {
			t.Fatalf("[%s %s] 完整列表跨頁（total=%v、本頁 %d），比對前提不成立", label, r.key, fullTotal, len(fullRows))
		}
		base = fullRows
		for _, row := range rows {
			firstPage[row[r.column]] = true
		}
	}
	for _, name := range e.enCandidates(r) {
		got := get(r.lookup(name))
		var want []map[string]any
		for _, row := range base {
			if row[r.column] == name {
				want = append(want, row)
			}
		}
		if got.code != http.StatusOK {
			t.Errorf("[%s %s] %s=%q 應回 200，得 %s", label, r.key, r.param, name, srShow(got))
			continue
		}
		gotRows, gotTotal, gotRest := enParse(t, got.body)
		if !reflect.DeepEqual(gotRest, rest) {
			t.Errorf("[%s %s] %s=%q：分頁與附帶欄位應與不帶參數的列表相同：%v／%v", label, r.key, r.param, name, gotRest, rest)
		}
		if !reflect.DeepEqual(srHeaders(got.header), srHeaders(list.header)) {
			t.Errorf("[%s %s] %s=%q：回應標頭應與列表相同：%v／%v", label, r.key, r.param, name, srHeaders(got.header), srHeaders(list.header))
		}
		if total != nil && gotTotal == nil {
			t.Errorf("[%s %s] %s=%q：列表帶總數，查找也應帶", label, r.key, r.param, name)
		}
		if paged {
			// 篩選在切頁之前：完整列表中名稱相同的列，其第一頁就是查找結果，總數為相符的筆數；
			// 目標原本落在未篩選的後頁時同樣要在第一頁回來
			if len(want) == 0 {
				if !srSame(got, miss) {
					t.Errorf("[%s %s] %s=%q：完整列表看不到，應與不存在同一回應（%s），得 %s", label, r.key, r.param, name, srShow(miss), srShow(got))
				}
				out.hidden++
				continue
			}
			wantPage := want
			if len(wantPage) > r.pageSize {
				wantPage = wantPage[:r.pageSize]
			}
			if !reflect.DeepEqual(enCanon(gotRows), enCanon(wantPage)) {
				t.Errorf("[%s %s] %s=%q：應回完整列表中名稱相同的 %d 列的第一頁，得 %s", label, r.key, r.param, name, len(want), clipCmp(string(got.body)))
			}
			if gotTotal == nil || int(gotTotal.(float64)) != len(want) {
				t.Errorf("[%s %s] %s=%q：總數應為 %d，得 %v", label, r.key, r.param, name, len(want), gotTotal)
			}
			out.visible[name] = true
			if !firstPage[name] {
				out.later++
			}
			continue
		}
		if len(want) == 0 {
			if !srSame(got, miss) {
				t.Errorf("[%s %s] %s=%q：列表看不到，應與不存在同一回應（%s），得 %s", label, r.key, r.param, name, srShow(miss), srShow(got))
			}
			out.hidden++
			continue
		}
		if !reflect.DeepEqual(enCanon(gotRows), enCanon(want)) {
			t.Errorf("[%s %s] %s=%q：應等於列表中名稱相同的 %d 列，得 %s", label, r.key, r.param, name, len(want), clipCmp(string(got.body)))
		}
		if gotTotal != nil && int(gotTotal.(float64)) != len(want) {
			t.Errorf("[%s %s] %s=%q：總數應為 %d，得 %v", label, r.key, r.param, name, len(want), gotTotal)
		}
		out.visible[name] = true
	}
	if mrows, mtotal, _ := enParse(t, miss.body); len(mrows) != 0 || (mtotal != nil && mtotal.(float64) != 0) {
		t.Errorf("[%s %s] 不存在的名稱應回空集合與總數 0：%s", label, r.key, srShow(miss))
	}
	return out
}

// enCheckSubject 一個主體在全部列表上的比對結果，鍵為列表代號。
func (e *baselineEnv) enCheckSubject(t *testing.T, label string, subj *baselineSubject) map[string]enOutcome {
	t.Helper()
	out := map[string]enOutcome{}
	var parts []string
	for _, r := range enRoutes {
		o := e.enCompare(t, label, subj, r)
		out[r.key] = o
		parts = append(parts, fmt.Sprintf("%s %d/%d/%d", r.key, len(o.visible), o.hidden, o.denied))
	}
	t.Logf("[%s] 查得到／看不到／被拒：%s", label, strings.Join(parts, "、"))
	return out
}

func enVisibleTotal(r map[string]enOutcome) int {
	n := 0
	for _, o := range r {
		n += len(o.visible)
	}
	return n
}

func TestExactNameLookupAcrossPrincipals(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	ag1 := e.object("assetGroup.1").(uint)
	admin := e.roleID(model.RoleAdmin)
	nodeRole := e.apiTokenCustomRole("en-node-role", authz.PermAssetView, authz.PermAssetGroupManage,
		authz.PermAuthorizationManage, authz.PermCredentialView)
	mgmt := e.apiTokenCustomRole("en-mgmt-role", authz.PermAssetView, authz.PermAssetGroupManage,
		authz.PermAuthorizationManage, authz.PermUserGroupManage)
	credView := e.apiTokenCustomRole("en-cred-view-role", authz.PermCredentialView, authz.PermCredentialManage)

	// 本人為超級管理者並以節點範圍持有節點角色，token 只授權節點角色
	superOwner := e.apiTokenUser("en-super-owner", admin)
	e.srGrantNodes(superOwner.userID, nodeRole, ag1)
	// 本人持有管理角色與憑證檢視，token 只授權管理角色
	credOwner := e.apiTokenUser("en-cred-owner", mgmt, credView)
	// 自動化帳號對一台資產有連線授權（資產查找的可見正例）
	sshAsset := e.object("asset.ssh").(uint)
	// 有憑證檢視的本人（token 沿用同一主體）同樣對該資產有連線授權（資產查找的可見正例）
	for _, uid := range []uint{e.subjects["S12"].UserID, credOwner.userID} {
		u := uid
		if err := e.db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &sshAsset, Permission: model.PermissionConnect,
			Source: model.AuthorizationSourceManual, GrantedBy: e.subjects["S01"].UserID,
			Accounts: model.AccountScope{model.AccountScopeAll}}).Error; err != nil {
			t.Fatalf("連線授權：%v", err)
		}
	}
	tokNode := e.srToken("T-en-node", superOwner, nodeRole)
	tokNoCred := e.srToken("T-en-no-cred", credOwner, mgmt)
	sessSuper := e.srSession("H-en-super-owner", superOwner)
	sessCred := e.srSession("H-en-cred-owner", credOwner)
	e.apiTokenRetemplate()

	subjects := []struct {
		label string
		subj  *baselineSubject
	}{
		{"超級管理者 S01", e.subjects["S01"]},
		{"稽核者 S03", e.subjects["S03"]},
		{"一般使用者 S02", e.subjects["S02"]},
		{"自動化帳號 S12", e.subjects["S12"]},
		{"token 只有節點範圍角色（本人為超級管理者）", tokNode},
		{"本人工作階段：超級管理者", sessSuper},
		{"token 沒有憑證檢視（本人有）", tokNoCred},
		{"本人工作階段：有憑證檢視者", sessCred},
	}
	results := map[string]map[string]enOutcome{}
	for _, s := range subjects {
		results[s.label] = e.enCheckSubject(t, s.label, s.subj)
	}

	t.Run("every_subject_has_a_visible_positive", func(t *testing.T) {
		for _, s := range subjects {
			if enVisibleTotal(results[s.label]) == 0 {
				t.Errorf("%s：至少要有一個查得到的名稱，否則全部被拒或全部看不到也會通過", s.label)
			}
		}
	})

	t.Run("paged_lookup_reaches_targets_beyond_first_unfiltered_page", func(t *testing.T) {
		// 先切頁再篩的實作只找得到未篩選第一頁內的名稱：看得到超過一頁資產的主體，必須有落在後頁的正例
		for _, label := range []string{"超級管理者 S01", "token 只有節點範圍角色（本人為超級管理者）"} {
			if o := results[label]["asset_paged"]; o.later == 0 {
				t.Errorf("%s：每頁兩筆的資產查找沒有任何落在未篩選後頁的可見正例（可見 %d 個），驗不到篩選先於切頁", label, len(o.visible))
			}
		}
	})

	t.Run("auditor_is_actually_called", func(t *testing.T) {
		r := results["稽核者 S03"]
		for _, k := range []string{"asset", "node"} {
			if len(r[k].visible) == 0 {
				t.Errorf("稽核者的 %s 查找應查得到（與其列表相同）：%v", k, r[k])
			}
		}
	})

	t.Run("automation_account_looks_up_assets_and_is_refused_elsewhere_like_list", func(t *testing.T) {
		r := results["自動化帳號 S12"]
		var sshName string
		if err := e.db.Table("assets").Where("id = ?", sshAsset).Pluck("name", &sshName).Error; err != nil || sshName == "" {
			t.Fatalf("讀取資產名稱：%v", err)
		}
		if !r["asset"].visible[sshName] {
			t.Errorf("自動化帳號應查得到有授權的資產 %q：%v", sshName, r["asset"].visible)
		}
		if r["asset"].hidden < 2 {
			t.Errorf("前提：自動化帳號有看不到的資產名稱與不存在的名稱（看不到 %d）", r["asset"].hidden)
		}
		for _, k := range []string{"node", "user", "user_group", "credential", "credential_paged"} {
			if r[k].denied == 0 || len(r[k].visible) != 0 {
				t.Errorf("自動化帳號的 %s 查找應照列表被拒：%v", k, r[k])
			}
		}
	})

	t.Run("token_narrower_than_super_admin_owner_answers_out_of_scope_names_as_missing", func(t *testing.T) {
		tok, own := results["token 只有節點範圍角色（本人為超級管理者）"], results["本人工作階段：超級管理者"]
		for _, k := range []string{"asset", "node"} {
			narrower := 0
			for name := range own[k].visible {
				if !tok[k].visible[name] {
					narrower++
				}
			}
			if narrower == 0 || len(tok[k].visible) == 0 {
				t.Errorf("%s：前提是本人查得到而 token 查不到的名稱至少一個、token 自己也查得到至少一個（本人 %d、token %d、差 %d）",
					k, len(own[k].visible), len(tok[k].visible), narrower)
			}
		}
		for _, k := range []string{"user", "user_group"} {
			if tok[k].denied == 0 || len(own[k].visible) == 0 {
				t.Errorf("%s：token 沒有該能力應照列表被拒、本人查得到（token %v、本人 %v）", k, tok[k], own[k])
			}
		}
	})

	t.Run("token_without_credential_view_is_refused_like_its_list", func(t *testing.T) {
		tok, own := results["token 沒有憑證檢視（本人有）"], results["本人工作階段：有憑證檢視者"]
		for _, k := range []string{"credential", "credential_paged"} {
			if tok[k].denied == 0 || len(own[k].visible) == 0 {
				t.Errorf("%s：token 應照列表被拒、本人查得到（token %v、本人 %v）", k, tok[k], own[k])
			}
		}
		if len(tok["asset"].visible) == 0 {
			t.Errorf("前提：token 仍查得到資產：%v", tok["asset"])
		}
	})

	t.Run("token_role_revoked_follows_list", func(t *testing.T) {
		before := results["token 只有節點範圍角色（本人為超級管理者）"]
		if len(before["asset"].visible) == 0 {
			t.Fatalf("前提：收回前 token 查得到資產")
		}
		if err := e.db.Where("user_id = ? AND role_id = ?", superOwner.userID, nodeRole).Delete(&model.UserRole{}).Error; err != nil {
			t.Fatalf("收回角色：%v", err)
		}
		if err := e.db.Where("subject_kind = ? AND subject_id = ? AND role_id = ?", model.BindingSubjectUser,
			superOwner.userID, nodeRole).Delete(&model.RoleBindingNode{}).Error; err != nil {
			t.Fatalf("收回範圍：%v", err)
		}
		e.apiTokenRetemplate()
		after := e.enCheckSubject(t, "token 角色收回後", tokNode)
		for _, k := range []string{"asset", "asset_paged", "credential", "credential_paged"} {
			for name := range before[k].visible {
				if after[k].visible[name] {
					t.Errorf("角色收回後 token 不應再查得到 %s %q", k, name)
				}
			}
		}
	})
}
