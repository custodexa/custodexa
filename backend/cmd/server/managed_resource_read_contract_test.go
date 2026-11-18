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
	"time"

	"github.com/custodexa/backend/internal/guards/managedapi"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 納管資源的讀取面規則（端到端，正式的認證、路由登錄與完整服務圖），逐列執行納管資源登錄表：
//   - 基準：有讀取能力的呼叫者，列表回 200 且含剛建立的那一筆，單筆讀取回 200。基準不成立即失敗，不略過。
//   - 單筆讀取與列表中那一筆比對：列表有的每個欄位單筆讀取都要有且值相同（登錄「詳情投影不同」者改比共同欄位，
//     或排除登錄的列表獨有欄位）。比對的呼叫者有三位：超級管理者、節點範圍的管理者、只有連線授權的一般使用者；
//     呼叫者的列表看得到那一筆時就要比對，節點範圍管理者對範圍內的資源必定看得到。
//   - 範圍隔離：同一位受限的呼叫者讀範圍內的資源回 200，讀範圍外的資源與不存在的識別都回 404，狀態碼與本文相同。
//     只有全域能力的資源沒有部分可見的呼叫者，改驗沒有能力的呼叫者讀單筆與讀列表同一個拒絕。
//   - 精確查找：以登錄的參數查剛建立的那一筆，回恰好一筆且就是它（登錄「查找不能唯一定位」者改驗結果含它）；
//     查不存在的值回空。
//   - 時間欄位：登錄符合或「時間精度不同」者，列表那一筆至少有一個時間欄位且都是 RFC 3339；登錄「沒有時間欄位」者
//     沒有修改時間。
// 登錄表新增一列而這裡沒有對應的測試資料即失敗；初始名單以外的列另須提供寫入面的測試資料（建立、修改、刪除三個函式）。

// mrCase 一列的測試資料：listParams／readParams 為路由樣板參數的實值；id 為剛建立那一筆的識別。
type mrCase struct {
	listParams map[string]string
	readParams map[string]string
	id         uint
	// lookup 精確查找的參數值（對應登錄的參數）；miss 為查不到的值。
	lookup, miss url.Values
	// limited 受限的呼叫者；scoped 為真時 outParams 指向它範圍外的一筆，inParams 指向範圍內的一筆。
	limited             *baselineSubject
	scoped              bool
	inParams, outParams map[string]string
	// missParams 不存在的識別（與 outParams 比對本文）；missAlt 非空時另一個不存在的識別，同樣比對。
	missParams, missAlt map[string]string
}

// mrFixtures 跨列共用的資料：節點範圍的受限呼叫者、只有連線授權的一般使用者與兩個節點下的資產。
type mrFixtures struct {
	scoped          *baselineSubject
	connectOnly     *baselineSubject
	inAsset, outAss uint
	ag1, ag2        uint
	pw              string
}

func p(kv ...string) map[string]string {
	out := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func idStr(id uint) string { return fmt.Sprint(id) }

var mrFixtureTable = map[string]func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase{
	"asset_node": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		in := e.apiID("S01", http.MethodPost, "/api/v1/asset-groups", map[string]any{"name": "mr-node-in", "parent_id": f.ag1}, "node in")
		// 範圍外的那一個與範圍內的同名（名稱只在同一個上層之下唯一）：精確查找的唯一性在這裡實際受檢
		out := e.apiID("S01", http.MethodPost, "/api/v1/asset-groups", map[string]any{"name": "mr-node-in", "parent_id": f.ag2}, "node out")
		return mrCase{readParams: p("id", idStr(in)), id: in,
			lookup: url.Values{"name": {"mr-node-in"}}, miss: url.Values{"name": {"mr-node-none"}},
			limited: f.scoped, scoped: true, inParams: p("id", idStr(in)), outParams: p("id", idStr(out)), missParams: p("id", idStr(srMissingID))}
	},
	"asset": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		return mrCase{readParams: p("id", idStr(f.inAsset)), id: f.inAsset,
			lookup: url.Values{"name": {"mr-asset-in"}}, miss: url.Values{"name": {"mr-asset-none"}},
			limited: f.scoped, scoped: true, inParams: p("id", idStr(f.inAsset)), outParams: p("id", idStr(f.outAss)), missParams: p("id", idStr(srMissingID))}
	},
	"asset_account": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		in := e.apiID("S01", http.MethodPost, fmt.Sprintf("/api/v1/assets/%d/accounts", f.inAsset), map[string]any{"username": "mr-acc-in", "password": f.pw, "note": "mr"}, "account in")
		out := e.apiID("S01", http.MethodPost, fmt.Sprintf("/api/v1/assets/%d/accounts", f.outAss), map[string]any{"username": "mr-acc-out", "password": f.pw, "note": "mr"}, "account out")
		return mrCase{listParams: p("id", idStr(f.inAsset)), readParams: p("id", idStr(f.inAsset), "accountId", idStr(in)), id: in,
			limited: f.scoped, scoped: true,
			inParams:  p("id", idStr(f.inAsset), "accountId", idStr(in)),
			outParams: p("id", idStr(f.outAss), "accountId", idStr(out)),
			// 帳號掛在資產之下：範圍外資產上的帳號，與同一台（呼叫者看來不存在的）資產下不存在的帳號比對；
			// 另與完全不存在的資產比對（outAlt）
			missParams: p("id", idStr(f.outAss), "accountId", idStr(srMissingID)),
			missAlt:    p("id", idStr(srMissingID), "accountId", idStr(srMissingID))}
	},
	"credential": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		// 共用憑證的範圍依歸屬節點：以正式路由建立後把歸屬改到兩個節點（直接寫表，與歸屬轉換寫出的欄位相同）
		mk := func(name string, node uint) uint {
			id := e.apiID("S01", http.MethodPost, "/api/v1/credentials", map[string]any{
				"name": name, "username": name, "protocol_family": "ssh", "password": f.pw, "note": "mr"}, "credential "+name)
			if err := e.db.Model(&model.Credential{}).Where("id = ?", id).Updates(map[string]any{
				"owner_kind": model.CredentialOwnerNode, "owner_node_id": node}).Error; err != nil {
				t.Fatalf("憑證歸屬：%v", err)
			}
			return id
		}
		in, out := mk("mr-cred-in", f.ag1), mk("mr-cred-out", f.ag2)
		return mrCase{readParams: p("id", idStr(in)), id: in,
			lookup: url.Values{"name": {"mr-cred-in"}}, miss: url.Values{"name": {"mr-cred-none"}},
			limited: f.scoped, scoped: true, inParams: p("id", idStr(in)), outParams: p("id", idStr(out)), missParams: p("id", idStr(srMissingID))}
	},
	"user": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		id := e.createUser("mr-user", nil)
		return mrCase{readParams: p("id", idStr(id)), id: id,
			lookup: url.Values{"username": {"mr-user"}}, miss: url.Values{"username": {"mr-user-none"}},
			limited: e.subjects["S02"], inParams: p("id", idStr(id)), missParams: p("id", idStr(srMissingID))}
	},
	"user_group": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		id := e.apiID("S01", http.MethodPost, "/api/v1/user-groups", map[string]any{"name": "mr-ug", "description": "mr"}, "user group")
		return mrCase{readParams: p("id", idStr(id)), id: id,
			lookup: url.Values{"name": {"mr-ug"}}, miss: url.Values{"name": {"mr-ug-none"}},
			limited: e.subjects["S02"], inParams: p("id", idStr(id)), missParams: p("id", idStr(srMissingID))}
	},
	"user_group_role_binding": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		ug := e.apiID("S01", http.MethodPost, "/api/v1/user-groups", map[string]any{"name": "mr-ug-binding", "description": "mr"}, "binding group")
		role := e.roleID(model.RoleAuditor)
		e.mustAPI("S01", http.MethodPut, fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", ug), map[string]any{"role_ids": []uint{role}})
		return mrCase{listParams: p("id", idStr(ug)), limited: e.subjects["S02"],
			inParams: p("id", idStr(ug)), missParams: p("id", idStr(srMissingID))}
	},
	"authorization": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		uid := e.createUser("mr-authz-subject", nil)
		in := e.apiID("S01", http.MethodPost, "/api/v1/authorizations", map[string]any{"user_id": uid, "asset_id": f.inAsset, "permission": "connect"}, "authz in")
		out := e.apiID("S01", http.MethodPost, "/api/v1/authorizations", map[string]any{"user_id": uid, "asset_id": f.outAss, "permission": "connect"}, "authz out")
		return mrCase{readParams: p("id", idStr(in)), id: in,
			limited: f.scoped, scoped: true, inParams: p("id", idStr(in)), outParams: p("id", idStr(out)), missParams: p("id", idStr(srMissingID))}
	},
	"role_definition": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		id := e.apiID("S01", http.MethodPost, "/api/v1/role-definitions", map[string]any{"name": "mr-role", "permissions": []string{"asset:view"}}, "role")
		return mrCase{readParams: p("id", idStr(id)), id: id,
			lookup: url.Values{"name": {"  mr-role "}}, miss: url.Values{"name": {"mr-role-none"}},
			limited: e.subjects["S02"], inParams: p("id", idStr(id)), missParams: p("id", idStr(srMissingID))}
	},
	"group_role_mapping": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		src := e.object("oidcProvider.1").(uint)
		id := e.idOf(e.mustAPI("S01", http.MethodPost, fmt.Sprintf("/api/v1/identity-sources/oidc/%d/role-mappings", src), map[string]any{
			"match_value": "mr-rm-group", "role": "auditor", "note": "mr", "enabled": true, "risk_acknowledged": true}), "role mapping")
		parent := p("type", "oidc", "sourceId", idStr(src))
		read := p("type", "oidc", "sourceId", idStr(src), "ruleId", idStr(id))
		return mrCase{listParams: parent, readParams: read, id: id,
			lookup: url.Values{"match_value": {"mr-rm-group"}, "role": {"auditor"}}, miss: url.Values{"match_value": {"mr-rm-none"}},
			limited: e.subjects["S02"], inParams: read, missParams: p("type", "oidc", "sourceId", idStr(src), "ruleId", idStr(srMissingID))}
	},
	"group_user_group_mapping": func(t *testing.T, e *baselineEnv, f *mrFixtures) mrCase {
		src := e.object("oidcProvider.1").(uint)
		ug := e.apiID("S01", http.MethodPost, "/api/v1/user-groups", map[string]any{"name": "mr-ugm-target", "description": "mr"}, "mapping target group")
		id := e.idOf(e.mustAPI("S01", http.MethodPost, fmt.Sprintf("/api/v1/identity-sources/oidc/%d/user-group-mappings", src), map[string]any{
			"match_value": "mr-ugm-group", "user_group_id": ug, "enabled": true, "risk_acknowledged": true,
			"source_config_acknowledged": true, "note": "mr"}), "user group mapping")
		parent := p("type", "oidc", "sourceId", idStr(src))
		read := p("type", "oidc", "sourceId", idStr(src), "ruleId", idStr(id))
		return mrCase{listParams: parent, readParams: read, id: id,
			lookup: url.Values{"match_value": {"mr-ugm-group"}, "user_group_id": {idStr(ug)}}, miss: url.Values{"match_value": {"mr-ugm-none"}},
			limited: e.subjects["S02"], inParams: read, missParams: p("type", "oidc", "sourceId", idStr(src), "ruleId", idStr(srMissingID))}
	},
}

// mrWriteFixture 一列的寫入面測試資料：建立一筆並回傳識別、對那一筆送出修改、刪除那一筆。
// 函式回傳請求本文與路由樣板參數的實值，由寫入面的共用測試送出並比對；三個都必須提供。
type mrWriteFixture struct {
	create func(t *testing.T, e *baselineEnv, f *mrFixtures) (body map[string]any, params map[string]string)
	update func(t *testing.T, e *baselineEnv, f *mrFixtures, id uint) (body map[string]any, params map[string]string)
	delete func(t *testing.T, e *baselineEnv, f *mrFixtures, id uint) (params map[string]string)
}

// complete 三個函式都有提供。
func (w mrWriteFixture) complete() bool { return w.create != nil && w.update != nil && w.delete != nil }

// mrWriteFixtures 初始名單以外的列的寫入面測試資料。目前沒有初始名單以外的列。
var mrWriteFixtures = map[string]mrWriteFixture{}

// mrFill 以實值替換路由樣板的參數，回傳請求路徑（不含方法）。
func mrFill(t *testing.T, routeKey string, params map[string]string) string {
	t.Helper()
	_, path, _ := strings.Cut(routeKey, " ")
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") {
			v, ok := params[s[1:]]
			if !ok {
				t.Fatalf("%s：參數 %s 沒有實值", routeKey, s)
			}
			segs[i] = url.PathEscape(v)
		}
	}
	return strings.Join(segs, "/")
}

func mrWithQuery(path, extra string, q url.Values) string {
	parts := []string{}
	if extra != "" {
		parts = append(parts, extra)
	}
	if len(q) > 0 {
		parts = append(parts, q.Encode())
	}
	if len(parts) == 0 {
		return path
	}
	return path + "?" + strings.Join(parts, "&")
}

func mrRows(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("解析列表：%v：%s", err, clipCmp(string(body)))
	}
	return out.Data
}

func mrRowID(row map[string]any) uint {
	v, _ := row["id"].(float64)
	return uint(v)
}

// mrSingle 解析單筆讀取的資源本體（包在 data 內者取出 data）。
func mrSingle(t *testing.T, body []byte, wrapped bool) map[string]any {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("解析單筆：%v：%s", err, clipCmp(string(body)))
	}
	if wrapped {
		d, ok := top["data"].(map[string]any)
		if !ok {
			t.Fatalf("單筆讀取登錄為包在 data 內，實際沒有 data：%s", clipCmp(string(body)))
		}
		return d
	}
	return top
}

// mrCompareFields 列表那一筆的欄位（或登錄的共同欄位）都要出現在單筆讀取且值相同；登錄的列表獨有欄位不比。
// 回傳不一致的描述。
func mrCompareFields(listRow, single map[string]any, common, listOnly []string) []string {
	keys := common
	if len(keys) == 0 {
		skip := map[string]bool{}
		for _, k := range listOnly {
			skip[k] = true
		}
		for k := range listRow {
			if !skip[k] {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	var diffs []string
	for _, k := range keys {
		lv, inList := listRow[k]
		sv, inSingle := single[k]
		switch {
		case len(common) > 0 && !inList:
			diffs = append(diffs, fmt.Sprintf("共同欄位 %s 不在列表中", k))
		case !inSingle:
			diffs = append(diffs, fmt.Sprintf("單筆讀取缺欄位 %s", k))
		case !reflect.DeepEqual(lv, sv):
			a, _ := json.Marshal(lv)
			b, _ := json.Marshal(sv)
			diffs = append(diffs, fmt.Sprintf("%s：列表 %s，單筆 %s", k, clipCmp(string(a)), clipCmp(string(b))))
		}
	}
	return diffs
}

// mrCheck 一列的讀取面檢查。回傳實際執行的檢查名稱（供涵蓋判定）。
func (e *baselineEnv) mrCheck(t *testing.T, res managedapi.Resource, c mrCase, f *mrFixtures) []string {
	t.Helper()
	var ran []string
	s01 := e.subjects["S01"]
	cell := func(r managedapi.Rule) managedapi.Cell { return res.Cells[r] }
	common := res.CommonFields

	// 基準：列表 200 且含剛建立的那一筆
	listPath := mrWithQuery(mrFill(t, res.List[0], c.listParams), res.ListPassthrough, nil)
	list := e.srGet(s01, listPath)
	if list.code != http.StatusOK {
		t.Fatalf("[%s] 基準不成立：列表 %s 回 %s", res.Name, listPath, srShow(list))
	}
	rows := mrRows(t, list.body)
	if len(rows) == 0 {
		t.Fatalf("[%s] 基準不成立：列表 %s 為空", res.Name, listPath)
	}
	ran = append(ran, "baseline_list")

	if len(res.Read) > 0 {
		var row map[string]any
		for _, r := range rows {
			if mrRowID(r) == c.id {
				row = r
			}
		}
		if row == nil {
			t.Fatalf("[%s] 基準不成立：列表 %s 沒有剛建立的 %d", res.Name, listPath, c.id)
		}
		readPath := mrFill(t, res.Read[0], c.readParams)
		one := e.srGet(s01, readPath)
		if one.code != http.StatusOK {
			t.Fatalf("[%s] 基準不成立：單筆 %s 回 %s", res.Name, readPath, srShow(one))
		}
		ran = append(ran, "baseline_read")
		if cell(managedapi.RuleSingleMatchesList).Status != managedapi.StatusNotApplicable {
			single := mrSingle(t, one.body, res.ReadWrapped)
			if diffs := mrCompareFields(row, single, common, res.ListOnlyFields); len(diffs) > 0 {
				t.Errorf("[%s] 單筆讀取與列表中那一筆不一致：%s", res.Name, strings.Join(diffs, "；"))
			}
			// 列表獨有欄位只限部分呼叫者：超級管理者的列表不得出現，否則例外的範圍登錄錯了
			for _, k := range res.ListOnlyFields {
				if _, has := row[k]; has {
					t.Errorf("[%s] 超級管理者的列表帶了登錄為列表獨有的欄位 %s：例外的範圍與實際不符", res.Name, k)
				}
			}
			ran = append(ran, "single_matches_list")
			for _, caller := range []struct {
				label string
				subj  *baselineSubject
				must  bool
			}{
				{"scoped_manager", f.scoped, c.scoped},
				{"connect_only_user", f.connectOnly, false},
			} {
				if e.mrCompareAs(t, res, c, caller.label, caller.subj, caller.must) {
					ran = append(ran, "single_matches_list@"+caller.label)
				}
			}
		}
		ran = append(ran, e.mrCheckTimeFields(t, res, row)...)
	} else {
		ran = append(ran, e.mrCheckTimeFields(t, res, rows[0])...)
	}

	// 範圍隔離
	if c.scoped {
		in := e.srGet(c.limited, mrFill(t, res.Read[0], c.inParams))
		out := e.srGet(c.limited, mrFill(t, res.Read[0], c.outParams))
		miss := e.srGet(c.limited, mrFill(t, res.Read[0], c.missParams))
		if in.code != http.StatusOK {
			t.Errorf("[%s] 範圍隔離的前提不成立：受限呼叫者讀範圍內的一筆回 %s", res.Name, srShow(in))
		}
		if out.code != http.StatusNotFound || miss.code != http.StatusNotFound {
			t.Errorf("[%s] 範圍外與不存在都應回 404：範圍外 %s，不存在 %s", res.Name, srShow(out), srShow(miss))
		}
		if out.code != miss.code || string(out.body) != string(miss.body) {
			t.Errorf("[%s] 範圍外與不存在的本文應相同：範圍外 %s，不存在 %s", res.Name, srShow(out), srShow(miss))
		}
		if c.missAlt != nil {
			if alt := e.srGet(c.limited, mrFill(t, res.Read[0], c.missAlt)); !srSame(alt, out) {
				t.Errorf("[%s] 範圍外與不存在（%v）應同一回應：%s／%s", res.Name, c.missAlt, srShow(out), srShow(alt))
			}
		}
		// 受限呼叫者的列表也看不到範圍外的那一筆
		lim := e.srGet(c.limited, mrWithQuery(mrFill(t, res.List[0], c.listParams), res.ListPassthrough, nil))
		if lim.code != http.StatusOK {
			t.Errorf("[%s] 受限呼叫者的列表應回 200，得到 %s", res.Name, srShow(lim))
		} else if res.Name != "asset_account" {
			outID, inID := c.outParams[lastParam(res.Read[0])], c.inParams[lastParam(res.Read[0])]
			sawIn := false
			for _, r := range mrRows(t, lim.body) {
				switch idStr(mrRowID(r)) {
				case outID:
					t.Errorf("[%s] 受限呼叫者的列表含範圍外的 %s", res.Name, outID)
				case inID:
					sawIn = true
				}
			}
			if !sawIn {
				t.Errorf("[%s] 受限呼叫者的列表應含範圍內的 %s", res.Name, inID)
			}
		}
		ran = append(ran, "out_of_scope")
	} else {
		// 只有全域能力的資源：沒有能力的呼叫者，單筆讀取與列表同一個拒絕；不存在的識別對有能力者回 404
		limList := e.srGet(c.limited, mrWithQuery(mrFill(t, res.List[0], c.listParams), res.ListPassthrough, nil))
		if limList.code == http.StatusOK {
			t.Errorf("[%s] 前提：沒有能力的呼叫者 %s 讀列表應被拒，得 %s", res.Name, c.limited.ID, srShow(limList))
		}
		target := res.List[0]
		params := c.inParams
		if len(res.Read) > 0 {
			target = res.Read[0]
		}
		if got := e.srGet(c.limited, mrFill(t, target, params)); !srSame(got, limList) && len(res.Read) > 0 {
			t.Errorf("[%s] 沒有能力的呼叫者讀單筆應與讀列表同一回應：列表 %s，單筆 %s", res.Name, srShow(limList), srShow(got))
		}
		key := res.List[0]
		if len(res.Read) > 0 {
			key = res.Read[0]
		}
		if miss := e.srGet(s01, mrFill(t, key, c.missParams)); miss.code != http.StatusNotFound {
			t.Errorf("[%s] 不存在的識別應回 404，得 %s", res.Name, srShow(miss))
		}
		ran = append(ran, "capability_gate")
	}

	// 精確查找
	if len(res.Lookup.Params) > 0 {
		base := mrFill(t, res.List[0], c.listParams)
		hit := e.srGet(s01, mrWithQuery(base, res.ListPassthrough, c.lookup))
		notUnique := cell(managedapi.RuleExactLookup).Exception == managedapi.ExcLookupNotUnique
		if hit.code != http.StatusOK {
			t.Errorf("[%s] 精確查找回 %s", res.Name, srShow(hit))
		} else if got := mrRows(t, hit.body); notUnique {
			found := false
			for _, r := range got {
				found = found || mrRowID(r) == c.id
			}
			if !found {
				t.Errorf("[%s] 精確查找 %v 的結果應含剛建立的 %d，得 %d 筆", res.Name, c.lookup, c.id, len(got))
			}
		} else if len(got) != 1 || mrRowID(got[0]) != c.id {
			t.Errorf("[%s] 精確查找 %v 應回恰好一筆（%d），得 %d 筆", res.Name, c.lookup, c.id, len(got))
		}
		none := e.srGet(s01, mrWithQuery(base, res.ListPassthrough, c.miss))
		if none.code != http.StatusOK || len(mrRows(t, none.body)) != 0 {
			t.Errorf("[%s] 查不存在的值應回空，得 %s", res.Name, srShow(none))
		}
		ran = append(ran, "exact_lookup")
	}
	return ran
}

// mrCompareAs 以 subj 讀列表；看得到剛建立的那一筆時，單筆讀取必須 200 且與那一筆一致（規則同超級管理者）。
// must 為真時（範圍內的資源）列表必須看得到那一筆。回傳是否實際比對。
func (e *baselineEnv) mrCompareAs(t *testing.T, res managedapi.Resource, c mrCase, label string, subj *baselineSubject, must bool) bool {
	t.Helper()
	list := e.srGet(subj, mrWithQuery(mrFill(t, res.List[0], c.listParams), res.ListPassthrough, nil))
	var row map[string]any
	if list.code == http.StatusOK {
		for _, r := range mrRows(t, list.body) {
			if mrRowID(r) == c.id {
				row = r
			}
		}
	}
	if row == nil {
		if must {
			t.Errorf("[%s] %s 的列表應看得到範圍內的 %d，得 %s", res.Name, label, c.id, srShow(list))
		}
		return false
	}
	one := e.srGet(subj, mrFill(t, res.Read[0], c.readParams))
	if one.code != http.StatusOK {
		t.Errorf("[%s] %s 的列表看得到 %d，單筆讀取卻回 %s", res.Name, label, c.id, srShow(one))
		return true
	}
	if diffs := mrCompareFields(row, mrSingle(t, one.body, res.ReadWrapped), res.CommonFields, res.ListOnlyFields); len(diffs) > 0 {
		t.Errorf("[%s] %s：單筆讀取與列表中那一筆不一致：%s", res.Name, label, strings.Join(diffs, "；"))
	}
	return true
}

// mrCheckTimeFields 依時間欄位規則的狀態檢查列表那一筆：符合與「時間精度不同」要至少一個時間欄位且都能以
// RFC 3339 解析；「沒有時間欄位」要沒有修改時間。時間欄位指以 _at 結尾、值為字串的欄位。
func (e *baselineEnv) mrCheckTimeFields(t *testing.T, res managedapi.Resource, row map[string]any) []string {
	t.Helper()
	cell := res.Cells[managedapi.RuleTimeFields]
	n := 0
	for k, v := range row {
		str, ok := v.(string)
		if !ok || !strings.HasSuffix(k, "_at") {
			continue
		}
		n++
		if _, err := time.Parse(time.RFC3339, str); err != nil {
			t.Errorf("[%s] 時間欄位 %s 不是 RFC 3339：%q", res.Name, k, str)
		}
	}
	switch {
	case cell.Status == managedapi.StatusConforms || cell.Exception == managedapi.ExcTimeFieldFormat:
		if n == 0 {
			t.Errorf("[%s] 時間欄位登錄為 %s，列表那一筆卻沒有任何時間欄位", res.Name, cell.Status)
		}
	case cell.Exception == managedapi.ExcNoTimeFields:
		if _, has := row["updated_at"]; has {
			t.Errorf("[%s] 登錄為沒有時間欄位（或沒有修改時間），列表那一筆卻有 updated_at", res.Name)
		}
	default:
		return nil
	}
	return []string{"time_fields"}
}

func mrRan(ran []string, name string) bool {
	for _, r := range ran {
		if r == name {
			return true
		}
	}
	return false
}

func lastParam(routeKey string) string {
	segs := strings.Split(routeKey, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if strings.HasPrefix(segs[i], ":") {
			return segs[i][1:]
		}
	}
	return ""
}

func TestManagedResourceReadContract(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	f := &mrFixtures{ag1: e.object("assetGroup.1").(uint), ag2: e.object("assetGroup.2").(uint), pw: "Baseline-Pass-123"}
	role := e.apiTokenCustomRole("mr-node-role", authz.PermAssetView, authz.PermAssetGroupManage,
		authz.PermAuthorizationManage, authz.PermCredentialView)
	mgr := e.apiTokenUser("mr-node-manager")
	e.srGrantNodes(mgr.userID, role, f.ag1)
	f.scoped = e.srSession("H-mr-node-manager", mgr)
	mkAsset := func(name string, node uint) uint {
		return e.apiID("S01", http.MethodPost, "/api/v1/assets", map[string]any{"name": name, "protocol": "ssh", "host": "127.0.0.1",
			"port": e.recv.port("ssh"), "username": "mr-root", "password": f.pw, "node_ids": []uint{node}}, "asset "+name)
	}
	f.inAsset, f.outAss = mkAsset("mr-asset-in", f.ag1), mkAsset("mr-asset-out", f.ag2)
	// 只有連線授權的一般使用者：一般使用者角色，加上對範圍內那台資產的連線授權
	conn := e.apiTokenUser("mr-connect-only", e.roleID(model.RoleUser))
	inAsset := f.inAsset
	if err := e.db.Create(&model.AssetAuthorization{UserID: &conn.userID, AssetID: &inAsset, Permission: model.PermissionConnect,
		Source: model.AuthorizationSourceManual, GrantedBy: e.subjects["S01"].UserID,
		Accounts: model.AccountScope{model.AccountScopeAll}}).Error; err != nil {
		t.Fatalf("連線授權：%v", err)
	}
	f.connectOnly = e.srSession("H-mr-connect-only", conn)

	resources := managedapi.Resources()
	cases := map[string]mrCase{}
	for _, res := range resources {
		fx, ok := mrFixtureTable[res.Name]
		if !ok {
			t.Errorf("[%s] 登錄表有這一列但沒有讀取面的測試資料：新增列時要同時提供", res.Name)
			continue
		}
		if w, ok := mrWriteFixtures[res.Name]; !managedapi.IsInitial(res.Name) && (!ok || !w.complete()) {
			t.Errorf("[%s] 初始名單以外的列必須提供寫入面的測試資料（建立、修改、刪除三個函式）", res.Name)
		}
		cases[res.Name] = fx(t, e, f)
	}
	for name := range mrFixtureTable {
		found := false
		for _, res := range resources {
			found = found || res.Name == name
		}
		if !found {
			t.Errorf("測試資料 %s 不在登錄表內（過時）", name)
		}
	}
	e.apiTokenRetemplate()

	ran := map[string][]string{}
	for _, res := range resources {
		c, ok := cases[res.Name]
		if !ok {
			continue
		}
		res := res
		t.Run(res.Name, func(t *testing.T) {
			e.apiTokenRuleRestore()
			defer e.apiTokenRuleRestore()
			ran[res.Name] = e.mrCheck(t, res, c, f)
		})
	}
	if len(ran) != len(resources) {
		t.Errorf("執行了 %d 列，登錄表有 %d 列", len(ran), len(resources))
	}
	// 一般使用者的比對要真的發生：至少在資產這一列（它的列表依呼叫者投影），否則多呼叫者比對等於沒做
	if !mrRan(ran["asset"], "single_matches_list@connect_only_user") {
		t.Errorf("只有連線授權的一般使用者沒有在資產這一列比對單筆讀取與列表：%v", ran["asset"])
	}
	for _, res := range resources {
		t.Logf("[%s] 執行：%s", res.Name, strings.Join(ran[res.Name], "、"))
	}
}
