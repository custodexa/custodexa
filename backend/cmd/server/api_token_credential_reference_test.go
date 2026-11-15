package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 以 API token 引用系統保存的既有憑證（共同授權判定，端到端）：
// 五個入口（建立資產、匯入預覽與提交、建立資產帳號、掛載、更換憑證）在 token 與「只持那些角色的人類帳號」之間
// 回應狀態、回應本文與資料庫的變更相同，含全域指派、節點範圍內、節點範圍外、無掛載能力四種情形。
// 唯一刻意的差異是 token 成功掛載時多出的一則系統安全告警（告警列、明細、每個啟用通道一筆投遞）：
// 先單獨取出並驗證，再比對其餘結果；人類請求不得有這則告警。

const attachAlertType = string(port.SystemAlertAPITokenCredentialAttached)

// apiTokenAttachAlertRoutes 開放端點中，以 token 成功時會多出一則掛載告警的路由（逐端點對照的預期差異）。
var apiTokenAttachAlertRoutes = map[string]bool{
	"POST /api/v1/credentials/:id/bindings":                 true,
	"PUT /api/v1/assets/:id/accounts/:accountId/credential": true,
}

// cmpTakeAttachAlert 從一筆對照紀錄取出掛載告警：告警列（依類型）與明細、投遞兩張表中屬於這些告警（以告警編號
// 對應）的新增列。回傳取出的告警列數；其餘列與差異原樣留下照常比對，不屬於已取出告警的額外寫入不會被遮掉。
func cmpTakeAttachAlert(rec *cmpRecord) int {
	taken := map[string]bool{}
	var kept []map[string]any
	for _, a := range rec.Alerts {
		if a["@table"] == "command_alerts" && a["reason_code"] == attachAlertType {
			taken[fmt.Sprint(a["id"])] = true
			continue
		}
		kept = append(kept, a)
	}
	rec.Alerts = kept
	if len(taken) == 0 {
		return 0
	}
	for _, tbl := range []string{"system_alert_details", "system_alert_outbox"} {
		entry, ok := rec.DB[tbl]
		if !ok {
			continue
		}
		var rest []any
		for _, r := range cmpRows(entry["added"]) {
			if row, ok := r.(map[string]any); ok && taken[fmt.Sprint(row["alert_id"])] {
				continue
			}
			rest = append(rest, r)
		}
		if len(rest) > 0 {
			entry["added"] = rest
		} else {
			delete(entry, "added")
		}
		if len(entry) == 0 {
			delete(rec.DB, tbl)
		}
	}
	if len(rec.DB) == 0 {
		rec.DB = nil
	}
	return len(taken)
}

// cmpRows 差異中的列清單（正規化前後的兩種型別都接受）。
func cmpRows(v any) []any {
	switch rows := v.(type) {
	case []any:
		return rows
	case []map[string]any:
		out := make([]any, 0, len(rows))
		for _, r := range rows {
			out = append(out, r)
		}
		return out
	}
	return nil
}

// refEchoMasked 回應本文的 JSON，請求中引用的憑證識別在回顯處（credential_id 的值）換成佔位。
func refEchoMasked(body any, credID uint) string {
	raw, _ := json.Marshal(body)
	return strings.ReplaceAll(string(raw), fmt.Sprintf(`"credential_id":%d`, credID), `"credential_id":"<input>"`)
}

// apiTokenAttachAlertRows 資料庫中目前的掛載告警明細（參數解開）與其告警列分級、投遞數。
type apiTokenAttachAlertRow struct {
	detail   model.SystemAlertDetail
	params   map[string]string
	severity string
	outbox   int64
}

func (e *baselineEnv) apiTokenAttachAlerts() []apiTokenAttachAlertRow {
	e.t.Helper()
	var details []model.SystemAlertDetail
	if err := e.db.Where("alert_type = ?", attachAlertType).Order("alert_id").Find(&details).Error; err != nil {
		e.t.Fatalf("讀取告警明細：%v", err)
	}
	out := make([]apiTokenAttachAlertRow, 0, len(details))
	for _, d := range details {
		row := apiTokenAttachAlertRow{detail: d, params: map[string]string{}}
		if err := json.Unmarshal([]byte(d.Params), &row.params); err != nil {
			e.t.Fatalf("解析告警參數：%v", err)
		}
		var sev []string
		if err := e.db.Table("command_alerts").Where("id = ?", d.AlertID).Pluck("severity", &sev).Error; err != nil || len(sev) != 1 {
			e.t.Fatalf("讀取告警列：%v（%d 筆）", err, len(sev))
		}
		row.severity = sev[0]
		if err := e.db.Model(&model.SystemAlertOutbox{}).Where("alert_id = ?", d.AlertID).Count(&row.outbox).Error; err != nil {
			e.t.Fatalf("計數投遞：%v", err)
		}
		out = append(out, row)
	}
	return out
}

func (e *baselineEnv) enabledChannelCount() int64 {
	return e.apiTokenCount("notification_channels", "enabled = ?", true)
}

// apiTokenRefEntry 一個入口：請求、成功時的掛載方式與目標資產名稱（匯入為空）。
type apiTokenRefEntry struct {
	name   string
	entry  string // 告警的掛載方式；空＝此入口不產生告警（預覽）
	method string
	path   string
	body   func(credID uint) any
	asset  string // 單筆入口的目標資產名稱
}

func apiTokenRefEntries(e *baselineEnv) []apiTokenRefEntry {
	ag1 := e.object("assetGroup.1").(uint)
	ssh := e.object("asset.ssh").(uint)
	ssh2 := e.object("account.ssh2").(uint)
	importBody := func(credID uint) any {
		return map[string]any{"source": "form", "rows": []map[string]any{
			{"name": "cmp-ref-import-plain", "protocol": "ssh", "host": "198.51.100.11", "port": 22, "credential_id": nil, "node_ids": []uint{ag1}},
			{"name": "cmp-ref-import-1", "protocol": "ssh", "host": "198.51.100.12", "port": 22, "credential_id": credID, "node_ids": []uint{ag1}},
			{"name": "cmp-ref-import-2", "protocol": "ssh", "host": "198.51.100.13", "port": 22, "credential_id": credID, "node_ids": []uint{ag1}},
		}}
	}
	return []apiTokenRefEntry{
		{name: "建立資產", entry: "asset_create", method: http.MethodPost, path: "/api/v1/assets", asset: "cmp-ref-asset",
			body: func(credID uint) any {
				return map[string]any{"name": "cmp-ref-asset", "protocol": "ssh", "host": "198.51.100.10", "port": 22,
					"credential_id": credID, "node_ids": []uint{ag1}}
			}},
		{name: "匯入預覽", method: http.MethodPost, path: "/api/v1/assets/import/preview", body: importBody},
		{name: "匯入提交", entry: "import", method: http.MethodPost, path: "/api/v1/assets/import", body: importBody},
		{name: "建立資產帳號", entry: "account_create", method: http.MethodPost, path: fmt.Sprintf("/api/v1/assets/%d/accounts", ssh),
			asset: "baseline-ssh", body: func(credID uint) any { return map[string]any{"credential_id": credID, "note": "cmp"} }},
		{name: "掛載", entry: "bind", method: http.MethodPost, asset: "baseline-ssh",
			body: func(uint) any { return map[string]any{"asset_id": ssh, "note": "cmp"} }},
		{name: "更換憑證", entry: "rebind", method: http.MethodPut, path: fmt.Sprintf("/api/v1/assets/%d/accounts/%d/credential", ssh, ssh2),
			asset: "baseline-ssh", body: func(credID uint) any { return map[string]any{"credential_id": credID} }},
	}
}

func (r apiTokenRefEntry) request(credID uint) baselineRequest {
	path := r.path
	if r.entry == "bind" {
		path = fmt.Sprintf("/api/v1/credentials/%d/bindings", credID)
	}
	raw, _ := json.Marshal(r.body(credID))
	return baselineRequest{Method: r.method, Path: path, Body: raw, ContentType: "application/json"}
}

// apiTokenRefCase 一種授權情形。
type apiTokenRefCase struct {
	name    string
	pair    *apiTokenPair
	credID  uint
	success bool
}

// seedAPITokenRefCredentials 兩筆共用憑證：歸屬節點 1（節點範圍內）與歸屬節點 2（節點範圍外）。
func seedAPITokenRefCredentials(e *baselineEnv) (inNode, outNode uint) {
	ag1 := e.object("assetGroup.1").(uint)
	ag2 := e.object("assetGroup.2").(uint)
	mk := func(name string, node uint) uint {
		id := e.apiID("S01", http.MethodPost, "/api/v1/credentials", map[string]any{
			"name": name, "username": name, "protocol_family": "ssh", "password": "Cmp-Known-Secret-" + name}, name)
		kind := model.CredentialOwnerNode
		if err := e.db.Model(&model.Credential{}).Where("id = ?", id).
			Updates(map[string]any{"owner_kind": kind, "owner_node_id": node}).Error; err != nil {
			e.t.Fatalf("設定憑證歸屬 %s：%v", name, err)
		}
		return id
	}
	return mk("cmp-ref-node1", ag1), mk("cmp-ref-node2", ag2)
}

// refRejected 請求被拒：非 2xx，或匯入預覽以列錯誤回報（200 且 ok 為 false）。
func refRejected(r cmpRecord) bool {
	if !is2xx(r.Status) {
		return true
	}
	m, _ := r.Body.(map[string]any)
	ok, has := m["ok"].(bool)
	return has && !ok
}

// TestAPITokenCredentialReferenceParity 五個入口、四種情形：token 與只持那些角色的人類結果相同，
// token 成功掛載時多出恰一則告警（內容另驗），人類請求沒有。
func TestAPITokenCredentialReferenceParity(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	pairs := seedAPITokenPairs(e)
	super, scoped := pairs[0], pairs[1]
	node := e.apiTokenNodePair(e.object("assetGroup.1").(uint))
	inNode, outNode := seedAPITokenRefCredentials(e)
	e.apiTokenRetemplate()
	unbound := e.object("credential.unbound").(uint)
	channels := e.enabledChannelCount()

	cases := []apiTokenRefCase{
		{name: "全域指派", pair: super, credID: unbound, success: true},
		{name: "節點範圍內", pair: node, credID: inNode, success: true},
		{name: "節點範圍外", pair: node, credID: outNode},
		{name: "無掛載能力", pair: scoped, credID: unbound},
	}
	ran := 0
	for _, entry := range apiTokenRefEntries(e) {
		for _, c := range cases {
			entry, c := entry, c
			t.Run(entry.name+"／"+c.name, func(t *testing.T) {
				ran++
				br := entry.request(c.credID)
				tr := e.cmpRun(c.pair.token, br, c.pair.tokenSelf, c.pair.humanSelf)
				hr := e.cmpRun(c.pair.human, br, c.pair.humanSelf, c.pair.tokenSelf)
				tokenAlerts, humanAlerts := cmpTakeAttachAlert(&tr), cmpTakeAttachAlert(&hr)
				if humanAlerts != 0 {
					t.Errorf("人類請求不應產生掛載告警（%d 則）", humanAlerts)
				}
				wantAlerts := 0
				if c.success && entry.entry != "" {
					wantAlerts = 1
				}
				if tokenAlerts != wantAlerts {
					t.Errorf("token 的掛載告警 %d 則，應為 %d", tokenAlerts, wantAlerts)
				}
				if d := cmpDiff(tr, hr); d != "" {
					t.Errorf("token 與只持有授權角色的本人不同%s", d)
				}
				if c.success {
					if refRejected(hr) {
						t.Fatalf("情境應走到成功分支，人類側得到 %d %v", hr.Status, hr.Body)
					}
					if entry.entry != "" && len(hr.DB) == 0 {
						t.Errorf("成功的寫入應有資料變更")
					}
				} else {
					if !refRejected(tr) {
						t.Fatalf("應被拒，token 得到 %d %v", tr.Status, tr.Body)
					}
					if len(tr.DB) > 0 || len(tr.Alerts) > 0 || len(tr.FS) > 0 || len(tr.Remote) > 0 {
						t.Errorf("被拒卻有變更 db=%v alerts=%v fs=%v remote=%v", tr.DB, tr.Alerts, tr.FS, tr.Remote)
					}
				}
				if c.success && entry.entry != "" {
					e.assertAttachAlertContent(t, c.pair, entry, br, channels)
				}
			})
		}
	}
	if ran != 6*len(cases) {
		t.Fatalf("實際跑到 %d 個情境，應為 %d", ran, 6*len(cases))
	}

	// 節點範圍外的憑證與不存在的憑證回應相同（不構成存在性探測）：狀態、錯誤碼與完整回應本文（匯入預覽回 200 時
	// 含逐列的錯誤與解析結果）；本文中唯一允許不同的是回顯的輸入值本身
	t.Run("節點範圍外與不存在同形", func(t *testing.T) {
		const missingID = 987654
		previewChecked := false
		for _, entry := range apiTokenRefEntries(e) {
			out := e.cmpRun(node.token, entry.request(outNode), node.tokenSelf, node.humanSelf)
			missing := e.cmpRun(node.token, entry.request(missingID), node.tokenSelf, node.humanSelf)
			if out.Status != missing.Status || cmpErrorCode(out) != cmpErrorCode(missing) {
				t.Errorf("%s：範圍外 %d %s，不存在 %d %s", entry.name, out.Status, cmpErrorCode(out), missing.Status, cmpErrorCode(missing))
			}
			ob, mb := refEchoMasked(out.Body, outNode), refEchoMasked(missing.Body, missingID)
			if ob != mb {
				t.Errorf("%s：範圍外與不存在的回應本文不同\n  範圍外 %s\n  不存在 %s", entry.name, clipCmp(ob), clipCmp(mb))
			}
			if entry.name == "匯入預覽" {
				previewChecked = out.Status == http.StatusOK && strings.Contains(ob, `"rows"`)
			}
		}
		if !previewChecked {
			t.Errorf("前提：匯入預覽應回 200 並帶逐列結果")
		}
	})
}

// assertAttachAlertContent 以 token 重送一次成功的請求，直接讀取落地的告警：恰一則、分級中、
// 參數照入口（單筆帶憑證與資產名稱，匯入帶資產數與憑證數）、每個啟用通道一筆投遞。之後還原。
func (e *baselineEnv) assertAttachAlertContent(t *testing.T, p *apiTokenPair, entry apiTokenRefEntry, br baselineRequest, channels int64) {
	t.Helper()
	defer e.apiTokenRuleRestore()
	var body any
	_ = json.Unmarshal(br.Body, &body)
	code, resp := e.apiTokenRuleCall(p.token, br.Method, br.Path, body)
	if !is2xx(code) {
		t.Fatalf("重送應成功，得到 %d %v", code, resp)
	}
	rows := e.apiTokenAttachAlerts()
	if len(rows) != 1 {
		t.Fatalf("落地的掛載告警 %d 則，應為 1", len(rows))
	}
	r := rows[0]
	var token model.APIToken
	if err := e.db.First(&token, p.tokenID).Error; err != nil {
		t.Fatalf("讀取 token：%v", err)
	}
	if r.params["token_name"] != token.Name || r.params["actor"] != p.tokenSelf.username || r.params["entry"] != entry.entry {
		t.Errorf("告警參數：%v", r.params)
	}
	if r.severity != model.AlertSeverityMedium {
		t.Errorf("分級 %s，應為 medium", r.severity)
	}
	if r.outbox != channels {
		t.Errorf("投遞 %d 筆，啟用通道 %d 個", r.outbox, channels)
	}
	if entry.entry == "import" {
		if r.detail.TargetKind != "user" || r.params["asset_count"] != "2" || r.params["credential_count"] != "1" ||
			r.params["credential_name"] != "" || r.params["asset_name"] != "" {
			t.Errorf("匯入告警：目標 %s，參數 %v", r.detail.TargetKind, r.params)
		}
		return
	}
	if r.detail.TargetKind != "asset" || r.params["asset_name"] != entry.asset || r.params["credential_name"] == "" {
		t.Errorf("單筆告警：目標 %s，參數 %v", r.detail.TargetKind, r.params)
	}
}

// TestCmpTakeAttachAlertKeepsUnrelatedRows 比較器只移除屬於已取出告警的明細與投遞列：同一次請求多出不屬於該告警的
// 明細或投遞列時，取出後仍留在差異中，與沒有這些列的一方比對必然不同。
func TestCmpTakeAttachAlertKeepsUnrelatedRows(t *testing.T) {
	mk := func(extra bool) cmpRecord {
		rec := cmpRecord{Status: 201,
			Alerts: []map[string]any{{"@table": "command_alerts", "id": float64(41), "reason_code": attachAlertType}},
			DB: map[string]map[string]any{
				"assets":               {"added": []any{map[string]any{"id": float64(9), "name": "x"}}},
				"system_alert_details": {"added": []any{map[string]any{"alert_id": float64(41), "alert_type": attachAlertType}}},
				"system_alert_outbox":  {"added": []any{map[string]any{"alert_id": float64(41), "dest_name": "a"}}},
			}}
		if extra {
			rec.DB["system_alert_details"]["added"] = append(rec.DB["system_alert_details"]["added"].([]any),
				map[string]any{"alert_id": float64(42), "alert_type": "other"})
			rec.DB["system_alert_outbox"]["added"] = append(rec.DB["system_alert_outbox"]["added"].([]any),
				map[string]any{"alert_id": float64(42), "dest_name": "b"})
		}
		return rec
	}
	human := cmpRecord{Status: 201, DB: map[string]map[string]any{
		"assets": {"added": []any{map[string]any{"id": float64(9), "name": "x"}}},
	}}

	t.Run("only_the_alert_rows_are_taken", func(t *testing.T) {
		rec := mk(false)
		if n := cmpTakeAttachAlert(&rec); n != 1 {
			t.Fatalf("應取出 1 則，得 %d", n)
		}
		if d := cmpDiff(rec, human); d != "" {
			t.Errorf("只有該告警的列時，取出後應與人類側相同%s", d)
		}
	})
	t.Run("unrelated_rows_stay_and_fail_the_comparison", func(t *testing.T) {
		rec := mk(true)
		if n := cmpTakeAttachAlert(&rec); n != 1 {
			t.Fatalf("應取出 1 則，得 %d", n)
		}
		for _, tbl := range []string{"system_alert_details", "system_alert_outbox"} {
			rows := cmpRows(rec.DB[tbl]["added"])
			if len(rows) != 1 || fmt.Sprint(rows[0].(map[string]any)["alert_id"]) != "42" {
				t.Errorf("%s 應只留下不屬於該告警的那一列：%v", tbl, rec.DB[tbl])
			}
		}
		if d := cmpDiff(rec, human); d == "" {
			t.Errorf("多出不屬於該告警的列時，比對應失敗")
		}
	})
	t.Run("no_alert_taken_leaves_everything", func(t *testing.T) {
		rec := mk(true)
		rec.Alerts = nil
		if n := cmpTakeAttachAlert(&rec); n != 0 {
			t.Fatalf("沒有掛載告警時應取出 0 則，得 %d", n)
		}
		if len(cmpRows(rec.DB["system_alert_details"]["added"])) != 2 {
			t.Errorf("沒有取出告警時不得移除任何列：%v", rec.DB)
		}
	})
}
