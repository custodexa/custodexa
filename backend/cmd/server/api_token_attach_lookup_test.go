package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 以 API token 掛載既有憑證的告警回查（端到端，正式的路由註冊與完整服務圖）：
//   - 匯入：告警明細帶回那一次請求的請求識別；以操作日誌的「同一次請求」篩選查到的，恰好是那一次匯入寫下的
//     每一列（中介層的請求列與交易內逐台的資產、帳號、節點列），不多也不少。同一時間窗內另有其他主體與同一把
//     token 的寫入，不得混入；同批列的建立時刻與告警相隔超過一分鐘時照樣查到；分頁逐頁取回的聯集與一次取回相同。
//   - 單筆：告警明細帶操作者的使用者編號，以及發出請求的來源位址。

// attachLookupDetail 系統告警明細中本測試用到的欄位。
type attachLookupDetail struct {
	RequestID   string `json:"request_id"`
	ClientIP    string `json:"client_ip"`
	ActorUserID uint   `json:"actor_user_id"`
	Actor       string `json:"actor"`
	AuditLogID  *uint  `json:"audit_log_id"`
}

func (e *baselineEnv) attachLookupDetail(t *testing.T, alertID uint) attachLookupDetail {
	t.Helper()
	r := e.srGet(e.subjects["S01"], fmt.Sprintf("/api/v1/command-alerts/%d/system-detail", alertID))
	if r.code != http.StatusOK {
		t.Fatalf("讀取告警 %d 明細：%s", alertID, srShow(r))
	}
	var d attachLookupDetail
	if err := json.Unmarshal(r.body, &d); err != nil {
		t.Fatalf("解析告警明細：%v", err)
	}
	return d
}

// attachLookupAuditIDs 以操作日誌列表的同一次請求篩選逐頁取回，回傳全部列的識別（已排序）。
func (e *baselineEnv) attachLookupAuditIDs(t *testing.T, requestID string, pageSize int) []uint {
	t.Helper()
	var ids []uint
	total := -1
	for page := 1; page <= 100; page++ {
		r := e.srGet(e.subjects["S01"], fmt.Sprintf("/api/v1/audit-logs?request_id=%s&page=%d&page_size=%d", requestID, page, pageSize))
		if r.code != http.StatusOK {
			t.Fatalf("操作日誌列表：%s", srShow(r))
		}
		var body struct {
			Data []struct {
				ID uint `json:"id"`
			} `json:"data"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(r.body, &body); err != nil {
			t.Fatalf("解析操作日誌列表：%v", err)
		}
		total = body.Total
		for _, d := range body.Data {
			ids = append(ids, d.ID)
		}
		if len(body.Data) == 0 || len(ids) >= total {
			break
		}
	}
	if len(ids) != total {
		t.Fatalf("逐頁取回 %d 列，列表總數 %d", len(ids), total)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// attachLookupDatetimeAlerts 共用整合環境以模型建的 command_alerts 在 sqlite 讀回時間欄會是字串，明細端點讀不回；
// 換成與正式欄位語義相同的 DATETIME 表。明細與投遞佇列以告警編號關聯，一併清空。須在取範本之前呼叫。
func (e *baselineEnv) attachLookupDatetimeAlerts(t *testing.T) {
	t.Helper()
	for _, tbl := range []string{"system_alert_details", "system_alert_outbox", "command_alerts"} {
		if err := e.db.Exec("DELETE FROM " + tbl).Error; err != nil {
			t.Fatalf("清空 %s：%v", tbl, err)
		}
	}
	for _, stmt := range []string{`DROP TABLE command_alerts`, `CREATE TABLE command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`} {
		if err := e.db.Exec(stmt).Error; err != nil {
			t.Fatalf("重建告警表：%v", err)
		}
	}
}

func (e *baselineEnv) attachLookupMaxAuditID(t *testing.T) uint {
	t.Helper()
	var max uint
	if err := e.db.Model(&model.AuditLog{}).Select("COALESCE(MAX(id), 0)").Scan(&max).Error; err != nil {
		t.Fatalf("讀取稽核列最大識別：%v", err)
	}
	return max
}

func TestAPITokenAttachAlertAuditLookup(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	super := seedAPITokenPairs(e)[0]
	ag1 := e.object("assetGroup.1").(uint)
	cred := e.apiID("S01", http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "attach-lookup", "username": "attach-lookup", "protocol_family": "ssh", "password": "Attach-Lookup-Fixture-1"}, "lookup credential")
	e.attachLookupDatetimeAlerts(t)
	e.apiTokenRetemplate()
	defer e.apiTokenRuleRestore()

	call := func(subj *baselineSubject, method, path string, body any) {
		t.Helper()
		code, resp := e.apiTokenRuleCall(subj, method, path, body)
		if !is2xx(code) {
			raw, _ := json.Marshal(resp)
			t.Fatalf("%s %s 應成功，得到 %d %s", method, path, code, raw)
		}
	}
	importBody := func(prefix string, hosts ...string) map[string]any {
		var rows []map[string]any
		for i, h := range hosts {
			row := map[string]any{"name": fmt.Sprintf("%s-%d", prefix, i), "protocol": "ssh", "host": h, "port": 22, "node_ids": []uint{ag1}}
			if i < 2 {
				row["credential_id"] = cred
			}
			rows = append(rows, row)
		}
		return map[string]any{"source": "form", "rows": rows}
	}

	// 同一時間窗內的其他寫入：另一位使用者的建立資產、同一把 token 的另一次匯入（前後各一）
	call(e.subjects["S01"], http.MethodPost, "/api/v1/assets", map[string]any{"name": "attach-lookup-other-before", "protocol": "ssh",
		"host": "198.51.100.61", "port": 22, "node_ids": []uint{ag1}})
	call(super.token, http.MethodPost, "/api/v1/assets/import", importBody("attach-lookup-prev", "203.0.113.61", "203.0.113.62"))
	alertsBefore := len(e.apiTokenAttachAlerts())

	// 受測的那一次匯入：前後以稽核列識別劃界，界內即這次請求寫下的全部列（獨立於請求識別的基準）
	lo := e.attachLookupMaxAuditID(t)
	call(super.token, http.MethodPost, "/api/v1/assets/import", importBody("attach-lookup-imp", "203.0.113.71", "203.0.113.72", "203.0.113.73"))
	hi := e.attachLookupMaxAuditID(t)

	call(super.token, http.MethodPost, "/api/v1/assets/import", importBody("attach-lookup-next", "203.0.113.81", "203.0.113.82"))
	call(e.subjects["S01"], http.MethodPost, "/api/v1/assets", map[string]any{"name": "attach-lookup-other-after", "protocol": "ssh",
		"host": "198.51.100.62", "port": 22, "node_ids": []uint{ag1}})

	alerts := e.apiTokenAttachAlerts()
	if len(alerts) != alertsBefore+2 {
		t.Fatalf("掛載告警應多 2 則（受測與其後各一次匯入），得 %d → %d", alertsBefore, len(alerts))
	}
	target := alerts[alertsBefore]
	if target.params["entry"] != "import" || target.params["asset_count"] != "2" {
		t.Fatalf("受測告警應為引用 2 台的匯入：%v", target.params)
	}

	var want []uint
	if err := e.db.Model(&model.AuditLog{}).Where("id > ? AND id <= ?", lo, hi).Order("id").Pluck("id", &want).Error; err != nil {
		t.Fatalf("讀取界內稽核列：%v", err)
	}
	var importRequestRows int64
	e.db.Model(&model.AuditLog{}).Where("id > ? AND id <= ? AND path = ? AND method = ?", lo, hi, "/api/v1/assets/import", http.MethodPost).Count(&importRequestRows)
	if len(want) < 4 || importRequestRows != 1 {
		t.Fatalf("前提：界內應有這次匯入的請求列與逐台的資產列（%d 列，其中請求列 %d）", len(want), importRequestRows)
	}

	d := e.attachLookupDetail(t, target.detail.AlertID)
	if d.RequestID == "" {
		t.Fatalf("匯入告警的明細應帶回那一次請求的請求識別：%+v", d)
	}

	// 前提：時間窗（告警前後各一分鐘）內確實混有其他寫入，時間窗不足以分辨
	var alertAt time.Time
	if err := e.db.Model(&model.CommandAlert{}).Where("id = ?", target.detail.AlertID).Pluck("triggered_at", &alertAt).Error; err != nil {
		t.Fatalf("讀取告警時刻：%v", err)
	}
	var inWindow int64
	e.db.Model(&model.AuditLog{}).Where("created_at >= ? AND created_at < ? AND (id <= ? OR id > ?)",
		alertAt.Add(-time.Minute), alertAt.Add(time.Minute), lo, hi).Count(&inWindow)
	if inWindow == 0 {
		t.Fatalf("前提：告警前後一分鐘內應有其他寫入的稽核列")
	}

	t.Run("same_request_filter_returns_exactly_this_import", func(t *testing.T) {
		got := e.attachLookupAuditIDs(t, d.RequestID, 100)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("同一次請求篩選的結果與這次匯入寫下的列不同\n  得到 %v\n  應為 %v", got, want)
		}
	})
	t.Run("pages_union_equals_whole", func(t *testing.T) {
		got := e.attachLookupAuditIDs(t, d.RequestID, 2)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("每頁 2 列逐頁取回的聯集與這次匯入寫下的列不同\n  得到 %v\n  應為 %v", got, want)
		}
	})
	t.Run("rows_older_than_one_minute_still_found", func(t *testing.T) {
		// 大批匯入歷時較長：把同批列（請求列除外）的建立時刻移到告警前五分鐘
		if err := e.db.Exec("UPDATE audit_logs SET created_at = ? WHERE id > ? AND id <= ? AND path = ''",
			alertAt.Add(-5*time.Minute), lo, hi).Error; err != nil {
			t.Fatalf("調整建立時刻：%v", err)
		}
		var moved int64
		e.db.Model(&model.AuditLog{}).Where("id > ? AND id <= ? AND created_at < ?", lo, hi, alertAt.Add(-time.Minute)).Count(&moved)
		if moved == 0 {
			t.Fatalf("前提：應有同批列早於告警一分鐘以上")
		}
		got := e.attachLookupAuditIDs(t, d.RequestID, 100)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("早於告警一分鐘以上的同批列應照樣查到\n  得到 %v\n  應為 %v", got, want)
		}
	})
}

// TestAPITokenAttachAlertSingleActorAndSource 單筆掛載告警的明細帶操作者的使用者編號與發出請求的來源位址。
func TestAPITokenAttachAlertSingleActorAndSource(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	super := seedAPITokenPairs(e)[0]
	ag1 := e.object("assetGroup.1").(uint)
	cred := e.apiID("S01", http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "attach-single", "username": "attach-single", "protocol_family": "ssh", "password": "Attach-Single-Fixture-1"}, "single credential")
	e.attachLookupDatetimeAlerts(t)
	e.apiTokenRetemplate()
	defer e.apiTokenRuleRestore()

	code, resp := e.apiTokenRuleCall(super.token, http.MethodPost, "/api/v1/assets", map[string]any{"name": "attach-single-asset",
		"protocol": "ssh", "host": "198.51.100.71", "port": 22, "credential_id": cred, "node_ids": []uint{ag1}})
	if !is2xx(code) {
		raw, _ := json.Marshal(resp)
		t.Fatalf("建立資產應成功，得到 %d %s", code, raw)
	}
	alerts := e.apiTokenAttachAlerts()
	if len(alerts) != 1 || alerts[0].params["entry"] != "asset_create" {
		t.Fatalf("應有一則建立資產的掛載告警：%d 則", len(alerts))
	}
	d := e.attachLookupDetail(t, alerts[0].detail.AlertID)
	if d.ActorUserID != super.token.UserID || d.ActorUserID == 0 {
		t.Errorf("操作者的使用者編號應為 token 擁有者 %d，得 %d", super.token.UserID, d.ActorUserID)
	}
	// 來源位址：與中介層為同一次請求寫的請求列相同
	var reqRow model.AuditLog
	if err := e.db.Where("request_id = ? AND path = ?", d.RequestID, "/api/v1/assets").First(&reqRow).Error; err != nil {
		t.Fatalf("以明細的請求識別找不到這次請求的請求列（%q）：%v", d.RequestID, err)
	}
	if d.ClientIP == "" || d.ClientIP != reqRow.ClientIP {
		t.Errorf("來源位址應為發出請求的位址 %q，得 %q", reqRow.ClientIP, d.ClientIP)
	}
	if d.AuditLogID == nil || *d.AuditLogID == reqRow.ID {
		t.Errorf("明細關聯的稽核列應為同交易的業務列，不是請求列：%v", d.AuditLogID)
	}
	if d.Actor == "" {
		t.Errorf("明細應帶操作者名稱")
	}
}
