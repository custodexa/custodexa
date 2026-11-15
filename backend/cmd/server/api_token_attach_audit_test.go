package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// 以 API token 掛載既有憑證的留痕（端到端）：五個寫入入口各一次（匯入一批兩台）之後，
//   - 稽核列標示經由的 token 識別與名稱，並帶受影響的憑證與資產；由每則告警的關聯識別回查得到同交易的稽核列，
//     匯入的那則回查到每一台；
//   - 以已知秘密字串、該憑證現行版本的密文、token 明文與雜湊，對實際落地的告警明細、以三語渲染後的通知本文、
//     全部稽核列與五次回應本文做全文搜尋，零命中。

// TestAPITokenAttachAuditTrail 見檔頭。
func TestAPITokenAttachAuditTrail(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	super := seedAPITokenPairs(e)[0]
	ag1 := e.object("assetGroup.1").(uint)
	ssh := e.object("asset.ssh").(uint)
	ssh2 := e.object("account.ssh2").(uint)
	const secret = "Cmp-Attach-Known-Secret-7Q"
	cred := e.apiID("S01", http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "cmp-attach-audit", "username": "cmp-attach", "protocol_family": "ssh", "password": secret}, "attach credential")
	other := e.apiID("S01", http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "cmp-attach-audit-2", "username": "cmp-attach-2", "protocol_family": "ssh", "password": secret + "-2"}, "attach credential 2")
	e.apiTokenRetemplate()
	defer e.apiTokenRuleRestore()

	var token model.APIToken
	if err := e.db.First(&token, super.tokenID).Error; err != nil {
		t.Fatalf("讀取 token：%v", err)
	}
	var ciphertexts []string
	if err := e.db.Model(&model.CredentialSecretVersion{}).Where("credential_id IN ?", []uint{cred, other}).
		Pluck("password_enc", &ciphertexts).Error; err != nil || len(ciphertexts) == 0 {
		t.Fatalf("讀取密文：%v（%d 筆）", err, len(ciphertexts))
	}
	needles := map[string]string{"已知秘密": secret, "token 明文": super.token.Token, "token 雜湊": token.TokenHash}
	for i, c := range ciphertexts {
		needles[fmt.Sprintf("密文 %d", i)] = c
	}

	steps := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/assets", map[string]any{"name": "cmp-attach-asset", "protocol": "ssh", "host": "198.51.100.30",
			"port": 22, "credential_id": cred, "node_ids": []uint{ag1}}},
		{http.MethodPost, fmt.Sprintf("/api/v1/assets/%d/accounts", ssh), map[string]any{"credential_id": cred, "note": "cmp"}},
		{http.MethodPost, fmt.Sprintf("/api/v1/credentials/%d/bindings", other), map[string]any{"asset_id": e.object("asset.approval").(uint)}},
		{http.MethodPut, fmt.Sprintf("/api/v1/assets/%d/accounts/%d/credential", ssh, ssh2), map[string]any{"credential_id": other}},
		{http.MethodPost, "/api/v1/assets/import", map[string]any{"source": "form", "rows": []map[string]any{
			{"name": "cmp-attach-imp-1", "protocol": "ssh", "host": "203.0.113.31", "port": 22, "credential_id": cred, "node_ids": []uint{ag1}},
			{"name": "cmp-attach-imp-2", "protocol": "ssh", "host": "203.0.113.32", "port": 22, "credential_id": cred, "node_ids": []uint{ag1}},
			{"name": "cmp-attach-imp-3", "protocol": "ssh", "host": "203.0.113.33", "port": 22, "credential_id": nil, "node_ids": []uint{ag1}},
		}}},
	}
	var responses []string
	for _, s := range steps {
		code, body := e.apiTokenRuleCall(super.token, s.method, s.path, s.body)
		raw, _ := json.Marshal(body)
		if !is2xx(code) {
			t.Fatalf("%s %s 應成功，得到 %d %s", s.method, s.path, code, raw)
		}
		responses = append(responses, string(raw))
	}

	rows := e.apiTokenAttachAlerts()
	if len(rows) != len(steps) {
		t.Fatalf("掛載告警 %d 則，應為 %d（每次一則、匯入一則）", len(rows), len(steps))
	}
	var haystack []string
	haystack = append(haystack, responses...)
	ev, _ := notifycat.SystemAlertEvent(attachAlertType)
	for _, r := range rows {
		haystack = append(haystack, r.detail.Params, r.detail.TargetID, r.detail.CorrelationID)
		rendered := map[string]string{"severity": r.severity}
		for k, v := range r.params {
			rendered[k] = v
		}
		for _, lang := range notifycat.SupportedLangs {
			title, text := notifycat.Render(lang, ev, rendered)
			haystack = append(haystack, title, text)
		}
		// 由告警的關聯識別回查同交易的稽核列：帶 token 標示、受影響的資產與憑證
		var audits []model.AuditLog
		if err := e.db.Where("details LIKE ?", `%"correlation_id":"`+r.detail.CorrelationID+`"%`).Find(&audits).Error; err != nil {
			t.Fatalf("回查稽核列：%v", err)
		}
		want := 1
		if r.params["entry"] == "import" {
			want = 2
		}
		if len(audits) != want {
			t.Errorf("%s：回查到 %d 筆稽核列，應為 %d", r.params["entry"], len(audits), want)
		}
		for _, a := range audits {
			if a.APITokenID == nil || *a.APITokenID != super.tokenID || a.APITokenName == nil || *a.APITokenName != token.Name {
				t.Errorf("%s：稽核列 %d 應標示 token %d／%s，得到 %v／%v", r.params["entry"], a.ID, super.tokenID, token.Name, a.APITokenID, a.APITokenName)
			}
			if a.AssetID == nil || !strings.Contains(a.Details, `"credential_id":`) {
				t.Errorf("%s：稽核列 %d 應帶受影響的資產與憑證：asset=%v details=%s", r.params["entry"], a.ID, a.AssetID, a.Details)
			}
		}
	}
	var audits []model.AuditLog
	if err := e.db.Find(&audits).Error; err != nil {
		t.Fatalf("讀取稽核列：%v", err)
	}
	for _, a := range audits {
		haystack = append(haystack, a.Details, a.RequestBody, a.ErrorMsg, a.Path)
	}
	all := strings.Join(haystack, "\n")
	for label, n := range needles {
		if n == "" {
			t.Fatalf("搜尋字串 %s 為空，搜尋不成立", label)
		}
		if strings.Contains(all, n) {
			t.Errorf("%s 出現在告警明細、通知本文、稽核列或回應中", label)
		}
	}
	t.Logf("搜尋範圍：告警 %d 則（明細與三語通知本文）、稽核列 %d 筆、回應 %d 份；搜尋字串 %d 個，零命中",
		len(rows), len(audits), len(responses), len(needles))
}
