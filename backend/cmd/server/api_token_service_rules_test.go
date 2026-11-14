package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 服務層的 token 專屬限制（端到端）：
//   - 引用系統已保存的憑證：建立資產、建立帳號、匯入（預覽與送出）時引用既有憑證一律拒絕，整筆請求不寫入；
//     自帶密碼照常；卸載不受影響。人類帳號照常。
//   - 改密計畫：建立與每一次保存都以背景執行前重驗所用的執行授權判定檢查最新目標；token 不持有執行能力、
//     或目標在 token 範圍外即拒絕、不寫入；承接暫停中的計畫時不承接。持有執行能力的 token 照常。人類帳號照常。

// apiTokenRuleCall 以 subj 送出一次 JSON 請求，回傳狀態與解析後的本文；不還原狀態（由 apiTokenRuleRestore 還原）。
func (e *baselineEnv) apiTokenRuleCall(subj *baselineSubject, method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var buf []byte
	if body != nil {
		var err error
		if buf, err = json.Marshal(body); err != nil {
			e.t.Fatalf("marshal: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(buf))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	subj.authorize(req)
	w := e.serve(req)
	awaitBackground(e.t)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// apiTokenRuleRestore 把資料庫與行程內狀態還原回範本。
func (e *baselineEnv) apiTokenRuleRestore() {
	touched := e.touched()
	e.resetTables(touched)
	if e.fsDiff() != nil {
		e.resetFS()
	}
	e.resetInProcess(touched)
}

func (e *baselineEnv) apiTokenCount(table, where string, args ...any) int64 {
	e.t.Helper()
	var n int64
	q := e.db.Table(table)
	if where != "" {
		q = q.Where(where, args...)
	}
	if err := q.Count(&n).Error; err != nil {
		e.t.Fatalf("計數 %s：%v", table, err)
	}
	return n
}

// apiTokenNodePair 節點範圍的一組對照：owner 與 twin 皆以節點範圍持有同一個角色（含執行能力），token 只授權該角色。
func (e *baselineEnv) apiTokenNodePair(node uint) *apiTokenPair {
	perms := append(append([]authz.Permission{}, apiTokenScopedGranted...), apiTokenScopedExtra...)
	role := e.apiTokenCustomRole("cmp-node-role", perms...)
	grant := func(username string) cmpIdentity {
		id := e.createUser(username, nil)
		if err := e.db.Create(&model.UserRole{UserID: id, RoleID: role, Source: model.RoleSourceManual,
			ScopeKind: model.ScopeKindNodes}).Error; err != nil {
			e.t.Fatalf("節點範圍指派 %s：%v", username, err)
		}
		if err := e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: id,
			RoleID: role, NodeID: node}).Error; err != nil {
			e.t.Fatalf("節點範圍 %s：%v", username, err)
		}
		return cmpIdentity{userID: id, username: username, email: username + "@baseline.test"}
	}
	owner, twin := grant("cmp-owner-node"), grant("cmp-twin-node")
	plain, tokenID := e.apiTokenIssue(owner, "cmp-node", role)
	return &apiTokenPair{
		name:      "node",
		token:     &baselineSubject{ID: "T-node", Username: owner.username, UserID: owner.userID, Token: plain, Kind: "api_token"},
		human:     &baselineSubject{ID: "H-node", Username: twin.username, UserID: twin.userID, Token: e.issueSessionToken(twin.userID), Kind: "session"},
		tokenSelf: owner, humanSelf: twin, tokenID: tokenID, grantedRole: []uint{role},
	}
}

func apiTokenRuleCode(body map[string]any) string {
	c, _ := body["code"].(string)
	return c
}

func planAuthID(p *uint) uint {
	if p == nil {
		return 0
	}
	return *p
}

func is2xx(code int) bool { return code >= 200 && code < 300 }

// TestAPITokenServiceRules token 專屬的服務層限制與人類對照。
func TestAPITokenServiceRules(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	pairs := seedAPITokenPairs(e)
	super, scoped, protected := pairs[0], pairs[1], pairs[2]
	ag1 := e.object("assetGroup.1").(uint)
	node := e.apiTokenNodePair(ag1)
	e.apiTokenRetemplate()

	sshAsset := e.object("asset.ssh").(uint)
	outOfNodeAsset := e.object("asset.approval").(uint)
	unbound := e.object("credential.unbound").(uint)
	shared := e.object("credential.shared").(uint)
	sharedAccount := e.object("account.sshShared").(uint)
	plan := e.object("changeSecretPlan.1").(uint)
	port := e.recv.port("ssh")
	refCode := string(apierror.CodeAuthAPITokenCredentialReferenceForbidden)
	denyCode := string(apierror.CodePermissionDenied)

	assetWithCredential := func(name string, node uint) map[string]any {
		return map[string]any{"name": name, "protocol": "ssh", "host": "127.0.0.1", "port": port,
			"credential_id": unbound, "node_ids": []uint{node}}
	}
	importRows := func(withCredential bool) map[string]any {
		rows := []map[string]any{
			{"name": "cmp-import-plain", "protocol": "ssh", "host": "127.0.0.1", "port": port, "credential_id": nil, "node_ids": []uint{ag1}},
		}
		if withCredential {
			rows = append(rows, map[string]any{"name": "cmp-import-ref", "protocol": "ssh", "host": "127.0.0.1", "port": port,
				"credential_id": unbound, "node_ids": []uint{ag1}})
		}
		return map[string]any{"source": "form", "rows": rows}
	}

	// 引用既有憑證的請求：token 一律 403 且資產、帳號皆不增加；人類照常成功。
	refCases := []struct {
		name, method, path string
		body               any
	}{
		{"建立資產引用既有憑證", http.MethodPost, "/api/v1/assets", assetWithCredential("cmp-ref-asset", ag1)},
		{"建立帳號引用既有憑證", http.MethodPost, fmt.Sprintf("/api/v1/assets/%d/accounts", sshAsset),
			map[string]any{"credential_id": unbound, "note": "cmp"}},
		{"匯入預覽含引用既有憑證的列", http.MethodPost, "/api/v1/assets/import/preview", importRows(true)},
		{"匯入送出混合列（一列自帶、一列引用）", http.MethodPost, "/api/v1/assets/import", importRows(true)},
	}
	for _, c := range refCases {
		t.Run("APIToken 引用既有憑證被拒："+c.name, func(t *testing.T) {
			for _, p := range []*apiTokenPair{super, node} {
				assets, accounts := e.apiTokenCount("assets", ""), e.apiTokenCount("asset_accounts", "")
				code, body := e.apiTokenRuleCall(p.token, c.method, c.path, c.body)
				if code != http.StatusForbidden || apiTokenRuleCode(body) != refCode {
					t.Errorf("[%s] token 應回 403 %s，得到 %d %v", p.name, refCode, code, body)
				}
				if a, n := e.apiTokenCount("assets", ""), e.apiTokenCount("asset_accounts", ""); a != assets || n != accounts {
					t.Errorf("[%s] token 被拒卻有寫入：資產 %d→%d、帳號 %d→%d", p.name, assets, a, accounts, n)
				}
				e.apiTokenRuleRestore()
			}
			code, body := e.apiTokenRuleCall(super.human, c.method, c.path, c.body)
			if !is2xx(code) {
				t.Errorf("人類帳號應照常成功，得到 %d %v", code, body)
			}
			e.apiTokenRuleRestore()
			if code, body := e.apiTokenRuleCall(node.human, c.method, c.path, c.body); apiTokenRuleCode(body) == refCode {
				t.Errorf("節點範圍的人類帳號不應以 token 專屬錯誤碼被拒：%d %v", code, body)
			}
			e.apiTokenRuleRestore()
		})
	}

	t.Run("APIToken 自帶密碼的建立與匯入照常", func(t *testing.T) {
		before := e.apiTokenCount("assets", "")
		code, body := e.apiTokenRuleCall(super.token, http.MethodPost, "/api/v1/assets", map[string]any{
			"name": "cmp-self-secret", "protocol": "ssh", "host": "127.0.0.1", "port": port,
			"username": "cmp-root", "password": "Cmp-Pass-12345", "node_ids": []uint{ag1}})
		if !is2xx(code) || e.apiTokenCount("assets", "") != before+1 {
			t.Errorf("自帶密碼建立資產應成功並新增一筆，得到 %d %v", code, body)
		}
		e.apiTokenRuleRestore()
		code, body = e.apiTokenRuleCall(super.token, http.MethodPost, "/api/v1/assets/import", importRows(false))
		if !is2xx(code) || e.apiTokenCount("assets", "name = ?", "cmp-import-plain") != 1 {
			t.Errorf("不引用憑證的匯入應成功並寫入，得到 %d %v", code, body)
		}
		e.apiTokenRuleRestore()
	})

	t.Run("APIToken 卸載憑證掛載不受引用限制", func(t *testing.T) {
		path := fmt.Sprintf("/api/v1/credentials/%d/bindings/%d", shared, sharedAccount)
		code, body := e.apiTokenRuleCall(super.token, http.MethodDelete, path, nil)
		if !is2xx(code) {
			t.Errorf("token 卸載應成功，得到 %d %v", code, body)
		}
		e.apiTokenRuleRestore()
	})

	// 受保護帳號（超級管理者）的操作只依 token 授權的角色判定：所屬帳號經未授權的角色是超級管理者，token 不因此豁免。
	t.Run("APIToken 受保護帳號的操作不因所屬帳號的未授權角色豁免", func(t *testing.T) {
		target := e.subjects["S01"].UserID
		ops := []struct {
			method, path string
			body         any
		}{
			{http.MethodPut, fmt.Sprintf("/api/v1/users/%d/password", target), map[string]any{"password": "CmpProtectedSet2026pw"}},
			{http.MethodPut, fmt.Sprintf("/api/v1/users/%d/status", target), map[string]any{"active": false}},
		}
		protCode := string(apierror.CodeAuthProtectedAccountOperation)
		for _, o := range ops {
			for _, subj := range []*baselineSubject{protected.token, protected.human} {
				code, body := e.apiTokenRuleCall(subj, o.method, o.path, o.body)
				if code != http.StatusForbidden || apiTokenRuleCode(body) != protCode {
					t.Errorf("%s %s %s：應回 403 %s，得到 %d %v", subj.ID, o.method, o.path, protCode, code, body)
				}
				e.apiTokenRuleRestore()
			}
			if code, body := e.apiTokenRuleCall(super.token, o.method, o.path, o.body); !is2xx(code) {
				t.Errorf("授權超級管理者的 token %s %s 應成功，得到 %d %v", o.method, o.path, code, body)
			}
			e.apiTokenRuleRestore()
		}
	})

	// 改密計畫
	planPath := fmt.Sprintf("/api/v1/change-secret-plans/%d", plan)
	planBody := func(name, cron string, assetID uint, enabled bool) map[string]any {
		return map[string]any{"name": name, "asset_ids": []uint{assetID}, "accounts": []string{"baseline-root"},
			"cron": cron, "enabled": enabled}
	}
	var planRow model.ChangeSecretPlan
	if err := e.db.First(&planRow, plan).Error; err != nil {
		t.Fatalf("讀取計畫：%v", err)
	}
	planAuthRows := func() int64 { return e.apiTokenCount("credential_job_authorizations", "") }
	authRowsBefore := planAuthRows()
	planUnchanged := func(t *testing.T, label string) {
		t.Helper()
		var now model.ChangeSecretPlan
		if err := e.db.First(&now, plan).Error; err != nil {
			t.Fatalf("讀取計畫：%v", err)
		}
		if now.Name != planRow.Name || now.Cron != planRow.Cron || now.Enabled != planRow.Enabled ||
			now.Revision != planRow.Revision || planAuthID(now.AuthorizationID) != planAuthID(planRow.AuthorizationID) ||
			now.AuthorizationState != planRow.AuthorizationState || now.AssetIDs != planRow.AssetIDs || now.Accounts != planRow.Accounts {
			t.Errorf("%s：被拒卻改動了計畫（名稱 %q→%q、排程 %q→%q、啟用 %v→%v、修訂 %d→%d、授權狀態 %q→%q、目標 %s→%s、帳號 %s→%s）", label,
				planRow.Name, now.Name, planRow.Cron, now.Cron, planRow.Enabled, now.Enabled, planRow.Revision, now.Revision,
				planRow.AuthorizationState, now.AuthorizationState, planRow.AssetIDs, now.AssetIDs, planRow.Accounts, now.Accounts)
		}
		if n := planAuthRows(); n != authRowsBefore {
			t.Errorf("%s：被拒卻新增了授權脈絡紀錄（%d→%d）", label, authRowsBefore, n)
		}
	}
	setPlan := func(cols map[string]any) {
		if err := e.db.Model(&model.ChangeSecretPlan{}).Where("id = ?", plan).Updates(cols).Error; err != nil {
			t.Fatalf("設定計畫前置狀態：%v", err)
		}
		if err := e.db.First(&planRow, plan).Error; err != nil {
			t.Fatalf("讀取計畫：%v", err)
		}
		authRowsBefore = planAuthRows()
	}

	t.Run("APIToken 無執行能力不能建立改密計畫", func(t *testing.T) {
		before := e.apiTokenCount("change_secret_plans", "")
		code, body := e.apiTokenRuleCall(scoped.token, http.MethodPost, "/api/v1/change-secret-plans",
			planBody("cmp-plan-new", "0 3 * * *", sshAsset, false))
		if code != http.StatusForbidden || apiTokenRuleCode(body) != denyCode {
			t.Errorf("token 應回 403 %s，得到 %d %v", denyCode, code, body)
		}
		if e.apiTokenCount("change_secret_plans", "") != before {
			t.Error("token 被拒卻新增了計畫")
		}
		e.apiTokenRuleRestore()
		code, body = e.apiTokenRuleCall(scoped.human, http.MethodPost, "/api/v1/change-secret-plans",
			planBody("cmp-plan-new", "0 3 * * *", sshAsset, false))
		if !is2xx(code) {
			t.Errorf("人類帳號應照常建立，得到 %d %v", code, body)
		}
		e.apiTokenRuleRestore()
	})

	planUpdates := []struct {
		name  string
		setup map[string]any
		body  map[string]any
	}{
		{"已啟用、尚無排程的計畫只補排程", map[string]any{"enabled": true, "cron": ""},
			planBody("baseline-plan-1", "0 4 * * *", sshAsset, true)},
		{"暫停待承接的計畫只改名稱", map[string]any{"authorization_state": model.PlanAuthNeedsReauthorization},
			planBody("cmp-plan-renamed", "", sshAsset, false)},
		{"只改目標", nil, planBody("baseline-plan-1", "", e.object("asset.rdp").(uint), false)},
		{"啟用計畫", nil, planBody("baseline-plan-1", "", sshAsset, true)},
	}
	for _, c := range planUpdates {
		t.Run("APIToken 無執行能力不能保存改密計畫："+c.name, func(t *testing.T) {
			if c.setup != nil {
				setPlan(c.setup)
			}
			code, body := e.apiTokenRuleCall(scoped.token, http.MethodPut, planPath, c.body)
			if code != http.StatusForbidden || apiTokenRuleCode(body) != denyCode {
				t.Errorf("token 應回 403 %s，得到 %d %v", denyCode, code, body)
			}
			planUnchanged(t, "token")
			e.apiTokenRuleRestore()
			if c.setup != nil {
				setPlan(c.setup)
			}
			code, body = e.apiTokenRuleCall(scoped.human, http.MethodPut, planPath, c.body)
			if !is2xx(code) {
				t.Errorf("人類帳號應照常保存，得到 %d %v", code, body)
			}
			e.apiTokenRuleRestore()
			if err := e.db.First(&planRow, plan).Error; err != nil {
				t.Fatalf("讀取計畫：%v", err)
			}
		})
	}

	t.Run("APIToken 無執行能力不承接暫停中的計畫", func(t *testing.T) {
		setPlan(map[string]any{"authorization_state": model.PlanAuthNeedsReauthorization})
		code, body := e.apiTokenRuleCall(scoped.token, http.MethodPost, "/api/v1/change-secret-plans/reauthorize", nil)
		if !is2xx(code) || fmt.Sprint(body["count"]) != "0" {
			t.Errorf("token 不應承接任何計畫，得到 %d %v", code, body)
		}
		planUnchanged(t, "token 承接")
		e.apiTokenRuleRestore()
		setPlan(map[string]any{"authorization_state": model.PlanAuthNeedsReauthorization})
		code, body = e.apiTokenRuleCall(super.token, http.MethodPost, "/api/v1/change-secret-plans/reauthorize", nil)
		if !is2xx(code) || fmt.Sprint(body["count"]) != "1" {
			t.Errorf("持有執行能力的 token 應承接一筆，得到 %d %v", code, body)
		}
		e.apiTokenRuleRestore()
		if err := e.db.First(&planRow, plan).Error; err != nil {
			t.Fatalf("讀取計畫：%v", err)
		}
	})

	// 範圍外目標在計畫頁的可見範圍即被擋下（執行範圍那一層由 TestAPITokenPlanRunScopeRecheckedForVisibleTarget 單獨驗證）
	t.Run("APIToken 持有執行能力可建立與保存，目標在可見範圍外則拒絕", func(t *testing.T) {
		for _, p := range []*apiTokenPair{super, node} {
			code, body := e.apiTokenRuleCall(p.token, http.MethodPost, "/api/v1/change-secret-plans",
				planBody("cmp-plan-ok", "0 3 * * *", sshAsset, false))
			if !is2xx(code) {
				t.Errorf("[%s] 持有執行能力的 token 應能建立，得到 %d %v", p.name, code, body)
			}
			e.apiTokenRuleRestore()
		}
		code, body := e.apiTokenRuleCall(super.token, http.MethodPut, planPath, planBody("cmp-plan-ok", "0 5 * * *", sshAsset, true))
		if !is2xx(code) {
			t.Errorf("持有執行能力的 token 應能保存，得到 %d %v", code, body)
		}
		e.apiTokenRuleRestore()
		before := e.apiTokenCount("change_secret_plans", "")
		code, body = e.apiTokenRuleCall(node.token, http.MethodPost, "/api/v1/change-secret-plans",
			planBody("cmp-plan-out", "0 3 * * *", outOfNodeAsset, false))
		if code != http.StatusNotFound || apiTokenRuleCode(body) != string(apierror.CodeBatchItemsUnavailable) ||
			e.apiTokenCount("change_secret_plans", "") != before {
			t.Errorf("目標在 token 可見範圍外應以 404 %s 拒絕且不寫入，得到 %d %v", apierror.CodeBatchItemsUnavailable, code, body)
		}
		e.apiTokenRuleRestore()
	})
}
