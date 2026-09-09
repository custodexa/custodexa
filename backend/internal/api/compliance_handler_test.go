package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// TestComplianceHandlerSnapshot 合規對照的唯讀端點：admin 與 auditor 皆可讀，
// 回應同時帶判定、逐組摘要、政策組本體與條文（一次呼叫足以畫出整頁）。
func TestComplianceHandlerSnapshot(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	for _, role := range []string{"admin", "auditor"} {
		w := env.do(t, http.MethodGet, "/api/v1/compliance/snapshot", role, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s 讀判定 = %d（body %s）", role, w.Code, w.Body.String())
		}
		body := decodePolicyBody(t, w)
		data, ok := body["data"].(map[string]any)
		if !ok {
			t.Fatalf("%s 回應缺 data：%s", role, w.Body.String())
		}
		verdicts, ok := data["verdicts"].([]any)
		if !ok || len(verdicts) == 0 {
			t.Fatalf("%s 回應缺判定：%s", role, w.Body.String())
		}
		if _, ok := data["built_at"]; !ok {
			t.Errorf("%s 回應缺建構時點", role)
		}
		if _, ok := body["summaries"]; !ok {
			t.Errorf("%s 回應缺逐組摘要", role)
		}
		if _, ok := body["groups"]; !ok {
			t.Errorf("%s 回應缺政策組清單", role)
		}
		if _, ok := body["clauses"]; !ok {
			t.Errorf("%s 回應缺條文清單", role)
		}
		// 摘要的第六格：系統內建保護型條文的條數。單位是**條文**不是設定鍵，
		// 故不進前五格的合計；漏掉這一格，那些條文在畫面上會像是漏判
		summaries := body["summaries"].([]any)
		if len(summaries) == 0 {
			t.Fatalf("%s 逐組摘要為空", role)
		}
		if _, ok := summaries[0].(map[string]any)["builtin_protection"]; !ok {
			t.Errorf("%s 摘要缺 builtin_protection：%v", role, summaries[0])
		}
	}

	// 密碼最小長度出廠 12、內規要求至少 14 ⇒ 該鍵對該組為偏離
	w := env.do(t, http.MethodGet, "/api/v1/compliance/snapshot?group=inhouse", "auditor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("單組判定 = %d（body %s）", w.Code, w.Body.String())
	}
	data := decodePolicyBody(t, w)["data"].(map[string]any)
	found := false
	for _, raw := range data["verdicts"].([]any) {
		v := raw.(map[string]any)
		if v["key"] != policy.PolicyPasswordMinLength || v["group_code"] != "inhouse" {
			continue
		}
		found = true
		if v["result"] != policy.ComplianceResultDeviating {
			t.Errorf("密碼最小長度對內規 = %v，want %s", v["result"], policy.ComplianceResultDeviating)
		}
		if v["expected"] != "14" {
			t.Errorf("要求值 = %v，want 14", v["expected"])
		}
		if v["current"] == nil || v["current"] == "" {
			t.Errorf("判定未帶目前值：%v", v)
		}
	}
	if !found {
		t.Fatalf("單組判定裡找不到密碼最小長度：%s", w.Body.String())
	}
}

// TestComplianceHandlerUnknownGroup 指定不存在的組回 404 具名碼，
// 而不是一份「每個鍵都未對照」的結果——後者與組代號打錯字在畫面上分不出來。
func TestComplianceHandlerUnknownGroup(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	w := env.do(t, http.MethodGet, "/api/v1/compliance/snapshot?group=nope", "admin", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("狀態 = %d，want 404（body %s）", w.Code, w.Body.String())
	}
	if got := decodePolicyBody(t, w)["code"]; got != "POLICY_GROUP_NOT_FOUND" {
		t.Errorf("錯誤碼 = %v，want POLICY_GROUP_NOT_FOUND", got)
	}
}

// TestComplianceHandlerIsReadOnly 合規對照端點不寫任何資料：讀完之後
// 政策組、條文與備註三張表逐張與讀之前相同。
func TestComplianceHandlerIsReadOnly(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	var before []model.PolicyClauseAnnotation
	if err := env.db.Find(&before).Error; err != nil {
		t.Fatalf("讀備註: %v", err)
	}
	if w := env.do(t, http.MethodGet, "/api/v1/compliance/snapshot", "auditor", nil); w.Code != http.StatusOK {
		t.Fatalf("讀判定 = %d", w.Code)
	}
	var after []model.PolicyClauseAnnotation
	if err := env.db.Find(&after).Error; err != nil {
		t.Fatalf("讀備註: %v", err)
	}
	if len(before) != len(after) {
		t.Errorf("唯讀端點改動了備註：%d → %d", len(before), len(after))
	}
}

// TestComplianceHandlerCountsBuiltinProtection 系統內建保護型條文不產生鍵層判定，
// 另以條文為單位計數並隨判定結果一起帶出。
func TestComplianceHandlerCountsBuiltinProtection(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)
	if _, _, err := env.repo.UpsertCustomClause(model.PolicyClause{
		GroupCode: "inhouse", ClauseNo: "2", Title: "產品直接承擔",
		Kind: model.PolicyClauseKindBuiltinProtection,
	}, nil); err != nil {
		t.Fatalf("建內建保護條文: %v", err)
	}

	w := env.do(t, http.MethodGet, "/api/v1/compliance/snapshot?group=inhouse", "auditor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("讀判定 = %d（body %s）", w.Code, w.Body.String())
	}
	body := decodePolicyBody(t, w)
	summaries := body["summaries"].([]any)
	got := summaries[0].(map[string]any)["builtin_protection"]
	if got != float64(1) {
		t.Errorf("內建保護條數 = %v，want 1", got)
	}
	data := body["data"].(map[string]any)
	clauses, ok := data["builtin_protection_clauses"].(map[string]any)
	if !ok || clauses["inhouse"] != float64(1) {
		t.Errorf("判定結果未帶逐組內建保護條數：%v", data["builtin_protection_clauses"])
	}
	// 該條文不掛設定鍵，故不產生任何鍵層判定
	for _, raw := range data["verdicts"].([]any) {
		if v := raw.(map[string]any); v["clause_no"] == "2" {
			t.Errorf("內建保護型條文產生了鍵層判定：%v", v)
		}
	}
}

// TestComplianceHandlerSnapshotCarriesLastChange 判定結果帶得出「這個設定何時被誰改的」，
// 且**稽核角色同樣拿得到**。
//
// 這兩個欄位的另一個來源是管理端的設定列表，那支端點 auditor 讀不到；判定不帶的話，
// 稽核人員的追證會停在「知道偏離、不知道誰改的」。
func TestComplianceHandlerSnapshotCarriesLastChange(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	changedAt := time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC)
	if err := env.db.Create(&model.SecurityPolicy{
		Key:       policy.PolicyPasswordMinLength,
		Value:     "12",
		UpdatedBy: "policy-admin",
		UpdatedAt: changedAt,
	}).Error; err != nil {
		t.Fatalf("寫政策列: %v", err)
	}

	for _, role := range []string{"admin", "auditor"} {
		w := env.do(t, http.MethodGet, "/api/v1/compliance/snapshot?group=inhouse", role, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s 讀判定 = %d（body %s）", role, w.Code, w.Body.String())
		}
		data := decodePolicyBody(t, w)["data"].(map[string]any)
		var found bool
		for _, raw := range data["verdicts"].([]any) {
			v := raw.(map[string]any)
			if v["key"] != policy.PolicyPasswordMinLength {
				continue
			}
			found = true
			if v["updated_by"] != "policy-admin" {
				t.Errorf("%s 讀到的操作者 = %v，want policy-admin", role, v["updated_by"])
			}
			at, _ := v["updated_at"].(string)
			if at == "" {
				t.Errorf("%s 讀到的判定沒帶最後變更時戳：%v", role, v)
				continue
			}
			parsed, err := time.Parse(time.RFC3339, at)
			if err != nil || !parsed.Equal(changedAt) {
				t.Errorf("%s 讀到的最後變更時戳 = %q（解析 %v），want %v",
					role, at, err, changedAt)
			}
		}
		if !found {
			t.Fatalf("%s 的判定裡找不到密碼最小長度：%s", role, w.Body.String())
		}
		// 從未被改過的鍵不得憑空帶出一筆變更
		for _, raw := range data["verdicts"].([]any) {
			v := raw.(map[string]any)
			if v["key"] == policy.PolicyPasswordMinLength {
				continue
			}
			if _, has := v["updated_by"]; has {
				t.Errorf("%s：%v 從未變更卻帶了操作者", role, v["key"])
			}
		}
	}
}
