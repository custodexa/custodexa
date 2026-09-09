package api

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 安全政策端點的判定投影與條文表單支援面。
//
// 設定頁的分區偏離數與抽屜逐組要求都由政策列表的 `verdicts` 供給，套用預覽與
// 草稿回饋各有一支端點。三者共用同一份判定建構——設定頁自己算一份判定是本波
// 要消滅的第二份對照。

// TestSecurityPolicyHandlerListCarriesVerdicts 列表每一項附對各生效組的判定；
// 頂層另附生效組清單供頁首呈現。
func TestSecurityPolicyHandlerListCarriesVerdicts(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	w := env.do(t, http.MethodGet, "/api/v1/security-policies", "admin", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("讀列表 = %d（body %s）", w.Code, w.Body.String())
	}
	body := decodePolicyBody(t, w)
	items, ok := body["data"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("列表 data 形狀不對：%s", w.Body.String())
	}
	groups, ok := body["groups"].([]any)
	if !ok || len(groups) != 1 {
		t.Fatalf("頂層生效組清單 = %v，want 一組", body["groups"])
	}
	if got := groups[0].(map[string]any)["name"]; got != "內規" {
		t.Errorf("生效組名稱 = %v，want 內規", got)
	}

	var target map[string]any
	for _, raw := range items {
		item := raw.(map[string]any)
		if item["key"] == policy.PolicyPasswordMinLength {
			target = item
		}
		if _, ok := item["verdicts"]; !ok {
			t.Fatalf("政策項 %v 缺 verdicts", item["key"])
		}
	}
	if target == nil {
		t.Fatalf("列表裡找不到密碼最小長度")
	}
	// **欄位集合逐字釘住**：判定是唯一的符合性來源，政策項與回應頂層都不得
	// 再帶第二份自算的符合性或建議值——同一個鍵在兩條路徑上給出不同答案，
	// 而畫面上不會有任何一處報錯
	assertFieldSet(t, "政策項", target, "key", "type", "default", "direction", "max",
		"label", "unit", "unit_key", "value", "verdicts")
	assertFieldSet(t, "列表回應頂層", body, "data", "groups")
	verdicts := target["verdicts"].([]any)
	if len(verdicts) != 1 {
		t.Fatalf("密碼最小長度的判定數 = %d，want 1", len(verdicts))
	}
	v := verdicts[0].(map[string]any)
	if v["group_code"] != "inhouse" || v["result"] != policy.ComplianceResultDeviating {
		t.Errorf("判定 = %v，want 內規偏離", v)
	}
}

// TestSecurityPolicyHandlerCompliancePreviewUsesDraft 草稿覆蓋現值後重算，
// 結果標為草稿且不寫入任何東西。
func TestSecurityPolicyHandlerCompliancePreviewUsesDraft(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	w := env.do(t, http.MethodPost, "/api/v1/security-policies/compliance/preview", "admin",
		map[string]any{"draft": map[string]string{policy.PolicyPasswordMinLength: "16"}})
	if w.Code != http.StatusOK {
		t.Fatalf("草稿預覽 = %d（body %s）", w.Code, w.Body.String())
	}
	data := decodePolicyBody(t, w)["data"].(map[string]any)
	if data["draft"] != true {
		t.Errorf("草稿旗標 = %v，want true", data["draft"])
	}
	for _, raw := range data["verdicts"].([]any) {
		v := raw.(map[string]any)
		if v["key"] != policy.PolicyPasswordMinLength || v["group_code"] != "inhouse" {
			continue
		}
		if v["result"] != policy.ComplianceResultCompliant {
			t.Errorf("草稿 16 對要求至少 14 = %v，want 符合", v["result"])
		}
		if v["current"] != "16" {
			t.Errorf("草稿判定的目前值 = %v，want 16", v["current"])
		}
	}
	// 草稿不落庫：儲存值仍是出廠預設
	if got := env.service.Get(policy.PolicyPasswordMinLength); got == "16" {
		t.Errorf("草稿預覽把值寫進去了：%q", got)
	}
}

// TestSecurityPolicyHandlerCompliancePreviewUsesTempControls 尚未儲存的條文要求
// 由後端判定，只影響本次回應。
//
// 反例：條文編輯器自己算一份符合性。那一份與伺服器的判定會漂移，而分歧不會有
// 任何一處報錯——畫面預告「儲存後符合」，儲存出來卻是偏離。
func TestSecurityPolicyHandlerCompliancePreviewUsesTempControls(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t) // inhouse 條文 1：密碼最小長度至少 14

	// 覆蓋既有要求：同組同鍵改成至少 20，出廠的 12 應由符合翻成偏離
	w := env.do(t, http.MethodPost, "/api/v1/security-policies/compliance/preview", "admin",
		map[string]any{"temp_controls": []map[string]any{{
			"group_code": "inhouse", "clause_no": "1",
			"policy_key": policy.PolicyPasswordMinLength,
			"comparator": "min", "expected_value": "20",
		}}})
	if w.Code != http.StatusOK {
		t.Fatalf("一次性要求預覽 = %d（body %s）", w.Code, w.Body.String())
	}
	data := decodePolicyBody(t, w)["data"].(map[string]any)
	if data["draft"] != true {
		t.Errorf("尚未儲存的要求算出的結果必須標為草稿，got %v", data["draft"])
	}
	seen := 0
	for _, raw := range data["verdicts"].([]any) {
		v := raw.(map[string]any)
		if v["key"] != policy.PolicyPasswordMinLength || v["group_code"] != "inhouse" {
			continue
		}
		seen++
		if v["expected"] != "20" {
			t.Errorf("要求值 = %v，want 20（同組同鍵應被覆蓋而非新增一條）", v["expected"])
		}
		if v["result"] != policy.ComplianceResultDeviating {
			t.Errorf("現值 12 對要求至少 20 = %v，want 偏離", v["result"])
		}
	}
	if seen != 1 {
		t.Errorf("該鍵對該組的判定列數 = %d，want 1", seen)
	}

	// 尚未存在的條文也判得出來（編輯器正在新增一條）
	w = env.do(t, http.MethodPost, "/api/v1/security-policies/compliance/preview", "admin",
		map[string]any{"temp_controls": []map[string]any{{
			"group_code": "inhouse", "clause_no": "99",
			"policy_key": policy.PolicyPasswordMinLength,
			"comparator": "min", "expected_value": "8",
		}}})
	if w.Code != http.StatusOK {
		t.Fatalf("新條文預覽 = %d（body %s）", w.Code, w.Body.String())
	}
	for _, raw := range decodePolicyBody(t, w)["data"].(map[string]any)["verdicts"].([]any) {
		v := raw.(map[string]any)
		if v["key"] != policy.PolicyPasswordMinLength || v["group_code"] != "inhouse" {
			continue
		}
		if v["clause_no"] != "99" || v["result"] != policy.ComplianceResultCompliant {
			t.Errorf("新條文的判定 = %v，want 條號 99 且符合", v)
		}
	}

	// 驗證沿寫入端：值域不合的要求回具名碼，不是一份看起來正常的判定
	w = env.do(t, http.MethodPost, "/api/v1/security-policies/compliance/preview", "admin",
		map[string]any{"temp_controls": []map[string]any{{
			"group_code": "inhouse", "clause_no": "1",
			"policy_key": policy.PolicyPasswordMinLength,
			"comparator": "min", "expected_value": "not-a-number",
		}}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("不合法要求值 = %d，want 400（body %s）", w.Code, w.Body.String())
	}
	if got := decodePolicyBody(t, w)["code"]; got != "VALIDATION_POLICY_GROUP_EXPECTED_VALUE" {
		t.Errorf("錯誤碼 = %v", got)
	}

	// 未知組代號回找不到（與「這一組沒有任何要求」分得出來）
	w = env.do(t, http.MethodPost, "/api/v1/security-policies/compliance/preview", "admin",
		map[string]any{"temp_controls": []map[string]any{{
			"group_code": "nope", "clause_no": "1",
			"policy_key": policy.PolicyPasswordMinLength,
			"comparator": "min", "expected_value": "14",
		}}})
	if w.Code != http.StatusNotFound {
		t.Fatalf("未知組 = %d，want 404（body %s）", w.Code, w.Body.String())
	}
	if got := decodePolicyBody(t, w)["code"]; got != "POLICY_GROUP_NOT_FOUND" {
		t.Errorf("錯誤碼 = %v，want POLICY_GROUP_NOT_FOUND", got)
	}

	// 一次性要求不落庫
	var controls []model.PolicyClauseControl
	if err := env.db.Find(&controls).Error; err != nil {
		t.Fatalf("讀要求: %v", err)
	}
	if len(controls) != 1 || controls[0].ExpectedValue != "14" {
		t.Errorf("一次性要求被寫進資料庫了：%+v", controls)
	}
}

// TestSecurityPolicyHandlerApplyPreview 套用預覽只算不寫，且回聲帶回套用方式。
func TestSecurityPolicyHandlerApplyPreview(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	w := env.do(t, http.MethodPost, "/api/v1/security-policies/apply-preview", "admin",
		map[string]any{
			"scope": []string{policy.PolicyPasswordMinLength},
			"mode":  policy.ApplyModeStrictest,
		})
	if w.Code != http.StatusOK {
		t.Fatalf("套用預覽 = %d（body %s）", w.Code, w.Body.String())
	}
	data := decodePolicyBody(t, w)["data"].(map[string]any)
	if data["mode"] != policy.ApplyModeStrictest {
		t.Errorf("回聲的套用方式 = %v", data["mode"])
	}
	changes, ok := data["changes"].([]any)
	if !ok || len(changes) != 1 {
		t.Fatalf("預覽變更 = %v，want 一列", data["changes"])
	}
	change := changes[0].(map[string]any)
	if change["key"] != policy.PolicyPasswordMinLength || change["proposed"] != "14" {
		t.Errorf("預覽變更 = %v，want 密碼最小長度改成 14", change)
	}
	if got := env.service.Get(policy.PolicyPasswordMinLength); got == "14" {
		t.Errorf("預覽把值寫進去了：%q", got)
	}

	// 未知模式回具名碼（前端據以區分「參數打錯」與「伺服器壞了」）
	w = env.do(t, http.MethodPost, "/api/v1/security-policies/apply-preview", "admin",
		map[string]any{"scope": []string{policy.PolicyPasswordMinLength}, "mode": "whatever"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未知模式 = %d，want 400（body %s）", w.Code, w.Body.String())
	}
	if got := decodePolicyBody(t, w)["code"]; got != "VALIDATION_APPLY_PREVIEW_MODE" {
		t.Errorf("錯誤碼 = %v，want VALIDATION_APPLY_PREVIEW_MODE", got)
	}
}

// TestSecurityPolicyHandlerDefLookup 條文表單選鍵後取得型別、比較方式候選、
// 單位、值域與現值；未知鍵回具名碼。
func TestSecurityPolicyHandlerDefLookup(t *testing.T) {
	env := newPolicyTestEnv(t)

	w := env.do(t, http.MethodGet, "/api/v1/security-policies/defs/"+policy.PolicyPasswordMinLength,
		"admin", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("取設定定義 = %d（body %s）", w.Code, w.Body.String())
	}
	data := decodePolicyBody(t, w)["data"].(map[string]any)
	if data["type"] != policy.PolicyTypeInt {
		t.Errorf("型別 = %v，want %s", data["type"], policy.PolicyTypeInt)
	}
	comparators, ok := data["comparators"].([]any)
	if !ok || len(comparators) != 3 {
		t.Fatalf("整數型的比較方式候選 = %v，want 至少／至多／不定值三項", data["comparators"])
	}
	if data["value"] == nil || data["value"] == "" {
		t.Errorf("未回現值：%v", data)
	}
	if _, ok := data["max"]; !ok {
		t.Errorf("未回值域上界：%v", data)
	}

	// 枚舉型：候選只有明確值與不定值，且回枚舉序供表單列出可選值
	w = env.do(t, http.MethodGet, "/api/v1/security-policies/defs/"+policy.PolicyMFARequired, "admin", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("取枚舉設定定義 = %d（body %s）", w.Code, w.Body.String())
	}
	data = decodePolicyBody(t, w)["data"].(map[string]any)
	if got := data["comparators"].([]any); len(got) != 2 {
		t.Errorf("枚舉型的比較方式候選 = %v，want 兩項", got)
	}
	if order, ok := data["enum_order"].([]any); !ok || len(order) == 0 {
		t.Errorf("枚舉型未回可選值：%v", data)
	}

	w = env.do(t, http.MethodGet, "/api/v1/security-policies/defs/no_such_key", "admin", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("未知鍵 = %d，want 404（body %s）", w.Code, w.Body.String())
	}
	if got := decodePolicyBody(t, w)["code"]; got != "VALIDATION_POLICY_GROUP_UNKNOWN_KEY" {
		t.Errorf("錯誤碼 = %v，want VALIDATION_POLICY_GROUP_UNKNOWN_KEY", got)
	}
}

// assertFieldSet 一個 JSON 物件的欄位集合恰為 want（多一個少一個都紅）。
func assertFieldSet(t *testing.T, label string, got map[string]any, want ...string) {
	t.Helper()
	allowed := make(map[string]bool, len(want))
	for _, f := range want {
		allowed[f] = true
		if _, ok := got[f]; !ok {
			t.Errorf("%s 缺欄位 %s", label, f)
		}
	}
	for f := range got {
		if !allowed[f] {
			t.Errorf("%s 多出欄位 %s", label, f)
		}
	}
}
