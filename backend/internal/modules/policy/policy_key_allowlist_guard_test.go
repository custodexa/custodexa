package policy

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
)

// TestPolicyKeyAllowlistCoversDefs 政策鍵允許清單與政策表雙向相等。
//
// VALIDATION_POLICY_INVALID_VALUE 以 ParamEnum 承接 {key}，允許清單必須放在
// apierror（service import apierror，反向會成環），因此清單是政策表的複本。
// 複本會漂移：新增政策鍵而漏補清單 → 該鍵觸發的錯誤在執行期驗證失敗 →
// params 整組丟棄 → 訊息退化成「安全政策值不合法：」（線上才看得到）。
// 本測試把那個執行期退化提前成編譯後即紅。
//
// 雙向：缺鍵＝漏補；多鍵＝政策已刪而清單殘留（stale 條目會赦免不存在的鍵）。
func TestPolicyKeyAllowlistCoversDefs(t *testing.T) {
	d, ok := apierror.DescriptorOf(apierror.CodePolicyInvalidValue)
	if !ok {
		t.Fatal("VALIDATION_POLICY_INVALID_VALUE 未註冊")
	}
	var allowed map[string]string
	for _, p := range d.Params {
		if p.Key == "key" {
			if p.Kind != apierror.ParamEnum {
				t.Fatalf("{key} 的 kind = %v, want ParamEnum（允許清單是本守衛的前提）", p.Kind)
			}
			allowed = p.ZhLabels
		}
	}
	if allowed == nil {
		t.Fatal("VALIDATION_POLICY_INVALID_VALUE 缺 {key} ParamSpec")
	}

	defined := map[string]bool{}
	for _, def := range policyDefs {
		defined[def.Key] = true
		if _, ok := allowed[def.Key]; !ok {
			t.Errorf("政策鍵 %q 不在 apierror.policyKeyZhLabels 內（新增政策鍵時須同步補入）", def.Key)
		}
	}
	for key := range allowed {
		if !defined[key] {
			t.Errorf("apierror.policyKeyZhLabels 有殘留鍵 %q（policyDefs 已無此鍵）", key)
		}
	}
}

// TestPolicyTypedErrorsCarryKey 兩個 typed error 帶得出鍵名，且仍可被
// errors.Is 以 sentinel 比對（handler 的 errors.As 映射與既有分支同時成立）。
func TestPolicyTypedErrorsCarryKey(t *testing.T) {
	svc, _ := setupPolicyDB(t)

	var unknown *PolicyUnknownKeyError
	_, err := svc.Update("nonexistent_key", "1", "admin")
	if !errors.As(err, &unknown) {
		t.Fatalf("未知鍵 = %v, want *PolicyUnknownKeyError", err)
	}
	if unknown.Key != "nonexistent_key" {
		t.Errorf("Key = %q, want nonexistent_key", unknown.Key)
	}

	var invalid *PolicyInvalidValueError
	_, err = svc.Update(PolicyLockoutMaxAttempts, "abc", "admin")
	if !errors.As(err, &invalid) {
		t.Fatalf("非法值 = %v, want *PolicyInvalidValueError", err)
	}
	if invalid.Key != PolicyLockoutMaxAttempts {
		t.Errorf("Key = %q, want %s", invalid.Key, PolicyLockoutMaxAttempts)
	}
	if invalid.Reason == "" {
		t.Error("Reason 為空（伺服器端日誌會失去原因）")
	}
}
