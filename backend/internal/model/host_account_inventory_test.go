package model

import "testing"

func TestHostAccountInventoryConstants(t *testing.T) {
	if got := len(InventoryFailureReasons); got != 16 {
		t.Fatalf("結束原因碼 = %d, want 16", got)
	}
	seen := map[string]bool{}
	for _, c := range InventoryFailureReasons {
		if seen[c] {
			t.Fatalf("結束原因碼重複：%s", c)
		}
		seen[c] = true
		if len(c) > 48 {
			t.Fatalf("結束原因碼 %s 超過 failure_reason 欄寬 48", c)
		}
	}
	if got := len(PrivilegeReasonKinds); got != 8 {
		t.Fatalf("理由碼種類 = %d, want 8", got)
	}
	if n := len(AuditResourceHostAccountFinding); n > 20 {
		t.Fatalf("審計 resource %q 長度 %d 超過 20", AuditResourceHostAccountFinding, n)
	}
	if n := len(AuditResourceHostAccountScan); n > 20 {
		t.Fatalf("審計 resource %q 長度 %d 超過 20", AuditResourceHostAccountScan, n)
	}
}
