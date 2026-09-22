package apierror

import "testing"

func TestCompletenessAgentSelfServicePublic(t *testing.T) {
	for _, code := range []ErrCode{CodeRuleAgentSelfCreateDisabled, CodeRuleAgentSelfCreateLimit} {
		d, ok := DescriptorOf(code)
		if !ok || d.AuditOnly {
			t.Fatal("not public", code)
		}
	}
}
