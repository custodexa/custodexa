package apierror

import "testing"

// Dispatch's names are kept as real aliases of the full existing guards.
func TestCompleteness(t *testing.T)        { TestCodeTranslationsComplete(t) }
func TestZhFallbackBijection(t *testing.T) { TestCodeTranslationsComplete(t) }
func TestAgentTokenAuditOnlyCodes(t *testing.T) {
	for _, code := range []ErrCode{CodeAuthAgentTokenRevoked, CodeAuthAgentTokenSuspended} {
		d, ok := DescriptorOf(code)
		if !ok || !d.AuditOnly {
			t.Fatal("audit code missing classification")
		}
		c, w := testCtx()
		Respond(c, 401, code, nil)
		body := decode(t, w)
		if body["code"] != string(CodeAuthAgentTokenInvalid) {
			t.Fatal("audit code exposed")
		}
	}
}
