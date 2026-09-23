package policy

import (
	"testing"
)

func TestSensitiveRevealPolicyDefaultAndValidation(t *testing.T) {
	svc, _ := setupPolicyDB(t)
	if svc.GetBool(PolicyAlertOnSensitiveReveal) {
		t.Fatal("must default off")
	}
	def := FindPolicyDef(PolicyAlertOnSensitiveReveal)
	if def == nil || def.Type != PolicyTypeBool || def.Default != "false" {
		t.Fatalf("definition=%+v", def)
	}
	if _, err := svc.Update(PolicyAlertOnSensitiveReveal, "invalid", "admin"); err == nil {
		t.Fatal("accepted non-boolean")
	}
	if _, err := svc.Update(PolicyAlertOnSensitiveReveal, "true", "admin"); err != nil {
		t.Fatal(err)
	}
	if !svc.GetBool(PolicyAlertOnSensitiveReveal) {
		t.Fatal("update did not invalidate cache")
	}
	if controls := builtinSeedRequirements(t, PolicyAlertOnSensitiveReveal); len(controls) != 0 {
		t.Fatalf("optional signal entered compliance requirements: %v", controls)
	}
}
