package policy

import "testing"

func TestPolicyDefsAgentSelfService(t *testing.T) {
	s, db := setupPolicyDB(t)
	if s.GetBool(PolicyAgentSelfCreateEnabled) || s.GetInt(PolicyAgentSelfCreateMaxPerOwner) != 3 {
		t.Fatal("factory defaults")
	}
	for _, bad := range []string{"0", "101"} {
		if _, err := s.UpdateBatch(map[string]string{PolicyAgentSelfCreateEnabled: "true", PolicyAgentSelfCreateMaxPerOwner: bad}, "admin"); err == nil {
			t.Fatal("accepted", bad)
		}
		if s.GetBool(PolicyAgentSelfCreateEnabled) || s.GetInt(PolicyAgentSelfCreateMaxPerOwner) != 3 {
			t.Fatal("partial update")
		}
	}
	for _, good := range []string{"1", "100"} {
		if _, err := s.Update(PolicyAgentSelfCreateMaxPerOwner, good, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	enabled, limit, err := AgentSelfCreationInTx(db)
	if err != nil || enabled || limit != 100 {
		t.Fatal(enabled, limit, err)
	}
	for _, key := range []string{PolicyAgentSelfCreateEnabled, PolicyAgentSelfCreateMaxPerOwner} {
		if findDef(key).Direction != "" || findDef(key).Min != 0 {
			t.Fatal("unexpected baseline/min", key)
		}
	}
}
func TestComplianceVerdictAgentSelfService(t *testing.T) {
	_, cs := newSeededComplianceStack(t)
	for _, group := range builtinPolicyGroupSeeds() {
		snap, err := cs.Snapshot(group.Code, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{PolicyAgentSelfCreateEnabled, PolicyAgentSelfCreateMaxPerOwner} {
			for _, v := range snap.VerdictsForKey(key) {
				if v.GroupCode != "" || v.Result != "unmapped" {
					t.Fatalf("%s %s: %+v", group.Code, key, v)
				}
			}
		}
	}
}
