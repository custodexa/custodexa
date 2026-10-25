package main

import (
	"path/filepath"
	"testing"
)

// The approved refusal for revoked monitor and share-link subscriptions must
// pin the new value (403 plus the revoked-access error), and must fail when
// only one of the two covered routes carries it.
func TestAuthzBaselineAD11PinsValueAndBothRoutes(t *testing.T) {
	all, err := loadApprovedDiffs(filepath.Join(authzBaselineDir, "approved-diffs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ad11 approvedEntry
	for _, e := range all.Entries {
		if e.ID == "AD-11" {
			ad11 = e
		}
	}
	if ad11.ID == "" || ad11.Expect == nil || !ad11.RequireAllKeys {
		t.Fatalf("AD-11 must carry expect and require_all_keys: %+v", ad11)
	}
	ad := approvedDiffs{Entries: []approvedEntry{ad11}}

	const monitor = "R/S10/GET /api/v1/sessions/:id/monitor"
	const share = "R/S10/GET /api/v1/sessions/share/:code/ws"
	revoked := map[string]any{"code": "AUTH_MONITOR_REVOKED", "keys": []any{"code", "error"},
		"message": "監看連線已因憑證撤銷而中止，請重新登入"}
	oldRec := func(id string) map[string]any { return map[string]any{"id": id, "status": float64(200)} }
	refused := func(id string) map[string]any {
		return map[string]any{"id": id, "status": float64(403), "error": revoked}
	}
	golden := map[string]map[string]any{monitor: oldRec(monitor), share: oldRec(share)}
	fresh := func(m, s map[string]any) map[string]map[string]any {
		return map[string]map[string]any{monitor: m, share: s}
	}

	t.Run("both_refused_passes", func(t *testing.T) {
		res := compareRecords(golden, fresh(refused(monitor), refused(share)), ad)
		if res.failed() {
			t.Fatalf("both routes refused with the approved value must pass: %s", res.summary(5))
		}
	})
	t.Run("generic_500_fails", func(t *testing.T) {
		bad := map[string]any{"id": monitor, "status": float64(500),
			"error": map[string]any{"code": "INTERNAL", "keys": []any{"code", "error"}, "message": "x"}}
		res := compareRecords(golden, fresh(bad, refused(share)), ad)
		if !res.failed() {
			t.Fatal("a 500 generic error on one route must not be approved")
		}
		found := false
		for _, d := range res.Diffs {
			if d.ID == monitor && d.Verdict == "expect-mismatch" {
				found = true
			}
		}
		if !found {
			t.Fatalf("want expect-mismatch on the monitor route: %s", res.summary(10))
		}
	})
	t.Run("one_route_back_to_old_fails", func(t *testing.T) {
		res := compareRecords(golden, fresh(oldRec(monitor), refused(share)), ad)
		if !res.failed() || len(res.PartialActive) != 1 {
			t.Fatalf("a route returning to its old value must fail as partial: %+v", res)
		}
		// Control: without the option the same input passes (default unchanged).
		loose := ad11
		loose.RequireAllKeys = false
		res = compareRecords(golden, fresh(oldRec(monitor), refused(share)), approvedDiffs{Entries: []approvedEntry{loose}})
		if res.failed() {
			t.Fatalf("entries without require_all_keys keep the entry-level rule: %s", res.summary(5))
		}
	})
}
