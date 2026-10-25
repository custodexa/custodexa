package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/robfig/cron/v3"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/scheduler"
)

// Authorization decision baseline: flow declaration tables B4, I and T.

var catalogOnce struct {
	sync.Once
	rows map[string]routeEntry
}

// catalogRow returns the routes.json row for method and path.
func (f *flowCtx) catalogRow(method, path string) routeEntry {
	catalogOnce.Do(func() {
		catalogOnce.rows = map[string]routeEntry{}
		for _, r := range loadRouteCatalog(f.e.t).Routes {
			catalogOnce.rows[routeKey(r)] = r
		}
	})
	r, ok := catalogOnce.rows[method+" "+path]
	if !ok {
		f.e.t.Fatalf("flow: no catalog row for %s %s", method, path)
	}
	return r
}

// catalogCall sends the catalog's request for a route as subject.
func (f *flowCtx) catalogCall(name, subject, method, path string) map[string]any {
	return f.send(name, subject, f.e.request(f.catalogRow(method, path)))
}

// --- B4: recordings and live monitoring ---------------------------------------

var b4Subjects = []string{"S01", "S02", "S03"}

func b4Scenarios() []flowScenario {
	closed := func(f *flowCtx) uint { return f.e.object("session.closed").(uint) }
	type action struct {
		name  string
		setup func(f *flowCtx)
		steps func(f *flowCtx, subj string)
	}
	actions := []action{
		{"recording-ticket-issue", nil, func(f *flowCtx, subj string) {
			f.call("issue", subj, http.MethodPost, fmt.Sprintf("/api/v1/sessions/%d/recording/token", closed(f)), nil)
		}},
		{"recording-playback", nil, func(f *flowCtx, subj string) {
			out := f.call("issue", subj, http.MethodPost, fmt.Sprintf("/api/v1/sessions/%d/recording/token", closed(f)), nil)
			if tok := str(out, "token"); tok != "" {
				f.call("stream", "", http.MethodGet, "/api/v1/recordings/stream?"+url.Values{"rtoken": {tok}}.Encode(), nil)
			}
		}},
		{"recording-download-offsite", func(f *flowCtx) {
			// The local copy is gone and the ledger points at the offsite
			// object: an allowed download fetches from the object store.
			var s model.Session
			if err := f.e.db.First(&s, closed(f)).Error; err != nil {
				f.e.t.Fatalf("flow: closed session: %v", err)
			}
			if err := os.Remove(s.RecordingPath); err != nil {
				f.e.t.Fatalf("flow: remove local recording: %v", err)
			}
			f.e.db.Model(&model.Session{}).Where("id = ?", s.ID).Update("offsite_object_id", f.e.object("offsiteObject.failed"))
		}, func(f *flowCtx, subj string) {
			f.call("download", subj, http.MethodGet, fmt.Sprintf("/api/v1/sessions/%d/recording/download", closed(f)), nil)
		}},
		{"monitor-subscribe", nil, func(f *flowCtx, subj string) {
			active := f.e.object("session.active").(uint)
			out := f.call("monitor-ticket", subj, http.MethodPost, fmt.Sprintf("/api/v1/sessions/%d/monitor-token", active), nil)
			tok := str(out, "connect_token")
			if tok == "" {
				return
			}
			f.ws("subscribe", "", fmt.Sprintf("/api/v1/sessions/%d/monitor?%s", active, url.Values{"connect_token": {tok}}.Encode()))
		}},
	}
	var out []flowScenario
	for _, subj := range b4Subjects {
		for _, a := range actions {
			subj, a := subj, a
			out = append(out, flowScenario{id: "B4/" + subj + "/" + a.name, setup: a.setup,
				steps: func(f *flowCtx) { a.steps(f, subj) }})
		}
	}
	return out
}

// --- I: batch and background entries ------------------------------------------

var iSubjects = []string{"S01", "S02", "S03"}

// changeSecretCron returns the plan scheduler's cron (the scheduler is never
// started in the baseline; its entries are run synchronously instead).
func (f *flowCtx) changeSecretCron() (*cron.Cron, func()) {
	found := map[string][]reflect.Value{}
	walkByTypeName(reflect.ValueOf(f.e.graph), found, map[serviceVisitKey]bool{}, 0)
	sch := firstOf[*scheduler.ChangeSecretScheduler](found, "*scheduler.ChangeSecretScheduler")
	if sch == nil {
		f.e.t.Fatalf("flow: change-secret scheduler not found on the service graph")
	}
	field := reflect.ValueOf(sch).Elem().FieldByName("cron")
	c := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(*cron.Cron)
	return c, sch.Reload
}

func iScenarios() []flowScenario {
	type entry struct {
		name   string
		setup  func(f *flowCtx)
		steps  func(f *flowCtx, subj string)
		settle time.Duration
	}
	entries := []entry{
		{"import-preview", nil, func(f *flowCtx, subj string) {
			f.catalogCall("preview", subj, http.MethodPost, "/api/v1/assets/import/preview")
		}, 0},
		{"import-commit", nil, func(f *flowCtx, subj string) {
			f.catalogCall("import", subj, http.MethodPost, "/api/v1/assets/import")
		}, 0},
		{"batch-rotate-all", nil, func(f *flowCtx, subj string) {
			// The Windows asset's default account: the runner reaches the
			// remote management endpoint.
			f.call("batch", subj, http.MethodPost, "/api/v1/change-secret-batches",
				map[string]any{"username": "Administrator", "all": true, "password_mode": "per_target"})
		}, 500 * time.Millisecond},
		{"batch-rotate-unknown-id", nil, func(f *flowCtx, subj string) {
			f.call("batch", subj, http.MethodPost, "/api/v1/change-secret-batches",
				map[string]any{"username": "baseline-root", "account_ids": []uint{999999}, "password_mode": "per_target"})
		}, 300 * time.Millisecond},
		{"plan-create", nil, func(f *flowCtx, subj string) {
			f.catalogCall("create", subj, http.MethodPost, "/api/v1/change-secret-plans")
		}, 0},
		{"plan-scheduled-run", func(f *flowCtx) {
			_, reload := f.changeSecretCron()
			reload() // schedule entries reflect the template state
		}, func(f *flowCtx, subj string) {
			// The subject schedules the plan (on the Windows asset, whose
			// account has no pending candidate); the scheduler then fires
			// once. Cron entries left behind are never run on their own:
			// the scheduler is not started and this setup reloads first.
			f.call("schedule", subj, http.MethodPut, fmt.Sprintf("/api/v1/change-secret-plans/%d", f.e.object("changeSecretPlan.1")),
				map[string]any{"name": "baseline-plan-1", "asset_ids": []any{"{asset.winrm}"}, "accounts": []string{"Administrator"}, "cron": "0 3 * * *", "enabled": true})
			c, _ := f.changeSecretCron()
			for _, en := range c.Entries() {
				en.Job.Run()
			}
		}, 500 * time.Millisecond},
		{"candidate-retry", nil, func(f *flowCtx, subj string) {
			f.catalogCall("retry", subj, http.MethodPost, "/api/v1/change-secret-candidates/:id/retry")
		}, 0},
		{"batch-assign-roles", nil, func(f *flowCtx, subj string) {
			// No bulk endpoint exists; a batch is consecutive per-user calls.
			for _, u := range []string{"user.target", "user.extTarget"} {
				f.call("roles-"+u, subj, http.MethodPut, fmt.Sprintf("/api/v1/users/%d/roles", f.e.object(u)), map[string]any{"manual_roles": []string{"user", "auditor"}})
			}
		}, 0},
		{"shared-credential-update", func(f *flowCtx) {
			f.e.mustAPI("S01", http.MethodPost, fmt.Sprintf("/api/v1/credentials/%d/bindings", f.e.object("credential.shared")),
				map[string]any{"asset_id": f.e.object("asset.approval")})
		}, func(f *flowCtx, subj string) {
			id := f.e.object("credential.shared")
			f.call("update", subj, http.MethodPut, fmt.Sprintf("/api/v1/credentials/%d", id), map[string]any{"note": "baseline shared updated"})
			f.call("secret", subj, http.MethodPost, fmt.Sprintf("/api/v1/credentials/%d/secret", id), map[string]any{"password": "Baseline-Pass-789"})
		}, 0},
	}
	var out []flowScenario
	for _, subj := range iSubjects {
		for _, en := range entries {
			subj, en := subj, en
			out = append(out, flowScenario{id: "I/" + subj + "/" + en.name, setup: en.setup, settle: en.settle,
				steps: func(f *flowCtx) { en.steps(f, subj) }})
		}
	}
	return out
}

// --- T: timing ------------------------------------------------------------------

func tScenarios() []flowScenario {
	userPath := func(f *flowCtx, subj string) string { return fmt.Sprintf("/api/v1/users/%d", f.uid(subj)) }
	return []flowScenario{
		{id: "T/T01", steps: func(f *flowCtx) {
			// Role removal while S07 holds a token issued before it.
			f.call("before", "S07", http.MethodGet, "/api/v1/audit-logs?page=1&page_size=1", nil)
			f.call("remove-auditor", "S01", http.MethodPut, userPath(f, "S07")+"/roles", map[string]any{"manual_roles": []string{"user"}})
			f.call("after", "S07", http.MethodGet, "/api/v1/audit-logs?page=1&page_size=1", nil)
		}},
		{id: "T/T02", steps: func(f *flowCtx) {
			f.call("before", "S02", http.MethodGet, "/api/v1/audit-logs?page=1&page_size=1", nil)
			f.call("add-auditor", "S01", http.MethodPost, userPath(f, "S02")+"/roles/auditor", nil)
			f.call("next-request", "S02", http.MethodGet, "/api/v1/audit-logs?page=1&page_size=1", nil)
		}},
		{id: "T/T03", steps: func(f *flowCtx) {
			f.call("before", "S08", http.MethodGet, "/api/v1/auth/me", nil)
			f.call("remove-from-group", "S01", http.MethodPut, fmt.Sprintf("/api/v1/user-groups/%d/members", f.e.object("userGroup.1")), map[string]any{"manual_user_ids": []uint{}})
			f.call("after", "S08", http.MethodGet, "/api/v1/auth/me", nil)
		}},
		{id: "T/T04", steps: func(f *flowCtx) {
			// The mapping rule is removed on the server; S13's mapped
			// administrator role was granted from the provider channel and
			// is re-evaluated only at its next sign-in.
			f.call("before", "S13", http.MethodGet, "/api/v1/users?page=1&page_size=1", nil)
			f.call("remove-mapping", "S01", http.MethodDelete, fmt.Sprintf("/api/v1/identity-sources/oidc/%d/role-mappings/%d",
				f.e.object("oidcProvider.1"), f.e.object("roleMapping.spare")), nil)
			f.call("after", "S13", http.MethodGet, "/api/v1/users?page=1&page_size=1", nil)
		}},
		{id: "T/T05", setup: func(f *flowCtx) {
			n := f.newNode("t05", 0)
			f.set("other", f.newNode("t05-other", 0))
			f.set("asset", f.newAsset("t05", "ssh", []uint{n}, nil))
			f.grant(map[string]any{"user_id": f.uid("S02"), "asset_group_id": n, "permission": "connect"})
		}, steps: func(f *flowCtx) {
			a := f.get("asset").(uint)
			out := f.call("issue", "S02", http.MethodPost, "/api/v1/connect-tokens", map[string]any{"asset_id": a})
			f.call("move", "S01", http.MethodPut, fmt.Sprintf("/api/v1/assets/%d", a), map[string]any{"node_ids": []uint{f.get("other").(uint)}})
			if tok := str(out, "connect_token"); tok != "" {
				f.redeem("ssh", tok)
			}
		}},
		{id: "T/T06", setup: func(f *flowCtx) {
			a := f.newAsset("t06", "ssh", []uint{f.newNode("t06", 0)}, nil)
			f.set("asset", a)
			f.grant(map[string]any{"user_id": f.uid("S02"), "asset_id": a, "permission": "connect"})
		}, steps: func(f *flowCtx) {
			a := f.get("asset").(uint)
			out := f.call("issue", "S02", http.MethodPost, "/api/v1/connect-tokens", map[string]any{"asset_id": a})
			f.call("delete", "S01", http.MethodDelete, fmt.Sprintf("/api/v1/assets/%d", a), nil)
			if tok := str(out, "connect_token"); tok != "" {
				f.redeem("ssh", tok)
			}
		}},
		{id: "T/T07", settle: 500 * time.Millisecond, setup: func(f *flowCtx) {
			_, reload := f.changeSecretCron()
			reload() // schedule entries reflect the template state
			f.set("plan", f.e.apiID("S01", http.MethodPost, "/api/v1/change-secret-plans", map[string]any{
				"name": "baseline-flow-t07", "asset_ids": []any{"{asset.winrm}"}, "accounts": []string{"Administrator"}, "cron": "", "enabled": false}, "flow plan"))
		}, steps: func(f *flowCtx) {
			// S06 schedules the plan (the job is queued on the scheduler),
			// then loses its administrator role, then the schedule fires.
			plan := f.get("plan")
			f.call("schedule", "S06", http.MethodPut, fmt.Sprintf("/api/v1/change-secret-plans/%d", plan),
				map[string]any{"name": "baseline-flow-t07", "asset_ids": []any{"{asset.winrm}"}, "accounts": []string{"Administrator"}, "cron": "0 3 * * *", "enabled": true})
			f.call("remove-admin", "S01", http.MethodPut, userPath(f, "S06")+"/roles", map[string]any{"manual_roles": []string{"approver"}})
			c, _ := f.changeSecretCron()
			for _, en := range c.Entries() {
				en.Job.Run()
			}
		}},
		{id: "T/T08", fresh: true, steps: func(f *flowCtx) {
			out := f.call("issue-connect", "S02", http.MethodPost, "/api/v1/connect-tokens", map[string]any{"asset_id": f.e.object("asset.ssh")})
			rec := f.call("issue-recording", "S03", http.MethodPost, fmt.Sprintf("/api/v1/sessions/%d/recording/token", f.e.object("session.closed")), nil)
			f.restartSameDB()
			if tok := str(out, "connect_token"); tok != "" {
				f.redeem("ssh", tok)
			}
			if tok := str(rec, "token"); tok != "" {
				f.call("stream", "", http.MethodGet, "/api/v1/recordings/stream?"+url.Values{"rtoken": {tok}}.Encode(), nil)
			}
		}},
		{id: "T/T09", steps: func(f *flowCtx) {
			rec := f.call("issue-recording", "S03", http.MethodPost, fmt.Sprintf("/api/v1/sessions/%d/recording/token", f.e.object("session.closed")), nil)
			f.call("remove-auditor", "S01", http.MethodPut, userPath(f, "S03")+"/roles", map[string]any{"manual_roles": []string{"user"}})
			if tok := str(rec, "token"); tok != "" {
				f.call("stream", "", http.MethodGet, "/api/v1/recordings/stream?"+url.Values{"rtoken": {tok}}.Encode(), nil)
			}
		}},
	}
}
