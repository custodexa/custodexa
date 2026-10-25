package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// Authorization decision baseline: flow declaration tables B1-B3.
//
// Objects a scenario needs beyond the shared fixture are created in its
// setup through the product API as S01 (or written directly where the API
// has no field for it, such as an authorization's expiry); setup effects
// are the comparison base and do not appear in the record.

const flowPassword = "Baseline-Pass-123"

// --- setup helpers ----------------------------------------------------------

// newAsset creates an asset through the API as S01 and returns its id.
func (f *flowCtx) newAsset(name, protocol string, nodes []uint, extra map[string]any) uint {
	e := f.e
	body := map[string]any{"name": "baseline-flow-" + name, "host": "127.0.0.1", "protocol": protocol, "password": flowPassword, "node_ids": nodes}
	switch protocol {
	case "ssh":
		body["port"], body["username"] = e.recv.port("ssh"), "baseline-root"
	case "mysql", "postgres", "mssql":
		body["port"], body["username"], body["db_name"] = e.recv.port("db-"+protocol), "baseline-db", "baseline"
	case "redis":
		body["port"] = e.recv.port("db-redis")
	case "rdp":
		body["port"], body["username"] = 3389, "baseline-rdp"
	}
	for k, v := range extra {
		body[k] = v
	}
	if nodes == nil {
		body["node_ids"] = []uint{}
	}
	return e.apiID("S01", http.MethodPost, "/api/v1/assets", body, "flow asset "+name)
}

// newNode creates an asset group (node), optionally under parent.
func (f *flowCtx) newNode(name string, parent uint) uint {
	body := map[string]any{"name": "baseline-flow-" + name}
	if parent != 0 {
		body["parent_id"] = parent
	}
	return f.e.apiID("S01", http.MethodPost, "/api/v1/asset-groups", body, "flow node "+name)
}

// grant creates an authorization through the API as S01.
func (f *flowCtx) grant(body map[string]any) uint {
	return f.e.apiID("S01", http.MethodPost, "/api/v1/authorizations", body, "flow authorization")
}

func (f *flowCtx) uid(subject string) uint { return f.e.subjects[subject].UserID }

// newGroupWith creates a user group whose only member is subject.
func (f *flowCtx) newGroupWith(name, subject string) uint {
	g := f.e.apiID("S01", http.MethodPost, "/api/v1/user-groups", map[string]any{"name": "baseline-flow-" + name, "description": "baseline"}, "flow user group")
	f.e.mustAPI("S01", http.MethodPut, fmt.Sprintf("/api/v1/user-groups/%d/members", g), map[string]any{"manual_user_ids": []uint{f.uid(subject)}})
	return g
}

// approverScope writes an approver scope directly (admin-only metadata).
func (f *flowCtx) approverScope(s model.ApproverScope) {
	s.GrantedBy = f.uid("S01")
	f.e.dbCreate(&s, "flow approver scope")
}

// --- step helpers -------------------------------------------------------------

// issueAndRedeem issues a connect token for assetID as subject and, when
// one is returned, redeems it at entry (a pre-upgrade WebSocket request).
func (f *flowCtx) issueAndRedeem(subject string, assetID uint, entry string, extra map[string]any) {
	body := map[string]any{"asset_id": assetID}
	for k, v := range extra {
		body[k] = v
	}
	out := f.call("issue", subject, http.MethodPost, "/api/v1/connect-tokens", body)
	tok := str(out, "connect_token")
	if tok == "" {
		tok = str(out, "data.connect_token")
	}
	if tok == "" {
		return
	}
	f.redeem(entry, tok)
}

// redeem presents a connect token at a ticket-authenticated entry.
func (f *flowCtx) redeem(entry, tok string) {
	q := url.Values{"connect_token": {tok}}
	path := "/api/v1/" + entry
	if entry == "ssh-k8s" {
		// Kubernetes exec goes through the terminal entry with a pod.
		path = "/api/v1/ssh"
		q.Set("k8s_pod", "baseline-pod")
		q.Set("k8s_container", "app")
	}
	if entry == "ssh" || entry == "ssh-k8s" {
		q.Set("cols", "80")
		q.Set("rows", "24")
	}
	f.ws("redeem-"+entry, "", path+"?"+q.Encode())
}

// scopedToken signs a token for subject carrying an intermediate scope
// (MFA pending, password change), as the login flow would.
func (f *flowCtx) scopedToken(subject, scope string) string {
	e := f.e
	claims, err := e.graph.deps.authService.ValidateToken(e.subjects[subject].Token)
	if err != nil {
		e.t.Fatalf("flow scoped token: %v", err)
	}
	tok, err := crypto.NewJWTManager(e.graph.cfg.Security.JWTSecret, time.Hour).
		GenerateScopedToken(claims.UserID, claims.Username, claims.Email, claims.Role, scope, 5*time.Minute, crypto.AuthContext{})
	if err != nil {
		e.t.Fatalf("flow scoped token: %v", err)
	}
	return tok
}

// --- B1: connection object variants --------------------------------------------

var b1Subjects = []string{"S01", "S02", "S03"}

func b1Scenarios() []flowScenario {
	type variant struct {
		name  string
		setup func(f *flowCtx, subj string) uint // returns the asset id to connect to
	}
	variants := []variant{
		{"no-grant", func(f *flowCtx, subj string) uint {
			return f.newAsset("b1", "ssh", []uint{f.newNode("b1", 0)}, nil)
		}},
		{"view-only", func(f *flowCtx, subj string) uint {
			a := f.newAsset("b1", "ssh", []uint{f.newNode("b1", 0)}, nil)
			f.grant(map[string]any{"user_id": f.uid(subj), "asset_id": a, "permission": "view"})
			return a
		}},
		{"personal-connect", func(f *flowCtx, subj string) uint {
			a := f.newAsset("b1", "ssh", []uint{f.newNode("b1", 0)}, nil)
			f.grant(map[string]any{"user_id": f.uid(subj), "asset_id": a, "permission": "connect"})
			return a
		}},
		{"expired-connect", func(f *flowCtx, subj string) uint {
			a := f.newAsset("b1", "ssh", []uint{f.newNode("b1", 0)}, nil)
			g := f.grant(map[string]any{"user_id": f.uid(subj), "asset_id": a, "permission": "connect"})
			past := time.Now().Add(-time.Hour)
			f.e.db.Model(&model.AssetAuthorization{}).Where("id = ?", g).Updates(map[string]any{"date_start": past.Add(-time.Hour), "date_expired": past})
			return a
		}},
		{"group-connect", func(f *flowCtx, subj string) uint {
			a := f.newAsset("b1", "ssh", []uint{f.newNode("b1", 0)}, nil)
			f.grant(map[string]any{"user_group_id": f.newGroupWith("b1", subj), "asset_id": a, "permission": "connect"})
			return a
		}},
		{"node-subtree-connect", func(f *flowCtx, subj string) uint {
			parent := f.newNode("b1-parent", 0)
			a := f.newAsset("b1", "ssh", []uint{f.newNode("b1-child", parent)}, nil)
			f.grant(map[string]any{"user_id": f.uid(subj), "asset_group_id": parent, "permission": "connect"})
			return a
		}},
		{"multi-home-one-node", func(f *flowCtx, subj string) uint {
			n1, n2 := f.newNode("b1-a", 0), f.newNode("b1-b", 0)
			a := f.newAsset("b1", "ssh", []uint{n1, n2}, nil)
			f.grant(map[string]any{"user_id": f.uid(subj), "asset_group_id": n2, "permission": "connect"})
			return a
		}},
		{"ungrouped-asset", func(f *flowCtx, subj string) uint {
			a := f.newAsset("b1", "ssh", nil, nil)
			f.grant(map[string]any{"user_id": f.uid(subj), "asset_id": a, "permission": "connect"})
			return a
		}},
		{"missing-asset", func(f *flowCtx, subj string) uint { return 999999 }},
		{"account-scope-mismatch", func(f *flowCtx, subj string) uint {
			a := f.newAsset("b1", "ssh", []uint{f.newNode("b1", 0)}, nil)
			f.grant(map[string]any{"user_id": f.uid(subj), "asset_id": a, "permission": "connect", "accounts": []string{"baseline-nobody"}})
			return a
		}},
	}
	var out []flowScenario
	for _, subj := range b1Subjects {
		for _, v := range variants {
			subj, v := subj, v
			out = append(out, flowScenario{
				id:    "B1/" + subj + "/" + v.name,
				setup: func(f *flowCtx) { f.set("asset", v.setup(f, subj)) },
				steps: func(f *flowCtx) { f.issueAndRedeem(subj, f.get("asset").(uint), "ssh", nil) },
			})
		}
	}
	return out
}

// --- B2: business gate variants (personal connect as the base) -------------------

var b2Subjects = []string{"S01", "S02"}

// b2Base creates an SSH asset with the given access policy and a personal
// connect grant for subj; S04 is given an approver scope over it.
func (f *flowCtx) b2Base(subj, policy string) uint {
	a := f.newAsset("b2", "ssh", []uint{f.newNode("b2", 0)}, map[string]any{"access_policy": policy})
	f.grant(map[string]any{"user_id": f.uid(subj), "asset_id": a, "permission": "connect"})
	s04 := f.uid("S04")
	f.approverScope(model.ApproverScope{ApproverID: &s04, AssetID: &a})
	return a
}

// requestAccess submits an access request as subj (a step) and remembers its id.
func (f *flowCtx) requestAccess(subj string, assetID uint, reason string) {
	out := f.call("request", subj, http.MethodPost, "/api/v1/access-requests",
		map[string]any{"asset_id": assetID, "reason": reason, "duration_minutes": 60})
	if id := str(out, "id"); id != "" {
		f.set("request", id)
	} else if id := str(out, "data.id"); id != "" {
		f.set("request", id)
	}
}

// approve approves the remembered request as approver (a step), if any.
func (f *flowCtx) approve(approver string) {
	id, ok := f.vars["request"].(string)
	if !ok {
		return
	}
	f.call("approve-"+approver, approver, http.MethodPost, "/api/v1/access-requests/"+id+"/approve", map[string]any{"note": "baseline"})
}

func b2Scenarios() []flowScenario {
	type variant struct {
		name  string
		setup func(f *flowCtx, subj string)
		steps func(f *flowCtx, subj string)
	}
	issue := func(f *flowCtx, subj string) { f.issueAndRedeem(subj, f.get("asset").(uint), "ssh", nil) }
	variants := []variant{
		{"policy-open", func(f *flowCtx, subj string) { f.set("asset", f.b2Base(subj, "open")) }, issue},
		{"reason-missing", func(f *flowCtx, subj string) { f.set("asset", f.b2Base(subj, "reason")) }, issue},
		{"reason-given", func(f *flowCtx, subj string) { f.set("asset", f.b2Base(subj, "reason")) },
			func(f *flowCtx, subj string) {
				f.requestAccess(subj, f.get("asset").(uint), "baseline reason")
				issue(f, subj)
			}},
		{"approval-no-ticket", func(f *flowCtx, subj string) { f.set("asset", f.b2Base(subj, "approval")) }, issue},
		{"approval-valid-ticket", func(f *flowCtx, subj string) { f.set("asset", f.b2Base(subj, "approval")) },
			func(f *flowCtx, subj string) {
				f.requestAccess(subj, f.get("asset").(uint), "baseline approval")
				f.approve("S04")
				issue(f, subj)
			}},
		{"approval-expired-ticket", func(f *flowCtx, subj string) {
			a := f.b2Base(subj, "approval")
			f.set("asset", a)
			// Request and approval happen before the scenario; the resulting
			// ticket authorization is then moved out of its window.
			_, out := f.e.api(subj, http.MethodPost, "/api/v1/access-requests", map[string]any{"asset_id": a, "reason": "baseline expired", "duration_minutes": 60})
			if id := str(out, "id"); id != "" {
				f.e.api("S04", http.MethodPost, "/api/v1/access-requests/"+id+"/approve", map[string]any{"note": "baseline"})
			}
			past := time.Now().Add(-time.Hour)
			f.e.db.Model(&model.AssetAuthorization{}).Where("asset_id = ? AND source = ?", a, "ticket").
				Updates(map[string]any{"date_start": past.Add(-time.Hour), "date_expired": past})
		}, issue},
		{"self-approval", func(f *flowCtx, subj string) {
			a := f.b2Base(subj, "approval")
			f.set("asset", a)
			g := f.newGroupWith("b2-approvers", subj)
			f.approverScope(model.ApproverScope{ApproverGroupID: &g, AssetID: &a})
		}, func(f *flowCtx, subj string) {
			f.requestAccess(subj, f.get("asset").(uint), "baseline self approval")
			f.approve(subj)
			issue(f, subj)
		}},
		{"quorum-unmet", func(f *flowCtx, subj string) {
			f.set("asset", f.b2Base(subj, "approval"))
			f.e.setPolicy("access_request_min_approvals", "2")
		}, func(f *flowCtx, subj string) {
			f.requestAccess(subj, f.get("asset").(uint), "baseline quorum")
			f.approve("S04")
			issue(f, subj)
		}},
		{"asset-disabled", func(f *flowCtx, subj string) {
			a := f.b2Base(subj, "open")
			f.set("asset", a)
			f.e.mustAPI("S01", http.MethodPut, fmt.Sprintf("/api/v1/assets/%d", a), map[string]any{"active": false})
		}, issue},
		{"transmission-policy-reject", func(f *flowCtx, subj string) {
			a := f.newAsset("b2-db", "postgres", []uint{f.newNode("b2", 0)}, map[string]any{"access_policy": "open"})
			f.grant(map[string]any{"user_id": f.uid(subj), "asset_id": a, "permission": "connect"})
			f.set("asset", a)
			f.e.mustAPI("S01", http.MethodPut, "/api/v1/security-policies", map[string]any{"policies": map[string]any{"transport_db_level": "strict"}})
			f.e.clearPolicyCaches()
		}, func(f *flowCtx, subj string) { f.issueAndRedeem(subj, f.get("asset").(uint), "db-console", nil) }},
		{"host-key-mismatch", func(f *flowCtx, subj string) {
			a := f.b2Base(subj, "open")
			f.set("asset", a)
			f.e.dbCreate(&model.AssetHostKey{AssetID: a, Algorithm: "ssh-ed25519",
				Fingerprint: "SHA256:baselinemismatchbaselinemismatchbaselinemis",
				PublicKey:   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaselineMismatchBaselineMismatchBaseline"}, "flow host key")
		}, issue},
		{"mfa-pending-token", func(f *flowCtx, subj string) {
			f.set("asset", f.b2Base(subj, "open"))
			f.set("token", f.scopedToken(subj, crypto.ScopeMFAPending))
		}, func(f *flowCtx, subj string) { f.issueWithToken(f.get("token").(string), f.get("asset").(uint)) }},
		{"password-change-token", func(f *flowCtx, subj string) {
			f.set("asset", f.b2Base(subj, "open"))
			f.set("token", f.scopedToken(subj, crypto.ScopePasswordChange))
		}, func(f *flowCtx, subj string) { f.issueWithToken(f.get("token").(string), f.get("asset").(uint)) }},
	}
	var out []flowScenario
	for _, subj := range b2Subjects {
		for _, v := range variants {
			subj, v := subj, v
			out = append(out, flowScenario{
				id:    "B2/" + subj + "/" + v.name,
				setup: func(f *flowCtx) { v.setup(f, subj) },
				steps: func(f *flowCtx) { v.steps(f, subj) },
			})
		}
	}
	return out
}

// issueWithToken issues a connect token with an explicit bearer token.
func (f *flowCtx) issueWithToken(tok string, assetID uint) {
	raw := fmt.Sprintf(`{"asset_id":%d}`, assetID)
	f.send("issue", "", baselineRequest{Method: http.MethodPost, Path: "/api/v1/connect-tokens", Body: []byte(raw),
		ContentType: "application/json", Headers: map[string]string{"Authorization": "Bearer " + tok}})
}

// --- B3: protocol entries, allowed and denied -----------------------------------

func b3Scenarios() []flowScenario {
	type entry struct {
		name    string
		allow   string // subject expected to pass the decision
		deny    string // subject expected to be refused
		setup   func(f *flowCtx, subj string, allowed bool)
		perform func(f *flowCtx, subj string)
	}
	grantOn := func(f *flowCtx, subj, placeholder string) {
		f.grant(map[string]any{"user_id": f.uid(subj), "asset_id": f.e.object(placeholder), "permission": "connect"})
	}
	entries := []entry{
		{"ssh", "S02", "S03", nil, func(f *flowCtx, subj string) {
			f.issueAndRedeem(subj, f.e.object("asset.ssh").(uint), "ssh", nil)
		}},
		{"sftp", "S02", "S03", nil, func(f *flowCtx, subj string) {
			f.call("list", subj, http.MethodGet, fmt.Sprintf("/api/v1/assets/%d/files?path=%%2F", f.e.object("asset.ssh")), nil)
		}},
		{"k8s-exec", "S02", "S03", func(f *flowCtx, subj string, allowed bool) {
			if allowed {
				grantOn(f, subj, "asset.k8s")
			}
		}, func(f *flowCtx, subj string) { f.issueAndRedeem(subj, f.e.object("asset.k8s").(uint), "ssh-k8s", nil) }},
		{"k8s-upload", "S01", "S02", func(f *flowCtx, subj string, allowed bool) {
			// The refused subject holds a connect grant on the asset: the
			// upload decision does not consult per-asset grants today.
			if !allowed {
				grantOn(f, subj, "asset.k8s")
			}
		}, func(f *flowCtx, subj string) {
			f.send("upload", subj, f.e.request(routeEntry{Method: http.MethodPost, Path: "/api/v1/assets/:id/k8s/upload",
				Params: map[string]any{"id": "{asset.k8s}"}, Multipart: &multipartSpec{
					Fields: map[string]string{"pod": "baseline-pod", "container": "app", "dest_path": "/tmp"},
					Files: map[string]struct {
						Name    string `json:"name"`
						Content string `json:"content"`
					}{"file": {Name: "a.txt", Content: "hello"}}}}))
		}},
		{"k8s-download", "S01", "S02", func(f *flowCtx, subj string, allowed bool) {
			if !allowed {
				grantOn(f, subj, "asset.k8s")
			}
		}, func(f *flowCtx, subj string) {
			f.call("download", subj, http.MethodGet, fmt.Sprintf("/api/v1/assets/%d/k8s/download?container=app&path=%%2Ftmp%%2Fbaseline.txt&pod=baseline-pod", f.e.object("asset.k8s")), nil)
		}},
		{"db", "S02", "S03", func(f *flowCtx, subj string, allowed bool) {
			if allowed {
				for _, p := range []string{"asset.mysql", "asset.postgres", "asset.redis", "asset.mssql"} {
					grantOn(f, subj, p)
				}
			}
		}, func(f *flowCtx, subj string) {
			// Terminal entry for every engine (each starts its command-line
			// client) and the query console for the engines it supports
			// (a direct driver connection).
			for _, p := range []string{"mysql", "postgres", "redis", "mssql"} {
				f.issueAndRedeem(subj, f.e.object("asset."+p).(uint), "ssh", nil)
			}
			for _, p := range []string{"postgres", "mssql"} {
				f.issueAndRedeem(subj, f.e.object("asset."+p).(uint), "db-console", nil)
			}
			// The connection test is the only server-side network dial to
			// a key-value store; it is an administrator action, recorded
			// only next to the allowed terminal entry.
			if subj != "S02" {
				return
			}
			f.call("test-connection-redis(S01)", "S01", http.MethodPost, fmt.Sprintf("/api/v1/assets/%d/test-connection", f.e.object("asset.redis")), map[string]any{"timeout": 2})
		}},
		{"rdp", "S02", "S03", func(f *flowCtx, subj string, allowed bool) {
			if allowed {
				grantOn(f, subj, "asset.rdp")
			}
		}, func(f *flowCtx, subj string) { f.issueAndRedeem(subj, f.e.object("asset.rdp").(uint), "connect", nil) }},
	}
	var out []flowScenario
	for _, en := range entries {
		for _, allowed := range []bool{true, false} {
			en, allowed := en, allowed
			subj, kind := en.allow, "allow"
			if !allowed {
				subj, kind = en.deny, "deny"
			}
			s := flowScenario{
				id:    "B3/" + subj + "/" + en.name + "-" + kind,
				steps: func(f *flowCtx) { en.perform(f, subj) },
			}
			if en.setup != nil {
				s.setup = func(f *flowCtx) { en.setup(f, subj, allowed) }
			}
			out = append(out, s)
		}
	}
	return out
}
