package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/custodexa/backend/internal/modules/authz"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// Authorization decision baseline: object fixtures.
//
// Objects whose stored form involves encryption or cross-table invariants are
// created through the product API as S01 (or as the owner where the route is
// owner-scoped), so the stored state is exactly what the product produces.
// Records that only arise from runtime activity (sessions, recordings,
// command events, finished jobs) are inserted directly.

// seedObjects creates every placeholder used by the route catalog and the
// flow tables. Order matters only where an object references another.
func (e *baselineEnv) seedObjects() {
	for _, cat := range egressTCPCategories {
		e.setObject("port."+cat, e.recv.port(cat))
	}
	for cat := range egressHTTPCategories {
		e.setObject("port."+cat, e.recv.port(cat))
		e.setObject("url."+cat, e.recv.url(cat))
	}
	e.setObject("password.common", baselinePassword)
	// "Two days before today" (see the date freezing in the normalizer: dates in fresh output are
	// shifted back by the days elapsed since the capture, so the records do not depend on the run date).
	today := baselineClock()
	e.setObject("date.past", today.AddDate(0, 0, -2).Format("2006-01-02"))
	e.setObject("date.reviewable", today.AddDate(0, 0, -2).Format("2006-01-02"))

	e.seedIdentity()
	e.seedAssets()
	e.seedAccessObjects()
	e.seedCredentials()
	e.seedSessions()
	e.seedAuditAndPolicy()
	e.seedOffsite()
	e.seedAccessRequests()
	e.seedRotations()
}

// seedRotations runs product work whose outcome is the fixture: a plan run
// that leaves an unapplied candidate, and a group rotation that is then
// pinned to the "running, one member failed" state.
func (e *baselineEnv) seedRotations() {
	ssh := e.object("asset.ssh").(uint)
	var acc model.AssetAccount
	if err := e.db.First(&acc, e.object("account.ssh").(uint)).Error; err != nil {
		e.t.Fatalf("account.ssh: %v", err)
	}
	var cred model.Credential
	if err := e.db.First(&cred, acc.CredentialID).Error; err != nil {
		e.t.Fatalf("account.ssh credential: %v", err)
	}
	version := uint(0)
	if acc.EffectiveVersionID != nil {
		version = *acc.EffectiveVersionID
	}
	found := map[string][]reflect.Value{}
	walkByTypeName(reflect.ValueOf(e.graph), found, map[serviceVisitKey]bool{}, 0)
	cs := firstOf[*asset.ChangeSecretCandidateService](found, "*asset.ChangeSecretCandidateService")
	if cs == nil {
		e.t.Fatalf("candidate service not found on the service graph")
	}
	cand, err := cs.Create(context.Background(), asset.CandidateInput{AssetID: ssh, AccountID: acc.ID, AccountUsername: acc.Username,
		SecretType: "password", Password: "Baseline-Next-456", CredentialID: cred.ID, CredentialName: derefStr(cred.Name), TargetVersionID: version})
	if err != nil {
		e.t.Fatalf("change-secret candidate: %v", err)
	}
	e.setObject("changeSecretCandidate.1", cand.ID)
	e.waitQuiet()

	pw := "Baseline-Pass-123"
	rot := e.apiID("S01", http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "baseline-rotating", "username": "baseline-rotating", "protocol_family": "ssh", "password": pw, "note": "baseline"}, "rotating credential")
	e.setObject("credential.rotating", rot)
	e.mustAPI("S01", http.MethodPost, fmt.Sprintf("/api/v1/credentials/%d/bindings", rot), map[string]any{"asset_id": ssh})
	e.mustAPI("S01", http.MethodPost, fmt.Sprintf("/api/v1/credentials/%d/rotations", rot), map[string]any{})
	var r model.CredentialRotation
	deadline := time.Now().Add(10 * time.Second)
	for {
		var busy int64
		found := e.db.Where("credential_id = ?", rot).Order("id DESC").First(&r).Error == nil
		if found {
			e.db.Model(&model.CredentialRotationMember{}).Where("rotation_id = ? AND state IN ?", r.ID, []string{"queued", "changing", "pending"}).Count(&busy)
		}
		if found && busy == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r.ID == 0 {
		e.t.Fatalf("baseline: credential rotation not created")
	}
	e.waitQuiet()
	e.db.Model(&model.CredentialRotation{}).Where("id = ?", r.ID).Update("status", "running")
	e.db.Model(&model.Credential{}).Where("id = ?", rot).Update("active_rotation_id", r.ID)
	var m model.CredentialRotationMember
	if err := e.db.Where("rotation_id = ?", r.ID).First(&m).Error; err != nil {
		e.t.Fatalf("baseline: rotation member: %v", err)
	}
	e.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m.ID).Update("state", "terminal_failed")
	e.setObject("credentialRotation.running", r.ID)
	e.setObject("credentialRotationMember.failed", m.ID)
}

// waitQuiet lets post-response work started during seeding finish.
func (e *baselineEnv) waitQuiet() { time.Sleep(500 * time.Millisecond) }

// apiID seeds via API as subject and returns the created id.
func (e *baselineEnv) apiID(subject, method, path string, body any, what string) uint {
	return e.idOf(e.mustAPI(subject, method, path, e.resolveValue(toJSONValue(body))), what)
}

func toJSONValue(v any) any { return v }

func (e *baselineEnv) dbCreate(v any, what string) {
	if err := e.db.Create(v).Error; err != nil {
		e.t.Fatalf("baseline seed %s: %v", what, err)
	}
}

func (e *baselineEnv) setPolicy(key, value string) {
	res := e.db.Model(&model.SecurityPolicy{}).Where("key = ?", key).Updates(map[string]any{"value": value, "updated_by": "baseline"})
	if res.Error != nil {
		e.t.Fatalf("baseline policy %s: %v", key, res.Error)
	}
	if res.RowsAffected == 0 {
		e.dbCreate(&model.SecurityPolicy{Key: key, Value: value, UpdatedBy: "baseline"}, "policy "+key)
	}
	e.clearPolicyCaches()
}

// clearPolicyCaches empties every SecurityPolicyService cache on the graph.
func (e *baselineEnv) clearPolicyCaches() {
	found := map[string][]reflect.Value{}
	walkByTypeName(reflect.ValueOf(e.graph), found, map[serviceVisitKey]bool{}, 0)
	for _, inst := range found["*policy.SecurityPolicyService"] {
		for _, name := range []string{"cache", "lastGood"} {
			clearMapField(inst.Elem().FieldByName(name))
		}
	}
}

func (e *baselineEnv) seedIdentity() {
	// User groups and membership (S08 is a member; the group holds an
	// approver scope over assetGroup.1, set in seedAccessObjects).
	ug := e.apiID("S01", http.MethodPost, "/api/v1/user-groups", map[string]any{"name": "baseline-group-1", "description": "baseline"}, "user group")
	e.setObject("userGroup.1", ug)
	e.mustAPI("S01", http.MethodPut, fmt.Sprintf("/api/v1/user-groups/%d/members", ug), map[string]any{"manual_user_ids": []uint{e.subjects["S08"].UserID}})

	spare := e.apiID("S01", http.MethodPost, "/api/v1/oidc-providers", map[string]any{
		"name": "baseline-idp-spare", "issuer": e.recv.url("oidc") + "/spare",
		"client_id": "baseline-client-spare", "client_secret": "baseline-client-secret",
		"scopes": "openid profile email", "enabled": true, "risk_acknowledged": true,
	}, "spare oidc provider")
	e.setObject("oidcProvider.spare", spare)
	p := e.apiID("S01", http.MethodPost, "/api/v1/oidc-providers", map[string]any{
		"name": "baseline-idp", "issuer": e.recv.url("oidc"),
		"client_id": "baseline-client", "client_secret": "baseline-client-secret",
		"scopes": "openid profile email", "enabled": true, "risk_acknowledged": true,
	}, "oidc provider")
	e.setObject("oidcProvider.1", p)

	src := fmt.Sprintf("/api/v1/identity-sources/oidc/%d", p)
	rm := e.mustAPI("S01", http.MethodPost, src+"/role-mappings", map[string]any{
		"match_value": "baseline-spare-role-group", "role": "auditor", "note": "baseline", "enabled": true, "risk_acknowledged": true,
	})
	e.setObject("roleMapping.spare", e.idOf(rm, "role mapping"))
	ugm := e.mustAPI("S01", http.MethodPost, src+"/user-group-mappings", map[string]any{
		"match_value": "baseline-ug-group", "user_group_id": ug, "enabled": true,
		"risk_acknowledged": true, "source_config_acknowledged": true, "note": "baseline",
	})
	e.setObject("userGroupMapping.1", e.idOf(ugm, "user group mapping"))
	var eg model.ExternalGroup
	if err := e.db.Where("oidc_provider_id = ? AND match_value = ?", p, "baseline-spare-role-group").First(&eg).Error; err != nil {
		e.t.Fatalf("external group: %v", err)
	}
	e.setObject("externalGroup.1", eg.ID)

	ext := e.createUser("baseline-ext-target", []string{model.RoleUser})
	e.setObject("user.extTarget", ext)
	var prov model.OIDCProvider
	if err := e.db.First(&prov, p).Error; err != nil {
		e.t.Fatalf("provider: %v", err)
	}
	ei := &model.UserExternalIdentity{UserID: ext, ProviderID: p, Issuer: prov.Issuer, ClientID: prov.ClientID, Subject: "baseline-ext-subject"}
	e.dbCreate(ei, "external identity")
	e.setObject("externalIdentity.extTarget", ei.ID)

	owner := e.subjects["S02"].UserID
	now := time.Now()
	brk := &model.User{Username: "baseline-agent-breaker", Password: "!", Kind: model.KindAgent, OwnerUserID: &owner, Active: true, BreakerPendingAt: &now}
	e.dbCreate(brk, "breaker agent")
	e.setObject("user.agentBreaker", brk.ID)

	// OIDC login ticket and flow state for exchange / callback.
	secret := "baseline-browser-secret"
	plain := "baseline-oidc-ticket-plain"
	e.setObject("oidcTicket.browserSecret", secret)
	e.setObject("oidcTicket.plain", plain)
	e.setObject("oidcFlow.state", "baseline-flow-state")
	far := time.Now().Add(365 * 24 * time.Hour)
	e.dbCreate(&model.OIDCLoginTicket{
		TokenHash: sha256Hex(plain), UserID: e.subjects["S13"].UserID, ProviderID: p,
		AuthEpoch: prov.AuthEpoch, CredEpoch: 0, AuthMethod: "oidc",
		FlowBindingHash: sha256Hex(secret), ExpiresAt: far,
	}, "oidc ticket")
	e.dbCreate(&model.OIDCFlowState{
		State: "baseline-flow-state", Nonce: "baseline-nonce", PKCEVerifier: "baseline-verifier-baseline-verifier-baseline",
		ProviderID: p, AuthEpoch: prov.AuthEpoch, BindingHash: sha256Hex(secret), ExpiresAt: far,
	}, "oidc flow state")

	e.mustAPI("S01", http.MethodPut, "/api/v1/ldap-directory", map[string]any{
		"name": "Baseline Directory", "url": "ldap://" + e.recv.addr("ldap"),
		"bind_dn": "cn=svc-baseline,dc=example,dc=test", "base_dn": "dc=example,dc=test",
		"user_filter": "(uid=%s)", "attr_email": "mail", "attr_fullname": "cn", "attr_group": "memberOf",
		"bind_password": "baseline-bind-secret", "skip_tls_verify": false, "enabled": true, "risk_acknowledged": true,
	})
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (e *baselineEnv) seedAssets() {
	ag1 := e.apiID("S01", http.MethodPost, "/api/v1/asset-groups", map[string]any{"name": "baseline-node-1"}, "asset group 1")
	ag2 := e.apiID("S01", http.MethodPost, "/api/v1/asset-groups", map[string]any{"name": "baseline-node-2"}, "asset group 2")
	empty := e.apiID("S01", http.MethodPost, "/api/v1/asset-groups", map[string]any{"name": "baseline-node-empty"}, "empty asset group")
	e.setObject("assetGroup.1", ag1)
	e.setObject("assetGroup.2", ag2)
	e.setObject("assetGroup.empty", empty)

	pw := "Baseline-Pass-123"
	specs := []struct {
		name string
		body map[string]any
	}{
		{"ssh", map[string]any{"protocol": "ssh", "port": e.recv.port("ssh"), "username": "baseline-root", "password": pw, "node_ids": []uint{ag1}, "tags": "baseline-tag-a", "sftp_enabled": true}},
		{"rdp", map[string]any{"protocol": "rdp", "port": 3389, "username": "baseline-rdp", "password": pw, "node_ids": []uint{ag1}, "tags": "baseline-tag-b"}},
		{"vnc", map[string]any{"protocol": "vnc", "port": 5901, "password": pw, "node_ids": []uint{ag1}}},
		{"mysql", map[string]any{"protocol": "mysql", "port": e.recv.port("db-mysql"), "username": "baseline-db", "password": pw, "db_name": "baseline", "node_ids": []uint{ag1}}},
		{"postgres", map[string]any{"protocol": "postgres", "port": e.recv.port("db-postgres"), "username": "baseline-db", "password": pw, "db_name": "baseline", "node_ids": []uint{ag1}}},
		{"redis", map[string]any{"protocol": "redis", "port": e.recv.port("db-redis"), "password": pw, "node_ids": []uint{ag1}}},
		{"mssql", map[string]any{"protocol": "mssql", "port": e.recv.port("db-mssql"), "username": "baseline-db", "password": pw, "db_name": "baseline", "node_ids": []uint{ag1}}},
		{"k8s", map[string]any{"protocol": "k8s", "port": e.recv.port("k8s"), "password": "baseline-k8s-token", "k8s_namespace": "default", "k8s_pod": "baseline-pod", "k8s_container": "app", "k8s_insecure_skip_tls": true, "node_ids": []uint{ag1}}},
		{"winrm", map[string]any{"protocol": "rdp", "port": 3389, "username": "Administrator", "password": pw, "rotation_channel": "windows_winrm", "winrm_scheme": "http", "winrm_port": e.recv.port("winrm"), "node_ids": []uint{ag2}}},
		{"approval", map[string]any{"protocol": "ssh", "port": e.recv.port("ssh"), "username": "baseline-root", "password": pw, "access_policy": "approval", "node_ids": []uint{ag2}}},
		{"request", map[string]any{"protocol": "ssh", "port": e.recv.port("ssh"), "username": "baseline-root", "password": pw, "access_policy": "approval", "node_ids": []uint{ag2}}},
	}
	for _, s := range specs {
		s.body["name"] = "baseline-" + s.name
		s.body["host"] = "127.0.0.1"
		id := e.apiID("S01", http.MethodPost, "/api/v1/assets", s.body, "asset "+s.name)
		e.setObject("asset."+s.name, id)
		var acc model.AssetAccount
		if err := e.db.Where("asset_id = ? AND is_default = ?", id, true).First(&acc).Error; err == nil {
			e.setObject("account."+s.name, acc.ID)
			if s.name == "ssh" {
				e.setObject("accountName.ssh", acc.Username)
			}
		}
	}
	ssh := e.object("asset.ssh").(uint)
	acc2 := e.mustAPI("S01", http.MethodPost, fmt.Sprintf("/api/v1/assets/%d/accounts", ssh), map[string]any{"username": "baseline-second", "password": pw, "note": "baseline"})
	e.setObject("account.ssh2", e.idOf(acc2, "second account"))
	e.setObject("tag.a", "baseline-tag-a")
	e.setObject("tag.b", "baseline-tag-b")
	e.dbCreate(&model.AssetHostKey{AssetID: ssh, Algorithm: "ssh-ed25519",
		Fingerprint: "SHA256:baselinebaselinebaselinebaselinebaselinebas",
		PublicKey:   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaselineBaselineBaselineBaselineBaseline"}, "host key")
}

func (e *baselineEnv) seedAccessObjects() {
	s02 := e.subjects["S02"].UserID
	e.setObject("authorization.1", e.apiID("S01", http.MethodPost, "/api/v1/authorizations",
		map[string]any{"user_id": s02, "asset_id": e.object("asset.ssh"), "permission": "connect"}, "authorization 1"))
	e.setObject("authorization.approval", e.apiID("S01", http.MethodPost, "/api/v1/authorizations",
		map[string]any{"user_id": s02, "asset_id": e.object("asset.approval"), "permission": "connect"}, "authorization approval"))
	e.setObject("authorization.request", e.apiID("S01", http.MethodPost, "/api/v1/authorizations",
		map[string]any{"user_id": s02, "asset_id": e.object("asset.request"), "permission": "connect"}, "authorization request"))

	s01 := e.subjects["S01"].UserID
	ug := e.object("userGroup.1").(uint)
	ag1 := e.object("assetGroup.1").(uint)
	vnc := e.object("asset.vnc").(uint)
	approval := e.object("asset.approval").(uint)
	s04, s06 := e.subjects["S04"].UserID, e.subjects["S06"].UserID
	group := &model.ApproverScope{ApproverGroupID: &ug, AssetGroupID: &ag1, GrantedBy: s01}
	e.dbCreate(group, "group approver scope")
	del := &model.ApproverScope{ApproverID: &s06, AssetID: &vnc, GrantedBy: s01}
	e.dbCreate(del, "approver scope 1")
	e.setObject("approverScope.1", del.ID)
	ap := &model.ApproverScope{ApproverID: &s04, AssetID: &approval, GrantedBy: s01}
	e.dbCreate(ap, "approval approver scope")
	e.setObject("approverScope.approval", ap.ID)

	e.setObject("snippet.S02", e.apiID("S02", http.MethodPost, "/api/v1/snippets",
		map[string]any{"name": "baseline-snippet-1", "content": "uptime"}, "snippet"))
}

func (e *baselineEnv) seedCredentials() {
	ssh := e.object("asset.ssh").(uint)
	pw := "Baseline-Pass-123"
	shared := e.apiID("S01", http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "baseline-shared", "username": "baseline-shared", "protocol_family": "ssh", "password": pw, "note": "baseline"}, "shared credential")
	e.setObject("credential.shared", shared)
	e.mustAPI("S01", http.MethodPost, fmt.Sprintf("/api/v1/credentials/%d/bindings", shared), map[string]any{"asset_id": ssh})
	var acc model.AssetAccount
	if err := e.db.Where("asset_id = ? AND credential_id = ?", ssh, shared).First(&acc).Error; err != nil {
		e.t.Fatalf("shared binding account: %v", err)
	}
	e.setObject("account.sshShared", acc.ID)
	e.setObject("credential.unbound", e.apiID("S01", http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "baseline-unbound", "username": "baseline-unbound", "protocol_family": "ssh", "password": pw, "note": "baseline"}, "unbound credential"))

	e.setObject("changeSecretPlan.1", e.apiID("S01", http.MethodPost, "/api/v1/change-secret-plans", map[string]any{
		"name": "baseline-plan-1", "asset_ids": []uint{ssh}, "accounts": []string{"baseline-root"}, "cron": "", "enabled": false}, "change secret plan"))
	e.setObject("rotationReportSchedule.1", e.apiID("S01", http.MethodPost, "/api/v1/rotation-report/schedules", map[string]any{
		"name": "baseline-schedule-1", "cron": "0 3 * * *", "enabled": false, "scope_kind": "all", "scope_id": 0,
		"retention_days": 30, "language": "en-US"}, "rotation report schedule"))

	s01 := e.subjects["S01"]
	batch := &model.ChangeSecretBatch{Username: "baseline-root", PasswordMode: "random", PasswordLength: 20,
		TargetCount: 1, FailedCount: 1, Status: "completed", RequestedBy: s01.UserID, RequestedByName: s01.Username,
		StartedAt: time.Now().Add(-time.Hour)}
	e.dbCreate(batch, "change secret batch")
	e.setObject("changeSecretBatch.1", batch.ID)
}

func (e *baselineEnv) seedSessions() {
	s02 := e.subjects["S02"].UserID
	ssh := e.object("asset.ssh").(uint)
	acc := e.object("account.ssh").(uint)
	human := model.KindHuman
	start := baselineTodayOffset(-2 * time.Hour)
	end := start.Add(10 * time.Minute)
	recDir := e.fsDirs["recordings"]
	recPath := filepath.Join(recDir, "baseline-closed.cast")
	cast := "{\"version\":2,\"width\":80,\"height\":24,\"timestamp\":1700000000}\n[0.1,\"o\",\"$ ls\\r\\n\"]\n"
	if err := os.WriteFile(recPath, []byte(cast), 0o644); err != nil {
		e.t.Fatalf("recording file: %v", err)
	}
	closed := &model.Session{SessionID: "baseline-closed", Status: model.SessionStatus("closed"), Protocol: model.ProtocolType("ssh"),
		ActorKind: &human, UserID: s02, AssetID: &ssh, ClientIP: "192.0.2.10", StartTime: start, EndTime: &end,
		Duration: 600, RecordingPath: recPath, RecordingSize: int64(len(cast)), HasRecording: true,
		AccountID: acc, AccountUsername: "baseline-root"}
	e.dbCreate(closed, "closed session")
	e.setObject("session.closed", closed.ID)
	active := &model.Session{SessionID: "baseline-active", Status: model.SessionStatus("active"), Protocol: model.ProtocolType("ssh"),
		ActorKind: &human, UserID: s02, AssetID: &ssh, ClientIP: "192.0.2.10", StartTime: baselineTodayOffset(-5 * time.Minute),
		AccountID: acc, AccountUsername: "baseline-root"}
	e.dbCreate(active, "active session")
	e.setObject("session.active", active.ID)
	// The observer ticket store is created lazily on first use; touch it now
	// so it exists (and is reset) before the template is taken.
	found := map[string][]reflect.Value{}
	walkByTypeName(reflect.ValueOf(e.graph), found, map[serviceVisitKey]bool{}, 0)
	for _, h := range found["*sshproxy.Handler"] {
		elem := h.Elem()
		once := (*sync.Once)(unsafe.Pointer(elem.FieldByName("observerTicketsOnce").UnsafeAddr()))
		reg := elem.FieldByName("observerTicketsReg")
		once.Do(func() {
			reflect.NewAt(reg.Type(), unsafe.Pointer(reg.UnsafeAddr())).Elem().Set(reflect.ValueOf(proxy.NewObserverTicketManager()))
		})
	}
	e.dbCreate(&model.SessionCommand{SessionID: closed.ID, UserID: s02, AssetID: &ssh, Command: "ls", Seq: 1, ExecutedAt: start.Add(time.Minute)}, "session command")
	ce := &model.ClipboardEvent{SessionID: closed.ID, Direction: "upload", ContentLength: 0, ContentStatus: "not_retained"}
	e.dbCreate(ce, "clipboard event")
	e.setObject("clipboardEvent.1", ce.ID)
	ca := &model.CommandAlert{SessionID: closed.ID, UserID: s02, AssetID: &ssh, Command: "ls", Severity: "high",
		Kind: "rule", RuleName: "baseline", TriggeredAt: time.Now(), Disposition: "pending"}
	e.dbCreate(ca, "command alert")
	e.setObject("commandAlert.1", ca.ID)
}

func (e *baselineEnv) seedAuditAndPolicy() {
	e.setObject("alertRule.custom", e.apiID("S01", http.MethodPost, "/api/v1/alert-rules", map[string]any{
		"name": "baseline-rule-custom", "pattern": "^baseline-custom$", "severity": "low", "action": "alert", "direction": "input", "enabled": true}, "alert rule"))
	e.setObject("notificationChannel.1", e.apiID("S01", http.MethodPost, "/api/v1/notification-channels", map[string]any{
		"name": "baseline-channel-1", "type": "webhook", "url": e.recv.url("notify"), "enabled": true,
		"language": "en-US", "min_severity": "low", "risk_acknowledged": true}, "notification channel"))
	e.mustAPI("S01", http.MethodPost, "/api/v1/policy-groups", map[string]any{"code": "baseline-custom", "name": "Baseline custom", "locale": "en-US"})
	e.setObject("policyGroup.custom", "baseline-custom")
	e.mustAPI("S01", http.MethodPut, "/api/v1/policy-groups/baseline-custom/clauses/B-1", map[string]any{"title": "Baseline clause", "summary": "baseline", "kind": "self_attested"})
	e.setObject("policyClause.custom", "B-1")

	// Daily review enabled with history dated before the reviewable day.
	e.setPolicy("daily_review_enabled", "true")
	e.dbCreate(&model.SecurityPolicyHistory{PolicyKey: "daily_review_enabled", OldValue: "false", NewValue: "true",
		ChangedAt: time.Now().AddDate(0, 0, -5), ChangedBy: "baseline", Source: "baseline"}, "policy history")

	s03 := e.subjects["S03"]
	art := filepath.Join(e.fsDirs["exports"], "baseline-export.zip")
	content := []byte("baseline export artifact")
	if err := os.WriteFile(art, content, 0o644); err != nil {
		e.t.Fatalf("export artifact: %v", err)
	}
	exp := time.Now().Add(30 * 24 * time.Hour)
	done := time.Now().Add(-time.Hour)
	job := &model.AuditExportJob{RequesterID: s03.UserID, RequesterName: s03.Username, Kind: "evidence_bundle",
		FilterJSON: "{}", FilterHash: sha256Hex("{}"), Status: "done", ArtifactPath: art, ArtifactSHA256: sha256Hex(string(content)),
		ArtifactSize: int64(len(content)), RequestedAt: done, PackagedAt: &done, ExpiresAt: &exp}
	e.dbCreate(job, "export job")
	e.setObject("exportJob.doneS03", job.ID)
}

func (e *baselineEnv) seedOffsite() {
	body := map[string]any{"provider": "s3", "endpoint": e.recv.url("offsite"), "bucket": "baseline-bucket",
		"prefix": "", "region": "us-east-1", "path_style": false}
	e.mustAPI("S01", http.MethodPut, "/api/v1/offsite-storage/settings", body)
	var prof model.OffsiteProfile
	if err := e.db.Order("generation_id DESC").First(&prof).Error; err != nil {
		e.t.Fatalf("offsite profile: %v", err)
	}
	e.setObject("offsiteProfile.current", prof.GenerationID)
	obj := &model.OffsiteObject{Kind: "recording", OwnerID: e.object("session.closed").(uint), Origin: "baseline", Provider: "s3",
		StorageGenerationID: prof.GenerationID, Bucket: "baseline-bucket", ObjectKey: "baseline/object", SHA256: sha256Hex("x"),
		Size: 1, State: "failed", Attempts: 3, ErrorCode: "baseline_failure"}
	// A recording upload may already be queued for this generation (the
	// product enqueues on settings activation); pin that row to "failed".
	if err := e.db.Where("kind = ? AND owner_id = ? AND storage_generation_id = ?", obj.Kind, obj.OwnerID, obj.StorageGenerationID).
		Assign(map[string]any{"state": "failed", "attempts": 3, "error_code": "baseline_failure"}).FirstOrCreate(obj).Error; err != nil {
		e.t.Fatalf("offsite object: %v", err)
	}
	e.setObject("offsiteObject.failed", obj.ID)
	body["bucket"] = "baseline-bucket-2"
	body["credential_intent"] = "reuse"
	code, out := e.api("S01", http.MethodPut, "/api/v1/offsite-storage/settings", body)
	digest, _ := out["settings_digest"].(string)
	if digest == "" {
		if d, ok := out["data"].(map[string]any); ok {
			digest, _ = d["settings_digest"].(string)
		}
	}
	if digest == "" {
		e.t.Fatalf("offsite confirm digest unavailable (HTTP %d %v)", code, out)
	}
	e.setObject("offsite.confirmDigest", digest)
}

func (e *baselineEnv) seedAccessRequests() {
	approval := e.object("asset.approval").(uint)
	// Approved first, while the pending index for S02 on this asset is free.
	ar := e.mustAPI("S02", http.MethodPost, "/api/v1/access-requests", map[string]any{"asset_id": approval, "reason": "baseline approved", "duration_minutes": 60})
	approved := e.idOf(ar, "approved access request")
	e.mustAPI("S04", http.MethodPost, fmt.Sprintf("/api/v1/access-requests/%d/approve", approved), map[string]any{"note": "baseline"})
	e.setObject("accessRequest.approved", approved)
	pr := e.mustAPI("S02", http.MethodPost, "/api/v1/access-requests", map[string]any{"asset_id": approval, "reason": "baseline pending", "duration_minutes": 60})
	e.setObject("accessRequest.pending", e.idOf(pr, "pending access request"))
	e.setPolicy("break_glass_enabled", "true")
	bg := e.mustAPI("S02", http.MethodPost, "/api/v1/access-requests/break-glass", map[string]any{"asset_id": approval, "reason": "baseline break glass", "duration_minutes": 60})
	e.setObject("accessRequest.breakGlass", e.idOf(bg, "break-glass request"))
	e.setPolicy("break_glass_enabled", "false")

	rv := e.mustAPI("S01", http.MethodPost, "/api/v1/access-reviews", map[string]any{"scope": "all", "note": "baseline"})
	e.setObject("accessReview.1", e.idOf(rv, "access review"))

	owner := e.subjects["S02"].UserID
	agent := e.subjects["S12"].UserID
	ssh := e.object("asset.ssh").(uint)
	req := &model.AccessRequest{RequesterID: agent, AssetID: ssh, Reason: "baseline agent task", RequestedDurationMinutes: 60,
		Status: model.AccessRequestPending, Kind: model.AccessRequestKindNormal, PendingExpiresAt: time.Now().Add(7 * 24 * time.Hour)}
	e.dbCreate(req, "agent task request")
	e.dbCreate(&model.AccessRequestItem{RequestID: req.ID, RequesterID: agent, AssetID: ssh,
		Accounts: model.AccountScope{"baseline-root"}, Status: model.AccessRequestPending, PolicySnapshot: "{}"}, "agent task item")
	e.setObject("accessRequest.agentTask", req.ID)

	// Tool call row without sealed arguments: the arguments route reaches its
	// "no retained arguments" answer after every authorization check.
	tc := &model.AgentToolCall{Seq: 1, UserID: agent, AgentTokenID: e.object("agentToken.1").(uint), OwnerUserID: owner,
		Tool: "list_assets", ArgsRedacted: "{}", Decision: "allowed", ResultStatus: "ok", CreatedAt: time.Now().Add(-time.Hour)}
	e.dbCreate(tc, "agent tool call")
	e.setObject("agentToolCall.1", tc.ID)

	tok, err := identity.NewAgentTokenService(e.db, audit.NewTxSink()).Create(agent,
		identity.CreateAgentTokenRequest{Name: "baseline-spare", ExpiresAt: time.Now().Add(30 * 24 * time.Hour)},
		gatewayapi.Actor{UserID: owner})
	if err != nil {
		e.t.Fatalf("spare agent token: %v", err)
	}
	e.setObject("agentToken.spare", tok.ID)
}

// --- per-scenario process-memory tickets ------------------------------------

// dynamicPlaceholders are issued for the scenario's subject right before the
// request, because they live only in process memory and are bound to a user.
var dynamicPlaceholders = map[string]bool{
	"connectToken.ssh": true, "connectToken.rdp": true, "connectToken.mysql": true,
	"observerTicket.monitor": true, "observerTicket.share": true, "shareCode.active": true,
	"recordingToken.closed": true,
}

// issueDynamic prepares process-memory tickets for subj. The holder of the
// ticket is the scenario's own subject; for S00 and S11 (no live user) the
// tickets are issued to S02 so the request carries a well-formed credential.
func (e *baselineEnv) issueDynamic(subj *baselineSubject) {
	holder := subj
	if subj.UserID == 0 || subj.ID == "S11" {
		holder = e.subjects["S02"]
	}
	claims, err := e.graph.deps.authService.ValidateToken(e.subjects["S02"].Token)
	if holder.Kind == "session" {
		if c, err2 := e.graph.deps.authService.ValidateToken(holder.Token); err2 == nil {
			claims, err = c, nil
		}
	}
	if err != nil {
		e.t.Fatalf("dynamic tickets: %v", err)
	}
	found := map[string][]reflect.Value{}
	walkByTypeName(reflect.ValueOf(e.graph), found, map[serviceVisitKey]bool{}, 0)
	ctm := firstOf[*proxy.ConnectTokenManager](found, "*proxy.ConnectTokenManager")
	otm := firstOf[*proxy.ObserverTicketManager](found, "*proxy.ObserverTicketManager")
	exp := time.Now().Add(time.Minute)
	for _, a := range []string{"ssh", "rdp", "mysql"} {
		tok, err := ctm.IssueConnectToken(context.Background(), gatewayapi.ConnectGrant{
			PrincipalKind: model.KindHuman, UserID: holder.UserID,
			AssetID: e.object("asset." + a).(uint), AccountID: e.object("account." + a).(uint),
			AuthMethod: claims.EffectiveMethod(), ProviderID: claims.ProviderID, AuthEpoch: claims.AuthEpoch, CredEpoch: claims.CredEpoch,
			ExpiresAt: exp,
		})
		if err != nil {
			tok = "unissued"
		}
		e.objects["connectToken."+a] = tok
	}
	active := e.object("session.active").(uint)
	code := e.issueShare(active)
	e.objects["shareCode.active"] = code
	for _, p := range []proxy.ObserverPurpose{proxy.ObserverPurposeMonitor, proxy.ObserverPurposeShare} {
		g := proxy.ObserverGrant{UserID: holder.UserID, Purpose: p, SessionID: active, Username: holder.Username,
			AuthMethod: claims.EffectiveMethod(), ProviderID: claims.ProviderID, AuthEpoch: claims.AuthEpoch, CredEpoch: claims.CredEpoch, ExpiresAt: exp}
		if p == proxy.ObserverPurposeShare {
			g.ShareCode = code
		}
		tok, err := otm.IssueObserverTicket(context.Background(), g)
		if err != nil {
			tok = "unissued"
		}
		e.objects["observerTicket."+string(p)] = tok
	}
	rtok, err := e.graph.deps.recording.TokenManager().Issue(holder.UserID, e.object("session.closed").(uint), holder.Username, claims.AuthContext, authz.TokenFacts{})
	if err != nil {
		// The product refuses to issue for this holder (e.g. a stale
		// credential epoch); the request then carries an unknown ticket.
		rtok = "unissued"
	}
	e.objects["recordingToken.closed"] = rtok
}

func firstOf[T any](found map[string][]reflect.Value, name string) T {
	var zero T
	for _, v := range found[name] {
		v = reflect.NewAt(v.Type().Elem(), unsafe.Pointer(v.Pointer()))
		if t, ok := v.Interface().(T); ok {
			return t
		}
	}
	return zero
}

// clearMapField empties a (possibly unexported) map field in place.
func clearMapField(f reflect.Value) {
	if !f.IsValid() || f.Kind() != reflect.Map {
		return
	}
	alias := reflect.NewAt(f.Type(), unsafePointer(f)).Elem()
	if alias.IsNil() {
		return
	}
	for _, k := range alias.MapKeys() {
		alias.SetMapIndex(k, reflect.Value{})
	}
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// baselineTodayOffset is now+d, but never earlier than one minute past UTC midnight, so
// "sessions started today" counts do not depend on the time of day the baseline runs
// (the golden records were captured well after midnight, with every seeded session today).
func baselineTodayOffset(d time.Duration) time.Time {
	now := time.Now().UTC()
	t := now.Add(d)
	floor := time.Date(now.Year(), now.Month(), now.Day(), 0, 1, 0, 0, time.UTC)
	if t.Before(floor) && now.After(floor) {
		return floor
	}
	return t
}
