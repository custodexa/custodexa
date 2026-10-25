package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// Authorization decision baseline: the 15 subjects (S00–S14).
//
// Tokens are issued by the product's own issuance path (IssueSessionResponse)
// so the primary role and credential epoch are the real ones, then re-signed
// with the same secret and identical claims under a long lifetime so a full
// run (both orders) never crosses the access-token TTL. S10 is signed before
// it is disabled and S11 before it is deleted. S04 and S09 are created
// exactly as described; the framework never adds a role to them.

// baselineSubjectIDs fixed subject order.
var baselineSubjectIDs = []string{
	"S00", "S01", "S02", "S03", "S04", "S05", "S06", "S07",
	"S08", "S09", "S10", "S11", "S12", "S13", "S14",
}

type baselineSubject struct {
	ID       string
	Username string
	UserID   uint
	Roles    []string // manual roles assigned at creation
	Token    string   // bearer credential ("" for S00)
	Kind     string   // "anonymous", "session", "agent"
}

// subjectSpec creation recipe for each subject.
var subjectSpecs = []struct {
	id    string
	roles []string
}{
	{"S01", []string{model.RoleAdmin}},
	{"S02", []string{model.RoleUser}},
	{"S03", []string{model.RoleAuditor}},
	{"S04", []string{model.RoleApprover}},
	{"S05", []string{model.RoleUser, model.RoleApprover}},
	{"S06", []string{model.RoleAdmin, model.RoleApprover}},
	{"S07", []string{model.RoleAuditor, model.RoleUser}},
	{"S08", []string{model.RoleUser}},
	{"S09", nil},
	{"S10", []string{model.RoleUser}},
	{"S11", []string{model.RoleUser}},
	{"S13", nil}, // admin granted through external mapping in finalizeSubjects
	{"S14", []string{model.RoleUser}},
}

const baselinePassword = "BaselinePass!2026x"

func (e *baselineEnv) roleID(name string) uint {
	var r model.Role
	if err := e.db.Where("name = ?", name).First(&r).Error; err != nil {
		e.t.Fatalf("baseline: role %s missing: %v", name, err)
	}
	return r.ID
}

// createUser inserts a local human user with manual roles.
func (e *baselineEnv) createUser(username string, roles []string) uint {
	hash, err := crypto.DefaultPasswordHasher().Hash([]byte(baselinePassword))
	if err != nil {
		e.t.Fatalf("hash: %v", err)
	}
	email := username + "@baseline.test"
	u := model.User{
		Username: username, Email: &email, Password: string(hash), FullName: username,
		Active: true, Kind: model.KindHuman, ProvisioningOrigin: model.AuthSourceLocal,
	}
	if err := e.db.Create(&u).Error; err != nil {
		e.t.Fatalf("create user %s: %v", username, err)
	}
	for _, r := range roles {
		if err := model.AssignUserRoleWithSource(e.db, u.ID, e.roleID(r), model.RoleSourceManual, model.RoleOriginSystem); err != nil {
			e.t.Fatalf("assign %s to %s: %v", r, username, err)
		}
	}
	return u.ID
}

// seedSubjects creates the subject users (roles that need other fixtures
// are applied in finalizeSubjects) and a bootstrap admin token for seeding.
func (e *baselineEnv) seedSubjects() {
	e.subjects["S00"] = &baselineSubject{ID: "S00", Kind: "anonymous"}
	for _, s := range subjectSpecs {
		name := "baseline-" + lower(s.id)
		id := e.createUser(name, s.roles)
		e.subjects[s.id] = &baselineSubject{ID: s.id, Username: name, UserID: id, Roles: s.roles, Kind: "session"}
		e.setObject("user."+s.id, id)
	}
	// S12: agent owned by S02.
	owner := e.subjects["S02"].UserID
	agent := model.User{Username: "baseline-s12", Password: "!", Kind: model.KindAgent, OwnerUserID: &owner, Active: true}
	if err := e.db.Create(&agent).Error; err != nil {
		e.t.Fatalf("create agent: %v", err)
	}
	e.subjects["S12"] = &baselineSubject{ID: "S12", Username: agent.Username, UserID: agent.ID, Kind: "agent"}
	e.setObject("user.S12", agent.ID)
	issued, err := identity.NewAgentTokenService(e.db, audit.NewTxSink()).Create(agent.ID,
		identity.CreateAgentTokenRequest{Name: "baseline", ExpiresAt: time.Now().Add(30 * 24 * time.Hour)},
		gatewayapi.Actor{UserID: owner})
	if err != nil {
		e.t.Fatalf("S12 agent token: %v", err)
	}
	e.subjects["S12"].Token = issued.Token
	e.setObject("agentToken.1", issued.ID)

	// Object of user-management mutations; never a subject.
	target := e.createUser("baseline-target", []string{model.RoleUser})
	e.setObject("user.target", target)
	e.setObject("user.targetName", "baseline-target")
	for _, r := range []string{model.RoleAdmin, model.RoleUser, model.RoleAuditor, model.RoleApprover} {
		e.setObject("role."+r, e.roleID(r))
	}
	// Seeding tokens (reissued in finalizeSubjects once all roles are final).
	for _, s := range subjectSpecs {
		e.subjects[s.id].Token = e.issueSessionToken(e.subjects[s.id].UserID)
	}
}

// finalizeSubjects applies mapped roles, issues all tokens, then disables
// S10 and deletes S11 (their tokens stay in hand).
func (e *baselineEnv) finalizeSubjects() {
	channel := fmt.Sprintf("%s:%v", model.RoleMappingChannelKindProvider, e.object("oidcProvider.1"))
	now := time.Now()
	if _, err := identity.GrantMappedRole(e.db, e.subjects["S13"].UserID, e.roleID(model.RoleAdmin), channel, now); err != nil {
		e.t.Fatalf("S13 mapped admin: %v", err)
	}
	if _, err := identity.GrantMappedRole(e.db, e.subjects["S14"].UserID, e.roleID(model.RoleUser), channel, now); err != nil {
		e.t.Fatalf("S14 mapped user: %v", err)
	}
	for _, id := range baselineSubjectIDs {
		s := e.subjects[id]
		switch s.Kind {
		case "session":
			s.Token = e.issueSessionToken(s.UserID)
		}
	}
	var firstAudit model.AuditLog
	if err := e.db.Order("id").First(&firstAudit).Error; err != nil {
		e.t.Fatalf("first audit row: %v", err)
	}
	e.setObject("auditLog.1", firstAudit.ID)
	if err := e.db.Model(&model.User{}).Where("id = ?", e.subjects["S10"].UserID).Update("active", false).Error; err != nil {
		e.t.Fatalf("disable S10: %v", err)
	}
	if err := e.db.Delete(&model.User{}, e.subjects["S11"].UserID).Error; err != nil {
		e.t.Fatalf("delete S11: %v", err)
	}
}

// issueSessionToken issues through the product path and re-signs long-lived.
func (e *baselineEnv) issueSessionToken(userID uint) string {
	auth := e.graph.deps.authService
	resp, err := auth.IssueSessionResponse(userID, crypto.AuthMethodLocalPassword, 0)
	if err != nil {
		e.t.Fatalf("issue token for user %d: %v", userID, err)
	}
	claims, err := auth.ValidateToken(resp.Token)
	if err != nil {
		e.t.Fatalf("validate issued token: %v", err)
	}
	long, err := crypto.NewJWTManager(e.graph.cfg.Security.JWTSecret, 72*time.Hour).
		GenerateToken(claims.UserID, claims.Username, claims.Email, claims.Role, claims.AuthContext)
	if err != nil {
		e.t.Fatalf("re-sign token: %v", err)
	}
	return long
}

// api performs a seeding call as a subject and decodes the JSON response.
func (e *baselineEnv) api(subject, method, path string, body any) (int, map[string]any) {
	var buf []byte
	if body != nil {
		var err error
		if buf, err = json.Marshal(body); err != nil {
			e.t.Fatalf("marshal: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(buf))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok := e.subjects[subject].Token; tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := e.serve(req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// mustAPI seeds through the API and fails unless 2xx; returns the payload's
// "data" object when present, else the whole body.
func (e *baselineEnv) mustAPI(subject, method, path string, body any) map[string]any {
	code, out := e.api(subject, method, path, body)
	if code < 200 || code >= 300 {
		raw, _ := json.Marshal(out)
		e.t.Fatalf("baseline seed %s %s as %s: HTTP %d %s", method, path, subject, code, raw)
	}
	if d, ok := out["data"].(map[string]any); ok {
		return d
	}
	return out
}

// idOf extracts a numeric "id" from a seeded payload.
func (e *baselineEnv) idOf(m map[string]any, what string) uint {
	v, ok := m["id"].(float64)
	if !ok || v <= 0 {
		raw, _ := json.Marshal(m)
		e.t.Fatalf("baseline seed %s: no id in %s", what, raw)
	}
	return uint(v)
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// authHeader sets the subject's credential on a request.
func (s *baselineSubject) authorize(req *http.Request) {
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
}
