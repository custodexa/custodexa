package identity

import (
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"testing"
	"time"
)

type agentTerminatorProbe struct {
	calls  []uint
	result AgentSessionTermination
	err    error
}

func (p *agentTerminatorProbe) TerminateByAgentToken(id uint, _ string) (AgentSessionTermination, error) {
	p.calls = append(p.calls, id)
	return p.result, p.err
}
func TestAgentTokenRevokeTerminatesSessions(t *testing.T) {
	for _, suspend := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoke", true: "suspend"}[suspend], func(t *testing.T) {
			s, db, owner, agent := agentTokenEnv(t)
			token := createAgentTestToken(t, s, owner, agent)
			probe := &agentTerminatorProbe{result: AgentSessionTermination{TerminatedIDs: []uint{31, 32}}}
			s.SetSessionTerminator(probe)
			var err error
			action := model.ActionAgentTokenRevoked
			if suspend {
				err = s.Suspend(agent.ID, token.ID, "disabled", gatewayapi.Actor{UserID: owner.ID})
				action = model.ActionAgentTokenSuspended
			} else {
				err = s.Revoke(agent.ID, token.ID, "revoked", gatewayapi.Actor{UserID: owner.ID})
			}
			if err != nil || len(probe.calls) != 1 || probe.calls[0] != token.ID {
				t.Fatalf("terminate: %v %+v", err, probe)
			}
			var named, terminated model.AuditLog
			if err := db.Where("action = ?", action).First(&named).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Where("action = ?", model.ActionAgentSessionsTerminated).First(&terminated).Error; err != nil {
				t.Fatal(err)
			}
			var details struct {
				IDs []uint `json:"terminated_session_ids"`
			}
			if err := json.Unmarshal([]byte(terminated.Details), &details); err != nil || len(details.IDs) != 2 || details.IDs[0] != 31 || details.IDs[1] != 32 {
				t.Fatalf("details=%s %v", terminated.Details, err)
			}
		})
	}
}
func TestAgentSessionsTerminateLate(t *testing.T) {
	s, db, owner, agent := agentTokenEnv(t)
	token := createAgentTestToken(t, s, owner, agent)
	s.SetSessionTerminator(&agentTerminatorProbe{result: AgentSessionTermination{TerminatedIDs: []uint{71}, Late: map[uint]time.Duration{71: 4 * time.Second}}})
	if err := s.Revoke(agent.ID, token.ID, "late", gatewayapi.Actor{UserID: owner.ID}); err != nil {
		t.Fatal(err)
	}
	var row model.AuditLog
	if err := db.Where("action = ?", model.ActionAgentSessionsTerminateLate).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	var detail struct {
		ID      uint    `json:"session_id"`
		Elapsed float64 `json:"elapsed_seconds"`
	}
	if err := json.Unmarshal([]byte(row.Details), &detail); err != nil || detail.ID != 71 || detail.Elapsed != 4 {
		t.Fatalf("late detail=%s", row.Details)
	}
	var saved model.AgentToken
	if err := db.First(&saved, token.ID).Error; err != nil || saved.RevokedAt == nil {
		t.Fatal("late close resurrected token")
	}
}
func TestOwnerDisableTerminatesAgentSessions(t *testing.T) {
	testAgentOwnerInvalidation(t, "owner disable")
	t.Run("agent disable", func(t *testing.T) { testAgentOwnerInvalidation(t, "agent disable") })
}
func TestOwnerEpochBumpTerminatesAgentSessions(t *testing.T) {
	for _, source := range []string{"unbind", "provider disable"} {
		t.Run(source, func(t *testing.T) { testAgentOwnerInvalidation(t, source) })
	}
}
func testAgentOwnerInvalidation(t *testing.T, source string) {
	t.Helper()
	users, auth, db, owner, agent := principalEnv(t)
	if err := db.AutoMigrate(&model.AgentToken{}); err != nil {
		t.Fatal(err)
	}
	auth.SetEpochGateDB(db)
	svc := NewAgentTokenService(db, audit.NewTxSink())
	probe := &agentTerminatorProbe{result: AgentSessionTermination{TerminatedIDs: []uint{1, 2}}}
	svc.SetSessionTerminator(probe)
	users.SetAgentTokenService(svc)
	sibling := &model.User{Username: "sibling-agent", Password: "!", Kind: model.KindAgent, OwnerUserID: &owner.ID, Active: true}
	if err := db.Create(sibling).Error; err != nil {
		t.Fatal(err)
	}
	tokens := []*CreatedAgentToken{createAgentTestToken(t, svc, owner, agent), createAgentTestToken(t, svc, owner, agent), createAgentTestToken(t, svc, owner, sibling)}
	for _, token := range tokens {
		if principal, reason := auth.ValidateAgentToken(token.Token, "192.0.2.8"); principal == nil {
			t.Fatalf("before %s", reason)
		}
	}
	var err error
	switch source {
	case "owner disable":
		err = users.UpdateStatus(owner.ID, false)
	case "agent disable":
		err = users.UpdateStatus(agent.ID, false)
	default:
		p := model.OIDCProvider{Name: "agent-owner-provider", Issuer: "https://id.example.test", ClientID: "client", Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, AdmissionRules: "{}"}
		if e := db.Create(&p).Error; e != nil {
			t.Fatal(e)
		}
		link := model.UserExternalIdentity{UserID: owner.ID, ProviderID: p.ID, Issuer: p.Issuer, ClientID: p.ClientID, Subject: "owner"}
		if e := db.Create(&link).Error; e != nil {
			t.Fatal(e)
		}
		if source == "unbind" {
			err = users.UnbindExternalIdentity(owner.ID, link.ID, IdentityAdminActor{})
		} else {
			providers := NewOIDCProviderService(db, nil, nil, nil, "https://app.example.test")
			providers.SetAgentTokenService(svc)
			off := false
			_, err = providers.Update(p.ID, &OIDCProviderRequest{Enabled: &off})
			var saved model.OIDCProvider
			if e := db.First(&saved, p.ID).Error; e != nil || saved.AuthEpoch <= p.AuthEpoch || saved.Enabled {
				t.Fatal("provider epoch not advanced")
			}
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	var after model.User
	if err := db.First(&after, owner.ID).Error; err != nil {
		t.Fatal(err)
	}
	if source == "unbind" && (!after.Active || after.CredentialEpoch <= owner.CredentialEpoch) {
		t.Fatal("epoch-only counterexample invalid")
	}
	if source == "owner disable" && after.Active {
		t.Fatal("owner still active")
	}
	expected := 3
	if source == "agent disable" {
		expected = 2
	}
	if len(probe.calls) != expected {
		t.Fatalf("all agent tokens must close: calls=%v", probe.calls)
	}
	for i, token := range tokens {
		principal, reason := auth.ValidateAgentToken(token.Token, "192.0.2.8")
		var saved model.AgentToken
		if e := db.First(&saved, token.ID).Error; e != nil {
			t.Fatal(e)
		}
		if i < expected {
			if saved.SuspendedAt == nil || principal != nil {
				t.Fatalf("invalid token accepted via 5.2 query: %s", reason)
			}
		} else if principal == nil || saved.SuspendedAt != nil {
			t.Fatal("sibling affected by agent-only disable")
		}
	}
	var count int64
	if err := db.Model(&model.AuditLog{}).Where("action = ?", model.ActionAgentTokenSuspended).Count(&count).Error; err != nil || count != int64(expected) {
		t.Fatalf("suspension audits %d %v", count, err)
	}
}
func TestAgentRevokeNotRolledBackOnTerminateFailure(t *testing.T) {
	s, db, owner, agent := agentTokenEnv(t)
	token := createAgentTestToken(t, s, owner, agent)
	s.SetSessionTerminator(&agentTerminatorProbe{result: AgentSessionTermination{FailedIDs: []uint{77}, TerminatedIDs: []uint{78}}, err: errors.New("injected failure")})
	if err := s.Revoke(agent.ID, token.ID, "fail", gatewayapi.Actor{UserID: owner.ID}); err != nil {
		t.Fatal(err)
	}
	auth := NewAuthService("failure-test", time.Hour)
	auth.SetEpochGateDB(db)
	if principal, _ := auth.ValidateAgentToken(token.Token, "192.0.2.8"); principal != nil {
		t.Fatal("revoked credential accepted")
	}
	var tokenRow model.AgentToken
	if err := db.First(&tokenRow, token.ID).Error; err != nil || tokenRow.RevokedAt == nil {
		t.Fatal("revocation rolled back")
	}
	var row model.AuditLog
	if err := db.Where("action = ?", model.ActionAgentSessionsTerminated).First(&row).Error; err != nil || row.Status != model.StatusFailure {
		t.Fatalf("failure not audited: %v", err)
	}
	var d struct {
		IDs []uint `json:"failed_session_ids"`
	}
	if err := json.Unmarshal([]byte(row.Details), &d); err != nil || len(d.IDs) != 1 || d.IDs[0] != 77 {
		t.Fatalf("failure IDs %s", row.Details)
	}
}
