package identity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

func agentTokenEnv(t *testing.T) (*AgentTokenService, *gorm.DB, *model.User, *model.User) {
	t.Helper()
	_, _, db, owner, agent := principalEnv(t)
	if err := db.AutoMigrate(&model.AgentToken{}); err != nil {
		t.Fatal(err)
	}
	return NewAgentTokenService(db, audit.NewTxSink()), db, owner, agent
}
func createAgentTestToken(t *testing.T, s *AgentTokenService, owner, agent *model.User) *CreatedAgentToken {
	t.Helper()
	token, err := s.Create(agent.ID, CreateAgentTokenRequest{Name: "automation", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID, Username: owner.Username})
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func TestAgentTokenGeneration(t *testing.T) {
	s, db, owner, agent := agentTokenEnv(t)
	a := createAgentTestToken(t, s, owner, agent)
	b := createAgentTestToken(t, s, owner, agent)
	if !strings.HasPrefix(a.Token, AgentTokenPrefix) || a.Token == b.Token {
		t.Fatal("prefix/randomness")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(a.Token, AgentTokenPrefix))
	if err != nil || len(decoded) != 32 {
		t.Fatal("entropy length")
	}
	var saved model.AgentToken
	if err := db.First(&saved, a.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.TokenHash == a.Token || saved.TokenHash != agentTokenDigest(a.Token) || len(saved.TokenHash) != 64 {
		t.Fatal("not SHA-256 persistence")
	}
	raw, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), saved.TokenHash) || strings.Contains(string(raw), a.Token) || strings.Contains(string(raw), "token_hash") {
		t.Fatal("secret exposed in JSON")
	}
}
func TestAgentTokenCreate(t *testing.T) {
	for _, which := range []string{"human", "missing expiry", "past expiry", "valid"} {
		t.Run(which, func(t *testing.T) {
			s, _, owner, agent := agentTokenEnv(t)
			id := agent.ID
			req := CreateAgentTokenRequest{Name: "task", ExpiresAt: time.Now().Add(time.Hour)}
			switch which {
			case "human":
				id = owner.ID
			case "missing expiry":
				req.ExpiresAt = time.Time{}
			case "past expiry":
				req.ExpiresAt = time.Now().Add(-time.Hour)
			}
			token, err := s.Create(id, req, gatewayapi.Actor{UserID: owner.ID})
			if which != "valid" {
				if err == nil {
					t.Fatal("invalid issuance accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			list, err := s.List(agent.ID)
			if err != nil || len(list) != 1 {
				t.Fatalf("list: %v", err)
			}
			data, _ := json.Marshal(list)
			if strings.Contains(string(data), token.Token) || strings.Contains(string(data), token.TokenHash) || strings.Contains(string(data), `"token"`) {
				t.Fatal("list leaked credentials")
			}
		})
	}
}
func TestBreakerPendingBlocksIssuance(t *testing.T) {
	s, db, owner, agent := agentTokenEnv(t)
	token := createAgentTestToken(t, s, owner, agent)
	now := time.Now()
	if err := db.Model(agent).Update("breaker_pending_at", now).Error; err != nil {
		t.Fatal(err)
	}
	for _, revoked := range []bool{false, true} {
		if revoked {
			if err := s.Revoke(agent.ID, token.ID, "", gatewayapi.Actor{UserID: owner.ID}); err != nil {
				t.Fatal(err)
			}
		}
		_, err := s.Create(agent.ID, CreateAgentTokenRequest{Name: "again", ExpiresAt: now.Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
		var pe *PrincipalError
		if !errors.As(err, &pe) || pe.Status != 409 || pe.Code != apierror.CodeRuleAgentBreakerPending {
			t.Fatalf("breaker=%v", err)
		}
	}
	var after model.User
	if err := db.First(&after, agent.ID).Error; err != nil || after.BreakerPendingAt == nil {
		t.Fatal("breaker cleared")
	}
}
func TestAgentTokenRevokeSuspend(t *testing.T) {
	for _, suspend := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoke", true: "suspend"}[suspend], func(t *testing.T) {
			s, db, owner, agent := agentTokenEnv(t)
			token := createAgentTestToken(t, s, owner, agent)
			actor := gatewayapi.Actor{UserID: owner.ID, Username: owner.Username}
			note := token.Token + " " + token.TokenHash
			operation := s.Revoke
			if suspend {
				operation = s.Suspend
			}
			for i := 0; i < 2; i++ {
				if err := operation(agent.ID, token.ID, note, actor); err != nil {
					t.Fatal(err)
				}
			}
			var stored model.AgentToken
			if err := db.First(&stored, token.ID).Error; err != nil {
				t.Fatal(err)
			}
			if suspend {
				if stored.SuspendedAt == nil || stored.SuspendedReason != note {
					t.Fatal("suspension missing")
				}
			} else {
				if stored.RevokedAt == nil || stored.RevokedBy == nil || *stored.RevokedBy != owner.ID || stored.RevokeNote != note {
					t.Fatal("revocation missing")
				}
			}
			var rows []model.AuditLog
			if err := db.Where("resource = ? AND resource_id = ?", model.ResourceAgentToken, token.ID).Order("id").Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			action := model.ActionRevoke
			if suspend {
				action = model.ActionSuspend
			}
			named := model.ActionAgentTokenRevoked
			if suspend {
				named = model.ActionAgentTokenSuspended
			}
			if len(rows) != 3 || rows[0].Action != model.ActionCreate || rows[1].Action != action || rows[2].Action != named {
				t.Fatalf("audit rows=%v", rows)
			}
			for _, row := range rows {
				if strings.Contains(row.Details, token.Token) || strings.Contains(row.Details, "cxa_") || strings.Contains(row.Details, token.TokenHash) {
					t.Fatal("audit leaked secret")
				}
				var details struct {
					Name      string    `json:"token_name"`
					ExpiresAt time.Time `json:"expires_at"`
				}
				if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
					t.Fatal(err)
				}
				if details.Name != token.Name || !details.ExpiresAt.Equal(token.ExpiresAt) {
					t.Fatalf("audit metadata missing or changed for %s", row.Action)
				}
			}
		})
	}
}
