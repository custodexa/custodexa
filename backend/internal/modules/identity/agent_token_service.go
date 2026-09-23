package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const AgentTokenPrefix = "cxa_"
const agentTokenLastUsedInterval = time.Minute

func GenerateAgentToken() (plaintext, digest string, err error) {
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return "", "", err
	}
	plaintext = AgentTokenPrefix + base64.RawURLEncoding.EncodeToString(entropy[:])
	return plaintext, agentTokenDigest(plaintext), nil
}
func agentTokenDigest(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

type AgentTokenService struct {
	integrityProbe TokenIssueProbe
	terminator     AgentSessionTerminator
	db             *gorm.DB
	sink           port.TxSink
}

func NewAgentTokenService(db *gorm.DB, sink port.TxSink) *AgentTokenService {
	return &AgentTokenService{db: db, sink: sink}
}

type CreateAgentTokenRequest struct {
	Name      string    `json:"name" binding:"required,max=100"`
	ExpiresAt time.Time `json:"expires_at" binding:"required"`
}
type CreatedAgentToken struct {
	model.AgentToken
	Token string `json:"token"`
}

func (s *AgentTokenService) Create(userID uint, req CreateAgentTokenRequest, actor gatewayapi.Actor) (*CreatedAgentToken, error) {
	if strings.TrimSpace(req.Name) == "" || len([]rune(req.Name)) > 100 || !req.ExpiresAt.After(time.Now()) {
		return nil, &PrincipalError{Code: apierror.CodeBadParams, Status: 400}
	}
	s.reconcileBeforeIssue()
	var target model.User
	if err := s.db.First(&target, userID).Error; err != nil {
		return nil, err
	}
	if target.Kind != model.KindAgent || target.OwnerUserID == nil {
		return nil, &PrincipalError{Code: apierror.CodeValidationExecutorNotAgent, Status: 400}
	}
	var result CreatedAgentToken
	// Serialize issuance against owner epoch invalidation, then lock the target row.
	err := WithUserCredentialLock(s.db, *target.OwnerUserID, func(tx *gorm.DB) error {
		var fresh model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&fresh, userID).Error; err != nil {
			return err
		}
		if fresh.Kind != model.KindAgent || fresh.OwnerUserID == nil || *fresh.OwnerUserID != *target.OwnerUserID {
			return ErrAgentOwnerRequired
		}
		if fresh.BreakerPendingAt != nil {
			return &PrincipalError{Code: apierror.CodeRuleAgentBreakerPending, Status: 409}
		}
		if err := validateAgentOwner(tx, fresh.OwnerUserID); err != nil {
			return err
		}
		plaintext, digest, err := GenerateAgentToken()
		if err != nil {
			return err
		}
		result = CreatedAgentToken{AgentToken: model.AgentToken{UserID: userID, Name: req.Name, TokenHash: digest, CreatedBy: actor.UserID, ExpiresAt: req.ExpiresAt.UTC().Truncate(time.Microsecond)}, Token: plaintext}
		if err := tx.Create(&result.AgentToken).Error; err != nil {
			return err
		}
		return s.record(tx, &result.AgentToken, model.ActionCreate, actor)
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}
func (s *AgentTokenService) List(userID uint) ([]model.AgentToken, error) {
	result := []model.AgentToken{}
	err := s.db.Where("user_id = ?", userID).Order("id").Find(&result).Error
	return result, s.fillTokenCreatorNames(result, err)
}
func (s *AgentTokenService) Revoke(userID, tokenID uint, note string, actor gatewayapi.Actor) error {
	err := s.db.Transaction(func(tx *gorm.DB) error { return s.changeState(tx, userID, tokenID, note, actor, false) })
	if err == nil {
		s.finishTermination(tokenID, actor)
	}
	return err
}
func (s *AgentTokenService) Suspend(userID, tokenID uint, reason string, actor gatewayapi.Actor) error {
	err := s.db.Transaction(func(tx *gorm.DB) error { return s.changeState(tx, userID, tokenID, reason, actor, true) })
	if err == nil {
		s.finishTermination(tokenID, actor)
	}
	return err
}
func (s *AgentTokenService) changeState(tx *gorm.DB, userID, tokenID uint, note string, actor gatewayapi.Actor, suspend bool) error {
	var token model.AgentToken
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("user_id = ?", userID).First(&token, tokenID).Error; err != nil {
		return err
	}
	now := time.Now()
	changes := map[string]any{"revoked_at": now, "revoked_by": actor.UserID, "revoke_note": note}
	action := model.ActionRevoke
	if suspend {
		if token.SuspendedAt != nil {
			return nil
		}
		changes = map[string]any{"suspended_at": now, "suspended_reason": note}
		action = model.ActionSuspend
	} else if token.RevokedAt != nil {
		return nil
	}
	if err := tx.Model(&token).Updates(changes).Error; err != nil {
		return err
	}
	if err := s.record(tx, &token, action, actor); err != nil {
		return err
	}
	event := model.ActionAgentTokenRevoked
	if suspend {
		event = model.ActionAgentTokenSuspended
	}
	return s.recordLifecycle(tx, token.ID, event, actor, agentTokenAuditDetails(&token), model.StatusSuccess)
}
func (s *AgentTokenService) record(tx *gorm.DB, token *model.AgentToken, action model.AuditAction, actor gatewayapi.Actor) error {
	// Credential metadata is auditable; notes, reasons and credential material stay out.
	details, err := json.Marshal(agentTokenAuditDetails(token))
	if err != nil {
		return err
	}
	return port.WriteInTx(s.sink, tx, port.AuditEvent{Actor: actor, Action: string(action), Resource: string(model.ResourceAgentToken), ResourceID: &token.ID, Status: string(model.StatusSuccess), Details: string(details)})
}

func agentTokenAuditDetails(token *model.AgentToken) map[string]any {
	return map[string]any{"token_id": token.ID, "user_id": token.UserID, "token_name": token.Name, "expires_at": token.ExpiresAt.UTC(), "revoked": token.RevokedAt != nil, "suspended": token.SuspendedAt != nil, "credential_fingerprint": audit.CredentialFingerprint(token.TokenHash)}
}

// suspendOwnedInTx is the credential-epoch prerequisite for authentication. Session
// termination belongs to the subsequent lifecycle work; state + audit are atomic here.
func (s *AgentTokenService) suspendOwnedInTx(tx *gorm.DB, ownerID uint) error {
	var agents []uint
	if err := tx.Model(&model.User{}).Where("kind = ? AND owner_user_id = ?", model.KindAgent, ownerID).Pluck("id", &agents).Error; err != nil {
		return err
	}
	if len(agents) == 0 {
		return nil
	}
	var tokens []model.AgentToken
	if err := tx.Where("user_id IN ? AND suspended_at IS NULL AND revoked_at IS NULL", agents).Find(&tokens).Error; err != nil {
		return err
	}
	for _, token := range tokens {
		if err := s.changeState(tx, token.UserID, token.ID, "owner_credential_epoch_advanced", gatewayapi.Actor{Username: "system"}, true); err != nil {
			return err
		}
	}
	return nil
}

type AgentTokenIdentity struct {
	TokenID  uint
	UserID   uint
	Username string
	Email    string
}

// ValidateAgentToken reads all authorization facts with one joined query. No
// token/user/owner/CIDR state is cached. last_used_at is telemetry, never a gate.
func (s *AuthService) ValidateAgentToken(plaintext, ip string) (*AgentTokenIdentity, string) {
	invalid := string(apierror.CodeAuthAgentTokenInvalid)
	db := s.epochDB()
	if db == nil {
		return nil, "agent_token_store_unavailable"
	}
	var row struct {
		model.AgentToken `gorm:"embedded"`
		AgentID          uint
		AgentKind        string
		AgentActive      bool
		Username         string
		Email            string
		AllowedCIDRs     string `gorm:"column:allowed_cidrs"`
		OwnerID          uint
		OwnerKind        string
		OwnerActive      bool
	}
	err := db.Table("agent_tokens AS t").Select("t.*, a.id AS agent_id, a.kind AS agent_kind, a.active AS agent_active, a.username, a.email, a.allowed_cidrs, o.id AS owner_id, o.kind AS owner_kind, o.active AS owner_active").
		Joins("JOIN users a ON a.id = t.user_id AND a.deleted_at IS NULL").Joins("JOIN users o ON o.id = a.owner_user_id AND o.deleted_at IS NULL").Where("t.token_hash = ?", agentTokenDigest(plaintext)).Take(&row).Error
	if err != nil {
		return nil, invalid
	}
	if !row.ExpiresAt.After(time.Now()) {
		return nil, "agent_token_expired"
	}
	if row.RevokedAt != nil {
		return nil, string(apierror.CodeAuthAgentTokenRevoked)
	}
	if row.SuspendedAt != nil {
		return nil, string(apierror.CodeAuthAgentTokenSuspended)
	}
	if row.AgentKind != model.KindAgent || !row.AgentActive {
		return nil, "agent_principal_inactive"
	}
	if row.OwnerID == 0 || row.OwnerKind != model.KindHuman || !row.OwnerActive {
		return nil, "agent_owner_invalid"
	}
	if verdict := sourceip.Evaluate(row.AllowedCIDRs, nil, ip); !verdict.Allowed {
		return nil, verdict.Reason
	}
	now := time.Now()
	threshold := now.Add(-agentTokenLastUsedInterval)
	if row.LastUsedAt == nil || row.LastUsedAt.Before(threshold) {
		// Conditional update coordinates replicas; failure cannot deny authentication.
		_ = db.Session(&gorm.Session{SkipDefaultTransaction: true}).Model(&model.AgentToken{}).Where("id = ? AND (last_used_at IS NULL OR last_used_at < ?)", row.ID, threshold).UpdateColumn("last_used_at", now).Error
	}
	return &AgentTokenIdentity{TokenID: row.ID, UserID: row.AgentID, Username: row.Username, Email: row.Email}, ""
}
