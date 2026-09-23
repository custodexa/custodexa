package identity

import (
	"encoding/json"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Only these two fields are accepted. Owner, credentials, roles and kind cannot
// be supplied through this request; owner always comes from the authenticated actor.
type CreateMyAgentRequest struct {
	Username string `json:"username"`
	Purpose  string `json:"purpose"`
}

var ErrAgentSelfCreateDisabled = &PrincipalError{Code: apierror.CodeRuleAgentSelfCreateDisabled, Status: 403}
var ErrAgentSelfCreateLimit = &PrincipalError{Code: apierror.CodeRuleAgentSelfCreateLimit, Status: 403}

type agentSelfCreation struct {
	actor   gatewayapi.Actor
	purpose string
	limit   int
}

func selfServiceOwner(db *gorm.DB, ownerID uint) error {
	enabled, _, err := policy.AgentSelfCreationInTx(db)
	if err != nil {
		return err
	}
	if !enabled {
		return ErrAgentSelfCreateDisabled
	}
	return validateAgentOwner(db, &ownerID)
}

func (s *UserService) CreateMyAgent(actor gatewayapi.Actor, req CreateMyAgentRequest) (*model.User, error) {
	if err := selfServiceOwner(s.db, actor.UserID); err != nil {
		return nil, err
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Purpose = strings.TrimSpace(req.Purpose)
	if n := len([]rune(req.Username)); n < 3 || n > 50 || req.Purpose == "" || len([]rune(req.Purpose)) > 2000 {
		return nil, &PrincipalError{Code: apierror.CodeBadParams, Status: 400}
	}
	return s.Create(&CreateUserRequest{Username: req.Username, Kind: model.KindAgent, OwnerUserID: &actor.UserID, selfCreation: &agentSelfCreation{actor: actor, purpose: req.Purpose}})
}

func (self *agentSelfCreation) check(tx *gorm.DB) error {
	// Serialize the count and insert on the owner row across backend instances.
	// Re-read owner eligibility after acquiring the lock, in the creation transaction.
	var owner model.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&owner, self.actor.UserID).Error; err != nil {
		return err
	}
	if owner.Kind != model.KindHuman || !owner.Active {
		return ErrAgentOwnerRequired
	}
	enabled, limit, err := policy.AgentSelfCreationInTx(tx)
	if err != nil {
		return err
	}
	if !enabled {
		return ErrAgentSelfCreateDisabled
	}
	var count int64
	if err := tx.Model(&model.User{}).Where("kind = ? AND owner_user_id = ?", model.KindAgent, owner.ID).Count(&count).Error; err != nil {
		return err
	}
	if count >= int64(limit) {
		return ErrAgentSelfCreateLimit
	}
	self.limit = limit
	self.actor.Username = owner.Username
	return nil
}

func (self *agentSelfCreation) audit(tx *gorm.DB, user *model.User) error {
	details, err := json.Marshal(map[string]any{"self_service": true, "purpose": self.purpose, "owner_user_id": self.actor.UserID, "agent_self_create_enabled": true, "agent_self_create_max_per_owner": self.limit})
	if err != nil {
		return err
	}
	return port.WriteInTx(audit.NewTxSink(), tx, port.AuditEvent{Actor: self.actor, Action: string(model.ActionCreate), Resource: string(model.ResourceUser), ResourceID: &user.ID, Status: string(model.StatusSuccess), Details: string(details)})
}

// ListMyAgents is deliberately independent of the self-creation policy key: an owner
// stays accountable for the agents already in their name even when creating new ones
// is closed, so the list is gated on owner eligibility alone.
func (s *UserService) ListMyAgents(ownerID uint) ([]model.User, error) {
	if err := validateAgentOwner(s.db, &ownerID); err != nil {
		return nil, err
	}
	users := make([]model.User, 0)
	err := s.db.Where("kind = ? AND owner_user_id = ?", model.KindAgent, ownerID).Order("id").Find(&users).Error
	if err != nil {
		return nil, err
	}
	return users, s.fillAgentOwnerNames(users)
}

// AgentSelfCreateStatus contains only the caller's quota and public policy values.
type AgentSelfCreateStatus struct {
	Enabled     bool  `json:"enabled"`
	MaxPerOwner int   `json:"max_per_owner"`
	Current     int64 `json:"current"`
}

func (s *UserService) MyAgentCreationStatus(ownerID uint) (*AgentSelfCreateStatus, error) {
	if err := validateAgentOwner(s.db, &ownerID); err != nil {
		return nil, err
	}
	enabled, limit, err := policy.AgentSelfCreationInTx(s.db)
	if err != nil {
		return nil, err
	}
	out := &AgentSelfCreateStatus{Enabled: enabled, MaxPerOwner: limit}
	err = s.db.Model(&model.User{}).Where("kind = ? AND owner_user_id = ?", model.KindAgent, ownerID).Count(&out.Current).Error
	return out, err
}
