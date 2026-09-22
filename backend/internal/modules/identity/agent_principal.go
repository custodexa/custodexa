package identity

import (
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// PrincipalError carries the service decision to API callers without exposing DB errors.
type PrincipalError struct {
	Code     apierror.ErrCode
	Status   int
	AgentIDs []uint
}

func (e *PrincipalError) Error() string { return fmt.Sprintf("%s (agent_ids=%v)", e.Code, e.AgentIDs) }

var (
	ErrAgentOwnerRequired     = &PrincipalError{Code: apierror.CodeValidationAgentOwnerRequired, Status: 400}
	ErrPrincipalKindImmutable = &PrincipalError{Code: apierror.CodeBadParams, Status: 400}
	ErrAgentPassword          = &PrincipalError{Code: apierror.CodeBadParams, Status: 400}
	ErrAgentRoleForbidden     = &PrincipalError{Code: apierror.CodePermissionDenied, Status: 403}
	ErrAgentHumanOnly         = &PrincipalError{Code: apierror.CodePermissionDenied, Status: 403}
)

func validateAgentOwner(db *gorm.DB, ownerID *uint) error {
	if ownerID == nil || *ownerID == 0 {
		return ErrAgentOwnerRequired
	}
	var owner model.User
	if err := db.First(&owner, *ownerID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return ErrAgentOwnerRequired
		}
		return err
	}
	if owner.Kind != model.KindHuman || !owner.Active {
		return ErrAgentOwnerRequired
	}
	return nil
}

// GuardAgentRoles is shared by every service role assignment path, including login recomputation.
func GuardAgentRoles(user *model.User, roleNames []string) error {
	if user.Kind != model.KindAgent {
		return nil
	}
	for _, name := range roleNames {
		switch name {
		case model.RoleAdmin, model.RoleAuditor, model.RoleApprover:
			return ErrAgentRoleForbidden
		}
	}
	return nil
}

func rejectOwnedAgents(db *gorm.DB, userID uint) error {
	var ids []uint
	if err := db.Model(&model.User{}).Where("kind = ? AND owner_user_id = ?", model.KindAgent, userID).Order("id").Pluck("id", &ids).Error; err != nil {
		return err
	}
	if len(ids) > 0 {
		return &PrincipalError{Code: apierror.CodeBadParams, Status: 409, AgentIDs: ids}
	}
	return nil
}

// UnmarshalJSON preserves password field presence while keeping the existing Go request API.
func (r *CreateUserRequest) UnmarshalJSON(data []byte) error {
	type wireRequest CreateUserRequest
	var value wireRequest
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*r = CreateUserRequest(value)
	_, r.passwordProvided = fields["password"]
	return nil
}
