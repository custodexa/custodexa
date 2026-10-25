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
//
// 依能力類別判定（能力類別），不依角色名稱清單：agent 不得持有內建超管、稽核員、
// 審核者範本，也不得持有含管理、稽核、審核類權限點的角色。角色列以名稱查表取得其內建
// 識別；查無此名稱的角色由呼叫端既有的「角色不存在」路徑回報。
func GuardAgentRoles(db *gorm.DB, user *model.User, roleNames []string) error {
	if user.Kind != model.KindAgent || len(roleNames) == 0 {
		return nil
	}
	var roles []model.Role
	if err := db.Where("name IN ?", roleNames).Find(&roles).Error; err != nil {
		return err
	}
	for _, r := range roles {
		forbidden, err := roleForbiddenForAgent(db, r)
		if err != nil {
			return err
		}
		if forbidden {
			return deny(DenyReasonAgentRole, ErrAgentRoleForbidden)
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
