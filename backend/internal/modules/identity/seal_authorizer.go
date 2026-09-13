package identity

import (
	"context"
	"errors"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"time"
)

// SealAuthorizer retains only the existing JWT verifier and identity database.
// It cannot decrypt MFA material, perform login, or issue a token.
type SealAuthorizer struct {
	verify func(string) (*crypto.Claims, error)
	db     *gorm.DB
}

func NewSealAuthorizer(secret string, db *gorm.DB) *SealAuthorizer {
	manager := crypto.NewJWTManager(secret, AccessTokenTTL)
	return &SealAuthorizer{verify: func(token string) (*crypto.Claims, error) { return validateIdentityToken(manager, token) }, db: db}
}
func validateIdentityToken(manager *crypto.JWTManager, token string) (*crypto.Claims, error) {
	return manager.ValidateToken(token)
}
func (a *SealAuthorizer) Authorize(ctx context.Context, token string) (uint, error) {
	claims, err := a.verify(token)
	if err != nil {
		return 0, err
	}
	if claims.Scope != "" {
		return 0, ErrConnectionNotAuthorized
	}
	if a.db == nil {
		return 0, ErrEpochGateUnavailable
	}
	var user model.User
	if err = a.db.WithContext(ctx).Preload("Roles").First(&user, claims.UserID).Error; err != nil {
		return 0, err
	}
	if err = checkConnectableUser(&user); err != nil {
		return 0, err
	}
	if err = VerifyCredentialGenerationTx(a.db.WithContext(ctx), claims.AuthContext, &user); err != nil {
		return 0, err
	}
	if primaryRoleOf(&user) != "admin" {
		return 0, errors.New("identity: administrator required")
	}
	return user.ID, nil
}
func checkConnectableUser(user *model.User) error {
	if !user.Active {
		return ErrUserInactive
	}
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return ErrAccountLocked
	}
	return nil
}
