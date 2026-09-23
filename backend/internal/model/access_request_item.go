package model

import (
	"encoding/json"
	"gorm.io/gorm"
	"time"
)

const AccessRequestItemRevoked AccessRequestStatus = "revoked"

// AccessRequestItem is the independently scoped asset within a request envelope.
type AccessRequestItem struct {
	DecisionBounds *AccessRequestDecisionBounds `gorm:"-" json:"decision_bounds,omitempty"`
	// Current username for the stored decider ID; read-only projection, never a stored name.
	// An automatic approval has no decider, so it stays empty.
	DecidedByUsername string `gorm:"-" json:"decided_by_username,omitempty"`
	// Account scope as requested, preserved in policy_snapshot before a decision may narrow
	// Accounts. Null means the snapshot predates the projection, not "requested nothing".
	RequestedAccounts *AccountScope `gorm:"-" json:"requested_accounts"`
	// AssetName is a read-only display projection so a reviewer can tell which machine an
	// item is for. Deciding an item is not reading the asset, so the name travels with the
	// item instead of forcing a second fetch the reviewer may not be authorized to make.
	// Empty means the asset row is gone entirely (hard delete), not "unnamed".
	AssetName string `gorm:"-" json:"asset_name"`
	// AssetDeleted marks a soft-deleted asset: the name still resolves, and the reviewer
	// needs to know the target no longer exists.
	AssetDeleted bool `gorm:"-" json:"asset_deleted"`

	ID                      uint                `gorm:"primaryKey" json:"id"`
	CreatedAt               time.Time           `json:"created_at"`
	UpdatedAt               time.Time           `json:"updated_at"`
	DeletedAt               gorm.DeletedAt      `gorm:"index:access_request_items_deleted_idx" json:"-"`
	RequestID               uint                `gorm:"not null;index:access_request_items_request_idx" json:"request_id"`
	RequesterID             uint                `gorm:"not null;index:access_request_items_requester_idx" json:"requester_id"`
	AssetID                 uint                `gorm:"not null;index:access_request_items_asset_idx" json:"asset_id"`
	Accounts                AccountScope        `gorm:"type:text" json:"accounts"`
	Status                  AccessRequestStatus `gorm:"type:varchar(20);not null;index:access_request_items_status_idx" json:"status"`
	ApprovedDurationMinutes *int                `json:"approved_duration_minutes,omitempty"`
	ApprovedDateStart       *time.Time          `json:"approved_date_start,omitempty"`
	DecidedBy               *uint               `json:"decided_by,omitempty"`
	DecidedAt               *time.Time          `json:"decided_at,omitempty"`
	RevokedAt               *time.Time          `json:"revoked_at,omitempty"`
	RevokedBy               *uint               `json:"revoked_by,omitempty"`
	AuthorizationID         *uint               `gorm:"uniqueIndex" json:"authorization_id,omitempty"`
	Authorization           *AssetAuthorization `gorm:"foreignKey:AuthorizationID" json:"-"`
	RevokeNote              string              `gorm:"type:varchar(1000)" json:"revoke_note,omitempty"`
	PolicySnapshot          string              `gorm:"type:jsonb;not null;default:'{}'" json:"policy_snapshot"`
	Requester               User                `gorm:"foreignKey:RequesterID" json:"-"`
	Asset                   *Asset              `gorm:"foreignKey:AssetID" json:"-"`
	Decider                 *User               `gorm:"foreignKey:DecidedBy" json:"-"`
	Revoker                 *User               `gorm:"foreignKey:RevokedBy" json:"-"`
}

func (AccessRequestItem) TableName() string { return "access_request_items" }
func (i *AccessRequestItem) BeforeCreate(*gorm.DB) error {
	if i.RequestID == 0 || i.RequesterID == 0 || i.AssetID == 0 || i.Status != AccessRequestPending {
		return gorm.ErrInvalidValue
	}
	if i.PolicySnapshot == "" {
		i.PolicySnapshot = "{}"
	}
	var object map[string]any
	if json.Unmarshal([]byte(i.PolicySnapshot), &object) != nil || object == nil {
		return gorm.ErrInvalidValue
	}
	return nil
}

// FillRequestedAccounts projects the pre-decision account scope preserved in policy_snapshot.
// A snapshot without the key leaves the field nil, so a reader can tell "not preserved"
// from "requested an empty scope".
func (i *AccessRequestItem) FillRequestedAccounts() {
	i.RequestedAccounts = nil
	var snapshot struct {
		RequestedAccounts *AccountScope `json:"requested_accounts"`
	}
	if json.Unmarshal([]byte(i.PolicySnapshot), &snapshot) == nil {
		i.RequestedAccounts = snapshot.RequestedAccounts
	}
}
