package identity

import (
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

const ExternalGroupNoteUpdateEvent = "external_group_note_update"

func mappingViewSource(directoryID, providerID *uint) (string, uint) {
	if directoryID != nil {
		return model.RoleMappingChannelKindDirectory, *directoryID
	}
	if providerID != nil {
		return model.RoleMappingChannelKindProvider, *providerID
	}
	return "", 0
}

type UserGroupMappingUsage struct {
	AssetAuthorizations int64 `json:"asset_authorizations"`
	ApproverScopes      int64 `json:"approver_scopes"`
	RequesterScopes     int64 `json:"requester_scopes"`
}

func (u UserGroupMappingUsage) HasAny() bool {
	return u.AssetAuthorizations+u.ApproverScopes+u.RequesterScopes > 0
}

type UserGroupMappingUsageAckError struct{ UserGroupMappingUsage }

func (e *UserGroupMappingUsageAckError) Error() string {
	return "使用者群組映射需確認現有用途"
}

func usageOfUserGroup(tx *gorm.DB, id uint) (UserGroupMappingUsage, error) {
	var u UserGroupMappingUsage
	if err := tx.Model(&model.AssetAuthorization{}).Where("user_group_id=?", id).Count(&u.AssetAuthorizations).Error; err != nil {
		return u, err
	}
	var err error
	u.ApproverScopes, u.RequesterScopes, err = authz.GroupScopeUsage(tx, id)
	if err != nil {
		return u, err
	}
	return u, nil
}

func (s *IdentitySourceService) UserGroupMappingUsage(kind string, sourceID, groupID uint) (UserGroupMappingUsage, error) {
	if _, err := resolveSource(s.db, kind, sourceID); err != nil {
		return UserGroupMappingUsage{}, err
	}
	if err := validateMappingTargetGroup(s.db, groupID); err != nil {
		return UserGroupMappingUsage{}, err
	}
	return usageOfUserGroup(s.db, groupID)
}

func mappedUsersForSource(tx *gorm.DB, kind string, sourceID uint) (int64, error) {
	channel := model.RoleMappingChannel(kind, sourceID)
	var roleUsers, groupUsers []uint
	if err := tx.Table("user_role_mapping_rule_supports").Where("channel=?", channel).Distinct().Pluck("user_id", &roleUsers).Error; err != nil {
		return 0, err
	}
	if err := tx.Table("user_group_mapping_rule_supports").Where("channel=?", channel).Distinct().Pluck("user_id", &groupUsers).Error; err != nil {
		return 0, err
	}
	unique := map[uint]bool{}
	for _, id := range roleUsers {
		unique[id] = true
	}
	for _, id := range groupUsers {
		unique[id] = true
	}
	return int64(len(unique)), nil
}

type UserGroupMappingView struct {
	ID                       uint                  `json:"id"`
	SourceType               string                `json:"source_type"`
	SourceID                 uint                  `json:"source_id"`
	ExternalGroupID          uint                  `json:"external_group_id"`
	MatchValue               string                `json:"match_value"`
	Note                     string                `json:"note"`
	UserGroupID              uint                  `json:"user_group_id"`
	UserGroupName            string                `json:"user_group_name"`
	Usage                    UserGroupMappingUsage `json:"usage"`
	Enabled                  bool                  `json:"enabled"`
	CreatedBy                string                `json:"created_by"`
	CreatedAt                time.Time             `json:"created_at"`
	UpdatedAt                time.Time             `json:"updated_at"`
	AffectedUserCount        int64                 `json:"affected_user_count"`
	EffectiveRoleLossCount   int64                 `json:"effective_role_loss_count"`
	EffectiveMemberLossCount int64                 `json:"effective_member_loss_count"`
}

func (s *IdentitySourceService) userGroupMappingView(tx *gorm.DB, row *model.GroupUserGroupMapping) (UserGroupMappingView, error) {
	view := UserGroupMappingView{ID: row.ID, ExternalGroupID: row.ExternalGroupID, UserGroupID: row.UserGroupID, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
	kind, sourceID := mappingViewSource(row.LDAPDirectoryID, row.OIDCProviderID)
	sourceType := "oidc"
	if kind == model.RoleMappingChannelKindDirectory {
		sourceType = "ldap"
	}
	var group model.ExternalGroup
	if err := tx.First(&group, row.ExternalGroupID).Error; err != nil {
		return view, err
	}
	view = UserGroupMappingView{ID: row.ID, SourceType: sourceType, SourceID: sourceID, ExternalGroupID: row.ExternalGroupID, MatchValue: group.MatchValue, Note: group.Note, UserGroupID: row.UserGroupID, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
	var target model.UserGroup
	if err := tx.First(&target, row.UserGroupID).Error; err != nil {
		return view, err
	}
	view.UserGroupName = target.Name
	if err := tx.Model(&model.User{}).Select("username").Where("id=?", row.CreatedBy).Scan(&view.CreatedBy).Error; err != nil {
		return view, err
	}
	usage, err := usageOfUserGroup(tx, row.UserGroupID)
	if err != nil {
		return view, err
	}
	view.Usage = usage
	preview, err := previewMappingRevocation(tx, kind, sourceID, "group", row.ID)
	if err != nil {
		return view, err
	}
	view.AffectedUserCount, view.EffectiveRoleLossCount, view.EffectiveMemberLossCount = preview.AffectedUserCount, preview.EffectiveRoleLossCount, preview.EffectiveMemberLossCount
	return view, nil
}

func (s *IdentitySourceService) ListUserGroupMappings(kind string, sourceID uint) ([]UserGroupMappingView, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	if _, err := resolveSource(s.db, kind, sourceID); err != nil {
		return nil, err
	}
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return nil, err
	}
	var rows []model.GroupUserGroupMapping
	if err := s.db.Where(column+"=?", sourceID).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]UserGroupMappingView, 0, len(rows))
	for i := range rows {
		view, err := s.userGroupMappingView(s.db, &rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, view)
	}
	return out, nil
}

func (s *IdentitySourceService) UserGroupMappingView(kind string, sourceID, ruleID uint) (UserGroupMappingView, error) {
	row, err := userGroupMappingRow(s.db, kind, sourceID, ruleID)
	if err != nil {
		return UserGroupMappingView{}, err
	}
	return s.userGroupMappingView(s.db, row)
}

func (s *IdentitySourceService) ListExternalGroups(kind string, sourceID uint) ([]model.ExternalGroup, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	if _, err := resolveSource(s.db, kind, sourceID); err != nil {
		return nil, err
	}
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return nil, err
	}
	var groups []model.ExternalGroup
	if err := s.db.Where(column+"=?", sourceID).Order("id").Find(&groups).Error; err != nil {
		return nil, err
	}
	return groups, nil
}

func (s *IdentitySourceService) UpdateExternalGroupNote(kind string, sourceID, groupID uint, note string, actor GroupRoleMappingActor) error {
	if s == nil || s.db == nil {
		return ErrMappingServiceUnavailable
	}
	if utf8.RuneCountInString(note) > 200 {
		return ErrExternalGroupNoteTooLong
	}
	return withMappingSourceLock(s.db, kind, sourceID, func(tx *gorm.DB) error {
		if _, err := resolveSource(tx, kind, sourceID); err != nil {
			return err
		}
		column, err := roleMappingSourceColumn(kind)
		if err != nil {
			return err
		}
		var group model.ExternalGroup
		if err := tx.Where("id=? AND "+column+"=?", groupID, sourceID).First(&group).Error; err != nil {
			return ErrExternalGroupNotFound
		}
		oldLength := utf8.RuneCountInString(group.Note)
		if err := tx.Model(&group).Update("note", note).Error; err != nil {
			return err
		}
		details, err := json.Marshal(map[string]any{"event": ExternalGroupNoteUpdateEvent, "external_group_id": groupID, "old_length": oldLength, "new_length": utf8.RuneCountInString(note)})
		if err != nil {
			return err
		}
		return port.WriteInTx(s.auditTx, tx, port.AuditEvent{Action: string(model.ActionUpdate), Resource: string(model.ResourceUserGroup), ResourceID: &groupID, Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: actor.ID, Username: actor.Name}, Request: gatewayapi.RequestMeta{ClientIP: actor.IP}, Details: string(details)})
	})
}

var ErrExternalGroupNotFound = fmt.Errorf("外部群組不存在")
var ErrExternalGroupNoteTooLong = fmt.Errorf("外部群組備註超過 200 字")
