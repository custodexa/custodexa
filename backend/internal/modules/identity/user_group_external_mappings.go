package identity

import (
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// UserGroupExternalMappingSource 指向某個群組的一條啟用中外部映射規則的來源描述。
// 只含管理者看懂「這個群組的成員從哪裡帶進來」所需的欄位；不含成員名單、成員數、影響人數。
type UserGroupExternalMappingSource struct {
	RuleID             uint   `json:"rule_id"`
	SourceType         string `json:"source_type"`
	SourceName         string `json:"source_name"`
	SourceEnabled      bool   `json:"source_enabled"`
	ExternalGroupLabel string `json:"external_group_label"`
}

// ExternalMappingSources 唯讀列出指向目標群組、且規則本身啟用中的外部映射規則。
// 規則停用者不列；來源（目錄或身分提供者）停用者仍列，以 SourceEnabled 標示，
// 讓管理者看得出該規則目前不會帶人進來。群組不存在回 ErrUserGroupNotFound。
func (s *UserGroupService) ExternalMappingSources(groupID uint) ([]UserGroupExternalMappingSource, error) {
	var n int64
	if err := s.db.Model(&model.UserGroup{}).Where("id = ?", groupID).Count(&n).Error; err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrUserGroupNotFound
	}
	var rules []model.GroupUserGroupMapping
	if err := s.db.Where("user_group_id = ? AND enabled = ?", groupID, true).Order("id").Find(&rules).Error; err != nil {
		return nil, err
	}
	out := make([]UserGroupExternalMappingSource, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		var ext model.ExternalGroup
		if err := s.db.First(&ext, r.ExternalGroupID).Error; err != nil {
			return nil, err
		}
		item := UserGroupExternalMappingSource{RuleID: r.ID, ExternalGroupLabel: ext.MatchValue}
		if strings.TrimSpace(ext.Note) != "" {
			item.ExternalGroupLabel = ext.Note
		}
		switch {
		case r.LDAPDirectoryID != nil:
			var d model.LDAPDirectory
			if err := s.db.First(&d, *r.LDAPDirectoryID).Error; err != nil {
				continue // 來源已刪除：規則不再有效，不列
			}
			item.SourceType, item.SourceName, item.SourceEnabled = "ldap", d.Name, d.Enabled
		case r.OIDCProviderID != nil:
			var p model.OIDCProvider
			if err := s.db.First(&p, *r.OIDCProviderID).Error; err != nil {
				continue
			}
			item.SourceType, item.SourceName, item.SourceEnabled = "oidc", p.Name, p.Enabled
		default:
			continue
		}
		out = append(out, item)
	}
	return out, nil
}
