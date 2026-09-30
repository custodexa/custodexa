package identity

import (
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

func TestUserGroupMappingUsageRequiresAcknowledgement(t *testing.T) {
	f := newMappingSegmentFixture(t)
	if err := f.db.Create(&model.AssetAuthorization{UserGroupID: &f.group.ID, AssetID: func() *uint { id := uint(1); return &id }(), Permission: "view", Source: "manual"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&model.ApproverScope{ApproverGroupID: &f.group.ID, SubjectUserID: &f.user.ID, GrantedBy: f.user.ID}).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&model.ApproverScope{ApproverID: &f.user.ID, SubjectGroupID: &f.group.ID, GrantedBy: f.user.ID}).Error; err != nil {
		t.Fatal(err)
	}
	input := UserGroupMappingInput{MatchValue: "ops", UserGroupID: f.group.ID, Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}}
	_, err := f.service.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, input)
	var usage *UserGroupMappingUsageAckError
	if !errors.As(err, &usage) || usage.AssetAuthorizations != 1 || usage.ApproverScopes != 1 || usage.RequesterScopes != 1 {
		t.Fatalf("有授權用途應要求確認並回實數: %v", err)
	}
	input.RiskAcknowledged = true
	if _, err := f.service.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, input); err != nil {
		t.Fatal(err)
	}
}

func TestExternalGroupNoteSharedAcrossMappingTypes(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "ops")
	f.groupRule(t, "ops")
	actor := GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}
	groups, err := f.service.ListExternalGroups(model.RoleMappingChannelKindProvider, f.provider.ID)
	if err != nil || len(groups) != 1 {
		t.Fatalf("共用字典未去重: %v %+v", err, groups)
	}
	if err := f.service.UpdateExternalGroupNote(model.RoleMappingChannelKindProvider, f.provider.ID, groups[0].ID, "Operations", actor); err != nil {
		t.Fatal(err)
	}
	var auditRow model.AuditLog
	if err := f.db.Order("id desc").First(&auditRow).Error; err != nil || strings.Contains(auditRow.Details, "Operations") {
		t.Fatalf("備註原文不得進稽核 details: %v %+v", err, auditRow)
	}
	roles, err := f.service.ListMappings(model.RoleMappingChannelKindProvider, f.provider.ID)
	if err != nil || len(roles) != 1 || roles[0].Note != "Operations" {
		t.Fatalf("角色分頁未讀共用備註: %v %+v", err, roles)
	}
	userGroups, err := f.service.ListUserGroupMappings(model.RoleMappingChannelKindProvider, f.provider.ID)
	if err != nil || len(userGroups) != 1 || userGroups[0].Note != "Operations" {
		t.Fatalf("使用者群組分頁未讀共用備註: %v %+v", err, userGroups)
	}
}

func TestExternalGroupNoteAuditFailureRollsBack(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "ops")
	groups, err := f.service.ListExternalGroups(model.RoleMappingChannelKindProvider, f.provider.ID)
	if err != nil || len(groups) != 1 {
		t.Fatalf("讀取字典: %v %+v", err, groups)
	}
	f.service = NewIdentitySourceService(f.db, rejectMappingAudit{})
	err = f.service.UpdateExternalGroupNote(model.RoleMappingChannelKindProvider, f.provider.ID, groups[0].ID, "private note", GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username})
	if err == nil {
		t.Fatal("稽核失敗應中止備註更新")
	}
	var actual model.ExternalGroup
	if err := f.db.First(&actual, groups[0].ID).Error; err != nil || actual.Note != "" {
		t.Fatalf("備註應隨稽核失敗回滾: %v %+v", err, actual)
	}
}

func TestIdentitySourceMappingCountsSeparateTargets(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "ops")
	f.groupRule(t, "ops")
	rows, err := f.service.ListSources()
	if err != nil || len(rows) != 1 {
		t.Fatalf("來源列表: %v %+v", err, rows)
	}
	if rows[0].MappingRuleCount != 1 || rows[0].RoleMappingRuleCount != 1 || rows[0].UserGroupMappingRuleCount != 1 {
		t.Fatalf("兩類計數範圍不對: %+v", rows[0])
	}
}
