package identity

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

func TestFixSeg2UsageAcknowledgementDoesNotAcknowledgeMissingSourceAttribute(t *testing.T) {
	f := newMappingSegmentFixture(t)
	if err := f.db.Model(&model.OIDCProvider{}).Where("id=?", f.provider.ID).Update("groups_claim", "").Error; err != nil {
		t.Fatal(err)
	}
	assetID := uint(1)
	if err := f.db.Create(&model.AssetAuthorization{UserGroupID: &f.group.ID, AssetID: &assetID, Permission: "view", Source: "manual"}).Error; err != nil {
		t.Fatal(err)
	}
	input := UserGroupMappingInput{MatchValue: "ops", UserGroupID: f.group.ID, Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}}
	_, err := f.service.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, input)
	var usage *UserGroupMappingUsageAckError
	if !errors.As(err, &usage) || usage.AssetAuthorizations != 1 {
		t.Fatalf("未確認用途應先回用途實數: %v", err)
	}
	input.RiskAcknowledged = true
	_, err = f.service.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, input)
	var ack *MappingAckRequiredError
	if !errors.As(err, &ack) || len(ack.Warnings) != 1 || ack.Warnings[0] != mappingWarningSourceAttrUnset {
		t.Fatalf("用途確認不得代替來源群組欄位警告確認: %v", err)
	}
	input.SourceConfigAcknowledged = true
	if _, err := f.service.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, input); err != nil {
		t.Fatalf("兩項分別確認後應可建立: %v", err)
	}
}

func TestFixSeg2RevocationPreviewPreservesOverlappingSupport(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "a")
	f.roleRule(t, "b")
	f.groupRule(t, "a")
	f.groupRule(t, "b")
	f.login(t, "a", "b")
	roles, err := f.service.ListMappings(model.RoleMappingChannelKindProvider, f.provider.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range roles {
		if row.EffectiveRoleLossCount != 0 || row.AffectedUserCount != 1 {
			t.Fatalf("重疊角色的單規則預覽: %+v", row)
		}
	}
	groups, err := f.service.ListUserGroupMappings(model.RoleMappingChannelKindProvider, f.provider.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range groups {
		if row.EffectiveMemberLossCount != 0 || row.AffectedUserCount != 1 {
			t.Fatalf("重疊成員的單規則預覽: %+v", row)
		}
	}
	sources, err := f.service.ListSources()
	if err != nil || len(sources) != 1 || sources[0].EffectiveRoleLossCount != 1 || sources[0].EffectiveMemberLossCount != 1 {
		t.Fatalf("來源全撤預覽: %v %+v", err, sources)
	}
	if err := f.db.Transaction(func(tx *gorm.DB) error {
		return revokeMappingSupportsLocked(tx, f.service.auditTx, model.RoleMappingChannelKindProvider, f.provider.ID, "source", 0)
	}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "user_roles") != 0 || f.count(t, "user_group_members") != 0 {
		t.Fatal("來源撤回實際有效權限與預覽不符")
	}
}

func TestFixSeg2RevocationPreviewExcludesManualSupport(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "a")
	f.groupRule(t, "a")
	f.login(t, "a")
	if err := f.db.Model(&model.UserGroupMember{}).Where("user_id=? AND user_group_id=?", f.user.ID, f.group.ID).Update("manual", true).Error; err != nil {
		t.Fatal(err)
	}
	if err := model.SetUserRoleSource(f.db, f.user.ID, f.role.ID, model.RoleSourceBoth); err != nil {
		t.Fatal(err)
	}
	sources, err := f.service.ListSources()
	if err != nil || len(sources) != 1 || sources[0].EffectiveRoleLossCount != 0 || sources[0].EffectiveMemberLossCount != 0 {
		t.Fatalf("手動支持不可計為權限損失: %v %+v", err, sources)
	}
	if err := f.db.Transaction(func(tx *gorm.DB) error {
		return revokeMappingSupportsLocked(tx, f.service.auditTx, model.RoleMappingChannelKindProvider, f.provider.ID, "source", 0)
	}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "user_roles") != 1 || f.count(t, "user_group_members") != 1 {
		t.Fatal("實際撤回未保留手動支持")
	}
}

func TestFixSeg2UserGroupRuleAuditActionAndExternalCode(t *testing.T) {
	f := newMappingSegmentFixture(t)
	actor := GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}
	input := UserGroupMappingInput{MatchValue: "ops", UserGroupID: f.group.ID, RiskAcknowledged: true, Actor: actor}
	row, err := f.service.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	check := func(action model.AuditAction, code string, acknowledged bool) {
		t.Helper()
		var log model.AuditLog
		if err := f.db.Order("id desc").First(&log).Error; err != nil {
			t.Fatal(err)
		}
		var details map[string]any
		if err := json.Unmarshal([]byte(log.Details), &details); err != nil {
			t.Fatal(err)
		}
		if log.Action != action || log.ErrorMsg != code || details["source_kind"] != model.RoleMappingChannelKindProvider || details["source_id"] != float64(f.provider.ID) || details["match_value"] != "ops" || details["risk_acknowledged"] != acknowledged {
			t.Fatalf("稽核動作／外送碼／確認與來源資訊不完整: action=%q code=%q details=%v", log.Action, log.ErrorMsg, details)
		}
	}
	check(model.ActionCreate, UserGroupMappingEventCreate, true)
	if _, err := f.service.UpdateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, row.ID, input); err != nil {
		t.Fatal(err)
	}
	check(model.ActionUpdate, UserGroupMappingEventUpdate, true)
	if err := f.service.DeleteUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, row.ID, actor); err != nil {
		t.Fatal(err)
	}
	check(model.ActionDelete, UserGroupMappingEventDelete, false)
}

func TestFixSeg2UserGroupRuleAuditFailureRollsBackCRUD(t *testing.T) {
	f := newMappingSegmentFixture(t)
	actor := GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}
	f.service = NewIdentitySourceService(f.db, rejectMappingAudit{})
	input := UserGroupMappingInput{MatchValue: "a", UserGroupID: f.group.ID, Actor: actor}
	if _, err := f.service.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, input); err == nil || f.count(t, "group_user_group_mappings") != 0 {
		t.Fatal("建立的稽核失敗未回滾")
	}
	// A successful rule and login supply support that update/delete must retain on audit failure.
	f.service = NewIdentitySourceService(f.db, audit.NewTxSink())
	ruleID := f.groupRule(t, "a")
	f.login(t, "a")
	f.service = NewIdentitySourceService(f.db, rejectMappingAudit{})
	disabled := false
	input.Enabled = &disabled
	if _, err := f.service.UpdateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, ruleID, input); err == nil {
		t.Fatal("更新的稽核失敗未回滾")
	}
	if err := f.service.DeleteUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, ruleID, actor); err == nil {
		t.Fatal("刪除的稽核失敗未回滾")
	}
	if f.count(t, "group_user_group_mappings") != 1 || f.count(t, "user_group_mapping_rule_supports") != 1 || f.count(t, "user_group_members") != 1 {
		t.Fatal("稽核失敗後規則、支持或有效成員已改變")
	}
}

func TestFixSeg2MappingViewsExposeSourceAndRevocationLoss(t *testing.T) {
	f := newMappingSegmentFixture(t)
	roleID := f.roleRule(t, "ops")
	groupID := f.groupRule(t, "ops")
	f.login(t, "ops")
	check := func(value any, roleLoss, memberLoss float64) {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got["effective_role_loss_count"] != roleLoss || got["effective_member_loss_count"] != memberLoss {
			t.Fatalf("撤回預覽數字不符: %s, want role=%v member=%v", body, roleLoss, memberLoss)
		}
	}
	roles, err := f.service.ListMappings(model.RoleMappingChannelKindProvider, f.provider.ID)
	if err != nil || len(roles) != 1 || roles[0].ID != roleID {
		t.Fatalf("角色規則: %v %+v", err, roles)
	}
	groups, err := f.service.ListUserGroupMappings(model.RoleMappingChannelKindProvider, f.provider.ID)
	if err != nil || len(groups) != 1 || groups[0].ID != groupID {
		t.Fatalf("群組規則: %v %+v", err, groups)
	}
	check(roles[0], 1, 0)
	check(groups[0], 0, 1)
	var roleJSON, groupJSON map[string]any
	roleBytes, _ := json.Marshal(roles[0])
	groupBytes, _ := json.Marshal(groups[0])
	_ = json.Unmarshal(roleBytes, &roleJSON)
	_ = json.Unmarshal(groupBytes, &groupJSON)
	if roleJSON["source_type"] != "oidc" || roleJSON["source_id"] != float64(f.provider.ID) || groupJSON["source_type"] != "oidc" || groupJSON["source_id"] != float64(f.provider.ID) {
		t.Fatalf("規則回應缺來源: role=%v group=%v", roleJSON, groupJSON)
	}
	sources, err := f.service.ListSources()
	if err != nil || len(sources) != 1 {
		t.Fatalf("來源列表: %v %+v", err, sources)
	}
	check(sources[0], 1, 1)
}
