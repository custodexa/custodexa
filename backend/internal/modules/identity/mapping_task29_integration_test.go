package identity

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// The runtime authorization and approver decisions must read the effective
// membership maintained by login recomputation and immediate rule revocation.
func TestMappedGroupAuthorizationAndApproverEligibilityImmediate(t *testing.T) {
	f := newMappingSegmentFixture(t)
	if err := f.db.AutoMigrate(&model.AssetNode{}); err != nil { t.Fatal(err) }
	ruleID := f.groupRule(t, "external-operators")
	asset := model.Asset{Name: "demo-asset", Protocol: model.ProtocolSSH, Host: "asset.example.test", Port: 22, Active: true, CreatedBy: f.user.ID}
	if err := f.db.Create(&asset).Error; err != nil {
		t.Fatal(err)
	}
	groupID, assetID := f.group.ID, asset.ID
	if err := f.db.Create(&model.AssetAuthorization{UserGroupID: &groupID, AssetID: &assetID, Permission: model.PermissionConnect, GrantedBy: f.user.ID}).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&model.ApproverScope{ApproverGroupID: &groupID, AssetID: &assetID, GrantedBy: f.user.ID}).Error; err != nil {
		t.Fatal(err)
	}
	authorization := authz.NewAssetAuthorizationService(f.db)
	check := func(want bool) {
		t.Helper()
		allowed, err := authorization.CheckPermission(context.Background(), f.user.ID, asset.ID, model.PermissionConnect)
		if err != nil || allowed != want {
			t.Fatalf("資產連線判定=%v err=%v, want %v", allowed, err, want)
		}
		approver, err := authorization.IsEffectiveApprover(f.user.ID)
		if err != nil || approver != want {
			t.Fatalf("審核方判定=%v err=%v, want %v", approver, err, want)
		}
	}
	check(false)
	f.login(t, "external-operators")
	check(true)
	f.login(t)
	check(false)
	f.login(t, "external-operators")
	check(true)
	disabled := false
	if _, err := f.service.UpdateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, ruleID, UserGroupMappingInput{
		MatchValue: "external-operators", UserGroupID: groupID, Enabled: &disabled, RiskAcknowledged: true,
		Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username},
	}); err != nil {
		t.Fatal(err)
	}
	check(false)
	enabled := true
	if _, err := f.service.UpdateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, ruleID, UserGroupMappingInput{
		MatchValue: "external-operators", UserGroupID: groupID, Enabled: &enabled, RiskAcknowledged: true,
		Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username},
	}); err != nil {
		t.Fatal(err)
	}
	check(false)
	f.login(t, "external-operators")
	check(true)
}
