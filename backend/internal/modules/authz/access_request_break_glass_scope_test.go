package authz

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 破窗票證的帳號範圍等於破窗人的常設連線帳號範圍。
func TestBreakGlassScope_NarrowStandingNotWidened(t *testing.T) {
	s, policies, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	setStanding(t, db, 1, 1, "app")
	requireStandingScope(t, s, 1, 1, "app")
	enableBreakGlass(t, policies)
	req, err := s.BreakGlass(1, "requester", false, 1, "incident")
	if err != nil {
		t.Fatalf("break glass: %v", err)
	}
	if req.AuthorizationID == nil {
		t.Fatal("precondition: break-glass ticket missing")
	}
	var ticket model.AssetAuthorization
	if err := db.First(&ticket, *req.AuthorizationID).Error; err != nil {
		t.Fatal(err)
	}
	if !scopeIs(ticket.Accounts, "app") {
		t.Fatalf("ticket accounts = %v, want [app]", []string(ticket.Accounts))
	}
}

// 個人與使用者群組授權取聯集。
func TestBreakGlassScope_UnionOfPersonalAndGroup(t *testing.T) {
	s, policies, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	setStanding(t, db, 1, 1, "app")
	if err := db.Create(&model.UserGroup{Name: "ops"}).Error; err != nil {
		t.Fatal(err)
	}
	var gid uint
	if err := db.Raw("SELECT id FROM user_groups WHERE name = 'ops'").Scan(&gid).Error; err != nil || gid == 0 {
		t.Fatalf("group id: %v", err)
	}
	if err := db.Exec("INSERT INTO user_group_members (user_group_id, user_id) VALUES (?, 1)", gid).Error; err != nil {
		t.Fatal(err)
	}
	a := uint(1)
	if err := db.Create(&model.AssetAuthorization{UserGroupID: &gid, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 3,
		Source: model.AuthorizationSourceManual, Accounts: model.NormalizeAccountScope([]string{"ops"})}).Error; err != nil {
		t.Fatal(err)
	}
	enableBreakGlass(t, policies)
	req, err := s.BreakGlass(1, "requester", false, 1, "incident")
	if err != nil {
		t.Fatal(err)
	}
	if req.AuthorizationID == nil {
		t.Fatal("precondition: break-glass ticket missing")
	}
	var ticket model.AssetAuthorization
	if err := db.First(&ticket, *req.AuthorizationID).Error; err != nil {
		t.Fatal(err)
	}
	if !scopeIs(ticket.Accounts, "app", "ops") {
		t.Fatalf("ticket accounts = %v, want [app ops]", []string(ticket.Accounts))
	}
}

// 回歸：常設為全部帳號者破窗範圍不變。
func TestBreakGlassStandingAllUnchanged(t *testing.T) {
	s, policies, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	setStanding(t, db, 1, 1)
	enableBreakGlass(t, policies)
	req, err := s.BreakGlass(1, "requester", false, 1, "incident")
	if err != nil {
		t.Fatal(err)
	}
	var ticket model.AssetAuthorization
	if err := db.First(&ticket, *req.AuthorizationID).Error; err != nil {
		t.Fatal(err)
	}
	if !ticket.Accounts.IsAll() {
		t.Fatalf("ticket accounts = %v, want all", []string(ticket.Accounts))
	}
}
