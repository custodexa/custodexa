package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

func addGroupGrant(t *testing.T, db *gorm.DB, groupID, assetID uint, accounts ...string) {
	t.Helper()
	g, a := groupID, assetID
	row := model.AssetAuthorization{UserGroupID: &g, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 3, Source: model.AuthorizationSourceManual}
	if len(accounts) > 0 {
		row.Accounts = model.NormalizeAccountScope(accounts)
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
}

func newGroupWithMember(t *testing.T, db *gorm.DB, name string, userID uint) uint {
	t.Helper()
	g := model.UserGroup{Name: name}
	if err := db.Create(&g).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO user_group_members (user_group_id, user_id) VALUES (?, ?)", g.ID, userID).Error; err != nil {
		t.Fatal(err)
	}
	return g.ID
}

// 常設帳號範圍上界的查詢：個人與群組聯集、任一全部帳號、過期不計、臨時授權不計、節點授權計入。
func TestStandingAccountScopes(t *testing.T) {
	bound := func(t *testing.T, s *AccessRequestService, db *gorm.DB, subject, asset uint) (model.AccountScope, bool) {
		t.Helper()
		got, err := s.standingBoundsOf(db, []uint{subject}, []uint{asset}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		scope, ok := got[standingKey{subject, asset}]
		return scope, ok
	}
	t.Run("personal and group union", func(t *testing.T) {
		s, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		setStanding(t, db, 1, 1, "app")
		gid := newGroupWithMember(t, db, "ops", 1)
		addGroupGrant(t, db, gid, 1, "ops")
		scope, ok := bound(t, s, db, 1, 1)
		if !ok || !scopeIs(scope, "app", "ops") {
			t.Fatalf("scope=%v found=%v", scope, ok)
		}
	})
	t.Run("any all-accounts grant makes the bound all accounts", func(t *testing.T) {
		s, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		setStanding(t, db, 1, 1, "app")
		gid := newGroupWithMember(t, db, "ops", 1)
		addGroupGrant(t, db, gid, 1)
		scope, ok := bound(t, s, db, 1, 1)
		if !ok || !scope.IsAll() {
			t.Fatalf("scope=%v found=%v", scope, ok)
		}
	})
	t.Run("expired grant is ignored", func(t *testing.T) {
		s, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		setStanding(t, db, 1, 1, "app")
		past := time.Now().Add(-time.Hour)
		a := uint(1)
		// 過期列（全部帳號）與現行列並存：唯一索引只擋同組合的常設列，故改掛在群組上
		g := newGroupWithMember(t, db, "old", 1)
		if err := db.Create(&model.AssetAuthorization{UserGroupID: &g, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 3,
			Source: model.AuthorizationSourceManual, DateExpired: &past}).Error; err != nil {
			t.Fatal(err)
		}
		scope, ok := bound(t, s, db, 1, 1)
		if !ok || !scopeIs(scope, "app") {
			t.Fatalf("scope=%v found=%v", scope, ok)
		}
	})
	t.Run("ticket grant is ignored", func(t *testing.T) {
		s, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		setStanding(t, db, 1, 1, "app")
		u, a := uint(1), uint(1)
		start, end := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
		if err := db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 3,
			Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &end}).Error; err != nil {
			t.Fatal(err)
		}
		scope, ok := bound(t, s, db, 1, 1)
		if !ok || !scopeIs(scope, "app") {
			t.Fatalf("scope=%v found=%v", scope, ok)
		}
	})
	t.Run("ticket only is not standing", func(t *testing.T) {
		s, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		clearDirectGrants(t, db, 1, 1)
		u, a := uint(1), uint(1)
		start, end := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
		if err := db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 3,
			Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &end}).Error; err != nil {
			t.Fatal(err)
		}
		if scope, ok := bound(t, s, db, 1, 1); ok {
			t.Fatalf("ticket-only user found standing scope %v", scope)
		}
	})
	t.Run("view grant is not standing connect", func(t *testing.T) {
		s, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		setViewOnly(t, db, 1, 1)
		if scope, ok := bound(t, s, db, 1, 1); ok {
			t.Fatalf("view-only user found standing scope %v", scope)
		}
	})
	t.Run("asset node grant covers the asset below it", func(t *testing.T) {
		s, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		clearDirectGrants(t, db, 1, 1)
		clearDirectGrants(t, db, 1, 2)
		u, node := uint(1), uint(1)
		if err := db.Create(&model.AssetAuthorization{UserID: &u, AssetGroupID: &node, Permission: model.PermissionConnect, GrantedBy: 3,
			Source: model.AuthorizationSourceManual, Accounts: model.NormalizeAccountScope([]string{"svc"})}).Error; err != nil {
			t.Fatal(err)
		}
		if scope, ok := bound(t, s, db, 1, 1); !ok || !scopeIs(scope, "svc") {
			t.Fatalf("asset 1 scope=%v found=%v", scope, ok)
		}
		if _, ok := bound(t, s, db, 1, 2); ok {
			t.Fatal("asset 2 is outside the node")
		}
	})
	t.Run("several subjects and assets in one query", func(t *testing.T) {
		s, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		setStanding(t, db, 1, 1, "app")
		setStanding(t, db, 4, 1, "ops")
		setStanding(t, db, 4, 2)
		clearDirectGrants(t, db, 1, 2)
		got, err := s.standingBoundsOf(db, []uint{1, 4}, []uint{1, 2}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !scopeIs(got[standingKey{1, 1}], "app") || !scopeIs(got[standingKey{4, 1}], "ops") || !got[standingKey{4, 2}].IsAll() {
			t.Fatalf("bounds = %v", got)
		}
		if _, ok := got[standingKey{1, 2}]; ok {
			t.Fatal("user 1 has no grant on asset 2 after its grants were cleared")
		}
	})
}

// 零列輸入回 not-found，不得回空範圍（空範圍即全部帳號）。
func TestStandingScopeUnionZeroRows(t *testing.T) {
	scope, ok := unionStandingScope(nil)
	if ok || len(scope) != 0 {
		t.Fatalf("zero rows: scope=%v found=%v", scope, ok)
	}
	scope, ok = unionStandingScope([]model.AccountScope{})
	if ok {
		t.Fatalf("empty slice: scope=%v found=%v", scope, ok)
	}
	// 一列但值為空（舊資料的空值＝全部帳號）要被視為找到且為全部帳號
	scope, ok = unionStandingScope([]model.AccountScope{nil})
	if !ok || !scope.IsAll() {
		t.Fatalf("one all-accounts row: scope=%v found=%v", scope, ok)
	}
	scope, ok = unionStandingScope([]model.AccountScope{{"b"}, {"a", "b"}})
	if !ok || !scopeIs(scope, "a", "b") {
		t.Fatalf("named union: scope=%v found=%v", scope, ok)
	}
}

// 輔助模式：執行者只有檢視權時，回應與「執行者不存在」完全相同。
func TestAssistedExecutorViewOnlySameEnvelope(t *testing.T) {
	s, _, db, agent := setupItemRequestEnv(t)
	setStanding(t, db, 4, 1)
	setViewOnly(t, db, agent, 1)
	names := []string{"app"}
	in := func(executor uint) SubmitAccessRequestInput {
		return SubmitAccessRequestInput{AssetID: 1, Accounts: &names, Reason: "task", DurationMinutes: 60, ExecutorUserID: &executor}
	}
	_, viewOnlyErr := s.Submit(4, "requester2", false, in(agent))
	_, missingErr := s.Submit(4, "requester2", false, in(9999))
	if !errors.Is(viewOnlyErr, ErrAccessRequestNotFound) || viewOnlyErr != missingErr {
		t.Fatalf("view-only executor err=%v, missing executor err=%v", viewOnlyErr, missingErr)
	}
	assertNothingCreated(t, db)
}
