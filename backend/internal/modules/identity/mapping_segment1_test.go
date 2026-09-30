package identity

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type rejectMappingAudit struct{}

func (rejectMappingAudit) WriteInTx(*gorm.DB, port.AuditEvent) error {
	return errors.New("injected audit failure")
}

type countingMappingAudit struct {
	mu      sync.Mutex
	writes  int
	failAt  int
	ready   chan struct{}
	release chan struct{}
}

func (s *countingMappingAudit) WriteInTx(tx *gorm.DB, event port.AuditEvent) error {
	s.mu.Lock()
	s.writes++
	n := s.writes
	s.mu.Unlock()
	if n == 1 && s.ready != nil {
		close(s.ready)
		<-s.release
	}
	if s.failAt > 0 && n == s.failAt {
		return errors.New("injected mid-batch audit failure")
	}
	return audit.NewTxSink().WriteInTx(tx, event)
}

type mappingSegmentFixture struct {
	db       *gorm.DB
	service  *IdentitySourceService
	user     model.User
	provider model.OIDCProvider
	role     model.Role
	group    model.UserGroup
}

func newMappingSegmentFixture(t *testing.T) *mappingSegmentFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.UserGroupMember{}, &model.LDAPDirectory{}, &model.OIDCProvider{}, &model.UserExternalIdentity{}, &model.GroupRoleMapping{}, &model.ExternalGroup{}, &model.GroupUserGroupMapping{}, &model.UserRoleMapping{}, &model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.AuditLog{}, &model.RefreshToken{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetAuthorization{}, &model.ApproverScope{}); err != nil {
		t.Fatal(err)
	}
	f := &mappingSegmentFixture{db: db, service: NewIdentitySourceService(db, audit.NewTxSink())}
	f.user = model.User{Username: "demo", Password: "x", Active: true, IsLDAP: true}
	if err := db.Create(&f.user).Error; err != nil {
		t.Fatal(err)
	}
	f.provider = model.OIDCProvider{Name: "demo-provider", Issuer: "https://idp.example.test", ClientID: "demo", GroupsClaim: "groups", Enabled: true}
	if err := db.Create(&f.provider).Error; err != nil {
		t.Fatal(err)
	}
	f.role = model.Role{Name: "auditor"}
	if err := db.Create(&f.role).Error; err != nil {
		t.Fatal(err)
	}
	f.group = model.UserGroup{Name: "operators"}
	if err := db.Create(&f.group).Error; err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *mappingSegmentFixture) roleRule(t *testing.T, value string) uint {
	t.Helper()
	v, err := f.service.CreateMapping(model.RoleMappingChannelKindProvider, f.provider.ID, GroupRoleMappingInput{MatchValue: value, Role: f.role.Name, RiskAcknowledged: true, Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}})
	if err != nil {
		t.Fatal(err)
	}
	return v.ID
}
func (f *mappingSegmentFixture) groupRule(t *testing.T, value string) uint {
	t.Helper()
	r, err := f.service.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, UserGroupMappingInput{MatchValue: value, UserGroupID: f.group.ID, RiskAcknowledged: true, Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}
func (f *mappingSegmentFixture) login(t *testing.T, groups ...string) RoleMappingOutcome {
	t.Helper()
	out, err := RecomputeMappedRoles(f.db, audit.NewTxSink(), &f.user, GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: f.provider.ID, State: GroupObservationKnown, Groups: groups})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func (f *mappingSegmentFixture) count(t *testing.T, table string) int64 {
	t.Helper()
	var n int64
	if err := f.db.Table(table).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}
func (f *mappingSegmentFixture) epoch(t *testing.T) int {
	t.Helper()
	var u model.User
	if err := f.db.First(&u, f.user.ID).Error; err != nil {
		t.Fatal(err)
	}
	return u.CredentialEpoch
}

// The fixture has one SQLite connection. A higher WaitCount proves the second
// operation reached the database while the first transaction held the source
// lock, instead of merely being scheduled after that transaction committed.
func (f *mappingSegmentFixture) connectionWaitCount(t *testing.T) int64 {
	t.Helper()
	sqlDB, err := f.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	return sqlDB.Stats().WaitCount
}

func (f *mappingSegmentFixture) awaitConnectionWait(t *testing.T, before int64) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if f.connectionWaitCount(t) > before {
			return
		}
		select {
		case <-deadline:
			t.Fatal("並發操作未到達資料庫等待障礙點")
		case <-tick.C:
		}
	}
}

func TestMappingAuditOverlappingSupportChange(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "a")
	f.roleRule(t, "b")
	f.login(t, "a", "b")
	epoch := f.epoch(t)
	out := f.login(t, "b")
	if out.Changed() || out.EpochBumped || f.epoch(t) != epoch {
		t.Fatalf("重疊支持不應移除有效角色或推世代: %+v", out)
	}
	if n := f.count(t, "user_role_mapping_rule_supports"); n != 1 {
		t.Fatalf("支持數=%d", n)
	}
	var n int64
	f.db.Model(&model.AuditLog{}).Where("error_msg=?", RoleMappingEventApplied).Count(&n)
	if n != 2 {
		t.Fatalf("支持縮減仍須稽核，事件=%d", n)
	}
}

func TestMappingAuditFailureRollsBackLogin(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "a")
	f.groupRule(t, "a")
	_, err := RecomputeMappedRoles(f.db, rejectMappingAudit{}, &f.user, GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: f.provider.ID, State: GroupObservationKnown, Groups: []string{"a"}})
	if err == nil {
		t.Fatal("稽核失敗未傳回")
	}
	for _, table := range []string{"user_role_mapping_rule_supports", "user_group_mapping_rule_supports", "user_group_members", "user_role_mappings", "user_roles"} {
		if n := f.count(t, table); n != 0 {
			t.Fatalf("%s 在稽核失敗後仍有 %d 列", table, n)
		}
	}
}

func TestMappingAuditUnknownSkip(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "a")
	f.login(t, "a")
	_, err := RecomputeMappedRoles(f.db, audit.NewTxSink(), &f.user, GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: f.provider.ID, State: GroupObservationUnknown})
	if err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "user_role_mapping_rule_supports"); n != 1 {
		t.Fatalf("未知觀測撤了支持: %d", n)
	}
	var n int64
	f.db.Model(&model.AuditLog{}).Where("error_msg=?", RoleMappingSkipGroupsUnknown).Count(&n)
	if n != 1 {
		t.Fatalf("跳過稽核=%d", n)
	}
}

func TestMappingAuditUnconfiguredUserGroupSkip(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.groupRule(t, "a")
	out, err := RecomputeMappedRoles(f.db, audit.NewTxSink(), &f.user, GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: f.provider.ID, State: GroupObservationUnconfigured})
	if err != nil {
		t.Fatal(err)
	}
	if out.Skipped != RoleMappingSkipSourceAttrUnset {
		t.Fatalf("未設定群組宣告但有群組規則時應留跳過事件: %+v", out)
	}
	var n int64
	if err := f.db.Model(&model.AuditLog{}).Where("error_msg=?", RoleMappingSkipSourceAttrUnset).Count(&n).Error; err != nil || n != 1 {
		t.Fatalf("跳過稽核數=%d err=%v", n, err)
	}
}

func TestRoleMappingRuleRevocationPreservesOtherSupport(t *testing.T) {
	f := newMappingSegmentFixture(t)
	a := f.roleRule(t, "a")
	f.roleRule(t, "b")
	f.login(t, "a", "b")
	epoch := f.epoch(t)
	if err := f.service.DeleteMapping(model.RoleMappingChannelKindProvider, f.provider.ID, a, GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "user_role_mapping_rule_supports"); n != 1 {
		t.Fatalf("剩餘支持=%d", n)
	}
	if n := f.count(t, "user_roles"); n != 1 {
		t.Fatalf("有效角色=%d", n)
	}
	if f.epoch(t) != epoch {
		t.Fatal("仍有支持卻推進世代")
	}
}

func TestUserGroupMappingRuleRevocationPreservesOtherSupport(t *testing.T) {
	f := newMappingSegmentFixture(t)
	a := f.groupRule(t, "a")
	f.groupRule(t, "b")
	f.login(t, "a", "b")
	epoch := f.epoch(t)
	if err := f.service.DeleteUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, a, GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "user_group_mapping_rule_supports"); n != 1 {
		t.Fatalf("剩餘支持=%d", n)
	}
	if n := f.count(t, "user_group_members"); n != 1 {
		t.Fatalf("有效成員=%d", n)
	}
	if f.epoch(t) != epoch {
		t.Fatal("仍有支持卻推進世代")
	}
}

func TestUserGroupMappingManualAndOtherChannelSupport(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.groupRule(t, "a")
	f.login(t, "a")
	second := model.OIDCProvider{Name: "second", Issuer: "https://second.example.test", ClientID: "second", GroupsClaim: "groups", Enabled: true}
	if err := f.db.Create(&second).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, second.ID, UserGroupMappingInput{MatchValue: "a", UserGroupID: f.group.ID, RiskAcknowledged: true, Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecomputeMappedRoles(f.db, audit.NewTxSink(), &f.user, GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: second.ID, State: GroupObservationKnown, Groups: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "user_group_mapping_rule_supports") != 2 || f.count(t, "user_group_members") != 1 {
		t.Fatal("兩通道未合成一筆有效成員")
	}
	f.login(t)
	if f.count(t, "user_group_mapping_rule_supports") != 1 || f.count(t, "user_group_members") != 1 || f.epoch(t) != 0 {
		t.Fatal("撤第一通道時損及第二通道有效成員")
	}
	s := NewUserGroupService(f.db, audit.NewTxSink(), nil)
	ids := []uint{f.user.ID}
	if _, err := s.ReplaceMembersDetailed(f.group.ID, &ids, nil, f.user.ID, f.user.Username, "system"); err != nil {
		t.Fatal(err)
	}
	if _, err := RecomputeMappedRoles(f.db, audit.NewTxSink(), &f.user, GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: second.ID, State: GroupObservationKnown}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "user_group_mapping_rule_supports") != 0 || f.count(t, "user_group_members") != 1 || f.epoch(t) != 0 {
		t.Fatal("撤第二通道時損及手動成員")
	}
	noMembers := []uint{}
	if _, err := s.ReplaceMembersDetailed(f.group.ID, &noMembers, nil, f.user.ID, f.user.Username, "system"); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "user_group_members") != 0 || f.epoch(t) != 1 {
		t.Fatal("最後手動支持移除後未撤權")
	}
}

func TestMappingEditIdentity(t *testing.T) {
	f := newMappingSegmentFixture(t)
	old := f.roleRule(t, "a")
	f.login(t, "a")
	next, err := f.service.UpdateMapping(model.RoleMappingChannelKindProvider, f.provider.ID, old, GroupRoleMappingInput{MatchValue: "b", Role: f.role.Name, Enabled: func() *bool { v := true; return &v }(), RiskAcknowledged: true, Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}})
	if err != nil {
		t.Fatal(err)
	}
	if next.ID == old {
		t.Fatal("規則身分編輯未換新列")
	}
	if n := f.count(t, "user_role_mapping_rule_supports"); n != 0 {
		t.Fatalf("舊支持=%d", n)
	}
	if n := f.count(t, "user_roles"); n != 0 {
		t.Fatalf("舊角色未即時收回: %d", n)
	}
	f.login(t, "b")
	if n := f.count(t, "user_role_mapping_rule_supports"); n != 1 {
		t.Fatalf("新支持下次登入未建立: %d", n)
	}
}

func TestMappingLoginRevokesAndIssuesCurrentEpoch(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "a")
	f.groupRule(t, "a")
	f.login(t, "a")
	if err := f.db.Create(&model.RefreshToken{UserID: f.user.ID, TokenHash: "hash", SessionStartedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), LastUsedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	out := f.login(t)
	if !out.EpochBumped || f.epoch(t) == 0 {
		t.Fatalf("縮權未推進世代: %+v", out)
	}
	var n int64
	f.db.Model(&model.RefreshToken{}).Where("user_id=? AND revoked_at IS NOT NULL", f.user.ID).Count(&n)
	if n != 1 {
		t.Fatalf("更新憑證未撤: %d", n)
	}
}

func TestMappingLoginRereadsDisabledSourceUnderLock(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "a")
	if err := f.db.Model(&model.OIDCProvider{}).Where("id=?", f.provider.ID).Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	out := f.login(t, "a")
	if out.Skipped != MappingSkipSourceDisabled || f.count(t, "user_role_mapping_rule_supports") != 0 {
		t.Fatalf("停用來源仍授權: %+v", out)
	}
}

func TestUserGroupMembersManualFieldPreservesMapped(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.groupRule(t, "a")
	f.login(t, "a")
	s := NewUserGroupService(f.db, audit.NewTxSink(), nil)
	empty := []uint{}
	if _, err := s.ReplaceMembersDetailed(f.group.ID, &empty, nil, f.user.ID, f.user.Username, "system"); err != nil {
		t.Fatal(err)
	}
	var m model.UserGroupMember
	if err := f.db.First(&m, "user_group_id=? AND user_id=?", f.group.ID, f.user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if m.Manual {
		t.Fatal("映射成員被標為手動")
	}
}

func TestUserGroupMembersLegacyGetPutRoundTrip(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.groupRule(t, "a")
	f.login(t, "a")
	s := NewUserGroupService(f.db, audit.NewTxSink(), nil)
	groups, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].MappedUserIDs) != 1 || len(groups[0].ManualUserIDs) != 0 || len(groups[0].MemberSources) != 1 || groups[0].MemberSources[0].Manual || !groups[0].MemberSources[0].Mapped {
		t.Fatalf("GET 來源欄=%+v", groups)
	}
	if _, err := s.ReplaceMembers(f.group.ID, groups[0].UserIDs); err != nil {
		t.Fatal(err)
	}
	f.login(t)
	if n := f.count(t, "user_group_members"); n != 0 {
		t.Fatalf("legacy 回送把映射成員固定成手動: %d", n)
	}
}

func TestUserGroupMembersRemovalRevokesCredential(t *testing.T) {
	f := newMappingSegmentFixture(t)
	s := NewUserGroupService(f.db, audit.NewTxSink(), nil)
	ids := []uint{f.user.ID}
	if _, err := s.ReplaceMembersDetailed(f.group.ID, &ids, nil, f.user.ID, f.user.Username, "system"); err != nil {
		t.Fatal(err)
	}
	empty := []uint{}
	if _, err := s.ReplaceMembersDetailed(f.group.ID, &empty, nil, f.user.ID, f.user.Username, "system"); err != nil {
		t.Fatal(err)
	}
	if f.epoch(t) == 0 || f.count(t, "user_group_members") != 0 {
		t.Fatal("移除最後手動支持未撤權")
	}
}

func TestSourceDisableMappingRevocationAllChannels(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "a")
	f.groupRule(t, "a")
	f.login(t, "a")
	providerSvc := NewOIDCProviderService(f.db, nil, &OIDCEgressPolicy{}, nil, "")
	providerSvc.SetMappingAuditSink(audit.NewTxSink())
	disabled := false
	if _, err := providerSvc.Update(f.provider.ID, &OIDCProviderRequest{Enabled: &disabled, RiskAcknowledged: true}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "user_role_mapping_rule_supports") != 0 || f.count(t, "user_group_mapping_rule_supports") != 0 || f.count(t, "user_group_members") != 0 {
		t.Fatal("provider 停用後仍有支持或成員")
	}
	if f.epoch(t) == 0 {
		t.Fatal("provider 停用未推進使用者世代")
	}

	// The directory channel is independent of the provider channel.
	dir := model.LDAPDirectory{Singleton: 1, Name: "directory", URL: "ldaps://ldap.example.test:636", BaseDN: "dc=example,dc=test", UserFilter: "(uid=%s)", AttrGroup: "memberOf", BindPasswordEnc: "enc", Enabled: true}
	if err := f.db.Create(&dir).Error; err != nil {
		t.Fatal(err)
	}
	actor := GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}
	if _, err := f.service.CreateMapping(model.RoleMappingChannelKindDirectory, dir.ID, GroupRoleMappingInput{MatchValue: "cn=a,dc=example,dc=test", Role: f.role.Name, RiskAcknowledged: true, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.CreateUserGroupMapping(model.RoleMappingChannelKindDirectory, dir.ID, UserGroupMappingInput{MatchValue: "cn=a,dc=example,dc=test", UserGroupID: f.group.ID, RiskAcknowledged: true, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecomputeMappedRoles(f.db, audit.NewTxSink(), &f.user, GroupObservation{Kind: model.RoleMappingChannelKindDirectory, SourceID: dir.ID, State: GroupObservationKnown, Groups: []string{"cn=a,dc=example,dc=test"}}); err != nil {
		t.Fatal(err)
	}
	if err := WithLDAPDirectoryLock(f.db, func(tx *gorm.DB) error {
		if err := tx.Model(&model.LDAPDirectory{}).Where("id=?", dir.ID).Update("enabled", false).Error; err != nil {
			return err
		}
		return revokeMappingSupportsLocked(tx, audit.NewTxSink(), model.RoleMappingChannelKindDirectory, dir.ID, "source", 0)
	}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "user_role_mapping_rule_supports") != 0 || f.count(t, "user_group_mapping_rule_supports") != 0 {
		t.Fatal("directory 停用後仍有支持")
	}
}

func TestSourceDisableMappingRevocationAuditFailureRollsBack(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "a")
	f.groupRule(t, "a")
	f.login(t, "a")
	providerSvc := NewOIDCProviderService(f.db, nil, &OIDCEgressPolicy{}, nil, "")
	providerSvc.SetMappingAuditSink(rejectMappingAudit{})
	disabled := false
	if _, err := providerSvc.Update(f.provider.ID, &OIDCProviderRequest{Enabled: &disabled, RiskAcknowledged: true}); err == nil {
		t.Fatal("稽核失敗未回滾")
	}
	var provider model.OIDCProvider
	if err := f.db.First(&provider, f.provider.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !provider.Enabled || f.count(t, "user_role_mapping_rule_supports") != 1 || f.count(t, "user_group_mapping_rule_supports") != 1 || f.epoch(t) != 0 {
		t.Fatal("停用失敗留下部分狀態")
	}
}

func TestMappingDeleteSourceRejectsLiveRules(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.groupRule(t, "a")
	providerSvc := NewOIDCProviderService(f.db, nil, &OIDCEgressPolicy{}, nil, "")
	providerSvc.SetMappingAuditSink(audit.NewTxSink())
	if err := providerSvc.Delete(f.provider.ID); !errors.Is(err, ErrOIDCProviderHasMappings) {
		t.Fatalf("仍有群組規則卻可刪來源: %v", err)
	}
	var provider model.OIDCProvider
	if err := f.db.First(&provider, f.provider.ID).Error; err != nil {
		t.Fatal(err)
	}
}

func TestMappingDeleteHistoryAndDictionaryOrder(t *testing.T) {
	f := newMappingSegmentFixture(t)
	a := f.roleRule(t, "a")
	b := f.groupRule(t, "a")
	actor := GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}
	if err := f.service.DeleteMapping(model.RoleMappingChannelKindProvider, f.provider.ID, a, actor); err != nil {
		t.Fatal(err)
	}
	if err := f.service.DeleteUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, b, actor); err != nil {
		t.Fatal(err)
	}
	providerSvc := NewOIDCProviderService(f.db, nil, &OIDCEgressPolicy{}, nil, "")
	providerSvc.SetMappingAuditSink(audit.NewTxSink())
	if err := providerSvc.Delete(f.provider.ID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"external_groups", "group_role_mappings", "group_user_group_mappings"} {
		var n int64
		f.db.Table(table).Count(&n)
		if n != 0 {
			t.Fatalf("刪來源後 %s 仍有 %d 列", table, n)
		}
	}
}

func TestMappingRevocationConcurrentLogin(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.roleRule(t, "a")
	f.groupRule(t, "a")
	f.login(t, "a")
	barrier := &countingMappingAudit{ready: make(chan struct{}), release: make(chan struct{})}
	disabled := false
	providerSvc := NewOIDCProviderService(f.db, nil, &OIDCEgressPolicy{}, nil, "")
	providerSvc.SetMappingAuditSink(barrier)
	disableDone := make(chan error, 1)
	go func() {
		_, err := providerSvc.Update(f.provider.ID, &OIDCProviderRequest{Enabled: &disabled, RiskAcknowledged: true})
		disableDone <- err
	}()
	select {
	case <-barrier.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("停用未到達撤權稽核障礙點")
	}
	loginDone := make(chan error, 1)
	waitBefore := f.connectionWaitCount(t)
	go func() {
		_, err := RecomputeMappedRoles(f.db, audit.NewTxSink(), &f.user, GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: f.provider.ID, State: GroupObservationKnown, Groups: []string{"a"}})
		loginDone <- err
	}()
	f.awaitConnectionWait(t, waitBefore)
	close(barrier.release)
	if err := <-disableDone; err != nil {
		t.Fatal(err)
	}
	if err := <-loginDone; err != nil {
		t.Fatal(err)
	}
	if f.count(t, "user_role_mapping_rule_supports") != 0 || f.count(t, "user_group_mapping_rule_supports") != 0 {
		t.Fatal("停用後的登入恢復了映射支持")
	}
}

func TestMappingSourceDeleteConcurrentRuleCreate(t *testing.T) {
	f := newMappingSegmentFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	oidcProviderPreWriteHook = func(site string) {
		if site == oidcSiteProviderInvalidate {
			close(entered)
			<-release
		}
	}
	t.Cleanup(func() { oidcProviderPreWriteHook = nil })
	providerSvc := NewOIDCProviderService(f.db, nil, &OIDCEgressPolicy{}, nil, "")
	providerSvc.SetMappingAuditSink(audit.NewTxSink())
	deleteDone := make(chan error, 1)
	go func() { deleteDone <- providerSvc.Delete(f.provider.ID) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("來源刪除未到達鎖內障礙點")
	}
	createDone := make(chan error, 1)
	waitBefore := f.connectionWaitCount(t)
	go func() {
		_, err := f.service.CreateMapping(model.RoleMappingChannelKindProvider, f.provider.ID, GroupRoleMappingInput{MatchValue: "a", Role: f.role.Name, RiskAcknowledged: true, Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}})
		createDone <- err
	}()
	f.awaitConnectionWait(t, waitBefore)
	close(release)
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if err := <-createDone; !errors.Is(err, ErrMappingSourceNotFound) {
		t.Fatalf("刪來源後建規則應失敗: %v", err)
	}
	if f.count(t, "group_role_mappings") != 0 || f.count(t, "external_groups") != 0 {
		t.Fatal("刪來源與建規則競態留下孤兒")
	}
}

func TestMappingLargeRevocationAtomicRollback(t *testing.T) {
	f := newMappingSegmentFixture(t)
	ruleID := f.roleRule(t, "a")
	channel := model.RoleMappingChannel(model.RoleMappingChannelKindProvider, f.provider.ID)
	const total = 128
	for i := 0; i < total; i++ {
		u := model.User{Username: fmt.Sprintf("bulk-%03d", i), Password: "x", Active: true, IsLDAP: true}
		if err := f.db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := GrantMappedRole(f.db, u.ID, f.role.ID, channel, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := f.db.Create(&model.UserRoleMappingRuleSupport{UserID: u.ID, RoleID: f.role.ID, Channel: channel, RuleID: ruleID}).Error; err != nil {
			t.Fatal(err)
		}
	}
	failure := &countingMappingAudit{failAt: 64}
	if err := withMappingSourceLock(f.db, model.RoleMappingChannelKindProvider, f.provider.ID, func(tx *gorm.DB) error {
		return revokeMappingSupportsLocked(tx, failure, model.RoleMappingChannelKindProvider, f.provider.ID, "role", ruleID)
	}); err == nil {
		t.Fatal("中途稽核失敗未回滾")
	}
	if n := f.count(t, "user_role_mapping_rule_supports"); n != total {
		t.Fatalf("批次失敗後只剩 %d/%d 支持", n, total)
	}
	if err := withMappingSourceLock(f.db, model.RoleMappingChannelKindProvider, f.provider.ID, func(tx *gorm.DB) error {
		return revokeMappingSupportsLocked(tx, audit.NewTxSink(), model.RoleMappingChannelKindProvider, f.provider.ID, "role", ruleID)
	}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "user_role_mapping_rule_supports") != 0 || f.count(t, "user_role_mappings") != 0 || f.count(t, "user_roles") != 0 {
		t.Fatal("重試後未完整撤權")
	}
}
