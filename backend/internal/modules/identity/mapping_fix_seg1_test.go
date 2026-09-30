package identity

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

func TestLDAPGroupOnlyRemovalIssuesCurrentEpoch(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		t.Run(map[bool]string{false: "formal", true: "mfa_enrollment"}[mfa], func(t *testing.T) {
			auth, policies, db := setupRoleMappingEnv(t)
			user := roleMappingUser(t, db, "testldap")
			if err := db.Create(&model.LDAPDirectory{Singleton: 1, Name: "directory", URL: "ldaps://ldap.example.test:636", BaseDN: "dc=example,dc=test", UserFilter: "(uid=%s)", AttrGroup: "memberOf", BindPasswordEnc: "enc", Enabled: true}).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.AutoMigrate(&model.Asset{}, &model.AssetGroup{}, &model.AssetAuthorization{}, &model.ApproverScope{}); err != nil {
				t.Fatal(err)
			}
			group := model.UserGroup{Name: "operators"}
			if err := db.Create(&group).Error; err != nil {
				t.Fatal(err)
			}
			service := NewIdentitySourceService(db, audit.NewTxSink())
			if _, err := service.CreateUserGroupMapping(model.RoleMappingChannelKindDirectory, 1, UserGroupMappingInput{
				MatchValue: roleMappingInnerGroup, UserGroupID: group.ID, RiskAcknowledged: true,
				Actor: GroupRoleMappingActor{ID: user.ID, Name: user.Username},
			}); err != nil {
				t.Fatal(err)
			}
			auth.SetLDAPResolver(mappingResolver(1, "memberOf", ldapInfoWithGroups(user.Username, roleMappingInnerGroup)))
			if _, err := auth.Login(&LoginRequest{Username: user.Username, Password: "pass"}); err != nil {
				t.Fatal(err)
			}
			before := credentialEpochOf(t, db, user.ID)
			if mfa {
				auth.mfaCrypto = aesColumnCodec(t, testMFAKey)
				if _, err := policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin"); err != nil {
					t.Fatal(err)
				}
			}
			auth.SetLDAPResolver(mappingResolver(1, "memberOf", ldapInfoWithGroups(user.Username)))
			resp, err := auth.Login(&LoginRequest{Username: user.Username, Password: "pass"})
			if err != nil {
				t.Fatal(err)
			}
			after := credentialEpochOf(t, db, user.ID)
			if after != before+1 {
				t.Fatalf("世代 %d -> %d", before, after)
			}
			token := resp.Token
			if mfa {
				token = resp.EnrollmentToken
			}
			if token == "" {
				t.Fatal("本次憑證未簽出")
			}
			claims, err := auth.ValidateToken(token)
			if err != nil {
				t.Fatalf("本次憑證不可驗證: %v", err)
			}
			if claims.CredEpoch != after {
				t.Fatalf("本次憑證世代=%d, want %d", claims.CredEpoch, after)
			}
			if mfa {
				if _, err := auth.EnrollmentSetup(token); err != nil {
					t.Fatalf("MFA 憑證不可兌換: %v", err)
				}
			} else if _, err := auth.ValidateConnectionToken(token); err != nil {
				t.Fatalf("正式憑證不可兌換: %v", err)
			}
		})
	}
}

func TestOIDCGroupOnlyRemovalTicketCurrentEpoch(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	db := login.db
	if err := db.Model(p).Update("groups_claim", "groups").Error; err != nil {
		t.Fatal(err)
	}
	p.GroupsClaim = "groups"
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetGroup{}, &model.AssetAuthorization{}, &model.ApproverScope{}); err != nil {
		t.Fatal(err)
	}
	group := model.UserGroup{Name: "operators"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatal(err)
	}
	service := NewIdentitySourceService(db, audit.NewTxSink())
	if _, err := service.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, p.ID, UserGroupMappingInput{
		MatchValue: oidcMappingGroup, UserGroupID: group.ID, RiskAcknowledged: true,
		Actor: GroupRoleMappingActor{ID: 1, Name: "admin"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := oidcLoginOnce(t, login, idp, p, "code-1", "sub-1", mappingClaims(map[string]any{"groups": []any{oidcMappingGroup}})); err != nil {
		t.Fatal(err)
	}
	before := oidcUserByName(t, db, "bob")
	res, err := oidcLoginOnce(t, login, idp, p, "code-2", "sub-1", mappingClaims(map[string]any{"groups": []any{}}))
	if err != nil {
		t.Fatal(err)
	}
	after := oidcUserByName(t, db, "bob")
	if after.CredentialEpoch != before.CredentialEpoch+1 {
		t.Fatalf("世代 %d -> %d", before.CredentialEpoch, after.CredentialEpoch)
	}
	var ticket model.OIDCLoginTicket
	if err := db.Where("token_hash=?", sha256Hex(res.Ticket)).First(&ticket).Error; err != nil {
		t.Fatal(err)
	}
	if ticket.CredEpoch != after.CredentialEpoch {
		t.Fatalf("本次票世代=%d, want %d", ticket.CredEpoch, after.CredentialEpoch)
	}
	if _, _, err := login.Exchange(res.Ticket, "browser-secret"); err != nil {
		t.Fatalf("本次票不可兌換: %v", err)
	}
}

func TestProviderDisableRereadsStateAfterEnableAndLogin(t *testing.T) {
	f := newMappingSegmentFixture(t)
	f.groupRule(t, "a")
	if err := f.db.Model(&model.OIDCProvider{}).Where("id=?", f.provider.ID).Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	service := NewOIDCProviderService(f.db, nil, &OIDCEgressPolicy{}, nil, "")
	service.SetMappingAuditSink(audit.NewTxSink())
	ready, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var first atomic.Bool
	if err := f.db.Callback().Query().After("gorm:query").Register("test:disable_prelock_barrier", func(tx *gorm.DB) {
		if tx.Statement.Table == "oidc_providers" && first.CompareAndSwap(false, true) {
			close(ready)
			<-release
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Callback().Query().Remove("test:disable_prelock_barrier") })
	disabled, enabled := false, true
	done := make(chan error, 1)
	go func() {
		_, err := service.Update(f.provider.ID, &OIDCProviderRequest{Enabled: &disabled, RiskAcknowledged: true})
		done <- err
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("停用未到預讀障礙點")
	}
	if _, err := service.Update(f.provider.ID, &OIDCProviderRequest{Enabled: &enabled, RiskAcknowledged: true}); err != nil {
		unblock()
		t.Fatal(err)
	}
	f.login(t, "a")
	if f.count(t, "user_group_mapping_rule_supports") != 1 {
		unblock()
		t.Fatal("交錯前提：啟用後登入未授權")
	}
	var before model.OIDCProvider
	if err := f.db.First(&before, f.provider.ID).Error; err != nil {
		unblock()
		t.Fatal(err)
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var after model.OIDCProvider
	if err := f.db.First(&after, f.provider.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Enabled || after.AuthEpoch != before.AuthEpoch+1 {
		t.Fatalf("來源停用失效狀態: enabled=%v epoch=%d -> %d", after.Enabled, before.AuthEpoch, after.AuthEpoch)
	}
	if f.count(t, "user_group_mapping_rule_supports") != 0 || f.count(t, "user_group_members") != 0 || f.epoch(t) != 1 {
		t.Fatal("停用提交後仍有映射支持或憑證未失效")
	}
}

func mappingAuditPayload(t *testing.T, f *mappingSegmentFixture, code string, index int) map[string]any {
	t.Helper()
	var rows []model.AuditLog
	if err := f.db.Where("error_msg=?", code).Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) <= index {
		t.Fatalf("%s 審計只有 %d 列", code, len(rows))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(rows[index].Details), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func assertSupportDelta(t *testing.T, payload map[string]any, key string, ruleID, targetID uint, value, direction string) {
	t.Helper()
	items, ok := payload[key].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("%s=%v，應有一筆支持變動", key, payload[key])
	}
	item, ok := items[0].(map[string]any)
	if !ok || item["rule_id"] != float64(ruleID) || item["target_id"] != float64(targetID) || item["external_group"] != value || item["direction"] != direction {
		t.Fatalf("%s[0]=%v，應記規則、原始群組、目標與方向", key, items[0])
	}
}

func TestMappingSupportAuditIdentifiesRuleAndDirection(t *testing.T) {
	f := newMappingSegmentFixture(t)
	roleRule := f.roleRule(t, "a")
	groupRule := f.groupRule(t, "a")
	f.login(t, "a")
	assertSupportDelta(t, mappingAuditPayload(t, f, RoleMappingEventApplied, 0), "support_changes", roleRule, f.role.ID, "a", "add")
	assertSupportDelta(t, mappingAuditPayload(t, f, UserGroupMappingEventApplied, 0), "support_changes", groupRule, f.group.ID, "a", "add")
	f.login(t)
	assertSupportDelta(t, mappingAuditPayload(t, f, RoleMappingEventApplied, 1), "support_changes", roleRule, f.role.ID, "a", "remove")
	assertSupportDelta(t, mappingAuditPayload(t, f, UserGroupMappingEventApplied, 1), "support_changes", groupRule, f.group.ID, "a", "remove")
}

func TestMappingSourceRevocationAuditIdentifiesBothSupports(t *testing.T) {
	f := newMappingSegmentFixture(t)
	roleRule := f.roleRule(t, "a")
	groupRule := f.groupRule(t, "a")
	f.login(t, "a")
	service := NewOIDCProviderService(f.db, nil, &OIDCEgressPolicy{}, nil, "")
	service.SetMappingAuditSink(audit.NewTxSink())
	disabled := false
	if _, err := service.Update(f.provider.ID, &OIDCProviderRequest{Enabled: &disabled, RiskAcknowledged: true}); err != nil {
		t.Fatal(err)
	}
	payload := mappingAuditPayload(t, f, MappingSourceRevokedEvent, 0)
	items, ok := payload["support_changes"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("來源撤權支持差異=%v, want 2", payload["support_changes"])
	}
	for _, want := range []struct {
		kind         string
		rule, target uint
	}{{"role", roleRule, f.role.ID}, {"user_group", groupRule, f.group.ID}} {
		found := false
		for _, raw := range items {
			item, ok := raw.(map[string]any)
			if ok && item["target_type"] == want.kind && item["rule_id"] == float64(want.rule) && item["target_id"] == float64(want.target) && item["external_group"] == "a" && item["direction"] == "remove" {
				found = true
			}
		}
		if !found {
			t.Fatalf("來源撤權缺 %s 規則 %d 的原始值、目標或方向: %v", want.kind, want.rule, items)
		}
	}
}

func TestUserGroupMappingRuleDisableRevokesSupport(t *testing.T) {
	for _, other := range []bool{false, true} {
		t.Run(map[bool]string{false: "last_support", true: "other_support"}[other], func(t *testing.T) {
			f := newMappingSegmentFixture(t)
			rule := f.groupRule(t, "a")
			if other {
				f.groupRule(t, "b")
			}
			f.login(t, "a", "b")
			if err := f.db.Create(&model.RefreshToken{UserID: f.user.ID, TokenHash: "hash", SessionStartedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), LastUsedAt: time.Now()}).Error; err != nil {
				t.Fatal(err)
			}
			before := f.epoch(t)
			falseValue := false
			input := UserGroupMappingInput{MatchValue: "a", UserGroupID: f.group.ID, Enabled: &falseValue, RiskAcknowledged: true, Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username}}
			if _, err := f.service.UpdateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, rule, input); err != nil {
				t.Fatal(err)
			}
			if got := f.count(t, "user_group_mapping_rule_supports"); got != map[bool]int64{false: 0, true: 1}[other] {
				t.Fatalf("剩餘支持=%d", got)
			}
			if got := f.count(t, "user_group_members"); got != map[bool]int64{false: 0, true: 1}[other] {
				t.Fatalf("有效成員=%d", got)
			}
			wantEpoch := before
			if !other {
				wantEpoch++
			}
			if f.epoch(t) != wantEpoch {
				t.Fatalf("世代=%d, want %d", f.epoch(t), wantEpoch)
			}
			var revoked int64
			f.db.Model(&model.RefreshToken{}).Where("user_id=? AND revoked_at IS NOT NULL", f.user.ID).Count(&revoked)
			if revoked != map[bool]int64{false: 1, true: 0}[other] {
				t.Fatalf("刷新憑證撤銷=%d", revoked)
			}
			assertSupportDelta(t, mappingAuditPayload(t, f, MappingRuleRevokedEvent, 0), "support_changes", rule, f.group.ID, "a", "remove")
		})
	}
	// 審計失敗必須回滾規則狀態與所有權限投影。
	f := newMappingSegmentFixture(t)
	rule := f.groupRule(t, "a")
	f.login(t, "a")
	f.service = NewIdentitySourceService(f.db, rejectMappingAudit{})
	falseValue := false
	_, err := f.service.UpdateUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, rule, UserGroupMappingInput{
		MatchValue: "a", UserGroupID: f.group.ID, Enabled: &falseValue, RiskAcknowledged: true,
		Actor: GroupRoleMappingActor{ID: f.user.ID, Name: f.user.Username},
	})
	if err == nil {
		t.Fatal("稽核失敗未回滾")
	}
	var row model.GroupUserGroupMapping
	if err := f.db.First(&row, rule).Error; err != nil {
		t.Fatal(err)
	}
	if !row.Enabled || f.count(t, "user_group_mapping_rule_supports") != 1 || f.count(t, "user_group_members") != 1 || f.epoch(t) != 0 {
		t.Fatal("停用稽核失敗留下部分狀態")
	}
}
