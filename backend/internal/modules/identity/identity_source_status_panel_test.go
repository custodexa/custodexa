package identity_test

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 狀態彙總為檢核面板新增的觀測時間與登入測試連結。

// TestStatusGroupSnapshotTimeNotLastLogin 群組燈的時間取快照時間，不是帳號的最近登入時間。
func TestStatusGroupSnapshotTimeNotLastLogin(t *testing.T) {
	db := setupMappingDB(t)
	p := seedProviderWithID(t, db, 5)
	snapAt := time.Now().Add(-5 * time.Hour).Truncate(time.Second)
	loginAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	user := &model.User{
		Username: "alice", Password: "x", Active: true, ExternalCredential: true,
		LastLoginAt:          &loginAt,
		GroupSnapshotChannel: model.RoleMappingChannel(model.RoleMappingChannelKindProvider, p.ID),
		GroupSnapshotGroups:  `["ops"]`,
		GroupSnapshotAt:      &snapAt,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&model.UserExternalIdentity{UserID: user.ID, ProviderID: p.ID,
		Issuer: p.Issuer, ClientID: p.ClientID, Subject: "s"}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	st := providerStatus(t, db, 5)
	if st.LastLoginGroupsAt == nil || !st.LastLoginGroupsAt.Equal(snapAt) {
		t.Fatalf("last_login_groups_at = %v，want 快照時間 %v（不是最近登入 %v）", st.LastLoginGroupsAt, snapAt, loginAt)
	}
	if !st.GroupAttrConfigured {
		t.Fatal("設了群組宣告名時 group_attr_configured 應為 true")
	}
}

// TestStatusGroupsUnknownChannelExact 快照之後有讀不到完整群組的列時回其時間；
// provider:50 的列不被 provider 5 取到。
func TestStatusGroupsUnknownChannelExact(t *testing.T) {
	db := setupMappingDB(t)
	seedProviderWithID(t, db, 5)
	seedProviderWithID(t, db, 50)
	now := time.Now()
	unknown := func(at time.Time, channel string) {
		seedAuditRow(t, db, at, model.ResourceUser, model.ActionUpdate, model.StatusSuccess, 7, "alice",
			identity.RoleMappingSkipGroupsUnknown, map[string]any{"channel": channel})
	}
	unknown(now.Add(-3*time.Hour), "provider:5")
	unknown(now.Add(-time.Hour), "provider:50")
	st := providerStatus(t, db, 5)
	if st.GroupsUnknownAt == nil {
		t.Fatal("groups_unknown_at = null，want provider 5 那一列的時間")
	}
	if st.GroupsUnknownAt.After(now.Add(-2 * time.Hour)) {
		t.Fatalf("groups_unknown_at = %v，取到了 provider:50 的列", st.GroupsUnknownAt)
	}
	if other := providerStatus(t, db, 50); other.GroupsUnknownAt == nil ||
		other.GroupsUnknownAt.Before(now.Add(-2*time.Hour)) {
		t.Fatalf("provider 50 應取到自己的列：%v", other.GroupsUnknownAt)
	}
}

// TestStatusGroupAttrUnconfigured 群組宣告名為空時 group_attr_configured=false。
func TestStatusGroupAttrUnconfigured(t *testing.T) {
	db := setupMappingDB(t)
	p := seedMappingProvider(t, db, "", "openid")
	if st := providerStatus(t, db, p.ID); st.GroupAttrConfigured {
		t.Fatal("未設群組宣告名時 group_attr_configured 應為 false")
	}
}

// TestStatusLoginTestState 基準網址未設、來源停用、正常三種登入測試狀態。
func TestStatusLoginTestState(t *testing.T) {
	db := setupMappingDB(t)
	p := seedProviderWithID(t, db, 5)
	svc := identity.NewIdentitySourceService(db, audit.NewTxSink())

	st, err := svc.ProviderStatus(p.ID)
	if err != nil {
		t.Fatalf("狀態彙總: %v", err)
	}
	if st.LoginTestState != identity.LoginTestStateBaseURLUnset || st.LoginTestURL != nil {
		t.Fatalf("未設基準網址：state=%q url=%v", st.LoginTestState, st.LoginTestURL)
	}

	svc.SetPublicBaseURL("https://bastion.example.com/")
	st, _ = svc.ProviderStatus(p.ID)
	if st.LoginTestState != identity.LoginTestStateReady || st.LoginTestURL == nil ||
		*st.LoginTestURL != "https://bastion.example.com/login?source=oidc:5" {
		t.Fatalf("正常：state=%q url=%v", st.LoginTestState, st.LoginTestURL)
	}

	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).Update("enabled", false).Error; err != nil {
		t.Fatalf("disable: %v", err)
	}
	st, _ = svc.ProviderStatus(p.ID)
	if st.LoginTestState != identity.LoginTestStateSourceDisabled || st.LoginTestURL != nil {
		t.Fatalf("停用：state=%q url=%v", st.LoginTestState, st.LoginTestURL)
	}
}

// TestStatusDiscoveryCheckedAtNullAndNoDial 快取不存在時 discovery_checked_at 為 null，
// 且整個狀態查詢不對外撥號（對端被打次數為 0）。
func TestStatusDiscoveryCheckedAtNullAndNoDial(t *testing.T) {
	db := setupMappingDB(t)
	srv, hits := newDiscoveryServer(t)
	p := &model.OIDCProvider{Name: "dex", Issuer: srv.URL, ClientID: "cid", Scopes: "openid groups",
		GroupsClaim: "groups", Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, ClientSecretEnc: "enc"}
	if err := db.Create(p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	svc := identity.NewIdentitySourceService(db, audit.NewTxSink())
	svc.SetDiscovery(identity.NewOIDCDiscoveryService(testEgress()))
	svc.SetPublicBaseURL("https://bastion.example.com")
	st, err := svc.ProviderStatus(p.ID)
	if err != nil {
		t.Fatalf("狀態彙總: %v", err)
	}
	if st.DiscoveryCheckedAt != nil {
		t.Fatalf("快取不存在時 discovery_checked_at = %v，want null", st.DiscoveryCheckedAt)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("狀態查詢撥號了 %d 次，want 0", got)
	}
}
