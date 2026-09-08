package identity_test

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 狀態彙總（檢核面板第二塊）與回呼網址揭露的測試。
//
// 三態欄位的斷言一律分「null」與「false」兩種情形：**不知道不得畫成綠色**，
// 而「還沒測過」與「測過但失敗」在介面上是不同顏色的燈。

// hasStatusWarning 狀態彙總是否回了指定的警告碼
func hasStatusWarning(warnings []identity.SourceStatusWarning, code string) bool {
	for _, w := range warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// TestSourceStatusSummaryOIDC 提供者的燈號一次回齊。
func TestSourceStatusSummaryOIDC(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())
	provider := seedMappingProvider(t, db, "groups", "openid groups")

	status, err := svc.ProviderStatus(provider.ID)
	if err != nil {
		t.Fatalf("狀態彙總: %v", err)
	}
	if !status.CredentialSet {
		t.Fatal("已設密鑰時 credential_set 應為 true")
	}
	// 尚無登入觀測：群組燈與時間皆為 null，不是「登入了但沒帶到群組」
	if status.LastLoginGroupsSeen != nil {
		t.Fatalf("尚無登入時 last_login_groups_seen = %v，want null", *status.LastLoginGroupsSeen)
	}
	if status.LastLoginAt != nil {
		t.Fatalf("尚無登入時 last_login_at = %v，want null", status.LastLoginAt)
	}
	// 未撥號過：探索燈為 null（狀態彙總不主動撥號）
	if status.DiscoveryReachable != nil {
		t.Fatalf("未探索過時 discovery_reachable = %v，want null", *status.DiscoveryReachable)
	}
	if status.RuleCount != 0 || status.EnabledRuleCount != 0 {
		t.Fatalf("規則數 = %d／%d，want 0／0", status.RuleCount, status.EnabledRuleCount)
	}
	if len(status.Warnings) != 0 {
		t.Fatalf("設定齊備時 warnings = %v，want 空", status.Warnings)
	}

	// 一條規則、一名經此途徑取得角色的帳號、一次帶群組的登入觀測
	if _, err := svc.CreateMapping(model.RoleMappingChannelKindProvider, provider.ID,
		mappingInput("ops", model.RoleUser, false)); err != nil {
		t.Fatalf("建立規則: %v", err)
	}
	now := time.Now()
	channel := model.RoleMappingChannel(model.RoleMappingChannelKindProvider, provider.ID)
	user := &model.User{
		Username: "alice", Password: "x", Active: true, ExternalCredential: true,
		LastLoginAt:          &now,
		GroupSnapshotChannel: channel,
		GroupSnapshotGroups:  `["ops","dev"]`,
		GroupSnapshotAt:      &now,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&model.UserExternalIdentity{
		UserID: user.ID, ProviderID: provider.ID, Issuer: provider.Issuer,
		ClientID: provider.ClientID, Subject: "sub-1",
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	if err := db.Create(&model.UserRoleMapping{
		UserID: user.ID, RoleID: 2, Channel: channel, MatchedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed mapping fact: %v", err)
	}

	status, err = svc.ProviderStatus(provider.ID)
	if err != nil {
		t.Fatalf("狀態彙總: %v", err)
	}
	if status.RuleCount != 1 || status.EnabledRuleCount != 1 {
		t.Fatalf("規則數 = %d／%d，want 1／1", status.RuleCount, status.EnabledRuleCount)
	}
	if status.LastRecomputeMatched != 1 {
		t.Fatalf("命中人數 = %d，want 1", status.LastRecomputeMatched)
	}
	if status.LastLoginGroupsSeen == nil || !*status.LastLoginGroupsSeen {
		t.Fatalf("last_login_groups_seen = %v，want true", status.LastLoginGroupsSeen)
	}
	if status.LastLoginGroupsCount != 2 {
		t.Fatalf("群組數 = %d，want 2", status.LastLoginGroupsCount)
	}
	if status.LastLoginAt == nil {
		t.Fatal("已有登入時 last_login_at 不應為 null")
	}
}

// TestSourceStatusSummaryDirectory 目錄的燈號（連線與群組屬性抽樣兩盞取自主動測試）。
func TestSourceStatusSummaryDirectory(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())
	dir := seedDirectory(t, db, "memberOf")

	status, err := svc.DirectoryStatus()
	if err != nil {
		t.Fatalf("狀態彙總: %v", err)
	}
	if !status.CredentialSet {
		t.Fatal("已設 bind 密碼時 credential_set 應為 true")
	}
	// 狀態彙總不撥號：兩盞取自連線測試的燈在未測過時是 null（灰），不是 false（黃）
	if status.ConnectionOK != nil {
		t.Fatalf("未測過時 connection_ok = %v，want null", *status.ConnectionOK)
	}
	if status.GroupAttrReadable != nil {
		t.Fatalf("未測過時 group_attr_readable = %v，want null", *status.GroupAttrReadable)
	}
	if len(status.Warnings) != 0 {
		t.Fatalf("設定齊備時 warnings = %v，want 空", status.Warnings)
	}

	// 目錄途徑的觀測快照只算本通道的（另一條途徑的快照不得混進來）
	now := time.Now()
	other := model.RoleMappingChannel(model.RoleMappingChannelKindProvider, 99)
	if err := db.Create(&model.User{
		Username: "bob", Password: "x", Active: true, IsLDAP: true, LastLoginAt: &now,
		GroupSnapshotChannel: other, GroupSnapshotGroups: `["x"]`, GroupSnapshotAt: &now,
	}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	status, err = svc.DirectoryStatus()
	if err != nil {
		t.Fatalf("狀態彙總: %v", err)
	}
	if status.LastLoginGroupsSeen != nil {
		t.Fatalf("他途徑的快照不得算進本來源：last_login_groups_seen = %v，want null",
			*status.LastLoginGroupsSeen)
	}
	if status.LastLoginAt == nil {
		t.Fatal("已有目錄帳號登入時 last_login_at 不應為 null")
	}
	_ = dir
}

// TestSourceStatusSummaryWarnsUnsetAttrWithRules 有啟用中的規則卻沒設群組屬性名／
// 宣告名時亮黃燈；另一格（設了宣告名卻沒帶 groups 授權範圍）同樣亮。
func TestSourceStatusSummaryWarnsUnsetAttrWithRules(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())

	dir := seedDirectory(t, db, "") // 未設群組屬性名
	if _, err := svc.CreateMapping(model.RoleMappingChannelKindDirectory, dir.ID,
		mappingInput("cn=ops,ou=groups,dc=example,dc=com", model.RoleUser, true)); err != nil {
		t.Fatalf("建立規則: %v", err)
	}
	dirStatus, err := svc.DirectoryStatus()
	if err != nil {
		t.Fatalf("目錄狀態: %v", err)
	}
	if !hasStatusWarning(dirStatus.Warnings, "MAPPING_SOURCE_ATTR_UNSET_WITH_RULES") {
		t.Fatalf("目錄 warnings = %v，want 含 MAPPING_SOURCE_ATTR_UNSET_WITH_RULES", dirStatus.Warnings)
	}

	// 設了宣告名卻沒帶 groups 授權範圍：規則不會命中任何人，且登入側沒有
	// 對應的跳過事件可依靠，這盞燈是唯一的訊號
	provider := seedMappingProvider(t, db, "groups", "openid email")
	provStatus, err := svc.ProviderStatus(provider.ID)
	if err != nil {
		t.Fatalf("提供者狀態: %v", err)
	}
	if !hasStatusWarning(provStatus.Warnings, "MAPPING_GROUPS_SCOPE_MISSING") {
		t.Fatalf("提供者 warnings = %v，want 含 MAPPING_GROUPS_SCOPE_MISSING", provStatus.Warnings)
	}

	// 停用規則之後屬性未設的黃燈消失（停用的規則於重算時視同不存在）
	rules, err := svc.ListMappings(model.RoleMappingChannelKindDirectory, dir.ID)
	if err != nil {
		t.Fatalf("列規則: %v", err)
	}
	off := false
	in := mappingInput(rules[0].MatchValue, rules[0].Role, true)
	in.Enabled = &off
	if _, err := svc.UpdateMapping(model.RoleMappingChannelKindDirectory, dir.ID, rules[0].ID, in); err != nil {
		t.Fatalf("停用規則: %v", err)
	}
	dirStatus, err = svc.DirectoryStatus()
	if err != nil {
		t.Fatalf("目錄狀態: %v", err)
	}
	if hasStatusWarning(dirStatus.Warnings, "MAPPING_SOURCE_ATTR_UNSET_WITH_RULES") {
		t.Fatalf("規則全停用後仍有黃燈：warnings = %v", dirStatus.Warnings)
	}
}

// TestProviderDetailCarriesRedirectURI 詳情帶回呼網址（要登記到提供者端的值）。
func TestProviderDetailCarriesRedirectURI(t *testing.T) {
	db := setupMappingDB(t)
	provider := seedMappingProvider(t, db, "groups", "openid groups")
	svc := identity.NewOIDCProviderService(db, nil, testEgress(), nil, "https://bastion.example.com")

	dto, err := svc.Get(provider.ID)
	if err != nil {
		t.Fatalf("讀取詳情: %v", err)
	}
	const want = "https://bastion.example.com/api/v1/auth/oidc/callback"
	if dto.RedirectURI != want {
		t.Fatalf("redirect_uri = %q，want %q", dto.RedirectURI, want)
	}
	if dto.RedirectURIState != identity.RedirectURIStateReady {
		t.Fatalf("redirect_uri_state = %q，want %q", dto.RedirectURIState, identity.RedirectURIStateReady)
	}
	if !dto.HasSecret {
		t.Fatal("已設密鑰時 has_secret 應為 true")
	}
	if dto.GroupsClaim != "groups" {
		t.Fatalf("groups_claim = %q，want groups", dto.GroupsClaim)
	}
}

// TestProviderDetailRedirectURIUnsetIsIdentifiable 未設對外基準網址時回可辨識的狀態。
//
// **不是空字串**：空字串與「算出來是空的」同形，而管理者要知道的是
// 「去把基準網址設起來」——現況是按下登入才失敗。
func TestProviderDetailRedirectURIUnsetIsIdentifiable(t *testing.T) {
	db := setupMappingDB(t)
	provider := seedMappingProvider(t, db, "groups", "openid groups")
	svc := identity.NewOIDCProviderService(db, nil, testEgress(), nil, "")

	dto, err := svc.Get(provider.ID)
	if err != nil {
		t.Fatalf("讀取詳情: %v", err)
	}
	if dto.RedirectURIState != identity.RedirectURIStateBaseURLUnset {
		t.Fatalf("redirect_uri_state = %q，want %q",
			dto.RedirectURIState, identity.RedirectURIStateBaseURLUnset)
	}
	if dto.RedirectURI != "" {
		t.Fatalf("未設基準網址時 redirect_uri = %q，want 空字串（狀態由 state 欄表達）", dto.RedirectURI)
	}
	if dto.ConfigComplete {
		t.Fatal("未設基準網址時 config_complete 應為 false")
	}
}
