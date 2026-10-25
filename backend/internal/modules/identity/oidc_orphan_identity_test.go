package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 帳號刪除後外部身分再登入的測試夾具與情境。
//
// 每個情境在 sqlite 與 PostgreSQL（隔離 schema，TEST_PG_DSN gating）各跑一次：
// 帳號名、email 與身分域三元組的唯一索引都是 partial（排除軟刪），重建帳號能否
// 沿用原帳號名、作廢後能否重綁，取決於索引語義，兩種引擎都要實際驗到。

// orphanEnv 一組接上 fake IdP 的完整登入環境，另含刪除帳號用的 UserService
type orphanEnv struct {
	db    *gorm.DB
	login *OIDCLoginService
	users *UserService
	idp   *fakeIdP
	p     *model.OIDCProvider
	codeN int
}

// forEachOrphanDialect 依序在 sqlite 與 PostgreSQL 執行同一情境
func forEachOrphanDialect(t *testing.T, fn func(t *testing.T, kind string)) {
	t.Helper()
	for _, kind := range []string{"sqlite", "postgres"} {
		kind := kind
		t.Run(kind, func(t *testing.T) { fn(t, kind) })
	}
}

// openOrphanDB sqlite :memory:（單連線）或 PostgreSQL 的一次性隔離 schema
func openOrphanDB(t *testing.T, kind string) *gorm.DB {
	t.Helper()
	cfg := &gorm.Config{Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true}
	if kind != "postgres" {
		db, err := gorm.Open(sqlite.Open(":memory:"), cfg)
		if err != nil {
			t.Fatalf("sqlite: %v", err)
		}
		sqlDB, err := db.DB()
		if err != nil {
			t.Fatalf("sql.DB: %v", err)
		}
		// :memory: 每條連線各是一個空庫，收斂到單連線
		sqlDB.SetMaxOpenConns(1)
		return db
	}
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	schema := fmt.Sprintf("oidc_orphan_%d", time.Now().UnixNano())
	admin, err := gorm.Open(postgres.Open(dsn), cfg)
	if err != nil {
		t.Fatalf("postgres 連線失敗: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("建立測試 schema: %v", err)
	}
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), cfg)
	if err != nil {
		t.Fatalf("postgres（schema）連線失敗: %v", err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	return db
}

// orphanMigrate 登入、映射重算與刪除帳號三條路徑所需的表，以及與正式庫同語義的
// partial 唯一索引。
//
// AutoMigrate 依 model 標記建出的帳號名與 email 唯一索引是**全表**唯一，比正式庫
// 嚴：重建帳號沿用原帳號名時必然撞索引，測到的會是夾具而不是產品行為
func orphanMigrate(t *testing.T, db *gorm.DB) {
	t.Helper()
	seedAuthzState(t, db)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{},
		&model.PasswordHistory{}, &model.RefreshToken{}, &model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{},
		&model.OIDCProvider{}, &model.RoleBindingNode{}, &model.UserExternalIdentity{},
		&model.OIDCFlowState{}, &model.OIDCLoginTicket{},
		&model.GroupRoleMapping{}, &model.UserRoleMapping{},
		&model.ExternalGroup{}, &model.GroupUserGroupMapping{}, &model.UserRoleMappingRuleSupport{},
		&model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.UserGroup{}, &model.UserGroupMember{},
		&model.ApproverScope{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.UserRole{}); err != nil {
		t.Fatalf("user_roles: %v", err)
	}
	for _, stmt := range []string{
		`DROP INDEX IF EXISTS idx_users_username`,
		`CREATE UNIQUE INDEX idx_users_username ON users (username) WHERE deleted_at IS NULL`,
		`DROP INDEX IF EXISTS idx_users_email`,
		`CREATE UNIQUE INDEX idx_users_email ON users (email) WHERE email IS NOT NULL AND deleted_at IS NULL`,
		`CREATE UNIQUE INDEX idx_uei_orphan_domain ON user_external_identities (issuer, client_id, subject) WHERE deleted_at IS NULL`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("partial index（%s）: %v", stmt, err)
		}
	}
	for _, name := range []string{model.RoleUser, model.RoleAdmin} {
		if err := db.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
	}
	// 刪除帳號的 admin 不變式：保留一個本地 admin，使刪除被測帳號不受其影響
	keeper := &model.User{Username: "keeper-admin", Password: "x", ProvisioningOrigin: model.AuthSourceLocal}
	if err := db.Create(keeper).Error; err != nil {
		t.Fatalf("seed keeper: %v", err)
	}
	var admin model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&admin).Error; err != nil {
		t.Fatalf("load admin role: %v", err)
	}
	if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", keeper.ID, admin.ID).Error; err != nil {
		t.Fatalf("attach keeper admin: %v", err)
	}
}

// newOrphanEnv 建環境；mode 為 provider 的准入模式
func newOrphanEnv(t *testing.T, kind string, mode model.AdmissionMode) *orphanEnv {
	t.Helper()
	db := openOrphanDB(t, kind)
	orphanMigrate(t, db)
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	idp := newFakeIdP(t)
	auth := NewAuthService("test-secret", 15*time.Minute)
	auth.SetSecurityPolicies(policy.NewSecurityPolicyService(db))
	providers := newOIDCProviderServiceT(db, nil, testEgress(), nil, "https://bastion.example.com")
	login := NewOIDCLoginService(db, providers, NewOIDCDiscoveryService(testEgress()), auth, nil)
	login.audit = newRecordingAudit()
	login.SetRoleMappingAuditSink(audit.NewTxSink())

	users := NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.audit = newRecordingAudit()

	p := seedProvider(t, db, func(p *model.OIDCProvider) {
		p.Issuer = idp.issuer
		p.ClientID = "test-client"
		p.AdmissionMode = mode
		if mode == model.AdmissionJITWithRules {
			p.AdmissionRules = `{"hd":["corp.example"]}`
		}
	})
	return &orphanEnv{db: db, login: login, users: users, idp: idp, p: p}
}

// orphanClaims 能通過准入的基本宣告（帳號名映射為 bob），可疊加
func orphanClaims(extra map[string]any) map[string]any {
	base := map[string]any{
		"hd": "corp.example", "preferred_username": "bob",
		"email": "bob@corp.example", "email_verified": true,
	}
	for k, v := range extra {
		base[k] = v
	}
	return base
}

// loginAs 走一次完整的 begin → callback
func (e *orphanEnv) loginAs(t *testing.T, subject string, claims map[string]any) (*CallbackResult, error) {
	t.Helper()
	e.codeN++
	code := fmt.Sprintf("code-%d", e.codeN)
	state, nonce := beginFlow(t, e.login, e.p, "browser-secret", e.idp)
	e.idp.stageCode(code, e.idp.issueIDToken(t, idTokenOpts{
		subject: subject, audience: e.p.ClientID, nonce: nonce, extra: claims,
	}))
	return e.login.Callback(context.Background(), state, code)
}

// liveUser 依帳號名取回未刪除的帳號
func (e *orphanEnv) liveUser(t *testing.T, username string) model.User {
	t.Helper()
	var u model.User
	if err := e.db.Where("username = ?", username).First(&u).Error; err != nil {
		t.Fatalf("查帳號 %s: %v", username, err)
	}
	return u
}

// liveIdentityCount 指定 subject 的有效綁定數
func (e *orphanEnv) liveIdentityCount(t *testing.T, subject string) int64 {
	t.Helper()
	var n int64
	if err := e.db.Model(&model.UserExternalIdentity{}).
		Where("issuer = ? AND client_id = ? AND subject = ?", e.p.Issuer, e.p.ClientID, subject).
		Count(&n).Error; err != nil {
		t.Fatalf("計數綁定: %v", err)
	}
	return n
}

// softDeleteUserOnly 只軟刪帳號、綁定不動（升級前刪除留下的狀態）
func (e *orphanEnv) softDeleteUserOnly(t *testing.T, userID uint) {
	t.Helper()
	if err := e.db.Exec("UPDATE users SET deleted_at = ? WHERE id = ?", time.Now(), userID).Error; err != nil {
		t.Fatalf("直寫軟刪帳號: %v", err)
	}
}

// ── 1.1 基準：刪除後同一外部身分再登入 ─────────────────────────────

// TestOIDCLoginAfterUserDeleted 自動供應模式：首登建帳號 → 刪除帳號 → 同一 subject
// 再登入，應重建帳號（帳號名相同、編號不同），且帳號建立意向標示所取代的原帳號
func TestOIDCLoginAfterUserDeleted(t *testing.T) {
	forEachOrphanDialect(t, func(t *testing.T, kind string) {
		env := newOrphanEnv(t, kind, model.AdmissionJITWithRules)
		if _, err := env.loginAs(t, "sub-1", orphanClaims(nil)); err != nil {
			t.Fatalf("首登應成功: %v", err)
		}
		first := env.liveUser(t, "bob")
		if err := env.users.Delete(first.ID); err != nil {
			t.Fatalf("刪除帳號: %v", err)
		}

		res, err := env.loginAs(t, "sub-1", orphanClaims(nil))
		if err != nil {
			t.Fatalf("刪除後再登入應重建帳號，實得錯誤 %v（意向 %v）", err, OIDCAuditEventsOf(err))
		}
		second := env.liveUser(t, "bob")
		if second.ID == first.ID {
			t.Fatalf("應為新帳號編號，實得同一編號 %d", second.ID)
		}
		prov := auditEvents(res.AuditEvents, "oidc_user_provisioned")
		if len(prov) != 1 {
			t.Fatalf("應恰一筆帳號建立意向，實得 %d（全部 %v）", len(prov), res.AuditEvents)
		}
		if got := prov[0].Details["replaces_user_id"]; got != first.ID {
			t.Errorf("replaces_user_id = %v, want %d", got, first.ID)
		}
		// 刪除時已同交易作廢綁定，登入路徑看不到懸空綁定，不應再落作廢意向
		if n := countAuditIntent(res.AuditEvents, "oidc_identity_orphan_revoked"); n != 0 {
			t.Errorf("刪除路徑已作廢綁定，登入不應再落作廢意向，實得 %d", n)
		}
	})
}

// ── 3.1 登入時處理懸空綁定 ─────────────────────────────────────────

// eventIndex 事件名在意向清單中第一次出現的位置（無則 -1）
func eventIndex(events []OIDCAuditEvent, name string) int {
	for i, e := range events {
		if ev, _ := e.Details["event"].(string); ev == name {
			return i
		}
	}
	return -1
}

// revokedIdentityCount 指定帳號名下已作廢的綁定數（Unscoped）
func (e *orphanEnv) revokedIdentityCount(t *testing.T, userID uint) int64 {
	t.Helper()
	var n int64
	if err := e.db.Unscoped().Model(&model.UserExternalIdentity{}).
		Where("user_id = ? AND deleted_at IS NOT NULL", userID).Count(&n).Error; err != nil {
		t.Fatalf("計數已作廢綁定: %v", err)
	}
	return n
}

// TestOIDCOrphanBindingFromPreUpgradeState 升級前留下的懸空綁定（帳號已刪、綁定未作廢）
// 於登入時作廢並重建帳號；意向依序為作廢與帳號建立（依主對話 2026-10-12 裁決，
// 順序斷言放在本案）。擋：升級前懸空綁定無法自癒
func TestOIDCOrphanBindingFromPreUpgradeState(t *testing.T) {
	forEachOrphanDialect(t, func(t *testing.T, kind string) {
		env := newOrphanEnv(t, kind, model.AdmissionJITWithRules)
		if _, err := env.loginAs(t, "sub-1", orphanClaims(nil)); err != nil {
			t.Fatalf("首登應成功: %v", err)
		}
		first := env.liveUser(t, "bob")
		env.softDeleteUserOnly(t, first.ID)

		res, err := env.loginAs(t, "sub-1", orphanClaims(nil))
		if err != nil {
			t.Fatalf("懸空綁定應自癒並重建帳號，實得錯誤 %v（意向 %v）", err, OIDCAuditEventsOf(err))
		}
		second := env.liveUser(t, "bob")
		if second.ID == first.ID {
			t.Fatalf("應為新帳號編號，實得同一編號 %d", second.ID)
		}
		if n := env.revokedIdentityCount(t, first.ID); n != 1 {
			t.Errorf("舊綁定應已作廢，已作廢筆數 %d", n)
		}
		if n := env.liveIdentityCount(t, "sub-1"); n != 1 {
			t.Errorf("同一 subject 應恰一筆有效綁定（新帳號），實得 %d", n)
		}

		revokeAt := eventIndex(res.AuditEvents, "oidc_identity_orphan_revoked")
		provAt := eventIndex(res.AuditEvents, "oidc_user_provisioned")
		if revokeAt < 0 || provAt < 0 || revokeAt > provAt {
			t.Fatalf("意向應依序為作廢與帳號建立，實得 %v", res.AuditEvents)
		}
		rev := res.AuditEvents[revokeAt]
		if rev.Action != model.ActionDelete || rev.Resource != model.ResourceUser ||
			rev.Status != model.StatusSuccess || rev.ResourceID == nil || *rev.ResourceID != first.ID {
			t.Errorf("作廢意向應為 delete／user／success／resource_id=%d，實得 %+v", first.ID, rev)
		}
		want := map[string]any{
			"issuer": env.p.Issuer, "subject": "sub-1", "previous_user_id": first.ID,
			"previous_username": "bob", "provider_id": env.p.ID, "provider_name": env.p.Name,
		}
		for k, v := range want {
			if rev.Details[k] != v {
				t.Errorf("作廢意向 %s = %v, want %v", k, rev.Details[k], v)
			}
		}
		if rev.Details["identity_id"] == nil || rev.Details["subject_fingerprint"] == nil {
			t.Errorf("作廢意向應帶 identity_id 與 subject_fingerprint，實得 %v", rev.Details)
		}
		if got := res.AuditEvents[provAt].Details["replaces_user_id"]; got != first.ID {
			t.Errorf("replaces_user_id = %v, want %d", got, first.ID)
		}
	})
}

// TestOIDCOrphanBindingRevokedEvenWhenAdmissionFails 准入未通過時懸空綁定照樣作廢
func TestOIDCOrphanBindingRevokedEvenWhenAdmissionFails(t *testing.T) {
	forEachOrphanDialect(t, func(t *testing.T, kind string) {
		env := newOrphanEnv(t, kind, model.AdmissionJITWithRules)
		if _, err := env.loginAs(t, "sub-1", orphanClaims(nil)); err != nil {
			t.Fatalf("首登應成功: %v", err)
		}
		first := env.liveUser(t, "bob")
		env.softDeleteUserOnly(t, first.ID)

		_, err := env.loginAs(t, "sub-1", orphanClaims(map[string]any{"hd": "other.example"}))
		if !errors.Is(err, ErrOIDCAdmissionDenied) {
			t.Fatalf("宣告不符應以准入不符拒絕，實得 %v", err)
		}
		if n := env.liveIdentityCount(t, "sub-1"); n != 0 {
			t.Errorf("懸空綁定應已作廢，有效綁定 %d", n)
		}
		events := OIDCAuditEventsOf(err)
		if countAuditIntent(events, "oidc_identity_orphan_revoked") != 1 ||
			countAuditIntent(events, "oidc_admission_denied") != 1 {
			t.Errorf("應有作廢與准入拒絕各一筆意向，實得 %v", events)
		}
		var cnt int64
		env.db.Model(&model.User{}).Where("username = ?", "bob").Count(&cnt)
		if cnt != 0 {
			t.Errorf("准入未通過不得建帳號，實得 %d 個 bob", cnt)
		}
	})
}

// TestOIDCOrphanConcurrentLogins 兩個請求都讀到懸空綁定後才放行（同步點控制交錯）：
// 只建一個帳號、兩者皆成功、無撞名事件，且作廢審計只由真正作廢到該列的一方寫出
// （依主對話 2026-10-12 裁決）
func TestOIDCOrphanConcurrentLogins(t *testing.T) {
	forEachOrphanDialect(t, func(t *testing.T, kind string) {
		env := newOrphanEnv(t, kind, model.AdmissionJITWithRules)
		if _, err := env.loginAs(t, "sub-1", orphanClaims(nil)); err != nil {
			t.Fatalf("首登應成功: %v", err)
		}
		first := env.liveUser(t, "bob")
		env.softDeleteUserOnly(t, first.ID)

		// 兩個流程在主 goroutine 備妥，goroutine 內只跑 callback
		type staged struct{ state, code string }
		var flows []staged
		for i := 0; i < 2; i++ {
			env.codeN++
			code := fmt.Sprintf("code-c%d", env.codeN)
			state, nonce := beginFlow(t, env.login, env.p, "browser-secret", nil)
			env.idp.stageCode(code, env.idp.issueIDToken(t, idTokenOpts{
				subject: "sub-1", audience: env.p.ClientID, nonce: nonce, extra: orphanClaims(nil),
			}))
			flows = append(flows, staged{state, code})
		}
		// 兩個流程各有自己的 challenge，fake IdP 一次只能比對一個：關閉比對
		// （PKCE 由既有流程測試承擔，本案只驗並發收斂）
		env.idp.expectChallenge("")

		var mu sync.Mutex
		arrived := 0
		release := make(chan struct{})
		env.login.orphanRevokeHook = func() {
			mu.Lock()
			arrived++
			if arrived == 2 {
				close(release)
			}
			mu.Unlock()
			select {
			case <-release:
			case <-time.After(5 * time.Second):
			}
		}

		results := make([]*CallbackResult, 2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range flows {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i], errs[i] = env.login.Callback(context.Background(), flows[i].state, flows[i].code)
			}(i)
		}
		wg.Wait()
		env.login.orphanRevokeHook = nil

		mu.Lock()
		gotArrived := arrived
		mu.Unlock()
		if gotArrived != 2 {
			t.Fatalf("兩個請求都應讀到懸空綁定（同步點到達 %d 次），交錯未成立", gotArrived)
		}
		var all []OIDCAuditEvent
		for i := range errs {
			if errs[i] != nil {
				t.Fatalf("請求 %d 應成功，實得 %v（意向 %v）", i, errs[i], OIDCAuditEventsOf(errs[i]))
			}
			all = append(all, results[i].AuditEvents...)
		}
		var cnt int64
		env.db.Model(&model.User{}).Where("username = ?", "bob").Count(&cnt)
		if cnt != 1 {
			t.Errorf("只應建一個帳號，實得 %d", cnt)
		}
		if n := countAuditIntent(all, "oidc_username_conflict"); n != 0 {
			t.Errorf("並發收斂不得落撞名事件，實得 %d", n)
		}
		if n := countAuditIntent(all, "oidc_identity_orphan_revoked"); n != 1 {
			t.Errorf("作廢審計應只由作廢到該列的一方寫出（恰 1 筆），實得 %d", n)
		}
		if n := countAuditIntent(all, "oidc_user_provisioned"); n != 1 {
			t.Errorf("帳號建立意向應恰 1 筆，實得 %d", n)
		}
	})
}

// ── 3.2 重建後群組映射重新給角色 ───────────────────────────────────

// TestOIDCRebuiltUserRegainsMappedRole 首登經映射取得 admin → 刪除 → 再登入，
// 新帳號由映射重新取得 admin，映射事實列指向新帳號
func TestOIDCRebuiltUserRegainsMappedRole(t *testing.T) {
	forEachOrphanDialect(t, func(t *testing.T, kind string) {
		env := newOrphanEnv(t, kind, model.AdmissionJITWithRules)
		if err := env.db.Model(env.p).Update("groups_claim", "groups").Error; err != nil {
			t.Fatalf("設群組宣告名: %v", err)
		}
		env.p.GroupsClaim = "groups"
		seedProviderMappingRule(t, env.db, env.p.ID, oidcMappingGroup, model.RoleAdmin)
		claims := orphanClaims(map[string]any{"groups": []any{oidcMappingGroup}})

		if _, err := env.loginAs(t, "sub-1", claims); err != nil {
			t.Fatalf("首登應成功: %v", err)
		}
		first := env.liveUser(t, "bob")
		if !containsRole(userRolesOf(t, env.db, first.ID), model.RoleAdmin) {
			t.Fatalf("首登應經映射取得 admin，實得 %v", userRolesOf(t, env.db, first.ID))
		}
		if err := env.users.Delete(first.ID); err != nil {
			t.Fatalf("刪除帳號: %v", err)
		}

		if _, err := env.loginAs(t, "sub-1", claims); err != nil {
			t.Fatalf("刪除後再登入應成功: %v", err)
		}
		second := env.liveUser(t, "bob")
		if second.ID == first.ID {
			t.Fatalf("應為新帳號")
		}
		if !containsRole(userRolesOf(t, env.db, second.ID), model.RoleAdmin) {
			t.Errorf("重建帳號應經映射重新取得 admin，實得 %v", userRolesOf(t, env.db, second.ID))
		}
		var adminRole model.Role
		if err := env.db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
			t.Fatalf("讀 admin 角色: %v", err)
		}
		var facts int64
		env.db.Model(&model.UserRoleMapping{}).
			Where("user_id = ? AND role_id = ?", second.ID, adminRole.ID).Count(&facts)
		if facts != 1 {
			t.Errorf("映射事實列應指向新帳號 %d（admin），實得 %d 筆", second.ID, facts)
		}
		env.db.Model(&model.UserRoleMapping{}).Where("user_id = ?", first.ID).Count(&facts)
		if facts != 0 {
			t.Errorf("原帳號不應殘留映射事實列，實得 %d", facts)
		}
	})
}

// ── 3.3 僅預綁模式 ──────────────────────────────────────────────────

// seedBoundAccount 管理者建帳號並為其綁定 subject（經正式的綁定服務）
func (e *orphanEnv) seedBoundAccount(t *testing.T, username, subject string) model.User {
	t.Helper()
	u := model.User{Username: username, Password: "x", Active: true, ProvisioningOrigin: model.AuthSourceLocal}
	if err := e.db.Create(&u).Error; err != nil {
		t.Fatalf("建帳號 %s: %v", username, err)
	}
	if _, err := e.users.BindExternalIdentity(u.ID, e.p.ID, subject,
		IdentityAdminActor{UserID: 1, Username: "keeper-admin"}); err != nil {
		t.Fatalf("綁定 %s → %s: %v", subject, username, err)
	}
	return u
}

// TestOIDCPreboundOnlyDeletedAccount 擋：僅預綁模式被刪的人自行回到系統
func TestOIDCPreboundOnlyDeletedAccount(t *testing.T) {
	forEachOrphanDialect(t, func(t *testing.T, kind string) {
		env := newOrphanEnv(t, kind, model.AdmissionPreboundOnly)
		original := env.seedBoundAccount(t, "bob", "sub-1")
		if _, err := env.loginAs(t, "sub-1", orphanClaims(nil)); err != nil {
			t.Fatalf("預綁帳號登入應成功: %v", err)
		}
		if err := env.users.Delete(original.ID); err != nil {
			t.Fatalf("刪除帳號: %v", err)
		}

		for attempt := 1; attempt <= 2; attempt++ {
			_, err := env.loginAs(t, "sub-1", orphanClaims(nil))
			if !errors.Is(err, ErrOIDCAccountRemoved) {
				t.Fatalf("第 %d 次：應回 ErrOIDCAccountRemoved，實得 %v", attempt, err)
			}
			got := auditEvents(OIDCAuditEventsOf(err), "oidc_account_removed")
			if len(got) != 1 || got[0].Status != model.StatusDenied || got[0].Resource != model.ResourceAuth ||
				got[0].Details["previous_user_id"] != original.ID {
				t.Errorf("第 %d 次：應有一筆 auth／denied 的帳號已刪除意向（previous_user_id=%d），實得 %v",
					attempt, original.ID, OIDCAuditEventsOf(err))
			}
			var cnt int64
			env.db.Model(&model.User{}).Where("username = ?", "bob").Count(&cnt)
			if cnt != 0 {
				t.Fatalf("第 %d 次：不得建帳號，實得 %d 個 bob", attempt, cnt)
			}
		}

		// 從未綁定的 subject 維持一般的准入不符
		_, err := env.loginAs(t, "sub-never", orphanClaims(map[string]any{"preferred_username": "zed"}))
		if !errors.Is(err, ErrOIDCAdmissionDenied) || errors.Is(err, ErrOIDCAccountRemoved) {
			t.Fatalf("未綁定的 subject 應回准入不符，實得 %v", err)
		}
		denied := auditEvents(OIDCAuditEventsOf(err), "oidc_admission_denied")
		if len(denied) != 1 || denied[0].Details["failed_rule"] != "not_prebound" {
			t.Errorf("應為 not_prebound，實得 %v", OIDCAuditEventsOf(err))
		}

		// 管理者重建同名帳號並綁定：不回衝突，之後登入進入新帳號
		rebuilt := env.seedBoundAccount(t, "bob", "sub-1")
		if _, err := env.loginAs(t, "sub-1", orphanClaims(nil)); err != nil {
			t.Fatalf("重新綁定後登入應成功: %v", err)
		}
		if rebuilt.ID == original.ID {
			t.Fatalf("重建帳號應為新編號")
		}
		var identity model.UserExternalIdentity
		if err := env.db.Where("subject = ?", "sub-1").First(&identity).Error; err != nil || identity.UserID != rebuilt.ID {
			t.Errorf("有效綁定應指向重建帳號 %d，實得 %+v（%v）", rebuilt.ID, identity, err)
		}
	})
}

// TestOIDCPreboundOnlyOrphanFromPreUpgradeState 僅預綁模式遇到升級前留下的懸空綁定：
// 作廢並以專屬原因拒絕，意向含作廢與拒絕各一筆
func TestOIDCPreboundOnlyOrphanFromPreUpgradeState(t *testing.T) {
	forEachOrphanDialect(t, func(t *testing.T, kind string) {
		env := newOrphanEnv(t, kind, model.AdmissionPreboundOnly)
		original := env.seedBoundAccount(t, "bob", "sub-1")
		env.softDeleteUserOnly(t, original.ID)

		_, err := env.loginAs(t, "sub-1", orphanClaims(nil))
		if !errors.Is(err, ErrOIDCAccountRemoved) {
			t.Fatalf("應回 ErrOIDCAccountRemoved，實得 %v", err)
		}
		events := OIDCAuditEventsOf(err)
		if countAuditIntent(events, "oidc_identity_orphan_revoked") != 1 ||
			countAuditIntent(events, "oidc_account_removed") != 1 {
			t.Errorf("應有作廢與帳號已刪除各一筆意向，實得 %v", events)
		}
		if n := env.liveIdentityCount(t, "sub-1"); n != 0 {
			t.Errorf("懸空綁定應已作廢，有效綁定 %d", n)
		}
	})
}

// ── 3.4 綁定時遇到懸空綁定 ─────────────────────────────────────────

// TestBindExternalIdentityRevokesOrphan 既有綁定屬已刪帳號時作廢並完成綁定；
// 屬在用帳號時照舊回衝突
func TestBindExternalIdentityRevokesOrphan(t *testing.T) {
	forEachOrphanDialect(t, func(t *testing.T, kind string) {
		env := newOrphanEnv(t, kind, model.AdmissionPreboundOnly)
		rec := env.users.audit.(*recordingAudit)
		old := env.seedBoundAccount(t, "carol", "sub-9")
		env.softDeleteUserOnly(t, old.ID)

		fresh := model.User{Username: "carol-new", Password: "x", Active: true, ProvisioningOrigin: model.AuthSourceLocal}
		if err := env.db.Create(&fresh).Error; err != nil {
			t.Fatalf("建帳號: %v", err)
		}
		actor := IdentityAdminActor{UserID: 1, Username: "keeper-admin"}
		dto, err := env.users.BindExternalIdentity(fresh.ID, env.p.ID, "sub-9", actor)
		if err != nil {
			t.Fatalf("綁定應成功（舊綁定指向已刪帳號），實得 %v", err)
		}
		if dto.UserID != fresh.ID {
			t.Errorf("新綁定應屬 %d，實得 %d", fresh.ID, dto.UserID)
		}
		if n := env.revokedIdentityCount(t, old.ID); n != 1 {
			t.Errorf("舊綁定應已作廢，已作廢筆數 %d", n)
		}
		if n := rec.countEvent("external_identity_orphan_revoked"); n != 1 {
			t.Errorf("應有一筆 external_identity_orphan_revoked 審計，實得 %d", n)
		}
		for _, e := range rec.entries {
			if strings.Contains(e.Details, `"event":"external_identity_orphan_revoked"`) {
				if e.ResourceID == nil || *e.ResourceID != old.ID || e.Action != model.ActionDelete ||
					!strings.Contains(e.Details, `"subject":"sub-9"`) ||
					!strings.Contains(e.Details, fmt.Sprintf(`"previous_user_id":%d`, old.ID)) {
					t.Errorf("作廢審計欄位不符: %+v", e)
				}
			}
		}

		// 既有綁定屬在用帳號：照舊衝突
		other := model.User{Username: "dave", Password: "x", Active: true, ProvisioningOrigin: model.AuthSourceLocal}
		if err := env.db.Create(&other).Error; err != nil {
			t.Fatalf("建帳號: %v", err)
		}
		if _, err := env.users.BindExternalIdentity(other.ID, env.p.ID, "sub-9", actor); !errors.Is(err, ErrExternalIdentityExists) {
			t.Fatalf("在用帳號的綁定應回 ErrExternalIdentityExists，實得 %v", err)
		}
		if n := rec.countEvent("external_identity_orphan_revoked"); n != 1 {
			t.Errorf("在用帳號不得作廢，作廢審計 %d 筆", n)
		}
	})
}
