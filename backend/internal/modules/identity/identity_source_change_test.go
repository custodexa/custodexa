package identity

import (
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// recordingAlertSink 測試用告警落地面：記錄事件，可注入失敗。
type recordingAlertSink struct {
	events []port.SystemAlertEvent
	fail   bool
}

func (r *recordingAlertSink) RaiseInTx(_ *gorm.DB, ev port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	if r.fail {
		return port.SystemAlertReceipt{}, errors.New("注入的告警寫入失敗")
	}
	r.events = append(r.events, ev)
	return port.SystemAlertReceipt{}, nil
}

func (r *recordingAlertSink) last(t *testing.T) port.SystemAlertEvent {
	t.Helper()
	if len(r.events) == 0 {
		t.Fatal("沒有任何告警事件")
	}
	return r.events[len(r.events)-1]
}

// migrateSourceAdminTables 補齊人數統計會讀到的表。目錄夾具的 user_roles 是 many2many 自動建的
// 兩欄表，少了來源與範圍欄位，先換成 model 定義的表（夾具資料表尚空，直接重建）。
func migrateSourceAdminTables(t *testing.T, db *gorm.DB) {
	t.Helper()
	var n int64
	if db.Migrator().HasTable("user_roles") {
		if err := db.Table("user_roles").Count(&n).Error; err != nil {
			t.Fatalf("count user_roles: %v", err)
		}
		if n == 0 {
			if err := db.Exec("DROP TABLE user_roles").Error; err != nil {
				t.Fatalf("drop user_roles: %v", err)
			}
		}
	}
	// 關聯 model 必須各自單獨遷移：同批會被 many2many 自動建出的兩欄關聯表蓋掉
	for _, m := range []any{&model.UserRole{}, &model.UserGroupRole{}, &model.UserExternalIdentity{}, &model.UserGroupMember{}} {
		if err := db.AutoMigrate(m); err != nil {
			t.Fatalf("migrate %T: %v", m, err)
		}
	}
}

// seedSourceAdmins 建立四個帳號：
//
//	直接持有超管的來源帳號、經群組持有超管的來源帳號、一般來源帳號、不屬於此來源的超管。
//
// authSource 決定「可經此來源登入」的判定欄；providerID 非 0 時改用外部身分綁定。
func seedSourceAdmins(t *testing.T, db *gorm.DB, authSource string, providerID uint) {
	t.Helper()
	migrateSourceAdminTables(t, db)
	var admin model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&admin).Error; err != nil {
		admin = model.Role{Name: model.RoleAdmin}
		if err := db.Create(&admin).Error; err != nil {
			t.Fatal(err)
		}
	}
	mk := func(name, source string, bound bool) model.User {
		u := model.User{Username: name, Password: "x", Active: true, IsLDAP: source == model.AuthSourceLDAP}
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
		if bound && providerID != 0 {
			if err := db.Create(&model.UserExternalIdentity{UserID: u.ID, ProviderID: providerID, Issuer: "https://idp.example.com",
				ClientID: "cid-1", Subject: "sub-" + name}).Error; err != nil {
				t.Fatal(err)
			}
		}
		return u
	}
	src := authSource
	direct := mk("src-direct", src, true)
	viaGroup := mk("src-group", src, true)
	mk("src-plain", src, true)
	other := mk("local-super", model.AuthSourceLocal, false)
	for _, uid := range []uint{direct.ID, other.ID} {
		if err := db.Create(&model.UserRole{UserID: uid, RoleID: admin.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
			t.Fatal(err)
		}
	}
	g := model.UserGroup{Name: "ops"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: admin.ID, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: viaGroup.ID}).Error; err != nil {
		t.Fatal(err)
	}
}

func hasToken(csv, want string) bool {
	for _, p := range strings.Split(csv, ",") {
		if p == want {
			return true
		}
	}
	return false
}

// TestIdentitySourceChangeAlert 目錄與身分提供者的建立、修改、停用、啟用、刪除各產生一筆事件，
// 內容列出實際變更的欄位與此來源的超級管理者人數；秘密只標示已變更；寫入失敗整筆回滾。
func TestIdentitySourceChangeAlert(t *testing.T) {
	const secret = "s3cret-bind"

	t.Run("目錄：五種動作各一筆，人數含群組取得者，秘密不入事件與審計", func(t *testing.T) {
		svc, db := newLDAPDirectorySvc(t)
		sink := &recordingAlertSink{}
		svc.SetSystemAlertSink(sink)
		seedSourceAdmins(t, db, model.AuthSourceLDAP, 0)
		ctx := t.Context()

		// 建立
		if _, err := svc.Upsert(ctx, ldapDirReq(nil)); err != nil {
			t.Fatalf("create: %v", err)
		}
		ev := sink.last(t)
		if ev.Type != port.SystemAlertIdentitySourceChanged || ev.Params["source_kind"] != "ldap" ||
			!hasToken(ev.Params["changed_fields"], "created") || ev.Params["super_admin_count"] != "2" ||
			ev.Params["bind_password_changed"] != "true" || ev.Actor.UserID != 7 {
			t.Fatalf("建立事件不符: %+v", ev)
		}
		// 修改（沿用密碼，只改 base_dn 與 user_filter）
		if _, err := svc.Upsert(ctx, ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.BindPassword = ""
			r.BaseDN = "ou=staff,dc=example,dc=com"
			r.UserFilter = "(sAMAccountName=%s)"
		})); err != nil {
			t.Fatalf("update: %v", err)
		}
		ev = sink.last(t)
		if got := ev.Params["changed_fields"]; got != "base_dn,user_filter" || ev.Params["bind_password_changed"] != "false" {
			t.Fatalf("修改事件欄位不符: %+v", ev.Params)
		}
		// 停用、啟用
		if _, err := svc.Upsert(ctx, ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.BindPassword = ""
			r.BaseDN = "ou=staff,dc=example,dc=com"
			r.UserFilter = "(sAMAccountName=%s)"
			r.Enabled = false
		})); err != nil {
			t.Fatalf("disable: %v", err)
		}
		if got := sink.last(t).Params["changed_fields"]; got != "enabled" {
			t.Fatalf("停用事件欄位 = %q", got)
		}
		if _, err := svc.Upsert(ctx, ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.BindPassword = ""
			r.BaseDN = "ou=staff,dc=example,dc=com"
			r.UserFilter = "(sAMAccountName=%s)"
		})); err != nil {
			t.Fatalf("enable: %v", err)
		}
		if got := sink.last(t).Params["changed_fields"]; got != "enabled" {
			t.Fatalf("啟用事件欄位 = %q", got)
		}
		// 刪除
		if err := svc.Delete(ctx, LDAPDirectoryActor{ID: 7, Name: "admin", IP: "10.1.2.3"}); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if got := sink.last(t).Params["changed_fields"]; got != "deleted" {
			t.Fatalf("刪除事件欄位 = %q", got)
		}
		if len(sink.events) != 5 {
			t.Fatalf("事件筆數 = %d，want 5", len(sink.events))
		}
		// 秘密不入事件與審計全文
		for _, e := range sink.events {
			for k, v := range e.Params {
				if strings.Contains(v, secret) {
					t.Fatalf("事件參數 %s 含秘密", k)
				}
			}
		}
		var logs []model.AuditLog
		if err := db.Find(&logs).Error; err != nil {
			t.Fatal(err)
		}
		for _, l := range logs {
			if strings.Contains(l.Details, secret) {
				t.Fatalf("審計全文含秘密: %s", l.Details)
			}
		}
		// 審計列與事件共用關聯識別
		corr := sink.events[0].CorrelationID
		found := false
		for _, l := range logs {
			if strings.Contains(l.Details, corr) {
				found = true
			}
		}
		if corr == "" || !found {
			t.Fatalf("審計列沒有帶事件的關聯識別 %q", corr)
		}
	})

	t.Run("目錄：告警寫入失敗時設定維持原值", func(t *testing.T) {
		svc, db := newLDAPDirectorySvc(t)
		sink := &recordingAlertSink{}
		svc.SetSystemAlertSink(sink)
		seedSourceAdmins(t, db, model.AuthSourceLDAP, 0)
		if _, err := svc.Upsert(t.Context(), ldapDirReq(nil)); err != nil {
			t.Fatal(err)
		}
		sink.fail = true
		_, err := svc.Upsert(t.Context(), ldapDirReq(func(r *LDAPDirectoryRequest) { r.BaseDN = "ou=changed,dc=example,dc=com" }))
		if err == nil {
			t.Fatal("告警寫入失敗時應回錯")
		}
		var row model.LDAPDirectory
		if err := db.First(&row).Error; err != nil {
			t.Fatal(err)
		}
		if row.BaseDN != "ou=users,dc=example,dc=com" {
			t.Fatalf("設定被改動: %q", row.BaseDN)
		}
		if err := svc.Delete(t.Context(), LDAPDirectoryActor{ID: 7, Name: "admin"}); err == nil {
			t.Fatal("刪除在告警失敗時應回錯")
		}
		if err := db.First(&row).Error; err != nil {
			t.Fatalf("設定不應被刪除: %v", err)
		}
	})

	t.Run("身分提供者：五種動作各一筆，client secret 只標示已變更", func(t *testing.T) {
		_, prov, db := setupOIDCEnv(t)
		sink := &recordingAlertSink{}
		prov.SetMappingAuditSink(audit.NewTxSink())
		prov.SetSystemAlertSink(sink)
		actor := GroupRoleMappingActor{ID: 7, Name: "admin", IP: "10.1.2.3"}
		migrateSourceAdminTables(t, db)
		dto, err := prov.Create(providerReq(func(r *OIDCProviderRequest) { r.Actor = actor }))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		seedSourceAdmins(t, db, model.AuthSourceOIDC, dto.ID)
		ev := sink.last(t)
		if ev.Params["source_kind"] != "oidc" || !hasToken(ev.Params["changed_fields"], "created") ||
			!hasToken(ev.Params["changed_fields"], "client_secret") || ev.Params["bind_password_changed"] != "true" {
			t.Fatalf("建立事件不符: %+v", ev.Params)
		}
		// 修改名稱與群組宣告名（不換密鑰）
		gc := "groups"
		if _, err := prov.Update(dto.ID, &OIDCProviderRequest{Name: "corp-2", GroupsClaim: &gc, Scopes: "profile email groups", Actor: actor}); err != nil {
			t.Fatalf("update: %v", err)
		}
		ev = sink.last(t)
		if got := ev.Params["changed_fields"]; got != "name,scopes,groups_claim" || ev.Params["super_admin_count"] != "2" ||
			ev.Params["bind_password_changed"] != "false" {
			t.Fatalf("修改事件不符: %+v", ev.Params)
		}
		// 輪替 client secret：只標示已變更
		if _, err := prov.Update(dto.ID, &OIDCProviderRequest{Name: "corp-2", ClientSecret: "new-s3cret-value", Actor: actor}); err != nil {
			t.Fatalf("rotate: %v", err)
		}
		ev = sink.last(t)
		if ev.Params["changed_fields"] != "client_secret" || ev.Params["bind_password_changed"] != "true" {
			t.Fatalf("輪替事件不符: %+v", ev.Params)
		}
		// 停用、啟用
		off := false
		on := true
		if _, err := prov.Update(dto.ID, &OIDCProviderRequest{Name: "corp-2", Enabled: &off, Actor: actor}); err != nil {
			t.Fatalf("disable: %v", err)
		}
		if got := sink.last(t).Params["changed_fields"]; got != "enabled" {
			t.Fatalf("停用事件欄位 = %q", got)
		}
		if _, err := prov.Update(dto.ID, &OIDCProviderRequest{Name: "corp-2", Enabled: &on, Actor: actor}); err != nil {
			t.Fatalf("enable: %v", err)
		}
		// 刪除另一個沒有外部身分綁定的提供者
		d2 := mustCreateProvider(t, prov, providerReq(func(r *OIDCProviderRequest) {
			r.Issuer = "https://idp2.example.com"
			r.Actor = actor
		}))
		if err := prov.DeleteBy(actor, d2.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		ev = sink.last(t)
		if ev.Params["changed_fields"] != "deleted" || ev.Params["super_admin_count"] != "0" {
			t.Fatalf("刪除事件不符: %+v", ev.Params)
		}
		for _, e := range sink.events {
			for k, v := range e.Params {
				if strings.Contains(v, "s3cret") {
					t.Fatalf("事件參數 %s 含秘密", k)
				}
			}
		}
		var logs []model.AuditLog
		if err := db.Where("details LIKE ?", "%"+OIDCProviderSettingsAuditEvent+"%").Find(&logs).Error; err != nil {
			t.Fatal(err)
		}
		if len(logs) != len(sink.events) {
			t.Fatalf("審計列 %d 筆，事件 %d 筆", len(logs), len(sink.events))
		}
		for _, l := range logs {
			if strings.Contains(l.Details, "s3cret") {
				t.Fatalf("審計全文含秘密: %s", l.Details)
			}
		}
	})

	t.Run("身分提供者：告警或審計寫入失敗時設定維持原值", func(t *testing.T) {
		_, prov, db := setupOIDCEnv(t)
		sink := &recordingAlertSink{}
		migrateSourceAdminTables(t, db)
		prov.SetMappingAuditSink(audit.NewTxSink())
		prov.SetSystemAlertSink(sink)
		actor := GroupRoleMappingActor{ID: 7, Name: "admin"}
		dto, err := prov.Create(providerReq(func(r *OIDCProviderRequest) { r.Actor = actor }))
		if err != nil {
			t.Fatal(err)
		}
		sink.fail = true
		if _, err := prov.Update(dto.ID, &OIDCProviderRequest{Name: "renamed", Actor: actor}); err == nil {
			t.Fatal("告警失敗時修改應回錯")
		}
		if got := reloadProvider(t, db, dto.ID).Name; got != "corp" {
			t.Fatalf("名稱被改動: %q", got)
		}
		if _, err := prov.Create(providerReq(func(r *OIDCProviderRequest) { r.Issuer = "https://idp3.example.com"; r.Actor = actor })); err == nil {
			t.Fatal("告警失敗時建立應回錯")
		}
		var n int64
		db.Model(&model.OIDCProvider{}).Count(&n)
		if n != 1 {
			t.Fatalf("提供者筆數 = %d，want 1", n)
		}
		sink.fail = false
		prov.SetMappingAuditSink(failingPinSink{})
		if _, err := prov.Update(dto.ID, &OIDCProviderRequest{Name: "renamed", Actor: actor}); err == nil {
			t.Fatal("審計失敗時修改應回錯")
		}
		if got := reloadProvider(t, db, dto.ID).Name; got != "corp" {
			t.Fatalf("審計失敗後名稱被改動: %q", got)
		}
	})
	t.Run("缺落地面即寫入失敗，系統操作者照常留痕", func(t *testing.T) {
		// 目錄：缺告警落地面時存檔失敗且不落地
		svc, db := newLDAPDirectorySvc(t)
		svc.SetSystemAlertSink(nil) // 夾具預設接了丟棄實作，這裡驗證缺注入
		if err := svc.SourceChangeSinksReady(); err == nil || !errors.Is(err, ErrSourceChangeSinksMissing) {
			t.Fatalf("缺告警落地面時自檢應回 ErrSourceChangeSinksMissing: %v", err)
		}
		if _, err := svc.Upsert(t.Context(), ldapDirReq(nil)); err == nil {
			t.Fatal("缺告警落地面時目錄存檔應失敗，不得略過留痕")
		}
		var n int64
		db.Model(&model.LDAPDirectory{}).Count(&n)
		if n != 0 {
			t.Fatalf("目錄不應落地: %d", n)
		}
		alerts := &recordingAlertSink{}
		svc.SetSystemAlertSink(alerts)
		if err := svc.SourceChangeSinksReady(); err != nil {
			t.Fatalf("兩個落地面齊備時自檢應通過: %v", err)
		}
		// 目錄：零值操作者（系統呼叫）照常留痕，操作者記為系統
		req := ldapDirReq(nil)
		req.Actor = LDAPDirectoryActor{}
		if _, err := svc.Upsert(t.Context(), req); err != nil {
			t.Fatalf("系統呼叫存檔: %v", err)
		}
		if got := alerts.last(t).Actor.Username; got != SystemSourceActorName {
			t.Fatalf("目錄事件操作者 = %q，want %q", got, SystemSourceActorName)
		}
		var ldapLogs []model.AuditLog
		if err := db.Where("username = ?", SystemSourceActorName).Find(&ldapLogs).Error; err != nil || len(ldapLogs) == 0 {
			t.Fatalf("目錄審計應記系統操作者: %v / %d", err, len(ldapLogs))
		}

		// 身分提供者：缺告警落地面
		_, prov, odb := setupOIDCEnv(t)
		migrateSourceAdminTables(t, odb)
		prov.SetSystemAlertSink(nil) // 夾具預設接了丟棄實作，這裡驗證缺注入
		prov.SetMappingAuditSink(audit.NewTxSink())
		if err := prov.SourceChangeSinksReady(); err == nil {
			t.Fatal("缺告警落地面時自檢應失敗")
		}
		if _, err := prov.Create(providerReq(nil)); err == nil {
			t.Fatal("缺告警落地面時建立應失敗，不得略過留痕")
		}
		odb.Model(&model.OIDCProvider{}).Count(&n)
		if n != 0 {
			t.Fatalf("提供者不應落地: %d", n)
		}
		// 身分提供者：缺審計落地面（有操作者也一樣）
		prov2Alerts := &recordingAlertSink{}
		prov.SetSystemAlertSink(prov2Alerts)
		prov.SetMappingAuditSink(nil)
		if err := prov.SourceChangeSinksReady(); err == nil {
			t.Fatal("缺審計落地面時自檢應失敗")
		}
		if _, err := prov.Create(providerReq(func(r *OIDCProviderRequest) { r.Actor = GroupRoleMappingActor{ID: 7, Name: "admin"} })); err == nil {
			t.Fatal("缺審計落地面時建立應失敗")
		}
		// 身分提供者：零值操作者（系統呼叫）審計與事件照寫，操作者記為系統
		prov.SetMappingAuditSink(audit.NewTxSink())
		if err := prov.SourceChangeSinksReady(); err != nil {
			t.Fatalf("齊備後自檢應通過: %v", err)
		}
		if _, err := prov.Create(providerReq(nil)); err != nil {
			t.Fatalf("系統呼叫建立: %v", err)
		}
		if got := prov2Alerts.last(t).Actor.Username; got != SystemSourceActorName {
			t.Fatalf("身分提供者事件操作者 = %q", got)
		}
		var oidcLogs []model.AuditLog
		if err := odb.Where("details LIKE ? AND username = ?", "%"+OIDCProviderSettingsAuditEvent+"%", SystemSourceActorName).Find(&oidcLogs).Error; err != nil || len(oidcLogs) != 1 {
			t.Fatalf("系統操作者的設定變更審計應有一列: %v / %d", err, len(oidcLogs))
		}
	})
}

// TestSourceCorrelationID 隨機來源失敗時回錯（呼叫端據此讓整筆變更失敗），不退回固定值；
// 成功時為 src- 前綴加 24 位十六進位，且兩次產生互不相同。
func TestSourceCorrelationID(t *testing.T) {
	t.Run("random source failure returns error", func(t *testing.T) {
		injected := errors.New("注入的隨機來源失敗")
		id, err := sourceCorrelationIDFrom(func([]byte) (int, error) { return 0, injected })
		if !errors.Is(err, injected) {
			t.Fatalf("err = %v, want wrapped injected error", err)
		}
		if id != "" {
			t.Fatalf("id = %q, want empty on failure", id)
		}
	})
	t.Run("success has prefix and is unique", func(t *testing.T) {
		a, err := newSourceCorrelationID()
		if err != nil {
			t.Fatal(err)
		}
		b, err := newSourceCorrelationID()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(a, "src-") || len(a) != len("src-")+24 {
			t.Fatalf("id = %q, want src- followed by 24 hex digits", a)
		}
		if a == b {
			t.Fatalf("two ids are equal: %q", a)
		}
	})
}
