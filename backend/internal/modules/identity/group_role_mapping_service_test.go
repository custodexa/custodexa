package identity_test

import (
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 映射規則管理面（CRUD、拒刪、兩種確認、來源旗標）的測試。
//
// 全部走真 sqlite 的結果面斷言（列在不在、審計列在不在），不用 sqlmock：
// 這一段的正確性是「交易的邊界」，而語句期望集合證明不了交易有沒有回滾。

// failingTxSink 交易內審計落地面的故障注入：一律回錯。
// 用於證明「留痕失敗即整筆回滾」——不是「錯誤被吞掉，業務照樣成立」。
type failingTxSink struct{}

func (failingTxSink) WriteInTx(*gorm.DB, port.AuditEvent) error {
	return errors.New("注入的審計寫入失敗")
}

// mappingTestActor 規則 CRUD 的操作者
var mappingTestActor = identity.GroupRoleMappingActor{ID: 1, Name: "admin", IP: "10.0.0.1"}

// mappingService 以指定的落地面組出服務（故障注入用同一支）
func mappingService(db *gorm.DB, sink port.TxSink) *identity.IdentitySourceService {
	return identity.NewIdentitySourceService(db, sink)
}

// setupMappingDB sqlite in-memory 環境（連線數 1：純 Go driver 的每條連線是
// 各自獨立的空 DB）。
func setupMappingDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	// UserRole 必須排在 User／Role 之後：GORM 對 many2many 關聯表的處理會蓋掉
	// 排在它之前的關聯 model 宣告，建出的表少一欄且編譯與 vet 都看不出來
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{},
		&model.AuditLog{}, &model.LDAPDirectory{}, &model.OIDCProvider{},
		&model.UserExternalIdentity{}, &model.RefreshToken{}, &model.Session{},
		&model.GroupRoleMapping{}, &model.UserRoleMapping{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, name := range []string{model.RoleAdmin, model.RoleUser, "auditor"} {
		if err := db.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
	}
	if err := db.Create(&model.User{Username: "admin", Password: "x", Active: true}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return db
}

// seedDirectory 建一列目錄設定（attrGroup 為空即「未設群組屬性名」）
func seedDirectory(t *testing.T, db *gorm.DB, attrGroup string) *model.LDAPDirectory {
	t.Helper()
	row := &model.LDAPDirectory{
		Singleton: 1, Name: "corp", URL: "ldaps://ldap.example.com:636",
		BaseDN: "dc=example,dc=com", UserFilter: "(uid=%s)", AttrGroup: attrGroup,
		Enabled: true, BindPasswordEnc: "enc",
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed directory: %v", err)
	}
	return row
}

// seedMappingProvider 建一列 provider（groupsClaim 為空即「未設群組宣告名」）
func seedMappingProvider(t *testing.T, db *gorm.DB, groupsClaim, scopes string) *model.OIDCProvider {
	t.Helper()
	row := &model.OIDCProvider{
		Name: "dex", Issuer: "https://idp.example.com", ClientID: "cid",
		Scopes: scopes, GroupsClaim: groupsClaim, Enabled: true,
		AdmissionMode: model.AdmissionPreboundOnly, ClientSecretEnc: "enc",
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	return row
}

func mappingInput(matchValue, role string, ack bool) identity.GroupRoleMappingInput {
	return identity.GroupRoleMappingInput{
		MatchValue: matchValue, Role: role, RiskAcknowledged: ack, Actor: mappingTestActor,
	}
}

func countAuditEvent(t *testing.T, db *gorm.DB, event string) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AuditLog{}).
		Where("details LIKE ?", "%\""+event+"\"%").Count(&n).Error; err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// TestGroupRoleMappingCRUDAudit 三條 CRUD 路徑各留一列，且留痕失敗即整筆回滾。
func TestGroupRoleMappingCRUDAudit(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())
	dir := seedDirectory(t, db, "memberOf")

	created, err := svc.CreateMapping(model.RoleMappingChannelKindDirectory, dir.ID,
		mappingInput("cn=ops,ou=groups,dc=example,dc=com", model.RoleUser, false))
	if err != nil {
		t.Fatalf("建立規則: %v", err)
	}
	if got := countAuditEvent(t, db, identity.MappingAuditEventCreate); got != 1 {
		t.Fatalf("建立事件審計列數 = %d，want 1", got)
	}

	if _, err := svc.UpdateMapping(model.RoleMappingChannelKindDirectory, dir.ID, created.ID,
		mappingInput("cn=ops,ou=groups,dc=example,dc=com", "auditor", false)); err != nil {
		t.Fatalf("更新規則: %v", err)
	}
	if got := countAuditEvent(t, db, identity.MappingAuditEventUpdate); got != 1 {
		t.Fatalf("更新事件審計列數 = %d，want 1", got)
	}

	if err := svc.DeleteMapping(model.RoleMappingChannelKindDirectory, dir.ID, created.ID,
		mappingTestActor); err != nil {
		t.Fatalf("刪除規則: %v", err)
	}
	if got := countAuditEvent(t, db, identity.MappingAuditEventDelete); got != 1 {
		t.Fatalf("刪除事件審計列數 = %d，want 1", got)
	}

	// fail-close：留痕寫不進去，規則列就不許建起來
	failing := mappingService(db, failingTxSink{})
	if _, err := failing.CreateMapping(model.RoleMappingChannelKindDirectory, dir.ID,
		mappingInput("cn=none,ou=groups,dc=example,dc=com", model.RoleUser, false)); err == nil {
		t.Fatal("審計注入失敗時建立規則應回錯")
	}
	total, _, err := identity.CountMappings(db, model.RoleMappingChannelKindDirectory, dir.ID)
	if err != nil {
		t.Fatalf("計數: %v", err)
	}
	if total != 0 {
		t.Fatalf("審計失敗後規則列數 = %d，want 0（整筆回滾）", total)
	}
}

// TestSourceWithMappingsRefusesDelete 仍有規則的來源不可刪除（兩種型別各一次）。
func TestSourceWithMappingsRefusesDelete(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())
	dir := seedDirectory(t, db, "memberOf")
	provider := seedMappingProvider(t, db, "groups", "openid groups")

	if _, err := svc.CreateMapping(model.RoleMappingChannelKindDirectory, dir.ID,
		mappingInput("cn=ops,ou=groups,dc=example,dc=com", model.RoleUser, false)); err != nil {
		t.Fatalf("建立目錄規則: %v", err)
	}
	if _, err := svc.CreateMapping(model.RoleMappingChannelKindProvider, provider.ID,
		mappingInput("ops", model.RoleUser, false)); err != nil {
		t.Fatalf("建立提供者規則: %v", err)
	}

	dirSvc := identity.NewLDAPDirectoryService(db, nil, audit.NewTxSink())
	dirSvc.SetTransmissionPolicy(ldapAllowAllGate{})
	if err := dirSvc.Delete(t.Context(), identity.LDAPDirectoryActor{ID: 1, Name: "admin"}); !errors.Is(err,
		identity.ErrLDAPDirectoryHasMappings) {
		t.Fatalf("目錄刪除 err = %v，want ErrLDAPDirectoryHasMappings", err)
	}

	providerSvc := identity.NewOIDCProviderService(db, nil, testEgress(), nil, "https://bastion.example.com")
	if err := providerSvc.Delete(provider.ID); !errors.Is(err, identity.ErrOIDCProviderHasMappings) {
		t.Fatalf("提供者刪除 err = %v，want ErrOIDCProviderHasMappings", err)
	}

	// 政策的邊界：規則清掉之後刪得掉（拒刪不是永久封死）
	rules, err := svc.ListMappings(model.RoleMappingChannelKindProvider, provider.ID)
	if err != nil {
		t.Fatalf("列規則: %v", err)
	}
	for _, r := range rules {
		if err := svc.DeleteMapping(model.RoleMappingChannelKindProvider, provider.ID, r.ID,
			mappingTestActor); err != nil {
			t.Fatalf("刪規則: %v", err)
		}
	}
	if err := providerSvc.Delete(provider.ID); err != nil {
		t.Fatalf("規則清空後刪除提供者: %v", err)
	}
}

// ackWarnings 取回「需要確認」錯誤帶的警告碼
func ackWarnings(t *testing.T, err error) []string {
	t.Helper()
	var ackErr *identity.MappingAckRequiredError
	if !errors.As(err, &ackErr) {
		t.Fatalf("err = %v，want *MappingAckRequiredError", err)
	}
	return ackErr.Warnings
}

func hasWarning(codes []string, want string) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

// TestAdminRoleMappingRequiresAck 映射至管理員角色要求確認，確認後存得下且留痕。
func TestAdminRoleMappingRequiresAck(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())
	dir := seedDirectory(t, db, "memberOf")

	_, err := svc.CreateMapping(model.RoleMappingChannelKindDirectory, dir.ID,
		mappingInput("cn=pam-admins,ou=groups,dc=example,dc=com", model.RoleAdmin, false))
	codes := ackWarnings(t, err)
	if !hasWarning(codes, "MAPPING_TARGETS_ADMIN_ROLE") {
		t.Fatalf("警告碼 = %v，want 含 MAPPING_TARGETS_ADMIN_ROLE", codes)
	}
	total, _, cerr := identity.CountMappings(db, model.RoleMappingChannelKindDirectory, dir.ID)
	if cerr != nil {
		t.Fatalf("計數: %v", cerr)
	}
	if total != 0 {
		t.Fatalf("未確認時規則列數 = %d，want 0", total)
	}

	// 重送帶確認：存得下，且確認的事實一併留痕（不阻擋，但不知情不行）
	if _, err := svc.CreateMapping(model.RoleMappingChannelKindDirectory, dir.ID,
		mappingInput("cn=pam-admins,ou=groups,dc=example,dc=com", model.RoleAdmin, true)); err != nil {
		t.Fatalf("帶確認建立: %v", err)
	}
	var n int64
	if err := db.Model(&model.AuditLog{}).
		Where("details LIKE ?", "%\"risk_acknowledged\":true%").Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("帶確認的審計列數 = %d，want 1", n)
	}
}

// TestUnsetSourceAttrMappingRequiresAck 指向尚未設定群組屬性名／宣告名的來源時要求確認。
func TestUnsetSourceAttrMappingRequiresAck(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())
	dir := seedDirectory(t, db, "")                            // 未設群組屬性名
	provider := seedMappingProvider(t, db, "", "openid email") // 未設群組宣告名

	_, err := svc.CreateMapping(model.RoleMappingChannelKindDirectory, dir.ID,
		mappingInput("cn=ops,ou=groups,dc=example,dc=com", model.RoleUser, false))
	if codes := ackWarnings(t, err); !hasWarning(codes, "MAPPING_SOURCE_ATTR_UNSET") {
		t.Fatalf("目錄側警告碼 = %v，want 含 MAPPING_SOURCE_ATTR_UNSET", codes)
	}
	_, err = svc.CreateMapping(model.RoleMappingChannelKindProvider, provider.ID,
		mappingInput("ops", model.RoleUser, false))
	if codes := ackWarnings(t, err); !hasWarning(codes, "MAPPING_SOURCE_ATTR_UNSET") {
		t.Fatalf("提供者側警告碼 = %v，want 含 MAPPING_SOURCE_ATTR_UNSET", codes)
	}

	// 確認後存得下：管理者可以先建規則再回頭補設定（阻擋只會逼人繞路）
	if _, err := svc.CreateMapping(model.RoleMappingChannelKindProvider, provider.ID,
		mappingInput("ops", model.RoleUser, true)); err != nil {
		t.Fatalf("帶確認建立: %v", err)
	}

	// 屬性名已設好的來源不要求確認（警告不是常態噪音）
	set := seedMappingProvider(t, db, "groups", "openid groups")
	if _, err := svc.CreateMapping(model.RoleMappingChannelKindProvider, set.ID,
		mappingInput("ops", model.RoleUser, false)); err != nil {
		t.Fatalf("已設宣告名的來源不應要求確認: %v", err)
	}
}

// TestMappingCRUDMaintainsSourceHasRulesFlag 登入側「本來源有無啟用中的規則」的
// 判準隨 CRUD 變動。
//
// 該判準是對規則表的一次索引計數而非反正規化旗標，故這裡驗的是計數本身：
// 建立 → 有；停用 → 無（停用的規則於重算時視同不存在）；重新啟用 → 有；刪除 → 無。
// 判準失效的症狀是「規則設了卻零命中且沒有任何訊號」。
func TestMappingCRUDMaintainsSourceHasRulesFlag(t *testing.T) {
	db := setupMappingDB(t)
	svc := mappingService(db, audit.NewTxSink())
	provider := seedMappingProvider(t, db, "groups", "openid groups")

	enabledCount := func() int64 {
		t.Helper()
		_, enabled, err := identity.CountMappings(db, model.RoleMappingChannelKindProvider, provider.ID)
		if err != nil {
			t.Fatalf("計數: %v", err)
		}
		return enabled
	}
	if got := enabledCount(); got != 0 {
		t.Fatalf("初始啟用中規則數 = %d，want 0", got)
	}

	created, err := svc.CreateMapping(model.RoleMappingChannelKindProvider, provider.ID,
		mappingInput("ops", model.RoleUser, false))
	if err != nil {
		t.Fatalf("建立: %v", err)
	}
	if got := enabledCount(); got != 1 {
		t.Fatalf("建立後啟用中規則數 = %d，want 1", got)
	}

	off, on := false, true
	in := mappingInput("ops", model.RoleUser, false)
	in.Enabled = &off
	if _, err := svc.UpdateMapping(model.RoleMappingChannelKindProvider, provider.ID, created.ID, in); err != nil {
		t.Fatalf("停用: %v", err)
	}
	if got := enabledCount(); got != 0 {
		t.Fatalf("停用後啟用中規則數 = %d，want 0", got)
	}

	in.Enabled = &on
	if _, err := svc.UpdateMapping(model.RoleMappingChannelKindProvider, provider.ID, created.ID, in); err != nil {
		t.Fatalf("重新啟用: %v", err)
	}
	if got := enabledCount(); got != 1 {
		t.Fatalf("重新啟用後啟用中規則數 = %d，want 1", got)
	}

	if err := svc.DeleteMapping(model.RoleMappingChannelKindProvider, provider.ID, created.ID,
		mappingTestActor); err != nil {
		t.Fatalf("刪除: %v", err)
	}
	if got := enabledCount(); got != 0 {
		t.Fatalf("刪除後啟用中規則數 = %d，want 0", got)
	}
	// 另一個來源的規則不算進來（來源分域）
	other := seedMappingProvider(t, db, "groups", "openid groups")
	if _, err := svc.CreateMapping(model.RoleMappingChannelKindProvider, other.ID,
		mappingInput("ops", model.RoleUser, false)); err != nil {
		t.Fatalf("建立他來源規則: %v", err)
	}
	if got := enabledCount(); got != 0 {
		t.Fatalf("他來源建規則後本來源啟用中規則數 = %d，want 0", got)
	}
}
