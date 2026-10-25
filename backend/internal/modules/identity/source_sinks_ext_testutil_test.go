package identity_test

import (
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"

	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

// 身分來源設定變更的留痕落地面是服務的必要依賴（缺注入即寫入失敗）。
// 本檔給單元測試夾具用：以丟棄實作接上，讓與留痕無關的測試不必各自接線；
// 要驗證留痕行為的測試自行注入記錄用實作覆蓋。

type discardSourceTx struct{}

func (discardSourceTx) WriteInTx(*gorm.DB, port.AuditEvent) error { return nil }

type discardSourceAlerts struct{}

func (discardSourceAlerts) RaiseInTx(*gorm.DB, port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, nil
}

func newOIDCProviderServiceT(db *gorm.DB, codec crypto.ColumnCodec, egress *identity.OIDCEgressPolicy,
	deployDedicated []string, baseURL string) *identity.OIDCProviderService {
	ensureSourceAdminTables(db)
	s := identity.NewOIDCProviderService(db, codec, egress, deployDedicated, baseURL)
	s.SetMappingAuditSink(discardSourceTx{})
	s.SetSystemAlertSink(discardSourceAlerts{})
	return s
}

func newLDAPDirectoryServiceT(db *gorm.DB, codec crypto.ColumnCodec, auditTx port.TxSink) *identity.LDAPDirectoryService {
	ensureSourceAdminTables(db)
	s := identity.NewLDAPDirectoryService(db, codec, auditTx)
	s.SetSystemAlertSink(discardSourceAlerts{})
	return s
}

// ensureSourceAdminTables 設定變更事件要統計來源的超級管理者人數，需要這幾張表存在；
// 夾具缺哪張就補哪張（各自單獨遷移，避免關聯表被自動建成兩欄）。
func ensureSourceAdminTables(db *gorm.DB) {
	if db == nil {
		return
	}
	for _, m := range []any{&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.UserExternalIdentity{}} {
		if !db.Migrator().HasTable(m) {
			_ = db.AutoMigrate(m)
		}
	}
}
