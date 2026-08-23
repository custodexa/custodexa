package asset

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/modules/audit"
)

// newTransmissionRiskAssetDB 資產列表風險項測試用的 in-memory DB。
// 原夾具來自 transmission_inventory_service_test.go 的 setupInventorySvc；該檔
// 已遷入 internal/modules/policy 並改為外部測試套件，本測試驗的是
// asset 側的 AssetService.List 行為，故遷入本包並自備夾具。
func newTransmissionRiskAssetDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetGroup{}, &model.AssetNode{}, &model.SecurityPolicy{},
		&model.SyslogSetting{}, &model.NotificationChannel{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// TestAssetListCarriesTransmissionRisks 資產列表 API 附風險項（5.1）：
// 判定在後端單一所在，前端徽章純呈現；不分政策等級恆填
func TestAssetListCarriesTransmissionRisks(t *testing.T) {
	db := newTransmissionRiskAssetDB(t)
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	assetSvc, err := NewAssetService(aesColumnCodec(t, []byte("dev-key-for-testing-only-ok32bts")), "guacd", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatal(err)
	}
	assetSvc.SetTransmissionPolicy(policy.NewTransmissionPolicyService(newPolicyServiceForTest(t), nil))

	for _, a := range []model.Asset{
		{Name: "vnc-risky", Protocol: model.ProtocolVNC, Host: "h", Port: 5900, CreatedBy: 1},
		{Name: "db-safe", Protocol: model.ProtocolMySQL, Host: "h", Port: 3306, CreatedBy: 1, DBTLSMode: "require"},
	} {
		asset := a
		if err := db.Create(&asset).Error; err != nil {
			t.Fatal(err)
		}
	}

	resp, err := assetSvc.List(&AssetFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	byName := map[string][]policy.RiskItem{}
	for _, a := range resp.Data {
		byName[a.Name] = a.TransmissionRisks
	}
	if len(byName["vnc-risky"]) != 1 || byName["vnc-risky"][0].Key != policy.RiskVNCUnencrypted {
		t.Errorf("vnc 資產應附 vnc_unencrypted 風險, got %v", byName["vnc-risky"])
	}
	if len(byName["db-safe"]) != 0 {
		t.Errorf("TLS 已啟資產不應附風險, got %v", byName["db-safe"])
	}
}

// newPolicyServiceForTest 政策服務夾具（原件在 identity 側的
// ldap_directory_service_test.go，搬檔後跨包取不到）。逐行複製，只用匯出面。
func newPolicyServiceForTest(t *testing.T) *policy.SecurityPolicyService {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return policy.NewSecurityPolicyService(db)
}
