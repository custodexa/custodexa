package policy

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupConsentSvc(t *testing.T) (*TransmissionConsentService, *SecurityPolicyService, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.TransmissionConsent{},
		&model.AuditLog{}, &model.User{}, &model.Asset{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	policy := NewSecurityPolicyService(db)
	tp := NewTransmissionPolicyService(policy, nil)
	return NewTransmissionConsentService(db, tp), policy, db
}

func vncAsset() *model.Asset {
	return &model.Asset{ID: 7, Name: "vnc-box", Protocol: model.ProtocolVNC}
}

func countAudit(t *testing.T, db *gorm.DB, status model.AuditStatus) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AuditLog{}).
		Where("resource = ? AND status = ?", model.ResourceTransmission, status).
		Count(&n).Error; err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

func TestGateOffZeroImpact(t *testing.T) {
	svc, _, db := setupConsentSvc(t)

	decision := svc.CheckConnect(1, vncAsset(), "10.0.0.1")
	if !decision.Allowed {
		t.Fatal("off 檔（預設）應零影響放行")
	}
	if n := countAudit(t, db, model.StatusDenied); n != 0 {
		t.Errorf("off 檔不應有拒絕審計, got %d", n)
	}
}

func TestGateWarnRequiresConsentOnDirectCall(t *testing.T) {
	svc, policy, _ := setupConsentSvc(t)
	policy.Update(PolicyTransportVNCLevel, TransportLevelWarn, "admin")

	// 繞前端直呼（無同意記憶）：428＋風險項清單
	decision := svc.CheckConnect(1, vncAsset(), "10.0.0.1")
	if decision.Allowed {
		t.Fatal("warn 無同意應被擋")
	}
	if decision.Status != http.StatusPreconditionRequired {
		t.Errorf("status = %d, want 428", decision.Status)
	}
	if len(decision.Risks) != 1 || decision.Risks[0].Key != RiskVNCUnencrypted {
		t.Errorf("risks = %v, want [vnc_unencrypted]", decision.Risks)
	}
}

func TestConsentFlowAndIdempotentUpdate(t *testing.T) {
	svc, policy, db := setupConsentSvc(t)
	policy.Update(PolicyTransportVNCLevel, TransportLevelWarn, "admin")
	asset := vncAsset()

	// 立據 → 放行
	if _, err := svc.Record(1, asset, []string{RiskVNCUnencrypted}, "10.0.0.1"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !svc.CheckConnect(1, asset, "10.0.0.1").Allowed {
		t.Fatal("有效同意應放行")
	}
	// 同意入審計
	if n := countAudit(t, db, model.StatusSuccess); n != 1 {
		t.Errorf("同意審計筆數 = %d, want 1", n)
	}

	// 重複同意冪等更新：仍一列
	if _, err := svc.Record(1, asset, []string{RiskVNCUnencrypted}, "10.0.0.1"); err != nil {
		t.Fatalf("重複 Record: %v", err)
	}
	var rows int64
	db.Model(&model.TransmissionConsent{}).Where("user_id = ? AND asset_id = ?", 1, asset.ID).Count(&rows)
	if rows != 1 {
		t.Errorf("同 user×asset 應唯一一列, got %d", rows)
	}

	// 同意是 per user：另一 user 無同意
	if svc.CheckConnect(2, asset, "10.0.0.1").Allowed {
		t.Error("他人同意不得沿用")
	}
}

func TestConsentRejectsStaleRiskView(t *testing.T) {
	svc, policy, _ := setupConsentSvc(t)
	policy.Update(PolicyTransportDBLevel, TransportLevelWarn, "admin")

	// 使用者看到的風險集合與當下不符（TOCTOU）：拒絕立據
	asset := &model.Asset{ID: 9, Name: "db", Protocol: model.ProtocolMySQL} // 當下風險=db_tls_disabled
	_, err := svc.Record(1, asset, []string{RiskVNCUnencrypted}, "10.0.0.1")
	if !errors.Is(err, ErrConsentRisksChanged) {
		t.Fatalf("err = %v, want ErrConsentRisksChanged", err)
	}
}

func TestGateTTLExpiry(t *testing.T) {
	svc, policy, db := setupConsentSvc(t)
	policy.Update(PolicyTransportVNCLevel, TransportLevelWarn, "admin")
	asset := vncAsset()

	if _, err := svc.Record(1, asset, []string{RiskVNCUnencrypted}, "10.0.0.1"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// 把 consented_at 撥回 91 天前（TTL 預設 90）
	db.Model(&model.TransmissionConsent{}).Where("user_id = ? AND asset_id = ?", 1, asset.ID).
		Update("consented_at", time.Now().Add(-91*24*time.Hour))
	if svc.CheckConnect(1, asset, "10.0.0.1").Allowed {
		t.Fatal("逾 TTL 的同意應失效")
	}

	// TTL=0 永不過期（動態判定：政策改動立即生效，無回填）
	policy.Update(PolicyTransportConsentTTLDays, "0", "admin")
	if !svc.CheckConnect(1, asset, "10.0.0.1").Allowed {
		t.Fatal("TTL=0 應永不過期")
	}
}

func TestGateFingerprintInvalidation(t *testing.T) {
	svc, policy, _ := setupConsentSvc(t)
	policy.Update(PolicyTransportRDPLevel, TransportLevelWarn, "admin")

	// RDP 預設兩風險項，同意後放行
	asset := &model.Asset{ID: 11, Name: "win", Protocol: model.ProtocolRDP}
	if _, err := svc.Record(1, asset, []string{RiskRDPIgnoreCert, RiskRDPSecurityBelowNLA}, "10.0.0.1"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !svc.CheckConnect(1, asset, "10.0.0.1").Allowed {
		t.Fatal("同意後應放行")
	}

	// 資產傳輸屬性變更（改 nla）→ 風險集合縮小 → fingerprint 不符 → 同意失效
	asset.RDPSecurity = model.RDPSecurityNLA
	decision := svc.CheckConnect(1, asset, "10.0.0.1")
	if decision.Allowed {
		t.Fatal("風險集合變更後舊同意應失效")
	}
	if decision.Status != http.StatusPreconditionRequired {
		t.Errorf("status = %d, want 428（重新同意）", decision.Status)
	}
}

func TestGateStrictIgnoresConsent(t *testing.T) {
	svc, policy, db := setupConsentSvc(t)
	policy.Update(PolicyTransportVNCLevel, TransportLevelWarn, "admin")
	asset := vncAsset()

	// 先在 warn 檔立據
	if _, err := svc.Record(1, asset, []string{RiskVNCUnencrypted}, "10.0.0.1"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// 升 strict：同意不再被接受，無條件拒絕＋審計
	policy.Update(PolicyTransportVNCLevel, TransportLevelStrict, "admin")
	decision := svc.CheckConnect(1, asset, "10.0.0.1")
	if decision.Allowed {
		t.Fatal("strict 不吃同意")
	}
	if decision.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", decision.Status)
	}
	if n := countAudit(t, db, model.StatusDenied); n != 1 {
		t.Errorf("strict 拒絕審計筆數 = %d, want 1", n)
	}

	// strict 檔也不受理新立據
	if _, err := svc.Record(1, asset, []string{RiskVNCUnencrypted}, "10.0.0.1"); !errors.Is(err, ErrConsentNotApplicable) {
		t.Errorf("strict 立據 err = %v, want ErrConsentNotApplicable", err)
	}
}

func TestGateNoRisksAllowsRegardlessOfLevel(t *testing.T) {
	svc, policy, _ := setupConsentSvc(t)
	policy.Update(PolicyTransportDBLevel, TransportLevelStrict, "admin")

	// TLS 已達標的資產在 strict 下照常放行
	asset := &model.Asset{ID: 12, Protocol: model.ProtocolPostgres, DBTLSMode: "verify-full"}
	if !svc.CheckConnect(1, asset, "10.0.0.1").Allowed {
		t.Fatal("無風險項的資產不受 strict 影響")
	}
}
