package audit

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupGatedChannelSvc 帶傳輸政策閘的通知服務（transmission-security-policy 3.1）
func setupGatedChannelSvc(t *testing.T) (*NotificationChannelService, *policy.SecurityPolicyService, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.NotificationChannel{}, &model.SecurityPolicy{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	svc := NewNotificationChannelService(db, nil)
	policies := policy.NewSecurityPolicyService(db)
	svc.SetTransmissionPolicy(policy.NewTransmissionPolicyService(policies, nil))
	return svc, policies, db
}

func httpChannelReq(ack bool) *NotificationChannelRequest {
	return &NotificationChannelRequest{
		Name: "ops", URL: "http://hooks.internal/x",
		RiskAcknowledged: ack, ActorID: 1, ActorName: "admin", ActorIP: "10.0.0.1",
	}
}

func TestNotifyGateOffAllowsHTTP(t *testing.T) {
	svc, _, _ := setupGatedChannelSvc(t)

	// off（預設）：http 照存，行為與現狀一致
	if _, err := svc.Create(httpChannelReq(false)); err != nil {
		t.Fatalf("off 檔存 http 應成功: %v", err)
	}
}

func TestNotifyGateWarnRequiresAck(t *testing.T) {
	svc, policies, db := setupGatedChannelSvc(t)
	policies.Update(policy.PolicyTransportNotifyLevel, policy.TransportLevelWarn, "admin")

	// 未附確認：拒絕並回風險項
	_, err := svc.Create(httpChannelReq(false))
	var gateErr *policy.TransmissionGateError
	if !errors.As(err, &gateErr) || gateErr.Code != policy.TransmissionGateAckRequired {
		t.Fatalf("err = %v, want ack_required", err)
	}

	// 附確認：存檔成功＋聲明入審計
	if _, err := svc.Create(httpChannelReq(true)); err != nil {
		t.Fatalf("warn＋確認應成功: %v", err)
	}
	var n int64
	db.Model(&model.AuditLog{}).Where("resource = ?", model.ResourceTransmission).Count(&n)
	if n != 1 {
		t.Errorf("確認聲明審計筆數 = %d, want 1", n)
	}

	// https 不受閘
	if _, err := svc.Create(&NotificationChannelRequest{Name: "safe", URL: "https://hooks.example.com/x"}); err != nil {
		t.Errorf("warn 檔存 https 不應受閘: %v", err)
	}
}

func TestNotifyGateStrictRejects(t *testing.T) {
	svc, policies, _ := setupGatedChannelSvc(t)
	policies.Update(policy.PolicyTransportNotifyLevel, policy.TransportLevelStrict, "admin")

	// strict：確認也無效
	_, err := svc.Create(httpChannelReq(true))
	var gateErr *policy.TransmissionGateError
	if !errors.As(err, &gateErr) || gateErr.Code != policy.TransmissionGateStrictReject {
		t.Fatalf("err = %v, want strict_reject", err)
	}
}

func TestNotifyGateUpdateEvaluatesEffectiveURL(t *testing.T) {
	svc, policies, _ := setupGatedChannelSvc(t)

	// off 檔先建一條存量 http 通道
	created, err := svc.Create(httpChannelReq(false))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// 收緊為 strict：存量通道不被停用，但再次存檔（未帶 URL＝沿用 http）被拒
	policies.Update(policy.PolicyTransportNotifyLevel, policy.TransportLevelStrict, "admin")
	_, err = svc.Update(created.ID, &NotificationChannelRequest{Name: "ops-renamed"})
	var gateErr *policy.TransmissionGateError
	if !errors.As(err, &gateErr) {
		t.Fatalf("沿用 http 的再存檔應被 strict 拒絕, err = %v", err)
	}

	// 改成 https 即可存
	if _, err := svc.Update(created.ID, &NotificationChannelRequest{
		Name: "ops", URL: "https://hooks.example.com/x",
	}); err != nil {
		t.Fatalf("改 https 應通過: %v", err)
	}
}

func TestNotifyListMarksDeviation(t *testing.T) {
	svc, _, _ := setupGatedChannelSvc(t)

	if _, err := svc.Create(httpChannelReq(false)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Create(&NotificationChannelRequest{Name: "safe", URL: "https://hooks.example.com/x"}); err != nil {
		t.Fatalf("Create https: %v", err)
	}

	channels, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	byName := map[string]bool{}
	for _, ch := range channels {
		byName[ch.Name] = ch.TransmissionDeviation
	}
	if !byName["ops"] {
		t.Error("http 通道應標傳輸偏離")
	}
	if byName["safe"] {
		t.Error("https 通道不應標偏離")
	}
}
