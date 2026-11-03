package policy

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 資料庫改密風險只進清冊與資產列表，不進連線前同意閘：db 通道 warn 時，
// db_native＋TLS disable 的資產連線風險只有 db_tls_disabled，同意指紋不含改密風險。
func TestDBRotationRiskNotInConnectConsent(t *testing.T) {
	svc, sp, _ := setupConsentSvc(t)
	sp.Update(PolicyTransportDBLevel, TransportLevelWarn, "admin")
	asset := &model.Asset{ID: 9, Name: "my-native-disable", Protocol: model.ProtocolMySQL,
		RotationChannel: model.RotationChannelDBNative, DBTLSMode: "disable"}

	// 前提：此資產確實帶改密風險，否則下面的斷言沒有鑑別力
	assertRisks(t, svc.policy.AssetRotationRisks(asset), RiskDBRotationUnencrypted)

	assertRisks(t, svc.policy.AssetRisks(asset), RiskDBTLSDisabled)
	decision := svc.CheckConnect(1, asset, "10.0.0.1")
	if decision.Allowed || decision.Status != http.StatusPreconditionRequired {
		t.Fatalf("warn 無同意應 428, got allowed=%v status=%d", decision.Allowed, decision.Status)
	}
	assertRisks(t, decision.Risks, RiskDBTLSDisabled)

	// 只就連線風險立據即放行：改密風險不得成為同意的必要成分
	if _, err := svc.Record(1, asset, []string{RiskDBTLSDisabled}, "10.0.0.1"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !svc.CheckConnect(1, asset, "10.0.0.1").Allowed {
		t.Error("只同意 db_tls_disabled 應放行")
	}
}
