package policy_test

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 清冊分列 db_rotation 通道：只計改密通道為 db_native 的 mysql／postgres／mssql 資產，
// 依 TLS 檔位分布，偏離數與資產傳輸風險同一判定；連線通道 db 的計數不受影響。
func TestInventoryListsDBRotationChannel(t *testing.T) {
	svc, _, db := setupInventorySvc(t, nil)
	for _, a := range []model.Asset{
		{Name: "my-native-unset", Protocol: model.ProtocolMySQL, Host: "h", Port: 3306, CreatedBy: 1,
			RotationChannel: model.RotationChannelDBNative},
		{Name: "pg-native-disable", Protocol: model.ProtocolPostgres, Host: "h", Port: 5432, CreatedBy: 1,
			RotationChannel: model.RotationChannelDBNative, DBTLSMode: "disable"},
		{Name: "ms-native-full", Protocol: model.ProtocolMSSQL, Host: "h", Port: 1433, CreatedBy: 1,
			RotationChannel: model.RotationChannelDBNative, DBTLSMode: "verify-full"},
		{Name: "my-plain", Protocol: model.ProtocolMySQL, Host: "h", Port: 3306, CreatedBy: 1},
		{Name: "win-http", Protocol: model.ProtocolRDP, Host: "h", Port: 3389, CreatedBy: 1,
			RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP},
	} {
		asset := a
		if err := db.Create(&asset).Error; err != nil {
			t.Fatal(err)
		}
	}
	// 直寫資料庫繞過驗證的髒資料：redis 帶 db_native
	if err := db.Create(&model.Asset{Name: "redis-dirty", Protocol: model.ProtocolRedis, Host: "h", Port: 6379, CreatedBy: 1}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.Asset{}).Where("name = ?", "redis-dirty").
		UpdateColumn("rotation_channel", model.RotationChannelDBNative).Error; err != nil {
		t.Fatal(err)
	}

	inv, err := svc.Build()
	if err != nil {
		t.Fatal(err)
	}
	ch := channelOf(t, inv, policy.TransportChannelDBRotation)
	if ch.TotalCount != 3 || ch.AtRiskCount != 2 {
		t.Errorf("db_rotation total=%d at_risk=%d, want 3/2", ch.TotalCount, ch.AtRiskCount)
	}
	if len(ch.DetailCodes) != 3 || ch.DetailCodes["unset"] != 1 || ch.DetailCodes["disable"] != 1 || ch.DetailCodes["verify-full"] != 1 {
		t.Errorf("detail_codes = %v", ch.DetailCodes)
	}
	if ch.Level != "" {
		t.Errorf("db_rotation 無政策等級, got %q", ch.Level)
	}
	if ch.PreflightCode != "" || ch.StrictPreflight != "" {
		t.Errorf("db_rotation 無 strict 預檢, got %q/%q", ch.PreflightCode, ch.StrictPreflight)
	}
	if ch.NoteCode != "db_rotation_channel" || ch.Note == "" {
		t.Errorf("note = %q/%q", ch.NoteCode, ch.Note)
	}
	if len(ch.Risks) != 1 || ch.Risks[0].Key != policy.RiskDBRotationUnencrypted {
		t.Errorf("risks = %+v, want 單項 %s", ch.Risks, policy.RiskDBRotationUnencrypted)
	}
	// 連線通道 db 的計數不因改密設定而變（含 redis 與未設改密通道者）
	if dbCh := channelOf(t, inv, policy.TransportChannelDB); dbCh.TotalCount != 5 {
		t.Errorf("db total=%d, want 5", dbCh.TotalCount)
	}
	if w := channelOf(t, inv, policy.TransportChannelWinRM); w.TotalCount != 1 {
		t.Errorf("winrm total=%d, want 1", w.TotalCount)
	}
	// 列序：db_rotation 緊接 winrm
	idx := map[string]int{}
	for i, c := range inv.Channels {
		idx[c.Channel] = i
	}
	if idx[policy.TransportChannelDBRotation] != idx[policy.TransportChannelWinRM]+1 {
		t.Errorf("列序 winrm=%d db_rotation=%d，db_rotation 應緊接 winrm", idx[policy.TransportChannelWinRM], idx[policy.TransportChannelDBRotation])
	}
}

// 全部改密資產皆走 TLS 時無偏離、不帶風險項。
func TestInventoryDBRotationChannelNoRiskWhenEncrypted(t *testing.T) {
	svc, _, db := setupInventorySvc(t, nil)
	asset := model.Asset{Name: "pg-ca", Protocol: model.ProtocolPostgres, Host: "h", Port: 5432, CreatedBy: 1,
		RotationChannel: model.RotationChannelDBNative, DBTLSMode: "verify-ca"}
	if err := db.Create(&asset).Error; err != nil {
		t.Fatal(err)
	}
	inv, err := svc.Build()
	if err != nil {
		t.Fatal(err)
	}
	ch := channelOf(t, inv, policy.TransportChannelDBRotation)
	if ch.TotalCount != 1 || ch.AtRiskCount != 0 {
		t.Errorf("db_rotation total=%d at_risk=%d, want 1/0", ch.TotalCount, ch.AtRiskCount)
	}
	if len(ch.Risks) != 0 {
		t.Errorf("無偏離不應帶風險項, got %+v", ch.Risks)
	}
}
