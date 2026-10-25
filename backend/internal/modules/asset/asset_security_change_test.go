package asset

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// recordingAlertSink 記錄型落地面：只記下收到的事件，可注入固定錯誤。
type recordingAlertSink struct {
	events []port.SystemAlertEvent
	err    error
}

func (r *recordingAlertSink) RaiseInTx(_ *gorm.DB, ev port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	if r.err != nil {
		return port.SystemAlertReceipt{}, r.err
	}
	r.events = append(r.events, ev)
	return port.SystemAlertReceipt{}, nil
}

func baseSecurityAsset() *model.Asset {
	return &model.Asset{
		Name: "a", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22,
		RDPSecurity: model.RDPSecurityNLA, RDPVerifyCert: true,
		DBTLSMode: "verify-full", WinrmTLSMode: "ca",
	}
}

func TestAssetSecurityChangeAlerts(t *testing.T) {
	addr, relax := port.SystemAlertAssetAddressChanged, port.SystemAlertTransportVerificationRelaxed

	// 第 4 節每一列：觸發方向各一條、收緊方向各一條（不觸發）
	cases := []struct {
		name   string
		mutate func(a *model.Asset)
		want   map[port.SystemAlertType][]string
	}{
		{"host 變更", func(a *model.Asset) { a.Host = "10.0.0.2" }, map[port.SystemAlertType][]string{addr: {"host"}}},
		{"port 變更", func(a *model.Asset) { a.Port = 2222 }, map[port.SystemAlertType][]string{addr: {"port"}}},
		{"protocol 變更", func(a *model.Asset) { a.Protocol = model.ProtocolRDP }, map[port.SystemAlertType][]string{addr: {"protocol"}}},
		{"rotation_channel 變更", func(a *model.Asset) { a.RotationChannel = "windows_ssh" }, map[port.SystemAlertType][]string{addr: {"rotation_channel"}}},
		{"winrm_scheme 變更", func(a *model.Asset) { a.WinrmScheme = "https" }, map[port.SystemAlertType][]string{addr: {"winrm_scheme"}}},
		{"winrm_port 變更", func(a *model.Asset) { a.WinrmPort = 5986 }, map[port.SystemAlertType][]string{addr: {"winrm_port"}}},
		{"rotation_ssh_port 變更", func(a *model.Asset) { a.RotationSSHPort = 2200 }, map[port.SystemAlertType][]string{addr: {"rotation_ssh_port"}}},
		{"sftp_port 變更", func(a *model.Asset) { a.SftpPort = 2022 }, map[port.SystemAlertType][]string{addr: {"sftp_port"}}},
		{"sftp_enabled 關到開", func(a *model.Asset) { a.SftpEnabled = true }, map[port.SystemAlertType][]string{addr: {"sftp_enabled"}}},
		{"rdp_verify_cert 開到關", func(a *model.Asset) { a.RDPVerifyCert = false }, map[port.SystemAlertType][]string{relax: {"rdp_verify_cert"}}},
		{"rdp_security nla 到 tls", func(a *model.Asset) { a.RDPSecurity = model.RDPSecurityTLS }, map[port.SystemAlertType][]string{relax: {"rdp_security"}}},
		{"rdp_security nla 到未設定", func(a *model.Asset) { a.RDPSecurity = "" }, map[port.SystemAlertType][]string{relax: {"rdp_security"}}},
		{"db_tls_mode verify-full 到 verify-ca", func(a *model.Asset) { a.DBTLSMode = "verify-ca" }, map[port.SystemAlertType][]string{relax: {"db_tls_mode"}}},
		{"db_tls_mode verify-full 到未設定", func(a *model.Asset) { a.DBTLSMode = "" }, map[port.SystemAlertType][]string{relax: {"db_tls_mode"}}},
		{"db_tls_mode 未設定到 disable", func(a *model.Asset) { a.DBTLSMode = ""; a.DBTLSMode = "disable" }, map[port.SystemAlertType][]string{relax: {"db_tls_mode"}}},
		{"k8s_insecure_skip_tls 關到開", func(a *model.Asset) { a.K8sInsecureSkipTLS = true }, map[port.SystemAlertType][]string{relax: {"k8s_insecure_skip_tls"}}},
		{"winrm_tls_mode 改為 insecure", func(a *model.Asset) { a.WinrmTLSMode = "insecure" }, map[port.SystemAlertType][]string{relax: {"winrm_tls_mode"}}},
		{"db_ca_cert 設定", func(a *model.Asset) { a.DBCACert = "PEM-1" }, map[port.SystemAlertType][]string{relax: {"db_ca_cert"}}},
		{"k8s_ca_cert 替換", func(a *model.Asset) { a.K8sCACert = "PEM-2" }, map[port.SystemAlertType][]string{relax: {"k8s_ca_cert"}}},
		{"winrm_ca_cert 清除", func(a *model.Asset) { a.WinrmCACert = "" }, nil}, // 見下方獨立子案例
		{"多類命中各一個事件", func(a *model.Asset) {
			a.Host = "10.0.0.9"
			a.Port = 2200
			a.RDPVerifyCert = false
			a.K8sInsecureSkipTLS = true
			a.DBCACert = "PEM-3"
		}, map[port.SystemAlertType][]string{
			addr:  {"host", "port"},
			relax: {"rdp_verify_cert", "k8s_insecure_skip_tls", "db_ca_cert"},
		}},

		// 收緊方向與表外欄位：不觸發
		{"sftp_enabled 開到關", func(a *model.Asset) { a.SftpEnabled = false }, nil},
		{"rdp_verify_cert 關到開（收緊）", func(a *model.Asset) { a.RDPVerifyCert = true }, nil},
		{"rdp_security tls 到 nla（收緊）", func(a *model.Asset) { a.RDPSecurity = model.RDPSecurityNLA }, nil},
		{"db_tls_mode disable 到 verify-ca（收緊）", func(a *model.Asset) { a.DBTLSMode = "verify-ca" }, nil},
		{"k8s_insecure_skip_tls 開到關（收緊）", func(a *model.Asset) { a.K8sInsecureSkipTLS = false }, nil},
		{"winrm_tls_mode insecure 到 ca（收緊）", func(a *model.Asset) { a.WinrmTLSMode = "ca" }, nil},
		{"表外欄位 name、tags、db_name、description", func(a *model.Asset) {
			a.Name = "renamed"
			a.Tags = "x,y"
			a.DBName = "other"
			a.Description = "d"
		}, nil},
	}

	for _, tc := range cases {
		if tc.name == "winrm_ca_cert 清除" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			old := baseSecurityAsset()
			// 收緊案例需要較弱的舊值
			switch tc.name {
			case "sftp_enabled 開到關":
				old.SftpEnabled = true
			case "rdp_verify_cert 關到開（收緊）":
				old.RDPVerifyCert = false
			case "rdp_security tls 到 nla（收緊）":
				old.RDPSecurity = model.RDPSecurityTLS
			case "db_tls_mode disable 到 verify-ca（收緊）":
				old.DBTLSMode = "disable"
			case "k8s_insecure_skip_tls 開到關（收緊）":
				old.K8sInsecureSkipTLS = true
			case "winrm_tls_mode insecure 到 ca（收緊）":
				old.WinrmTLSMode = "insecure"
			case "db_tls_mode 未設定到 disable":
				old.DBTLSMode = ""
			}
			next := *old
			tc.mutate(&next)
			got := ClassifyAssetSecurityChange(old, &next)
			if len(got) != len(tc.want) {
				t.Fatalf("事件數 %d，預期 %d：%+v", len(got), len(tc.want), got)
			}
			for _, g := range got {
				want, ok := tc.want[g.Type]
				if !ok {
					t.Fatalf("多出類型 %s", g.Type)
				}
				if strings.Join(g.Fields, ",") != strings.Join(want, ",") {
					t.Fatalf("%s 欄位 %v，預期 %v", g.Type, g.Fields, want)
				}
			}
		})
	}

	t.Run("winrm_ca_cert 清除屬傳輸放寬類", func(t *testing.T) {
		old := baseSecurityAsset()
		old.WinrmCACert = "PEM"
		next := *old
		next.WinrmCACert = ""
		got := ClassifyAssetSecurityChange(old, &next)
		if len(got) != 1 || got[0].Type != relax || strings.Join(got[0].Fields, ",") != "winrm_ca_cert" {
			t.Fatalf("清除 CA 應歸傳輸放寬類：%+v", got)
		}
	})

	// Update 實走：事件內容、序列化不含秘密、關聯識別與審計明細一致
	t.Run("Update 於同交易寫入事件", func(t *testing.T) {
		db := setupAccountDB(t)
		assets, _ := newAccountServices(t)
		rec := &recordingAlertSink{}
		assets.SetSecurityChangeAlertSink(rec)
		a := mustCreateAsset(t, assets, "srv-ev", "10.0.0.1")
		if len(rec.events) != 0 {
			t.Fatalf("Create 不應產生事件，收到 %d", len(rec.events))
		}

		host := "10.0.0.77"
		pw := "NewPw-Secret-123"
		sftpPw := "Sftp-Secret-456"
		if _, err := assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{Host: &host, Password: &pw, SftpPassword: &sftpPw}); err != nil {
			t.Fatalf("更新: %v", err)
		}
		if len(rec.events) != 1 {
			t.Fatalf("改 host 應恰一個事件，實得 %d", len(rec.events))
		}
		ev := rec.events[0]
		if ev.Type != port.SystemAlertAssetAddressChanged || ev.Target.Kind != port.SystemAlertTargetAsset ||
			ev.AssetID == nil || *ev.AssetID != a.ID || ev.Actor.UserID != 1 || ev.Actor.Username != "admin" ||
			ev.Params["changed_fields"] != "host" || ev.Params["asset_name"] != "srv-ev" {
			t.Fatalf("事件內容不符：%+v", ev)
		}
		raw, _ := json.Marshal(ev)
		for _, secret := range []string{pw, sftpPw, "root", "s3cret", "10.0.0.77", "10.0.0.1"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("事件序列化含不應出現的字串 %q：%s", secret, raw)
			}
		}
		if ev.CorrelationID == "" {
			t.Fatal("事件缺關聯識別")
		}
		var n int64
		db.Model(&model.AuditLog{}).Where("details LIKE ?", `%"correlation_id":"`+ev.CorrelationID+`"%`).Count(&n)
		if n != 1 {
			t.Fatalf("同交易審計列應恰一筆帶同一關聯識別，實得 %d", n)
		}

		// 表外欄位與收緊：不再收到事件
		desc := "only description"
		if _, err := assets.Update(adminCtx(), a.ID, &UpdateAssetRequest{Description: &desc}); err != nil {
			t.Fatalf("更新描述: %v", err)
		}
		if len(rec.events) != 1 {
			t.Fatalf("只改描述不應產生事件，累計 %d", len(rec.events))
		}
	})

	t.Run("Update 落地面未注入即回錯且全回滾", func(t *testing.T) {
		db := setupAccountDB(t)
		assets, _ := newAccountServices(t)
		a := mustCreateAsset(t, assets, "srv-nosink", "10.0.0.1")
		host := "10.0.0.5"
		_, err := assets.Update(adminCtx(), a.ID, &UpdateAssetRequest{Host: &host})
		if !errors.Is(err, port.ErrSystemAlertSinkMissing) {
			t.Fatalf("未注入時應回 ErrSystemAlertSinkMissing，實得 %v", err)
		}
		var row model.Asset
		if err := db.First(&row, a.ID).Error; err != nil || row.Host != "10.0.0.1" {
			t.Fatalf("資產主機應維持原值，實得 %q / %v", row.Host, err)
		}
	})

	t.Run("Create 與匯入不呼叫落地面", func(t *testing.T) {
		setupAccountDB(t)
		assets, _ := newAccountServices(t)
		rec := &recordingAlertSink{}
		assets.SetSecurityChangeAlertSink(rec)
		mustCreateAsset(t, assets, "srv-c1", "10.0.0.1")
		_, err := assets.ImportAssets(adminCtx(), &ImportBatch{Source: ImportSourceForm, Rows: []ImportRow{
			{Name: "imp-1", Protocol: "ssh", Host: "10.3.0.2"},
		}}, 1, "admin")
		if err != nil {
			t.Fatalf("匯入提交: %v", err)
		}
		if len(rec.events) != 0 {
			t.Fatalf("建立與匯入提交後落地面應收到 0 筆，實得 %d", len(rec.events))
		}
	})
}
