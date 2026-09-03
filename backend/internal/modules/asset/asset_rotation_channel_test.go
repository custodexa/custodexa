package asset

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 改密通道側車（windows-account-rotation）的驗證矩陣、協定切換清空與投影。

// testCAPEM 產一張可解析的自簽憑證（PEM）。
//
// 用真的憑證而非固定字串：驗證函式判的是「x509 解析得開」，
// 以假字串測會讓「解析成功」這一側從未被走過。
func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rotation-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestRotationChannelValidationMatrix 通道與附屬欄位的值域、相容性與必填。
func TestRotationChannelValidationMatrix(t *testing.T) {
	ca := testCAPEM(t)

	cases := []struct {
		name    string
		asset   model.Asset
		wantErr error
	}{
		// --- 合法 ---
		{"未設定於任何協定皆合法", model.Asset{Protocol: model.ProtocolMySQL}, nil},
		{"ssh 顯式 posix_ssh", model.Asset{
			Protocol: model.ProtocolSSH, RotationChannel: model.RotationChannelPosixSSH}, nil},
		{"ssh 顯式 none", model.Asset{
			Protocol: model.ProtocolSSH, RotationChannel: model.RotationChannelNone}, nil},
		{"rdp 顯式 none", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelNone}, nil},
		{"rdp winrm http", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTP}, nil},
		{"rdp winrm https system", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTPS, WinrmTLSMode: model.WinrmTLSModeSystem}, nil},
		{"rdp winrm https ca 帶可解析 PEM", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTPS, WinrmTLSMode: model.WinrmTLSModeCA, WinrmCACert: ca}, nil},
		{"rdp winrm https insecure", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTPS, WinrmTLSMode: model.WinrmTLSModeInsecure}, nil},
		{"rdp windows_ssh 帶埠", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsSSH,
			RotationSSHPort: 2222}, nil},
		{"ssh windows_ssh（Windows OpenSSH）", model.Asset{
			Protocol: model.ProtocolSSH, RotationChannel: model.RotationChannelWindowsSSH}, nil},
		{"winrm 埠 65535 合法", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTP, WinrmPort: 65535}, nil},

		// --- 通道值本身不合 ---
		{"mysql 設 winrm 被拒", model.Asset{
			Protocol: model.ProtocolMySQL, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTP}, ErrInvalidRotationChannel},
		{"vnc 設 windows_ssh 被拒", model.Asset{
			Protocol: model.ProtocolVNC, RotationChannel: model.RotationChannelWindowsSSH},
			ErrInvalidRotationChannel},
		{"rdp 設 posix_ssh 被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelPosixSSH},
			ErrInvalidRotationChannel},
		{"值域外的通道被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: "windows_wmi"}, ErrInvalidRotationChannel},

		// --- 附屬欄位不合 ---
		{"winrm 缺 scheme 被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM},
			ErrInvalidRotationChannelParams},
		{"winrm scheme 值域外被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: "ws"}, ErrInvalidRotationChannelParams},
		{"https 缺 tls_mode 被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTPS}, ErrInvalidRotationChannelParams},
		{"https tls_mode 值域外被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTPS, WinrmTLSMode: "verify-full"},
			ErrInvalidRotationChannelParams},
		{"ca 模式缺 PEM 被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTPS, WinrmTLSMode: model.WinrmTLSModeCA},
			ErrInvalidRotationChannelParams},
		{"ca 模式 PEM 無法解析被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTPS, WinrmTLSMode: model.WinrmTLSModeCA,
			WinrmCACert: "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"},
			ErrInvalidRotationChannelParams},
		{"http 之下設 tls_mode 被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTP, WinrmTLSMode: model.WinrmTLSModeSystem},
			ErrInvalidRotationChannelParams},
		{"winrm 埠 70000 被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTP, WinrmPort: 70000}, ErrInvalidRotationChannelParams},
		{"winrm 埠負值被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: model.WinrmSchemeHTTP, WinrmPort: -1}, ErrInvalidRotationChannelParams},
		{"改密 SSH 埠 70000 被拒", model.Asset{
			Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsSSH,
			RotationSSHPort: 70000}, ErrInvalidRotationChannelParams},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := c.asset
			err := validateRotationChannel(&a)
			if c.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, c.wantErr)
		})
	}
}

// TestRotationChannelValidationRejectedAtServiceBoundary 驗證確實掛在 Create／Update
// 上：驗證函式自己過了不代表端點會用它。
func TestRotationChannelValidationRejectedAtServiceBoundary(t *testing.T) {
	setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)

	_, err := svc.Create(&CreateAssetRequest{
		Name: "mysql-winrm", Protocol: model.ProtocolMySQL, Host: "10.0.0.9", Port: 3306,
		Username: "app", RotationChannel: model.RotationChannelWindowsWinRM,
		WinrmScheme: model.WinrmSchemeHTTP,
	})
	require.ErrorIs(t, err, ErrInvalidRotationChannel, "mysql 資產不得設定 Windows 改密通道")

	created, err := svc.Create(&CreateAssetRequest{
		Name: "rdp-a", Protocol: model.ProtocolRDP, Host: "10.0.0.10", Port: 3389,
		Username: "Administrator",
	})
	require.NoError(t, err)
	require.Equal(t, model.RotationChannelNone, created.EffectiveRotationChannel(),
		"rdp 資產未設定通道時推導為不改密")

	channel := model.RotationChannelWindowsWinRM
	scheme := model.WinrmSchemeHTTPS
	_, err = svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{
		RotationChannel: &channel, WinrmScheme: &scheme,
	})
	require.ErrorIs(t, err, ErrInvalidRotationChannelParams, "https 未指定憑證驗證模式須被拒")

	var stored model.Asset
	require.NoError(t, database.DB.First(&stored, created.ID).Error)
	require.Empty(t, stored.RotationChannel, "驗證失敗時資產不得被部分寫入")
}

// TestRotationChannelClearedOnProtocolChange 協定改為不相容時清空側車並留痕，
// 且改回原協定不得靜默恢復。
func TestRotationChannelClearedOnProtocolChange(t *testing.T) {
	db := setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)
	ca := testCAPEM(t)

	created, err := svc.Create(&CreateAssetRequest{
		Name: "win-1", Protocol: model.ProtocolRDP, Host: "10.0.0.11", Port: 3389,
		Username: "Administrator",
		RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTPS,
		WinrmPort: 5986, WinrmTLSMode: model.WinrmTLSModeCA, WinrmCACert: ca,
	})
	require.NoError(t, err)

	// ── 改協定為 vnc：請求**不帶**任何通道欄位，伺服端仍須清空全部六欄 ──
	vnc := model.ProtocolVNC
	updated, err := svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{Protocol: &vnc})
	require.NoError(t, err)
	require.Empty(t, updated.RotationChannel)

	var afterSwitch model.Asset
	require.NoError(t, db.First(&afterSwitch, created.ID).Error)
	require.Empty(t, afterSwitch.RotationChannel, "協定改離後不得留通道殘值")
	require.Empty(t, afterSwitch.WinrmScheme, "協定改離後不得留連線方式殘值")
	require.Zero(t, afterSwitch.WinrmPort, "協定改離後不得留埠殘值")
	require.Empty(t, afterSwitch.WinrmTLSMode, "協定改離後不得留 TLS 模式殘值")
	require.Empty(t, afterSwitch.WinrmCACert, "協定改離後不得留 CA 憑證殘值")

	// ── 審計列須記載清空事實與清空前的通道值 ──
	var logs []model.AuditLog
	require.NoError(t, db.Where("resource = ? AND action = ?",
		model.ResourceAsset, model.ActionUpdate).Find(&logs).Error)

	var cleared *model.AssetChangeDetails
	for i := range logs {
		if logs[i].Details == "" {
			continue
		}
		var d model.AssetChangeDetails
		if err := json.Unmarshal([]byte(logs[i].Details), &d); err != nil {
			continue
		}
		if d.RotationChannelCleared {
			cleared = &d
			break
		}
	}
	require.NotNil(t, cleared, "協定切換的更新審計未記載自動清空事實")
	require.Equal(t, model.RotationChannelWindowsWinRM, cleared.PreviousRotationChannel)

	var sawDiff bool
	for _, ch := range cleared.Changes {
		if ch.Field == "rotation_channel" {
			sawDiff = true
		}
	}
	require.True(t, sawDiff, "審計的欄位 diff 未含 rotation_channel")

	// ── 改回 rdp：通道仍空，不得靜默恢復一份沒人記得設過的連線設定 ──
	rdp := model.ProtocolRDP
	back, err := svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{Protocol: &rdp})
	require.NoError(t, err)
	require.Empty(t, back.RotationChannel)

	var afterRestore model.Asset
	require.NoError(t, db.First(&afterRestore, created.ID).Error)
	require.Empty(t, afterRestore.RotationChannel, "協定改回後通道不得靜默恢復")
	require.Empty(t, afterRestore.WinrmCACert, "協定改回後 CA 憑證不得靜默恢復")
}

// TestRotationChannelExplicitClearIsNotReportedAsServerCleared 反向對照：
// 協定沒動而管理者自己把通道關掉，不得被記成伺服端自動清空。
func TestRotationChannelExplicitClearIsNotReportedAsServerCleared(t *testing.T) {
	db := setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)

	created, err := svc.Create(&CreateAssetRequest{
		Name: "win-2", Protocol: model.ProtocolRDP, Host: "10.0.0.12", Port: 3389,
		Username: "Administrator",
		RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP,
	})
	require.NoError(t, err)

	empty := ""
	_, err = svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{RotationChannel: &empty})
	require.NoError(t, err)

	var logs []model.AuditLog
	require.NoError(t, db.Where("resource = ? AND action = ?",
		model.ResourceAsset, model.ActionUpdate).Find(&logs).Error)
	for _, l := range logs {
		if l.Details == "" {
			continue
		}
		var d model.AssetChangeDetails
		if err := json.Unmarshal([]byte(l.Details), &d); err != nil {
			continue
		}
		require.False(t, d.RotationChannelCleared,
			"協定未變動時的顯式清空不得記成伺服端自動清空")
	}
}

// TestAssetListNeverExposesWinrmCA 列表投影回「是否持有 CA」與有效通道，
// 不回 PEM 本體；單筆讀取（編輯路徑）仍回本體供表單回填。
func TestAssetListNeverExposesWinrmCA(t *testing.T) {
	setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)
	ca := testCAPEM(t)

	created, err := svc.Create(&CreateAssetRequest{
		Name: "win-3", Protocol: model.ProtocolRDP, Host: "10.0.0.13", Port: 3389,
		Username: "Administrator",
		RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTPS,
		WinrmTLSMode: model.WinrmTLSModeCA, WinrmCACert: ca,
	})
	require.NoError(t, err)

	_, err = svc.Create(&CreateAssetRequest{
		Name: "ssh-3", Protocol: model.ProtocolSSH, Host: "10.0.0.14", Port: 22,
		Username: "root",
	})
	require.NoError(t, err)

	list, err := svc.List(&AssetFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	require.Len(t, list.Data, 2)

	byName := map[string]model.Asset{}
	for _, a := range list.Data {
		byName[a.Name] = a
	}

	win := byName["win-3"]
	require.Empty(t, win.WinrmCACert, "列表投影不得回 CA 憑證本體")
	require.True(t, win.HasWinrmCACert, "列表投影須告知已設定 CA 憑證")
	require.Equal(t, model.RotationChannelWindowsWinRM, win.EffectiveChannel)

	sshAsset := byName["ssh-3"]
	require.False(t, sshAsset.HasWinrmCACert)
	require.Equal(t, model.RotationChannelPosixSSH, sshAsset.EffectiveChannel,
		"ssh 資產未設定通道時推導為 posix_ssh")

	// 序列化面：JSON 是實際離開後端的形狀，欄位標籤寫錯會讓上面的斷言全部假綠
	raw, err := json.Marshal(win)
	require.NoError(t, err)
	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	_, hasPEM := wire["winrm_ca_cert"]
	require.False(t, hasPEM, "列表 JSON 不得含 winrm_ca_cert")
	require.Equal(t, true, wire["has_winrm_ca_cert"])
	require.Equal(t, model.RotationChannelWindowsWinRM, wire["effective_rotation_channel"])

	// 編輯路徑（單筆讀取）仍須回本體，否則表單無法回填
	detail, err := svc.GetByID(created.ID)
	require.NoError(t, err)
	require.Equal(t, ca, detail.WinrmCACert, "單筆讀取須回 CA 憑證本體供編輯回填")
	require.True(t, detail.HasWinrmCACert)
}

// TestEffectiveRotationPortsDerivation 埠推導：WinRM 依 scheme、
// windows_ssh 在 ssh 資產上沿用資產埠、在 rdp 資產上取側車埠或 22。
func TestEffectiveRotationPortsDerivation(t *testing.T) {
	http := model.Asset{WinrmScheme: model.WinrmSchemeHTTP}
	require.Equal(t, model.WinrmDefaultPortHTTP, http.EffectiveWinrmPort())

	https := model.Asset{WinrmScheme: model.WinrmSchemeHTTPS}
	require.Equal(t, model.WinrmDefaultPortHTTPS, https.EffectiveWinrmPort())

	explicit := model.Asset{WinrmScheme: model.WinrmSchemeHTTPS, WinrmPort: 15986}
	require.Equal(t, 15986, explicit.EffectiveWinrmPort())

	sshAsset := model.Asset{Protocol: model.ProtocolSSH, Port: 2022, RotationSSHPort: 2222}
	require.Equal(t, 2022, sshAsset.EffectiveRotationSSHPort(),
		"ssh 資產沿用同一條 SSH 服務的埠")

	rdpDefault := model.Asset{Protocol: model.ProtocolRDP, Port: 3389}
	require.Equal(t, model.RotationDefaultSSHPort, rdpDefault.EffectiveRotationSSHPort())

	rdpExplicit := model.Asset{Protocol: model.ProtocolRDP, Port: 3389, RotationSSHPort: 2222}
	require.Equal(t, 2222, rdpExplicit.EffectiveRotationSSHPort())
}

// TestCreateAndUpdateResponsesCarryRotationProjection 建立與更新的回應須與列表同形：
// 帶套用後的推導欄位、抹去 CA 憑證本體。冷讀實打曾抓到建立回應沒有有效通道、
// 更新回應回的是更新前的「持有 CA」，前端據此判斷會誤判。
func TestCreateAndUpdateResponsesCarryRotationProjection(t *testing.T) {
	db := setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)
	ca := testCAPEM(t)

	created, err := svc.Create(&CreateAssetRequest{
		Name: "win-proj", Protocol: model.ProtocolRDP, Host: "10.0.0.21", Port: 3389,
		Username: "Administrator",
		RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTPS,
		WinrmTLSMode: model.WinrmTLSModeCA, WinrmCACert: ca,
	})
	require.NoError(t, err)
	require.Equal(t, model.RotationChannelWindowsWinRM, created.EffectiveChannel, "建立回應須帶有效通道")
	require.True(t, created.HasWinrmCACert, "建立回應須告知已持有 CA 憑證")
	require.Empty(t, created.WinrmCACert, "建立回應不回 CA 憑證本體")

	raw, err := json.Marshal(created)
	require.NoError(t, err)
	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	require.Equal(t, model.RotationChannelWindowsWinRM, wire["effective_rotation_channel"])
	require.Equal(t, true, wire["has_winrm_ca_cert"])
	_, hasPEM := wire["winrm_ca_cert"]
	require.False(t, hasPEM, "建立回應 JSON 不得含 winrm_ca_cert")

	// 抹去只發生在回應物件上，資料庫仍持有本體
	var stored model.Asset
	require.NoError(t, db.First(&stored, created.ID).Error)
	require.Equal(t, ca, stored.WinrmCACert, "回應抹去本體不得波及儲存")

	// 只改描述：投影仍以現值計，CA 仍為持有
	desc := "touched"
	touched, err := svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{Description: &desc})
	require.NoError(t, err)
	require.True(t, touched.HasWinrmCACert)
	require.Equal(t, model.RotationChannelWindowsWinRM, touched.EffectiveChannel)
	require.Empty(t, touched.WinrmCACert, "更新回應不回 CA 憑證本體")

	// 清掉 CA（同次改為 insecure 模式才過驗證）：回應須反映更新後的值，而非更新前的投影
	insecure := model.WinrmTLSModeInsecure
	empty := ""
	cleared, err := svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{
		WinrmTLSMode: &insecure, WinrmCACert: &empty,
	})
	require.NoError(t, err)
	require.False(t, cleared.HasWinrmCACert, "清掉 CA 後的更新回應不得仍報持有")
	require.Equal(t, model.RotationChannelWindowsWinRM, cleared.EffectiveChannel)

	// 改協定為 vnc：通道被伺服端清空，回應的有效通道須為 none
	vnc := model.ProtocolVNC
	switched, err := svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{Protocol: &vnc})
	require.NoError(t, err)
	require.Equal(t, model.RotationChannelNone, switched.EffectiveChannel, "協定切換後回應的有效通道須反映清空")
	require.False(t, switched.HasWinrmCACert)
}
