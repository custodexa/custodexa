package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 以 API token 掛載既有憑證的系統告警：四個產生點（建立資產、匯入、建立資產帳號、掛載與更換憑證）
// 接真實的告警落地面與持久投遞佇列。一則＝一筆告警列、一筆明細、每個啟用通道一筆投遞；
// 登入工作階段、匯入預覽、匯入無引用、更換成同一筆、內嵌秘密新建都不產生；
// 部分列已寫入後失敗與告警落地失敗時，業務、告警明細與投遞全數回滾。

const attachTokenName = "tf-prod-apply"

type attachFixture struct {
	*rotationFixture
	sink port.SystemAlertSink
}

func setupAttachFixture(t *testing.T) *attachFixture {
	t.Helper()
	f := setupRotationFixture(t)
	ensureRealAlertTables(t, f.db)
	sink := audit.NewSystemAlertSink(nil)
	auth := newAllowAllAuthorizer()
	f.assets.SetAssetWriteScopePort(allowAllAssetWriteScope{})
	f.assets.WithManagementAuthorizer(auth).WithSystemAlertSink(sink)
	f.accounts.WithManagementAuthorizer(auth).WithSystemAlertSink(sink)
	f.creds.WithSystemAlertSink(sink)
	require.NoError(t, f.db.Create(&model.NotificationChannel{
		Name: "安全群組", Type: "webhook", URL: "https://example.invalid/hook",
		Enabled: true, Language: "zh-TW", MinSeverity: "high",
	}).Error)
	return &attachFixture{rotationFixture: f, sink: sink}
}

func allowAllFields(ctx context.Context) context.Context {
	return WithFieldCapability(ctx, func(string) FieldCapGrant { return FieldCapViaCompat })
}

// attachTokenCtx 以 API token 認證的請求脈絡（操作者與 adminCtx 相同）。
func attachTokenCtx() context.Context {
	ctx := model.WithRequestCredential(adminCtx(), model.RequestCredentialAPIToken)
	ctx = model.WithAPITokenRef(ctx, model.APITokenRef{ID: 41, Name: attachTokenName})
	return allowAllFields(ctx)
}

// attachHumanCtx 以登入工作階段認證的同一個操作者。
func attachHumanCtx() context.Context {
	return allowAllFields(model.WithRequestCredential(adminCtx(), model.RequestCredentialHumanSession))
}

// sharedCred 建一筆未掛載的共用憑證。
func (f *attachFixture) sharedCred(t *testing.T, name string) *model.Credential {
	t.Helper()
	dto, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: name, Username: "u-" + name, ProtocolFamily: model.ProtocolFamilySSH, Password: "Known-Secret-" + name,
	})
	require.NoError(t, err)
	return f.credential(t, dto.ID)
}

type attachAlertRow struct {
	detail model.SystemAlertDetail
	params map[string]string
	alert  model.CommandAlert
}

func (f *attachFixture) attachAlerts(t *testing.T) []attachAlertRow {
	t.Helper()
	var details []model.SystemAlertDetail
	require.NoError(t, f.db.Where("alert_type = ?", string(port.SystemAlertAPITokenCredentialAttached)).
		Order("alert_id").Find(&details).Error)
	out := make([]attachAlertRow, 0, len(details))
	for _, d := range details {
		row := attachAlertRow{detail: d, params: map[string]string{}}
		require.NoError(t, json.Unmarshal([]byte(d.Params), &row.params))
		require.NoError(t, f.db.Where("id = ?", d.AlertID).First(&row.alert).Error)
		out = append(out, row)
	}
	return out
}

// requireOneAttachAlert 恰一則：一筆告警列、一筆明細、一筆投遞（夾具只有一個啟用通道）。
func (f *attachFixture) requireOneAttachAlert(t *testing.T) attachAlertRow {
	t.Helper()
	rows := f.attachAlerts(t)
	require.Len(t, rows, 1, "應恰一則告警")
	assert.EqualValues(t, 1, tableRows(t, f.db, "command_alerts"))
	var outbox int64
	require.NoError(t, f.db.Model(&model.NotificationDelivery{}).Where("alert_id = ?", rows[0].detail.AlertID).Count(&outbox).Error)
	assert.EqualValues(t, 1, outbox, "每個啟用通道一筆投遞")
	assert.Equal(t, model.AlertKindSystemSecurity, rows[0].alert.Kind)
	assert.Equal(t, uint(1), rows[0].alert.UserID)
	assert.Equal(t, "admin", rows[0].params["actor"])
	assert.Equal(t, attachTokenName, rows[0].params["token_name"])
	assert.NotEmpty(t, rows[0].detail.CorrelationID)
	return rows[0]
}

func (f *attachFixture) requireNoAlertRows(t *testing.T, label string) {
	t.Helper()
	assert.EqualValues(t, 0, tableRows(t, f.db, "command_alerts"), label+"：不應有告警列")
	assert.EqualValues(t, 0, tableRows(t, f.db, "system_alert_details"), label+"：不應有告警明細")
	assert.EqualValues(t, 0, tableRows(t, f.db, "system_alert_outbox"), label+"：不應有投遞")
}

// assertSingle 單筆入口的目標與參數：目標為該資產，帶憑證與資產名稱，不帶計數。
func assertSingle(t *testing.T, row attachAlertRow, entry string, assetID uint, assetName string, cred *model.Credential) {
	t.Helper()
	assert.Equal(t, string(port.SystemAlertTargetAsset), row.detail.TargetKind)
	assert.Equal(t, strconv.FormatUint(uint64(assetID), 10), row.detail.TargetID)
	require.NotNil(t, row.alert.AssetID)
	assert.Equal(t, assetID, *row.alert.AssetID)
	assert.Equal(t, map[string]string{
		"actor": "admin", "token_name": attachTokenName, "entry": entry,
		"credential_name": *cred.Name, "asset_name": assetName,
	}, row.params)
	assert.Equal(t, model.AlertSeverityMedium, row.alert.Severity, "預設分級為中")
}

// correlatedAudits 明細帶該關聯識別的稽核列。
func (f *attachFixture) correlatedAudits(t *testing.T, corr string) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, f.db.Where("details LIKE ?", `%"correlation_id":"`+corr+`"%`).Order("id").Find(&rows).Error)
	return rows
}

func intPtr64(v uint) *int64 {
	n := int64(v)
	return &n
}

func portPtr(n int) *int { return &n }

func TestAPITokenCredentialAttachAlert(t *testing.T) {
	t.Run("建立資產時引用：一則，目標為新資產", func(t *testing.T) {
		f := setupAttachFixture(t)
		cred := f.sharedCred(t, "prod-linux-root")
		a, err := f.assets.Create(attachTokenCtx(), &CreateAssetRequest{
			Name: "web-21", Protocol: model.ProtocolSSH, Host: "198.51.100.21", Port: 22,
			CredentialID: cred.ID, CreatedBy: 1, CreatedByName: "admin",
		})
		require.NoError(t, err)
		row := f.requireOneAttachAlert(t)
		assertSingle(t, row, "asset_create", a.ID, "web-21", cred)
		audits := f.correlatedAudits(t, row.detail.CorrelationID)
		require.Len(t, audits, 1, "同交易的帳號建立稽核帶同一個關聯識別")
		require.NotNil(t, audits[0].APITokenID)
		assert.EqualValues(t, 41, *audits[0].APITokenID)
		assert.Contains(t, audits[0].Details, fmt.Sprintf(`"credential_id":%d`, cred.ID))
	})

	t.Run("建立資產帳號時引用：一則，目標為該資產", func(t *testing.T) {
		f := setupAttachFixture(t)
		cred := f.sharedCred(t, "shared-a")
		host := newSSHAsset(t, f.assets, "db-01", "198.51.100.31")
		_, err := f.accounts.Create(attachTokenCtx(), host.ID, &CreateAssetAccountRequest{CredentialID: cred.ID})
		require.NoError(t, err)
		row := f.requireOneAttachAlert(t)
		assertSingle(t, row, "account_create", host.ID, "db-01", cred)
		require.Len(t, f.correlatedAudits(t, row.detail.CorrelationID), 1)
	})

	t.Run("掛到資產：一則，目標為該資產", func(t *testing.T) {
		f := setupAttachFixture(t)
		cred := f.sharedCred(t, "shared-b")
		host := newSSHAsset(t, f.assets, "app-01", "198.51.100.41")
		_, err := f.creds.Bind(attachTokenCtx(), cred.ID, &BindCredentialRequest{AssetID: host.ID})
		require.NoError(t, err)
		row := f.requireOneAttachAlert(t)
		assertSingle(t, row, "bind", host.ID, "app-01", cred)
		audits := f.correlatedAudits(t, row.detail.CorrelationID)
		require.Len(t, audits, 1)
		assert.Equal(t, model.ResourceCredential, audits[0].Resource)
		require.NotNil(t, audits[0].AssetID)
		assert.Equal(t, host.ID, *audits[0].AssetID)
	})

	t.Run("更換憑證：一則；更換成同一筆不寫入也不產生", func(t *testing.T) {
		f := setupAttachFixture(t)
		credA, accounts := f.sharedOn(t, "shared-c", "ops", "Known-Secret-c", "198.51.100.51")
		credB := f.sharedCred(t, "shared-d")
		host := f.binding(t, accounts[0]).AssetID

		// 更換成同一筆：掛載列、資產列不變，也不新增稽核列
		var accBefore model.AssetAccount
		require.NoError(t, f.db.First(&accBefore, accounts[0]).Error)
		var assetBefore model.Asset
		require.NoError(t, f.db.First(&assetBefore, host).Error)
		auditsBefore := tableRows(t, f.db, "audit_logs")
		_, err := f.creds.Rebind(attachTokenCtx(), host, accounts[0], credA)
		require.NoError(t, err)
		f.requireNoAlertRows(t, "更換成同一筆")
		var accAfter model.AssetAccount
		require.NoError(t, f.db.First(&accAfter, accounts[0]).Error)
		var assetAfter model.Asset
		require.NoError(t, f.db.First(&assetAfter, host).Error)
		assert.Equal(t, accBefore.CredentialID, accAfter.CredentialID, "更換成同一筆：掛載仍指向原憑證")
		assert.True(t, accBefore.UpdatedAt.Equal(accAfter.UpdatedAt), "更換成同一筆：掛載列不得改寫")
		assert.True(t, assetBefore.UpdatedAt.Equal(assetAfter.UpdatedAt), "更換成同一筆：資產列不得改寫")
		assert.EqualValues(t, auditsBefore, tableRows(t, f.db, "audit_logs"), "更換成同一筆：不新增稽核列")

		_, err = f.creds.Rebind(attachTokenCtx(), host, accounts[0], credB.ID)
		require.NoError(t, err)
		row := f.requireOneAttachAlert(t)
		var a model.Asset
		require.NoError(t, f.db.First(&a, host).Error)
		assertSingle(t, row, "rebind", host, a.Name, credB)
	})

	t.Run("分級覆寫：產生的告警採覆寫後的分級", func(t *testing.T) {
		f := setupAttachFixture(t)
		require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
			_, err := audit.SetSystemAlertSeverityInTx(tx, port.SystemAlertAPITokenCredentialAttached, model.AlertSeverityHigh, 1)
			return err
		}))
		cred := f.sharedCred(t, "shared-e")
		host := newSSHAsset(t, f.assets, "app-02", "198.51.100.42")
		_, err := f.creds.Bind(attachTokenCtx(), cred.ID, &BindCredentialRequest{AssetID: host.ID})
		require.NoError(t, err)
		row := f.requireOneAttachAlert(t)
		assert.Equal(t, model.AlertSeverityHigh, row.alert.Severity)
	})

	t.Run("登入工作階段的四個入口：不產生", func(t *testing.T) {
		f := setupAttachFixture(t)
		credA := f.sharedCred(t, "shared-f")
		credB := f.sharedCred(t, "shared-g")
		_, err := f.assets.Create(attachHumanCtx(), &CreateAssetRequest{
			Name: "human-1", Protocol: model.ProtocolSSH, Host: "198.51.100.61", Port: 22,
			CredentialID: credA.ID, CreatedBy: 1, CreatedByName: "admin",
		})
		require.NoError(t, err)
		host := newSSHAsset(t, f.assets, "human-2", "198.51.100.62")
		_, err = f.accounts.Create(attachHumanCtx(), host.ID, &CreateAssetAccountRequest{CredentialID: credA.ID})
		require.NoError(t, err)
		bound, err := f.creds.Bind(attachHumanCtx(), credB.ID, &BindCredentialRequest{AssetID: newSSHAsset(t, f.assets, "human-3", "198.51.100.63").ID})
		require.NoError(t, err)
		_, err = f.creds.Rebind(attachHumanCtx(), bound.AssetID, bound.ID, credA.ID)
		require.NoError(t, err)
		_, err = f.assets.ImportAssets(attachHumanCtx(), &ImportBatch{Source: "form", Rows: []ImportRow{
			{Name: "human-imp", Protocol: "ssh", Host: "198.51.100.64", Port: portPtr(22), CredentialID: intPtr64(credB.ID)},
		}}, 1, "admin")
		require.NoError(t, err)
		f.requireNoAlertRows(t, "登入工作階段")
		var corrRows int64
		require.NoError(t, f.db.Model(&model.AuditLog{}).Where("details LIKE ?", `%"correlation_id"%`).Count(&corrRows).Error)
		assert.Zero(t, corrRows, "登入工作階段的稽核明細不加關聯識別")
	})

	t.Run("內嵌秘密新建專用憑證：不產生", func(t *testing.T) {
		f := setupAttachFixture(t)
		_, err := f.assets.Create(attachTokenCtx(), &CreateAssetRequest{
			Name: "inline-1", Protocol: model.ProtocolSSH, Host: "198.51.100.71", Port: 22,
			Username: "root", Password: "Inline-Secret-71", CreatedBy: 1, CreatedByName: "admin",
		})
		require.NoError(t, err)
		host := newSSHAsset(t, f.assets, "inline-2", "198.51.100.72")
		_, err = f.accounts.Create(attachTokenCtx(), host.ID, &CreateAssetAccountRequest{Username: "extra", Password: "Inline-Secret-72"})
		require.NoError(t, err)
		f.requireNoAlertRows(t, "內嵌秘密")
	})

	t.Run("匯入多憑證與混合列：一則，資產數只計引用的列", func(t *testing.T) {
		f := setupAttachFixture(t)
		credA := f.sharedCred(t, "imp-a")
		credB := f.sharedCred(t, "imp-b")
		var rows []ImportRow
		for i := 0; i < 10; i++ {
			r := ImportRow{Name: fmt.Sprintf("imp-%02d", i), Protocol: "ssh", Host: fmt.Sprintf("203.0.113.%d", i+1), Port: portPtr(22)}
			switch {
			case i < 3:
				r.CredentialID = intPtr64(credA.ID)
			case i < 6:
				r.CredentialID = intPtr64(credB.ID)
			}
			rows = append(rows, r)
		}
		res, err := f.assets.ImportAssets(attachTokenCtx(), &ImportBatch{Source: "form", Rows: rows}, 1, "admin")
		require.NoError(t, err)
		require.Equal(t, 10, res.Created)
		row := f.requireOneAttachAlert(t)
		assert.Equal(t, string(port.SystemAlertTargetUser), row.detail.TargetKind)
		assert.Equal(t, "1", row.detail.TargetID)
		assert.Nil(t, row.alert.AssetID)
		assert.Equal(t, map[string]string{
			"actor": "admin", "token_name": attachTokenName, "entry": "import",
			"asset_count": "6", "credential_count": "2",
		}, row.params)
		audits := f.correlatedAudits(t, row.detail.CorrelationID)
		require.Len(t, audits, 6, "由告警的關聯識別回查到引用既有憑證的每一台")
		seen := map[uint]bool{}
		for _, a := range audits {
			require.NotNil(t, a.AssetID)
			seen[*a.AssetID] = true
			assert.True(t, strings.Contains(a.Details, fmt.Sprintf(`"credential_id":%d`, credA.ID)) ||
				strings.Contains(a.Details, fmt.Sprintf(`"credential_id":%d`, credB.ID)), a.Details)
		}
		assert.Len(t, seen, 6)
	})

	t.Run("匯入全無引用：不產生", func(t *testing.T) {
		f := setupAttachFixture(t)
		_, err := f.assets.ImportAssets(attachTokenCtx(), &ImportBatch{Source: "form", Rows: []ImportRow{
			{Name: "plain-1", Protocol: "ssh", Host: "203.0.113.21", Port: portPtr(22)},
			{Name: "plain-2", Protocol: "ssh", Host: "203.0.113.22", Port: portPtr(22)},
		}}, 1, "admin")
		require.NoError(t, err)
		f.requireNoAlertRows(t, "匯入全無引用")
	})

	t.Run("匯入預覽：不產生", func(t *testing.T) {
		f := setupAttachFixture(t)
		cred := f.sharedCred(t, "imp-preview")
		preview, err := f.assets.PreviewImport(attachTokenCtx(), &ImportBatch{Source: "form", Rows: []ImportRow{
			{Name: "pv-1", Protocol: "ssh", Host: "203.0.113.31", Port: portPtr(22), CredentialID: intPtr64(cred.ID)},
		}})
		require.NoError(t, err)
		require.True(t, preview.OK)
		f.requireNoAlertRows(t, "匯入預覽")
	})

	t.Run("匯入部分列已寫入後失敗：業務、告警明細與投遞全數回滾", func(t *testing.T) {
		f := setupAttachFixture(t)
		cred := f.sharedCred(t, "imp-rollback")
		before := tableRows(t, f.db, "assets")
		// 預檢通過後、交易開始前，另有人佔用第二列的名稱：第一列已寫入後第二列重驗失敗
		f.assets.SetImportPreTxHookForTest(func() {
			require.NoError(t, f.db.Create(&model.Asset{Name: "rb-2", Protocol: model.ProtocolSSH,
				Host: "203.0.113.99", Port: 22, CreatedBy: 1, Active: true}).Error)
		})
		_, err := f.assets.ImportAssets(attachTokenCtx(), &ImportBatch{Source: "form", Rows: []ImportRow{
			{Name: "rb-1", Protocol: "ssh", Host: "203.0.113.41", Port: portPtr(22), CredentialID: intPtr64(cred.ID)},
			{Name: "rb-2", Protocol: "ssh", Host: "203.0.113.42", Port: portPtr(22), CredentialID: intPtr64(cred.ID)},
		}}, 1, "admin")
		require.Error(t, err)
		assert.EqualValues(t, before+1, tableRows(t, f.db, "assets"), "只剩他人佔用的那一筆")
		var n int64
		require.NoError(t, f.db.Model(&model.Asset{}).Where("name = ?", "rb-1").Count(&n).Error)
		assert.Zero(t, n, "已寫入的第一列隨交易回滾")
		f.requireNoAlertRows(t, "部分列失敗")
	})

	t.Run("告警落地失敗：五個入口的業務皆回滾", func(t *testing.T) {
		f := setupAttachFixture(t)
		cred := f.sharedCred(t, "sink-fail")
		other := f.sharedCred(t, "sink-fail-2")
		host := newSSHAsset(t, f.assets, "sf-host", "198.51.100.81")
		var seedAccount model.AssetAccount
		require.NoError(t, f.db.Where("asset_id = ?", host.ID).First(&seedAccount).Error)
		accountsBefore := tableRows(t, f.db, "asset_accounts")
		assetsBefore := tableRows(t, f.db, "assets")
		require.NoError(t, f.db.Migrator().DropTable(&model.NotificationDelivery{}))

		_, err := f.assets.Create(attachTokenCtx(), &CreateAssetRequest{
			Name: "sf-new", Protocol: model.ProtocolSSH, Host: "198.51.100.82", Port: 22,
			CredentialID: cred.ID, CreatedBy: 1, CreatedByName: "admin",
		})
		require.ErrorContains(t, err, "投遞佇列", "建立資產")
		_, err = f.assets.ImportAssets(attachTokenCtx(), &ImportBatch{Source: "form", Rows: []ImportRow{
			{Name: "sf-imp", Protocol: "ssh", Host: "198.51.100.83", Port: portPtr(22), CredentialID: intPtr64(cred.ID)},
		}}, 1, "admin")
		require.ErrorContains(t, err, "投遞佇列", "匯入")
		_, err = f.accounts.Create(attachTokenCtx(), host.ID, &CreateAssetAccountRequest{CredentialID: cred.ID})
		require.ErrorContains(t, err, "投遞佇列", "建立資產帳號")
		_, err = f.creds.Bind(attachTokenCtx(), other.ID, &BindCredentialRequest{AssetID: host.ID})
		require.ErrorContains(t, err, "投遞佇列", "掛載")
		_, err = f.creds.Rebind(attachTokenCtx(), host.ID, seedAccount.ID, cred.ID)
		require.ErrorContains(t, err, "投遞佇列", "更換憑證")

		assert.EqualValues(t, assetsBefore, tableRows(t, f.db, "assets"))
		assert.EqualValues(t, accountsBefore, tableRows(t, f.db, "asset_accounts"))
		assert.Equal(t, seedAccount.CredentialID, f.binding(t, seedAccount.ID).CredentialID, "更換憑證未生效")
		assert.EqualValues(t, 0, tableRows(t, f.db, "command_alerts"))
		assert.EqualValues(t, 0, tableRows(t, f.db, "system_alert_details"))
	})

	t.Run("協定族不相容被拒：不產生", func(t *testing.T) {
		f := setupAttachFixture(t)
		cred := f.sharedCred(t, "proto-ssh")
		vnc := newBareAsset(t, f.assets, "vnc-1", "198.51.100.91")
		_, err := f.creds.Bind(attachTokenCtx(), cred.ID, &BindCredentialRequest{AssetID: vnc.ID})
		require.ErrorIs(t, err, ErrCredentialProtocolMismatch)
		f.requireNoAlertRows(t, "協定族不相容")
	})
}

// TestCredentialManagementGateTokenSameAsSession 憑證管理關卡不因請求以 API token 認證而另行拒絕：
// 掛載既有憑證的判定交給同一個判定器，放行與能力拒絕的結果與登入工作階段相同。
func TestCredentialManagementGateTokenSameAsSession(t *testing.T) {
	req := CredentialManagementRequest{Operation: CredOpBind, Capabilities: []string{CredCapBind},
		CredentialIDs: []uint{7}, AssetIDs: []uint{9}}
	for _, deny := range []bool{false, true} {
		auth := newAllowAllAuthorizer()
		if deny {
			auth.denied[CredCapBind] = true
		}
		g := credentialManagementGate{authorizer: auth}
		_, tokenErr := g.require(attachTokenCtx(), nil, req)
		_, humanErr := g.require(attachHumanCtx(), nil, req)
		require.Len(t, auth.asked, 2, "兩種請求都交給判定器")
		if deny {
			require.ErrorIs(t, tokenErr, ErrCredentialBindForbidden)
			require.ErrorIs(t, humanErr, ErrCredentialBindForbidden)
			assert.Equal(t, humanErr.Error(), tokenErr.Error())
		} else {
			require.NoError(t, tokenErr)
			require.NoError(t, humanErr)
		}
	}
}
