package asset

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// fakeAlertSink 記錄收到的系統告警事件；err 非空時模擬落地面（outbox append）寫入失敗。
// 只記事件，不記任何持有秘密的東西——事件本身就不該有。
type fakeAlertSink struct {
	mu     sync.Mutex
	events []port.SystemAlertEvent
	err    error
}

func newFakeAlertSink() *fakeAlertSink { return &fakeAlertSink{} }

func (f *fakeAlertSink) RaiseInTx(_ *gorm.DB, ev port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return port.SystemAlertReceipt{}, f.err
	}
	f.events = append(f.events, ev)
	return port.SystemAlertReceipt{AlertID: uint(len(f.events)), Severity: model.AlertSeverityHigh}, nil
}

func (f *fakeAlertSink) snapshot() []port.SystemAlertEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]port.SystemAlertEvent(nil), f.events...)
}

// failingAuditTxSink 交易內審計寫入一律失敗。
type failingAuditTxSink struct{}

func (failingAuditTxSink) WriteInTx(*gorm.DB, port.AuditEvent) error { return errors.New("audit down") }

// lastAuditDetails 取最後一筆審計列的 details（JSON map）。
func lastAuditDetails(t *testing.T, resource string, resourceID uint) map[string]any {
	t.Helper()
	var row model.AuditLog
	require.NoError(t, database.DB.Where("resource = ? AND resource_id = ?", resource, resourceID).
		Order("id DESC").First(&row).Error)
	out := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(row.Details), &out))
	return out
}

// evidenceFixture 一組共用憑證掛兩台資產，並提供可注入故障的告警落地面。
type evidenceFixture struct {
	assets   *AssetService
	accounts *AssetAccountService
	creds    *CredentialService
	alerts   *fakeAlertSink
	shared   *CredentialDTO
}

func newEvidenceFixture(t *testing.T) *evidenceFixture {
	t.Helper()
	setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)
	alerts := newFakeAlertSink()
	assets.WithSystemAlertSink(alerts)
	accounts.WithSystemAlertSink(alerts)
	creds.WithSystemAlertSink(alerts)
	shared := newSharedCredential(t, creds, "evidence-shared", "ops", "pw")
	for i, name := range []string{"ev-a", "ev-b"} {
		a := newSSHAsset(t, assets, name, "10.50.0."+string(rune('1'+i)))
		list, err := accounts.List(a.ID)
		require.NoError(t, err)
		require.NoError(t, accounts.Delete(adminCtx(), a.ID, list[0].ID))
		_, err = creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: a.ID})
		require.NoError(t, err)
	}
	return &evidenceFixture{assets: assets, accounts: accounts, creds: creds, alerts: alerts, shared: shared}
}

// 自訂秘密的敏感證據：同交易的版本、就位指標、服務審計與系統告警全有或全無，
// 事件不帶任何秘密，缺任一落地面即拒絕。
func TestCredentialSensitiveEvidence(t *testing.T) {
	const declared = "Declared-Secret-Value-9x"

	t.Run("SetSecret 成功：全部掛載立即使用新版本，審計與告警同交易同關聯", func(t *testing.T) {
		f := newEvidenceFixture(t)
		before := credentialVersionIDs(t, database.DB, f.shared.ID)
		_, err := f.creds.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: declared})
		require.NoError(t, err)

		after := credentialVersionIDs(t, database.DB, f.shared.ID)
		require.Len(t, after, len(before)+1)
		newVersion := after[len(after)-1]
		var cred model.Credential
		require.NoError(t, database.DB.First(&cred, f.shared.ID).Error)
		require.NotNil(t, cred.CurrentVersionID)
		assert.Equal(t, newVersion, *cred.CurrentVersionID)
		var bindings []model.AssetAccount
		require.NoError(t, database.DB.Where("credential_id = ?", f.shared.ID).Find(&bindings).Error)
		require.Len(t, bindings, 2)
		for _, b := range bindings {
			require.NotNil(t, b.EffectiveVersionID)
			assert.Equal(t, newVersion, *b.EffectiveVersionID, "全部掛載立即使用新版本")
		}

		events := f.alerts.snapshot()
		require.Len(t, events, 1)
		ev := events[0]
		assert.Equal(t, port.SystemAlertCustomSecretUsed, ev.Type)
		assert.Equal(t, map[string]string{"entry": secretEntryDeclareNew}, ev.Params)
		assert.Equal(t, port.SystemAlertTargetCredential, ev.Target.Kind)
		assert.Equal(t, fmt.Sprint(f.shared.ID), ev.Target.ID)
		details := lastAuditDetails(t, string(model.ResourceCredential), f.shared.ID)
		assert.Equal(t, model.AccountOpSetSecret, details["operation"])
		assert.Equal(t, secretSourceCustom, details["secret_source"])
		assert.NotEmpty(t, ev.CorrelationID)
		assert.Equal(t, ev.CorrelationID, details["correlation_id"], "事件與審計 details 同名欄一致")
	})

	t.Run("事件與審計不含明文、密文或秘密雜湊", func(t *testing.T) {
		f := newEvidenceFixture(t)
		_, err := f.creds.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: declared})
		require.NoError(t, err)
		raw, err := json.Marshal(f.alerts.snapshot())
		require.NoError(t, err)
		var row model.AuditLog
		require.NoError(t, database.DB.Where("resource = ?", string(model.ResourceCredential)).
			Order("id DESC").First(&row).Error)
		var versions []model.CredentialSecretVersion
		require.NoError(t, database.DB.Where("credential_id = ?", f.shared.ID).Find(&versions).Error)
		blob := string(raw) + row.Details
		assert.NotContains(t, blob, declared)
		for _, v := range versions {
			if v.PasswordEnc != "" {
				assert.NotContains(t, blob, v.PasswordEnc, "密文不入事件與審計")
			}
		}
		assert.False(t, strings.Contains(blob, "password\":\""), "不得出現帶值的 password 欄")
	})

	t.Run("審計或告警落地失敗全部回滾", func(t *testing.T) {
		for name, inject := range map[string]func(f *evidenceFixture){
			"TxSink 失敗":        func(f *evidenceFixture) { f.creds.auditTx = failingAuditTxSink{} },
			"outbox append 失敗": func(f *evidenceFixture) { f.alerts.err = errors.New("outbox down") },
		} {
			f := newEvidenceFixture(t)
			before := credentialVersionIDs(t, database.DB, f.shared.ID)
			var credBefore model.Credential
			require.NoError(t, database.DB.First(&credBefore, f.shared.ID).Error)
			inject(f)
			_, err := f.creds.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: declared})
			require.Error(t, err, name)
			assert.Equal(t, before, credentialVersionIDs(t, database.DB, f.shared.ID), "%s：版本回滾", name)
			var credAfter model.Credential
			require.NoError(t, database.DB.First(&credAfter, f.shared.ID).Error)
			assert.Equal(t, credBefore.CurrentVersionID, credAfter.CurrentVersionID, "%s：現行版本指標回滾", name)
			var bindings []model.AssetAccount
			require.NoError(t, database.DB.Where("credential_id = ?", f.shared.ID).Find(&bindings).Error)
			for _, b := range bindings {
				assert.Equal(t, credBefore.CurrentVersionID, b.EffectiveVersionID, "%s：就位指標回滾", name)
			}
			assert.Empty(t, f.alerts.snapshot(), "%s：沒有已提交的告警", name)
		}
	})

	t.Run("缺任一落地面拒絕", func(t *testing.T) {
		f := newEvidenceFixture(t)
		before := credentialVersionIDs(t, database.DB, f.shared.ID)
		f.creds.WithSystemAlertSink(nil)
		_, err := f.creds.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: declared})
		require.ErrorIs(t, err, port.ErrSystemAlertSinkMissing)
		assert.Equal(t, before, credentialVersionIDs(t, database.DB, f.shared.ID))
		f.creds.WithSystemAlertSink(f.alerts)
		f.creds.auditTx = nil
		_, err = f.creds.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: declared})
		require.ErrorIs(t, err, port.ErrTxSinkMissing)
		assert.Equal(t, before, credentialVersionIDs(t, database.DB, f.shared.ID))
	})

	t.Run("資產與帳號表單內嵌宣告同樣產生告警並全有或全無", func(t *testing.T) {
		f := newEvidenceFixture(t)
		a := newSSHAsset(t, f.assets, "ev-inline", "10.50.1.1")
		list, err := f.accounts.List(a.ID)
		require.NoError(t, err)
		var acc model.AssetAccount
		require.NoError(t, database.DB.First(&acc, list[0].ID).Error)
		before := credentialVersionIDs(t, database.DB, acc.CredentialID)

		pw := declared
		_, err = f.accounts.Update(adminCtx(), a.ID, acc.ID, &UpdateAssetAccountRequest{Password: &pw})
		require.NoError(t, err)
		_, err = f.assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{Password: &pw})
		require.NoError(t, err)
		events := f.alerts.snapshot()
		require.Len(t, events, 2)
		for _, ev := range events {
			assert.Equal(t, map[string]string{"entry": secretEntryDeclareNew}, ev.Params)
			require.NotNil(t, ev.AssetID)
			assert.Equal(t, a.ID, *ev.AssetID)
			assert.NotEmpty(t, ev.CorrelationID)
		}
		assert.NotEqual(t, events[0].CorrelationID, events[1].CorrelationID)
		assert.Len(t, credentialVersionIDs(t, database.DB, acc.CredentialID), len(before)+2)

		// 落地失敗：帳號表單與資產表單都整筆回滾
		f.alerts.err = errors.New("outbox down")
		afterOK := credentialVersionIDs(t, database.DB, acc.CredentialID)
		pw2 := declared + "-2"
		_, err = f.accounts.Update(adminCtx(), a.ID, acc.ID, &UpdateAssetAccountRequest{Password: &pw2})
		require.Error(t, err)
		_, err = f.assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{Password: &pw2})
		require.Error(t, err)
		assert.Equal(t, afterOK, credentialVersionIDs(t, database.DB, acc.CredentialID), "內嵌宣告回滾")
		f.alerts.err = nil

		// 缺落地面：拒絕
		f.accounts.WithSystemAlertSink(nil)
		f.assets.WithSystemAlertSink(nil)
		_, err = f.accounts.Update(adminCtx(), a.ID, acc.ID, &UpdateAssetAccountRequest{Password: &pw2})
		require.ErrorIs(t, err, port.ErrSystemAlertSinkMissing)
		_, err = f.assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{Password: &pw2})
		require.ErrorIs(t, err, port.ErrSystemAlertSinkMissing)
		assert.Equal(t, afterOK, credentialVersionIDs(t, database.DB, acc.CredentialID))
	})

	t.Run("不帶秘密的編輯不產生告警", func(t *testing.T) {
		f := newEvidenceFixture(t)
		note := "備註"
		_, err := f.creds.Update(adminCtx(), f.shared.ID, &UpdateCredentialRequest{Note: &note})
		require.NoError(t, err)
		assert.Empty(t, f.alerts.snapshot())
	})

	t.Run("入口分類器一次操作只選一種", func(t *testing.T) {
		assert.Equal(t, secretEntryDetachShared, customSecretEntryFor(CredOpDetach))
		assert.Equal(t, secretEntryDeclareNew, customSecretEntryFor(CredOpSetSecret))
		assert.Equal(t, secretEntryChangePassword, customSecretEntryFor(CredOpRotate), "其他自訂值遠端寫入")
	})

	t.Run("脫離（隨機與自訂）各一份意圖，隨機整組輪替與拆分沒有事件", func(t *testing.T) {
		f := setupRotationFixture(t)
		credID, accounts := f.sharedOn(t, "intent-shared", "ops", "old-shared", "10.51.0.1", "10.51.0.2", "10.51.0.3")

		_, err := f.rotations.Detach(adminCtx(), credID, accounts[0],
			DetachCredentialRequest{Source: DetachSourceRandom})
		require.NoError(t, err)
		_, err = f.rotations.Detach(adminCtx(), credID, accounts[1],
			DetachCredentialRequest{Source: DetachSourceCustom, Password: declared})
		require.NoError(t, err)
		events := f.alerts.snapshot()
		require.Len(t, events, 2, "自訂脫離只一份事件，不因同時命中兩項而重複")
		for _, ev := range events {
			assert.Equal(t, map[string]string{"entry": secretEntryDetachShared}, ev.Params)
			assert.Equal(t, port.SystemAlertCustomSecretUsed, ev.Type)
		}
		var intents []model.AuditLog
		require.NoError(t, database.DB.Where("resource = ? AND resource_id = ?",
			string(model.ResourceCredential), credID).Order("id ASC").Find(&intents).Error)
		sources := map[string]bool{}
		for _, row := range intents {
			d := map[string]any{}
			require.NoError(t, json.Unmarshal([]byte(row.Details), &d))
			if corr, ok := d["correlation_id"].(string); ok {
				sources[fmt.Sprint(d["secret_source"])] = true
				assert.Contains(t, []string{events[0].CorrelationID, events[1].CorrelationID}, corr)
				assert.NotZero(t, d["rotation_id"], "意圖審計可連到輪替工作")
			}
		}
		assert.Equal(t, map[string]bool{secretSourceRandom: true, secretSourceCustom: true}, sources)
		blob, _ := json.Marshal(events)
		assert.NotContains(t, string(blob), declared)

		// 隨機拆分（剩下一台）不是自訂值：沒有新事件
		_, err = f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
		if err == nil {
			assert.Len(t, f.alerts.snapshot(), 2, "隨機拆分不產生自訂秘密事件")
		}
	})

	t.Run("一般隨機整組輪替沒有自訂值事件", func(t *testing.T) {
		f := setupRotationFixture(t)
		credID, _ := f.sharedOn(t, "plain-shared", "ops", "old-shared", "10.51.1.1", "10.51.1.2")
		rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		assert.Empty(t, f.alerts.snapshot())
	})

	t.Run("意圖寫入失敗無工作、候選與遠端副作用", func(t *testing.T) {
		for name, inject := range map[string]func(f *rotationFixture){
			"outbox append 失敗": func(f *rotationFixture) { f.alerts.err = errors.New("outbox down") },
			"落地面缺席":            func(f *rotationFixture) { f.rotations.WithSystemAlertSink(nil) },
			"TxSink 失敗":        func(f *rotationFixture) { f.rotations.auditTx = failingAuditTxSink{} },
		} {
			f := setupRotationFixture(t)
			credID, accounts := f.sharedOn(t, "fail-shared", "ops", "old-shared", "10.51.2.1", "10.51.2.2")
			inject(f)
			_, err := f.rotations.Detach(adminCtx(), credID, accounts[0],
				DetachCredentialRequest{Source: DetachSourceCustom, Password: declared})
			require.Error(t, err, name)
			var rots, cands int64
			require.NoError(t, f.db.Model(&model.CredentialRotation{}).Count(&rots).Error)
			require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Count(&cands).Error)
			assert.EqualValues(t, 0, rots, "%s：沒有輪替工作", name)
			assert.EqualValues(t, 0, cands, "%s：沒有候選", name)
			_, rotateCalls, verifyCalls := f.remote.snapshot()
			assert.Empty(t, rotateCalls, "%s：遠端零 I/O", name)
			assert.Empty(t, verifyCalls, "%s：遠端零 I/O", name)
			assert.Equal(t, credID, f.binding(t, accounts[0]).CredentialID, "%s：仍掛在原憑證", name)
		}
	})

	t.Run("遠端送出後結果審計失敗：保留未知候選，不報成功", func(t *testing.T) {
		f := setupRotationFixture(t)
		credID, accounts := f.sharedOn(t, "result-shared", "ops", "old-shared", "10.51.3.1", "10.51.3.2")
		// 意圖（rotate）照常提交；結果（detach）審計失敗
		f.rotations.auditTx = failOnOperationSink{op: credentialOpDetach}
		_, err := f.rotations.Detach(adminCtx(), credID, accounts[0],
			DetachCredentialRequest{Source: DetachSourceCustom, Password: declared})
		var failed *CredentialDetachFailedError
		require.ErrorAs(t, err, &failed, "結果提交失敗不得回報成功")
		assert.Equal(t, credID, f.binding(t, accounts[0]).CredentialID, "未改綁，仍在原憑證")
		assert.EqualValues(t, 1, f.candidateCountFor(t, accounts[0]), "候選保留，那把秘密的唯一副本不丟")
		_, rotateCalls, _ := f.remote.snapshot()
		assert.NotEmpty(t, rotateCalls, "遠端確實已送出")
		assert.Len(t, f.alerts.snapshot(), 1, "意圖已提交，不因結果失敗而撤回")
	})
}

// failOnOperationSink 對指定 operation 的憑證審計寫入失敗，其餘寫入落庫（模擬結果交易失敗）。
type failOnOperationSink struct{ op string }

func (s failOnOperationSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	var d struct {
		Operation string `json:"operation"`
	}
	_ = json.Unmarshal([]byte(ev.Details), &d)
	if d.Operation == s.op {
		return errors.New("result audit down")
	}
	return audit.NewTxSink().WriteInTx(tx, ev)
}
