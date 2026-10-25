package asset

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 確認入口的授權與目標判定子案例（root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.1/確認入口/）。
// 每一個拒絕案例都要證明：沒有承接紀錄、沒有新增授權列、沒有確認審計、靶機沒有收到任何認證。

// takeoverTrace 判定前後可觀察的副作用基線。
type takeoverTrace struct {
	db       *gorm.DB
	authRows int64
	attempts func() int32
	base     int32
}

func newTakeoverTrace(t *testing.T, db *gorm.DB, attempts func() int32) takeoverTrace {
	t.Helper()
	// 夾具庫未預建承接紀錄表：先建出來，後面的「無紀錄」才有意義
	require.NoError(t, db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
	var n int64
	require.NoError(t, db.Model(&model.CredentialJobAuthorization{}).Count(&n).Error)
	return takeoverTrace{db: db, authRows: n, attempts: attempts, base: attempts()}
}

func (tr takeoverTrace) requireUntouched(t *testing.T) {
	t.Helper()
	var confirms int64
	require.NoError(t, tr.db.Model(&model.CredentialHostIdentityConfirmation{}).Count(&confirms).Error,
		"承接紀錄表必須存在，否則「無紀錄」斷言為假綠")
	assert.Zero(t, confirms, "無承接紀錄")
	var auths int64
	require.NoError(t, tr.db.Model(&model.CredentialJobAuthorization{}).Count(&auths).Error)
	assert.Equal(t, tr.authRows, auths, "純判定：不新增授權列")
	var audits int64
	require.NoError(t, tr.db.Model(&model.AuditLog{}).Where("details LIKE ?", `%host_identity_confirm%`).Count(&audits).Error)
	assert.Zero(t, audits, "無確認審計")
	assert.Equal(t, tr.base, tr.attempts(), "authAttempts 0：不得對靶機送出任何認證")
}

// takeoverTarget 一種工作（候選或成員）在入口測試中需要的操作把手。
type takeoverTarget struct {
	kind     string
	jobID    uint
	svc      *HostIdentityTakeoverService
	db       *gorm.DB
	authz    *fakeCredentialAuthorizer
	capKey   string
	assetID  uint
	req      HostIdentityConfirmRequest
	attempts func() int32
}

func validConfirmRequest(t *testing.T, db *gorm.DB, assetID uint) HostIdentityConfirmRequest {
	t.Helper()
	var own model.AssetHostKey
	require.NoError(t, db.Where("asset_id = ?", assetID).First(&own).Error)
	return HostIdentityConfirmRequest{Transport: model.HostKeyTransportSSH, RecordID: own.ID,
		Algorithm: own.Algorithm, Fingerprint: own.Fingerprint, Generation: own.TrustGeneration}
}

func candidateTakeoverTarget(t *testing.T) takeoverTarget {
	t.Helper()
	s := newRetryScenario(t)
	cand := candidateOfAccount(t, s.f)
	adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
	svc := NewHostIdentityTakeoverService(s.f.db, s.authz)
	svc.SetAuditTxSink(audit.NewTxSink())
	return takeoverTarget{kind: takeoverKindCandidate, jobID: cand.ID,
		svc: svc, db: s.f.db, authz: s.authz,
		capKey: CredCapAccountRotate, assetID: s.f.assetID,
		req:      validConfirmRequest(t, s.f.db, s.f.assetID),
		attempts: s.f.server.authAttempts.Load}
}

func memberTakeoverTarget(t *testing.T) takeoverTarget {
	t.Helper()
	f, _, m := sentUnverified(t, false)
	adoptRemoteKey(t, f.server, f.db, f.assetID, true)
	svc := NewHostIdentityTakeoverService(f.db, f.perms)
	svc.SetAuditTxSink(audit.NewTxSink())
	return takeoverTarget{kind: takeoverKindMember, jobID: m.ID,
		svc: svc, db: f.db, authz: f.perms,
		capKey: CredCapRotate, assetID: f.assetID,
		req:      validConfirmRequest(t, f.db, f.assetID),
		attempts: f.server.authAttempts.Load}
}

func runTakeoverGate(t *testing.T) {
	kinds := []struct {
		name string
		make func(*testing.T) takeoverTarget
	}{{"候選", candidateTakeoverTarget}, {"成員", memberTakeoverTarget}}

	for _, k := range kinds {
		t.Run("4.1/確認入口/"+k.name+"/對照組：具權且目標未變到達未完成", func(t *testing.T) {
			tg := k.make(t)
			tr := newTakeoverTrace(t, tg.db, tg.attempts)
			req := tg.req
			req.AcceptDifferentKey = true // 夾具的當下記錄是採用後的新鑰
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, req)
			assert.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete, "四個拒絕案例的對照：授權與目標都通過才會走到這裡")
			// 與拒絕案例的差別：只有這一案留下恰一筆承接紀錄與一筆審計；授權列與 authAttempts 仍不變
			var confirms, audits, auths int64
			require.NoError(t, tg.db.Model(&model.CredentialHostIdentityConfirmation{}).Count(&confirms).Error)
			require.NoError(t, tg.db.Model(&model.AuditLog{}).Where("details LIKE ?", `%host_identity_confirm%`).Count(&audits).Error)
			require.NoError(t, tg.db.Model(&model.CredentialJobAuthorization{}).Count(&auths).Error)
			assert.EqualValues(t, 1, confirms)
			assert.EqualValues(t, 1, audits)
			assert.Equal(t, tr.authRows, auths)
			assert.Equal(t, tr.base, tg.attempts())
			asked := tg.authz.asked
			require.GreaterOrEqual(t, len(asked), 2, "確實問過授權判定器：確認者一次、原發起者一次")
			confirmer, initiator := asked[len(asked)-2], asked[len(asked)-1]
			ctxCaps := authContextCaps(t, tg)
			assert.ElementsMatch(t, unionCaps(tg.capKey, ctxCaps), confirmer.Capabilities,
				"確認者能力＝基本鍵 ∪ 工作授權脈絡記下的能力集合")
			assert.Equal(t, []uint{tg.assetID}, confirmer.AssetIDs)
			assert.ElementsMatch(t, ctxCaps, initiator.Capabilities, "原發起者以脈絡能力重驗")
		})

		t.Run("4.1/確認入口/"+k.name+"/無權", func(t *testing.T) {
			tg := k.make(t)
			tg.authz.deny(tg.capKey)
			tr := newTakeoverTrace(t, tg.db, tg.attempts)
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, tg.req)
			assert.ErrorIs(t, err, ErrCredentialBindForbidden)
			tr.requireUntouched(t)
		})

		t.Run("4.1/確認入口/"+k.name+"/背景無主體", func(t *testing.T) {
			tg := k.make(t)
			tg.authz.reset()
			tr := newTakeoverTrace(t, tg.db, tg.attempts)
			for name, ctx := range map[string]context.Context{
				"空脈絡":    context.Background(),
				"系統呼叫標記": WithSystemCaller(context.Background()),
			} {
				err := tg.svc.ConfirmHostIdentityAndVerify(ctx, tg.kind, tg.jobID, tg.req)
				assert.ErrorIs(t, err, ErrCredentialBindForbidden, name)
			}
			assert.Empty(t, tg.authz.asked, "沒有主體：連判定器都不問")
			tr.requireUntouched(t)
		})

		t.Run("4.1/確認入口/"+k.name+"/偽造actor", func(t *testing.T) {
			tg := k.make(t)
			tr := newTakeoverTrace(t, tg.db, tg.attempts)
			// 請求主體不收 actor、授權旗標或 force：多餘欄位在解碼就拒絕
			valid := `{"transport":"ssh","record_id":1,"algorithm":"a","fingerprint":"f","generation":1,"accept_different_key":false`
			_, err := DecodeHostIdentityConfirmRequest([]byte(valid + `}`))
			require.NoError(t, err, "對照：沒有多餘欄位的請求可解碼")
			for _, extra := range []string{`"actor":{"user_id":1}`, `"user_id":1`, `"username":"admin"`, `"force":true`, `"authorized":true`} {
				_, err := DecodeHostIdentityConfirmRequest([]byte(valid + `,` + extra + `}`))
				assert.ErrorIs(t, err, ErrHostIdentityConfirmInvalid, extra)
			}
			// 系統呼叫標記不能替代主體；掛了標記的偽造主體仍由判定器依能力裁決
			tg.authz.deny(tg.capKey)
			forged := WithSystemCaller(contextWithInitiator(context.Background(), 999, "forged"))
			err = tg.svc.ConfirmHostIdentityAndVerify(forged, tg.kind, tg.jobID, tg.req)
			assert.ErrorIs(t, err, ErrCredentialBindForbidden)
			tr.requireUntouched(t)
		})

		t.Run("4.1/確認入口/"+k.name+"/改址回AUTHZ_TARGET_CHANGED", func(t *testing.T) {
			tg := k.make(t)
			require.NoError(t, tg.db.Model(&model.Asset{}).Where("id = ?", tg.assetID).
				Update("host", "10.77.0.9").Error)
			tr := newTakeoverTrace(t, tg.db, tg.attempts)
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, tg.req)
			assert.ErrorIs(t, err, ErrHostIdentityConfirmTargetChanged)
			assert.Equal(t, model.ChangeSecretReasonAuthzTargetChanged, err.Error(), "訊息即對外原因碼")
			tr.requireUntouched(t)
		})
	}

	t.Run("4.1/確認入口/請求形狀", func(t *testing.T) {
		cases := map[string]string{
			"transport 值域外": `{"transport":"rdp"}`,
			"ssh 缺指紋":       `{"transport":"ssh","record_id":1,"algorithm":"a","generation":1}`,
			"ssh 缺世代":       `{"transport":"ssh","record_id":1,"algorithm":"a","fingerprint":"f"}`,
			"winrm 帶身分欄位":   `{"transport":"winrm","record_id":1}`,
			"尾端多餘內容":        `{"transport":"winrm"}{"x":1}`,
		}
		for name, body := range cases {
			_, err := DecodeHostIdentityConfirmRequest([]byte(body))
			assert.ErrorIs(t, err, ErrHostIdentityConfirmInvalid, name)
		}
		ok, err := DecodeHostIdentityConfirmRequest([]byte(`{"transport":"winrm","accept_different_key":true}`))
		require.NoError(t, err)
		assert.True(t, ok.AcceptDifferentKey)
	})
}
