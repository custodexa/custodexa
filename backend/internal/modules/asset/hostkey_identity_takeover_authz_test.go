package asset

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 確認者能力集合與原發起者情形的子案例
// （root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.1/確認入口/能力集合/、4.1/原發起者/）。

// unionCaps 基本鍵加脈絡能力，去重。
func unionCaps(base string, ctxCaps []string) []string {
	out := []string{base}
	for _, c := range ctxCaps {
		if c != base {
			out = append(out, c)
		}
	}
	return out
}

// takeoverAuthRef 工作目前引用的授權脈絡（候選或其輪替）；沒有引用回 nil。
func takeoverAuthRef(t *testing.T, tg takeoverTarget) *uint {
	t.Helper()
	if tg.kind == takeoverKindCandidate {
		var c model.ChangeSecretCandidate
		require.NoError(t, tg.db.First(&c, tg.jobID).Error)
		return c.AuthorizationID
	}
	var m model.CredentialRotationMember
	require.NoError(t, tg.db.First(&m, tg.jobID).Error)
	var rot model.CredentialRotation
	require.NoError(t, tg.db.First(&rot, m.RotationID).Error)
	return rot.AuthorizationID
}

// authContextCaps 工作授權脈絡記下的能力集合。
func authContextCaps(t *testing.T, tg takeoverTarget) []string {
	t.Helper()
	auth, err := loadJobAuthorization(tg.db, takeoverAuthRef(t, tg))
	require.NoError(t, err)
	var caps []string
	require.NoError(t, json.Unmarshal([]byte(auth.Capabilities), &caps))
	return caps
}

// setTakeoverAuthRef 把工作引用的授權脈絡改成 ref（nil＝無脈絡）。
func setTakeoverAuthRef(t *testing.T, tg takeoverTarget, ref *uint) {
	t.Helper()
	// 夾具庫未預建承接紀錄表：先建出來，「無紀錄」與紀錄欄位斷言才有意義
	require.NoError(t, tg.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
	if tg.kind == takeoverKindCandidate {
		require.NoError(t, tg.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", tg.jobID).
			Update("authorization_id", ref).Error)
		return
	}
	var m model.CredentialRotationMember
	require.NoError(t, tg.db.First(&m, tg.jobID).Error)
	require.NoError(t, tg.db.Model(&model.CredentialRotation{}).Where("id = ?", m.RotationID).
		Update("authorization_id", ref).Error)
}

// attachInitiator 新增一列授權脈絡（原發起者 actor、能力 caps）並掛到工作；回該列。
func attachInitiator(t *testing.T, tg takeoverTarget, actor uint, caps []string) *model.CredentialJobAuthorization {
	t.Helper()
	auth := seedAuthorizationRow(t, tg.db, 9000+tg.jobID, actor, caps)
	setTakeoverAuthRef(t, tg, &auth.ID)
	return auth
}

// jobStateSnapshot 工作與授權相關的全部列（候選、輪替、成員、授權脈絡），序列化供前後比對。
func jobStateSnapshot(t *testing.T, db *gorm.DB) string {
	t.Helper()
	out := map[string]any{}
	for name, tbl := range map[string]any{
		"candidates": &model.ChangeSecretCandidate{}, "rotations": &model.CredentialRotation{},
		"members": &model.CredentialRotationMember{}, "authorizations": &model.CredentialJobAuthorization{},
	} {
		if !db.Migrator().HasTable(tbl) {
			continue
		}
		var rows []map[string]any
		require.NoError(t, db.Model(tbl).Order("id").Find(&rows).Error)
		out[name] = rows
	}
	b, err := json.Marshal(out)
	require.NoError(t, err)
	return string(b)
}

func actorsAsked(a *fakeCredentialAuthorizer) map[uint]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[uint]int{}
	for _, u := range a.askedActors {
		out[u]++
	}
	return out
}

const initiatorUser uint = 2

func runTakeoverAuthz(t *testing.T) {
	// 確認者能力集合：整批同一組缺 bind、拆分缺 detach
	t.Run("4.1/確認入口/能力集合/候選整批同一組缺bind", func(t *testing.T) {
		tg := candidateTakeoverTarget(t)
		caps := []string{CredCapAccountRotate, CredCapCreate, CredCapBind}
		attachInitiator(t, tg, initiatorUser, caps)
		tg.authz.denyFor(1, CredCapBind)
		tr := newTakeoverTrace(t, tg.db, tg.attempts)
		tg.authz.reset()
		err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, tg.req)
		assert.ErrorIs(t, err, ErrCredentialBindForbidden)
		tr.requireUntouched(t)
		require.NotEmpty(t, tg.authz.asked)
		assert.ElementsMatch(t, caps, tg.authz.asked[0].Capabilities, "確認者被問到整組脈絡能力（含 bind）")

		// 對照：確認者具備 bind 則通過到未完成
		tg2 := candidateTakeoverTarget(t)
		attachInitiator(t, tg2, initiatorUser, caps)
		err = tg2.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg2.kind, tg2.jobID, acceptDifferent(tg2.req))
		assert.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
	})

	t.Run("4.1/確認入口/能力集合/成員拆分缺detach", func(t *testing.T) {
		tg := memberTakeoverTarget(t)
		caps := []string{CredCapRotate, CredCapDetach}
		attachInitiator(t, tg, initiatorUser, caps)
		tg.authz.denyFor(1, CredCapDetach)
		tr := newTakeoverTrace(t, tg.db, tg.attempts)
		tg.authz.reset()
		err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, tg.req)
		assert.ErrorIs(t, err, ErrCredentialBindForbidden)
		tr.requireUntouched(t)
		require.NotEmpty(t, tg.authz.asked)
		assert.ElementsMatch(t, caps, tg.authz.asked[0].Capabilities, "確認者被問到整組脈絡能力（含 detach）")

		tg2 := memberTakeoverTarget(t)
		attachInitiator(t, tg2, initiatorUser, caps)
		err = tg2.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg2.kind, tg2.jobID, acceptDifferent(tg2.req))
		assert.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
	})

	for _, k := range []struct {
		name string
		make func(*testing.T) takeoverTarget
	}{{"候選", candidateTakeoverTarget}, {"成員", memberTakeoverTarget}} {
		t.Run("4.1/確認入口/能力集合/"+k.name+"/授權脈絡引用壞掉_fail_closed", func(t *testing.T) {
			tg := k.make(t)
			bad := uint(987654)
			setTakeoverAuthRef(t, tg, &bad)
			tr := newTakeoverTrace(t, tg.db, tg.attempts)
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, tg.req)
			assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable)
			tr.requireUntouched(t)
		})

		t.Run("4.1/確認入口/能力集合/"+k.name+"/無脈絡退回基本鍵", func(t *testing.T) {
			tg := k.make(t)
			setTakeoverAuthRef(t, tg, nil)
			tg.authz.reset()
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			assert.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
			require.Len(t, tg.authz.asked, 1, "無脈絡：只問確認者一次")
			assert.Equal(t, []string{tg.capKey}, tg.authz.asked[0].Capabilities)
		})

		runInitiatorCases(t, k.name, k.make)
	}
}

// runInitiatorCases 原發起者四種情形（有效、失權、無授權脈絡、還原前）。
func runInitiatorCases(t *testing.T, kind string, mk func(*testing.T) takeoverTarget) {
	type situation struct {
		name    string
		prepare func(t *testing.T, tg takeoverTarget) []string // 回傳脈絡能力（無脈絡回 nil）
		// 預期紀錄欄位與是否另重驗原發起者
		wantID      uint
		wantUnknown bool
		wantRestore string
		wantRecheck bool
	}
	sits := []situation{
		{name: "有效", prepare: func(t *testing.T, tg takeoverTarget) []string {
			caps := []string{tg.capKey}
			attachInitiator(t, tg, initiatorUser, caps)
			return caps
		}, wantID: initiatorUser, wantRecheck: true},
		{name: "失權", prepare: func(t *testing.T, tg takeoverTarget) []string {
			caps := []string{tg.capKey}
			attachInitiator(t, tg, initiatorUser, caps)
			tg.authz.denyFor(initiatorUser, tg.capKey)
			return caps
		}, wantID: initiatorUser, wantRecheck: true},
		{name: "無授權脈絡", prepare: func(t *testing.T, tg takeoverTarget) []string {
			setTakeoverAuthRef(t, tg, nil)
			return nil
		}, wantUnknown: true},
		{name: "還原前", prepare: func(t *testing.T, tg takeoverTarget) []string {
			caps := []string{tg.capKey}
			attachInitiator(t, tg, initiatorUser, caps)
			tg.authz.setRestoreGeneration("gen-after-restore")
			return caps
		}, wantID: initiatorUser, wantRestore: "gen-after-restore"},
	}

	for _, sit := range sits {
		p := "4.1/原發起者/" + kind + "/" + sit.name + "/"

		t.Run(p+"確認成功建立紀錄且整輪授權不變", func(t *testing.T) {
			tg := mk(t)
			caps := sit.prepare(t, tg)
			before := jobStateSnapshot(t, tg.db)
			tg.authz.reset()
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			require.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
			rows := confirmRecords(t, tg)
			require.Len(t, rows, 1)
			assert.Equal(t, sit.wantID, rows[0].OriginalInitiatorID)
			assert.Equal(t, sit.wantUnknown, rows[0].OriginalInitiatorUnknown)
			assert.Equal(t, sit.wantRestore, rows[0].RestoreGeneration)
			assert.Equal(t, before, jobStateSnapshot(t, tg.db),
				"候選、輪替、同輪其他成員、授權脈絡引用與列數全部不變")
			asked := actorsAsked(tg.authz)
			assert.Equal(t, 1, asked[1], "確認者恰被判一次")
			if sit.wantRecheck {
				assert.Equal(t, 1, asked[initiatorUser], "原發起者仍有授權脈絡且在還原之後：另重驗其能力")
				last := tg.authz.asked[len(tg.authz.asked)-1]
				assert.ElementsMatch(t, caps, last.Capabilities)
			} else {
				assert.Zero(t, asked[initiatorUser], "無脈絡或脈絡留自還原之前：不重驗原發起者")
			}
		})

		t.Run(p+"錯誤確認回409且狀態不變", func(t *testing.T) {
			tg := mk(t)
			sit.prepare(t, tg)
			before := jobStateSnapshot(t, tg.db)
			req := acceptDifferent(tg.req)
			req.Fingerprint = "SHA256:other"
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, req)
			requireConflict(t, err, "")
			assert.Empty(t, confirmRecords(t, tg))
			assert.Equal(t, before, jobStateSnapshot(t, tg.db))
		})

		t.Run(p+"審計失敗整筆回滾且狀態不變", func(t *testing.T) {
			tg := mk(t)
			sit.prepare(t, tg)
			before := jobStateSnapshot(t, tg.db)
			tg.svc.SetAuditTxSink(failingTxSink{err: errors.New("audit down")})
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
			assert.Empty(t, confirmRecords(t, tg))
			assert.Equal(t, before, jobStateSnapshot(t, tg.db))
		})
	}

	t.Run("4.1/原發起者/"+kind+"/有效但無法判定_fail_closed", func(t *testing.T) {
		tg := mk(t)
		attachInitiator(t, tg, initiatorUser, []string{tg.capKey})
		tg.authz.failFor(initiatorUser, errors.New("authorizer down"))
		tr := newTakeoverTrace(t, tg.db, tg.attempts)
		err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
		assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable)
		tr.requireUntouched(t)
	})
}
