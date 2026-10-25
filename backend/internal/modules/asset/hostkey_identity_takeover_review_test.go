package asset

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 授權複核的補強子案例（root：TestCredentialRecoveryHostIdentityTakeover，前綴 授權複核/）。
// 共同原則：授權證據不可證實時 fail closed；只有工作確實沒有授權引用（升級前）才退回基本鍵或記原發起者未知。

// corruptAuthCapabilities 把工作授權脈絡的能力欄改成無法解析的內容（列本身仍有效）。
func corruptAuthCapabilities(t *testing.T, tg takeoverTarget, raw string) {
	t.Helper()
	require.NoError(t, tg.db.Model(&model.CredentialJobAuthorization{}).
		Where("id = ?", *takeoverAuthRef(t, tg)).Update("capabilities", raw).Error)
}

// failNthAuthRead 讓授權脈絡表的第 n 次起的讀取失敗（之前的照常）；回傳還原函式。
func failNthAuthRead(t *testing.T, db *gorm.DB, n int32, injected error) func() {
	t.Helper()
	var seen atomic.Int32
	name := "p2m:fail-auth-read"
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table != "credential_job_authorizations" {
			return
		}
		if seen.Add(1) >= n {
			_ = tx.AddError(injected)
		}
	}))
	return func() { require.NoError(t, db.Callback().Query().Remove(name)) }
}

// swapAuthRefOnLockedRead 工作列在建立交易內的重讀（該表第 2 次讀取）被換成另一個授權引用，
// 模擬入口判權之後、鎖內重讀之前引用改變。
func swapAuthRefOnLockedRead(t *testing.T, tg takeoverTarget, other uint) func() {
	t.Helper()
	table := "change_secret_candidates"
	if tg.kind == takeoverKindMember {
		table = "credential_rotations"
	}
	var seen atomic.Int32
	name := "p2m:swap-auth-ref"
	require.NoError(t, tg.db.Callback().Query().After("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table != table || seen.Add(1) != 2 {
			return
		}
		switch d := tx.Statement.Dest.(type) {
		case *model.ChangeSecretCandidate:
			d.AuthorizationID = &other
		case *model.CredentialRotation:
			d.AuthorizationID = &other
		}
	}))
	return func() { require.NoError(t, tg.db.Callback().Query().Remove(name)) }
}

func runTakeoverExternalReview(t *testing.T) {
	for _, k := range []struct {
		name string
		make func(*testing.T) takeoverTarget
	}{{"候選", candidateTakeoverTarget}, {"成員", memberTakeoverTarget}} {
		p := "授權複核/"

		// 能力欄：授權列有效但能力欄損毀
		for _, raw := range []string{"{", ""} {
			t.Run(p+"能力欄/"+k.name+"/能力欄損毀["+raw+"]_fail_closed", func(t *testing.T) {
				tg := k.make(t)
				attachInitiator(t, tg, initiatorUser, []string{tg.capKey})
				corruptAuthCapabilities(t, tg, raw)
				tr := newTakeoverTrace(t, tg.db, tg.attempts)
				before := jobStateSnapshot(t, tg.db)
				tg.authz.reset()
				err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
				assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable)
				tr.requireUntouched(t)
				assert.Empty(t, tg.authz.asked, "能力脈絡不可讀：連確認者都不判，更不重驗發起者")
				assert.Equal(t, before, jobStateSnapshot(t, tg.db), "工作與授權列不變")
			})
		}

		t.Run(p+"能力欄/"+k.name+"/原發起者重驗遇損毀能力欄也fail_closed", func(t *testing.T) {
			tg := k.make(t)
			auth := attachInitiator(t, tg, initiatorUser, []string{tg.capKey})
			corruptAuthCapabilities(t, tg, "{")
			require.NoError(t, tg.db.First(auth, auth.ID).Error)
			tg.authz.reset()
			err := tg.svc.revalidateInitiator(&takeoverSubject{assetID: tg.assetID, auth: auth,
				capabilities: []string{tg.capKey}})
			assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable)
			assert.Empty(t, tg.authz.asked, "不得退回基本鍵去問")
		})

		t.Run(p+"能力欄/"+k.name+"/對照_可解析與升級前無引用行為不變", func(t *testing.T) {
			tg := k.make(t)
			attachInitiator(t, tg, initiatorUser, []string{tg.capKey})
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			assert.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)

			tg2 := k.make(t)
			setTakeoverAuthRef(t, tg2, nil)
			err = tg2.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg2.kind, tg2.jobID, acceptDifferent(tg2.req))
			assert.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
		})

		// 二次讀取：入口讀授權成功，建立交易內的第二次讀取失敗或讀到無效列
		for _, c := range []struct {
			name string
			err  error
		}{{"讀取出錯", errors.New("db read failed")}, {"讀到無效列", gorm.ErrRecordNotFound}} {
			t.Run(p+"二次讀取/"+k.name+"/鎖內第二次讀授權"+c.name+"_整筆回滾", func(t *testing.T) {
				tg := k.make(t)
				attachInitiator(t, tg, initiatorUser, []string{tg.capKey})
				tr := newTakeoverTrace(t, tg.db, tg.attempts)
				restore := failNthAuthRead(t, tg.db, 2, c.err)
				err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
				restore() // 驗證自己也會數授權列，須先拿掉注入
				assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable)
				tr.requireUntouched(t)
				assert.Empty(t, confirmRecords(t, tg))
			})
		}

		t.Run(p+"二次讀取/"+k.name+"/鎖內授權引用與入口判權時不同_拒絕", func(t *testing.T) {
			tg := k.make(t)
			attachInitiator(t, tg, initiatorUser, []string{tg.capKey})
			other := seedAuthorizationRow(t, tg.db, 9500+tg.jobID, initiatorUser, []string{tg.capKey})
			tr := newTakeoverTrace(t, tg.db, tg.attempts)
			restore := swapAuthRefOnLockedRead(t, tg, other.ID)
			defer restore()
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable)
			tr.requireUntouched(t)
			assert.Empty(t, confirmRecords(t, tg))
		})

		t.Run(p+"二次讀取/"+k.name+"/升級前無授權引用仍記未知並放行", func(t *testing.T) {
			tg := k.make(t)
			setTakeoverAuthRef(t, tg, nil)
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			require.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
			rows := confirmRecords(t, tg)
			require.Len(t, rows, 1)
			assert.True(t, rows[0].OriginalInitiatorUnknown)
		})
	}

	// 嚴格解碼：服務層 helper 的嚴格解碼
	t.Run("嚴格解碼/服務層helper拒絕尾隨內容", func(t *testing.T) {
		ok := `{"transport":"winrm"}`
		_, err := DecodeHostIdentityConfirmRequest([]byte(ok))
		require.NoError(t, err)
		_, err = DecodeHostIdentityConfirmRequest([]byte(ok + "\n  "))
		require.NoError(t, err, "尾端空白合法")
		for name, body := range map[string]string{
			"尾隨右中括號": ok + `]`, "尾隨右大括號": ok + `}`, "第二個JSON值": ok + ` {"transport":"winrm"}`,
			"尾隨數字": ok + ` 1`, "尾隨垃圾": ok + ` x`,
		} {
			_, err := DecodeHostIdentityConfirmRequest([]byte(body))
			assert.ErrorIs(t, err, ErrHostIdentityConfirmInvalid, name)
		}
	})
}
