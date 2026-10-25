package asset

import (
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

// 派送標記與派送證據分類的子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.1/）。

// markerOf 重新讀取成員列的派送標記。
func markerOf(t *testing.T, db *gorm.DB, memberID uint) *time.Time {
	t.Helper()
	var m model.CredentialRotationMember
	require.NoError(t, db.Where("id = ?", memberID).First(&m).Error)
	return m.SecretSentAt
}

func requireMarkerSet(t *testing.T, db *gorm.DB, memberID uint, msg string) time.Time {
	t.Helper()
	got := markerOf(t, db, memberID)
	require.NotNil(t, got, msg)
	return *got
}

func requireMarkerEqual(t *testing.T, db *gorm.DB, memberID uint, want time.Time, msg string) {
	t.Helper()
	got := markerOf(t, db, memberID)
	require.NotNil(t, got, msg)
	assert.True(t, want.Equal(*got), "%s: want %v got %v", msg, want, *got)
}

// runSentMarkCore 只動成員表的轉移序列（不需要資產與憑證表），兩種方言共用。
func runSentMarkCore(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&model.CredentialRotationMember{}))
	seq := 0
	// 直寫列（刻意保留）：這是只動成員表的派送標記轉移單元，沒有資產、憑證與主機金鑰表可走正式綁定回呼；
	// 驗的是轉移函式對標記欄的寫入規則，綁定欄只是列的既有值，與綁定流程無關。
	newMember := func(state string, sent *time.Time) *model.CredentialRotationMember {
		seq++
		m := &model.CredentialRotationMember{
			RotationID: 1, AccountID: uint(seq), CredentialID: 1, AssetID: uint(seq),
			State: state, HostKeyBinding: model.HostKeyBindingBound, SecretSentAt: sent,
		}
		require.NoError(t, db.Create(m).Error)
		return m
	}
	step := func(m *model.CredentialRotationMember, to string) {
		t.Helper()
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			return transitionMember(tx, m, to, memberTransition{})
		}), "%s -> %s", m.State, to)
	}

	t.Run("乾淨失敗不寫、已送出轉移寫一次、之後任何轉移不改值", func(t *testing.T) {
		m := newMember(model.CredentialMemberQueued, nil)
		step(m, model.CredentialMemberChanging)
		assert.Nil(t, markerOf(t, db, m.ID), "queued -> changing 不寫")
		step(m, model.CredentialMemberRetryWait)
		assert.Nil(t, markerOf(t, db, m.ID), "乾淨失敗 changing -> retry_wait 不寫")
		step(m, model.CredentialMemberChanging)
		step(m, model.CredentialMemberTerminalFailed)
		assert.Nil(t, markerOf(t, db, m.ID), "乾淨失敗 changing -> terminal_failed 不寫")
		step(m, model.CredentialMemberQueued)
		step(m, model.CredentialMemberChanging)
		assert.Nil(t, markerOf(t, db, m.ID))
		step(m, model.CredentialMemberChangedUnverified)
		first := requireMarkerSet(t, db, m.ID, "changing -> changed_unverified 寫入")
		require.NotNil(t, m.SecretSentAt, "記憶體中的成員同步")
		assert.WithinDuration(t, first, *m.SecretSentAt, time.Millisecond, "資料庫時間精度可能低於記憶體")
		step(m, model.CredentialMemberTerminalFailed)
		requireMarkerEqual(t, db, m.ID, first, "terminal_failed 不改值")
		step(m, model.CredentialMemberQueued)
		requireMarkerEqual(t, db, m.ID, first, "requeue 不改值")
		step(m, model.CredentialMemberChanging)
		step(m, model.CredentialMemberRetryWait)
		requireMarkerEqual(t, db, m.ID, first, "再一次乾淨失敗不改值（不寫回 NULL）")
	})

	t.Run("既有標記不被後續轉移覆寫", func(t *testing.T) {
		old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
		m := newMember(model.CredentialMemberChanging, &old)
		step(m, model.CredentialMemberChangedUnverified)
		requireMarkerEqual(t, db, m.ID, old, "changing -> changed_unverified 不覆寫既有值")
		m2 := newMember(model.CredentialMemberChanging, &old)
		step(m2, model.CredentialMemberAbandoned)
		requireMarkerEqual(t, db, m2.ID, old, "changing -> abandoned 不覆寫既有值")
	})

	t.Run("由changing放棄寫入、由queued放棄不寫", func(t *testing.T) {
		fromChanging := newMember(model.CredentialMemberChanging, nil)
		step(fromChanging, model.CredentialMemberAbandoned)
		requireMarkerSet(t, db, fromChanging.ID, "changing -> abandoned 寫入")
		fromQueued := newMember(model.CredentialMemberQueued, nil)
		step(fromQueued, model.CredentialMemberAbandoned)
		assert.Nil(t, markerOf(t, db, fromQueued.ID), "queued -> abandoned（從未下達）不寫")
		retryWait := newMember(model.CredentialMemberRetryWait, nil)
		step(retryWait, model.CredentialMemberAbandoned)
		assert.Nil(t, markerOf(t, db, retryWait.ID), "retry_wait -> abandoned（上次是乾淨失敗）不寫")
	})
}

func openSentMarkSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	return db
}

func openSentMarkPG(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	schema := fmt.Sprintf("sent_mark_%d", time.Now().UnixNano())
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{
		Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// 經正式 Run／RunMember／Abandon／RecoverInterruptedMembers 觸發的派送標記案例。
func runSentMarkThroughService(t *testing.T) {
	t.Run("成員轉changed_unverified與applied都寫入，補跑就位不改值", func(t *testing.T) {
		f := setupRotationFixture(t)
		credID, accounts := f.sharedOn(t, "標記甲", "ops", "old", "10.31.0.1", "10.31.0.2")
		f.remote.setVerifyErr("10.31.0.2", errRemoteDropped)
		rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		for _, id := range accounts {
			assert.Nil(t, f.memberFor(t, rot.ID, id).SecretSentAt, "派送前為 NULL")
		}
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		m1 := f.memberFor(t, rot.ID, accounts[0])
		m2 := f.memberFor(t, rot.ID, accounts[1])
		require.Equal(t, model.CredentialMemberApplied, m1.State)
		require.Equal(t, model.CredentialMemberChangedUnverified, m2.State)
		requireMarkerSet(t, f.db, m1.ID, "applied 寫入")
		sent := requireMarkerSet(t, f.db, m2.ID, "changed_unverified 寫入")

		f.remote.setVerifyErr("10.31.0.2", nil)
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m2.ID))
		after := f.memberFor(t, rot.ID, accounts[1])
		require.Equal(t, model.CredentialMemberApplied, after.State)
		requireMarkerEqual(t, f.db, m2.ID, sent, "補跑驗證就位不改值")
	})

	t.Run("由changing放棄寫入，從未下達的排隊成員不寫", func(t *testing.T) {
		f := setupRotationFixture(t)
		credID, accounts := f.sharedOn(t, "標記乙", "ops", "old", "10.31.1.1", "10.31.1.2")
		rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		m1 := f.memberFor(t, rot.ID, accounts[0])
		require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m1.ID).
			Update("state", model.CredentialMemberChanging).Error)
		// 放棄本輪：changing 成員結果未知，維持原狀；排隊成員從未下達，直接收束且不寫標記
		require.NoError(t, f.rotations.Abandon(adminCtx(), rot.ID))
		mid1 := f.memberFor(t, rot.ID, accounts[0])
		mid2 := f.memberFor(t, rot.ID, accounts[1])
		assert.Equal(t, model.CredentialMemberChanging, mid1.State)
		assert.Equal(t, model.CredentialMemberAbandoned, mid2.State)
		assert.Nil(t, mid2.SecretSentAt, "由 queued 放棄＝從未下達，不寫")
		assert.Nil(t, mid1.SecretSentAt)

		// 操作者宣告的新密文取代待生效版本：changing 成員就地收束，同一轉移寫入標記
		_, err = f.creds.SetSecret(adminCtx(), credID, &SetCredentialSecretRequest{Password: "declared-new"})
		require.NoError(t, err)
		a1 := f.memberFor(t, rot.ID, accounts[0])
		assert.Equal(t, model.CredentialMemberAbandoned, a1.State)
		assert.NotNil(t, a1.SecretSentAt, "由 changing 放棄＝結果不可知，寫入")
		assert.Nil(t, f.memberFor(t, rot.ID, accounts[1]).SecretSentAt, "排隊成員仍為 NULL")
	})

	t.Run("重啟收束寫入，乾淨失敗的對照成員不寫", func(t *testing.T) {
		f := setupRotationFixture(t)
		credID, accounts := f.sharedOn(t, "標記丙", "ops", "old", "10.31.2.1", "10.31.2.2")
		f.remote.setRotateErr("10.31.2.2", errRemoteRejected)
		rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		m2 := f.memberFor(t, rot.ID, accounts[1])
		require.Equal(t, model.CredentialMemberRetryWait, m2.State, "乾淨失敗進入重試等待")
		assert.Nil(t, m2.SecretSentAt, "failClean 不寫派送標記")

		// 再失敗一次（手動補跑），標記仍為 NULL
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m2.ID))
		again := f.memberFor(t, rot.ID, accounts[1])
		assert.Contains(t, []string{model.CredentialMemberRetryWait, model.CredentialMemberTerminalFailed}, again.State)
		assert.Nil(t, again.SecretSentAt, "再一次乾淨失敗仍為 NULL")

		// 模擬行程在下達途中結束，重啟收束
		f.remote.setRotateErr("10.31.2.2", nil)
		require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m2.ID).
			Updates(map[string]any{"state": model.CredentialMemberChanging, "next_attempt_at": nil}).Error)
		n, err := f.rotations.RecoverInterruptedMembers()
		require.NoError(t, err)
		require.Equal(t, 1, n)
		recovered := f.memberFor(t, rot.ID, accounts[1])
		assert.Equal(t, model.CredentialMemberChangedUnverified, recovered.State)
		assert.NotNil(t, recovered.SecretSentAt, "重啟收束的同一轉移寫入")
	})

	t.Run("送出後的requeue、清除候選、再一次乾淨失敗都不改值", func(t *testing.T) {
		f := setupRotationFixture(t)
		credID, accounts := f.sharedOn(t, "標記丁", "ops", "old", "10.31.3.1", "10.31.3.2")
		f.remote.setRotateErr("10.31.3.2", &remoteStateUnknownError{reason: model.ChangeSecretReasonRemoteStateUnknown})
		rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		m2 := f.memberFor(t, rot.ID, accounts[1])
		require.Equal(t, model.CredentialMemberChangedUnverified, m2.State)
		sent := requireMarkerSet(t, f.db, m2.ID, "結果未知的下達寫入標記")

		// 管理員清除候選副本
		cand, err := f.candidates.FindByAccount(accounts[1])
		require.NoError(t, err)
		require.NotNil(t, cand)
		require.NoError(t, f.candidates.Discard(cand.ID))
		assert.EqualValues(t, 0, f.candidateCountFor(t, accounts[1]))
		requireMarkerEqual(t, f.db, m2.ID, sent, "清除候選不改值")

		// 逾期收為終局失敗後逐台補跑：requeue 後再一次乾淨失敗
		f.remote.setRotateErr("10.31.3.2", errRemoteRejected)
		require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m2.ID).
			Update("state", model.CredentialMemberTerminalFailed).Error)
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m2.ID))
		mid := f.memberFor(t, rot.ID, accounts[1])
		assert.Contains(t, []string{model.CredentialMemberRetryWait, model.CredentialMemberTerminalFailed}, mid.State, "requeue 後乾淨失敗")
		assert.NotZero(t, mid.RequeuedBy, "確實經過 requeue")
		requireMarkerEqual(t, f.db, m2.ID, sent, "requeue 與乾淨失敗不改值")

		// 再一次
		require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m2.ID).
			Update("state", model.CredentialMemberTerminalFailed).Error)
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m2.ID))
		requireMarkerEqual(t, f.db, m2.ID, sent, "再一次乾淨失敗不改值")
	})
}

// 派送證據分類：分流層與交易層。
func runDeliveryClassification(t *testing.T) {
	sent := time.Now()
	type tc struct {
		name    string
		binding string
		sent    bool
		mode    string
		cand    bool
		want    deliveryRoute
	}
	group, split := model.CredentialRotationModeGroup, model.CredentialRotationModeSplit
	cases := []tc{
		{"pending 一律綁定（候選列存在也無關）", model.HostKeyBindingPending, false, group, true, deliveryRouteBind},
		{"bound 標記為 NULL 重新綁定（候選列不看）", model.HostKeyBindingBound, false, group, true, deliveryRouteBind},
		{"bound 標記為 NULL 無候選列", model.HostKeyBindingBound, false, group, false, deliveryRouteBind},
		{"bound 標記非空沿原 pin（候選列不在也一樣）", model.HostKeyBindingBound, true, group, false, deliveryRoutePinned},
		{"bound 標記非空拆分模式", model.HostKeyBindingBound, true, split, true, deliveryRoutePinned},
		{"legacy 標記非空停止", model.HostKeyBindingLegacy, true, group, false, deliveryRouteBlocked},
		{"legacy 標記非空拆分模式停止", model.HostKeyBindingLegacy, true, split, false, deliveryRouteBlocked},
		{"legacy 整組有候選列停止", model.HostKeyBindingLegacy, false, group, true, deliveryRouteBlocked},
		{"legacy 整組無候選列未標記照常綁定", model.HostKeyBindingLegacy, false, group, false, deliveryRouteBind},
		{"legacy 拆分有候選列未標記照常綁定", model.HostKeyBindingLegacy, false, split, true, deliveryRouteBind},
		{"legacy 拆分無候選列未標記照常綁定", model.HostKeyBindingLegacy, false, split, false, deliveryRouteBind},
		{"未知綁定值 fail-closed", "weird", false, group, false, deliveryRouteBlocked},
	}
	t.Run("分流層", func(t *testing.T) {
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				m := &model.CredentialRotationMember{HostKeyBinding: c.binding}
				if c.sent {
					m.SecretSentAt = &sent
				}
				assert.Equal(t, c.want, classifyMemberDelivery(m, c.mode, c.cand))
			})
		}
		t.Run("不看LastError與狀態名", func(t *testing.T) {
			for _, st := range credentialMemberStates {
				for _, le := range []string{"", model.ChangeSecretReasonInterrupted, model.ChangeSecretReasonRemoteRejected} {
					m := &model.CredentialRotationMember{HostKeyBinding: model.HostKeyBindingBound, State: st, LastError: le}
					assert.Equal(t, deliveryRouteBind, classifyMemberDelivery(m, model.CredentialRotationModeGroup, false), "%s/%s", st, le)
				}
			}
		})
	})

	t.Run("交易層條件只含三項可重驗事實", func(t *testing.T) {
		db := openSentMarkSQLite(t)
		require.NoError(t, db.AutoMigrate(&model.CredentialRotationMember{}))
		stamp := time.Now()
		seq := 0
		for _, st := range credentialMemberStates {
			for _, binding := range []string{model.HostKeyBindingPending, model.HostKeyBindingBound, model.HostKeyBindingLegacy} {
				for _, marked := range []bool{false, true} {
					seq++
					m := model.CredentialRotationMember{
						RotationID: 1, AccountID: uint(seq), CredentialID: 1, AssetID: uint(seq),
						State: st, HostKeyBinding: binding,
					}
					if marked {
						m.SecretSentAt = &stamp
					}
					require.NoError(t, db.Create(&m).Error)
					var n int64
					require.NoError(t, db.Model(&model.CredentialRotationMember{}).
						Where("id = ? AND "+memberBindEligibleSQL, m.ID).Count(&n).Error)
					want := st == model.CredentialMemberChanging &&
						(binding == model.HostKeyBindingPending || !marked)
					assert.Equal(t, want, n == 1, "state=%s binding=%s marked=%v", st, binding, marked)
				}
			}
		}
	})
}
