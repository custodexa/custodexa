package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 放棄之後的兩條規則，各守一邊：
//
//  1. 放棄的輪替**不再捕獲候選**——憑證的進行中識別已清空，該掛載對計劃與批次
//     重新開放，其後建立的候選必須能照常轉正。捕獲會讓遠端密碼已改、就位版本
//     卻永不更新，而畫面上看不出任何異常。
//  2. 未收斂的憑證**不接受任何會動遠端的新動作**（拆分、脫離、批次兩種模式）——
//     此刻再改一次那些主機的密碼，補跑就再也對不回上一輪的秘密。
//
// 兩條的判準各自唯一：前者是輪替狀態，後者是 assertCredentialConverged。

// abandonedOutOfSync 建一筆共用憑證、跑一輪全數「已下達未驗證」的改密後放棄，
// 使憑證停在未同步狀態。回傳憑證 id、逐台掛載 id 與那台 recorder。
func abandonedOutOfSync(t *testing.T, f *batchFixture, name string,
	hosts ...string) (uint, []uint, *secretRecorder) {

	t.Helper()
	credID, accounts := f.sharedOn(t, name, "ops", "old-shared", hosts...)
	rec := newSecretRecorder()
	for _, host := range hosts {
		rec.verifyErr[host] = errRemoteDropped
	}
	f.useRotationExecutor(rec)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	require.NoError(t, f.rotations.Abandon(adminCtx(), rot.ID))

	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	require.Equal(t, CredentialAggregateOutOfSync, state, "前提：放棄後憑證停在未同步")
	return credID, accounts, rec
}

// 放棄後建立的候選照常轉正：歸屬判準只認進行中的輪替
func TestAbandonedRotationDoesNotCaptureLaterCandidate(t *testing.T) {
	f := setupBatchFixture(t)
	_, accounts, rec := abandonedOutOfSync(t, f, "放棄後不捕獲", "10.6.1.1", "10.6.1.2")
	accountID := accounts[0]
	// 遠端恢復正常：本測試要看的是歸屬判準，不是連線結果
	rec.mu.Lock()
	rec.verifyErr = map[string]error{}
	rec.mu.Unlock()

	// 前提：放棄前該掛載確實會被捕獲——否則本測試證明不了判準真的窄化了
	var memberCount int64
	require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).
		Where("account_id = ? AND state <> ?", accountID, model.CredentialMemberApplied).
		Count(&memberCount).Error)
	require.NotZero(t, memberCount, "前提：該掛載仍有未就位的成員列")

	member, err := rotationMemberForAccount(f.db, accountID)
	require.NoError(t, err)
	assert.Nil(t, member, "放棄的輪替不得捕獲候選：其成員只由顯式補跑推進")

	// 那一輪留下的候選清掉，改放一筆計劃來源的候選（不帶憑證與目標版本）
	require.NoError(t, f.db.Where("account_id = ?", accountID).
		Delete(&model.ChangeSecretCandidate{}).Error)
	cand, err := f.candidates.Create(adminCtx(), CandidateInput{
		AssetID: f.bindingOf(t, accountID).AssetID, AccountID: accountID,
		AccountUsername: "ops", PlanID: 1,
		SecretType: model.ChangeSecretTypePassword,
		Password:   "plan-new-pass",
	})
	require.NoError(t, err)

	assert.True(t, f.retry.RetryOne(cand), "放棄後的計劃候選必須能轉正")
	var left int64
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).
		Where("account_id = ?", accountID).Count(&left).Error)
	assert.Zero(t, left, "轉正後該掛載的候選列清空")

	creds, err := f.assets.GetWithCredentialsForAccount(f.bindingOf(t, accountID).AssetID, accountID)
	require.NoError(t, err)
	assert.Equal(t, "plan-new-pass", creds.Password, "就位版本必須是剛轉正的那一組")
}

// 未收斂的憑證拒絕拆分與脫離（與發起新一輪同一判準）
func TestOutOfSyncCredentialRejectsSplitAndDetach(t *testing.T) {
	f := setupBatchFixture(t)
	credID, accounts, _ := abandonedOutOfSync(t, f, "未收斂拒拆分", "10.6.2.1", "10.6.2.2")

	_, err := f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
	assert.ErrorIs(t, err, ErrCredentialOutOfSync, "未收斂前不得發起拆分")

	_, err = f.rotations.StartSplitFor(adminCtx(), credID, accounts[:1], StartRotationRequest{})
	assert.ErrorIs(t, err, ErrCredentialOutOfSync, "只選部分掛載同樣不得拆分")

	_, err = f.rotations.Detach(adminCtx(), credID, accounts[0],
		DetachCredentialRequest{Source: DetachSourceRandom})
	assert.ErrorIs(t, err, ErrCredentialOutOfSync, "未收斂前不得單台脫離")
}

// 未收斂的憑證：批次的兩種密碼模式都只記略過，遠端零觸碰
func TestOutOfSyncCredentialSkippedByBatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
	}{
		{"每台各自隨機", model.BatchPasswordPerTarget},
		{"整批同一組", model.BatchPasswordShared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setupBatchFixture(t)
			credID, _, rec := abandonedOutOfSync(t, f, "未收斂批次-"+tc.name,
				"10.6.3.1", "10.6.3.2")
			// 放棄那一輪已對兩台下達過新密；本段只看批次有沒有再下達第二次
			_, rotateBefore, _ := rec.snapshotCalls()

			req := batchRequest("ops", tc.mode, true)
			if tc.mode == model.BatchPasswordShared {
				req.CredentialName = "未收斂批次憑證-" + tc.name
			}
			batch, assetIDs, err := f.batches.Create(req, 1, "admin")
			require.NoError(t, err)
			require.Len(t, assetIDs, 2)

			records := f.runner.RunBatch(batch, assetIDs)
			require.Len(t, records, 2)
			for _, r := range records {
				assert.Equal(t, model.ChangeSecretSkipped, r.Status,
					"未收斂憑證的掛載只能被略過")
				assert.Equal(t, model.ChangeSecretReasonSharedCredentialTargetRequired, r.Error)
			}
			_, rotateAfter, _ := rec.snapshotCalls()
			for _, host := range []string{"10.6.3.1", "10.6.3.2"} {
				assert.Equal(t, rotateBefore[host], rotateAfter[host],
					"遠端不得被再次下達（%s）", host)
			}

			// 憑證仍停在未同步，且沒有多開任何版本
			state, err := f.rotations.AggregateState(credID)
			require.NoError(t, err)
			assert.Equal(t, CredentialAggregateOutOfSync, state)
			assert.EqualValues(t, 2, f.versionCountOf(t, credID),
				"略過的批次不得在未收斂的憑證上再追加版本")
		})
	}
}
