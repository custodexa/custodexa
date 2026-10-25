package asset

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 逐台補跑把最終失敗或已收束的成員重新排入：判定與寫入在同一把帳號鎖、同一交易內；
// 重排的操作者與授權版本與狀態一起落列，之後每次派送（含背景接手）都重驗重排者。

// requeueFixture 一輪進行中的輪替，其中一台已收為最終失敗。
type requeueFixture struct {
	*batchFixture
	rec       *secretRecorder
	rot       *model.CredentialRotation
	memberID  uint
	accountID uint
}

func newRequeueFixture(t *testing.T, hosts ...string) *requeueFixture {
	t.Helper()
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "補跑重排", "ops", "old", hosts...)
	rec := newSecretRecorder()
	last := hosts[len(hosts)-1]
	rec.rotateErr[last] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
	f.rotations.executors = func(string) rotationExecutor { return rec }
	rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
	members, err := f.rotations.Members(rot.ID)
	require.NoError(t, err)
	var failed uint
	for _, m := range members {
		if m.AccountID == accounts[len(accounts)-1] {
			failed = m.ID
		}
	}
	require.NotZero(t, failed)
	// 夾具：該台已收為最終失敗（遠端確定未變更），只剩逐台補跑重新排入這條出口
	require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", failed).
		Update("state", model.CredentialMemberTerminalFailed).Error)
	rec.rotateErr[last] = nil
	return &requeueFixture{batchFixture: f, rec: rec, rot: rot, memberID: failed, accountID: accounts[len(accounts)-1]}
}

func (f *requeueFixture) member(t *testing.T) model.CredentialRotationMember {
	t.Helper()
	var m model.CredentialRotationMember
	require.NoError(t, f.db.Where("id = ?", f.memberID).First(&m).Error)
	return m
}

// askSignalAuthorizer 第一次對指定使用者判定時關閉 asked；可隨時切成拒絕該使用者。
type askSignalAuthorizer struct {
	inner  *fakeCredentialAuthorizer
	user   uint
	asked  chan struct{}
	once   sync.Once
	mu     sync.Mutex
	denied bool
}

func (a *askSignalAuthorizer) AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
	actor CredentialManagementActor, req CredentialManagementRequest) (CredentialManagementDecision, error) {
	if actor.UserID == a.user {
		a.once.Do(func() { close(a.asked) })
		a.mu.Lock()
		denied := a.denied
		a.mu.Unlock()
		if denied {
			return CredentialManagementDecision{Missing: req.Capabilities[0]}, nil
		}
	}
	return a.inner.AuthorizeCredentialManagement(ctx, db, actor, req)
}

func (a *askSignalAuthorizer) RestoreGeneration(db *gorm.DB) (string, error) {
	return a.inner.RestoreGeneration(db)
}

func (a *askSignalAuthorizer) revoke() {
	a.mu.Lock()
	a.denied = true
	a.mu.Unlock()
}

// 驗權通過 → 等帳號鎖 → 等鎖期間被撤權 → 取得鎖：重排必須以取得鎖之後的判定為準而拒絕，
// 成員不得變成 queued。判定若在等鎖之前就做完，撤權後仍會重新排入。
func TestRunMemberRequeueDecidesInsideAccountLock(t *testing.T) {
	f := newRequeueFixture(t, "10.9.9.31", "10.9.9.32")
	sig := &askSignalAuthorizer{inner: f.authz, user: 9, asked: make(chan struct{})}
	f.rotations.mgmt = credentialManagementGate{authorizer: sig}
	_, before, _ := f.rec.snapshotCalls()

	// 另一條路徑持有該帳號的互斥鎖：補跑必須在鎖上等
	release := lockRotationAccount(f.accountID)
	done := make(chan error, 1)
	go func() { done <- f.rotations.RunMember(userCtx(9, "clicker"), f.rot.ID, f.memberID) }()

	select {
	case <-sig.asked:
		// 判定發生在取得鎖之前（缺陷形態）：之後的撤權對這次重排無效
	case <-time.After(300 * time.Millisecond):
		// 正確形態：持鎖期間沒有任何判定
	}
	select {
	case err := <-done:
		t.Fatalf("補跑不應在帳號鎖釋放前完成: %v", err)
	default:
	}
	sig.revoke()
	release()

	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrCredentialBindForbidden, "取得鎖後以當下能力判定：已撤權即拒")
	case <-time.After(5 * time.Second):
		t.Fatal("補跑未在釋放鎖後返回")
	}
	m := f.member(t)
	assert.Equal(t, model.CredentialMemberTerminalFailed, m.State, "拒絕時成員狀態不得改成 queued")
	assert.Zero(t, m.RequeuedBy, "拒絕時不留重排紀錄")
	_, after, _ := f.rec.snapshotCalls()
	assert.Equal(t, before, after, "遠端零觸碰")
}

// 重排成功之後、手動派送取得鎖之前，背景先搶到鎖：背景只沿本輪發起者的脈絡，
// 必須另驗重排者當下的能力——重排者已失權即停止，不得以仍具權的發起者脈絡派送。
func TestBackgroundRevalidatesRequeuerBeforeDelivery(t *testing.T) {
	f := newRequeueFixture(t, "10.9.9.41", "10.9.9.42")
	deny := &perUserAuthorizer{inner: f.authz}
	f.rotations.mgmt = credentialManagementGate{authorizer: deny}
	_, before, _ := f.rec.snapshotCalls()

	// 具權點擊者重排（只做重排這一步，不派送）
	require.NoError(t, f.rotations.requeueMember(userCtx(9, "clicker"), f.rot, f.memberID))
	m := f.member(t)
	require.Equal(t, model.CredentialMemberQueued, m.State)
	assert.Equal(t, uint(9), m.RequeuedBy, "重排者與狀態一起落列")
	assert.Equal(t, int64(1), m.RequeuedAuthzVersion, "記下重排當下通過的權限世代")
	require.NotNil(t, m.RequeuedAt)

	// 重排者失權；本輪發起者（7）仍具權
	deny.denyUser = 9
	advanced, err := f.rotations.AdvanceMemberInBackground(context.Background(), f.rot.ID, f.memberID)
	require.NoError(t, err)
	assert.True(t, advanced, "背景確實接手了這個成員")
	m = f.member(t)
	assert.Equal(t, model.CredentialMemberAbandoned, m.State, "重排者已失權：成員停止，不派送")
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, m.LastError)
	_, after, _ := f.rec.snapshotCalls()
	assert.Equal(t, before, after, "遠端零觸碰")

	// 對照：重排者仍具權時，背景以發起者與重排者雙重重驗通過後派送
	g := newRequeueFixture(t, "10.9.9.43", "10.9.9.44")
	require.NoError(t, g.rotations.requeueMember(userCtx(9, "clicker"), g.rot, g.memberID))
	advanced, err = g.rotations.AdvanceMemberInBackground(context.Background(), g.rot.ID, g.memberID)
	require.NoError(t, err)
	assert.True(t, advanced)
	assert.Equal(t, model.CredentialMemberApplied, g.member(t).State)
}

// 重排者與發起者是同一人時只驗一次；手動派送的點擊者另與重排者不同時三方都要通過。
func TestRequeuerRevalidationCoversManualDispatch(t *testing.T) {
	f := newRequeueFixture(t, "10.9.9.51", "10.9.9.52")
	deny := &perUserAuthorizer{inner: f.authz}
	f.rotations.mgmt = credentialManagementGate{authorizer: deny}
	require.NoError(t, f.rotations.requeueMember(userCtx(9, "clicker"), f.rot, f.memberID))
	deny.denyUser = 9
	_, before, _ := f.rec.snapshotCalls()
	// 另一位具權者手動派送：重排者已失權，派送同樣停止
	require.NoError(t, f.rotations.RunMember(userCtx(7, "owner"), f.rot.ID, f.memberID))
	m := f.member(t)
	assert.Equal(t, model.CredentialMemberAbandoned, m.State)
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, m.LastError)
	_, after, _ := f.rec.snapshotCalls()
	assert.Equal(t, before, after, "遠端零觸碰")
}
