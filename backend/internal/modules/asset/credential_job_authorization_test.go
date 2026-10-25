package asset

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

func userCtx(id uint, name string) context.Context {
	ctx := context.WithValue(context.Background(), "userID", id) //nolint:staticcheck // 沿用既有審計 context 慣例
	return context.WithValue(ctx, "username", name)              //nolint:staticcheck
}

func (f *batchFixture) authRow(t *testing.T, id *uint) *model.CredentialJobAuthorization {
	t.Helper()
	require.NotNil(t, id, "應有授權脈絡引用")
	var row model.CredentialJobAuthorization
	require.NoError(t, f.db.Where("id = ?", *id).First(&row).Error)
	return &row
}

// lastStopReason 計畫最近一筆授權停止事件的原因碼（runner 須已接審計落地面）。
func (f *batchFixture) lastStopReason(t *testing.T, planID uint) string {
	t.Helper()
	var row model.AuditLog
	require.NoError(t, f.db.Where("resource = ? AND details LIKE ?", model.ResourceChangeSecretPlan, "%authorization_stop%").
		Order("id desc").First(&row).Error)
	var d struct {
		PlanID uint   `json:"plan_id"`
		Reason string `json:"reason"`
	}
	require.NoError(t, json.Unmarshal([]byte(row.Details), &d))
	require.Equal(t, planID, d.PlanID)
	return d.Reason
}

// flakyAuthorizer 前 failures 次判定回錯（授權庫暫時不可用），之後交給內層。
// 驗「首次判定失敗即停止，不靠之後的判定恢復放行」。
type flakyAuthorizer struct {
	inner    *fakeCredentialAuthorizer
	failures int
	calls    int
}

func (a *flakyAuthorizer) AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
	actor CredentialManagementActor, req CredentialManagementRequest) (CredentialManagementDecision, error) {
	a.calls++
	if a.calls <= a.failures {
		return CredentialManagementDecision{}, errAuthzStoreDown
	}
	return a.inner.AuthorizeCredentialManagement(ctx, db, actor, req)
}

func (a *flakyAuthorizer) RestoreGeneration(db *gorm.DB) (string, error) {
	return a.inner.RestoreGeneration(db)
}

var errAuthzStoreDown = errors.New("authorization store temporarily unavailable")

// 工作授權脈絡的保存、不可變與重啟後沿用
func TestCredentialJobAuthorizationSnapshots(t *testing.T) {
	t.Run("計畫建立與修改保存發起者與修訂，舊列不被覆寫", func(t *testing.T) {
		f := setupBatchFixture(t)
		a1, _ := f.addHost(t, "h1", "10.9.0.1", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("快照計畫", []uint{a1}, "ops"))
		require.NoError(t, err)
		first := f.authRow(t, plan.AuthorizationID)
		assert.Equal(t, uint(5), first.ActorID)
		assert.Equal(t, "creator", first.ActorName)
		assert.Equal(t, model.JobAuthSourcePlan, first.SourceKind)
		assert.Equal(t, plan.ID, first.SourceID)
		assert.Equal(t, 1, first.Revision)
		assert.Equal(t, model.JobAuthViaRequest, first.AuthSource)
		assert.EqualValues(t, 1, first.AuthzVersion, "記下判定當下的權限世代")
		assert.JSONEq(t, `["account:rotate"]`, first.Capabilities)
		assert.JSONEq(t, `[`+itoa(a1)+`]`, first.TargetBound, "建立時的目標上界只保存")

		updated, err := f.plans.Update(userCtx(6, "editor"), plan.ID, planRequest("快照計畫", []uint{a1}, "ops"))
		require.NoError(t, err)
		second := f.authRow(t, updated.AuthorizationID)
		assert.NotEqual(t, first.ID, second.ID, "保存新版計畫新增一列")
		assert.Equal(t, uint(6), second.ActorID, "新版計畫採修改者為發起者")
		assert.Equal(t, 2, second.Revision)
		again := f.authRow(t, &first.ID)
		assert.Equal(t, uint(5), again.ActorID, "舊 revision 不被覆寫")
		assert.Equal(t, 1, again.Revision)
	})

	t.Run("權限來源種類隨脈絡保存（direct／group／mapped／both）", func(t *testing.T) {
		f := setupBatchFixture(t)
		a1, _ := f.addHost(t, "h1", "10.9.0.9", "ops")
		f.authz.sources = []string{"both", "direct", "group", "mapped"}
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("來源", []uint{a1}, "ops"))
		require.NoError(t, err)
		assert.JSONEq(t, `["both","direct","group","mapped"]`, f.authRow(t, plan.AuthorizationID).PermissionSources)
		batch, _, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "batcher")
		require.NoError(t, err)
		assert.JSONEq(t, `["both","direct","group","mapped"]`, f.authRow(t, batch.AuthorizationID).PermissionSources)
	})

	t.Run("沒有伺服器端主體的計畫沒有脈絡，修改時也不被偽造", func(t *testing.T) {
		f := setupBatchFixture(t)
		a1, _ := f.addHost(t, "h1", "10.9.0.1", "ops")
		plan, err := f.plans.Create(context.Background(), planRequest("無主體", []uint{a1}, "ops"))
		require.NoError(t, err)
		assert.Nil(t, plan.AuthorizationID)
		updated, err := f.plans.Update(context.Background(), plan.ID, planRequest("無主體", []uint{a1}, "ops"))
		require.NoError(t, err)
		assert.Nil(t, updated.AuthorizationID, "空主體不補 admin、不以系統身分替代")
	})

	t.Run("client 提供的 actor、版本、授權欄位不作授權", func(t *testing.T) {
		f := setupBatchFixture(t)
		a1, _ := f.addHost(t, "h1", "10.9.0.1", "ops")
		var req ChangeSecretPlanRequest
		body := `{"name":"偽造","asset_ids":[` + itoa(a1) + `],"accounts":["ops"],` +
			`"initiator_id":999,"actor":"root","authorization_id":777,"authz_version":42,"allow":true,"revision":9}`
		require.NoError(t, json.Unmarshal([]byte(body), &req))
		plan, err := f.plans.Create(userCtx(5, "creator"), &req)
		require.NoError(t, err)
		row := f.authRow(t, plan.AuthorizationID)
		assert.Equal(t, uint(5), row.ActorID, "發起者只取伺服器端主體")
		assert.EqualValues(t, 1, row.AuthzVersion, "版本取自判定，不取請求")
		assert.NotEqual(t, uint(777), *plan.AuthorizationID)
		assert.Equal(t, 1, plan.Revision)
	})

	t.Run("手動執行不換排程發起者", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.useExecutor(newSecretRecorder())
		a1, _ := f.addHost(t, "h1", "10.9.0.1", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("手動", []uint{a1}, "ops"))
		require.NoError(t, err)
		before := *plan.AuthorizationID
		records := f.runner.RunPlanAs(userCtx(8, "clicker"), plan)
		require.Len(t, records, 1)
		got, err := f.plans.Get(plan.ID)
		require.NoError(t, err)
		assert.Equal(t, before, *got.AuthorizationID)
		assert.Equal(t, 1, got.Revision)
	})

	t.Run("手動執行另存點擊者的授權脈絡，候選帶引用，背景重試以點擊者重驗而不停下", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		rec.verifyErr["10.9.0.7"] = errRemoteDropped
		f.useExecutor(rec)
		a1, acc1 := f.addHost(t, "h1", "10.9.0.7", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("手動脈絡", []uint{a1}, "ops"))
		require.NoError(t, err)
		planAuth := *plan.AuthorizationID
		f.runner.RunPlanAs(userCtx(8, "clicker"), plan)

		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", acc1).First(&cand).Error)
		row := f.authRow(t, cand.AuthorizationID)
		assert.NotEqual(t, planAuth, row.ID, "手動執行另存一列，不沿用排程的脈絡")
		assert.Equal(t, uint(8), row.ActorID, "發起者為點擊者")
		assert.Equal(t, "clicker", row.ActorName)
		assert.Equal(t, model.JobAuthSourcePlan, row.SourceKind)
		assert.Equal(t, plan.ID, row.SourceID)
		assert.Equal(t, model.JobAuthViaManualRun, row.AuthSource)
		assert.Equal(t, plan.Revision, row.Revision, "記下執行當下的計畫修訂")
		assert.JSONEq(t, `["account:rotate"]`, row.Capabilities)
		assert.JSONEq(t, `[`+itoa(a1)+`]`, row.TargetBound)
		got, err := f.plans.Get(plan.ID)
		require.NoError(t, err)
		assert.Equal(t, planAuth, *got.AuthorizationID, "排程的發起者不變")

		rec.verifyErr["10.9.0.7"] = nil
		// 點擊者失權：背景重試以該脈絡的發起者（點擊者）當下能力重驗，判為撤權而停，不沿用存列當時的判定
		gate := f.retry.mgmt
		f.retry.mgmt = credentialManagementGate{authorizer: &perUserAuthorizer{inner: f.authz, denyUser: 8}}
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, f.retry.revalidateCandidate(context.Background(), &cand),
			"已失權點擊者的脈絡不得被沿用放行")
		f.retry.mgmt = gate
		assert.Empty(t, f.retry.revalidateCandidate(context.Background(), &cand),
			"背景重試以點擊者當下的能力重驗通過，不以缺授權脈絡停下")
		assert.True(t, f.retry.RetryOne(&cand), "背景重試可繼續收斂")
	})

	t.Run("手動執行的點擊者缺能力：不存脈絡、不建候選、遠端零觸碰（失敗關閉）", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		a1, acc1 := f.addHost(t, "h1", "10.9.0.8", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("無權手動", []uint{a1}, "ops"))
		require.NoError(t, err)
		f.runner.mgmt = credentialManagementGate{authorizer: &perUserAuthorizer{inner: f.authz, denyUser: 8}}
		f.runner.RunPlanAs(userCtx(8, "clicker"), plan)
		var n int64
		require.NoError(t, f.db.Model(&model.CredentialJobAuthorization{}).Where("actor_id = ?", 8).Count(&n).Error)
		assert.Zero(t, n, "無權點擊者名下不存授權脈絡")
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", acc1).Count(&n).Error)
		assert.Zero(t, n, "不建候選")
		_, calls, _ := rec.snapshotCalls()
		assert.Empty(t, calls, "遠端零觸碰")
	})

	t.Run("手動執行的首次授權判定失敗即停止：之後的判定恢復也不建候選、遠端零觸碰", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		a1, acc1 := f.addHost(t, "h1", "10.9.0.9", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("首次判定失敗", []uint{a1}, "ops"))
		require.NoError(t, err)
		// 第一次判定回錯（授權庫暫時不可用），之後恢復為全放行
		flaky := &flakyAuthorizer{inner: f.authz, failures: 1}
		f.runner.WithAuditSink(audit.NewTxSink()).mgmt = credentialManagementGate{authorizer: flaky}
		f.runner.RunPlanAs(userCtx(8, "clicker"), plan)

		assert.Equal(t, 1, flaky.calls, "首次判定失敗後不再問第二次：工作已停止")
		var n int64
		require.NoError(t, f.db.Model(&model.CredentialJobAuthorization{}).Where("actor_id = ?", 8).Count(&n).Error)
		assert.Zero(t, n, "判定失敗不存授權脈絡")
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", acc1).Count(&n).Error)
		assert.Zero(t, n, "不建候選（否則會是無脈絡候選）")
		_, calls, _ := rec.snapshotCalls()
		assert.Empty(t, calls, "遠端零觸碰")
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, f.lastStopReason(t, plan.ID), "停止原因＝無從判定")
	})

	t.Run("手動執行缺點擊者：以脈絡缺失停止，不建候選", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		a1, acc1 := f.addHost(t, "h1", "10.9.0.10", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("無點擊者", []uint{a1}, "ops"))
		require.NoError(t, err)
		asked := len(f.authz.asked)
		f.runner.WithAuditSink(audit.NewTxSink())
		f.runner.RunPlanAs(context.Background(), plan)
		assert.Equal(t, asked, len(f.authz.asked), "沒有主體就不問判定器")
		var n int64
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", acc1).Count(&n).Error)
		assert.Zero(t, n)
		_, calls, _ := rec.snapshotCalls()
		assert.Empty(t, calls)
		assert.Equal(t, model.ChangeSecretReasonAuthzContextMissing, f.lastStopReason(t, plan.ID))
	})

	t.Run("批次保存發起者與目標上界，候選帶授權引用", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.addHost(t, "h1", "10.9.1.1", "ops")
		_, acc2 := f.addHost(t, "h2", "10.9.1.2", "ops")
		rec := newSecretRecorder()
		rec.verifyErr["10.9.1.2"] = errRemoteDropped
		f.useExecutor(rec)
		batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "batcher")
		require.NoError(t, err)
		row := f.authRow(t, batch.AuthorizationID)
		assert.Equal(t, uint(7), row.ActorID)
		assert.Equal(t, model.JobAuthSourceBatch, row.SourceKind)
		assert.Equal(t, batch.ID, row.SourceID)
		assert.Contains(t, row.Capabilities, "account:rotate")
		var bound []uint
		require.NoError(t, json.Unmarshal([]byte(row.TargetBound), &bound))
		assert.ElementsMatch(t, assetIDs, bound)

		f.runner.RunBatch(batch, assetIDs)
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
		require.NotNil(t, cand.AuthorizationID, "候選與關聯的授權脈絡不可變地連結")
		assert.Equal(t, row.ID, *cand.AuthorizationID)
	})

	t.Run("兩個 worker 爭同一輪替步驟只送出一次", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, _ := f.sharedOn(t, "爭步驟共用", "ops", "old", "10.9.14.1", "10.9.14.2")
		rec := newSecretRecorder()
		// 第一個 worker 卡在遠端呼叫中時，其餘 worker 已經追上來：沒有互斥就會重複送出
		gate := &gatedExecutor{secretRecorder: rec, reached: make(chan struct{}), release: make(chan struct{})}
		f.rotations.executors = func(string) rotationExecutor { return gate }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		members, err := f.rotations.Members(rot.ID)
		require.NoError(t, err)
		require.NotEmpty(t, members)
		target := members[0]
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_ = f.rotations.RunMember(context.Background(), rot.ID, target.ID)
			}()
		}
		close(start)
		<-gate.reached
		time.Sleep(200 * time.Millisecond)
		close(gate.release)
		wg.Wait()
		_, calls, _ := rec.snapshotCalls()
		total := 0
		for _, n := range calls {
			total += n
		}
		assert.Equal(t, 1, total, "同一步只對遠端送出一次")
		var got model.CredentialRotationMember
		require.NoError(t, f.db.Where("id = ?", target.ID).First(&got).Error)
		assert.NotNil(t, got.DispatchClaimedAt, "claim 只落一次")
	})

	t.Run("在途工作不受下一版計畫影響", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		rec.hostKey = defaultRecorderHostKey()
		gate := &gatedExecutor{secretRecorder: rec, reached: make(chan struct{}), release: make(chan struct{})}
		f.runner.executors = func(string) rotationExecutor { return gate }
		a1, _ := f.addHost(t, "h1", "10.9.15.1", "ops")
		a2, _ := f.addHost(t, "h2", "10.9.15.2", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("在途", []uint{a1, a2}, "ops"))
		require.NoError(t, err)
		firstAuth := *plan.AuthorizationID

		done := make(chan []model.ChangeSecretRecord, 1)
		go func() { done <- f.runner.RunPlan(plan) }()
		<-gate.reached // 第一台正在遠端執行中
		// 下一版計畫：只剩 a1，且由另一位使用者保存
		_, err = f.plans.Update(userCtx(6, "editor"), plan.ID, planRequest("在途", []uint{a1}, "ops"))
		require.NoError(t, err)
		close(gate.release)
		records := <-done
		require.Len(t, records, 2, "在途工作沿原目標集合完成，不被下一版縮減")
		for _, r := range records {
			assert.Equal(t, model.ChangeSecretSuccess, r.Status, r.Error)
		}
		next, err := f.plans.Get(plan.ID)
		require.NoError(t, err)
		assert.NotEqual(t, firstAuth, *next.AuthorizationID, "下一版是另一列授權脈絡")
		assert.Equal(t, uint(5), f.authRow(t, &firstAuth).ActorID, "在途工作的發起者不變")
	})

	t.Run("未知格式與孤兒引用拒絕恢復，不補 admin", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		a1, _ := f.addHost(t, "h1", "10.9.2.1", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("損毀", []uint{a1}, "ops"))
		require.NoError(t, err)

		require.NoError(t, f.db.Model(&model.CredentialJobAuthorization{}).
			Where("id = ?", *plan.AuthorizationID).Update("schema_version", 99).Error)
		_, err = loadJobAuthorization(f.db, plan.AuthorizationID)
		require.ErrorIs(t, err, ErrJobAuthorizationUnreadable)
		assert.Empty(t, f.runner.RunPlan(plan), "未知格式不恢復")

		orphan := uint(424242)
		plan.AuthorizationID = &orphan
		_, err = loadJobAuthorization(f.db, plan.AuthorizationID)
		require.ErrorIs(t, err, ErrJobAuthorizationUnreadable)
		assert.Empty(t, f.runner.RunPlan(plan), "孤兒引用不恢復")
		_, rotateCalls, _ := rec.snapshotCalls()
		assert.Empty(t, rotateCalls, "遠端未被觸碰")
	})

	t.Run("輪替的發起者持久化，重啟後補跑沿用同一發起者", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "重啟共用", "ops", "old", "10.9.3.1", "10.9.3.2")
		rec := newSecretRecorder()
		rec.rotateErr["10.9.3.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
		f.useExecutor(rec)
		f.rotations.executors = func(string) rotationExecutor { return rec }

		rot, err := f.rotations.Start(userCtx(7, "rot-owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		row := f.authRow(t, rot.AuthorizationID)
		assert.Equal(t, uint(7), row.ActorID)
		assert.Equal(t, model.JobAuthSourceRotation, row.SourceKind)
		assert.Equal(t, rot.ID, row.SourceID)
		require.NoError(t, f.rotations.Run(userCtx(7, "rot-owner"), rot.ID))

		// 模擬重啟：以全新的服務實例、完全沒有主體的背景脈絡補跑，發起者只能來自資料庫
		fresh := NewCredentialRotationService(f.db, f.assets, f.candidates, NewHostKeyService(f.db),
			f.rotations.crypto, f.rotations.auditTx, f.authz)
		fresh.executors = func(string) rotationExecutor { return rec }
		members, err := f.rotations.Members(rot.ID)
		require.NoError(t, err)
		var failed uint
		for _, m := range members {
			if m.AccountID == accounts[1] {
				failed = m.ID
			}
		}
		require.NotZero(t, failed)
		rec.rotateErr["10.9.3.2"] = nil
		f.authz.reset()
		require.NoError(t, fresh.RunMember(context.Background(), rot.ID, failed))
		var asked bool
		for _, req := range f.authz.asked {
			asked = true
			assert.Equal(t, CredOpRun, req.Operation)
		}
		assert.True(t, asked, "補跑前以持久發起者重驗")
		var claimed model.CredentialRotationMember
		require.NoError(t, f.db.Where("id = ?", failed).First(&claimed).Error)
		require.NotNil(t, claimed.DispatchClaimedAt, "遠端步驟前先落 dispatch claim")
		assert.EqualValues(t, 1, claimed.DispatchAuthzVersion, "claim 記下放行時的權限世代")
		assert.Equal(t, 2, len(rec.rotated), "兩台都已改密，沿用同一發起者與目標")
	})
}

// 排程、批次、補跑與重試在每次遠端動作前以發起者當下的能力重驗
func TestCredentialWorkRevalidation(t *testing.T) {
	t.Run("排程：失權即停，遠端零觸碰，留記錄與審計", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		a1, _ := f.addHost(t, "h1", "10.9.4.1", "ops")
		a2, _ := f.addHost(t, "h2", "10.9.4.2", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("重驗", []uint{a1, a2}, "ops"))
		require.NoError(t, err)

		ok := f.runner.RunPlan(plan)
		require.Len(t, ok, 2)
		for _, r := range ok {
			assert.Equal(t, model.ChangeSecretSuccess, r.Status, r.Error)
		}
		_, before, _ := rec.snapshotCalls()

		f.authz.deny(CredCapAccountRotate)
		stopped := f.runner.RunPlan(plan)
		require.Len(t, stopped, 1, "第一台即停止，其後的目標不再處理")
		assert.Equal(t, model.ChangeSecretSkipped, stopped[0].Status)
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, stopped[0].Error)
		_, after, _ := rec.snapshotCalls()
		assert.Equal(t, before, after, "撤權後遠端沒有任何新的呼叫")
	})

	t.Run("排程：能力恢復後下一輪自然繼續（計畫不被永久鎖死）", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.useExecutor(newSecretRecorder())
		a1, _ := f.addHost(t, "h1", "10.9.5.1", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("恢復", []uint{a1}, "ops"))
		require.NoError(t, err)
		f.authz.deny(CredCapAccountRotate)
		require.Equal(t, model.ChangeSecretReasonAuthzRevoked, f.runner.RunPlan(plan)[0].Error)
		f.authz.allow(CredCapAccountRotate)
		f.authz.version = 9 // 權限世代已變動，但能力仍足夠：照常繼續
		got := f.runner.RunPlan(plan)
		require.Len(t, got, 1)
		assert.Equal(t, model.ChangeSecretSuccess, got[0].Status, got[0].Error)
	})

	t.Run("缺脈絡、無從判定一律 fail closed", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		a1, _ := f.addHost(t, "h1", "10.9.6.1", "ops")
		noCtx, err := f.plans.Create(context.Background(), planRequest("缺脈絡", []uint{a1}, "ops"))
		require.NoError(t, err)
		assert.Empty(t, f.runner.RunPlan(noCtx), "舊計畫沒有可指認的發起者：停")

		withCtx, err := f.plans.Create(userCtx(5, "creator"), planRequest("無從判定", []uint{a1}, "ops"))
		require.NoError(t, err)
		f.authz.err = context.DeadlineExceeded
		got := f.runner.RunPlan(withCtx)
		require.Len(t, got, 1)
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, got[0].Error)
		_, calls, _ := rec.snapshotCalls()
		assert.Empty(t, calls)
	})

	t.Run("還原世代不符：還原前留下的意圖不在還原後派送", restoreGenerationCases)

	t.Run("升級暫停的計畫不執行，重新授權後恢復", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.useExecutor(newSecretRecorder())
		a1, _ := f.addHost(t, "h1", "10.9.7.1", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("待重授權", []uint{a1}, "ops"))
		require.NoError(t, err)
		require.NoError(t, f.db.Model(&model.ChangeSecretPlan{}).Where("id = ?", plan.ID).
			Updates(map[string]any{"authorization_id": nil, "authorization_state": model.PlanAuthNeedsReauthorization}).Error)
		plan, err = f.plans.Get(plan.ID)
		require.NoError(t, err)
		assert.Empty(t, f.runner.RunPlan(plan))

		pending, err := f.plans.PendingReauthorization()
		require.NoError(t, err)
		require.Len(t, pending, 1)
		done, skipped, err := f.plans.ReauthorizePending(userCtx(1, "superadmin"))
		require.NoError(t, err)
		assert.Equal(t, []uint{plan.ID}, done)
		assert.Empty(t, skipped)
		plan, err = f.plans.Get(plan.ID)
		require.NoError(t, err)
		assert.Equal(t, "", plan.AuthorizationState)
		assert.Equal(t, model.JobAuthViaReauthorized, f.authRow(t, plan.AuthorizationID).AuthSource)
		assert.Equal(t, uint(1), f.authRow(t, plan.AuthorizationID).ActorID)
		got := f.runner.RunPlan(plan)
		require.Len(t, got, 1)
		assert.Equal(t, model.ChangeSecretSuccess, got[0].Status, got[0].Error)
	})

	t.Run("輪替補跑：失權即停且不因重新得權自行恢復", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "補跑共用", "ops", "old", "10.9.8.1", "10.9.8.2")
		rec := newSecretRecorder()
		rec.rotateErr["10.9.8.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
		f.rotations.executors = func(string) rotationExecutor { return rec }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
		members, err := f.rotations.Members(rot.ID)
		require.NoError(t, err)
		var waiting *model.CredentialRotationMember
		for i := range members {
			if members[i].AccountID == accounts[1] {
				waiting = &members[i]
			}
		}
		require.NotNil(t, waiting)
		require.Equal(t, model.CredentialMemberRetryWait, waiting.State)
		_, callsBefore, _ := rec.snapshotCalls()

		f.authz.deny(CredCapRotate)
		require.NoError(t, f.rotations.RunMember(context.Background(), rot.ID, waiting.ID))
		after, err := f.rotations.Members(rot.ID)
		require.NoError(t, err)
		for _, m := range after {
			if m.ID == waiting.ID {
				assert.Equal(t, model.CredentialMemberTerminalFailed, m.State)
				assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, m.LastError)
			}
		}
		_, callsAfter, _ := rec.snapshotCalls()
		assert.Equal(t, callsBefore, callsAfter, "撤權後遠端零新 I/O")

		// 重新得權不會讓背景自行恢復：終局失敗的成員不在到期清單內
		f.authz.allow(CredCapRotate)
		due, err := f.rotations.DueMembers(10)
		require.NoError(t, err)
		for _, d := range due {
			assert.NotEqual(t, waiting.ID, d.MemberID)
		}
	})

	t.Run("手動補跑同驗點擊者與原發起者", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "手動共用", "ops", "old", "10.9.9.1", "10.9.9.2")
		rec := newSecretRecorder()
		rec.rotateErr["10.9.9.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
		f.rotations.executors = func(string) rotationExecutor { return rec }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
		members, _ := f.rotations.Members(rot.ID)
		var id uint
		for _, m := range members {
			if m.AccountID == accounts[1] {
				id = m.ID
			}
		}
		rec.rotateErr["10.9.9.2"] = nil
		_, before, _ := rec.snapshotCalls()
		// 點擊者（另一人）無權：即使原發起者仍有權也不執行
		f.authz.reset()
		deny := &perUserAuthorizer{inner: f.authz, denyUser: 9}
		f.rotations.mgmt = credentialManagementGate{authorizer: deny}
		require.NoError(t, f.rotations.RunMember(userCtx(9, "clicker"), rot.ID, id))
		_, after, _ := rec.snapshotCalls()
		assert.Equal(t, before, after, "無權的點擊者不替有權的發起者送出變更")
	})

	t.Run("逐台補跑重新排入最終失敗的成員前先判定能力：缺輪替能力的點擊者或已失權的發起者都不改成員狀態", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "補跑關卡", "ops", "old", "10.9.9.21", "10.9.9.22")
		rec := newSecretRecorder()
		rec.rotateErr["10.9.9.22"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
		f.rotations.executors = func(string) rotationExecutor { return rec }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
		members, _ := f.rotations.Members(rot.ID)
		var failed uint
		for _, m := range members {
			if m.AccountID == accounts[1] {
				failed = m.ID
			}
		}
		require.NotZero(t, failed)
		// 夾具：該台已收為最終失敗（遠端確定未變更），只剩逐台補跑重新排入這條出口
		require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", failed).
			Update("state", model.CredentialMemberTerminalFailed).Error)
		rec.rotateErr["10.9.9.22"] = nil
		state := func() string {
			var m model.CredentialRotationMember
			require.NoError(t, f.db.Where("id = ?", failed).First(&m).Error)
			return m.State
		}
		_, before, _ := rec.snapshotCalls()

		// 點擊者缺輪替能力：寫入前被拒
		deny := &perUserAuthorizer{inner: f.authz, denyUser: 9}
		f.rotations.mgmt = credentialManagementGate{authorizer: deny}
		require.ErrorIs(t, f.rotations.RunMember(userCtx(9, "clicker"), rot.ID, failed), ErrCredentialBindForbidden)
		assert.Equal(t, model.CredentialMemberTerminalFailed, state(), "缺能力的點擊者不得重新排入")

		// 無點擊者（背景）且發起者已失權：同樣不重新排入
		f.rotations.mgmt = credentialManagementGate{authorizer: f.authz}
		f.authz.deny(CredCapRotate)
		require.Error(t, f.rotations.RunMember(context.Background(), rot.ID, failed))
		assert.Equal(t, model.CredentialMemberTerminalFailed, state(), "失權發起者的脈絡不得被沿用來重新排入")
		_, after, _ := rec.snapshotCalls()
		assert.Equal(t, before, after, "遠端零觸碰")

		// 能力恢復：具權點擊者補跑成功
		f.authz.allow(CredCapRotate)
		require.NoError(t, f.rotations.RunMember(userCtx(7, "owner"), rot.ID, failed))
		assert.Equal(t, model.CredentialMemberApplied, state())
	})

	t.Run("放棄輪替需輪替能力：缺能力者在寫入前被拒，本輪維持進行中", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, _ := f.sharedOn(t, "放棄共用", "ops", "old", "10.9.9.11", "10.9.9.12")
		rec := newSecretRecorder()
		rec.rotateErr["10.9.9.12"] = errRemoteDropped
		f.rotations.executors = func(string) rotationExecutor { return rec }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)

		f.authz.deny(CredCapRotate)
		require.ErrorIs(t, f.rotations.Abandon(userCtx(7, "owner"), rot.ID), ErrCredentialBindForbidden)
		var still model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&still).Error)
		assert.Equal(t, model.CredentialRotationRunning, still.Status, "被拒的放棄不改輪替狀態")
		var cred model.Credential
		require.NoError(t, f.db.Where("id = ?", credID).First(&cred).Error)
		require.NotNil(t, cred.ActiveRotationID)
		assert.Equal(t, rot.ID, *cred.ActiveRotationID, "被拒的放棄不清進行中識別")

		f.authz.allow(CredCapRotate)
		require.NoError(t, f.rotations.Abandon(userCtx(7, "owner"), rot.ID))
	})

	t.Run("候選重試：帶授權脈絡的候選失權不再對遠端認證", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.addHost(t, "h1", "10.9.10.1", "ops")
		_, acc2 := f.addHost(t, "h2", "10.9.10.2", "ops")
		rec := newSecretRecorder()
		rec.verifyErr["10.9.10.2"] = errRemoteDropped
		f.useExecutor(rec)
		batch, ids, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "batcher")
		require.NoError(t, err)
		f.runner.RunBatch(batch, ids)
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
		rec.verifyErr["10.9.10.2"] = nil
		// 未確認下達（無已送出證據）的候選不適用失權後的有限驗證；有限驗證另見 TestCredentialRevokedConvergence
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Update("applied", false).Error)
		cand.Applied = false
		_, _, verifyBefore := rec.snapshotCalls()

		f.authz.deny(CredCapAccountRotate)
		assert.False(t, f.retry.RetryOne(&cand))
		_, _, verifyAfter := rec.snapshotCalls()
		assert.Equal(t, verifyBefore, verifyAfter, "失權後不再以候選秘密對遠端認證")
		require.NoError(t, f.db.Where("id = ?", cand.ID).First(&cand).Error)
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, cand.LastError)

		f.authz.allow(CredCapAccountRotate)
		assert.True(t, f.retry.RetryOne(&cand), "能力恢復後同一候選可繼續收斂")
	})

	t.Run("判定器未注入：排程與重試拒絕執行並告警，不以不重驗放行", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		a1, acc1 := f.addHost(t, "h1", "10.9.11.1", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("未注入", []uint{a1}, "ops"))
		require.NoError(t, err)
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.runner.notifier = notifier
		f.retry.notifier = notifier

		f.runner.mgmt = credentialManagementGate{}
		assert.Empty(t, f.runner.RunPlan(plan), "判定器未注入：計畫不執行")
		assert.EqualValues(t, 1, notifier.PendingNotifications(), "停止走既有告警通道")
		_, calls, _ := rec.snapshotCalls()
		assert.Empty(t, calls, "遠端零觸碰")
		batch, ids, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "batcher")
		require.NoError(t, err)
		got := f.runner.RunBatch(batch, ids)
		require.NotEmpty(t, got)
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, got[0].Error)

		cand := model.ChangeSecretCandidate{AssetID: a1, AccountID: acc1, AccountUsername: "ops", PlanID: plan.ID, CreatedAt: time.Now()}
		f.retry.mgmt = credentialManagementGate{}
		before := notifier.PendingNotifications()
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, f.retry.revalidateCandidate(context.Background(), &cand))
		assert.False(t, f.retry.RetryOne(&cand))
		assert.Equal(t, before+1, notifier.PendingNotifications(), "重試拒絕同樣告警")
	})

	t.Run("升級前的舊候選：背景擋下並告警，無權者手動被擋，具權者手動通過並留痕", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.addHost(t, "h1", "10.9.12.1", "ops")
		_, acc2 := f.addHost(t, "h2", "10.9.12.2", "ops")
		rec := newSecretRecorder()
		rec.noHostKey = true // 失權的點擊者有限收斂要求主機身分綁定；本案例驗的是無權者被擋
		rec.verifyErr["10.9.12.2"] = errRemoteDropped
		f.useExecutor(rec)
		batch, ids, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "batcher")
		require.NoError(t, err)
		f.runner.RunBatch(batch, ids)
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Update("authorization_id", nil).Error)
		cand.AuthorizationID = nil
		rec.verifyErr["10.9.12.2"] = nil
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.retry.notifier = notifier
		_, _, verifyBefore := rec.snapshotCalls()

		assert.False(t, f.retry.RetryOne(&cand), "背景重試不送出")
		assert.GreaterOrEqual(t, notifier.PendingNotifications(), int64(1), "背景被擋要告警")
		_, _, v := rec.snapshotCalls()
		assert.Equal(t, verifyBefore, v, "遠端零觸碰")
		var kept model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("id = ?", cand.ID).First(&kept).Error)
		assert.Equal(t, model.ChangeSecretReasonAuthzContextMissing, kept.LastError, "候選保留並記原因")

		f.retry.mgmt = credentialManagementGate{authorizer: &perUserAuthorizer{inner: f.authz, denyUser: 9}}
		assert.False(t, f.retry.RetryOneAs(userCtx(9, "nopower"), &kept), "無權者手動重試被擋")
		_, _, v = rec.snapshotCalls()
		assert.Equal(t, verifyBefore, v)

		// 具權者的轉正要求候選有主機身分綁定：經正式回呼補上
		kept = *bindCandidateViaCallback(t, f.db, f.runner.hostKeys, kept.ID, defaultRecorderHostKey())
		assert.True(t, f.retry.RetryOneAs(userCtx(8, "operator"), &kept), "具權者手動重試通過")
		var promoted model.ChangeSecretCandidate
		err = f.db.Where("id = ?", cand.ID).First(&promoted).Error
		if err == nil {
			require.NotNil(t, promoted.AuthorizationID)
		}
		var row model.CredentialJobAuthorization
		require.NoError(t, f.db.Where("auth_source = ?", model.JobAuthViaManualCandidate).First(&row).Error)
		assert.Equal(t, uint(8), row.ActorID, "該次授權記在點擊者名下")
	})

	t.Run("重新授權承接：點擊者能力不足的計畫維持暫停並列出，其餘照常承接並留審計", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.useExecutor(newSecretRecorder())
		sink := audit.NewTxSink()
		f.plans.WithAuditSink(sink)
		a1, _ := f.addHost(t, "h1", "10.9.13.1", "ops")
		a2, _ := f.addHost(t, "h2", "10.9.13.2", "ops")
		var planIDs []uint
		for i, a := range []uint{a1, a2} {
			p, err := f.plans.Create(userCtx(5, "creator"), planRequest("待承接"+itoa(uint(i)), []uint{a}, "ops"))
			require.NoError(t, err)
			planIDs = append(planIDs, p.ID)
		}
		require.NoError(t, f.db.Model(&model.ChangeSecretPlan{}).Where("id IN ?", planIDs).
			Updates(map[string]any{"authorization_id": nil, "authorization_state": model.PlanAuthNeedsReauthorization}).Error)
		// 點擊者對第二個計畫的資產沒有能力
		f.plans.WithAuthorizer(assetDenyAuthorizer{inner: f.authz, denyAsset: a2})

		done, skipped, err := f.plans.ReauthorizePending(userCtx(1, "clicker"))
		require.NoError(t, err)
		assert.Equal(t, []uint{planIDs[0]}, done)
		assert.Equal(t, []uint{planIDs[1]}, skipped)
		left, err := f.plans.PendingReauthorization()
		require.NoError(t, err)
		require.Len(t, left, 1)
		assert.Equal(t, planIDs[1], left[0].ID, "被略過的維持暫停")

		f.plans.WithAuthorizer(nil)
		done, skipped, err = f.plans.ReauthorizePending(userCtx(1, "clicker"))
		require.NoError(t, err)
		assert.Empty(t, done, "判定器未注入：一律不承接")
		assert.Equal(t, []uint{planIDs[1]}, skipped)
	})
}

// perUserAuthorizer 對指定使用者一律拒絕、其餘交給內層（驗「呼叫者與發起者都要通過」）。
type perUserAuthorizer struct {
	inner    *fakeCredentialAuthorizer
	denyUser uint
}

func (p *perUserAuthorizer) AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
	actor CredentialManagementActor, req CredentialManagementRequest) (CredentialManagementDecision, error) {
	if actor.UserID == p.denyUser {
		return CredentialManagementDecision{Missing: req.Capabilities[0]}, nil
	}
	return p.inner.AuthorizeCredentialManagement(ctx, db, actor, req)
}

func (p *perUserAuthorizer) RestoreGeneration(db *gorm.DB) (string, error) {
	return p.inner.RestoreGeneration(db)
}

func itoa(n uint) string { return strconv.FormatUint(uint64(n), 10) }

// StartSplitFor 在起始交易內逐 ID 檢查來源、主體與管理能力
func TestCredentialSplitAuthorization(t *testing.T) {
	setup := func(t *testing.T) (*batchFixture, uint, []uint, *secretRecorder) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "拆分授權", "ops", "old", "10.9.20.1", "10.9.20.2", "10.9.20.3")
		rec := newSecretRecorder()
		f.rotations.executors = func(string) rotationExecutor { return rec }
		return f, credID, accounts, rec
	}
	counts := func(t *testing.T, f *batchFixture) (rotations, candidates int64) {
		require.NoError(t, f.db.Model(&model.CredentialRotation{}).Count(&rotations).Error)
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Count(&candidates).Error)
		return
	}

	t.Run("具權成功，只有選定成員被送出，其餘不動", func(t *testing.T) {
		f, credID, accounts, rec := setup(t)
		rot, err := f.rotations.StartSplitFor(userCtx(7, "owner"), credID, accounts[:2], StartRotationRequest{})
		require.NoError(t, err)
		members, err := f.rotations.Members(rot.ID)
		require.NoError(t, err)
		assert.Len(t, members, 2)
		require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
		_, calls, _ := rec.snapshotCalls()
		assert.Equal(t, map[string]int{"10.9.20.1": 1, "10.9.20.2": 1}, calls)
		assert.Equal(t, credID, f.bindingOf(t, accounts[2]).CredentialID, "未選定的掛載不動")
		row := f.authRow(t, rot.AuthorizationID)
		assert.Equal(t, uint(7), row.ActorID)
		assert.Contains(t, row.Capabilities, CredCapDetach)
	})

	t.Run("缺權、空主體、未注入判定器都拒絕且零寫入", func(t *testing.T) {
		f, credID, accounts, _ := setup(t)
		f.authz.deny(CredCapDetach)
		_, err := f.rotations.StartSplitFor(userCtx(7, "owner"), credID, accounts[:1], StartRotationRequest{})
		require.ErrorIs(t, err, ErrCredentialBindForbidden)
		f.authz.allow(CredCapDetach)
		_, err = f.rotations.StartSplitFor(context.Background(), credID, accounts[:1], StartRotationRequest{})
		require.ErrorIs(t, err, ErrCredentialBindForbidden, "空主體拒絕")
		bare := NewCredentialRotationService(f.db, f.assets, f.candidates, NewHostKeyService(f.db),
			f.rotations.crypto, f.rotations.auditTx, nil)
		_, err = bare.StartSplitFor(userCtx(7, "owner"), credID, accounts[:1], StartRotationRequest{})
		require.ErrorIs(t, err, ErrCredentialAuthzUnavailable, "未注入判定器拒絕")
		r, c := counts(t, f)
		assert.Zero(t, r)
		assert.Zero(t, c)
	})

	t.Run("混入不存在或不屬於來源的識別整筆不建立", func(t *testing.T) {
		f, credID, accounts, _ := setup(t)
		_, otherAccounts := f.sharedOn(t, "別組", "ops", "old", "10.9.21.1", "10.9.21.2")
		for name, ids := range map[string][]uint{
			"不存在":    {accounts[0], 987654},
			"屬於別的憑證": {accounts[0], otherAccounts[0]},
		} {
			_, err := f.rotations.StartSplitFor(userCtx(7, "owner"), credID, ids, StartRotationRequest{})
			require.ErrorIs(t, err, ErrCredentialRotationNoBinding, name)
		}
		r, c := counts(t, f)
		assert.Zero(t, r)
		assert.Zero(t, c)
	})

	t.Run("查驗後改綁的競態由交易重讀拒絕", func(t *testing.T) {
		f, credID, accounts, _ := setup(t)
		stale, err := f.rotations.currentBindingsForSplit(credID)
		require.NoError(t, err)
		require.NoError(t, f.creds.Unbind(adminCtx(), credID, accounts[0]))
		_, err = f.rotations.startSplitRotation(userCtx(7, "owner"), credID, stale, PasswordPolicy{}, nil, splitGateWhole(), nil, nil)
		require.ErrorIs(t, err, ErrCredentialRotationNoBinding)
		r, c := counts(t, f)
		assert.Zero(t, r)
		assert.Zero(t, c)
	})
}

// assetDenyAuthorizer 對涉及指定資產的請求拒絕、其餘交給內層（驗承接前以點擊者能力逐計畫重驗）。
type assetDenyAuthorizer struct {
	inner     *fakeCredentialAuthorizer
	denyAsset uint
}

func (a assetDenyAuthorizer) AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
	actor CredentialManagementActor, req CredentialManagementRequest) (CredentialManagementDecision, error) {
	for _, id := range req.AssetIDs {
		if id == a.denyAsset {
			return CredentialManagementDecision{Missing: req.Capabilities[0]}, nil
		}
	}
	return a.inner.AuthorizeCredentialManagement(ctx, db, actor, req)
}

// gatedExecutor 第一次 Rotate 時通知測試並等放行（驗在途工作期間外部狀態改變）。
type gatedExecutor struct {
	*secretRecorder
	once    sync.Once
	reached chan struct{}
	release chan struct{}
}

func (g *gatedExecutor) Rotate(ctx context.Context, t rotationTarget, old, newSecret []byte) error {
	g.once.Do(func() {
		close(g.reached)
		<-g.release
	})
	return g.secretRecorder.Rotate(ctx, t, old, newSecret)
}
