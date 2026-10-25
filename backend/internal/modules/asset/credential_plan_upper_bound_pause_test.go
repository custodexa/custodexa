package asset

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 憑證目標計畫的掛載上界暫停：範圍化發起者（只經節點範圍持有憑證改密）的計畫，當下掛載的範圍外部分
// 不是該版掛載上界的子集時，在任何候選建立前整次停止並轉待重新確認；範圍內新增的掛載照常執行。
// 經全系統來源持有憑證改密者可承接或手動執行一次。判定替身與正式轉接頭同口徑（不帶目標只認全系統來源）。

const pbGlobalUser uint = 21

type pbFixture struct {
	*rtFixture
	notifier *audit.AlertNotifier
	credID   uint
	// hosts 主機位址 → 資產；mounts 依建立順序的掛載
	hosts  map[string]uint
	mounts []uint
	tt     *testing.T
}

// newPbFixture 共用憑證歸屬範圍內節點，掛 inHosts（放範圍內）與 outHosts（放範圍外）各一個掛載。
func newPbFixture(t *testing.T, inHosts, outHosts []string) *pbFixture {
	t.Helper()
	g := newRtFixture(t)
	g.az.targetlessGlobalOnly = true
	g.az.grant(CredCapRotate, g.in)
	g.runner.WithAuditSink(audit.NewTxSink())
	p := &pbFixture{rtFixture: g, notifier: audit.NewAlertNotifier(g.db, nil), hosts: map[string]uint{}, tt: t}
	g.runner.notifier = p.notifier
	g.plans.WithAuthorizer(g.az)
	all := append(append([]string{}, inHosts...), outHosts...)
	credID, accounts := g.sharedOn(t, fmt.Sprintf("pb-cred-%d", len(all)), "ops", "old-shared", all...)
	require.NoError(t, g.db.Model(&model.Credential{}).Where("id = ?", credID).
		Updates(map[string]any{"owner_kind": model.CredentialOwnerNode, "owner_node_id": g.in}).Error)
	p.credID = credID
	for i, acc := range accounts {
		b := g.bindingOf(t, acc)
		p.hosts[all[i]] = b.AssetID
		node := g.out
		if i < len(inHosts) {
			node = g.in
		}
		g.place(t, b.AssetID, node)
		p.mounts = append(p.mounts, acc)
	}
	return p
}

// plan 以 initiator 建立憑證目標計畫；bound 非 nil 時把該版掛載上界寫成這些掛載（同儲存交易寫入的形狀）。
func (p *pbFixture) plan(t *testing.T, initiator uint, bound []uint) *model.ChangeSecretPlan {
	t.Helper()
	req := planRequest("pb-plan", []uint{p.bindingOf(t, p.mounts[0]).AssetID}, "ops")
	req.TargetKind = model.PlanTargetCredential
	req.TargetCredentialID = p.credID
	plan, err := p.plans.Create(userCtx(initiator, fmt.Sprintf("user-%d", initiator)), req)
	require.NoError(t, err)
	if bound != nil {
		p.setBound(t, plan, bound)
	}
	return p.reload(t, plan.ID)
}

func (p *pbFixture) setBound(t *testing.T, plan *model.ChangeSecretPlan, bound []uint) {
	t.Helper()
	raw, err := json.Marshal(bound)
	require.NoError(t, err)
	require.NoError(t, p.db.Model(&model.CredentialJobAuthorization{}).Where("id = ?", *plan.AuthorizationID).
		Update("target_mount_bound", string(raw)).Error)
}

func (p *pbFixture) reload(t *testing.T, id uint) *model.ChangeSecretPlan {
	t.Helper()
	got, err := p.plans.Get(id)
	require.NoError(t, err)
	return got
}

// mount 再掛一台（node 為放置節點）
func (p *pbFixture) mount(t *testing.T, host string, node uint) uint {
	t.Helper()
	a := newSSHAsset(t, p.assets, host, host)
	b, err := p.creds.Bind(adminCtx(), p.credID, &BindCredentialRequest{AssetID: a.ID})
	require.NoError(t, err)
	p.place(t, a.ID, node)
	p.hosts[host] = a.ID
	p.mounts = append(p.mounts, b.ID)
	return b.ID
}

// secondAccount 在既有資產上以同一憑證另掛一個帳號
func (p *pbFixture) secondAccount(t *testing.T, host string) uint {
	t.Helper()
	var src model.AssetAccount
	require.NoError(t, p.db.Where("asset_id = ? AND credential_id = ?", p.hosts[host], p.credID).First(&src).Error)
	// 共用憑證的掛載沿用憑證的登入帳號；另一列＝同一資產上的另一個掛載
	acc := src
	acc.ID, acc.IsDefault = 0, false
	require.NoError(t, p.db.Create(&acc).Error)
	p.mounts = append(p.mounts, acc.ID)
	return acc.ID
}

func (p *pbFixture) rows(t *testing.T, m any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, p.db.Model(m).Count(&n).Error)
	return n
}

func (p *pbFixture) remoteCalls() int {
	_, rc, vc := p.rec.snapshotCalls()
	n := 0
	for _, c := range rc {
		n += c
	}
	for _, c := range vc {
		n += c
	}
	return n
}

func (p *pbFixture) boundStopAudits(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, p.db.Model(&model.AuditLog{}).
		Where("details LIKE ? AND details LIKE ?", "%authorization_stop%", "%"+model.ChangeSecretReasonScopeBoundExceeded+"%").
		Count(&n).Error)
	return n
}

// snapshot 候選、輪替、成員表筆數與遠端呼叫數
type pbCounts struct{ candidates, rotations, members int64 }

func (p *pbFixture) counts(t *testing.T) pbCounts {
	return pbCounts{p.rows(t, &model.ChangeSecretCandidate{}), p.rows(t, &model.CredentialRotation{}),
		p.rows(t, &model.CredentialRotationMember{})}
}

// requireRanAll 一次執行涵蓋 want 個掛載，各一筆成功記錄
func requireRanAll(t *testing.T, records []model.ChangeSecretRecord, want int) {
	t.Helper()
	require.Len(t, records, want)
	seen := map[uint]bool{}
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, r.Error)
		seen[r.AccountID] = true
	}
	assert.Len(t, seen, want, "每個掛載各一筆")
}

func TestCredentialPlanUpperBoundPause(t *testing.T) {
	in, out := []string{"10.61.0.1"}, []string{"10.61.0.2", "10.61.0.3"}

	t.Run("out_of_scope_mount_added_pauses_both_paths", func(t *testing.T) {
		p := newPbFixture(t, in, out)
		plan := p.plan(t, rtScopedUser, p.mounts[:3])
		p.mount(t, "10.61.0.4", p.out)
		before, calls, alerts := p.counts(t), p.remoteCalls(), p.notifier.PendingNotifications()

		assert.Empty(t, p.runner.RunPlan(plan), "排程：任何候選建立前停止")
		assert.Equal(t, before, p.counts(t))
		assert.Equal(t, calls, p.remoteCalls(), "遠端零觸碰")
		plan = p.reload(t, plan.ID)
		assert.Equal(t, model.PlanAuthNeedsReconfirmation, plan.AuthorizationState)
		assert.EqualValues(t, 1, p.boundStopAudits(t))
		assert.Equal(t, alerts+1, p.notifier.PendingNotifications(), "沿既有停止告警通道，轉入當下一次")

		// 之後的排程時點不執行、不再告警與留痕
		assert.Empty(t, p.runner.RunPlan(plan))
		// 範圍化點擊者手動執行同樣停止
		assert.Empty(t, p.runner.RunPlanAs(userCtx(rtScopedUser, "scoped"), plan))
		assert.Equal(t, before, p.counts(t))
		assert.Equal(t, calls, p.remoteCalls())
		assert.EqualValues(t, 1, p.boundStopAudits(t))
		assert.Equal(t, alerts+1, p.notifier.PendingNotifications())

		// 範圍化點擊者一鍵重新授權：列在 skipped、狀態不變
		done, skipped, err := p.plans.ReauthorizePending(userCtx(rtScopedUser, "scoped"))
		require.NoError(t, err)
		assert.Empty(t, done)
		assert.Equal(t, []uint{plan.ID}, skipped)
		assert.Equal(t, model.PlanAuthNeedsReconfirmation, p.reload(t, plan.ID).AuthorizationState)

		// 全系統持有憑證改密者承接：成為新發起者、狀態回正常，下一次排程涵蓋當下全部掛載且不比對上界
		done, skipped, err = p.plans.ReauthorizePending(userCtx(pbGlobalUser, "global"))
		require.NoError(t, err)
		assert.Equal(t, []uint{plan.ID}, done)
		assert.Empty(t, skipped)
		plan = p.reload(t, plan.ID)
		assert.Empty(t, plan.AuthorizationState)
		assert.Equal(t, pbGlobalUser, p.authRow(t, plan.AuthorizationID).ActorID)
		assert.Empty(t, p.authRow(t, plan.AuthorizationID).TargetMountBound, "全系統發起者不寫掛載上界")
		var adopted int64
		require.NoError(t, p.db.Model(&model.AuditLog{}).Where("details LIKE ? AND details LIKE ?",
			"%\"operation\":\"reauthorize\"%", "%\"outcome\":\"reauthorized\"%").Count(&adopted).Error)
		assert.EqualValues(t, 1, adopted, "承接審計與待重新授權的承接同一則形狀")
		requireRanAll(t, p.runner.RunPlan(plan), 4)
		assert.EqualValues(t, 1, p.boundStopAudits(t))
	})

	t.Run("manual_run_first_pauses", func(t *testing.T) {
		p := newPbFixture(t, in, out)
		plan := p.plan(t, rtScopedUser, p.mounts[:3])
		p.mount(t, "10.61.0.4", p.out)
		before, calls := p.counts(t), p.remoteCalls()
		assert.Empty(t, p.runner.RunPlanAs(userCtx(rtScopedUser, "scoped"), plan), "手動執行：任何候選建立前停止")
		assert.Equal(t, before, p.counts(t))
		assert.Equal(t, calls, p.remoteCalls())
		assert.Equal(t, model.PlanAuthNeedsReconfirmation, p.reload(t, plan.ID).AuthorizationState)
		assert.EqualValues(t, 1, p.boundStopAudits(t))
	})

	t.Run("global_manual_run_once_keeps_paused", func(t *testing.T) {
		p := newPbFixture(t, in, out)
		plan := p.plan(t, rtScopedUser, p.mounts[:3])
		p.mount(t, "10.61.0.4", p.out)
		assert.Empty(t, p.runner.RunPlan(plan))
		plan = p.reload(t, plan.ID)
		requireRanAll(t, p.runner.RunPlanAs(userCtx(pbGlobalUser, "global"), plan), 4)
		plan = p.reload(t, plan.ID)
		assert.Equal(t, model.PlanAuthNeedsReconfirmation, plan.AuthorizationState, "手動執行一次不解除暫停")
		calls := p.remoteCalls()
		assert.Empty(t, p.runner.RunPlan(plan), "其後排程時點不執行")
		assert.Equal(t, calls, p.remoteCalls())
	})

	t.Run("reconfirmed_save_resumes", func(t *testing.T) {
		p := newPbFixture(t, in, out)
		plan := p.plan(t, rtScopedUser, p.mounts[:3])
		p.mount(t, "10.61.0.4", p.out)
		assert.Empty(t, p.runner.RunPlan(plan))
		// 重新儲存：新增一版脈絡並解除待重新確認（範圍化儲存交易寫入的上界＝當下全部掛載）
		req := planRequest("pb-plan", []uint{p.hosts["10.61.0.1"]}, "ops")
		req.TargetKind, req.TargetCredentialID = model.PlanTargetCredential, p.credID
		saved, err := p.plans.Update(userCtx(rtScopedUser, "scoped"), plan.ID, req)
		require.NoError(t, err)
		assert.Empty(t, saved.AuthorizationState)
		p.setBound(t, saved, p.mounts)
		requireRanAll(t, p.runner.RunPlan(p.reload(t, plan.ID)), 4)
	})

	t.Run("second_account_on_bounded_out_asset_pauses", func(t *testing.T) {
		p := newPbFixture(t, in, out)
		plan := p.plan(t, rtScopedUser, p.mounts[:3])
		p.secondAccount(t, "10.61.0.2")
		calls := p.remoteCalls()
		assert.Empty(t, p.runner.RunPlan(plan))
		assert.Equal(t, calls, p.remoteCalls())
		assert.Equal(t, model.PlanAuthNeedsReconfirmation, p.reload(t, plan.ID).AuthorizationState)
	})

	t.Run("in_scope_growth_runs", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			grow func(p *pbFixture)
		}{
			{"new_in_scope_asset", func(p *pbFixture) { p.mount(p.tt, "10.61.0.5", p.in) }},
			{"second_account_on_in_scope_asset", func(p *pbFixture) { p.secondAccount(p.tt, "10.61.0.1") }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				p := newPbFixture(t, in, out)
				plan := p.plan(t, rtScopedUser, p.mounts[:3])
				tc.grow(p)
				alerts := p.notifier.PendingNotifications()
				requireRanAll(t, p.runner.RunPlan(plan), 4)
				assert.Empty(t, p.reload(t, plan.ID).AuthorizationState)
				assert.Zero(t, p.boundStopAudits(t))
				assert.Equal(t, alerts, p.notifier.PendingNotifications())
			})
		}
	})

	// 暫停生效前取得的計畫快照（狀態仍為正常）在暫停後、超界掛載移除後才送進執行：起始交易重讀計畫當下狀態，
	// 不建立輪替與成員、遠端零呼叫、計畫維持待重新確認
	t.Run("stale_snapshot_after_pause_rejected", func(t *testing.T) {
		p := newPbFixture(t, in, out)
		plan := p.plan(t, rtScopedUser, p.mounts[:3])
		stale := *plan
		extra := p.mount(t, "10.61.0.9", p.out)
		assert.Empty(t, p.runner.RunPlan(plan))
		require.Equal(t, model.PlanAuthNeedsReconfirmation, p.reload(t, plan.ID).AuthorizationState)
		require.NoError(t, p.creds.Unbind(adminCtx(), p.credID, extra))
		before, calls := p.counts(t), p.remoteCalls()

		require.Empty(t, stale.AuthorizationState, "快照取於暫停之前")
		assert.Empty(t, p.runner.RunPlan(&stale), "排程以舊快照：起始交易讀到暫停而停止")
		assert.Empty(t, p.runner.RunPlanAs(userCtx(rtScopedUser, "scoped"), &stale), "手動以舊快照同樣停止")
		assert.Equal(t, before, p.counts(t), "輪替、成員、候選筆數不增加")
		assert.Equal(t, calls, p.remoteCalls(), "遠端零呼叫")
		assert.Equal(t, model.PlanAuthNeedsReconfirmation, p.reload(t, plan.ID).AuthorizationState, "不因當下符合上界自動解除")
	})

	t.Run("unmount_to_subset_runs", func(t *testing.T) {
		p := newPbFixture(t, in, out)
		plan := p.plan(t, rtScopedUser, p.mounts[:3])
		require.NoError(t, p.creds.Unbind(adminCtx(), p.credID, p.mounts[2]))
		requireRanAll(t, p.runner.RunPlan(plan), 2)
	})

	t.Run("scoped_without_bound_compares_empty_set", func(t *testing.T) {
		all := newPbFixture(t, []string{"10.61.1.1", "10.61.1.2"}, nil)
		requireRanAll(t, all.runner.RunPlan(all.plan(t, rtScopedUser, nil)), 2)

		one := newPbFixture(t, []string{"10.61.2.1"}, []string{"10.61.2.2"})
		plan := one.plan(t, rtScopedUser, nil)
		calls := one.remoteCalls()
		assert.Empty(t, one.runner.RunPlan(plan))
		assert.Equal(t, calls, one.remoteCalls())
		assert.Equal(t, model.PlanAuthNeedsReconfirmation, one.reload(t, plan.ID).AuthorizationState)
	})

	t.Run("global_credential_rotate_source_does_not_pause", func(t *testing.T) {
		p := newPbFixture(t, in, out)
		p.az.global = map[string]bool{CredCapRotate: true}
		p.az.grant(CredCapAccountRotate, p.in)
		plan := p.plan(t, rtScopedUser, p.mounts[:3])
		p.mount(t, "10.61.0.4", p.out)
		requireRanAll(t, p.runner.RunPlan(plan), 4)
		assert.Zero(t, p.boundStopAudits(t))
	})

	t.Run("global_initiator_runs_all_mounts", func(t *testing.T) {
		p := newPbFixture(t, in, out)
		plan := p.plan(t, pbGlobalUser, nil)
		p.mount(t, "10.61.0.4", p.out)
		requireRanAll(t, p.runner.RunPlan(plan), 4)
		assert.Empty(t, p.reload(t, plan.ID).AuthorizationState)
		assert.Zero(t, p.boundStopAudits(t))
	})

	// 範圍化點擊者手動執行全系統發起者儲存的計畫而撞上界：只拒絕這一次，不讓別人的排程停擺
	t.Run("scoped_manual_on_global_saved_plan_rejects_once", func(t *testing.T) {
		p := newPbFixture(t, in, out)
		plan := p.plan(t, pbGlobalUser, nil)
		p.mount(t, "10.61.0.4", p.out)
		before, calls := p.counts(t), p.remoteCalls()

		assert.Empty(t, p.runner.RunPlanAs(userCtx(rtScopedUser, "scoped"), plan), "任何候選建立前停止")
		assert.Equal(t, before, p.counts(t))
		assert.Equal(t, calls, p.remoteCalls(), "遠端零觸碰")
		got := p.reload(t, plan.ID)
		assert.Empty(t, got.AuthorizationState, "計畫狀態不變")
		assert.Equal(t, pbGlobalUser, p.authRow(t, got.AuthorizationID).ActorID, "發起者不變")
		assert.EqualValues(t, 1, p.boundStopAudits(t), "本次拒絕與上界拒絕同形留痕")

		// 排程照常：全系統發起者涵蓋當下全部掛載
		requireRanAll(t, p.runner.RunPlan(got), 4)
		assert.Empty(t, p.reload(t, plan.ID).AuthorizationState)
	})
}
