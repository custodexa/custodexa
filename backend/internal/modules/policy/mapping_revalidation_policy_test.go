package policy

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

type relaxAlertRecorder struct {
	events []HighRiskAlert
	fail   bool
}

func (r *relaxAlertRecorder) RaiseHighRiskInTx(_ *gorm.DB, ev HighRiskAlert) error {
	if r.fail {
		return errors.New("注入的告警寫入失敗")
	}
	r.events = append(r.events, ev)
	return nil
}

// TestMappingRevalidationPolicyKey 映射重新驗證時限政策鍵的值域、預設與放寬告警。
func TestMappingRevalidationPolicyKey(t *testing.T) {
	const key = PolicyMappingRevalidationHours

	t.Run("未設定時讀值 12；定義為小時、0＝不設限、上限 168", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		if got := svc.GetInt(key); got != 12 {
			t.Fatalf("預設 = %d, want 12", got)
		}
		def := findDef(key)
		if def == nil || !def.ZeroDisables || def.Max != 168 || def.Unit != "小時" {
			t.Fatalf("定義不符: %+v", def)
		}
	})

	t.Run("0、1、168 各儲存成功並各在交易內留一筆舊值到新值的審計；169 與 -1 連同另一合法鍵整批拒絕且不留審計", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		svc.SetHighRiskAlertRaiser(&relaxAlertRecorder{})
		var audited []PolicyChange
		auditor := func(_ *gorm.DB, ch PolicyChange) error {
			audited = append(audited, ch)
			return nil
		}
		prev := "12"
		for _, v := range []string{"0", "1", "168"} {
			before := len(audited)
			changes, err := svc.UpdateBatchAudited(map[string]string{key: v}, PolicyActor{ID: 1, Name: "root"}, auditor)
			if err != nil {
				t.Fatalf("存 %s: %v", v, err)
			}
			if len(changes) != 1 || changes[0].OldValue != prev || changes[0].NewValue != v {
				t.Fatalf("變更 %+v，want %s→%s", changes, prev, v)
			}
			got := audited[before:]
			if len(got) != 1 || got[0].Key != key || got[0].OldValue != prev || got[0].NewValue != v {
				t.Fatalf("存 %s 的審計 %+v，want 恰一筆 %s→%s", v, got, prev, v)
			}
			prev = v
		}
		auditedBeforeReject := len(audited)
		lockBefore := svc.GetInt(PolicyLockoutMaxAttempts)
		for _, bad := range []string{"169", "-1"} {
			if _, err := svc.UpdateBatchAudited(map[string]string{key: bad, PolicyLockoutMaxAttempts: "7"}, PolicyActor{ID: 1, Name: "root"}, auditor); err == nil {
				t.Fatalf("%s 應整批拒絕", bad)
			}
			if got := svc.GetInt(key); got != 168 {
				t.Fatalf("拒絕後本鍵 = %d, want 168", got)
			}
			if got := svc.GetInt(PolicyLockoutMaxAttempts); got != lockBefore {
				t.Fatalf("拒絕後另一鍵 = %d, want %d", got, lockBefore)
			}
		}
		if len(audited) != auditedBeforeReject {
			t.Fatalf("整批拒絕後多了 %d 筆審計，want 0", len(audited)-auditedBeforeReject)
		}
	})

	t.Run("放寬產生告警並帶前後時數，調短與由 0 改非 0 只有審計", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		rec := &relaxAlertRecorder{}
		svc.SetHighRiskAlertRaiser(rec)
		steps := []struct {
			to    string
			alert bool
		}{{"24", true}, {"6", false}, {"0", true}, {"12", false}, {"12", false}}
		for _, s := range steps {
			before := len(rec.events)
			if _, err := svc.UpdateBatch(map[string]string{key: s.to}, "root"); err != nil {
				t.Fatalf("→%s: %v", s.to, err)
			}
			got := len(rec.events) - before
			if s.alert && got != 1 || !s.alert && got != 0 {
				t.Fatalf("→%s 告警 %d 筆，want alert=%v", s.to, got, s.alert)
			}
		}
		first := rec.events[0]
		if first.Key != PolicyMappingRevalidationHours || first.Type != HighRiskMappingRevalidationRelax ||
			first.Params["hours_before"] != "12" || first.Params["hours_after"] != "24" || first.ActorName != "root" {
			t.Fatalf("事件不符: %+v", first)
		}
		if rec.events[1].Params["hours_before"] != "6" || rec.events[1].Params["hours_after"] != "0" {
			t.Fatalf("改 0 事件參數不符: %+v", rec.events[1])
		}
	})

	t.Run("告警寫入失敗或落地面缺注入時鍵維持原值", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		rec := &relaxAlertRecorder{fail: true}
		svc.SetHighRiskAlertRaiser(rec)
		if _, err := svc.UpdateBatch(map[string]string{key: "24"}, "root"); err == nil {
			t.Fatal("告警失敗時放寬應回錯")
		}
		if got := svc.GetInt(key); got != 12 {
			t.Fatalf("失敗後 = %d, want 12", got)
		}
		// 同批另一個鍵也不得寫入
		if _, err := svc.UpdateBatch(map[string]string{key: "24", PolicyLockoutMaxAttempts: "7"}, "root"); err == nil {
			t.Fatal("同批放寬在告警失敗時應整批回錯")
		}
		if got := svc.GetInt(PolicyLockoutMaxAttempts); got == 7 {
			t.Fatal("同批另一鍵不應被寫入")
		}
		// 缺注入
		_, bareDB := setupPolicyDB(t)
		bare := NewSecurityPolicyService(bareDB)
		if err := bare.HighRiskAlertSinkReady(); !errors.Is(err, ErrHighRiskAlertSinkMissing) {
			t.Fatalf("缺注入自檢 = %v", err)
		}
		if _, err := bare.UpdateBatch(map[string]string{key: "24"}, "root"); !errors.Is(err, ErrHighRiskAlertSinkMissing) {
			t.Fatalf("缺注入放寬應回 ErrHighRiskAlertSinkMissing: %v", err)
		}
		// 不放寬的寫入不需要落地面
		if _, err := bare.UpdateBatch(map[string]string{key: "6"}, "root"); err != nil {
			t.Fatalf("調短不應需要落地面: %v", err)
		}
	})
	// 兩個並行寫入若讀到同一個舊值，各自都判為「沒放寬」，落地的 6→10 卻是放寬而沒有告警。
	// 含本鍵的批次須先取交易級鎖再讀舊值，後寫者以前寫者的新值為舊值判定。
	t.Run("並行寫入：後寫者以前寫者的新值為舊值判定放寬（PostgreSQL）", func(t *testing.T) {
		db := openPolicyPG(t, fmt.Sprintf("policy_reval_%d", time.Now().UnixNano()))
		svc := NewSecurityPolicyService(db)
		rec := &relaxAlertRecorder{}
		svc.SetHighRiskAlertRaiser(rec)
		if err := db.Create(&model.SecurityPolicy{Key: key, Value: "12", UpdatedBy: "init", UpdatedAt: time.Now()}).Error; err != nil {
			t.Fatal(err)
		}
		var arrived sync.WaitGroup
		arrived.Add(2)
		goFirst, goSecond := make(chan struct{}), make(chan struct{})
		firstLocked, releaseFirst := make(chan struct{}), make(chan struct{})
		policyHistoryHooks.beforeLock = func(by string) {
			arrived.Done()
			if by == "first" {
				<-goFirst
			} else {
				<-goSecond
			}
		}
		policyHistoryHooks.afterLock = func(by string) {
			if by == "first" {
				close(firstLocked)
				<-releaseFirst
			}
		}
		t.Cleanup(func() { policyHistoryHooks.beforeLock, policyHistoryHooks.afterLock = nil, nil })

		errs := make(chan error, 2)
		for by, v := range map[string]string{"first": "6", "second": "10"} {
			by, v := by, v
			go func() {
				_, err := svc.UpdateBatch(map[string]string{key: v}, by)
				errs <- err
			}()
		}
		allArrived := make(chan struct{})
		go func() { arrived.Wait(); close(allArrived) }()
		select {
		case <-allArrived:
		case <-time.After(10 * time.Second):
			// 含本鍵的批次沒有走取鎖流程時，同步點永遠不會觸發
			t.Fatal("寫入沒有走政策寫入鎖流程：含本鍵的批次未先取交易級鎖")
		}
		close(goFirst)
		<-firstLocked
		close(goSecond)
		deadline := time.Now().Add(10 * time.Second)
		for waitingOnHistoryLock(t, db) < 1 {
			if time.Now().After(deadline) {
				t.Fatal("後行者未在等政策寫入鎖：含本鍵的批次沒有被序列化")
			}
			time.Sleep(10 * time.Millisecond)
		}
		close(releaseFirst)
		for i := 0; i < 2; i++ {
			if err := <-errs; err != nil {
				t.Fatalf("寫入失敗: %v", err)
			}
		}
		if len(rec.events) != 1 || rec.events[0].Params["hours_before"] != "6" || rec.events[0].Params["hours_after"] != "10" || rec.events[0].ActorName != "second" {
			t.Fatalf("告警 = %+v，want 一筆 6→10（後寫者）", rec.events)
		}
		var cur model.SecurityPolicy
		db.Where("key = ?", key).First(&cur)
		if cur.Value != "10" {
			t.Fatalf("現值 = %q, want 10", cur.Value)
		}
	})
}
