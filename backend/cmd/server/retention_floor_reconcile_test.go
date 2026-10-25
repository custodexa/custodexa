package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// TestRetentionFloorReconcileGatesStage2 擋：保留下限對帳排到保留讀者或保留排程之後、
// 對帳失敗卻讓段 2 繼續啟動，或對帳沒有經交易內審計落地面留痕。
//
// 觀察的是段 2 的實際執行序（appGraph 的建構序），不是清冊。
func TestRetentionFloorReconcileGatesStage2(t *testing.T) {
	t.Run("對帳失敗：段 2 回錯、保留排程與檢查點驗證讀者都沒有建立", func(t *testing.T) {
		env := newSealIntegrationEnv(t)
		if err := database.DB.Save(&model.SecurityPolicy{Key: policy.PolicyRetentionRecordingDays, Value: "3", UpdatedBy: "legacy"}).Error; err != nil {
			t.Fatal(err)
		}
		// 抬升紀錄表不存在＝對帳寫紀錄失敗（交易回滾）
		if err := database.DB.Migrator().DropTable(&model.SecurityPolicyFloorRaise{}); err != nil {
			t.Fatal(err)
		}
		kek, err := buildUIKEKProvider([]byte(testInitialKEK))
		if err != nil {
			t.Fatal(err)
		}
		g, err := runStage2(context.Background(), env.s1, kek, nil, nil)
		if err == nil {
			t.Fatal("對帳失敗時段 2 竟成功")
		}
		if !strings.Contains(err.Error(), "retentionFloorReconcile") {
			t.Fatalf("失敗未落在 retentionFloorReconcile 步驟：%v", err)
		}
		built := g.ServiceNames()
		for _, name := range []string{"retentionFloorReconcile", "recordingService", "auditIntegrity", "retentionScheduler", "checkpointScheduler", "chainVerifyScheduler"} {
			for _, b := range built {
				if b == name {
					t.Errorf("對帳失敗後 %s 不得已建立／啟動（建構序 %v）", name, built)
				}
			}
		}
		var row model.SecurityPolicy
		if err := database.DB.Where("key = ?", policy.PolicyRetentionRecordingDays).First(&row).Error; err != nil {
			t.Fatal(err)
		}
		if row.Value != "3" {
			t.Errorf("對帳回滾後錄影保留列 = %s, want 3（不帶著一半抬升的狀態）", row.Value)
		}
		var audits int64
		database.DB.Model(&model.AuditLog{}).Where("action = ?", string(model.ActionRetentionFloorRaised)).Count(&audits)
		if audits != 0 {
			t.Errorf("回滾後仍有 %d 筆抬升審計", audits)
		}
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := g.Release(rctx); err != nil {
			t.Fatalf("半建構圖收束失敗: %v", err)
		}
	})

	t.Run("對帳成功：排在保留讀者之前，讀者第一次讀到的錄影保留為 7", func(t *testing.T) {
		env := newSealIntegrationEnv(t)
		// 在正式組裝的同一個政策服務上觀測每一次讀值（含段 2 期間任何讀者）
		var svc *policy.SecurityPolicyService
		var reads []string
		stage2PolicyServiceObserver = func(p *policy.SecurityPolicyService) {
			svc = p
			p.SetReadObserver(func(key, value string) {
				if key == policy.PolicyRetentionRecordingDays {
					reads = append(reads, value)
				}
			})
		}
		t.Cleanup(func() { stage2PolicyServiceObserver = nil })
		if err := database.DB.Save(&model.SecurityPolicy{Key: policy.PolicyRetentionRecordingDays, Value: "3", UpdatedBy: "legacy"}).Error; err != nil {
			t.Fatal(err)
		}
		kek, err := buildUIKEKProvider([]byte(testInitialKEK))
		if err != nil {
			t.Fatal(err)
		}
		g, err := runStage2(context.Background(), env.s1, kek, nil, nil)
		if err != nil {
			t.Fatalf("段 2 失敗: %v", err)
		}
		t.Cleanup(func() {
			rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = g.Release(rctx)
		})
		built := g.ServiceNames()
		idx := map[string]int{}
		for i, b := range built {
			if _, ok := idx[b]; !ok {
				idx[b] = i
			}
		}
		rec, ok := idx["retentionFloorReconcile"]
		if !ok {
			t.Fatalf("建構序沒有 retentionFloorReconcile：%v", built)
		}
		if idx["auditTxSink"] > rec {
			t.Errorf("對帳早於交易內審計落地面：%v", built)
		}
		for _, reader := range []string{"recordingService", "auditIntegrity", "offsiteLedger", "retentionScheduler"} {
			i, ok := idx[reader]
			if !ok {
				t.Fatalf("建構序沒有 %s：%v", reader, built)
			}
			if i < rec {
				t.Errorf("保留讀者 %s 早於對帳：%v", reader, built)
			}
		}
		// 同一個政策服務（保留讀者共用的那一份）：第一次讀值必須是對帳後的 7，
		// 段 2 期間若有讀者先讀，觀測到的第一筆就會是退回值
		if svc == nil {
			t.Fatal("沒有觀測到段 2 的政策服務")
		}
		if got := svc.GetInt(policy.PolicyRetentionRecordingDays); got != 7 {
			t.Errorf("保留讀者讀到的錄影保留 = %d, want 7", got)
		}
		if len(reads) == 0 || reads[0] != "7" {
			t.Errorf("錄影保留的讀值序列 %v，第一筆須為 7", reads)
		}
		for _, r := range reads {
			if r != "7" {
				t.Errorf("讀者讀到非對帳後的值 %q（序列 %v）", r, reads)
			}
		}
		var audits int64
		database.DB.Model(&model.AuditLog{}).Where("action = ? AND resource = ?",
			string(model.ActionRetentionFloorRaised), string(model.ResourceSecurityPolicy)).Count(&audits)
		if audits != 1 {
			t.Errorf("抬升審計 %d 筆，want 1（經交易內審計落地面）", audits)
		}
		var recs int64
		database.DB.Model(&model.SecurityPolicyFloorRaise{}).Count(&recs)
		if recs != 1 {
			t.Errorf("抬升紀錄 %d 筆，want 1", recs)
		}
	})
}
