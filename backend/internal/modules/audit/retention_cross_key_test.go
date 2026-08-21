package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 執行期跨鍵保守行為（audit-checkpoint-chain tasks 7.5／security-policy spec
//「約束 SHALL 於執行期亦成立」）。
//
// 設定面的驗證只擋 API 路徑；政策表被 SQL 直改就繞過了。而鏈修剪是不可逆的
// 刪除，故執行面必須自己再判一次並採保守方向（不修剪）。

// setPolicyRowDirect 以 SQL 直寫政策列——**刻意繞過政策服務**，重現
// 「外部直改 DB 製造違規」的情境（經服務層會被跨鍵驗證擋下，就測不到執行期了）
func setPolicyRowDirect(t *testing.T, f *purgeFixture, key, value string) {
	t.Helper()
	row := model.SecurityPolicy{Key: key, Value: value, UpdatedBy: "sql-direct", UpdatedAt: time.Now()}
	if err := f.db.Save(&row).Error; err != nil {
		t.Fatalf("直寫政策 %s=%s: %v", key, value, err)
	}
	// 政策服務有 30 秒快取；直改 DB 不會使其失效，測試需自建服務讀新值
	f.svc.policy = policy.NewSecurityPolicyService(f.db)
}

// agedTrimmableChain 造出「若無跨鍵閘就一定會被修剪」的鏈：
// 四個已清除的老區間 ＋ 一個新區間，genesis 亦催老。
// 回傳修剪前的檢查點總數
func agedTrimmableChain(t *testing.T, f *purgeFixture) int64 {
	t.Helper()
	old := time.Now().Add(-400 * 24 * time.Hour)
	aged := time.Now().Add(-4000 * 24 * time.Hour)
	cutoff := time.Now().Add(-365 * 24 * time.Hour)
	for i := 0; i < 4; i++ {
		cp := f.sealAt(t, 2, old, aged.Add(time.Duration(i)*time.Minute))
		if _, err := f.purger.PurgeInterval(cp, 365, cutoff); err != nil {
			t.Fatalf("purge seq=%d: %v", cp.Seq, err)
		}
	}
	f.sealInterval(t, 1, time.Now())
	if err := f.db.Exec("UPDATE audit_checkpoints SET sealed_at = ? WHERE seq = 1",
		aged.Add(-time.Hour)).Error; err != nil {
		t.Fatalf("age genesis: %v", err)
	}
	var n int64
	if err := f.db.Model(&model.AuditCheckpoint{}).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestRetentionTrimSkippedOnCrossKeyViolation 政策違規時 PurgeAll 不修剪，且留痕告警。
func TestRetentionTrimSkippedOnCrossKeyViolation(t *testing.T) {
	f := setupPurgeFixture(t)
	before := agedTrimmableChain(t, f)

	// 違規組合：檢查點只留 30 天，但 audit_logs 永久保留（0=無限大）
	setPolicyRowDirect(t, f, policy.PolicyRetentionCheckpointDays, "30")
	setPolicyRowDirect(t, f, policy.PolicyRetentionAuditLogDays, "0")

	f.audit.entries = nil
	f.svc.PurgeAll()

	var after int64
	if err := f.db.Model(&model.AuditCheckpoint{}).Count(&after).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != before {
		t.Fatalf("違規政策下仍修剪了 %d 個檢查點（before=%d after=%d）", before-after, before, after)
	}
	var trims int64
	if err := f.db.Model(&model.AuditCheckpointTrim{}).Count(&trims).Error; err != nil {
		t.Fatalf("count trims: %v", err)
	}
	if trims != 0 {
		t.Fatalf("不應產生修剪記錄，實得 %d 筆", trims)
	}

	// 告警：留痕必須是 failure 狀態且指出成因，否則「跳過」與「沒到期」無從區分
	var found *AuditLogEntry
	for _, e := range f.audit.entries {
		if strings.Contains(e.Details, "audit_checkpoints") {
			found = e
		}
	}
	if found == nil {
		t.Fatal("跳過修剪未留痕（運維端無從得知鏈保留政策失效）")
	}
	if found.Status != model.StatusFailure {
		t.Errorf("留痕狀態 = %s, want %s", found.Status, model.StatusFailure)
	}
	if !strings.Contains(found.ErrorMsg, "跨鍵約束") {
		t.Errorf("留痕未指出成因: %q", found.ErrorMsg)
	}
}

// TestRetentionTrimRunsWhenPolicyConsistent 對照組：政策一致時修剪照常執行。
//
// **沒有這條，上一條就是零觸發的假綠**——若鏈根本沒到期（或 fixture 造錯），
// 「沒修剪」的原因可能與跨鍵閘無關
func TestRetentionTrimRunsWhenPolicyConsistent(t *testing.T) {
	f := setupPurgeFixture(t)
	before := agedTrimmableChain(t, f)

	// 一致組合：檢查點 30 天，四個資料鍵皆短於它
	setPolicyRowDirect(t, f, policy.PolicyRetentionCheckpointDays, "30")
	for _, key := range []string{
		policy.PolicyRetentionAuditLogDays,
		policy.PolicyRetentionSessionCommandDays,
		policy.PolicyRetentionAlertDays,
		policy.PolicyRetentionRecordingDays,
	} {
		setPolicyRowDirect(t, f, key, "10")
	}

	f.svc.PurgeAll()

	var after int64
	if err := f.db.Model(&model.AuditCheckpoint{}).Count(&after).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if after >= before {
		t.Fatalf("政策一致時應發生修剪（before=%d after=%d）", before, after)
	}
	var trims int64
	if err := f.db.Model(&model.AuditCheckpointTrim{}).Count(&trims).Error; err != nil {
		t.Fatalf("count trims: %v", err)
	}
	if trims != 1 {
		t.Fatalf("修剪記錄 = %d 筆, want 1", trims)
	}
}

// TestRetentionCrossKeyGateCoversEveryDataKey 四個資料鍵逐一都能觸發保守跳過。
//
// 執行期閘若漏列一個鍵，該類資料就能以「比檢查點更長的保留期」存在而鏈仍被修剪
func TestRetentionCrossKeyGateCoversEveryDataKey(t *testing.T) {
	for _, key := range []string{
		policy.PolicyRetentionAuditLogDays,
		policy.PolicyRetentionSessionCommandDays,
		policy.PolicyRetentionAlertDays,
		policy.PolicyRetentionRecordingDays,
	} {
		t.Run(key, func(t *testing.T) {
			f := setupPurgeFixture(t)
			setPolicyRowDirect(t, f, policy.PolicyRetentionCheckpointDays, "30")
			for _, k := range []string{
				policy.PolicyRetentionAuditLogDays,
				policy.PolicyRetentionSessionCommandDays,
				policy.PolicyRetentionAlertDays,
				policy.PolicyRetentionRecordingDays,
			} {
				setPolicyRowDirect(t, f, k, "10")
			}
			setPolicyRowDirect(t, f, key, "3650") // 只有這個鍵越界

			if msg := f.svc.crossKeyViolation(30); msg == "" {
				t.Fatalf("%s=3650 > 檢查點 30 天，應判違規", key)
			} else if !strings.Contains(msg, key) {
				t.Errorf("告警未指名越界的鍵: %q", msg)
			}
		})
	}
}
