package scheduler

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// recordingPolicyReader 記錄被查詢的鍵並回固定值，用於釘住「讀的是哪三個鍵」
type recordingPolicyReader struct {
	vals map[string]int
	seen []string
}

func (r *recordingPolicyReader) GetInt(key string) int {
	r.seen = append(r.seen, key)
	return r.vals[key]
}

func newPolicyServiceForTuning(t *testing.T) *policy.SecurityPolicyService {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return policy.NewSecurityPolicyService(db)
}

// TestChainVerifyTuningReadsExactPolicyKeys 三個 getter 各自只讀對應的那一個鍵。
//
// **值域相近的誤讀在只驗數值的測試裡看不出來**：例如把全鏈間隔誤讀成
// audit_checkpoint_interval_seconds（同為 3600 秒），數值斷言會照樣綠
func TestChainVerifyTuningReadsExactPolicyKeys(t *testing.T) {
	cases := []struct {
		name string
		call func(*ChainVerifyPolicyTuning)
		want string
	}{
		{"近期窗口", func(x *ChainVerifyPolicyTuning) { x.RecentWindowDays() }, policy.PolicyAuditChainRecentVerifyDays},
		{"全鏈間隔", func(x *ChainVerifyPolicyTuning) { x.FullInterval() }, policy.PolicyAuditChainVerifyIntervalSeconds},
		{"掃描速率", func(x *ChainVerifyPolicyTuning) { x.RowsPerHour() }, policy.PolicyAuditChainVerifyRowsPerHour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &recordingPolicyReader{vals: map[string]int{}}
			c.call(NewChainVerifyPolicyTuning(r))
			if len(r.seen) != 1 || r.seen[0] != c.want {
				t.Errorf("查詢的鍵 = %v, want [%s]", r.seen, c.want)
			}
		})
	}
}

// TestChainVerifyTuningDefaults 未設定時取到三鍵的出廠值，且單位換算正確
//（政策鍵存秒，介面要的是 Duration）
func TestChainVerifyTuningDefaults(t *testing.T) {
	tune := NewChainVerifyPolicyTuning(newPolicyServiceForTuning(t))

	if got := tune.RecentWindowDays(); got != 7 {
		t.Errorf("RecentWindowDays = %d, want 7", got)
	}
	if got := tune.FullInterval(); got != time.Hour {
		t.Errorf("FullInterval = %v, want 1h", got)
	}
	if got := tune.RowsPerHour(); got != 1000000 {
		t.Errorf("RowsPerHour = %d, want 1000000", got)
	}
}

// TestChainVerifyTuningReadsLive 改政策後**不重啟、不重建 adapter** 即生效。
//
// 釘的是「現讀」語義：若 adapter 在建構時取值或自行快取，改值後排程仍照舊節奏跑，
// 而政策頁上顯示的是新值——顯示值 ≠ 生效值
func TestChainVerifyTuningReadsLive(t *testing.T) {
	svc := newPolicyServiceForTuning(t)
	tune := NewChainVerifyPolicyTuning(svc)
	_ = tune.FullInterval() // 先讀一次，任何建構後快取都會在此固化

	for key, value := range map[string]string{
		policy.PolicyAuditChainRecentVerifyDays:      "3",
		policy.PolicyAuditChainVerifyIntervalSeconds: "7200",
		policy.PolicyAuditChainVerifyRowsPerHour:     "2000000",
	} {
		if _, err := svc.Update(key, value, "admin"); err != nil {
			t.Fatalf("Update %s: %v", key, err)
		}
	}

	if got := tune.RecentWindowDays(); got != 3 {
		t.Errorf("改值後 RecentWindowDays = %d, want 3", got)
	}
	if got := tune.FullInterval(); got != 2*time.Hour {
		t.Errorf("改值後 FullInterval = %v, want 2h", got)
	}
	if got := tune.RowsPerHour(); got != 2000000 {
		t.Errorf("改值後 RowsPerHour = %d, want 2000000", got)
	}
}

// TestChainVerifyTuningPassesThroughWithoutClamping adapter 不自行夾值：
// 界線由政策層與消費端各自承擔，adapter 再夾一次即等於同一條界線有三處定義
func TestChainVerifyTuningPassesThroughWithoutClamping(t *testing.T) {
	r := &recordingPolicyReader{vals: map[string]int{
		policy.PolicyAuditChainRecentVerifyDays:      999,
		policy.PolicyAuditChainVerifyIntervalSeconds: 1,
		policy.PolicyAuditChainVerifyRowsPerHour:     1,
	}}
	tune := NewChainVerifyPolicyTuning(r)

	if got := tune.RecentWindowDays(); got != 999 {
		t.Errorf("RecentWindowDays = %d, want 999（原值透傳）", got)
	}
	if got := tune.FullInterval(); got != time.Second {
		t.Errorf("FullInterval = %v, want 1s（原值透傳）", got)
	}
	if got := tune.RowsPerHour(); got != 1 {
		t.Errorf("RowsPerHour = %d, want 1（原值透傳）", got)
	}
}
