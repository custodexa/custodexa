package scheduler

import (
	"time"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
)

// chainVerifyPolicyReader 取 int 型政策現值的窄介面（實作為 *policy.SecurityPolicyService）。
//
// 窄介面而非具體型別：本 adapter 只讀三個整數，測試得以在不架 DB 的情況下
// 釘住「讀的到底是哪三個鍵」——鍵名打錯而值域恰好相近（例如誤讀封章週期）
// 在只驗數值的測試裡看不出來
type chainVerifyPolicyReader interface {
	GetInt(key string) int
}

// ChainVerifyPolicyTuning 以安全政策三鍵實作 audit.ChainVerifyTuning。
//
// **每次呼叫都現讀，不快取、不在建構時取值**：政策一改下一分鐘就要生效，
// 不能等重啟。建構時取值會使「政策頁上的數字」與「排程實際跑的節奏」在
// 改值後長期不一致——那正是本專案在別處拒絕的「顯示值 ≠ 生效值」。
//
// **不在此施加上下界**：值域由政策層擋（Min／Max／不可為 0），資料層直改
// 的殘值由消費端 audit.ChainVerifyService 的防禦邊界收束。adapter 再夾一次
// 會讓同一個界線有三處定義，改一處而漏兩處時無人會發現
type ChainVerifyPolicyTuning struct {
	policies chainVerifyPolicyReader
}

// 編譯期釘住：介面由 audit 側定義，簽名一改此處即不編譯
var _ audit.ChainVerifyTuning = (*ChainVerifyPolicyTuning)(nil)

// NewChainVerifyPolicyTuning 建立政策旋鈕轉接器
func NewChainVerifyPolicyTuning(policies chainVerifyPolicyReader) *ChainVerifyPolicyTuning {
	return &ChainVerifyPolicyTuning{policies: policies}
}

// RecentWindowDays 近期層窗口天數（設定值；保留天數 clamp 由消費端施加）
func (t *ChainVerifyPolicyTuning) RecentWindowDays() int {
	return t.policies.GetInt(policy.PolicyAuditChainRecentVerifyDays)
}

// FullInterval 全鏈層驗證間隔。政策鍵以**秒**存放，與
// audit_checkpoint_interval_seconds 的單位刻意一致——同性質的兩個週期鍵
// 若一個存秒一個存分，SeedFromEnv 與頁面顯示都得各自換算
func (t *ChainVerifyPolicyTuning) FullInterval() time.Duration {
	return time.Duration(t.policies.GetInt(policy.PolicyAuditChainVerifyIntervalSeconds)) * time.Second
}

// RowsPerHour 內容層掃描速率（列/小時）。**是速率不是每輪列數**——
// 每輪預算＝速率 × 間隔，見 audit.ChainVerifyService.rowBudget
func (t *ChainVerifyPolicyTuning) RowsPerHour() int64 {
	return int64(t.policies.GetInt(policy.PolicyAuditChainVerifyRowsPerHour))
}
