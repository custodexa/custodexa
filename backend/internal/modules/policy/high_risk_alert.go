package policy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 安全政策的共用高危掛點。
//
// 高危鍵的變更不阻擋，但在同一個政策寫入交易內留審計並建立系統告警：每個有變動、
// 經分類器判定要告警的鍵，次序固定為「政策列與歷史 → 審計（details 帶 correlation_id）
// → 告警（同一 CorrelationID、操作者、來源位址）」。任一步失敗（含落地面缺注入）整批回滾，
// 快取不失效。批次含任一高危鍵時，讀舊值前先取交易級鎖：兩個並行寫入若讀到同一個舊值，
// 各自都判為「沒有放寬」，落地的卻可能是放寬。
//
// 本模組不直接依賴告警模組：類型鍵以字串傳遞，由組裝根的 adapter 轉成告警類型。
// 播種（env-init）與保留下限的升級對帳不經本掛點——前者是主機層輸入，後者是收緊。

// ErrHighRiskAlertSinkMissing 高危設定告警落地面缺注入。
var ErrHighRiskAlertSinkMissing = errors.New("安全政策高危設定告警落地面未注入")

// ErrHighRiskAlertRaise 高危設定告警寫入失敗（整批已回滾）；包住落地面回的原始錯誤。
var ErrHighRiskAlertRaise = errors.New("安全政策高危設定告警寫入失敗")

// 高危設定告警類型鍵（與系統告警目錄的類型字串相同；組裝根轉型）。
const (
	HighRiskRetentionShortened       = "retention_shortened"
	HighRiskRecordingFailcloseOff    = "recording_failclose_disabled"
	HighRiskAccessPolicyRelaxed      = "access_policy_relaxed"
	HighRiskMappingRevalidationRelax = "mapping_revalidation_relaxed"
)

// PolicyActor 政策寫入的操作者（管理介面的寫入入口帶入；系統告警拒收零值操作者）。
type PolicyActor struct {
	ID       uint
	Name     string
	ClientIP string
}

// HighRiskAlert 一筆高危設定告警（只含純值，模組不直接依賴告警模組）。
type HighRiskAlert struct {
	Type          string // HighRisk* 類型鍵
	ActorID       uint
	ActorName     string
	ClientIP      string
	CorrelationID string
	Key           string // 目標政策鍵
	Params        map[string]string
}

// HighRiskAlertRaiser 高危設定告警落地面的消費端窄介面。實作在組裝根，包裝交易內系統告警
// 落地面；回錯使整批政策寫入回滾。
type HighRiskAlertRaiser interface {
	RaiseHighRiskInTx(tx *gorm.DB, a HighRiskAlert) error
}

// SetHighRiskAlertRaiser 注入高危設定告警落地面（組裝根在系統告警落地面建構與自檢之後呼叫）。
func (s *SecurityPolicyService) SetHighRiskAlertRaiser(r HighRiskAlertRaiser) { s.alerts = r }

// HighRiskAlertSinkReady 組裝根啟動自檢：高危設定告警落地面已注入（含 typed-nil）。
func (s *SecurityPolicyService) HighRiskAlertSinkReady() error {
	if s.alerts == nil {
		return fmt.Errorf("安全政策服務: %w", ErrHighRiskAlertSinkMissing)
	}
	if rv := reflect.ValueOf(s.alerts); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return fmt.Errorf("安全政策服務: %w", ErrHighRiskAlertSinkMissing)
	}
	return nil
}

// highRiskVerdict 分類器判定要告警時回傳的類型與參數。
type highRiskVerdict struct {
	Type   string
	Params map[string]string
}

// highRiskClassifier 依舊值與新值判定是否告警；可在交易內讀資料（例如受影響資產數）。
type highRiskClassifier func(tx *gorm.DB, oldValue, newValue string) (*highRiskVerdict, error)

// retentionDataClass 四個資料保留鍵對應的告警資料類別。
var retentionDataClass = map[string]string{
	PolicyRetentionAuditLogDays:       "audit_log",
	PolicyRetentionSessionCommandDays: "session_command",
	PolicyRetentionAlertDays:          "alert",
	PolicyRetentionRecordingDays:      "recording",
}

// highRiskClassifiers 高危鍵的分類器，以鍵註冊。新增高危鍵只在此登錄（取鎖判定同步涵蓋）。
var highRiskClassifiers = map[string]highRiskClassifier{
	PolicyRetentionAuditLogDays:       classifyRetention(PolicyRetentionAuditLogDays),
	PolicyRetentionSessionCommandDays: classifyRetention(PolicyRetentionSessionCommandDays),
	PolicyRetentionAlertDays:          classifyRetention(PolicyRetentionAlertDays),
	PolicyRetentionRecordingDays:      classifyRetention(PolicyRetentionRecordingDays),
	PolicyRecordingFailCloseEnabled:   classifyFailClose,
	PolicyAccessPolicyDefault:         classifyAccessDefault,
	PolicyMappingRevalidationHours:    classifyMappingRevalidation,
}

// batchHasHighRiskKey 批次是否含高危鍵（讀舊值前須先取交易級鎖）。
func batchHasHighRiskKey(updates map[string]string) bool {
	for key := range updates {
		if _, ok := highRiskClassifiers[key]; ok {
			return true
		}
	}
	return false
}

// RetentionShortened 保留天數由舊值改新值是否為下調：新值非 0 且舊值為 0，或兩者皆非 0
// 且新值較小。調長、改為 0（永久）不是下調。解析失敗的值視為下調（寧可多報）。
func RetentionShortened(oldValue, newValue string) bool {
	o, oerr := strconv.Atoi(oldValue)
	n, nerr := strconv.Atoi(newValue)
	if oerr != nil || nerr != nil {
		return oldValue != newValue
	}
	switch {
	case n == 0:
		return false
	case o == 0:
		return true
	default:
		return n < o
	}
}

func classifyRetention(key string) highRiskClassifier {
	return func(_ *gorm.DB, oldValue, newValue string) (*highRiskVerdict, error) {
		if !RetentionShortened(oldValue, newValue) {
			return nil, nil
		}
		return &highRiskVerdict{Type: HighRiskRetentionShortened, Params: map[string]string{
			"data_class": retentionDataClass[key], "days_before": oldValue, "days_after": newValue,
		}}, nil
	}
}

func classifyFailClose(_ *gorm.DB, oldValue, newValue string) (*highRiskVerdict, error) {
	o, _ := strconv.ParseBool(oldValue)
	n, _ := strconv.ParseBool(newValue)
	if o && !n {
		return &highRiskVerdict{Type: HighRiskRecordingFailcloseOff, Params: map[string]string{}}, nil
	}
	return nil, nil
}

// classifyAccessDefault 全系統預設存取政策降級時告警，附受影響的未刪除資產數：
// 覆寫為空或不合法、因而跟隨預設，且有效段位下降者（同一交易內以有效段位計算）。
func classifyAccessDefault(tx *gorm.DB, oldValue, newValue string) (*highRiskVerdict, error) {
	tc := ClassifyDefaultChange(oldValue, newValue)
	if tc.Result != TierChangeDowngraded {
		return nil, nil
	}
	var rows []struct{ AccessPolicy *string }
	if err := tx.Model(&model.Asset{}).Select("access_policy").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("計算受影響資產數失敗: %w", err)
	}
	affected := 0
	for _, r := range rows {
		if TierRank(EffectiveTier(r.AccessPolicy, newValue)) < TierRank(EffectiveTier(r.AccessPolicy, oldValue)) {
			affected++
		}
	}
	return &highRiskVerdict{Type: HighRiskAccessPolicyRelaxed, Params: map[string]string{
		"relax_type": tc.Cause, "before_level": tc.BeforeTier, "after_level": tc.AfterTier,
		"affected_assets": strconv.Itoa(affected),
	}}, nil
}

func classifyMappingRevalidation(_ *gorm.DB, oldValue, newValue string) (*highRiskVerdict, error) {
	if !MappingRevalidationRelaxed(oldValue, newValue) {
		return nil, nil
	}
	return &highRiskVerdict{Type: HighRiskMappingRevalidationRelax, Params: map[string]string{
		"hours_before": oldValue, "hours_after": newValue,
	}}, nil
}

// MappingRevalidationRelaxed 時限由舊值改新值是否為放寬：非 0 改 0，或兩者皆非 0 且調大。
// 解析失敗的值視為放寬（寧可多報）。
func MappingRevalidationRelaxed(oldValue, newValue string) bool {
	o, oerr := strconv.Atoi(oldValue)
	n, nerr := strconv.Atoi(newValue)
	if oerr != nil || nerr != nil {
		return oldValue != newValue
	}
	switch {
	case o == n:
		return false
	case n == 0:
		return true
	case o == 0:
		return false
	default:
		return n > o
	}
}

// newPolicyCorrelationID 審計列與告警共用的關聯識別（隨機、不含任何輸入內容）。
// 隨機來源失敗時回錯，整批政策寫入失敗：退回固定值會讓不同變更共用同一個關聯識別。
func newPolicyCorrelationID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("產生政策變更關聯識別失敗: %w", err)
	}
	return "pol-" + hex.EncodeToString(b), nil
}

// classifyHighRisk 判定本鍵變更是否要告警（非高危鍵回 nil）。
func classifyHighRisk(tx *gorm.DB, key, oldValue, newValue string) (*highRiskVerdict, error) {
	c, ok := highRiskClassifiers[key]
	if !ok {
		return nil, nil
	}
	return c(tx, oldValue, newValue)
}

// raiseHighRisk 在政策寫入交易內產生一筆高危設定告警（審計已寫入之後呼叫）。
func (s *SecurityPolicyService) raiseHighRisk(tx *gorm.DB, actor PolicyActor, key, correlationID string, v *highRiskVerdict) error {
	if err := s.HighRiskAlertSinkReady(); err != nil {
		return fmt.Errorf("%w: %w", ErrHighRiskAlertRaise, err)
	}
	if err := s.alerts.RaiseHighRiskInTx(tx, HighRiskAlert{
		Type: v.Type, ActorID: actor.ID, ActorName: actor.Name, ClientIP: actor.ClientIP,
		CorrelationID: correlationID, Key: key, Params: v.Params,
	}); err != nil {
		return fmt.Errorf("%w（%s）: %w", ErrHighRiskAlertRaise, key, err)
	}
	return nil
}
